//! Host liveness probing (ICMP + multi-port TCP connect) and hostname discovery (PTR/mDNS/NBNS).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::net::linux::read_dns_servers;
use crate::net::model::{clean_discovered_hostname, PrivilegeLevel};

/// Probes host reachability via raw ICMP (if privileged) or TCP connect touch, returning `Some((rtt_ms, ttl))`.
pub async fn probe_host_alive(
    ip: Ipv4Addr,
    timeout_ms: u64,
    priv_level: PrivilegeLevel,
) -> Option<(f64, Option<u8>)> {
    if let Some((rtt, ttl)) = icmp_ping(ip, timeout_ms, priv_level).await {
        return Some((rtt, ttl));
    }

    let ping_ports = [80_u16, 443, 22, 445, 139, 3389, 8000, 8080, 8765];
    let dur = Duration::from_millis(timeout_ms.clamp(80, 450));
    let mut min_rtt: Option<f64> = None;

    for port in ping_ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        let t0 = Instant::now();
        match tokio::time::timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                let rtt = (t0.elapsed().as_secs_f64() * 1000.0).max(0.05);
                min_rtt = Some(min_rtt.map_or(rtt, |m| m.min(rtt)));
                break;
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                let rtt = (t0.elapsed().as_secs_f64() * 1000.0).max(0.05);
                min_rtt = Some(min_rtt.map_or(rtt, |m| m.min(rtt)));
                break;
            }
            _ => {}
        }
    }

    min_rtt.map(|rtt| (rtt, None))
}

/// Resolves the cleanest hostname available via `/etc/hosts`, DNS PTR, mDNS `.local`, or NetBIOS.
pub async fn resolve_hostname(
    ip: Ipv4Addr,
    etc_hosts: &HashMap<Ipv4Addr, String>,
    existing: Option<&str>,
) -> Option<String> {
    if let Some(name) = etc_hosts
        .get(&ip)
        .and_then(|s| clean_discovered_hostname(s))
    {
        return Some(name);
    }
    if let Some(prev) = existing.and_then(clean_discovered_hostname) {
        return Some(prev);
    }

    let ptr = tokio::task::spawn_blocking(move || dns_ptr_lookup(ip)).await;
    if let Ok(Some(name)) = ptr {
        if let Some(clean) = clean_discovered_hostname(&name) {
            return Some(clean);
        }
    }

    let mdns = tokio::task::spawn_blocking(move || mdns_reverse_lookup(ip)).await;
    if let Ok(Some(name)) = mdns {
        if let Some(clean) = clean_discovered_hostname(&name) {
            return Some(clean);
        }
    }

    let nbns = tokio::task::spawn_blocking(move || nbns_lookup(ip)).await;
    if let Ok(Some(name)) = nbns {
        if let Some(clean) = clean_discovered_hostname(&name) {
            return Some(clean);
        }
    }

    let rdns = tokio::task::spawn_blocking(move || reverse_dns_blocking(ip)).await;
    if let Ok(Some(name)) = rdns {
        return Some(name);
    }
    None
}

fn dns_ptr_lookup(ip: Ipv4Addr) -> Option<String> {
    let mut servers = read_dns_servers();
    if servers.is_empty() {
        return None;
    }
    servers.truncate(2);
    let pkt = build_ptr_query(ip, 0x4D56);
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(160)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(160)));

    let mut buf = [0u8; 512];
    for dns_ip in servers {
        if sock
            .send_to(&pkt, SocketAddr::new(IpAddr::V4(dns_ip), 53))
            .is_ok()
        {
            if let Ok((len, _)) = sock.recv_from(&mut buf) {
                if let Some(name) = parse_dns_ptr_name(&buf[..len]) {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn mdns_reverse_lookup(ip: Ipv4Addr) -> Option<String> {
    let pkt = build_ptr_query(ip, 0);
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(140)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(140)));
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    sock.send_to(&pkt, target).ok()?;
    let mut buf = [0u8; 512];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    parse_dns_ptr_name(&buf[..len])
}

fn nbns_lookup(ip: Ipv4Addr) -> Option<String> {
    // NetBIOS Node Status request (NBSTAT, QTYPE=0x0021) to UDP/137
    let mut req = [
        0x4D, 0x56, // tx id
        0x00, 0x00, // flags
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR
        0x20, // encoded name len 32
    ]
    .to_vec();
    req.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    req.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(120)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(120)));
    sock.send_to(&req, SocketAddr::new(IpAddr::V4(ip), 137))
        .ok()?;
    let mut buf = [0u8; 512];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    if len < 60 {
        return None;
    }
    let mut idx = 12;
    while idx < len && buf[idx] != 0 {
        if (buf[idx] & 0xC0) == 0xC0 {
            idx += 2;
            break;
        }
        idx += usize::from(buf[idx]) + 1;
    }
    if idx < len && buf[idx] == 0 {
        idx += 1;
    }
    // Skip TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
    idx += 10;
    if idx >= len {
        return None;
    }
    let num_names = usize::from(buf[idx]);
    idx += 1;
    for _ in 0..num_names {
        if idx + 18 > len {
            break;
        }
        let name_bytes = &buf[idx..idx + 15];
        let suffix = buf[idx + 15];
        let flags = u16::from_be_bytes([buf[idx + 16], buf[idx + 17]]);
        idx += 18;
        let is_group = (flags & 0x8000) != 0;
        if !is_group && matches!(suffix, 0x00 | 0x20) {
            let s = String::from_utf8_lossy(name_bytes).trim().to_string();
            if !s.is_empty() && !s.starts_with("WORKGROUP") {
                return Some(s);
            }
        }
    }
    None
}

/// Synchronous reverse DNS resolution using `getnameinfo(NI_NAMEREQD)`.
pub fn reverse_dns_blocking(ip: Ipv4Addr) -> Option<String> {
    let mut host = [0 as libc::c_char; 256];
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    };
    let rc = unsafe {
        libc::getnameinfo(
            (&sa as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc == 0 {
        let cstr = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
        clean_discovered_hostname(&cstr.to_string_lossy())
    } else {
        None
    }
}

fn build_ptr_query(ip: Ipv4Addr, tx_id: u16) -> Vec<u8> {
    let o = ip.octets();
    let rev = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in rev.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);
    pkt
}

fn parse_dns_ptr_name(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(pkt, pos)?;
        pos += 4;
        if pos > pkt.len() {
            return None;
        }
    }
    for _ in 0..ancount {
        pos = skip_dns_name(pkt, pos)?;
        if pos + 10 > pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]));
        pos += 10;
        if pos + rdlen > pkt.len() {
            return None;
        }
        if rtype == 12 {
            return read_dns_name(pkt, pos);
        }
        pos += rdlen;
    }
    None
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..64 {
        let len = *pkt.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + usize::from(len);
    }
    None
}

fn read_dns_name(pkt: &[u8], mut pos: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    while pos < pkt.len() && jumps < 16 {
        let len = pkt[pos];
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            let next = *pkt.get(pos + 1)?;
            pos = usize::from(u16::from_be_bytes([len & 0x3F, next]));
            jumps += 1;
            continue;
        }
        pos += 1;
        let end = pos + usize::from(len);
        if end > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[pos..end]).into_owned());
        pos = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Async wrapper for raw ICMP Echo ping when running with Root or `CAP_NET_RAW`.
pub async fn icmp_ping(
    ip: Ipv4Addr,
    timeout_ms: u64,
    priv_level: PrivilegeLevel,
) -> Option<(f64, Option<u8>)> {
    if !matches!(
        priv_level,
        PrivilegeLevel::Root | PrivilegeLevel::Capabilities
    ) {
        return None;
    }
    tokio::task::spawn_blocking(move || icmp_ping_sync(ip, timeout_ms).map(|(r, t)| (r, Some(t))))
        .await
        .ok()
        .flatten()
}

/// Sends a single IPv4 ICMP Echo Request over raw socket (`CAP_NET_RAW` / root) and returns `(rtt_ms, ttl)`.
#[allow(deprecated)]
pub fn icmp_ping_sync(ip: Ipv4Addr, timeout_ms: u64) -> Option<(f64, u8)> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return None;
    }

    let ms = timeout_ms.clamp(50, 2000) as libc::suseconds_t;
    let tv = libc::timeval {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_usec: (ms % 1000) * 1000,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast::<libc::c_void>(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let ident = (std::process::id() & 0xFFFF) as u16;
    let seq = 1_u16;
    let mut pkt = [0u8; 64];
    pkt[0] = 8; // ICMP Echo Request
    pkt[4..6].copy_from_slice(&ident.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    let csum = internet_checksum(&pkt);
    pkt[2..4].copy_from_slice(&csum.to_be_bytes());

    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    };

    let t0 = Instant::now();
    let sent = unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr().cast::<libc::c_void>(),
            pkt.len(),
            0,
            (&sa as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent <= 0 {
        unsafe { libc::close(fd) };
        return None;
    }

    let mut rbuf = [0u8; 256];
    let mut res = None;
    for _ in 0..4 {
        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let recvd = unsafe {
            libc::recvfrom(
                fd,
                rbuf.as_mut_ptr().cast::<libc::c_void>(),
                rbuf.len(),
                0,
                (&mut from as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
                &mut from_len,
            )
        };
        if recvd < 28 {
            break;
        }
        let src_ip = Ipv4Addr::from(u32::from_be(from.sin_addr.s_addr));
        let ihl = usize::from(rbuf[0] & 0x0F) * 4;
        if recvd as usize >= ihl + 8 && src_ip == ip {
            let icmp_type = rbuf[ihl];
            let r_ident = u16::from_be_bytes([rbuf[ihl + 4], rbuf[ihl + 5]]);
            if icmp_type == 0 && r_ident == ident {
                let rtt = (t0.elapsed().as_secs_f64() * 1000.0).max(0.05);
                res = Some((rtt, rbuf[8]));
                break;
            }
        }
    }

    unsafe { libc::close(fd) };
    res
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
