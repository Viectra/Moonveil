//! Découverte d'hôtes : détection de présence, ping ICMP (TTL), résolution DNS inverse et mDNS.

use super::*;

/// Probes a host for liveness via ICMP (if permitted) and fast multi-port TCP touch.
pub async fn probe_host_alive(
    ip: Ipv4Addr,
    timeout_ms: u64,
    priv_level: PrivilegeLevel,
) -> Option<(f64, Option<u8>)> {
    if priv_level != PrivilegeLevel::User {
        if let Some((rtt, ttl)) = icmp_ping(ip, timeout_ms, priv_level).await {
            return Some((rtt, ttl));
        }
    }
    let touch_ports = [80_u16, 443, 22, 445, 62078];
    let per_port = Duration::from_millis(timeout_ms.clamp(90, 260));
    let mut set = tokio::task::JoinSet::new();
    for port in touch_ports {
        set.spawn(async move {
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            let t0 = Instant::now();
            match tokio::time::timeout(per_port, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(t0.elapsed().as_secs_f64() * 1000.0),
                Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                    Some(t0.elapsed().as_secs_f64() * 1000.0)
                }
                _ => None,
            }
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(rtt)) = res {
            return Some((rtt, None));
        }
    }
    None
}

/// Sends a single ICMP Echo Request and returns `(rtt_ms, Option<ttl>)` when permitted.
pub async fn icmp_ping(
    ip: Ipv4Addr,
    timeout_ms: u64,
    priv_level: PrivilegeLevel,
) -> Option<(f64, Option<u8>)> {
    if priv_level == PrivilegeLevel::User {
        return None;
    }
    tokio::task::spawn_blocking(move || icmp_ping_blocking(ip, timeout_ms, priv_level))
        .await
        .ok()
        .flatten()
}

pub(super) fn icmp_ping_blocking(
    ip: Ipv4Addr,
    timeout_ms: u64,
    priv_level: PrivilegeLevel,
) -> Option<(f64, Option<u8>)> {
    let sock_type = match priv_level {
        PrivilegeLevel::Raw => libc::SOCK_RAW,
        PrivilegeLevel::IcmpDatagram => libc::SOCK_DGRAM,
        PrivilegeLevel::User => return None,
    };
    unsafe {
        let fd = libc::socket(libc::AF_INET, sock_type, libc::IPPROTO_ICMP);
        if fd < 0 {
            return None;
        }
        let tv = libc::timeval {
            tv_sec: (timeout_ms / 1000) as libc::time_t,
            tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let id = (std::process::id() as u16) ^ 0x4D56;
        let seq: u16 = 1;
        let mut pkt = [0u8; 16];
        pkt[0] = 8; // Echo Request
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        pkt[8..16].copy_from_slice(b"MOONVEIL");
        let csum = internet_checksum(&pkt);
        pkt[2..4].copy_from_slice(&csum.to_be_bytes());

        let dst = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        let t0 = Instant::now();
        let sent = libc::sendto(
            fd,
            pkt.as_ptr().cast(),
            pkt.len(),
            0,
            (&dst as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if sent < 0 {
            libc::close(fd);
            return None;
        }

        let mut rx = [0u8; 256];
        let mut src: libc::sockaddr_in = std::mem::zeroed();
        let mut src_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let mut cbuf = [0u8; 64];
        let mut iov = libc::iovec {
            iov_base: rx.as_mut_ptr().cast(),
            iov_len: rx.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut src as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = src_len;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        let rtt = t0.elapsed().as_secs_f64() * 1000.0;
        libc::close(fd);
        if n < 8 {
            return None;
        }
        src_len = msg.msg_namelen;
        let _ = src_len;
        let from_ip = Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr));
        if from_ip != ip {
            return None;
        }
        let ttl = if priv_level == PrivilegeLevel::Raw && n >= 20 {
            Some(rx[8])
        } else {
            extract_cmsg_ttl(&msg)
        };
        Some((rtt, ttl))
    }
}

pub(super) unsafe fn extract_cmsg_ttl(msg: &libc::msghdr) -> Option<u8> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_TTL {
            let ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
            if !ptr.is_null() {
                let val = std::ptr::read_unaligned(ptr);
                if (1..=255).contains(&val) {
                    return Some(val as u8);
                }
            }
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    None
}

pub(super) fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) async fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    if let Ok(Some(name)) = tokio::task::spawn_blocking(move || reverse_dns_blocking(ip)).await {
        return Some(name);
    }
    mdns_reverse_lookup(ip).await
}

pub(crate) fn reverse_dns_blocking(ip: Ipv4Addr) -> Option<String> {
    unsafe {
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        let mut host_buf = [0 as libc::c_char; 256];
        let rc = libc::getnameinfo(
            (&sa as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host_buf.as_mut_ptr(),
            host_buf.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        );
        if rc == 0 {
            let name = std::ffi::CStr::from_ptr(host_buf.as_ptr())
                .to_string_lossy()
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

pub(super) async fn mdns_reverse_lookup(ip: Ipv4Addr) -> Option<String> {
    let octets = ip.octets();
    let labels = [
        octets[3].to_string(),
        octets[2].to_string(),
        octets[1].to_string(),
        octets[0].to_string(),
        "in-addr".to_string(),
        "arpa".to_string(),
    ];
    let mut pkt = vec![
        0x4D, 0x56, // ID
        0x00, 0x00, // Standard query
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in &labels {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // PTR, IN

    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(&pkt, "224.0.0.251:5353").await.ok()?;
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_millis(160), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_dns_ptr_name(&buf[..n])
}

pub(super) fn parse_dns_ptr_name(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
    if ancount == 0 {
        return None;
    }
    // Skip question section starting at byte 12.
    let mut idx = skip_dns_name(pkt, 12)?;
    idx += 4; // QTYPE + QCLASS
    if idx + 12 > pkt.len() {
        return None;
    }
    idx = skip_dns_name(pkt, idx)?;
    if idx + 10 > pkt.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([pkt[idx], pkt[idx + 1]]);
    let rdlen = u16::from_be_bytes([pkt[idx + 8], pkt[idx + 9]]) as usize;
    let rdata_start = idx + 10;
    if rtype != 12 || rdata_start + rdlen > pkt.len() {
        return None;
    }
    read_dns_name(pkt, rdata_start)
}

pub(super) fn skip_dns_name(pkt: &[u8], mut idx: usize) -> Option<usize> {
    loop {
        let len = *pkt.get(idx)?;
        if len == 0 {
            return Some(idx + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Some(idx + 2);
        }
        idx += 1 + usize::from(len);
    }
}

pub(super) fn read_dns_name(pkt: &[u8], mut idx: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    loop {
        let len = *pkt.get(idx)?;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            let next = *pkt.get(idx + 1)?;
            let ptr = ((usize::from(len & 0x3F)) << 8) | usize::from(next);
            idx = ptr;
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            continue;
        }
        idx += 1;
        let end = idx + usize::from(len);
        let slice = pkt.get(idx..end)?;
        labels.push(String::from_utf8_lossy(slice).into_owned());
        idx = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
