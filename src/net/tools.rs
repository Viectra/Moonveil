//! Active host diagnostics & utilities: Ping Monitor, Traceroute, Wake-on-LAN, OSC 52 Clipboard, and Exports.

use std::fmt::Write as _;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::net::model::{
    format_mac, ExportFormat, Host, NetworkSnapshot, PortState, PrivilegeLevel, TracerouteHop,
};
use crate::net::scanner::{icmp_ping, probe_host_alive, reverse_dns_blocking, EngineEvent};

/// Streams live 1-second RTT ping updates for a target host until cancelled.
pub async fn run_ping_monitor(
    ip: Ipv4Addr,
    priv_level: PrivilegeLevel,
    cancel: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<EngineEvent>,
) {
    while !cancel.load(Ordering::Relaxed) {
        let sample = if priv_level != PrivilegeLevel::User {
            icmp_ping(ip, 650, priv_level).await
        } else {
            probe_host_alive(ip, 450, priv_level).await
        };
        let (rtt_ms, ttl) = match sample {
            Some((r, t)) => (Some(r), t),
            None => (None, None),
        };
        let _ = tx.send(EngineEvent::PingUpdate { ip, rtt_ms, ttl });
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Runs an unprivileged hop-by-hop UDP traceroute using Linux `IP_RECVERR` + `MSG_ERRQUEUE`.
pub async fn run_traceroute(
    target: Ipv4Addr,
    max_hops: u8,
    cancel: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<EngineEvent>,
) {
    for ttl in 1..=max_hops {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let hop = tokio::task::spawn_blocking(move || probe_trace_hop(target, ttl))
            .await
            .ok()
            .unwrap_or(TracerouteHop {
                ttl,
                ip: None,
                hostname: None,
                rtt_ms: None,
            });
        let reached = hop.ip == Some(target);
        let _ = tx.send(EngineEvent::TraceHop(hop));
        if reached {
            break;
        }
    }
    let _ = tx.send(EngineEvent::TraceComplete);
}

fn probe_trace_hop(target: Ipv4Addr, ttl: u8) -> TracerouteHop {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return TracerouteHop {
                ttl,
                ip: None,
                hostname: None,
                rtt_ms: None,
            };
        }
        let ttl_val: libc::c_int = i32::from(ttl);
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            (&ttl_val as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let port = 33434_u16 + u16::from(ttl);
        let dst = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(target).to_be(),
            },
            sin_zero: [0; 8],
        };
        let payload = b"MOONVEIL";
        let t0 = Instant::now();
        let rc = libc::sendto(
            fd,
            payload.as_ptr().cast(),
            payload.len(),
            0,
            (&dst as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc < 0 {
            libc::close(fd);
            return TracerouteHop {
                ttl,
                ip: None,
                hostname: None,
                rtt_ms: None,
            };
        }

        // Poll up to 450ms for ICMP error queue message.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLERR | libc::POLLIN,
            revents: 0,
        };
        let prc = libc::poll(&mut pfd, 1, 450);
        let rtt = t0.elapsed().as_secs_f64() * 1000.0;
        if prc <= 0 {
            libc::close(fd);
            return TracerouteHop {
                ttl,
                ip: None,
                hostname: None,
                rtt_ms: None,
            };
        }

        let mut data = [0u8; 64];
        let mut cbuf = [0u8; 512];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;

        let err_n = libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT);
        let mut hop_ip = None;
        if err_n >= 0 {
            hop_ip = extract_errqueue_offender(&msg);
        } else {
            // Check if destination actually replied or rejected locally
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            let mut slen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let mut dummy = [0u8; 32];
            if libc::recvfrom(
                fd,
                dummy.as_mut_ptr().cast(),
                dummy.len(),
                libc::MSG_DONTWAIT,
                (&mut sa as *mut libc::sockaddr_in).cast(),
                &mut slen,
            ) >= 0
            {
                hop_ip = Some(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)));
            }
        }
        libc::close(fd);

        let hostname = hop_ip.and_then(reverse_dns_blocking);
        TracerouteHop {
            ttl,
            ip: hop_ip,
            hostname,
            rtt_ms: hop_ip.map(|_| rtt),
        }
    }
}

unsafe fn extract_errqueue_offender(msg: &libc::msghdr) -> Option<Ipv4Addr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_RECVERR {
            let err_ptr = libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err;
            if !err_ptr.is_null() {
                let offender = (err_ptr.add(1)) as *const libc::sockaddr_in;
                let ip = Ipv4Addr::from(u32::from_be((*offender).sin_addr.s_addr));
                if !ip.is_unspecified() {
                    return Some(ip);
                }
            }
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    None
}

/// Sends a Wake-on-LAN Magic Packet (`6x 0xFF` + `16x MAC`) via UDP broadcast port 9.
pub fn send_wake_on_lan(mac: [u8; 6], broadcast: Option<Ipv4Addr>) -> Result<(), String> {
    let mut packet = [0xFF_u8; 102];
    for chunk in packet[6..].as_chunks_mut::<6>().0 {
        chunk.copy_from_slice(&mac);
    }
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("UDP bind failed: {e}"))?;
    sock.set_broadcast(true)
        .map_err(|e| format!("Failed enabling broadcast: {e}"))?;
    sock.send_to(&packet, "255.255.255.255:9")
        .map_err(|e| format!("Failed sending WoL packet: {e}"))?;
    if let Some(bcast) = broadcast {
        let _ = sock.send_to(&packet, (bcast, 9));
    }
    Ok(())
}

/// Encodes `text` as Base64 and writes an OSC 52 clipboard escape sequence to stdout.
pub fn copy_osc52(text: &str) {
    use std::io::Write;
    let b64 = encode_base64(text.as_bytes());
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\x1b]52;c;{b64}\x07");
    let _ = out.flush();
}

fn encode_base64(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHA[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHA[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Exports the current `NetworkSnapshot` to `JSON`, `CSV`, or `Markdown` at `out_path`.
pub fn export_snapshot(
    snapshot: &NetworkSnapshot,
    format: ExportFormat,
    out_path: &Path,
) -> Result<(), String> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed creating export directory: {e}"))?;
    }
    let content = match format {
        ExportFormat::Json => serde_json::to_string_pretty(snapshot)
            .map_err(|e| format!("Failed serializing JSON: {e}"))?,
        ExportFormat::Csv => render_csv(snapshot),
        ExportFormat::Markdown => render_markdown(snapshot),
    };
    fs::write(out_path, content).map_err(|e| format!("Failed writing export file: {e}"))
}

fn render_csv(snapshot: &NetworkSnapshot) -> String {
    let mut s = String::from(
        "ip,hostname,nickname,mac,vendor,online,trusted,role,rtt_ms,os_guess,in_use_ports,open_ports,closed_ports,filtered_ports,active_services\n",
    );
    for h in &snapshot.hosts {
        let (iu, op, filt, cl) = h.port_counts();
        let active_list: Vec<String> = h
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
            .map(|p| format!("{}/{}", p.port, p.service))
            .collect();
        let _ = writeln!(
            s,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            h.ip,
            csv_cell(h.hostname.as_deref().unwrap_or("")),
            csv_cell(h.nickname.as_deref().unwrap_or("")),
            csv_cell(&h.mac.map(format_mac).unwrap_or_default()),
            csv_cell(h.vendor.as_deref().unwrap_or("")),
            h.online,
            h.trusted,
            csv_cell(h.role.label()),
            h.rtt_ms.map(|r| format!("{r:.2}")).unwrap_or_default(),
            csv_cell(h.os_guess.as_deref().unwrap_or("")),
            iu,
            op,
            cl,
            filt,
            csv_cell(&active_list.join(" "))
        );
    }
    s
}

fn csv_cell(raw: &str) -> String {
    if raw.contains(',') || raw.contains('"') || raw.contains('\n') {
        format!("\"{}\"", raw.replace('"', "\"\""))
    } else {
        raw.to_string()
    }
}

fn render_markdown(snapshot: &NetworkSnapshot) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Moonveil Network Snapshot\n");
    let _ = writeln!(
        s,
        "- **Host**: `{}@{}` (`{}` mode)",
        snapshot.username,
        snapshot.hostname,
        snapshot.privilege.badge()
    );
    let _ = writeln!(
        s,
        "- **Discovered Hosts**: {} ({} online)\n",
        snapshot.hosts.len(),
        snapshot.hosts.iter().filter(|h| h.online).count()
    );

    let _ = writeln!(
        s,
        "| IP | Name | MAC | Vendor | Status | RTT | In-Use | Open | Closed | Services |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    );
    for h in &snapshot.hosts {
        let (iu, op, _, cl) = h.port_counts();
        let svcs: Vec<String> = h
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
            .take(8)
            .map(|p| format!("{}/{}", p.port, p.service))
            .collect();
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            h.ip,
            h.display_name(),
            h.mac.map(format_mac).unwrap_or_else(|| "—".to_string()),
            h.vendor.as_deref().unwrap_or("—"),
            if h.online { "Online" } else { "Offline" },
            h.rtt_ms
                .map(|r| format!("{r:.1} ms"))
                .unwrap_or_else(|| "—".to_string()),
            iu,
            op,
            cl,
            if svcs.is_empty() {
                "—".to_string()
            } else {
                svcs.join(", ")
            }
        );
    }
    s
}

/// Formats active local open/in-use summary for a host.
pub fn host_service_summary(host: &Host) -> String {
    let items: Vec<String> = host
        .ports
        .iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
        .take(5)
        .map(|p| format!("{}:{}", p.port, p.service))
        .collect();
    items.join(" ")
}
