//! TCP port probing, banner grabbing (SSH/HTTP/TLS), and local `/proc/net` correlation.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::net::model::{service_info, LocalSocket, PortInfo, PortState, Proto, SocketState};

/// Probes a list of TCP ports on `ip`, grabbing optional banners and correlating local sockets.
pub async fn scan_ports_for_host(
    ip: Ipv4Addr,
    ports: &[u16],
    timeout_ms: u64,
    grab_banners: bool,
    local_sockets: &[LocalSocket],
    is_local: bool,
) -> Vec<PortInfo> {
    let sem = Arc::new(Semaphore::new(64));
    let per_port_ms = timeout_ms.clamp(90, 1200);

    let mut handles = Vec::with_capacity(ports.len());
    for &port in ports {
        let sem_c = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let Ok(_p) = sem_c.acquire().await else {
                return None;
            };
            Some(probe_single_port(ip, port, per_port_ms, grab_banners).await)
        }));
    }

    let mut out = Vec::with_capacity(ports.len());
    for h in handles {
        if let Ok(Some(mut info)) = h.await {
            enrich_port_with_local_sockets(&mut info, ip, is_local, local_sockets);
            out.push(info);
        }
    }

    out.sort_by(|a, b| {
        a.state
            .sort_rank()
            .cmp(&b.state.sort_rank())
            .then_with(|| a.port.cmp(&b.port))
    });
    out
}

fn enrich_port_with_local_sockets(
    info: &mut PortInfo,
    target_ip: Ipv4Addr,
    is_local: bool,
    local_sockets: &[LocalSocket],
) {
    if is_local {
        let mut active_proc: Option<(String, Option<u32>, Option<String>)> = None;
        let mut listen_proc: Option<(String, Option<u32>)> = None;

        for s in local_sockets {
            if !s.proto.starts_with("TCP") || s.local_port != info.port {
                continue;
            }
            let ip_matches = s
                .local_ip_v4
                .map(|lip| lip.is_unspecified() || lip == target_ip || lip.is_loopback())
                .unwrap_or(true);
            if !ip_matches {
                continue;
            }

            if s.state == SocketState::Established {
                let proc_name = s
                    .process
                    .clone()
                    .unwrap_or_else(|| "active socket".to_string());
                active_proc = Some((proc_name, s.pid, Some(s.remote_addr.clone())));
                break;
            } else if s.state == SocketState::Listen && listen_proc.is_none() {
                if let Some(p) = &s.process {
                    listen_proc = Some((p.clone(), s.pid));
                }
            }
        }

        if let Some((proc_name, pid, peer)) = active_proc {
            info.state = PortState::InUse;
            info.process = Some(proc_name);
            info.pid = pid;
            info.peer_endpoint = peer;
        } else if info.state == PortState::Open {
            if let Some((proc_name, pid)) = listen_proc {
                info.process = Some(proc_name);
                info.pid = pid;
            }
        }
        return;
    }

    // Remote host correlation: check if our host has an ESTABLISHED local socket connected to target_ip:port.
    for s in local_sockets {
        if !s.proto.starts_with("TCP") || s.state != SocketState::Established {
            continue;
        }
        if s.remote_ip_v4 == Some(target_ip) && s.remote_port == info.port {
            info.state = PortState::InUse;
            info.process = s
                .process
                .clone()
                .or_else(|| Some("local session".to_string()));
            info.pid = s.pid;
            info.peer_endpoint = Some(s.local_addr.clone());
            break;
        }
    }
}

async fn probe_single_port(
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    grab_banners: bool,
) -> PortInfo {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let (svc, desc) = service_info(port);
    let max_attempts = if port < 10_000 { 2 } else { 1 };

    let mut final_state = PortState::Filtered;
    let mut final_latency = None;
    let mut connected_stream: Option<TcpStream> = None;

    for attempt in 0..max_attempts {
        let t0 = Instant::now();
        let dur = Duration::from_millis(timeout_ms + (attempt as u64) * 120);
        match tokio::time::timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                final_state = PortState::Open;
                final_latency = Some((t0.elapsed().as_secs_f64() * 1000.0).max(0.05));
                connected_stream = Some(stream);
                break;
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    final_state = PortState::Closed;
                    final_latency = Some((t0.elapsed().as_secs_f64() * 1000.0).max(0.05));
                    break;
                }
                final_state = PortState::Filtered;
            }
            Err(_) => {
                final_state = PortState::Filtered;
            }
        }
    }

    let (banner, banner_hex) = if let Some(mut stream) = connected_stream {
        if grab_banners {
            read_service_banner(&mut stream, port).await
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    PortInfo {
        port,
        proto: Proto::Tcp,
        state: final_state,
        service: svc.to_string(),
        description: desc.to_string(),
        banner,
        banner_hex,
        latency_ms: final_latency,
        process: None,
        pid: None,
        peer_endpoint: None,
    }
}

async fn read_service_banner(
    stream: &mut TcpStream,
    port: u16,
) -> (Option<String>, Option<String>) {
    let is_http_port = matches!(
        port,
        80 | 81
            | 443
            | 3000
            | 3001
            | 4000
            | 4200
            | 5000
            | 5001
            | 5173
            | 7000
            | 7443
            | 8000
            | 8006
            | 8008
            | 8080
            | 8081
            | 8090
            | 8096
            | 8112
            | 8123
            | 8200
            | 8384
            | 8443
            | 8765
            | 8880
            | 8888
            | 8989
            | 9000
            | 9001
            | 9090
            | 9443
    );

    // First give greeting-based protocols (SSH/FTP/SMTP/POP/IMAP) a brief chance to speak first.
    let mut buf = [0u8; 1024];
    if !is_http_port {
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(160), stream.read(&mut buf)).await
        {
            if n > 0 {
                return format_banner_bytes(&buf[..n]);
            }
        }
    }

    // Probe HTTP (works for both well-known HTTP ports and unknown/ephemeral HTTP servers).
    let req =
        b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: Moonveil\r\nConnection: close\r\n\r\n";
    if stream.write_all(req).await.is_ok() {
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(260), stream.read(&mut buf)).await
        {
            if n > 0 {
                return format_http_or_raw_banner(&buf[..n], port);
            }
        }
    }

    (None, None)
}

fn format_http_or_raw_banner(bytes: &[u8], port: u16) -> (Option<String>, Option<String>) {
    let text = String::from_utf8_lossy(bytes);
    if text.starts_with("HTTP/") {
        let status = text.lines().next().unwrap_or("HTTP").trim();
        let server = text
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("server:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string());
        let title = extract_html_title(&text);
        let mut summary = status.to_string();
        if let Some(srv) = server {
            if !srv.is_empty() {
                summary.push_str(&format!(" • {srv}"));
            }
        }
        if let Some(t) = title {
            if !t.is_empty() {
                summary.push_str(&format!(" • \"{t}\""));
            }
        }
        return (Some(summary), Some(to_hex_preview(bytes)));
    }
    if matches!(port, 443 | 7443 | 8006 | 8443 | 9443) && !bytes.is_empty() {
        return (
            Some("TLS/HTTPS endpoint".to_string()),
            Some(to_hex_preview(bytes)),
        );
    }
    format_banner_bytes(bytes)
}

fn format_banner_bytes(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let clean: String = String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(96)
        .collect();
    let trimmed = clean.trim().to_string();
    if trimmed.is_empty() {
        (None, Some(to_hex_preview(bytes)))
    } else {
        (Some(trimmed), Some(to_hex_preview(bytes)))
    }
}

fn extract_html_title(body: &str) -> Option<String> {
    let low = body.to_ascii_lowercase();
    let start = low.find("<title>")? + 7;
    let end = low[start..].find("</title>")?;
    let slice = body.get(start..start + end)?;
    let clean: String = slice.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        None
    } else {
        Some(clean.chars().take(48).collect())
    }
}

fn to_hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(24)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
