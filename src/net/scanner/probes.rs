//! Sondes de ports TCP : classification d'état, capture de bannières HTTP/TLS et corrélation aux sockets locaux.

use super::*;

pub(super) fn enrich_port_with_local_sockets(
    info: &mut PortInfo,
    host_ip: Ipv4Addr,
    is_local: bool,
    local_sockets: &[LocalSocket],
) {
    if is_local {
        // Check for established sessions first (In Use).
        if let Some(sock) = local_sockets.iter().find(|s| {
            s.state == SocketState::Established
                && (s.local_port == info.port || s.remote_port == info.port)
        }) {
            if info.state == PortState::Open {
                info.state = PortState::InUse;
            }
            info.pid = sock.pid;
            info.process = sock.process.clone();
            info.peer_endpoint = Some(sock.remote_addr.clone());
            return;
        }
        // Attach process name/PID for local listening sockets.
        if let Some(sock) = local_sockets
            .iter()
            .find(|s| s.state == SocketState::Listen && s.local_port == info.port)
        {
            info.pid = sock.pid;
            info.process = sock.process.clone();
        }
    } else if let Some(sock) = local_sockets.iter().find(|s| {
        s.state == SocketState::Established
            && s.remote_ip_v4 == Some(host_ip)
            && s.remote_port == info.port
    }) {
        if info.state == PortState::Open {
            info.state = PortState::InUse;
        }
        info.pid = sock.pid;
        info.process = sock.process.clone();
        info.peer_endpoint = Some(sock.local_addr.clone());
    }
}

/// Probes one TCP port, classifying `Open`, `Closed` (`ConnectionRefused`), or `Filtered`.
pub async fn probe_single_port(
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    grab_banners: bool,
) -> PortInfo {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let (svc, desc) = service_info(port);
    let t0 = Instant::now();
    let res =
        tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await;
    let rtt = t0.elapsed().as_secs_f64() * 1000.0;

    match res {
        Ok(Ok(mut stream)) => {
            let (banner, banner_hex) = if grab_banners {
                read_service_banner(&mut stream, ip, port).await
            } else {
                (None, None)
            };
            PortInfo {
                port,
                proto: Proto::Tcp,
                state: PortState::Open,
                service: svc.to_string(),
                description: desc.to_string(),
                banner,
                banner_hex,
                latency_ms: Some(rtt),
                process: None,
                pid: None,
                peer_endpoint: None,
            }
        }
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => PortInfo {
            port,
            proto: Proto::Tcp,
            state: PortState::Closed,
            service: svc.to_string(),
            description: desc.to_string(),
            banner: None,
            banner_hex: None,
            latency_ms: Some(rtt),
            process: None,
            pid: None,
            peer_endpoint: None,
        },
        _ => PortInfo {
            port,
            proto: Proto::Tcp,
            state: PortState::Filtered,
            service: svc.to_string(),
            description: desc.to_string(),
            banner: None,
            banner_hex: None,
            latency_ms: None,
            process: None,
            pid: None,
            peer_endpoint: None,
        },
    }
}

pub(super) async fn read_service_banner(
    stream: &mut TcpStream,
    ip: Ipv4Addr,
    port: u16,
) -> (Option<String>, Option<String>) {
    let mut buf = [0u8; 1024];
    let is_http = matches!(
        port,
        80 | 81
            | 3000
            | 3001
            | 4000
            | 4200
            | 5000
            | 5173
            | 8000
            | 8008
            | 8080
            | 8081
            | 8096
            | 8888
            | 9000
            | 9090
            | 9200
            | 11434
    );
    let is_tls = matches!(port, 443 | 8443 | 9443 | 8006);

    if is_http {
        let req = format!(
            "GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Moonveil/0.1\r\nConnection: close\r\n\r\n"
        );
        let _ = tokio::time::timeout(Duration::from_millis(180), stream.write_all(req.as_bytes()))
            .await;
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(260), stream.read(&mut buf)).await
        {
            if n > 0 {
                let raw = &buf[..n];
                return (Some(summarize_http_banner(raw)), Some(hex_snippet(raw)));
            }
        }
        return (None, None);
    }

    if is_tls {
        let hello = build_tls_client_hello();
        let _ = tokio::time::timeout(Duration::from_millis(180), stream.write_all(&hello)).await;
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(280), stream.read(&mut buf)).await
        {
            if n > 0 {
                let raw = &buf[..n];
                return (Some(summarize_tls_banner(raw)), Some(hex_snippet(raw)));
            }
        }
        return (None, None);
    }

    // Greeting-first protocols (SSH, FTP, SMTP, Redis, MySQL, etc.).
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(220), stream.read(&mut buf)).await
    {
        if n > 0 {
            let raw = &buf[..n];
            let text = printable_line(raw, 96);
            return (
                if text.is_empty() { None } else { Some(text) },
                Some(hex_snippet(raw)),
            );
        }
    }
    (None, None)
}

pub(super) fn summarize_http_banner(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let status = text
        .lines()
        .next()
        .unwrap_or("HTTP")
        .trim()
        .trim_start_matches("HTTP/1.1 ")
        .trim_start_matches("HTTP/1.0 ");
    let server = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string());
    let title = extract_html_title(&text);
    let mut parts = vec![format!("HTTP {status}")];
    if let Some(s) = server {
        parts.push(s);
    }
    if let Some(t) = title {
        parts.push(format!("\"{t}\""));
    }
    parts.join(" • ")
}

pub(super) fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after_open = html[start..].find('>')? + start + 1;
    let end = lower[after_open..].find("</title>")? + after_open;
    let title = html[after_open..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(48).collect())
    }
}

pub(super) fn summarize_tls_banner(raw: &[u8]) -> String {
    // Check TLS record header (0x16 = handshake, 0x15 = alert)
    if raw.len() >= 3 && raw[0] == 0x16 {
        let ver = match (raw[1], raw[2]) {
            (3, 4) => "TLS 1.3",
            (3, 3) => "TLS 1.2",
            (3, 2) => "TLS 1.1",
            (3, 1) => "TLS 1.0",
            _ => "TLS",
        };
        if let Some(cn) = extract_printable_hostname(raw) {
            return format!("{ver} • cert:{cn}");
        }
        return format!("{ver} handshake");
    }
    if raw.len() >= 2 && raw[0] == 0x15 {
        return "TLS endpoint (SNI required)".to_string();
    }
    let text = printable_line(raw, 64);
    if text.chars().filter(|c| c.is_ascii_alphanumeric()).count() >= 4 {
        text
    } else {
        "TLS / binary service".to_string()
    }
}

pub(super) fn extract_printable_hostname(bytes: &[u8]) -> Option<String> {
    let mut best: Option<String> = None;
    let mut cur = String::new();
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'*') {
            cur.push(b as char);
        } else {
            if cur.contains('.')
                && cur.len() >= 4
                && cur.len() <= 48
                && !cur.starts_with('.')
                && !cur.ends_with('.')
                && cur.chars().any(|c| c.is_ascii_alphabetic())
            {
                best = Some(cur.clone());
                break;
            }
            cur.clear();
        }
    }
    best
}

pub(super) fn build_tls_client_hello() -> Vec<u8> {
    // Minimal RFC 5246 TLS 1.2 ClientHello for eliciting ServerHello + Certificate.
    let body: Vec<u8> = vec![
        0x03, 0x03, // TLS 1.2
        0x4d, 0x6f, 0x6f, 0x6e, 0x76, 0x65, 0x69, 0x6c, // 32-byte random
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x00, // Session ID len = 0
        0x00, 0x08, // Cipher suites len = 8
        0xc0, 0x2f, 0xc0, 0x30, 0x00, 0x9c, 0x00, 0x2f, 0x01, 0x00, // Compression = null
        0x00, 0x00, // Extensions len = 0
    ];
    let hs_len = body.len() as u32;
    let rec_len = (hs_len + 4) as u16;
    let mut pkt = Vec::with_capacity(body.len() + 9);
    pkt.push(0x16); // Handshake
    pkt.push(0x03);
    pkt.push(0x01);
    pkt.extend_from_slice(&rec_len.to_be_bytes());
    pkt.push(0x01); // ClientHello
    pkt.push(((hs_len >> 16) & 0xff) as u8);
    pkt.push(((hs_len >> 8) & 0xff) as u8);
    pkt.push((hs_len & 0xff) as u8);
    pkt.extend_from_slice(&body);
    pkt
}

pub(super) fn printable_line(raw: &[u8], max_chars: usize) -> String {
    raw.iter()
        .take(max_chars)
        .filter_map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                Some(b as char)
            } else if b == b'\n' || b == b'\r' {
                Some(' ')
            } else {
                None
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn hex_snippet(raw: &[u8]) -> String {
    raw.iter()
        .take(24)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
