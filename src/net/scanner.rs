//! Async tokio discovery, port-state classification (`InUse`/`Open`/`Closed`/`Filtered`), and banner probes.

use std::collections::{BTreeSet, HashMap};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

use crate::net::linux::{
    epoch_now, network_addr, prefix_mask, read_arp_entries, read_etc_hosts, ArpEntry,
};
use crate::net::model::{
    format_mac, format_oui, infer_device_role, infer_os_from_ttl, ports_for_preset, service_info,
    ArpState, Host, LocalSocket, NetworkInterface, PortInfo, PortState, PrivilegeLevel, Proto,
    ScanPreset, SocketState, TracerouteHop,
};
use crate::net::oui::lookup_vendor;

/// Streamed updates emitted from async network tasks back to the UI state loop.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    ScanStarted {
        total: usize,
        phase: String,
    },
    ScanProgress {
        probed: usize,
        total: usize,
        current_target: String,
        phase: String,
    },
    HostUpsert(Box<Host>),
    ScanCompleted {
        hosts_online: usize,
        ports_open: usize,
        duration_ms: u64,
    },
    PingUpdate {
        ip: Ipv4Addr,
        rtt_ms: Option<f64>,
        ttl: Option<u8>,
    },
    TraceHop(TracerouteHop),
    TraceComplete,
    TelemetryUpdate {
        interfaces: Vec<NetworkInterface>,
        local_sockets: Vec<LocalSocket>,
    },
    StatusToast(String),
}

/// Parameters controlling a network discovery + port scan run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub interface: NetworkInterface,
    pub preset: ScanPreset,
    pub custom_ports: String,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub grab_banners: bool,
    pub privilege: PrivilegeLevel,
    pub radar_page_offset: u32,
    pub single_host: Option<Ipv4Addr>,
    pub local_sockets: Vec<LocalSocket>,
    pub existing_hosts: HashMap<Ipv4Addr, Host>,
}

/// Computes the target IPv4 addresses to probe for an interface + optional `/24` page.
pub fn compute_scan_targets(
    iface: &NetworkInterface,
    arp_entries: &[ArpEntry],
    sockets: &[LocalSocket],
    page_offset: u32,
) -> Vec<Ipv4Addr> {
    let mut set = BTreeSet::new();
    if let Some(local_ip) = iface.ipv4 {
        set.insert(local_ip);
        if let Some(gw) = iface.gateway {
            set.insert(gw);
        }
        if iface.prefix_len <= 30 {
            let mask = prefix_mask(iface.prefix_len);
            let net_u32 = u32::from(local_ip) & mask;
            let bcast_u32 = net_u32 | !mask;
            let total_hosts = bcast_u32.saturating_sub(net_u32).saturating_sub(1);
            if total_hosts <= 254 {
                for addr in (net_u32 + 1)..bcast_u32 {
                    set.insert(Ipv4Addr::from(addr));
                }
            } else {
                // For /16 or wider networks, sweep the active /24 slice (or local /24 when offset==0).
                let local_slash24 = u32::from(local_ip) & 0xFFFF_FF00;
                let base24 = if page_offset == 0 {
                    local_slash24
                } else {
                    let max_pages = (bcast_u32 - net_u32) >> 8;
                    let clamped = page_offset.min(max_pages);
                    (net_u32 & 0xFFFF_FF00).saturating_add(clamped << 8)
                };
                for last in 1..=254_u32 {
                    let candidate = base24 | last;
                    if (candidate & mask) == net_u32 && candidate != bcast_u32 {
                        set.insert(Ipv4Addr::from(candidate));
                    }
                }
            }
        }
        let net = u32::from(network_addr(local_ip, iface.prefix_len));
        let mask = prefix_mask(iface.prefix_len);
        for arp in arp_entries {
            if arp.interface == iface.name || (u32::from(arp.ip) & mask) == net {
                set.insert(arp.ip);
            }
        }
        for sock in sockets {
            if let Some(ip) = sock.remote_ip_v4 {
                if !ip.is_loopback() && (u32::from(ip) & mask) == net {
                    set.insert(ip);
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Runs a full subnet discovery + port scan (or single-host deep scan) and streams `EngineEvent`s.
pub async fn run_scan(
    cfg: ScanConfig,
    cancel: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<EngineEvent>,
) {
    let started = Instant::now();
    let etc_hosts = read_etc_hosts();
    let initial_arp = read_arp_entries();
    let ports_to_scan = ports_for_preset(cfg.preset, &cfg.custom_ports);
    let iface = &cfg.interface;

    let mut discovered_hosts: HashMap<Ipv4Addr, Host> = HashMap::new();
    let now = epoch_now();

    if let Some(target_ip) = cfg.single_host {
        let mut base = cfg
            .existing_hosts
            .get(&target_ip)
            .cloned()
            .unwrap_or_else(|| make_skeleton_host(target_ip, iface, now));
        base.online = true;
        base.last_seen_epoch = now;
        discovered_hosts.insert(target_ip, base);
    } else {
        let targets = compute_scan_targets(
            iface,
            &initial_arp,
            &cfg.local_sockets,
            cfg.radar_page_offset,
        );
        let total = targets.len();
        let _ = tx.send(EngineEvent::ScanStarted {
            total,
            phase: format!("Discovering hosts on {}", iface.cidr),
        });

        // Immediately seed local host and known ARP hosts for instant responsiveness.
        if let Some(local_ip) = iface.ipv4 {
            let mut h = cfg
                .existing_hosts
                .get(&local_ip)
                .cloned()
                .unwrap_or_else(|| make_skeleton_host(local_ip, iface, now));
            h.online = true;
            h.mac = iface.mac.or(h.mac);
            h.oui_prefix = h.mac.map(format_oui);
            h.vendor = iface.vendor.clone().or(h.vendor);
            h.arp_state = ArpState::Local;
            h.ttl = Some(64);
            h.os_guess = Some("Linux (This Machine)".to_string());
            h.rtt_ms = Some(0.05);
            if h.hostname.is_none() {
                h.hostname = Some(
                    std::fs::read_to_string("/etc/hostname")
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|_| "localhost".to_string()),
                );
            }
            h.role = infer_device_role(
                true,
                false,
                h.vendor.as_deref(),
                h.hostname.as_deref(),
                &h.ports,
            );
            discovered_hosts.insert(local_ip, h.clone());
            let _ = tx.send(EngineEvent::HostUpsert(Box::new(h)));
        }

        let probed = Arc::new(AtomicUsize::new(0));
        let sem = Arc::new(Semaphore::new(cfg.concurrency.clamp(16, 256)));
        let timeout_ms = cfg.timeout_ms.clamp(80, 1500);
        let priv_level = cfg.privilege;
        let mut handles = Vec::with_capacity(targets.len());

        for ip in targets {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            if iface.ipv4 == Some(ip) {
                probed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let sem_c = sem.clone();
            let cancel_c = cancel.clone();
            let tx_c = tx.clone();
            let probed_c = probed.clone();
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = sem_c.acquire().await else {
                    return None;
                };
                if cancel_c.load(Ordering::Relaxed) {
                    return None;
                }
                let res = probe_host_alive(ip, timeout_ms, priv_level).await;
                let n = probed_c.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_multiple_of(8) || n == total {
                    let _ = tx_c.send(EngineEvent::ScanProgress {
                        probed: n,
                        total,
                        current_target: ip.to_string(),
                        phase: "Host sweep".to_string(),
                    });
                }
                res.map(|(rtt, ttl)| (ip, rtt, ttl))
            }));
        }

        for h in handles {
            if let Ok(Some((ip, rtt_ms, ttl))) = h.await {
                let mut host = cfg
                    .existing_hosts
                    .get(&ip)
                    .cloned()
                    .unwrap_or_else(|| make_skeleton_host(ip, iface, now));
                host.online = true;
                host.last_seen_epoch = now;
                host.rtt_ms = Some(rtt_ms);
                host.rtt_history.push(rtt_ms);
                if host.rtt_history.len() > 40 {
                    host.rtt_history.remove(0);
                }
                if let Some(t) = ttl {
                    host.ttl = Some(t);
                    host.os_guess = Some(infer_os_from_ttl(t).to_string());
                }
                discovered_hosts.insert(ip, host);
            }
        }

        if cancel.load(Ordering::Relaxed) {
            let _ = tx.send(EngineEvent::ScanCompleted {
                hosts_online: discovered_hosts.len(),
                ports_open: 0,
                duration_ms: started.elapsed().as_millis() as u64,
            });
            return;
        }

        // Re-read ARP cache briefly after probes so silent L2-responsive neighbors appear too.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let fresh_arp = read_arp_entries();
        let net = iface
            .ipv4
            .map(|ip| u32::from(network_addr(ip, iface.prefix_len)))
            .unwrap_or(0);
        let mask = prefix_mask(iface.prefix_len);

        for arp in fresh_arp {
            let in_iface = arp.interface == iface.name
                || (iface.ipv4.is_some() && (u32::from(arp.ip) & mask) == net);
            if !in_iface {
                continue;
            }
            let entry = discovered_hosts
                .entry(arp.ip)
                .or_insert_with(|| make_skeleton_host(arp.ip, iface, now));
            entry.online = true;
            entry.last_seen_epoch = now;
            entry.arp_state = arp.state;
            if let Some(v6) = arp.ipv6 {
                entry.ipv6 = Some(v6);
            }
            if let Some(mac) = arp.mac {
                entry.mac = Some(mac);
                entry.oui_prefix = Some(format_oui(mac));
                let (vendor, randomized) = lookup_vendor(mac);
                entry.vendor = vendor;
                entry.is_randomized_mac = randomized;
            }
        }
    }

    // Resolve hostnames concurrently via /etc/hosts, reverse DNS, and mDNS.
    let online_ips: Vec<Ipv4Addr> = discovered_hosts.keys().copied().collect();
    let name_sem = Arc::new(Semaphore::new(32));
    let mut name_tasks = Vec::with_capacity(online_ips.len());
    for ip in online_ips {
        let host_entry = discovered_hosts.get(&ip).cloned();
        if let Some(existing_name) = etc_hosts.get(&ip) {
            if let Some(h) = discovered_hosts.get_mut(&ip) {
                if h.hostname.is_none() {
                    h.hostname = Some(existing_name.clone());
                }
            }
            continue;
        }
        if host_entry
            .as_ref()
            .and_then(|h| h.hostname.as_ref())
            .is_some()
        {
            continue;
        }
        let sem_c = name_sem.clone();
        name_tasks.push(tokio::spawn(async move {
            let Ok(_p) = sem_c.acquire().await else {
                return (ip, None);
            };
            let resolved = resolve_hostname(ip).await;
            (ip, resolved)
        }));
    }
    for task in name_tasks {
        if let Ok((ip, Some(name))) = task.await {
            if let Some(h) = discovered_hosts.get_mut(&ip) {
                h.hostname = Some(name);
            }
        }
    }

    // Port scan every online host.
    let mut scan_ips: Vec<Ipv4Addr> = discovered_hosts.keys().copied().collect();
    scan_ips.sort();
    let total_port_jobs = scan_ips.len() * ports_to_scan.len();
    let _ = tx.send(EngineEvent::ScanStarted {
        total: total_port_jobs.max(1),
        phase: format!(
            "Scanning {} ports across {} hosts",
            ports_to_scan.len(),
            scan_ips.len()
        ),
    });

    let port_sem = Arc::new(Semaphore::new(cfg.concurrency.clamp(32, 512)));
    let port_probed = Arc::new(AtomicUsize::new(0));
    let mut host_tasks = Vec::with_capacity(scan_ips.len());

    for ip in scan_ips {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let ports_c = ports_to_scan.clone();
        let sem_c = port_sem.clone();
        let cancel_c = cancel.clone();
        let tx_c = tx.clone();
        let probed_c = port_probed.clone();
        let sockets_c = cfg.local_sockets.clone();
        let is_local = iface.ipv4 == Some(ip);
        let timeout_ms = cfg.timeout_ms.clamp(80, 1500);
        let grab_banners = cfg.grab_banners;

        host_tasks.push(tokio::spawn(async move {
            let scanned = scan_host_ports(
                ip,
                &ports_c,
                timeout_ms,
                grab_banners,
                is_local,
                &sockets_c,
                sem_c,
                cancel_c,
                probed_c,
                total_port_jobs,
                tx_c,
            )
            .await;
            (ip, scanned)
        }));
    }

    let mut total_open_ports = 0;
    for task in host_tasks {
        if let Ok((ip, ports)) = task.await {
            if let Some(host) = discovered_hosts.get_mut(&ip) {
                total_open_ports += ports
                    .iter()
                    .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
                    .count();
                host.ports = ports;
                let is_local = iface.ipv4 == Some(ip);
                let is_gw = iface.gateway == Some(ip);
                host.role = infer_device_role(
                    is_local,
                    is_gw,
                    host.vendor.as_deref(),
                    host.hostname.as_deref(),
                    &host.ports,
                );
                let _ = tx.send(EngineEvent::HostUpsert(Box::new(host.clone())));
            }
        }
    }

    let _ = tx.send(EngineEvent::ScanCompleted {
        hosts_online: discovered_hosts.len(),
        ports_open: total_open_ports,
        duration_ms: started.elapsed().as_millis() as u64,
    });
}

/// Scans an explicit list of ports on a single IP (used by the public engine API and tests).
pub async fn scan_ports_for_host(
    ip: Ipv4Addr,
    ports: &[u16],
    timeout_ms: u64,
    grab_banners: bool,
    local_sockets: &[LocalSocket],
    is_local: bool,
) -> Vec<PortInfo> {
    let sem = Arc::new(Semaphore::new(64));
    let cancel = Arc::new(AtomicBool::new(false));
    let probed = Arc::new(AtomicUsize::new(0));
    let (tx, _rx) = mpsc::unbounded_channel();
    scan_host_ports(
        ip,
        ports,
        timeout_ms,
        grab_banners,
        is_local,
        local_sockets,
        sem,
        cancel,
        probed,
        ports.len(),
        tx,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn scan_host_ports(
    ip: Ipv4Addr,
    ports: &[u16],
    timeout_ms: u64,
    grab_banners: bool,
    is_local: bool,
    local_sockets: &[LocalSocket],
    sem: Arc<Semaphore>,
    cancel: Arc<AtomicBool>,
    probed: Arc<AtomicUsize>,
    total_jobs: usize,
    tx: mpsc::UnboundedSender<EngineEvent>,
) -> Vec<PortInfo> {
    let mut handles = Vec::with_capacity(ports.len());
    for &port in ports {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let sem_c = sem.clone();
        let cancel_c = cancel.clone();
        let probed_c = probed.clone();
        let tx_c = tx.clone();
        handles.push(tokio::spawn(async move {
            let Ok(_permit) = sem_c.acquire().await else {
                return None;
            };
            if cancel_c.load(Ordering::Relaxed) {
                return None;
            }
            let info = probe_single_port(ip, port, timeout_ms, grab_banners).await;
            let n = probed_c.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(48) || n == total_jobs {
                let _ = tx_c.send(EngineEvent::ScanProgress {
                    probed: n,
                    total: total_jobs.max(1),
                    current_target: format!("{ip}:{port}"),
                    phase: "Port scan".to_string(),
                });
            }
            Some(info)
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(Some(mut pinfo)) = h.await {
            enrich_port_with_local_sockets(&mut pinfo, ip, is_local, local_sockets);
            out.push(pinfo);
        }
    }

    out.sort_by(|a, b| a.state.cmp(&b.state).then_with(|| a.port.cmp(&b.port)));
    out
}

fn enrich_port_with_local_sockets(
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

async fn read_service_banner(
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

fn summarize_http_banner(raw: &[u8]) -> String {
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

fn extract_html_title(html: &str) -> Option<String> {
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

fn summarize_tls_banner(raw: &[u8]) -> String {
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

fn extract_printable_hostname(bytes: &[u8]) -> Option<String> {
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

fn build_tls_client_hello() -> Vec<u8> {
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

fn printable_line(raw: &[u8], max_chars: usize) -> String {
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

fn hex_snippet(raw: &[u8]) -> String {
    raw.iter()
        .take(24)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

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

fn icmp_ping_blocking(
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

unsafe fn extract_cmsg_ttl(msg: &libc::msghdr) -> Option<u8> {
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

fn internet_checksum(data: &[u8]) -> u16 {
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

async fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
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

async fn mdns_reverse_lookup(ip: Ipv4Addr) -> Option<String> {
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

fn parse_dns_ptr_name(pkt: &[u8]) -> Option<String> {
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

fn skip_dns_name(pkt: &[u8], mut idx: usize) -> Option<usize> {
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

fn read_dns_name(pkt: &[u8], mut idx: usize) -> Option<String> {
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

fn make_skeleton_host(ip: Ipv4Addr, iface: &NetworkInterface, now: u64) -> Host {
    Host {
        ip,
        ipv6: None,
        hostname: None,
        nickname: None,
        mac: None,
        oui_prefix: None,
        vendor: None,
        is_randomized_mac: false,
        online: false,
        trusted: false,
        role: if iface.gateway == Some(ip) {
            crate::net::model::DeviceRole::Gateway
        } else {
            crate::net::model::DeviceRole::Host
        },
        arp_state: ArpState::Unknown,
        ttl: None,
        os_guess: None,
        rtt_ms: None,
        rtt_history: Vec::new(),
        jitter_ms: None,
        packet_loss_pct: 0.0,
        ports: Vec::new(),
        first_seen_epoch: now,
        last_seen_epoch: now,
        discovered_tick: 0,
        subnet_cidr: iface.cidr.clone(),
        interface: iface.name.clone(),
        is_new: true,
    }
}

/// Helper used by saved known-hosts sync to normalize MAC strings.
pub fn normalize_mac_opt(mac: Option<[u8; 6]>) -> Option<String> {
    mac.map(format_mac)
}
