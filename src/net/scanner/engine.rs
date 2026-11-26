//! Orchestration du scan : calcul des cibles, boucle `run_scan` et scan concurrent des ports par hôte.

use super::*;

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
pub(super) async fn scan_host_ports(
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
