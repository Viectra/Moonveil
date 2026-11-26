//! Orchestration réseau : lancement/arrêt des scans, ping, traceroute, exports, événements moteur et diff Watch Mode.

use super::*;

impl App {
    pub fn start_scan(&mut self, single_host: Option<Ipv4Addr>) {
        self.stop_scan();
        let Some(iface) = self.active_interface().cloned() else {
            self.set_toast(self.lang().t(
                "No active network interface selected.",
                "Aucune interface réseau active sélectionnée.",
            ));
            return;
        };

        if self.demo_mode {
            self.run_demo_scan(iface.name);
            return;
        }

        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.scan_cancel = Some(cancel.clone());
        self.scan_progress.active = true;
        self.scan_progress.phase = format!("Starting scan on {}", iface.cidr);
        self.scan_progress.probed = 0;
        self.scan_progress.total = 1;

        let existing_hosts = self
            .snapshot
            .hosts
            .iter()
            .map(|h| (h.ip, h.clone()))
            .collect();

        let cfg = ScanConfig {
            interface: iface,
            preset: self.config.default_preset,
            custom_ports: self.config.custom_ports.clone(),
            concurrency: self.config.concurrency,
            timeout_ms: self.config.timeout_ms,
            grab_banners: self.config.grab_banners,
            privilege: self.snapshot.privilege,
            radar_page_offset: self.radar_page_offset,
            single_host,
            local_sockets: self.snapshot.local_sockets.clone(),
            existing_hosts,
        };
        let tx = self.engine_tx.clone();
        rt.spawn(async move {
            run_scan(cfg, cancel, tx).await;
        });
    }

    pub(super) fn run_demo_scan(&mut self, iface_name: String) {
        let cancel = Arc::new(AtomicBool::new(false));
        self.scan_cancel = Some(cancel.clone());
        self.scan_progress.active = true;
        self.scan_progress.phase = format!("Sweeping {iface_name}");
        self.scan_progress.probed = 0;
        self.scan_progress.total = 254;

        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let tx = self.engine_tx.clone();
            rt.spawn(async move {
                let _ = tx.send(EngineEvent::ScanStarted {
                    total: 254,
                    phase: format!("Discovering hosts on {iface_name}"),
                });
                for step in (16..=254).step_by(24) {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    let _ = tx.send(EngineEvent::ScanProgress {
                        probed: step,
                        total: 254,
                        current_target: format!("192.168.1.{step}"),
                        phase: "Demo sweep".to_string(),
                    });
                    tokio::time::sleep(Duration::from_millis(45)).await;
                }
                let _ = tx.send(EngineEvent::ScanCompleted {
                    hosts_online: 13,
                    ports_open: 28,
                    duration_ms: 520,
                });
            });
        } else {
            self.scan_progress.active = false;
            self.scan_progress.last_duration_ms = Some(520);
        }
    }

    pub fn stop_scan(&mut self) {
        if let Some(c) = self.scan_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        self.scan_progress.active = false;
    }

    pub fn toggle_ping_monitor(&mut self, ip: Ipv4Addr) {
        if self.ping_target == Some(ip) {
            if let Some(c) = self.ping_cancel.take() {
                c.store(true, Ordering::Relaxed);
            }
            self.ping_target = None;
            self.set_toast(if self.lang().is_fr() {
                format!("Moniteur ping arrêté pour {ip}")
            } else {
                format!("Stopped ping monitor for {ip}")
            });
            return;
        }
        if let Some(c) = self.ping_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        self.ping_target = Some(ip);
        self.set_toast(if self.lang().is_fr() {
            format!("Moniteur ping en direct actif -> {ip}")
        } else {
            format!("Live Ping monitor active -> {ip}")
        });
        if self.demo_mode {
            return;
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let cancel = Arc::new(AtomicBool::new(false));
            self.ping_cancel = Some(cancel.clone());
            let priv_level = self.snapshot.privilege;
            let tx = self.engine_tx.clone();
            rt.spawn(async move {
                run_ping_monitor(ip, priv_level, cancel, tx).await;
            });
        }
    }

    pub fn launch_traceroute(&mut self, ip: Ipv4Addr) {
        if let Some(c) = self.trace_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        self.trace_hops.clear();
        self.modal = Modal::Traceroute { ip };
        if self.demo_mode {
            self.trace_hops = demo_traceroute(ip);
            self.trace_running = false;
            return;
        }
        self.trace_running = true;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let cancel = Arc::new(AtomicBool::new(false));
            self.trace_cancel = Some(cancel.clone());
            let tx = self.engine_tx.clone();
            rt.spawn(async move {
                run_traceroute(ip, 16, cancel, tx).await;
            });
        }
    }

    pub fn toggle_trusted(&mut self, ip: Ipv4Addr) {
        let mut saved_record = None;
        let mut toast_msg = None;
        if let Some(h) = self.snapshot.hosts.iter_mut().find(|h| h.ip == ip) {
            h.trusted = !h.trusted;
            h.is_new = !h.trusted && h.online;
            if let Some(mac) = h.mac {
                let mac_s = format_mac(mac);
                saved_record = Some((
                    mac_s,
                    h.ip,
                    h.nickname.clone(),
                    h.trusted,
                    h.vendor.clone(),
                    h.hostname.clone(),
                ));
            }
            let lang = self.config.language;
            toast_msg = Some(format!(
                "{} {} {}",
                h.display_name(),
                lang.t("marked", "marqué"),
                if h.trusted {
                    lang.t("Trusted ★", "De confiance ★")
                } else {
                    lang.t("Untrusted !", "Non fiable !")
                }
            ));
        }
        if let Some(msg) = toast_msg {
            self.set_toast(msg);
        }
        if let Some((mac_s, ip, nick, trusted, vend, host)) = saved_record {
            self.known_hosts
                .upsert(&mac_s, ip, nick, trusted, vend, host);
            self.save_known_hosts();
        }
    }

    pub fn export_now(&mut self, fmt: ExportFormat) -> Result<PathBuf, String> {
        let dir = Config::export_dir();
        let filename = format!("moonveil-{}.{}", epoch_now(), fmt.ext());
        let path = dir.join(filename);
        export_snapshot(&self.snapshot, fmt, &path)?;
        let msg = format!(
            "{} {} -> {}",
            self.lang().t("Exported", "Exporté"),
            fmt.label(),
            path.display()
        );
        self.push_event(EventKind::Action, None, msg.clone());
        self.set_toast(msg);
        Ok(path)
    }
}

impl App {
    pub(super) fn apply_engine_event(&mut self, ev: EngineEvent) {
        match ev {
            EngineEvent::ScanStarted { total, phase } => {
                self.scan_progress.active = true;
                self.scan_progress.total = total.max(1);
                self.scan_progress.probed = 0;
                self.scan_progress.phase = phase;
            }
            EngineEvent::ScanProgress {
                probed,
                total,
                current_target,
                phase,
            } => {
                self.scan_progress.probed = probed;
                self.scan_progress.total = total.max(1);
                self.scan_progress.current_target = current_target;
                self.scan_progress.phase = phase;
            }
            EngineEvent::HostUpsert(mut host) => {
                host.discovered_tick = self.tick_count;
                apply_single_known_metadata(&mut host, &self.known_hosts);
                if let Some(existing) = self.snapshot.hosts.iter_mut().find(|h| h.ip == host.ip) {
                    let prev_hist = existing.rtt_history.clone();
                    if host.rtt_history.len() <= 1 && !prev_hist.is_empty() {
                        host.rtt_history = prev_hist;
                        if let Some(r) = host.rtt_ms {
                            host.rtt_history.push(r);
                        }
                    }
                    *existing = *host;
                } else {
                    if self.selected_host_ip.is_none() {
                        self.selected_host_ip = Some(host.ip);
                    }
                    self.snapshot.hosts.push(*host);
                }
            }
            EngineEvent::ScanCompleted {
                hosts_online,
                ports_open,
                duration_ms,
            } => {
                self.scan_progress.active = false;
                self.scan_progress.probed = self.scan_progress.total;
                self.scan_progress.hosts_found = hosts_online;
                self.scan_progress.ports_found = ports_open;
                self.scan_progress.last_duration_ms = Some(duration_ms);
                self.last_watch_scan = Instant::now();
                self.diff_watch_events();
                self.push_event(
                    EventKind::ScanFinished,
                    None,
                    format!(
                        "Scan complete: {hosts_online} online, {ports_open} open/in-use ports ({duration_ms}ms)"
                    ),
                );
                self.set_toast(if self.lang().is_fr() {
                    format!(
                        "Scan terminé : {hosts_online} hôtes, {ports_open} ports ouverts ({duration_ms}ms)"
                    )
                } else {
                    format!(
                        "Scan done: {hosts_online} hosts, {ports_open} open ports ({duration_ms}ms)"
                    )
                });
            }
            EngineEvent::PingUpdate { ip, rtt_ms, ttl } => {
                if let Some(h) = self.snapshot.hosts.iter_mut().find(|h| h.ip == ip) {
                    if let Some(r) = rtt_ms {
                        h.online = true;
                        h.rtt_ms = Some(r);
                        h.rtt_history.push(r);
                        if h.rtt_history.len() > 40 {
                            h.rtt_history.remove(0);
                        }
                    }
                    if let Some(t) = ttl {
                        h.ttl = Some(t);
                    }
                }
            }
            EngineEvent::TraceHop(hop) => {
                self.trace_hops.push(hop);
            }
            EngineEvent::TraceComplete => {
                self.trace_running = false;
            }
            EngineEvent::TelemetryUpdate {
                interfaces,
                local_sockets,
            } => {
                self.telemetry_inflight = false;
                self.snapshot.interfaces = interfaces;
                self.snapshot.local_sockets = local_sockets;
                refresh_in_use_from_sockets(&mut self.snapshot);
            }
            EngineEvent::StatusToast(msg) => self.set_toast(msg),
        }
    }

    pub(super) fn record_baseline_for_watch(&mut self) {
        self.prev_online_set = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| h.online)
            .map(|h| h.ip)
            .collect();
        self.prev_open_ports.clear();
        for h in &self.snapshot.hosts {
            let ports: HashSet<u16> = h
                .ports
                .iter()
                .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
                .map(|p| p.port)
                .collect();
            self.prev_open_ports.insert(h.ip, ports);
        }
    }

    pub(super) fn diff_watch_events(&mut self) {
        let mut new_online = HashSet::new();
        let mut events = Vec::new();
        for h in &self.snapshot.hosts {
            if h.online {
                new_online.insert(h.ip);
                if !self.prev_online_set.contains(&h.ip) {
                    let kind = if h.trusted {
                        EventKind::HostJoined
                    } else {
                        EventKind::UnknownIntruder
                    };
                    events.push((
                        kind,
                        Some(h.ip),
                        format!(
                            "{} ({}) joined {}",
                            h.ip,
                            h.vendor.as_deref().unwrap_or("unknown vendor"),
                            h.interface
                        ),
                    ));
                }
                let cur_ports: HashSet<u16> = h
                    .ports
                    .iter()
                    .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
                    .map(|p| p.port)
                    .collect();
                if let Some(prev_p) = self.prev_open_ports.get(&h.ip) {
                    for p in cur_ports.difference(prev_p) {
                        events.push((
                            EventKind::PortOpened,
                            Some(h.ip),
                            format!("Port {p} opened on {}", h.ip),
                        ));
                    }
                    for p in prev_p.difference(&cur_ports) {
                        events.push((
                            EventKind::PortClosed,
                            Some(h.ip),
                            format!("Port {p} closed on {}", h.ip),
                        ));
                    }
                }
            }
        }
        for old_ip in &self.prev_online_set {
            if !new_online.contains(old_ip) {
                events.push((
                    EventKind::HostLeft,
                    Some(*old_ip),
                    format!("Host {old_ip} went offline"),
                ));
            }
        }
        for (k, ip, s) in events {
            self.push_event(k, ip, s);
        }
        self.record_baseline_for_watch();
    }
}
