//! Async scan orchestration, ping/WoL/socket background tasks, engine events, and exports.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::net::linux::{collect_interfaces, collect_local_sockets, epoch_now};
use crate::net::model::{ExportFormat, ScanProgress};
use crate::net::scanner::{icmp_ping_sync, run_scan, EngineEvent, ScanConfig};
use crate::net::tools::export_snapshot;

use super::App;

impl App {
    pub fn start_scan(&mut self) {
        let lang = self.lang();
        if self.demo_mode {
            self.scan_progress = ScanProgress {
                active: false,
                probed: self.snapshot.hosts.len(),
                total: self.snapshot.hosts.len(),
                hosts_found: self.snapshot.hosts.len(),
                ports_found: self
                    .snapshot
                    .hosts
                    .iter()
                    .map(|h| {
                        let (iu, op, _, _) = h.port_counts();
                        iu + op
                    })
                    .sum(),
                current_target: String::new(),
                started_at_tick: self.tick,
            };
            self.set_toast(lang.t("Demo dataset refreshed", "Jeu de données démo actualisé"));
            return;
        }

        let Some(iface) = self.active_interface().cloned() else {
            self.set_toast(lang.t("No active interface selected", "Aucune interface active"));
            return;
        };

        self.stop_scan();
        let cancel = Arc::new(AtomicBool::new(false));
        self.scan_cancel = Some(Arc::clone(&cancel));
        self.scan_progress = ScanProgress {
            active: true,
            probed: 0,
            total: 254,
            hosts_found: 0,
            ports_found: 0,
            current_target: iface.cidr.clone(),
            started_at_tick: self.tick,
        };
        self.status_message = match lang {
            crate::config::Language::En => format!("Scanning {} ({})…", iface.name, iface.cidr),
            crate::config::Language::Fr => format!("Scan de {} ({})…", iface.name, iface.cidr),
        };

        let scan_cfg = ScanConfig {
            interface: iface,
            preset: self.config.default_preset,
            custom_ports: self.config.custom_ports.clone(),
            concurrency: self.config.concurrency,
            timeout_ms: self.config.timeout_ms,
            grab_banners: self.config.grab_banners,
            privilege: self.snapshot.privilege,
            radar_page_offset: self.radar_page_offset,
            single_host: None,
            local_sockets: self.snapshot.local_sockets.clone(),
            existing_hosts: self
                .snapshot
                .hosts
                .iter()
                .map(|h| (h.ip, h.clone()))
                .collect(),
        };
        let tx = self.engine_tx.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                run_scan(scan_cfg, cancel, tx).await;
            });
        }
    }

    pub fn start_deep_scan_host(&mut self, ip: Ipv4Addr) {
        let lang = self.lang();
        if self.demo_mode {
            self.set_toast(match lang {
                crate::config::Language::En => format!("Demo deep inspect on {ip}"),
                crate::config::Language::Fr => format!("Inspection approfondie démo sur {ip}"),
            });
            return;
        }
        let Some(iface) = self.active_interface().cloned() else {
            return;
        };
        self.stop_scan();
        let cancel = Arc::new(AtomicBool::new(false));
        self.scan_cancel = Some(Arc::clone(&cancel));
        self.scan_progress = ScanProgress {
            active: true,
            probed: 0,
            total: 1,
            hosts_found: 1,
            ports_found: 0,
            current_target: ip.to_string(),
            started_at_tick: self.tick,
        };
        let scan_cfg = ScanConfig {
            interface: iface,
            preset: crate::net::model::ScanPreset::Full,
            custom_ports: self.config.custom_ports.clone(),
            concurrency: self.config.concurrency.max(256),
            timeout_ms: self.config.timeout_ms.max(300),
            grab_banners: true,
            privilege: self.snapshot.privilege,
            radar_page_offset: self.radar_page_offset,
            single_host: Some(ip),
            local_sockets: self.snapshot.local_sockets.clone(),
            existing_hosts: self
                .snapshot
                .hosts
                .iter()
                .map(|h| (h.ip, h.clone()))
                .collect(),
        };
        let tx = self.engine_tx.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                run_scan(scan_cfg, cancel, tx).await;
            });
        }
    }

    pub fn stop_scan(&mut self) {
        if let Some(flag) = self.scan_cancel.take() {
            flag.store(true, Ordering::Relaxed);
        }
        if self.scan_progress.active {
            self.scan_progress.active = false;
            self.status_message = self.lang().t("Scan stopped", "Scan interrompu").to_string();
        }
    }

    pub fn toggle_ping_host(&mut self, ip: Ipv4Addr) {
        if self.snapshot.ping_active && self.snapshot.ping_target == Some(ip) {
            self.stop_ping();
            return;
        }
        self.stop_ping();
        self.snapshot.ping_target = Some(ip);
        self.snapshot.ping_samples.clear();
        self.snapshot.ping_sent = 0;
        self.snapshot.ping_received = 0;
        self.snapshot.ping_last_rtt_ms = None;
        self.snapshot.ping_active = true;

        if self.demo_mode {
            self.set_toast(format!("Ping → {ip}"));
            return;
        }

        let cancel = Arc::new(AtomicBool::new(false));
        self.ping_cancel = Some(Arc::clone(&cancel));
        let tx = self.engine_tx.clone();
        let priv_lvl = self.snapshot.privilege;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                while !cancel.load(Ordering::Relaxed) {
                    let res = tokio::task::spawn_blocking(move || {
                        if matches!(
                            priv_lvl,
                            crate::net::model::PrivilegeLevel::Root
                                | crate::net::model::PrivilegeLevel::Capabilities
                        ) {
                            icmp_ping_sync(ip, 800).map(|(r, _)| r)
                        } else {
                            None
                        }
                    })
                    .await
                    .ok()
                    .flatten();

                    let rtt = match res {
                        Some(v) => Some(v),
                        None => {
                            let t0 = std::time::Instant::now();
                            let addr = std::net::SocketAddr::new(ip.into(), 80);
                            match tokio::time::timeout(
                                Duration::from_millis(600),
                                tokio::net::TcpStream::connect(addr),
                            )
                            .await
                            {
                                Ok(Ok(_)) => Some((t0.elapsed().as_secs_f64() * 1000.0).max(0.05)),
                                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                                    Some((t0.elapsed().as_secs_f64() * 1000.0).max(0.05))
                                }
                                _ => None,
                            }
                        }
                    };

                    let _ = tx.send(EngineEvent::PingSample {
                        target: ip,
                        rtt_ms: rtt,
                    });
                    tokio::time::sleep(Duration::from_millis(750)).await;
                }
            });
        }
    }

    pub fn stop_ping(&mut self) {
        if let Some(flag) = self.ping_cancel.take() {
            flag.store(true, Ordering::Relaxed);
        }
        self.snapshot.ping_active = false;
    }

    pub(super) fn spawn_socket_and_iface_refresh(&self) {
        if self.demo_mode {
            return;
        }
        let tx = self.engine_tx.clone();
        let show_virt = self.config.show_virtual_ifaces;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let res = tokio::task::spawn_blocking(move || {
                    let socks = collect_local_sockets(false);
                    let ifaces = collect_interfaces(show_virt);
                    (socks, ifaces)
                })
                .await;
                if let Ok((socks, ifaces)) = res {
                    let _ = tx.send(EngineEvent::SocketsUpdated(socks, ifaces));
                }
            });
        }
    }

    pub fn select_interface(&mut self, idx: usize) {
        if idx >= self.snapshot.interfaces.len() {
            return;
        }
        self.stop_scan();
        self.snapshot.active_iface_idx = idx;
        self.radar_page_offset = 0;
        self.host_scroll = 0;

        if self.demo_mode {
            let name = self.snapshot.interfaces[idx].name.clone();
            if let Some(hosts) = self.demo_ifaces_hosts.get(&name) {
                self.snapshot.hosts = hosts.clone();
            }
            self.selected_host_ip = self.snapshot.hosts.first().map(|h| h.ip);
            self.set_toast(format!("Interface: {name}"));
        } else {
            self.snapshot.hosts.clear();
            self.selected_host_ip = None;
            self.seed_initial_hosts();
            self.apply_known_hosts_to_snapshot();
            self.selected_host_ip = self.snapshot.hosts.first().map(|h| h.ip);
            self.start_scan();
        }
    }

    pub fn export_now(&mut self, fmt: ExportFormat) {
        let lang = self.lang();
        let epoch = epoch_now();
        let dir = Config::export_dir();
        let filename = format!("moonveil_{epoch}.{}", fmt.ext());
        let path = dir.join(&filename);
        match export_snapshot(&self.snapshot, fmt, &path) {
            Ok(()) => {
                self.set_toast(match lang {
                    crate::config::Language::En => format!("Exported {filename}"),
                    crate::config::Language::Fr => format!("Exporté : {filename}"),
                });
            }
            Err(e) => {
                self.set_toast(format!("Export error: {e}"));
            }
        }
    }

    pub fn apply_engine_event(&mut self, ev: EngineEvent) {
        let lang = self.lang();
        match ev {
            EngineEvent::ScanStarted { total_targets } => {
                self.scan_progress.active = true;
                self.scan_progress.total = total_targets;
                self.scan_progress.probed = 0;
            }
            EngineEvent::ScanProgress {
                probed,
                total,
                target,
            } => {
                self.scan_progress.probed = probed;
                self.scan_progress.total = total.max(1);
                self.scan_progress.current_target = target;
            }
            EngineEvent::HostUpsert(host) => {
                self.upsert_host(*host);
            }
            EngineEvent::ScanCompleted {
                hosts_found,
                ports_found,
                elapsed_ms,
            } => {
                self.scan_progress.active = false;
                self.scan_progress.probed = self.scan_progress.total;
                self.scan_progress.hosts_found = hosts_found;
                self.scan_progress.ports_found = ports_found;
                self.snapshot.last_scan_epoch = Some(epoch_now());
                self.snapshot.scan_duration_ms = Some(elapsed_ms);
                self.refresh_in_use_from_sockets();
                self.save_known_hosts_if_enabled();
                self.status_message = match lang {
                    crate::config::Language::En => {
                        format!("Scan complete • {hosts_found} hosts • {ports_found} open ports ({elapsed_ms} ms)")
                    }
                    crate::config::Language::Fr => {
                        format!("Scan terminé • {hosts_found} hôtes • {ports_found} ports ouverts ({elapsed_ms} ms)")
                    }
                };
            }
            EngineEvent::PingSample { target, rtt_ms } => {
                if self.snapshot.ping_target == Some(target) {
                    self.snapshot.ping_sent += 1;
                    if let Some(ms) = rtt_ms {
                        self.snapshot.ping_received += 1;
                        self.snapshot.ping_last_rtt_ms = Some(ms);
                        self.snapshot.ping_samples.push(ms);
                        if self.snapshot.ping_samples.len() > 36 {
                            self.snapshot.ping_samples.remove(0);
                        }
                    }
                }
            }
            EngineEvent::PingUpdate { ip, rtt_ms, .. } => {
                if self.snapshot.ping_target == Some(ip) {
                    self.snapshot.ping_sent += 1;
                    if let Some(ms) = rtt_ms {
                        self.snapshot.ping_received += 1;
                        self.snapshot.ping_last_rtt_ms = Some(ms);
                        self.snapshot.ping_samples.push(ms);
                        if self.snapshot.ping_samples.len() > 36 {
                            self.snapshot.ping_samples.remove(0);
                        }
                    }
                }
            }
            EngineEvent::TraceHop(hop) => {
                self.snapshot.traceroute_hops.push(hop);
            }
            EngineEvent::TraceComplete => {}
            EngineEvent::TracerouteResult { target, hops } => {
                self.snapshot.traceroute_target = Some(target);
                self.snapshot.traceroute_hops = hops;
            }
            EngineEvent::SocketsUpdated(socks, ifaces) => {
                self.snapshot.local_sockets = socks;
                if !ifaces.is_empty() {
                    let active_name = self.active_interface().map(|i| i.name.clone());
                    let prev = &self.snapshot.interfaces;
                    let mut updated = ifaces;
                    for iface in &mut updated {
                        if let Some(old) = prev.iter().find(|o| o.name == iface.name) {
                            let drx = iface.rx_bytes.saturating_sub(old.rx_bytes) as f64;
                            let dtx = iface.tx_bytes.saturating_sub(old.tx_bytes) as f64;
                            iface.rx_bps = drx;
                            iface.tx_bps = dtx;
                            let mut rh = old.rx_history.clone();
                            rh.push(drx);
                            if rh.len() > 24 {
                                rh.remove(0);
                            }
                            let mut th = old.tx_history.clone();
                            th.push(dtx);
                            if th.len() > 24 {
                                th.remove(0);
                            }
                            iface.rx_history = rh;
                            iface.tx_history = th;
                        }
                    }
                    self.snapshot.interfaces = updated;
                    if let Some(name) = active_name {
                        if let Some(idx) =
                            self.snapshot.interfaces.iter().position(|i| i.name == name)
                        {
                            self.snapshot.active_iface_idx = idx;
                        }
                    }
                }
                self.refresh_in_use_from_sockets();
            }
        }
    }
}
