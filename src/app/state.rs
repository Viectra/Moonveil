//! App initialization, accessors, configuration persistence, and animation ticks.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use tokio::sync::mpsc;

use crate::config::{Config, KnownHostStore, Language};
use crate::net::demo::{build_demo_snapshot, tick_demo_snapshot};
use crate::net::linux::{
    collect_interfaces, collect_local_sockets, detect_privilege, read_user_and_host,
};
use crate::net::model::{Host, HostSortColumn, NetworkInterface, NetworkSnapshot, ScanProgress};
use crate::ui::hit::HitRegistry;

use super::{App, Modal, Tab};

impl App {
    /// Constructs a new `App` for either live Linux scanning or deterministic `--demo` mode.
    pub fn new(config: Config, demo_mode: bool, iface_filter: Option<&str>) -> Self {
        let (engine_tx, engine_rx) = mpsc::unbounded_channel();
        let known_hosts = KnownHostStore::load();

        let (mut snapshot, demo_ifaces_hosts) = if demo_mode {
            build_demo_snapshot()
        } else {
            let interfaces = collect_interfaces(config.show_virtual_ifaces);
            let privilege = detect_privilege();
            let (username, hostname) = read_user_and_host();
            let local_sockets = collect_local_sockets(false);

            let snap = NetworkSnapshot {
                interfaces,
                active_iface_idx: 0,
                hosts: Vec::new(),
                local_sockets,
                events: Vec::new(),
                privilege,
                username,
                hostname,
                last_scan_epoch: None,
                scan_duration_ms: None,
                traceroute_target: None,
                traceroute_hops: Vec::new(),
                ping_target: None,
                ping_samples: Vec::new(),
                ping_sent: 0,
                ping_received: 0,
                ping_last_rtt_ms: None,
                ping_active: false,
            };
            (snap, HashMap::new())
        };

        if let Some(wanted) = iface_filter {
            if let Some(idx) = snapshot
                .interfaces
                .iter()
                .position(|i| i.name.eq_ignore_ascii_case(wanted))
            {
                snapshot.active_iface_idx = idx;
                if demo_mode {
                    let name = snapshot.interfaces[idx].name.clone();
                    if let Some(h) = demo_ifaces_hosts.get(&name) {
                        snapshot.hosts = h.clone();
                    }
                }
            }
        }

        let lang = config.language;
        let splash_ticks = if config.splash { 18 } else { 0 };
        let initial_status = if demo_mode {
            lang.t(
                "Demo mode • Click hosts or radar tiles to inspect",
                "Mode démo • Cliquez sur un hôte ou une tuile radar",
            )
            .to_string()
        } else {
            lang.t(
                "Ready • Press s or click Scan",
                "Prêt • Appuyez sur s ou Scanner",
            )
            .to_string()
        };

        let mut app = Self {
            config,
            demo_mode,
            snapshot,
            demo_ifaces_hosts,
            tab: Tab::Hosts,
            modal: Modal::None,
            selected_host_ip: None,
            host_scroll: 0,
            host_sort: HostSortColumn::Ip,
            host_sort_desc: false,
            port_filter: Default::default(),
            selected_port_idx: 0,
            port_scroll: 0,
            show_closed_ports: false,
            search_focused: false,
            search_query: String::new(),
            radar_page_offset: 0,
            radar_selected_octet: 1,
            tick: 0,
            splash_ticks_remaining: splash_ticks,
            status_message: initial_status,
            toast: None,
            should_quit: false,
            persist_state: true,
            watch_enabled: false,
            scan_progress: ScanProgress::default(),
            hits: HitRegistry::default(),
            known_hosts,
            engine_tx,
            engine_rx,
            scan_cancel: None,
            ping_cancel: None,
            last_socket_refresh_tick: 0,
            host_last_click: None,
        };

        app.seed_initial_hosts();
        app.apply_known_hosts_to_snapshot();
        app.selected_host_ip = app.snapshot.hosts.first().map(|h| h.ip);
        if let Some(ip) = app.selected_host_ip {
            app.radar_selected_octet = ip.octets()[3];
        }
        app
    }

    #[inline]
    pub fn lang(&self) -> Language {
        self.config.language
    }

    #[inline]
    pub fn is_splash_active(&self) -> bool {
        self.splash_ticks_remaining > 0
    }

    pub fn pulse_phase(&self) -> f64 {
        if !self.config.animations {
            return 0.0;
        }
        ((self.tick % 40) as f64) / 40.0
    }

    pub fn active_interface(&self) -> Option<&NetworkInterface> {
        self.snapshot.interfaces.get(self.snapshot.active_iface_idx)
    }

    pub fn selected_host(&self) -> Option<&Host> {
        let ip = self.selected_host_ip?;
        self.snapshot.hosts.iter().find(|h| h.ip == ip)
    }

    /// Returns hosts filtered by `search_query` and sorted according to `host_sort` / `host_sort_desc`.
    pub fn filtered_hosts(&self) -> Vec<&Host> {
        let mut list: Vec<&Host> = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| h.matches_query(&self.search_query))
            .collect();

        let lang = self.lang();
        list.sort_by(|a, b| {
            let ord = match self.host_sort {
                HostSortColumn::Ip => a.ip.cmp(&b.ip),
                HostSortColumn::Device => a
                    .display_name_for(lang)
                    .to_ascii_lowercase()
                    .cmp(&b.display_name_for(lang).to_ascii_lowercase()),
                HostSortColumn::Vendor => a
                    .vendor
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .cmp(&b.vendor.as_deref().unwrap_or("").to_ascii_lowercase()),
                HostSortColumn::Rtt => {
                    let ar = a.rtt_ms.unwrap_or(f64::MAX);
                    let br = b.rtt_ms.unwrap_or(f64::MAX);
                    ar.partial_cmp(&br).unwrap_or(std::cmp::Ordering::Equal)
                }
                HostSortColumn::OpenPorts => {
                    let (aiu, aop, _, _) = a.port_counts();
                    let (biu, bop, _, _) = b.port_counts();
                    (aiu + aop).cmp(&(biu + bop))
                }
            };
            let ordered = if self.host_sort_desc {
                ord.reverse()
            } else {
                ord
            };
            ordered.then_with(|| a.ip.cmp(&b.ip))
        });
        list
    }

    pub fn select_host(&mut self, ip: Ipv4Addr) {
        self.selected_host_ip = Some(ip);
        self.radar_selected_octet = ip.octets()[3];
        self.selected_port_idx = 0;
        self.port_scroll = 0;
    }

    pub fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), 18));
    }

    pub(super) fn save_config_if_enabled(&self) {
        if self.persist_state {
            let _ = self.config.save();
        }
    }

    pub(super) fn save_known_hosts_if_enabled(&self) {
        if self.persist_state {
            let _ = self.known_hosts.save();
        }
    }

    /// Advances animations, demo waveforms, splash countdown, toast decay, and incoming engine events.
    pub fn on_tick(&mut self) -> bool {
        let mut changed = false;
        self.tick = self.tick.wrapping_add(1);

        if self.splash_ticks_remaining > 0 {
            self.splash_ticks_remaining -= 1;
            changed = true;
        }

        if let Some((_, ttl)) = &mut self.toast {
            if *ttl > 0 {
                *ttl -= 1;
                if *ttl == 0 {
                    self.toast = None;
                }
                changed = true;
            }
        }

        while let Ok(ev) = self.engine_rx.try_recv() {
            self.apply_engine_event(ev);
            changed = true;
        }

        if self.demo_mode && self.tick.is_multiple_of(4) && self.config.animations {
            tick_demo_snapshot(&mut self.snapshot, self.tick);
            changed = true;
        } else if !self.demo_mode && self.tick.saturating_sub(self.last_socket_refresh_tick) >= 10 {
            self.last_socket_refresh_tick = self.tick;
            self.spawn_socket_and_iface_refresh();
        }

        if self.config.animations && (self.scan_progress.active || self.snapshot.ping_active) {
            changed = true;
        }
        changed
    }
}
