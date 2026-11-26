//! Construction de `App`, accesseurs d'état (filtres, sélection, interfaces), persistance, toasts et tick d'animation.

use super::*;

impl App {
    /// Initializes Moonveil in live Linux mode or simulated `--demo` mode.
    pub fn new(config: Config, demo_mode: bool, initial_iface: Option<&str>) -> Self {
        let (engine_tx, engine_rx) = mpsc::unbounded_channel();
        let known_hosts = KnownHostStore::load();
        let palette = Palette::from_config(config.theme, config.accent);

        let (mut snapshot, timeline) = if demo_mode {
            build_demo_snapshot()
        } else {
            let (username, hostname) = read_user_and_host();
            let privilege = detect_privilege();
            let interfaces = collect_interfaces(&[], 1.0);
            let local_sockets = collect_local_sockets(true);
            let mut snap = NetworkSnapshot {
                hostname,
                username,
                privilege,
                interfaces,
                local_sockets,
                hosts: Vec::new(),
            };
            seed_initial_hosts(&mut snap, &known_hosts);
            (snap, Vec::new())
        };

        apply_known_metadata(&mut snapshot.hosts, &known_hosts);

        let mut selected_iface_idx = 0;
        if let Some(target_name) = initial_iface {
            if let Some(idx) = snapshot
                .interfaces
                .iter()
                .position(|i| i.name == target_name)
            {
                selected_iface_idx = idx;
            }
        } else if let Some(idx) = snapshot
            .interfaces
            .iter()
            .position(|i| i.is_up && !i.is_virtual && i.gateway.is_some() && i.ipv4.is_some())
            .or_else(|| {
                snapshot
                    .interfaces
                    .iter()
                    .position(|i| i.is_up && !i.is_virtual && i.ipv4.is_some())
            })
        {
            selected_iface_idx = idx;
        }

        let selected_host_ip = snapshot.hosts.first().map(|h| h.ip);
        let splash_until = if config.splash && config.animations {
            Some(Instant::now() + Duration::from_millis(650))
        } else {
            None
        };

        let mut app = Self {
            config,
            known_hosts,
            palette,
            tab: Tab::Hosts,
            demo_mode,
            snapshot,
            selected_iface_idx,
            selected_host_ip,
            search_query: String::new(),
            search_focused: false,
            host_sort: HostSortColumn::Ip,
            host_sort_desc: false,
            host_scroll: 0,
            port_filter: PortFilter::All,
            port_scroll: 0,
            show_closed_ports: false,
            show_inspector_on_compact: false,
            radar_selected_octet: 1,
            radar_page_offset: 0,
            radar_role_filter: None,
            socket_filter: SocketFilter::All,
            socket_search: String::new(),
            socket_search_focused: false,
            socket_scroll: 0,
            net_iface_scroll: 0,
            timeline,
            timeline_scroll: 0,
            saved_scroll: 0,
            settings_scroll: 0,
            watch_mode: false,
            last_watch_scan: Instant::now(),
            scan_progress: Default::default(),
            scan_cancel: None,
            ping_target: None,
            ping_cancel: None,
            trace_hops: Vec::new(),
            trace_running: false,
            trace_cancel: None,
            modal: Modal::None,
            toast: None,
            tick_count: 0,
            splash_until,
            hover: None,
            last_click: None,
            hits: HitRegistry::default(),
            persist_state: true,
            should_quit: false,
            engine_tx,
            engine_rx,
            last_telemetry_at: Instant::now(),
            telemetry_cycle: 0,
            telemetry_inflight: false,
            prev_online_set: HashSet::new(),
            prev_open_ports: HashMap::new(),
        };

        app.record_baseline_for_watch();
        app
    }

    pub fn is_splash_active(&self) -> bool {
        self.splash_until
            .is_some_and(|until| Instant::now() < until)
    }

    pub(super) fn save_config(&self) {
        if self.persist_state {
            let _ = self.config.save();
        }
    }

    pub(super) fn save_known_hosts(&self) {
        if self.persist_state {
            let _ = self.known_hosts.save();
        }
    }

    pub fn pulse_phase(&self) -> f64 {
        if !self.config.animations {
            return 1.0;
        }
        let rad = (self.tick_count as f64) * 0.22;
        (rad.cos() + 1.0) * 0.5
    }

    pub fn visible_interfaces(&self) -> Vec<(usize, &NetworkInterface)> {
        let mut list: Vec<(usize, &NetworkInterface)> = self
            .snapshot
            .interfaces
            .iter()
            .enumerate()
            .filter(|(_, i)| self.config.show_virtual_ifaces || !i.is_virtual)
            .collect();
        if list.is_empty() {
            list = self.snapshot.interfaces.iter().enumerate().collect();
        }
        list
    }

    pub fn active_interface(&self) -> Option<&NetworkInterface> {
        self.snapshot
            .interfaces
            .get(self.selected_iface_idx)
            .or_else(|| self.snapshot.interfaces.first())
    }

    pub fn filtered_hosts(&self) -> Vec<&Host> {
        let active_name = self.active_interface().map(|i| i.name.as_str());
        let mut hosts: Vec<&Host> = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| {
                active_name.is_none_or(|name| h.interface == name || h.interface.is_empty())
            })
            .filter(|h| h.matches_query(&self.search_query))
            .collect();

        hosts.sort_by(|a, b| {
            let ord = match self.host_sort {
                HostSortColumn::Ip => a.ip.cmp(&b.ip),
                HostSortColumn::Name => a
                    .display_name()
                    .to_ascii_lowercase()
                    .cmp(&b.display_name().to_ascii_lowercase()),
                HostSortColumn::Vendor => a
                    .vendor
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .cmp(&b.vendor.as_deref().unwrap_or("").to_ascii_lowercase()),
                HostSortColumn::Rtt => {
                    let ra = a.rtt_ms.unwrap_or(f64::MAX);
                    let rb = b.rtt_ms.unwrap_or(f64::MAX);
                    ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
                }
                HostSortColumn::OpenPorts => {
                    let (_, oa, _, _) = a.port_counts();
                    let (_, ob, _, _) = b.port_counts();
                    oa.cmp(&ob).then_with(|| a.ip.cmp(&b.ip))
                }
                HostSortColumn::InUsePorts => {
                    let (ia, _, _, _) = a.port_counts();
                    let (ib, _, _, _) = b.port_counts();
                    ia.cmp(&ib).then_with(|| a.ip.cmp(&b.ip))
                }
            };
            if self.host_sort_desc {
                ord.reverse()
            } else {
                ord
            }
        });
        hosts
    }

    pub fn selected_host(&self) -> Option<&Host> {
        self.selected_host_ip
            .and_then(|ip| self.snapshot.hosts.iter().find(|h| h.ip == ip))
            .or_else(|| self.filtered_hosts().into_iter().next())
    }

    /// Active UI language from the persisted configuration.
    pub const fn lang(&self) -> Language {
        self.config.language
    }

    pub fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now() + Duration::from_secs(4)));
    }

    pub fn push_event(
        &mut self,
        kind: EventKind,
        ip: Option<Ipv4Addr>,
        summary: impl Into<String>,
    ) {
        self.timeline.push(TimelineEvent {
            timestamp: format_clock_now(),
            kind,
            ip,
            summary: summary.into(),
        });
        if self.timeline.len() > 250 {
            self.timeline.remove(0);
        }
    }
}

impl App {
    /// Advances background engine events, animations, and periodic telemetry; returns `true` when UI should redraw.
    pub fn on_tick(&mut self) -> bool {
        let mut dirty = false;
        self.tick_count = self.tick_count.wrapping_add(1);
        if let Some((_, until)) = &self.toast {
            if Instant::now() >= *until {
                self.toast = None;
                dirty = true;
            }
        }
        if let Some(until) = self.splash_until {
            if Instant::now() >= until {
                self.splash_until = None;
                dirty = true;
            } else if self.config.animations {
                dirty = true;
            }
        }

        while let Ok(ev) = self.engine_rx.try_recv() {
            self.apply_engine_event(ev);
            dirty = true;
        }

        if self.scan_progress.active && self.config.animations {
            dirty = true;
        }

        let interval = if self.demo_mode {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(1500)
        };
        if self.last_telemetry_at.elapsed() >= interval {
            let dt = self.last_telemetry_at.elapsed().as_secs_f64();
            self.last_telemetry_at = Instant::now();
            self.telemetry_cycle += 1;

            if self.demo_mode {
                tick_demo_snapshot(&mut self.snapshot, self.tick_count);
                dirty = true;
            } else if !self.telemetry_inflight {
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    self.telemetry_inflight = true;
                    let prev_ifaces = self.snapshot.interfaces.clone();
                    let resolve_pids = self.telemetry_cycle.is_multiple_of(2);
                    let tx = self.engine_tx.clone();
                    rt.spawn_blocking(move || {
                        let interfaces = collect_interfaces(&prev_ifaces, dt);
                        let local_sockets = collect_local_sockets(resolve_pids);
                        let _ = tx.send(EngineEvent::TelemetryUpdate {
                            interfaces,
                            local_sockets,
                        });
                    });
                } else {
                    self.snapshot.interfaces = collect_interfaces(&self.snapshot.interfaces, dt);
                    let resolve_pids = self.telemetry_cycle.is_multiple_of(2);
                    self.snapshot.local_sockets = collect_local_sockets(resolve_pids);
                    refresh_in_use_from_sockets(&mut self.snapshot);
                    dirty = true;
                }
            }
        }

        if self.watch_mode
            && !self.scan_progress.active
            && self.last_watch_scan.elapsed()
                >= Duration::from_secs(self.config.watch_interval_secs.max(5))
        {
            self.last_watch_scan = Instant::now();
            self.start_scan(None);
            dirty = true;
        }

        dirty
    }
}

pub(super) fn format_clock_now() -> String {
    let secs = epoch_now() % 86_400;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
