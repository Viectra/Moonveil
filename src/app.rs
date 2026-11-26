//! Application state controller: event loop ticks, mouse/key handling, and async scan orchestration.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use tokio::sync::mpsc;

use crate::config::{Config, KnownHostStore};
use crate::net::demo::{build_demo_snapshot, tick_demo_snapshot};
use crate::net::linux::{
    collect_interfaces, collect_local_sockets, detect_privilege, epoch_now, network_addr,
    prefix_mask, read_arp_entries, read_etc_hosts, read_tailscale_peers, read_user_and_host,
};
use crate::net::model::{
    clean_discovered_hostname, format_mac, format_oui, infer_device_role, parse_mac,
    parse_port_expr, ArpState, DeviceRole, ExportFormat, Host, HostSortColumn, NetworkInterface,
    NetworkSnapshot, PortFilter, PortState, ScanPreset,
};
use crate::net::oui::lookup_vendor;
use crate::net::scanner::{run_scan, EngineEvent, ScanConfig};
use crate::net::tools::{copy_osc52, export_snapshot};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::theme::Palette;

/// Primary workspace view tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Hosts,
    Radar,
    Settings,
}

impl Tab {
    pub const ALL: &'static [Self] = &[Self::Hosts, Self::Radar, Self::Settings];

    pub const fn icon(self) -> &'static str {
        match self {
            Self::Hosts => "●",
            Self::Radar => "⊞",
            Self::Settings => "◆",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Hosts => "Devices",
            Self::Radar => "Subnet Map",
            Self::Settings => "Settings",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Hosts => "Devices",
            Self::Radar => "Radar",
            Self::Settings => "Settings",
        }
    }
}

/// Active floating modal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    None,
    Help,
    RenameHost {
        ip: Ipv4Addr,
        input: String,
    },
    CustomPorts {
        input: String,
        error: Option<String>,
    },
}

/// Root Moonveil application state.
pub struct App {
    pub config: Config,
    pub known_hosts: KnownHostStore,
    pub palette: Palette,
    pub tab: Tab,
    pub demo_mode: bool,
    pub snapshot: NetworkSnapshot,
    pub selected_iface_idx: usize,
    pub selected_host_ip: Option<Ipv4Addr>,
    pub search_query: String,
    pub search_focused: bool,
    pub host_sort: HostSortColumn,
    pub host_sort_desc: bool,
    pub host_scroll: usize,
    pub port_filter: PortFilter,
    pub port_scroll: usize,
    pub radar_selected_octet: u8,
    pub radar_page_offset: u32,
    pub settings_scroll: usize,
    pub scan_progress: crate::net::model::ScanProgress,
    pub scan_cancel: Option<Arc<AtomicBool>>,
    pub modal: Modal,
    pub toast: Option<(String, Instant)>,
    pub tick_count: u64,
    pub splash_until: Option<Instant>,
    pub hover: Option<(u16, u16)>,
    pub hits: HitRegistry,
    pub persist_state: bool,
    pub should_quit: bool,
    pub engine_tx: mpsc::UnboundedSender<EngineEvent>,
    pub engine_rx: mpsc::UnboundedReceiver<EngineEvent>,
    pub last_telemetry_at: Instant,
    pub telemetry_cycle: u64,
    telemetry_inflight: bool,
}

impl App {
    /// Initializes Moonveil in live Linux mode or simulated `--demo` mode.
    pub fn new(config: Config, demo_mode: bool, initial_iface: Option<&str>) -> Self {
        let (engine_tx, engine_rx) = mpsc::unbounded_channel();
        let known_hosts = KnownHostStore::load();
        let palette = Palette::from_config(config.theme, config.accent);

        let mut snapshot = if demo_mode {
            build_demo_snapshot().0
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
            snap
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
            selected_host_ip: None,
            search_query: String::new(),
            search_focused: false,
            host_sort: HostSortColumn::Ip,
            host_sort_desc: false,
            host_scroll: 0,
            port_filter: PortFilter::Open,
            port_scroll: 0,
            radar_selected_octet: 1,
            radar_page_offset: 0,
            settings_scroll: 0,
            scan_progress: Default::default(),
            scan_cancel: None,
            modal: Modal::None,
            toast: None,
            tick_count: 0,
            splash_until,
            hover: None,
            hits: HitRegistry::default(),
            persist_state: true,
            should_quit: false,
            engine_tx,
            engine_rx,
            last_telemetry_at: Instant::now(),
            telemetry_cycle: 0,
            telemetry_inflight: false,
        };

        app.selected_host_ip = app
            .filtered_hosts()
            .first()
            .map(|h| h.ip)
            .or_else(|| app.snapshot.hosts.first().map(|h| h.ip));
        app
    }

    pub fn is_splash_active(&self) -> bool {
        self.splash_until
            .is_some_and(|until| Instant::now() < until)
    }

    fn save_config(&self) {
        if self.persist_state {
            let _ = self.config.save();
        }
    }

    fn save_known_hosts(&self) {
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
                    let (ia, oa, _, _) = a.port_counts();
                    let (ib, ob, _, _) = b.port_counts();
                    (ia + oa).cmp(&(ib + ob)).then_with(|| a.ip.cmp(&b.ip))
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

    pub fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now() + Duration::from_secs(4)));
    }

    /// Starts a subnet sweep (or single-host probe) using the user's selected preset.
    pub fn start_scan(&mut self, single_host: Option<Ipv4Addr>) {
        self.start_scan_with_preset(single_host, self.config.default_preset);
    }

    /// Deep scans a specific device across `ScanPreset::Full` (1,000+ ports) and opens the Open filter.
    pub fn start_deep_scan_host(&mut self, ip: Ipv4Addr) {
        self.port_filter = PortFilter::Open;
        self.port_scroll = 0;
        self.start_scan_with_preset(Some(ip), ScanPreset::Full);
        self.set_toast(format!("Deep scanning 1,000+ ports on {ip}…"));
    }

    fn start_scan_with_preset(&mut self, single_host: Option<Ipv4Addr>, preset: ScanPreset) {
        self.stop_scan();
        let Some(iface) = self.active_interface().cloned() else {
            self.set_toast("No active network interface selected.");
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
        self.scan_progress.phase = if let Some(ip) = single_host {
            format!("Deep scanning {ip}")
        } else {
            format!("Scanning {}", iface.cidr)
        };
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
            preset,
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

    fn run_demo_scan(&mut self, iface_name: String) {
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

    pub fn export_now(&mut self, fmt: ExportFormat) -> Result<PathBuf, String> {
        let dir = Config::export_dir();
        let filename = format!("moonveil-{}.{}", epoch_now(), fmt.ext());
        let path = dir.join(filename);
        export_snapshot(&self.snapshot, fmt, &path)?;
        let msg = format!("Exported {} -> {}", fmt.label(), path.display());
        self.set_toast(msg);
        Ok(path)
    }

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

        dirty
    }

    fn apply_engine_event(&mut self, ev: EngineEvent) {
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
                self.set_toast(format!(
                    "Scan complete: {hosts_online} devices, {ports_open} open ports ({duration_ms}ms)"
                ));
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
            _ => {}
        }
    }

    /// Handles keyboard input across modals, search bars, and global navigation.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.splash_until.is_some() {
            self.splash_until = None;
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        // Modal keyboard capture
        match &mut self.modal {
            Modal::None => {}
            Modal::Help => {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?')
                ) {
                    self.modal = Modal::None;
                }
                return;
            }
            Modal::RenameHost { ip, input } => {
                let target_ip = *ip;
                match key.code {
                    KeyCode::Esc => self.modal = Modal::None,
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Enter => {
                        let new_nick = input.trim().to_string();
                        self.apply_host_nickname(target_ip, new_nick);
                        self.modal = Modal::None;
                    }
                    KeyCode::Char(c) => input.push(c),
                    _ => {}
                }
                return;
            }
            Modal::CustomPorts { input, error } => {
                match key.code {
                    KeyCode::Esc => self.modal = Modal::None,
                    KeyCode::Backspace => {
                        input.pop();
                        *error = None;
                    }
                    KeyCode::Enter => {
                        let expr = input.clone();
                        match parse_port_expr(&expr) {
                            Ok(ports) => {
                                self.config.custom_ports = expr;
                                self.config.default_preset = ScanPreset::Custom;
                                self.save_config();
                                self.modal = Modal::None;
                                self.set_toast(format!(
                                    "Custom preset set ({} ports)",
                                    ports.len()
                                ));
                            }
                            Err(err) => {
                                *error = Some(err);
                            }
                        }
                    }
                    KeyCode::Char(c) => {
                        input.push(c);
                        *error = None;
                    }
                    _ => {}
                }
                return;
            }
        }

        // Focused search input
        if self.search_focused {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.search_focused = false;
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                    self.host_scroll = 0;
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    self.host_scroll = 0;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::Char('1') => self.tab = Tab::Hosts,
            KeyCode::Char('2') => self.tab = Tab::Radar,
            KeyCode::Char('3') => self.tab = Tab::Settings,
            KeyCode::Tab => {
                let idx = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
                self.tab = Tab::ALL[(idx + 1) % Tab::ALL.len()];
            }
            KeyCode::BackTab => {
                let idx = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
                self.tab = Tab::ALL[(idx + Tab::ALL.len() - 1) % Tab::ALL.len()];
            }
            KeyCode::Char('s') => self.handle_click_action(ClickAction::StartOrStopScan),
            KeyCode::Char('p') => self.handle_click_action(ClickAction::CyclePreset),
            KeyCode::Char('/') => {
                self.tab = Tab::Hosts;
                self.search_focused = true;
            }
            KeyCode::Esc => {
                if !self.search_query.is_empty() {
                    self.search_query.clear();
                }
            }
            KeyCode::Char('n') => {
                if let Some(ip) = self.selected_host().map(|h| h.ip) {
                    self.handle_click_action(ClickAction::OpenRenameModal(ip));
                }
            }
            KeyCode::Char('e') => {
                let _ = self.export_now(ExportFormat::Json);
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let ips: Vec<Ipv4Addr> = self.filtered_hosts().iter().map(|h| h.ip).collect();
        if ips.is_empty() {
            return;
        }
        let cur = self
            .selected_host_ip
            .and_then(|ip| ips.iter().position(|x| *x == ip))
            .unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, (ips.len() - 1) as i32) as usize;
        self.selected_host_ip = Some(ips[next]);
        self.port_scroll = 0;
        if next < self.host_scroll {
            self.host_scroll = next;
        } else if next >= self.host_scroll + 10 {
            self.host_scroll = next.saturating_sub(9);
        }
    }

    /// Handles mouse clicks, hover movement, and scroll wheel events; returns `true` if redraw is needed.
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> bool {
        let pos = (mouse.column, mouse.row);
        let moved = self.hover != Some(pos);
        self.hover = Some(pos);
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if self.splash_until.is_some() {
                    self.splash_until = None;
                    return true;
                }
                self.search_focused = false;
                if let Some(action) = self.hits.hit_test(mouse.column, mouse.row) {
                    self.handle_click_action(action);
                }
                true
            }
            MouseEventKind::ScrollUp => {
                self.handle_scroll(mouse.column, mouse.row, -2);
                true
            }
            MouseEventKind::ScrollDown => {
                self.handle_scroll(mouse.column, mouse.row, 2);
                true
            }
            MouseEventKind::Moved | MouseEventKind::Drag(_) => moved,
            _ => false,
        }
    }

    fn handle_scroll(&mut self, col: u16, row: u16, delta: isize) {
        match self.hits.scroll_target(col, row) {
            Some(ScrollTarget::Hosts) => {
                self.host_scroll = self.host_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::InspectorPorts) => {
                self.port_scroll = self.port_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::Settings) | None => {
                self.settings_scroll = self.settings_scroll.saturating_add_signed(delta);
            }
        }
    }

    /// Executes a `ClickAction` triggered from a registered mouse target or shortcut.
    pub fn handle_click_action(&mut self, action: ClickAction) {
        match action {
            ClickAction::SwitchTab(tab) => {
                self.tab = tab;
            }
            ClickAction::CycleInterface => {
                let vis = self.visible_interfaces();
                if !vis.is_empty() {
                    let cur_pos = vis
                        .iter()
                        .position(|(idx, _)| *idx == self.selected_iface_idx)
                        .unwrap_or(0);
                    let next = vis[(cur_pos + 1) % vis.len()].0;
                    self.selected_iface_idx = next;
                    self.radar_page_offset = 0;
                    self.host_scroll = 0;
                    self.port_scroll = 0;
                    self.selected_host_ip = self.filtered_hosts().first().map(|h| h.ip);
                }
            }
            ClickAction::SelectInterface(idx) => {
                if idx < self.snapshot.interfaces.len() {
                    self.selected_iface_idx = idx;
                    self.radar_page_offset = 0;
                    self.host_scroll = 0;
                    self.port_scroll = 0;
                    self.selected_host_ip = self.filtered_hosts().first().map(|h| h.ip);
                }
            }
            ClickAction::StartOrStopScan => {
                if self.scan_progress.active {
                    self.stop_scan();
                    self.set_toast("Scan stopped.");
                } else {
                    self.start_scan(None);
                }
            }
            ClickAction::CyclePreset => {
                self.config.default_preset = self.config.default_preset.next();
                self.save_config();
                self.set_toast(format!("Preset: {}", self.config.default_preset.label()));
            }
            ClickAction::SetPreset(p) => {
                self.config.default_preset = p;
                self.save_config();
            }
            ClickAction::ToggleHelp => {
                self.modal = if matches!(self.modal, Modal::Help) {
                    Modal::None
                } else {
                    Modal::Help
                };
            }
            ClickAction::CloseModal => self.modal = Modal::None,
            ClickAction::Quit => self.should_quit = true,
            ClickAction::SkipSplash => self.splash_until = None,
            ClickAction::FocusSearch => self.search_focused = true,
            ClickAction::ClearSearch => {
                self.search_query.clear();
                self.host_scroll = 0;
            }
            ClickAction::SortBy(col) => {
                if self.host_sort == col {
                    self.host_sort_desc = !self.host_sort_desc;
                } else {
                    self.host_sort = col;
                    self.host_sort_desc = false;
                }
            }
            ClickAction::SelectHost(ip) => {
                self.selected_host_ip = Some(ip);
                self.port_scroll = 0;
            }
            ClickAction::OpenRenameModal(ip) => {
                let initial = self
                    .snapshot
                    .hosts
                    .iter()
                    .find(|h| h.ip == ip)
                    .and_then(|h| h.nickname.clone())
                    .unwrap_or_default();
                self.modal = Modal::RenameHost { ip, input: initial };
            }
            ClickAction::SetPortFilter(pf) => {
                self.port_filter = pf;
                self.port_scroll = 0;
            }
            ClickAction::DeepScanHost(ip) => self.start_deep_scan_host(ip),
            ClickAction::CopyText(label, value) => {
                copy_osc52(&value);
                self.set_toast(format!("Copied {label} ({value}) to clipboard"));
            }
            ClickAction::SelectRadarOctet(octet) => {
                self.radar_selected_octet = octet;
            }
            ClickAction::RadarPageDelta(delta) => {
                let next = (self.radar_page_offset as i32 + delta).max(0) as u32;
                self.radar_page_offset = next;
            }
            ClickAction::JumpToHostIp(ip) => {
                self.selected_host_ip = Some(ip);
                self.port_scroll = 0;
                self.tab = Tab::Hosts;
            }
            ClickAction::ExportSnapshot(fmt) => {
                if let Err(err) = self.export_now(fmt) {
                    self.set_toast(err);
                }
            }
            ClickAction::SetTheme(t) => {
                self.config.theme = t;
                self.palette = Palette::from_config(self.config.theme, self.config.accent);
                self.save_config();
            }
            ClickAction::SetAccent(a) => {
                self.config.accent = a;
                self.palette = Palette::from_config(self.config.theme, self.config.accent);
                self.save_config();
            }
            ClickAction::ToggleAnimations => {
                self.config.animations = !self.config.animations;
                self.save_config();
            }
            ClickAction::ToggleVirtualIfaces => {
                self.config.show_virtual_ifaces = !self.config.show_virtual_ifaces;
                self.save_config();
            }
            ClickAction::ToggleGrabBanners => {
                self.config.grab_banners = !self.config.grab_banners;
                self.save_config();
            }
            ClickAction::OpenCustomPortsModal => {
                self.modal = Modal::CustomPorts {
                    input: self.config.custom_ports.clone(),
                    error: None,
                };
            }
            ClickAction::ResetDefaults => {
                self.config = Config::default();
                self.palette = Palette::from_config(self.config.theme, self.config.accent);
                self.save_config();
                self.set_toast("Reset preferences to Moonveil defaults.");
            }
        }
    }

    fn apply_host_nickname(&mut self, ip: Ipv4Addr, nick: String) {
        let mut saved = None;
        if let Some(h) = self.snapshot.hosts.iter_mut().find(|h| h.ip == ip) {
            h.nickname = if nick.is_empty() {
                None
            } else {
                Some(nick.clone())
            };
            if let Some(mac) = h.mac {
                saved = Some((
                    format_mac(mac),
                    h.ip,
                    h.nickname.clone(),
                    h.trusted,
                    h.vendor.clone(),
                    h.hostname.clone(),
                ));
            }
        }
        if let Some((mac_s, ip, nickname, trusted, vend, host)) = saved {
            self.known_hosts
                .upsert(&mac_s, ip, nickname, trusted, vend, host);
            self.save_known_hosts();
        }
        self.set_toast(format!("Updated nickname for {ip}"));
    }
}

fn seed_initial_hosts(snap: &mut NetworkSnapshot, known: &KnownHostStore) {
    let now = epoch_now();
    let arp = read_arp_entries();
    let etc_hosts = read_etc_hosts();
    let ts_peers = read_tailscale_peers();
    let ts_by_ip: HashMap<Ipv4Addr, _> = ts_peers.iter().map(|p| (p.ip, p.clone())).collect();

    for iface in &snap.interfaces {
        if iface.is_virtual {
            continue;
        }
        if let Some(ip) = iface.ipv4 {
            let local_hostname = ts_by_ip
                .get(&ip)
                .map(|p| p.hostname.clone())
                .or_else(|| clean_discovered_hostname(&snap.hostname));
            snap.hosts.push(Host {
                ip,
                ipv6: iface.ipv6_list.first().cloned(),
                hostname: local_hostname,
                nickname: None,
                mac: iface.mac,
                oui_prefix: iface.mac.map(format_oui),
                vendor: iface.vendor.clone().or_else(|| {
                    if iface.name.starts_with("tailscale") {
                        Some("Tailscale".to_string())
                    } else {
                        None
                    }
                }),
                is_randomized_mac: false,
                online: true,
                trusted: true,
                role: DeviceRole::ThisMachine,
                arp_state: ArpState::Local,
                ttl: Some(64),
                os_guess: Some("Linux".to_string()),
                rtt_ms: Some(0.05),
                rtt_history: vec![0.05],
                jitter_ms: None,
                packet_loss_pct: 0.0,
                ports: Vec::new(),
                first_seen_epoch: now,
                last_seen_epoch: now,
                discovered_tick: 0,
                subnet_cidr: iface.cidr.clone(),
                interface: iface.name.clone(),
                is_new: false,
            });
        }
        if let Some(gw) = iface.gateway {
            if !snap.hosts.iter().any(|h| h.ip == gw) {
                snap.hosts.push(Host {
                    ip: gw,
                    ipv6: None,
                    hostname: etc_hosts
                        .get(&gw)
                        .and_then(|s| clean_discovered_hostname(s)),
                    nickname: None,
                    mac: None,
                    oui_prefix: None,
                    vendor: None,
                    is_randomized_mac: false,
                    online: true,
                    trusted: true,
                    role: DeviceRole::Gateway,
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
                    is_new: false,
                });
            }
        }
        let is_ts_iface = iface.name.starts_with("tailscale")
            || (iface.prefix_len == 32 && iface.ipv4.is_some_and(|ip| ip.octets()[0] == 100));
        if is_ts_iface {
            for peer in &ts_peers {
                if !peer.online || snap.hosts.iter().any(|h| h.ip == peer.ip) {
                    continue;
                }
                snap.hosts.push(Host {
                    ip: peer.ip,
                    ipv6: None,
                    hostname: Some(peer.hostname.clone()),
                    nickname: None,
                    mac: None,
                    oui_prefix: None,
                    vendor: Some("Tailscale Peer".to_string()),
                    is_randomized_mac: false,
                    online: true,
                    trusted: true,
                    role: DeviceRole::Host,
                    arp_state: ArpState::Reachable,
                    ttl: None,
                    os_guess: peer.os.clone(),
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
                    is_new: false,
                });
            }
        }
    }

    for entry in arp {
        let iface_obj = snap.interfaces.iter().find(|i| i.name == entry.interface);
        let subnet_cidr = iface_obj
            .map(|i| i.cidr.clone())
            .unwrap_or_else(|| "lan".to_string());
        let is_gw = iface_obj.is_some_and(|i| i.gateway == Some(entry.ip));
        let (vendor, rand) = entry.mac.map(lookup_vendor).unwrap_or((None, false));
        let hostname = etc_hosts
            .get(&entry.ip)
            .and_then(|s| clean_discovered_hostname(s));
        if let Some(h) = snap.hosts.iter_mut().find(|h| h.ip == entry.ip) {
            h.mac = entry.mac;
            h.oui_prefix = entry.mac.map(format_oui);
            h.vendor = vendor;
            h.is_randomized_mac = rand;
            h.arp_state = entry.state;
            h.ipv6 = entry.ipv6;
            if h.hostname.is_none() {
                h.hostname = hostname;
            }
        } else {
            snap.hosts.push(Host {
                ip: entry.ip,
                ipv6: entry.ipv6,
                hostname: hostname.clone(),
                nickname: None,
                mac: entry.mac,
                oui_prefix: entry.mac.map(format_oui),
                vendor: vendor.clone(),
                is_randomized_mac: rand,
                online: true,
                trusted: false,
                role: infer_device_role(false, is_gw, vendor.as_deref(), hostname.as_deref(), &[]),
                arp_state: entry.state,
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
                subnet_cidr,
                interface: entry.interface,
                is_new: true,
            });
        }
    }

    // Add offline saved hosts matching primary subnet when user gave them a nickname/bookmark.
    if let Some(primary) = snap
        .interfaces
        .iter()
        .find(|i| i.is_up && !i.is_virtual && i.ipv4.is_some())
    {
        if let Some(local_ip) = primary.ipv4 {
            let net = u32::from(network_addr(local_ip, primary.prefix_len));
            let mask = prefix_mask(primary.prefix_len);
            for k in known.hosts.values() {
                if let Ok(ip) = k.last_ip.parse::<Ipv4Addr>() {
                    if (u32::from(ip) & mask) == net && !snap.hosts.iter().any(|h| h.ip == ip) {
                        snap.hosts.push(Host {
                            ip,
                            ipv6: None,
                            hostname: k.hostname.clone(),
                            nickname: k.nickname.clone(),
                            mac: parse_mac(&k.mac),
                            oui_prefix: parse_mac(&k.mac).map(format_oui),
                            vendor: k.vendor.clone(),
                            is_randomized_mac: false,
                            online: false,
                            trusted: k.trusted,
                            role: DeviceRole::Host,
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
                            subnet_cidr: primary.cidr.clone(),
                            interface: primary.name.clone(),
                            is_new: false,
                        });
                    }
                }
            }
        }
    }
}

fn apply_known_metadata(hosts: &mut [Host], known: &KnownHostStore) {
    for h in hosts {
        apply_single_known_metadata(h, known);
    }
}

fn apply_single_known_metadata(h: &mut Host, known: &KnownHostStore) {
    if let Some(mac) = h.mac {
        let key = format_mac(mac);
        if let Some(entry) = known.hosts.get(&key) {
            h.trusted = entry.trusted;
            if let Some(nick) = &entry.nickname {
                if !nick.trim().is_empty() {
                    h.nickname = Some(nick.clone());
                }
            }
            h.is_new = !h.trusted && h.online;
        }
    }
}

fn refresh_in_use_from_sockets(snap: &mut NetworkSnapshot) {
    let mut local_ips: HashSet<Ipv4Addr> = HashSet::new();
    for iface in &snap.interfaces {
        if let Some(ip) = iface.ipv4 {
            local_ips.insert(ip);
        }
    }
    for host in &mut snap.hosts {
        let is_local = local_ips.contains(&host.ip);
        for port in &mut host.ports {
            if port.state != PortState::Open && port.state != PortState::InUse {
                continue;
            }
            let active = if is_local {
                snap.local_sockets.iter().find(|s| {
                    s.state == crate::net::model::SocketState::Established
                        && s.local_port == port.port
                        && (s.local_ip_v4.is_none() || s.local_ip_v4 == Some(host.ip))
                })
            } else {
                snap.local_sockets.iter().find(|s| {
                    s.state == crate::net::model::SocketState::Established
                        && s.remote_ip_v4 == Some(host.ip)
                        && s.remote_port == port.port
                })
            };
            if let Some(sock) = active {
                port.state = PortState::InUse;
                port.pid = sock.pid;
                port.process = sock.process.clone();
                port.peer_endpoint = Some(if is_local {
                    sock.remote_addr.clone()
                } else {
                    sock.local_addr.clone()
                });
            }
        }
    }
}
