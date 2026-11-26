//! Exécution des `ClickAction` (souris/raccourcis), fermeture des modales, renommage d'hôte et Wake-on-LAN.

use super::*;

impl App {
    /// Executes a `ClickAction` triggered from a registered mouse target or shortcut.
    pub fn handle_click_action(&mut self, action: ClickAction) {
        match action {
            ClickAction::SwitchTab(tab) => {
                self.tab = tab;
                self.show_inspector_on_compact = false;
            }
            ClickAction::ToggleMode => {
                self.config.mode = self.config.mode.toggle();
                self.save_config();
                let lang = self.lang();
                let (m, sub) = (
                    self.config.mode.label_for(lang),
                    self.config.mode.subtitle_for(lang),
                );
                self.set_toast(if lang.is_fr() {
                    format!("Passage au mode {m} ({sub})")
                } else {
                    format!("Switched to {m} Mode ({sub})")
                });
            }
            ClickAction::SetMode(mode) => {
                self.config.mode = mode;
                self.save_config();
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
                    self.selected_host_ip = self.filtered_hosts().first().map(|h| h.ip);
                }
            }
            ClickAction::SelectInterface(idx) | ClickAction::SelectNetInterface(idx) => {
                if idx < self.snapshot.interfaces.len() {
                    self.selected_iface_idx = idx;
                    self.radar_page_offset = 0;
                }
            }
            ClickAction::StartOrStopScan => {
                if self.scan_progress.active {
                    self.stop_scan();
                    self.set_toast(self.lang().t("Scan stopped.", "Scan arrêté."));
                } else {
                    self.start_scan(None);
                }
            }
            ClickAction::CyclePreset => {
                self.config.default_preset = self.config.default_preset.next();
                self.save_config();
                let lang = self.lang();
                self.set_toast(format!(
                    "{} {}",
                    lang.t("Preset:", "Préréglage :"),
                    self.config.default_preset.label_for(lang)
                ));
            }
            ClickAction::SetPreset(p) => {
                self.config.default_preset = p;
                self.save_config();
            }
            ClickAction::ToggleWatch => {
                self.watch_mode = !self.watch_mode;
                self.last_watch_scan = Instant::now();
                let fr = self.lang().is_fr();
                let secs = self.config.watch_interval_secs;
                self.set_toast(match (self.watch_mode, fr) {
                    (true, false) => format!("Watch Mode enabled (every {secs}s)"),
                    (true, true) => format!("Mode Veille activé (toutes les {secs}s)"),
                    (false, false) => "Watch Mode paused".to_string(),
                    (false, true) => "Mode Veille en pause".to_string(),
                });
            }
            ClickAction::ToggleHelp => {
                self.modal = if matches!(self.modal, Modal::Help) {
                    Modal::None
                } else {
                    Modal::Help
                };
            }
            ClickAction::CloseModal => self.close_modal(),
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
                let now = Instant::now();
                let dbl = self.last_click.is_some_and(|(prev, t)| {
                    prev == ip && now.duration_since(t) < Duration::from_millis(450)
                });
                self.last_click = Some((ip, now));
                self.selected_host_ip = Some(ip);
                self.port_scroll = 0;
                if dbl {
                    self.show_inspector_on_compact = true;
                }
            }
            ClickAction::ToggleInspectorPane => {
                self.show_inspector_on_compact = !self.show_inspector_on_compact;
            }
            ClickAction::ToggleTrusted(ip) => self.toggle_trusted(ip),
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
            ClickAction::ToggleClosedPorts => {
                self.show_closed_ports = !self.show_closed_ports;
            }
            ClickAction::TogglePingMonitor(ip) => self.toggle_ping_monitor(ip),
            ClickAction::LaunchTraceroute(ip) => self.launch_traceroute(ip),
            ClickAction::DeepScanHost(ip) => self.start_scan(Some(ip)),
            ClickAction::SendWol(ip) => self.trigger_wol(ip),
            ClickAction::CopyText(label, value) => {
                copy_osc52(&value);
                self.set_toast(if self.lang().is_fr() {
                    format!("{label} ({value}) copié dans le presse-papiers")
                } else {
                    format!("Copied {label} ({value}) to clipboard")
                });
            }
            ClickAction::SelectRadarOctet(octet) => {
                self.radar_selected_octet = octet;
            }
            ClickAction::RadarPageDelta(delta) => {
                let next = (self.radar_page_offset as i32 + delta).max(0) as u32;
                self.radar_page_offset = next;
            }
            ClickAction::RadarFilterRole(role) => self.radar_role_filter = role,
            ClickAction::SetSocketFilter(sf) => {
                self.socket_filter = sf;
                self.socket_scroll = 0;
            }
            ClickAction::FocusSocketSearch => self.socket_search_focused = true,
            ClickAction::ClearSocketSearch => {
                self.socket_search.clear();
                self.socket_scroll = 0;
            }
            ClickAction::JumpToHostIp(ip) => {
                self.selected_host_ip = Some(ip);
                self.tab = Tab::Hosts;
                self.show_inspector_on_compact = true;
            }
            ClickAction::ExportSnapshot(fmt) => {
                if let Err(err) = self.export_now(fmt) {
                    self.set_toast(err);
                }
            }
            ClickAction::ClearTimeline => self.timeline.clear(),
            ClickAction::SetLanguage(lang) => {
                self.config.language = lang;
                self.save_config();
                self.set_toast(lang.t(
                    "Interface language: English",
                    "Langue de l'interface : Français",
                ));
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
            ClickAction::ToggleSplash => {
                self.config.splash = !self.config.splash;
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
            ClickAction::CycleConcurrency => {
                self.config.concurrency = match self.config.concurrency {
                    64 => 128,
                    128 => 256,
                    256 => 512,
                    _ => 64,
                };
                self.save_config();
            }
            ClickAction::CycleTimeout => {
                self.config.timeout_ms = match self.config.timeout_ms {
                    150 => 250,
                    250 => 500,
                    500 => 1000,
                    _ => 150,
                };
                self.save_config();
            }
            ClickAction::CycleWatchInterval => {
                self.config.watch_interval_secs = match self.config.watch_interval_secs {
                    10 => 15,
                    15 => 30,
                    30 => 60,
                    _ => 10,
                };
                self.save_config();
            }
            ClickAction::OpenCustomPortsModal => {
                self.modal = Modal::CustomPorts {
                    input: self.config.custom_ports.clone(),
                    error: None,
                };
            }
            ClickAction::ResetDefaults => {
                let lang = self.lang();
                self.config = Config {
                    language: lang,
                    ..Config::default()
                };
                self.palette = Palette::from_config(self.config.theme, self.config.accent);
                self.save_config();
                self.set_toast(lang.t(
                    "Reset preferences to Moonveil defaults.",
                    "Préférences réinitialisées aux valeurs Moonveil par défaut.",
                ));
            }
        }
    }

    pub(super) fn close_modal(&mut self) {
        if let Some(c) = self.trace_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        self.trace_running = false;
        self.modal = Modal::None;
    }

    pub(super) fn apply_host_nickname(&mut self, ip: Ipv4Addr, nick: String) {
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
        self.set_toast(if self.lang().is_fr() {
            format!("Surnom mis à jour pour {ip}")
        } else {
            format!("Updated nickname for {ip}")
        });
    }

    pub(super) fn trigger_wol(&mut self, ip: Ipv4Addr) {
        let mac_opt = self
            .snapshot
            .hosts
            .iter()
            .find(|h| h.ip == ip)
            .and_then(|h| h.mac)
            .or_else(|| {
                self.known_hosts
                    .hosts
                    .values()
                    .find(|e| e.last_ip == ip.to_string())
                    .and_then(|e| parse_mac(&e.mac))
            });
        let Some(mac) = mac_opt else {
            self.set_toast(if self.lang().is_fr() {
                format!("Aucune adresse MAC connue pour {ip}")
            } else {
                format!("No MAC address known for {ip}")
            });
            return;
        };
        let bcast = self.active_interface().and_then(|i| i.broadcast);
        if self.demo_mode {
            let msg = format!(
                "Sent Wake-on-LAN magic packet to {} ({ip})",
                format_mac(mac)
            );
            self.push_event(EventKind::Action, Some(ip), msg.clone());
            self.set_toast(msg);
            return;
        }
        match send_wake_on_lan(mac, bcast) {
            Ok(()) => {
                let msg = format!(
                    "Sent Wake-on-LAN magic packet to {} ({ip})",
                    format_mac(mac)
                );
                self.push_event(EventKind::Action, Some(ip), msg.clone());
                self.set_toast(msg);
            }
            Err(err) => self.set_toast(err),
        }
    }
}
