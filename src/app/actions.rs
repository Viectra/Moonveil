//! ClickAction execution, rename/custom-port modals, trust toggles, clipboard copy, and WoL.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::config::Language;
use crate::net::model::{format_mac, HostSortColumn};
use crate::net::tools::{copy_osc52, send_wake_on_lan};
use crate::ui::hit::ClickAction;

use super::{App, Modal, Tab};

impl App {
    /// Dispatches a `ClickAction` triggered from mouse interaction or headless tests.
    pub fn handle_click_action(&mut self, action: ClickAction) {
        let lang = self.lang();
        match action {
            ClickAction::SwitchTab(t) => {
                self.tab = t;
                self.search_focused = false;
            }
            ClickAction::SelectInterface(idx) => self.select_interface(idx),
            ClickAction::ToggleScan => {
                if self.scan_progress.active {
                    self.stop_scan();
                } else {
                    self.start_scan();
                }
            }
            ClickAction::CyclePreset => self.cycle_preset(),
            ClickAction::SetPreset(p) => {
                self.config.default_preset = p;
                self.save_config_if_enabled();
                self.set_toast(p.label_for(lang));
            }
            ClickAction::OpenCustomPortsModal => {
                self.modal = Modal::CustomPorts {
                    input: self.config.custom_ports.clone(),
                    error: None,
                };
            }
            ClickAction::FocusSearch => {
                self.tab = Tab::Hosts;
                self.search_focused = true;
            }
            ClickAction::ClearSearch => {
                self.search_query.clear();
                self.host_scroll = 0;
                self.search_focused = false;
            }
            ClickAction::SortBy(col) => {
                if self.host_sort == col {
                    self.host_sort_desc = !self.host_sort_desc;
                } else {
                    self.host_sort = col;
                    self.host_sort_desc =
                        matches!(col, HostSortColumn::OpenPorts | HostSortColumn::Rtt);
                }
            }
            ClickAction::SelectHostIp(ip) => {
                let now = Instant::now();
                let is_double = self
                    .host_last_click
                    .map(|(prev_ip, t)| {
                        prev_ip == ip && now.duration_since(t) <= Duration::from_millis(450)
                    })
                    .unwrap_or(false);
                self.host_last_click = Some((ip, now));
                self.search_focused = false;
                self.select_host(ip);
                if is_double {
                    self.start_deep_scan_host(ip);
                }
            }
            ClickAction::JumpToHostIp(ip) => {
                self.tab = Tab::Hosts;
                self.search_focused = false;
                self.select_host(ip);
            }
            ClickAction::SetPortFilter(pf) => {
                self.port_filter = pf;
                self.port_scroll = 0;
                self.selected_port_idx = 0;
            }
            ClickAction::ToggleClosedPorts => {
                self.show_closed_ports = !self.show_closed_ports;
                self.port_scroll = 0;
            }
            ClickAction::SelectPortRow(idx) => {
                self.selected_port_idx = idx;
            }
            ClickAction::OpenRenameModal(ip) => self.open_rename_modal(ip),
            ClickAction::DeepScanHost(ip) => self.start_deep_scan_host(ip),
            ClickAction::PingHost(ip) => self.toggle_ping_host(ip),
            ClickAction::WakeOnLan(ip) => self.wake_host_by_ip(ip),
            ClickAction::ToggleTrust(ip) => self.toggle_trust(ip),
            ClickAction::CopyText { label, value } => {
                copy_osc52(&value);
                self.set_toast(match lang {
                    Language::En => format!("Copied {label}: {value}"),
                    Language::Fr => format!("{label} copié : {value}"),
                });
            }
            ClickAction::SelectRadarOctet(oct) => {
                self.radar_selected_octet = oct;
                if let Some(iface) = self.active_interface() {
                    let base = crate::net::linux::network_addr(iface.ip, iface.prefix_len);
                    let target = Ipv4Addr::from(
                        (u32::from(base) & 0xFFFFFF00)
                            + self.radar_page_offset * 256
                            + u32::from(oct),
                    );
                    if self.snapshot.hosts.iter().any(|h| h.ip == target) {
                        self.select_host(target);
                    }
                }
            }
            ClickAction::RadarPageDelta(delta) => {
                let pages = self
                    .active_interface()
                    .map(|i| i.slash24_page_count())
                    .unwrap_or(1)
                    .max(1);
                let cur = self.radar_page_offset as i64;
                let next = (cur + i64::from(delta)).rem_euclid(i64::from(pages)) as u32;
                self.radar_page_offset = next;
            }
            ClickAction::ExportSnapshot(fmt) => self.export_now(fmt),
            ClickAction::SetTheme(theme) => {
                self.config.theme = theme;
                self.save_config_if_enabled();
                self.set_toast(match lang {
                    Language::En => format!("Theme: {}", theme.label_for(lang)),
                    Language::Fr => format!("Thème : {}", theme.label_for(lang)),
                });
            }
            ClickAction::SetAccent(accent) => {
                self.config.accent = accent;
                self.save_config_if_enabled();
                self.set_toast(match lang {
                    Language::En => format!("Accent: {}", accent.label_for(lang)),
                    Language::Fr => format!("Accent : {}", accent.label_for(lang)),
                });
            }
            ClickAction::SetLanguage(new_lang) => {
                self.config.language = new_lang;
                self.save_config_if_enabled();
                self.status_message = new_lang
                    .t("Ready • Language updated", "Prêt • Langue mise à jour")
                    .to_string();
                self.set_toast(match new_lang {
                    Language::En => "Language: English",
                    Language::Fr => "Langue : Français",
                });
            }
            ClickAction::ToggleAnimations => {
                self.config.animations = !self.config.animations;
                self.save_config_if_enabled();
            }
            ClickAction::ToggleSplash => {
                self.config.splash = !self.config.splash;
                self.save_config_if_enabled();
            }
            ClickAction::ToggleGrabBanners => {
                self.config.grab_banners = !self.config.grab_banners;
                self.save_config_if_enabled();
            }
            ClickAction::ToggleVirtualIfaces => {
                self.config.show_virtual_ifaces = !self.config.show_virtual_ifaces;
                self.save_config_if_enabled();
                if !self.demo_mode {
                    self.spawn_socket_and_iface_refresh();
                }
            }
            ClickAction::AdjustConcurrency(delta) => {
                let next = (self.config.concurrency as i32 + delta).clamp(32, 512) as usize;
                self.config.concurrency = next;
                self.save_config_if_enabled();
            }
            ClickAction::AdjustTimeout(delta) => {
                let next = (self.config.timeout_ms as i64 + delta).clamp(100, 1500) as u64;
                self.config.timeout_ms = next;
                self.save_config_if_enabled();
            }
            ClickAction::CloseModal => self.modal = Modal::None,
            ClickAction::DismissSplash => self.splash_ticks_remaining = 0,
            ClickAction::ShowHelp => self.modal = Modal::Help,
            ClickAction::Quit => self.should_quit = true,
        }
    }

    pub(super) fn open_rename_modal(&mut self, ip: Ipv4Addr) {
        let lang = self.lang();
        if let Some(h) = self.snapshot.hosts.iter().find(|h| h.ip == ip) {
            let current = h
                .nickname
                .clone()
                .unwrap_or_else(|| h.display_name_for(lang));
            self.modal = Modal::RenameHost { ip, input: current };
        }
    }

    pub(super) fn apply_host_nickname(&mut self, ip: Ipv4Addr, nickname: Option<String>) {
        let lang = self.lang();
        if let Some(h) = self.snapshot.hosts.iter_mut().find(|h| h.ip == ip) {
            h.nickname = nickname.clone();
            if nickname.is_some() {
                h.trusted = true;
            }
            if let Some(mac) = h.mac {
                let mac_s = format_mac(mac);
                self.known_hosts.upsert(
                    &mac_s,
                    h.ip,
                    h.nickname.clone(),
                    h.trusted,
                    h.vendor.clone(),
                    h.hostname.clone(),
                );
                self.save_known_hosts_if_enabled();
            }
            self.set_toast(match (&nickname, lang) {
                (Some(n), Language::En) => format!("Renamed to {n}"),
                (Some(n), Language::Fr) => format!("Renommé : {n}"),
                (None, Language::En) => "Cleared nickname".to_string(),
                (None, Language::Fr) => "Surnom effacé".to_string(),
            });
        }
    }

    pub(super) fn toggle_trust(&mut self, ip: Ipv4Addr) {
        let lang = self.lang();
        let mut updated_trusted = None;
        if let Some(h) = self.snapshot.hosts.iter_mut().find(|h| h.ip == ip) {
            h.trusted = !h.trusted;
            updated_trusted = Some(h.trusted);
            if let Some(mac) = h.mac {
                let mac_s = format_mac(mac);
                self.known_hosts.upsert(
                    &mac_s,
                    h.ip,
                    h.nickname.clone(),
                    h.trusted,
                    h.vendor.clone(),
                    h.hostname.clone(),
                );
                self.save_known_hosts_if_enabled();
            }
        }
        if let Some(is_trusted) = updated_trusted {
            let msg = if is_trusted {
                lang.t("Marked host trusted", "Hôte marqué fiable")
            } else {
                lang.t("Removed trusted mark", "Marquage fiable retiré")
            };
            self.set_toast(msg);
        }
    }

    fn wake_host_by_ip(&mut self, ip: Ipv4Addr) {
        let lang = self.lang();
        let Some(host) = self.snapshot.hosts.iter().find(|h| h.ip == ip) else {
            return;
        };
        let Some(mac) = host.mac else {
            self.set_toast(lang.t(
                "No MAC address for Wake-on-LAN",
                "Aucune adresse MAC pour WoL",
            ));
            return;
        };
        if self.demo_mode {
            self.set_toast(match lang {
                Language::En => format!("Demo WoL sent to {}", format_mac(mac)),
                Language::Fr => format!("WoL démo envoyé à {}", format_mac(mac)),
            });
            return;
        }
        match send_wake_on_lan(mac, None) {
            Ok(()) => self.set_toast(match lang {
                Language::En => format!("Wake-on-LAN sent to {}", format_mac(mac)),
                Language::Fr => format!("Wake-on-LAN envoyé à {}", format_mac(mac)),
            }),
            Err(e) => self.set_toast(format!("WoL error: {e}")),
        }
    }
}
