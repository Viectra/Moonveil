//! Keyboard and mouse event handlers for navigation, search, modals, and scrolling.

use std::net::Ipv4Addr;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use crate::config::Language;
use crate::net::model::{parse_port_expr, ExportFormat, ScanPreset};
use crate::ui::hit::ScrollTarget;

use super::{App, Modal, Tab};

impl App {
    /// Handles a terminal keyboard event across modals, search input, and global shortcuts.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.is_splash_active() {
            self.splash_ticks_remaining = 0;
            if matches!(key.code, KeyCode::Char('q'))
                || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
            {
                self.should_quit = true;
            }
            return;
        }

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return;
        }

        if !matches!(self.modal, Modal::None) {
            self.handle_modal_key(key);
            return;
        }

        if self.search_focused {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.search_focused = false,
                KeyCode::Backspace => {
                    self.search_query.pop();
                    self.host_scroll = 0;
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.search_query.push(c);
                    self.host_scroll = 0;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::Char('1') => self.tab = Tab::Hosts,
            KeyCode::Char('2') => self.tab = Tab::Radar,
            KeyCode::Char('3') => self.tab = Tab::Settings,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::BackTab => self.tab = self.tab.prev(),
            KeyCode::Char('/') => {
                self.tab = Tab::Hosts;
                self.search_focused = true;
            }
            KeyCode::Esc => {
                if !self.search_query.is_empty() {
                    self.search_query.clear();
                    self.host_scroll = 0;
                } else if self.snapshot.ping_active {
                    self.stop_ping();
                }
            }
            KeyCode::Char('s') | KeyCode::Char(' ') => {
                if self.scan_progress.active {
                    self.stop_scan();
                } else {
                    self.start_scan();
                }
            }
            KeyCode::Char('p') => self.cycle_preset(),
            KeyCode::Char('r') => {
                if let Some(ip) = self.selected_host_ip {
                    self.start_deep_scan_host(ip);
                }
            }
            KeyCode::Char('t') => {
                if let Some(ip) = self.selected_host_ip {
                    self.toggle_trust(ip);
                }
            }
            KeyCode::Char('n') => {
                if let Some(ip) = self.selected_host_ip {
                    self.open_rename_modal(ip);
                }
            }
            KeyCode::Char('e') => self.export_now(ExportFormat::Json),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-8),
            KeyCode::PageDown => self.move_selection(8),
            KeyCode::Left | KeyCode::Char('h') if self.tab == Tab::Radar => {
                self.radar_selected_octet = self.radar_selected_octet.saturating_sub(1);
            }
            KeyCode::Right | KeyCode::Char('l') if self.tab == Tab::Radar => {
                self.radar_selected_octet = self.radar_selected_octet.saturating_add(1);
            }
            _ => {}
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let lang = self.lang();
        match &mut self.modal {
            Modal::None => {}
            Modal::Help => {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?')
                ) {
                    self.modal = Modal::None;
                }
            }
            Modal::RenameHost { ip, input } => match key.code {
                KeyCode::Esc => self.modal = Modal::None,
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Enter => {
                    let ip_val = *ip;
                    let trimmed = input.trim().to_string();
                    let nick = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    };
                    self.modal = Modal::None;
                    self.apply_host_nickname(ip_val, nick);
                }
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL) && input.len() < 42 =>
                {
                    input.push(c);
                }
                _ => {}
            },
            Modal::CustomPorts { input, error } => match key.code {
                KeyCode::Esc => self.modal = Modal::None,
                KeyCode::Backspace => {
                    input.pop();
                    *error = None;
                }
                KeyCode::Enter => match parse_port_expr(input) {
                    Ok(_) => {
                        let expr = input.trim().to_string();
                        self.config.custom_ports = expr;
                        self.config.default_preset = ScanPreset::Custom;
                        self.save_config_if_enabled();
                        self.modal = Modal::None;
                        self.set_toast(
                            lang.t("Custom ports saved", "Plage personnalisée enregistrée"),
                        );
                    }
                    Err(e) => {
                        *error = Some(e);
                    }
                },
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL) && input.len() < 96 =>
                {
                    input.push(c);
                    *error = None;
                }
                _ => {}
            },
        }
    }

    /// Handles mouse clicks, hover coordinates, and wheel scrolling via `HitRegistry`.
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> bool {
        self.hits.set_hover(mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if self.is_splash_active() {
                    self.splash_ticks_remaining = 0;
                    return true;
                }
                if let Some(action) = self.hits.hit_test(mouse.column, mouse.row) {
                    self.handle_click_action(action);
                    return true;
                }
                false
            }
            MouseEventKind::ScrollUp => self.handle_scroll(mouse.column, mouse.row, -1),
            MouseEventKind::ScrollDown => self.handle_scroll(mouse.column, mouse.row, 1),
            MouseEventKind::Moved => true,
            _ => false,
        }
    }

    pub fn handle_scroll(&mut self, col: u16, row: u16, delta: isize) -> bool {
        match self.hits.scroll_test(col, row) {
            ScrollTarget::HostTable => {
                self.move_selection(delta);
                true
            }
            ScrollTarget::PortList => {
                if delta < 0 {
                    self.port_scroll = self.port_scroll.saturating_sub((-delta) as usize);
                } else {
                    self.port_scroll = self.port_scroll.saturating_add(delta as usize);
                }
                true
            }
            ScrollTarget::None => false,
        }
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.tab != Tab::Hosts {
            return;
        }
        let ips: Vec<Ipv4Addr> = self.filtered_hosts().into_iter().map(|h| h.ip).collect();
        if ips.is_empty() {
            return;
        }
        let cur_idx = self
            .selected_host_ip
            .and_then(|ip| ips.iter().position(|x| *x == ip))
            .unwrap_or(0);
        let next_idx = if delta < 0 {
            cur_idx.saturating_sub((-delta) as usize)
        } else {
            (cur_idx + delta as usize).min(ips.len() - 1)
        };
        let next_ip = ips[next_idx];
        self.select_host(next_ip);
    }

    pub(super) fn cycle_preset(&mut self) {
        let next = self.config.default_preset.next();
        self.config.default_preset = next;
        self.save_config_if_enabled();
        let lang = self.lang();
        self.set_toast(match lang {
            Language::En => format!("Preset: {}", next.label_for(lang)),
            Language::Fr => format!("Profil : {}", next.label_for(lang)),
        });
    }
}
