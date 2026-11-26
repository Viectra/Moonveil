//! Gestion des entrées clavier et souris (navigation, recherche, défilement).

use super::*;

impl App {
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
            Modal::Help | Modal::Traceroute { .. } => {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?')
                ) {
                    self.close_modal();
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
                                let n = ports.len();
                                self.set_toast(if self.lang().is_fr() {
                                    format!("Préréglage perso défini ({n} ports)")
                                } else {
                                    format!("Custom preset set ({n} ports)")
                                });
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

        // Focused text inputs
        if self.search_focused {
            match key.code {
                KeyCode::Esc => {
                    self.search_focused = false;
                }
                KeyCode::Enter => {
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
        if self.socket_search_focused {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.socket_search_focused = false,
                KeyCode::Backspace => {
                    self.socket_search.pop();
                    self.socket_scroll = 0;
                }
                KeyCode::Char(c) => {
                    self.socket_search.push(c);
                    self.socket_scroll = 0;
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
            KeyCode::Char('3') => self.tab = Tab::Network,
            KeyCode::Char('4') => self.tab = Tab::Watch,
            KeyCode::Char('5') => self.tab = Tab::Settings,
            KeyCode::Tab => {
                let idx = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
                self.tab = Tab::ALL[(idx + 1) % Tab::ALL.len()];
            }
            KeyCode::BackTab => {
                let idx = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
                self.tab = Tab::ALL[(idx + Tab::ALL.len() - 1) % Tab::ALL.len()];
            }
            KeyCode::Char('m') => self.handle_click_action(ClickAction::ToggleMode),
            KeyCode::Char('s') => self.handle_click_action(ClickAction::StartOrStopScan),
            KeyCode::Char('p') => self.handle_click_action(ClickAction::CyclePreset),
            KeyCode::Char('w') => self.handle_click_action(ClickAction::ToggleWatch),
            KeyCode::Char('/') => {
                if self.tab == Tab::Network {
                    self.socket_search_focused = true;
                } else {
                    self.tab = Tab::Hosts;
                    self.search_focused = true;
                }
            }
            KeyCode::Esc => {
                if !self.search_query.is_empty() {
                    self.search_query.clear();
                } else if self.show_inspector_on_compact {
                    self.show_inspector_on_compact = false;
                }
            }
            KeyCode::Char('t') => {
                if let Some(ip) = self.selected_host().map(|h| h.ip) {
                    self.toggle_trusted(ip);
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
            KeyCode::Enter if self.tab == Tab::Hosts => {
                self.show_inspector_on_compact = !self.show_inspector_on_compact;
            }
            _ => {}
        }
    }

    pub(super) fn move_selection(&mut self, delta: i32) {
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
                self.socket_search_focused = false;
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

    pub(super) fn handle_scroll(&mut self, col: u16, row: u16, delta: isize) {
        match self.hits.scroll_target(col, row) {
            Some(ScrollTarget::Hosts) => {
                self.host_scroll = self.host_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::InspectorPorts) => {
                self.port_scroll = self.port_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::Sockets) => {
                self.socket_scroll = self.socket_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::Interfaces) => {
                self.net_iface_scroll = self.net_iface_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::Timeline) => {
                self.timeline_scroll = self.timeline_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::SavedHosts) => {
                self.saved_scroll = self.saved_scroll.saturating_add_signed(delta);
            }
            Some(ScrollTarget::Settings) | None => {
                self.settings_scroll = self.settings_scroll.saturating_add_signed(delta);
            }
        }
    }
}
