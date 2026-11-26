//! Devices tab: clean interface/scan toolbar, sortable 4-column device table, and Device Inspector.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::net::model::{
    clean_discovered_hostname, format_mac, short_vendor_name, Host, HostSortColumn, PortFilter,
    PortState,
};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};
use crate::ui::widgets::{mix, render_scan_wave};

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 36 || area.height < 10 {
        return;
    }

    let wave_h = if app.scan_progress.active { 1 } else { 0 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // Top toolbar + search bar
            Constraint::Length(wave_h), // Animated scan wave when scanning
            Constraint::Min(6),         // Devices table + Inspector split
        ])
        .split(area);

    render_toolbar(frame, app, rows[0], pal);
    if app.scan_progress.active {
        let lbl = format!(
            "{}/{} {}",
            app.scan_progress.probed, app.scan_progress.total, app.scan_progress.current_target
        );
        render_scan_wave(
            frame,
            rows[1],
            pal,
            app.scan_progress.ratio(),
            app.tick_count,
            &truncate_str(&lbl, 28),
        );
    }

    let body = rows[2];
    if body.width >= 104 {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
            .split(body);
        render_host_table(frame, app, pad_right(split[0], 1), pal);
        render_inspector(frame, app, split[1], pal);
    } else if body.height >= 20 {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(body);
        render_host_table(frame, app, split[0], pal);
        render_inspector(frame, app, split[1], pal);
    } else {
        render_host_table(frame, app, body, pal);
    }
}

fn render_toolbar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 0);
    if inner.height < 2 || inner.width < 20 {
        return;
    }

    // Row 0: Interface pill | Scan / Stop | Preset pill | right status summary
    let row0 = Rect::new(inner.x, inner.y, inner.width, 1);
    let mut x = row0.x;

    let iface_label = app
        .active_interface()
        .map(|i| format!(" ⇄ {} · {} ", i.name, i.cidr))
        .unwrap_or_else(|| " ⇄ no interface ".to_string());
    x = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        &iface_label,
        false,
        pal,
        ClickAction::CycleInterface,
    );
    x += 1;

    let scan_lbl = if app.scan_progress.active {
        " ■ Stop "
    } else {
        " ▶ Scan "
    };
    x = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        scan_lbl,
        true,
        pal,
        ClickAction::StartOrStopScan,
    );
    x += 1;

    let preset_lbl = format!(" Preset: {} ", app.config.default_preset.short_label());
    x = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        &preset_lbl,
        false,
        pal,
        ClickAction::CyclePreset,
    );

    let hosts = app.filtered_hosts();
    let online_cnt = hosts.iter().filter(|h| h.online).count();
    let summary = if app.scan_progress.active {
        "Scanning…".to_string()
    } else {
        format!("{online_cnt} online")
    };
    let sum_w = summary.len() as u16;
    if row0.right() > x + sum_w + 2 {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                summary,
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ))),
            Rect::new(row0.right() - sum_w - 1, row0.y, sum_w, 1),
        );
    }

    // Row 2: Search bar
    let row2 = Rect::new(inner.x, inner.y + 2.min(inner.height - 1), inner.width, 1);
    let clear_w = if app.search_query.is_empty() { 0 } else { 7 };
    let search_w = row2.width.saturating_sub(clear_w + 1);
    let search_rect = Rect::new(row2.x, row2.y, search_w, 1);
    let search_bg = if app.search_focused {
        pal.selection
    } else {
        pal.recessed
    };
    let cursor = if app.search_focused && (app.tick_count / 6).is_multiple_of(2) {
        "▏"
    } else {
        ""
    };
    let display = if app.search_query.is_empty() && !app.search_focused {
        " / Search device name, IP, MAC, vendor, or port…".to_string()
    } else {
        format!(" / {}{}", app.search_query, cursor)
    };
    let text_color = if app.search_query.is_empty() && !app.search_focused {
        pal.text_muted
    } else {
        pal.text
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate_str(&display, usize::from(search_w)),
            Style::default().fg(text_color).bg(search_bg),
        )))
        .style(Style::default().bg(search_bg)),
        search_rect,
    );
    app.hits.register(search_rect, ClickAction::FocusSearch);

    if clear_w > 0 && row2.right() >= clear_w {
        let clr_rect = Rect::new(row2.right() - clear_w, row2.y, clear_w, 1);
        let hovered = HitRegistry::is_hovered(clr_rect, app.hover);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " Clear ",
                pal.pill_style(false, hovered),
            ))),
            clr_rect,
        );
        app.hits.register(clr_rect, ClickAction::ClearSearch);
    }
}

fn device_table_columns(area_width: u16) -> [(&'static str, HostSortColumn, u16); 4] {
    let avail = area_width.saturating_sub(4);
    let (w_dev, w_ip, w_vend) = if avail >= 76 {
        (24_u16, 16_u16, 16_u16)
    } else if avail >= 52 {
        (18_u16, 15_u16, 10_u16)
    } else {
        (14_u16, 15_u16, 8_u16)
    };
    let w_ports = avail.saturating_sub(w_dev + w_ip + w_vend).max(8);
    [
        ("Device", HostSortColumn::Name, w_dev),
        ("IP Address", HostSortColumn::Ip, w_ip),
        ("Vendor", HostSortColumn::Vendor, w_vend),
        ("Open Ports", HostSortColumn::OpenPorts, w_ports),
    ]
}

fn render_host_table(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let hosts: Vec<Host> = app.filtered_hosts().into_iter().cloned().collect();
    let online_cnt = hosts.iter().filter(|h| h.online).count();
    let badge = format!("{online_cnt} online");
    let body = draw_card_header(
        frame,
        pal,
        area,
        "Devices on Network",
        Some((&badge, pal.veil_peach)),
    );
    if body.height < 3 || body.width < 20 {
        return;
    }

    let cols = device_table_columns(body.width);
    let hdr = Rect::new(body.x + 3, body.y, body.width.saturating_sub(4), 1);
    render_table_header(frame, app, hdr, pal, &cols);

    let list_area = Rect::new(
        body.x,
        body.y + 1,
        body.width,
        body.height.saturating_sub(1),
    );
    app.hits.register_scroll(list_area, ScrollTarget::Hosts);

    if hosts.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No devices found. Press 's' or click [Scan].",
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ))),
            list_area,
        );
        return;
    }

    let visible_rows = usize::from(list_area.height);
    let max_scroll = hosts.len().saturating_sub(visible_rows);
    if app.host_scroll > max_scroll {
        app.host_scroll = max_scroll;
    }

    for (vis_idx, host) in hosts
        .iter()
        .skip(app.host_scroll)
        .take(visible_rows)
        .enumerate()
    {
        let row_rect = Rect::new(
            list_area.x,
            list_area.y + vis_idx as u16,
            list_area.width,
            1,
        );
        let selected = app.selected_host_ip == Some(host.ip);
        let hovered = HitRegistry::is_hovered(row_rect, app.hover);
        let glow_t = if app.config.animations && app.tick_count < host.discovered_tick + 16 {
            let rem = (host.discovered_tick + 16).saturating_sub(app.tick_count);
            (rem as f64 / 16.0) * 0.45
        } else {
            0.0
        };
        let base_bg = if selected {
            pal.selection
        } else if hovered {
            pal.surface_hover
        } else if vis_idx % 2 == 1 {
            pal.surface_alt
        } else {
            pal.surface
        };
        let row_bg = if glow_t > 0.0 {
            mix(base_bg, pal.moon_violet, glow_t)
        } else {
            base_bg
        };

        render_host_row(frame, host, row_rect, row_bg, pal, &cols);
        app.hits
            .register(row_rect, ClickAction::SelectHost(host.ip));
    }
}

fn render_table_header(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    cols: &[(&'static str, HostSortColumn, u16); 4],
) {
    let mut x = area.x;
    for &(label, col, width) in cols {
        let w = width.min(area.right().saturating_sub(x));
        if w < 3 {
            break;
        }
        let rect = Rect::new(x, area.y, w, 1);
        let active = app.host_sort == col;
        let arrow = if active {
            if app.host_sort_desc {
                " ↓"
            } else {
                " ↑"
            }
        } else {
            ""
        };
        let txt = truncate_str(&format!("{label}{arrow}"), usize::from(w));
        let style = if active {
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.surface)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(pal.text_muted).bg(pal.surface)
        };
        frame.render_widget(Paragraph::new(Line::from(Span::styled(txt, style))), rect);
        app.hits.register(rect, ClickAction::SortBy(col));
        x += w;
    }
}

fn render_host_row(
    frame: &mut Frame,
    host: &Host,
    area: Rect,
    bg: Color,
    pal: Palette,
    cols: &[(&'static str, HostSortColumn, u16); 4],
) {
    let status_dot = if host.online {
        Span::styled(" ● ", Style::default().fg(pal.ok).bg(bg))
    } else {
        Span::styled(" · ", Style::default().fg(pal.text_muted).bg(bg))
    };

    let (w_dev, w_ip, w_vend, w_ports) = (
        usize::from(cols[0].2),
        usize::from(cols[1].2),
        usize::from(cols[2].2),
        usize::from(cols[3].2),
    );

    let name = format!("{} {}", host.role.icon(), host.display_name());
    let dev_cell = format!(
        "{:<w$}",
        truncate_str(&name, w_dev.saturating_sub(1)),
        w = w_dev
    );

    let ip_cell = format!("{:<w$}", host.ip, w = w_ip);

    let vend_short = host
        .vendor
        .as_deref()
        .map(short_vendor_name)
        .unwrap_or_else(|| "—".to_string());
    let vend_cell = format!(
        "{:<w$}",
        truncate_str(&vend_short, w_vend.saturating_sub(1)),
        w = w_vend
    );

    let (iu, op, _, _) = host.port_counts();
    let ports_text = if !host.online {
        "Offline".to_string()
    } else {
        host.open_ports_summary(3)
    };
    let ports_col = if !host.online || ports_text == "—" {
        pal.text_muted
    } else if iu > 0 {
        pal.in_use
    } else if op > 0 {
        pal.open
    } else {
        pal.text_muted
    };

    let spans = vec![
        status_dot,
        Span::styled(
            dev_cell,
            Style::default()
                .fg(if host.online {
                    pal.text
                } else {
                    pal.text_muted
                })
                .bg(bg)
                .add_modifier(if host.online {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ),
        Span::styled(ip_cell, Style::default().fg(pal.veil_peach).bg(bg)),
        Span::styled(vend_cell, Style::default().fg(pal.text_dim).bg(bg)),
        Span::styled(
            truncate_str(&ports_text, w_ports),
            Style::default().fg(ports_col).bg(bg),
        ),
    ];

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(bg)),
        area,
    );
}

fn render_inspector(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let Some(host) = app.selected_host().cloned() else {
        let body = draw_card_header(frame, pal, area, "Device Inspector", None);
        frame.render_widget(
            Paragraph::new("  Select a device to inspect its identity and open ports.")
                .style(Style::default().fg(pal.text_muted).bg(pal.surface))
                .wrap(Wrap { trim: true }),
            body,
        );
        return;
    };

    let status_lbl = if host.online {
        match host.rtt_ms {
            Some(r) if r < 10.0 => format!("Online · {r:.1} ms"),
            Some(r) => format!("Online · {r:.0} ms"),
            None => "Online".to_string(),
        }
    } else {
        "Offline".to_string()
    };
    let status_col = if host.online { pal.ok } else { pal.text_muted };

    let body = draw_card_header(
        frame,
        pal,
        area,
        &format!("{} {}", host.role.icon(), host.display_name()),
        Some((&status_lbl, status_col)),
    );
    if body.height < 6 || body.width < 20 {
        return;
    }

    let inner = inset_rect(body, 1, 0);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Identity summary (3 lines + 1 blank line)
            Constraint::Length(1), // Port filter pills
            Constraint::Min(4),    // Port list
            Constraint::Length(1), // Action buttons bar
        ])
        .split(inner);

    // 1. Clean Identity Block
    let raw_hostname = host.hostname.as_deref().and_then(clean_discovered_hostname);
    let host_span = match raw_hostname {
        Some(name) => Span::styled(
            truncate_str(&name, usize::from(chunks[0].width.saturating_sub(12))),
            Style::default().fg(pal.text).add_modifier(Modifier::BOLD),
        ),
        None => Span::styled(
            "Not advertised (using vendor ID)",
            Style::default().fg(pal.text_muted),
        ),
    };
    let mac_str = host.mac.map(format_mac).unwrap_or_else(|| "—".to_string());
    let vend_str = host.vendor.as_deref().unwrap_or("Unknown vendor");
    let vend_line = if let Some(os) = &host.os_guess {
        format!("{vend_str}  ·  {os}")
    } else {
        vend_str.to_string()
    };

    let meta_lines = vec![
        Line::from(vec![
            Span::styled("Hostname : ", Style::default().fg(pal.text_muted)),
            host_span,
        ]),
        Line::from(vec![
            Span::styled("IP / MAC : ", Style::default().fg(pal.text_muted)),
            Span::styled(
                host.ip.to_string(),
                Style::default()
                    .fg(pal.veil_peach)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ·  ", Style::default().fg(pal.text_muted)),
            Span::styled(mac_str, Style::default().fg(pal.text)),
        ]),
        Line::from(vec![
            Span::styled("Vendor   : ", Style::default().fg(pal.text_muted)),
            Span::styled(
                truncate_str(&vend_line, usize::from(chunks[0].width.saturating_sub(12))),
                Style::default().fg(pal.moon_violet),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(meta_lines).style(Style::default().bg(pal.surface)),
        chunks[0],
    );

    // 2. Simple 3-pill Port Filter: Open | In Use | Closed
    let (iu, op, filt, cl) = host.port_counts();
    let mut px = chunks[1].x;
    for &pf in PortFilter::ALL {
        let cnt = match pf {
            PortFilter::Open => iu + op,
            PortFilter::InUse => iu,
            PortFilter::Closed => cl + filt,
        };
        let lbl = format!(" {} ({cnt}) ", pf.label());
        px = push_pill(
            frame,
            app,
            px,
            chunks[1].y,
            chunks[1].right(),
            &lbl,
            app.port_filter == pf,
            pal,
            ClickAction::SetPortFilter(pf),
        );
        px += 1;
    }

    // 3. Port List
    let ports_rect = chunks[2];
    app.hits
        .register_scroll(ports_rect, ScrollTarget::InspectorPorts);

    let displayed_ports: Vec<_> = host
        .ports
        .iter()
        .filter(|p| app.port_filter.matches(p.state))
        .collect();

    if displayed_ports.is_empty() {
        let empty_msg = if host.ports.is_empty() {
            "  Press 's' or click [Scan] to probe ports.".to_string()
        } else {
            match app.port_filter {
                PortFilter::Open => format!(
                    "  No open ports found ({} scanned). Click [Deep Scan] for 1,000+ ports.",
                    host.ports.len()
                ),
                PortFilter::InUse => {
                    "  No active established sessions with this device.".to_string()
                }
                PortFilter::Closed => "  No closed or filtered ports recorded.".to_string(),
            }
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::from(Span::styled(empty_msg, Style::default().fg(pal.text_muted))),
            ])
            .style(Style::default().bg(pal.surface))
            .wrap(Wrap { trim: false }),
            ports_rect,
        );
    } else {
        let max_p_rows = usize::from(ports_rect.height);
        let max_p_scroll = displayed_ports.len().saturating_sub(max_p_rows);
        if app.port_scroll > max_p_scroll {
            app.port_scroll = max_p_scroll;
        }

        for (idx, p) in displayed_ports
            .iter()
            .skip(app.port_scroll)
            .take(max_p_rows)
            .enumerate()
        {
            let row_y = ports_rect.y + idx as u16;
            if row_y >= ports_rect.bottom() {
                break;
            }
            let line_rect = Rect::new(ports_rect.x, row_y, ports_rect.width, 1);
            let st_col = pal.port_color(p.state);
            let svc_label = if p.service == "tcp" {
                "—"
            } else {
                &p.service
            };
            let port_col = format!("{}/{}", p.port, p.proto.label().to_ascii_lowercase());

            let detail = match p.state {
                PortState::Closed => "Connection refused".to_string(),
                PortState::Filtered => "Filtered (no response)".to_string(),
                PortState::Open | PortState::InUse => {
                    if let Some(proc_name) = &p.process {
                        let proc_lbl = match p.pid {
                            Some(pid) => format!("{proc_name}({pid})"),
                            None => proc_name.clone(),
                        };
                        if let Some(banner) = &p.banner {
                            if !banner.is_empty() {
                                format!("{proc_lbl} · {banner}")
                            } else {
                                proc_lbl
                            }
                        } else if let Some(peer) = &p.peer_endpoint {
                            if !peer.is_empty() {
                                format!("{proc_lbl} <-> {peer}")
                            } else {
                                proc_lbl
                            }
                        } else {
                            proc_lbl
                        }
                    } else if let Some(banner) = &p.banner {
                        if !banner.is_empty() {
                            banner.clone()
                        } else if !p.description.is_empty() {
                            p.description.clone()
                        } else {
                            "Open TCP port".to_string()
                        }
                    } else if !p.description.is_empty() {
                        p.description.clone()
                    } else {
                        "Open TCP port".to_string()
                    }
                }
            };

            let rem_w = ports_rect.width.saturating_sub(31) as usize;
            let spans = vec![
                Span::styled(
                    format!("{port_col:<9}"),
                    Style::default().fg(pal.text).bg(pal.surface),
                ),
                Span::styled(
                    format!("{:<9}", p.state.label()),
                    Style::default()
                        .fg(st_col)
                        .bg(pal.surface)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<13}", truncate_str(svc_label, 12)),
                    Style::default().fg(pal.veil_peach).bg(pal.surface),
                ),
                Span::styled(
                    truncate_str(&detail, rem_w),
                    Style::default().fg(pal.text_dim).bg(pal.surface),
                ),
            ];
            frame.render_widget(Paragraph::new(Line::from(spans)), line_rect);
        }
    }

    // 4. Single-Row Action Bar
    let act_area = chunks[3];
    if act_area.height >= 1 {
        let mut ax = act_area.x;
        ax = push_pill(
            frame,
            app,
            ax,
            act_area.y,
            act_area.right(),
            " ▶ Deep Scan ",
            true,
            pal,
            ClickAction::DeepScanHost(host.ip),
        );
        ax += 1;
        ax = push_pill(
            frame,
            app,
            ax,
            act_area.y,
            act_area.right(),
            " * Rename ",
            false,
            pal,
            ClickAction::OpenRenameModal(host.ip),
        );
        ax += 1;
        ax = push_pill(
            frame,
            app,
            ax,
            act_area.y,
            act_area.right(),
            " + Copy IP ",
            false,
            pal,
            ClickAction::CopyText("IP".to_string(), host.ip.to_string()),
        );
        ax += 1;
        if let Some(mac) = host.mac {
            let mac_lbl = if ax + 12 <= act_area.right() {
                " + Copy MAC "
            } else {
                " Copy MAC "
            };
            let _ = push_pill(
                frame,
                app,
                ax,
                act_area.y,
                act_area.right(),
                mac_lbl,
                false,
                pal,
                ClickAction::CopyText("MAC".to_string(), format_mac(mac)),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn push_pill(
    frame: &mut Frame,
    app: &mut App,
    x: u16,
    y: u16,
    max_x: u16,
    label: &str,
    active: bool,
    pal: Palette,
    action: ClickAction,
) -> u16 {
    let w = unicode_width::UnicodeWidthStr::width(label) as u16;
    if x + w > max_x || w == 0 {
        return x;
    }
    let rect = Rect::new(x, y, w, 1);
    let hovered = HitRegistry::is_hovered(rect, app.hover);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            label,
            pal.pill_style(active, hovered),
        ))),
        rect,
    );
    app.hits.register(rect, action);
    x + w
}

fn pad_right(r: Rect, n: u16) -> Rect {
    Rect::new(r.x, r.y, r.width.saturating_sub(n), r.height)
}
