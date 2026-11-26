//! Hosts tab: top toolbar (search, mode switch, scan, preset, watch), sortable host table, and Host Inspector.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::net::model::{format_mac, Host, HostSortColumn, PortFilter, PortState, ScanMode};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};
use crate::ui::widgets::{
    mix, render_mode_pill, render_port_ratio_bar, render_scan_wave, SplineChart,
};

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 36 || area.height < 10 {
        return;
    }

    let wave_h = if app.scan_progress.active { 1 } else { 0 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // Top interactive toolbar
            Constraint::Length(wave_h), // Animated scan wave when scanning
            Constraint::Min(6),         // Table + Inspector split
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
            .constraints([Constraint::Percentage(57), Constraint::Percentage(43)])
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
    } else if app.show_inspector_on_compact {
        render_inspector(frame, app, body, pal);
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

    // Row 0: Interface pill | Mode toggle | Scan / Stop | Preset | Watch | Compact Inspect toggle
    let row0 = Rect::new(inner.x, inner.y, inner.width, 1);
    let mut x = row0.x;

    let iface_label = app
        .active_interface()
        .map(|i| format!(" ⇄ {} ({}) ", i.name, i.cidr))
        .unwrap_or_else(|| " ⇄ no-iface ".to_string());
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

    // Mode toggle pill: Normal <-> Advanced
    let is_adv = app.config.mode == ScanMode::Advanced;
    let mode_line = render_mode_pill("Normal", "Advanced", is_adv, pal, pal.surface);
    let mode_w = 24_u16;
    if x + mode_w <= row0.right() {
        let m_rect = Rect::new(x, row0.y, mode_w, 1);
        frame.render_widget(Paragraph::new(mode_line), m_rect);
        app.hits.register(m_rect, ClickAction::ToggleMode);
        x += mode_w + 1;
    }

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
        !app.scan_progress.active,
        pal,
        ClickAction::StartOrStopScan,
    );
    x += 1;

    let preset_lbl = format!(" {} ", app.config.default_preset.short_label());
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
    x += 1;

    let watch_lbl = if app.watch_mode {
        " ● Watch ON "
    } else {
        " - Watch "
    };
    let _ = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        watch_lbl,
        app.watch_mode,
        pal,
        ClickAction::ToggleWatch,
    );

    // Row 2: Interactive Search & Filter Bar
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
        " / Search IP, MAC, vendor, port:22, state:in-use, state:closed, status:new…".to_string()
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

fn render_host_table(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let hosts: Vec<Host> = app.filtered_hosts().into_iter().cloned().collect();
    let online_cnt = hosts.iter().filter(|h| h.online).count();
    let badge = format!("{online_cnt}/{} up", hosts.len());
    let body = draw_card_header(
        frame,
        pal,
        area,
        &format!("Discovered Hosts ({})", app.config.mode.subtitle()),
        Some((&badge, pal.veil_peach)),
    );
    if body.height < 3 || body.width < 20 {
        return;
    }

    let is_adv = app.config.mode == ScanMode::Advanced;
    let hdr = Rect::new(body.x + 1, body.y, body.width.saturating_sub(2), 1);
    render_table_header(frame, app, hdr, pal, is_adv);

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
                "  No hosts match current filter. Press 's' or click Scan.",
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

        render_host_row(frame, host, row_rect, row_bg, pal, is_adv);
        app.hits
            .register(row_rect, ClickAction::SelectHost(host.ip));
    }
}

fn render_table_header(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette, is_adv: bool) {
    let cols: &[(&str, HostSortColumn, u16)] = if is_adv {
        &[
            ("IP", HostSortColumn::Ip, 16),
            ("MAC / Vendor", HostSortColumn::Vendor, 22),
            ("RTT", HostSortColumn::Rtt, 8),
            ("Use", HostSortColumn::InUsePorts, 5),
            ("Open", HostSortColumn::OpenPorts, 6),
            ("Host / OS", HostSortColumn::Name, 18),
        ]
    } else {
        &[
            ("Device", HostSortColumn::Name, 20),
            ("IP", HostSortColumn::Ip, 16),
            ("Vendor", HostSortColumn::Vendor, 14),
            ("Ping", HostSortColumn::Rtt, 8),
            ("Services", HostSortColumn::OpenPorts, 16),
        ]
    };

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
                "↓"
            } else {
                "↑"
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
    is_adv: bool,
) {
    let mut spans: Vec<Span> = Vec::new();
    let status_dot = if !host.online {
        Span::styled(" · ", Style::default().fg(pal.text_muted).bg(bg))
    } else if !host.trusted {
        Span::styled(" ● ", Style::default().fg(pal.crit).bg(bg))
    } else {
        Span::styled(" ● ", Style::default().fg(pal.ok).bg(bg))
    };
    spans.push(status_dot);

    let (iu, op, filt, cl) = host.port_counts();
    let rtt_str = host
        .rtt_ms
        .map(|r| {
            if r < 10.0 {
                format!("{r:.1}ms")
            } else {
                format!("{r:.0}ms")
            }
        })
        .unwrap_or_else(|| "—".to_string());
    let rtt_col = host
        .rtt_ms
        .map(|r| pal.rtt_color(r))
        .unwrap_or(pal.text_muted);

    if is_adv {
        let ip_s = format!("{:<15} ", host.ip);
        let mac_s = host.mac.map(format_mac).unwrap_or_else(|| "—".to_string());
        let vend_s = host.vendor.as_deref().unwrap_or("—");
        let mac_vend = truncate_str(&format!("{mac_s} {vend_s}"), 21);
        let os_s = host
            .os_guess
            .as_deref()
            .unwrap_or(host.hostname.as_deref().unwrap_or(""));

        spans.push(Span::styled(ip_s, Style::default().fg(pal.text).bg(bg)));
        spans.push(Span::styled(
            format!("{mac_vend:<22}"),
            Style::default().fg(pal.text_dim).bg(bg),
        ));
        spans.push(Span::styled(
            format!("{rtt_str:<8}"),
            Style::default().fg(rtt_col).bg(bg),
        ));
        spans.push(Span::styled(
            format!("{iu:<5}"),
            Style::default()
                .fg(if iu > 0 { pal.in_use } else { pal.text_muted })
                .bg(bg),
        ));
        spans.push(Span::styled(
            format!("{op:<5}"),
            Style::default()
                .fg(if op > 0 { pal.open } else { pal.text_muted })
                .bg(bg),
        ));
        spans.push(Span::styled(
            format!("{filt}/{cl} "),
            Style::default().fg(pal.closed).bg(bg),
        ));
        spans.push(Span::styled(
            truncate_str(os_s, 18),
            Style::default().fg(pal.text_dim).bg(bg),
        ));
    } else {
        let name = format!("{} {}", host.role.icon(), host.display_name());
        let vend = host.vendor.as_deref().unwrap_or("—");
        let tags = host.friendly_service_tags();
        let svc_summary = if !host.online {
            "Offline (Saved)".to_string()
        } else if tags.is_empty() && iu + op == 0 {
            "No open ports".to_string()
        } else if tags.is_empty() {
            format!("{iu} use • {op} open")
        } else {
            tags.join(" · ")
        };

        spans.push(Span::styled(
            format!("{:<19}", truncate_str(&name, 18)),
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
        ));
        spans.push(Span::styled(
            format!("{:<16}", host.ip),
            Style::default().fg(pal.veil_peach).bg(bg),
        ));
        spans.push(Span::styled(
            format!("{:<14}", truncate_str(vend, 13)),
            Style::default().fg(pal.text_dim).bg(bg),
        ));
        spans.push(Span::styled(
            format!("{rtt_str:<8}"),
            Style::default().fg(rtt_col).bg(bg),
        ));
        spans.push(Span::styled(
            truncate_str(&svc_summary, 24),
            Style::default()
                .fg(if iu > 0 { pal.in_use } else { pal.open })
                .bg(bg),
        ));
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(bg)),
        area,
    );
}

fn render_inspector(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let Some(host) = app.selected_host().cloned() else {
        let body = draw_card_header(frame, pal, area, "Host Inspector", None);
        frame.render_widget(
            Paragraph::new("  Click any host to inspect IPs, MACs, ports, and services.")
                .style(Style::default().fg(pal.text_muted).bg(pal.surface))
                .wrap(Wrap { trim: true }),
            body,
        );
        return;
    };

    let trust_lbl = if host.trusted {
        "★ Trusted"
    } else {
        "! Untrusted"
    };
    let trust_col = if host.trusted { pal.ok } else { pal.crit };
    let body = draw_card_header(
        frame,
        pal,
        area,
        &format!("{} {}", host.role.icon(), host.display_name()),
        Some((trust_lbl, trust_col)),
    );
    if body.height < 6 || body.width < 20 {
        return;
    }

    // Register clickable Trust badge on top right of card header
    let trust_w = unicode_width::UnicodeWidthStr::width(trust_lbl) as u16 + 2;
    let hdr_trust = Rect::new(area.right().saturating_sub(trust_w), area.y, trust_w, 1);
    app.hits
        .register(hdr_trust, ClickAction::ToggleTrusted(host.ip));

    let inner = inset_rect(body, 1, 0);
    let is_adv = app.config.mode == ScanMode::Advanced;
    let chart_h = if host.rtt_history.len() >= 2 && inner.height >= 16 {
        3
    } else {
        0
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if is_adv { 4 } else { 3 }), // Metadata block
            Constraint::Length(chart_h),                    // Live RTT spline chart
            Constraint::Length(1),                          // Port ratio bar
            Constraint::Length(1),                          // Port filter pills
            Constraint::Min(3),                             // Port list
            Constraint::Length(2),                          // Action buttons bar
        ])
        .split(inner);

    // 1. Metadata summary
    let mac_str = host
        .mac
        .map(format_mac)
        .unwrap_or_else(|| "Unknown".to_string());
    let vend_str = host.vendor.as_deref().unwrap_or("Unknown vendor");
    let rtt_str = host
        .rtt_ms
        .map(|r| format!("{r:.2} ms"))
        .unwrap_or_else(|| "offline".to_string());

    let mut meta_lines = vec![
        Line::from(vec![
            Span::styled("IP: ", Style::default().fg(pal.text_muted)),
            Span::styled(
                host.ip.to_string(),
                Style::default()
                    .fg(pal.veil_peach)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  MAC: ", Style::default().fg(pal.text_muted)),
            Span::styled(mac_str.clone(), Style::default().fg(pal.text)),
        ]),
        Line::from(vec![
            Span::styled("Vendor: ", Style::default().fg(pal.text_muted)),
            Span::styled(
                truncate_str(vend_str, 22),
                Style::default().fg(pal.moon_violet),
            ),
            Span::styled("  RTT: ", Style::default().fg(pal.text_muted)),
            Span::styled(rtt_str, Style::default().fg(pal.ok)),
        ]),
    ];
    if is_adv {
        meta_lines.push(Line::from(vec![
            Span::styled("OS: ", Style::default().fg(pal.text_muted)),
            Span::styled(
                truncate_str(host.os_guess.as_deref().unwrap_or("Unknown"), 20),
                Style::default().fg(pal.text_dim),
            ),
            Span::styled("  ARP: ", Style::default().fg(pal.text_muted)),
            Span::styled(host.arp_state.label(), Style::default().fg(pal.text_dim)),
        ]));
        if let Some(v6) = &host.ipv6 {
            meta_lines.push(Line::from(vec![
                Span::styled("IPv6: ", Style::default().fg(pal.text_muted)),
                Span::styled(truncate_str(v6, 34), Style::default().fg(pal.text_dim)),
            ]));
        }
    } else {
        meta_lines.push(Line::from(vec![
            Span::styled("Role: ", Style::default().fg(pal.text_muted)),
            Span::styled(host.role.label(), Style::default().fg(pal.text_dim)),
            Span::styled("  Status: ", Style::default().fg(pal.text_muted)),
            Span::styled(
                if host.online { "Online" } else { "Offline" },
                Style::default().fg(if host.online { pal.ok } else { pal.text_muted }),
            ),
        ]));
    }
    frame.render_widget(
        Paragraph::new(meta_lines).style(Style::default().bg(pal.surface)),
        chunks[0],
    );

    // 2. RTT Spline Chart
    if chart_h > 0 {
        let ping_col = if app.ping_target == Some(host.ip) {
            pal.veil_peach
        } else {
            pal.accent
        };
        let label = format!("RTT {:.1}ms", host.rtt_ms.unwrap_or_default());
        frame.render_widget(
            SplineChart {
                series: &[(&host.rtt_history, ping_col)],
                bg: pal.recessed,
                max_override: None,
                unit_label: &label,
            },
            chunks[1],
        );
    }

    // 3. Port ratio bar
    let (iu, op, filt, cl) = host.port_counts();
    render_port_ratio_bar(frame, chunks[2], pal, iu, op, filt, cl);

    // 4. Filter pills: All | In Use | Open | Closed | Filtered
    let mut px = chunks[3].x;
    for &pf in PortFilter::ALL {
        let cnt = match pf {
            PortFilter::All => host.ports.len(),
            PortFilter::InUse => iu,
            PortFilter::Open => op,
            PortFilter::Closed => cl,
            PortFilter::Filtered => filt,
        };
        let lbl = format!(" {}({}) ", pf.label(), cnt);
        px = push_pill(
            frame,
            app,
            px,
            chunks[3].y,
            chunks[3].right(),
            &lbl,
            app.port_filter == pf,
            pal,
            ClickAction::SetPortFilter(pf),
        );
        px += 1;
    }

    // 5. Port list (InUse + Open + Filtered, with Closed collapsible when All selected)
    let ports_rect = chunks[4];
    app.hits
        .register_scroll(ports_rect, ScrollTarget::InspectorPorts);

    let mut displayed_ports = Vec::new();
    let mut collapsed_closed = 0usize;
    for p in &host.ports {
        if !app.port_filter.matches(p.state) {
            continue;
        }
        if app.port_filter == PortFilter::All
            && p.state == PortState::Closed
            && !app.show_closed_ports
        {
            collapsed_closed += 1;
            continue;
        }
        displayed_ports.push(p);
    }

    let max_p_rows = usize::from(ports_rect.height);
    let max_p_scroll = displayed_ports
        .len()
        .saturating_sub(max_p_rows.saturating_sub(1));
    if app.port_scroll > max_p_scroll {
        app.port_scroll = max_p_scroll;
    }

    let mut row_y = ports_rect.y;
    for p in displayed_ports
        .iter()
        .skip(app.port_scroll)
        .take(max_p_rows)
    {
        if row_y >= ports_rect.bottom() {
            break;
        }
        let line_rect = Rect::new(ports_rect.x, row_y, ports_rect.width, 1);
        let st_col = pal.port_color(p.state);
        let mut spans = vec![
            Span::styled(
                format!("{:<9}", p.state.label()),
                Style::default()
                    .fg(st_col)
                    .bg(pal.surface)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "{:<10}",
                    format!("{}/{}", p.port, p.proto.label().to_ascii_lowercase())
                ),
                Style::default().fg(pal.text).bg(pal.surface),
            ),
            Span::styled(
                format!("{:<12}", truncate_str(&p.service, 11)),
                Style::default().fg(pal.veil_peach).bg(pal.surface),
            ),
        ];
        let extra = if let Some(proc_name) = &p.process {
            if let Some(pid) = p.pid {
                format!(
                    "{proc_name}({pid}) {}",
                    p.peer_endpoint.as_deref().unwrap_or("")
                )
            } else {
                proc_name.clone()
            }
        } else if is_adv {
            if let Some(b) = &p.banner {
                b.clone()
            } else if let Some(lat) = p.latency_ms {
                format!("{lat:.2}ms")
            } else {
                p.description.clone()
            }
        } else {
            p.banner.clone().unwrap_or_else(|| p.description.clone())
        };
        let rem_w = ports_rect.width.saturating_sub(31) as usize;
        spans.push(Span::styled(
            truncate_str(&extra, rem_w),
            Style::default().fg(pal.text_dim).bg(pal.surface),
        ));
        frame.render_widget(Paragraph::new(Line::from(spans)), line_rect);
        row_y += 1;
    }

    if collapsed_closed > 0 && row_y < ports_rect.bottom() {
        let pill_rect = Rect::new(ports_rect.x, row_y, ports_rect.width.min(34), 1);
        let hovered = HitRegistry::is_hovered(pill_rect, app.hover);
        let txt = format!(" + {collapsed_closed} Closed ports (click to expand) ");
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_str(&txt, usize::from(pill_rect.width)),
                pal.pill_style(false, hovered),
            ))),
            pill_rect,
        );
        app.hits.register(pill_rect, ClickAction::ToggleClosedPorts);
    } else if app.show_closed_ports
        && app.port_filter == PortFilter::All
        && cl > 0
        && row_y < ports_rect.bottom()
    {
        let pill_rect = Rect::new(ports_rect.x, row_y, ports_rect.width.min(30), 1);
        let hovered = HitRegistry::is_hovered(pill_rect, app.hover);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " - Collapse closed ports ",
                pal.pill_style(false, hovered),
            ))),
            pill_rect,
        );
        app.hits.register(pill_rect, ClickAction::ToggleClosedPorts);
    }

    // 6. Action Drawer (Ping, Trace, Deep Scan, WoL, Rename, Copy IP/MAC)
    let act_area = chunks[5];
    if act_area.height >= 2 {
        let mut ax = act_area.x;
        let ping_active = app.ping_target == Some(host.ip);
        ax = push_pill(
            frame,
            app,
            ax,
            act_area.y,
            act_area.right(),
            if ping_active {
                " ■ Ping "
            } else {
                " ● Ping "
            },
            ping_active,
            pal,
            ClickAction::TogglePingMonitor(host.ip),
        );
        ax += 1;
        ax = push_pill(
            frame,
            app,
            ax,
            act_area.y,
            act_area.right(),
            " → Trace ",
            false,
            pal,
            ClickAction::LaunchTraceroute(host.ip),
        );
        ax += 1;
        ax = push_pill(
            frame,
            app,
            ax,
            act_area.y,
            act_area.right(),
            " ▶ Deep ",
            false,
            pal,
            ClickAction::DeepScanHost(host.ip),
        );
        ax += 1;
        let _ = push_pill(
            frame,
            app,
            ax,
            act_area.y,
            act_area.right(),
            " ▲ WoL ",
            false,
            pal,
            ClickAction::SendWol(host.ip),
        );

        let mut bx = act_area.x;
        let by = act_area.y + 1;
        bx = push_pill(
            frame,
            app,
            bx,
            by,
            act_area.right(),
            " * Rename ",
            false,
            pal,
            ClickAction::OpenRenameModal(host.ip),
        );
        bx += 1;
        bx = push_pill(
            frame,
            app,
            bx,
            by,
            act_area.right(),
            " + Copy IP ",
            false,
            pal,
            ClickAction::CopyText("IP".to_string(), host.ip.to_string()),
        );
        bx += 1;
        if let Some(mac) = host.mac {
            let _ = push_pill(
                frame,
                app,
                bx,
                by,
                act_area.right(),
                " + Copy MAC ",
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
