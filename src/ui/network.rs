//! Network & Sockets tab: interface telemetry + live RX/TX curves + local PID socket table.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::app::{App, SocketFilter};
use crate::net::model::{format_bps, format_bytes, format_mac, SocketState};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::hosts::push_pill;
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};
use crate::ui::widgets::SplineChart;

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 36 || area.height < 12 {
        return;
    }

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    render_interfaces_panel(frame, app, split[0], pal);
    render_sockets_panel(frame, app, split[1], pal);
}

fn render_interfaces_panel(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let cols = if area.width >= 96 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(100), Constraint::Length(0)])
            .split(area)
    };

    // Left: Interface list
    let left = Rect::new(
        cols[0].x,
        cols[0].y,
        cols[0]
            .width
            .saturating_sub(if cols[1].width > 0 { 1 } else { 0 }),
        cols[0].height,
    );
    frame.render_widget(Block::default().style(pal.card_style()), left);
    let body = draw_card_header(frame, pal, left, "Network Interfaces", None);
    let list_area = inset_rect(body, 1, 0);
    app.hits
        .register_scroll(list_area, ScrollTarget::Interfaces);

    let ifaces: Vec<(usize, _)> = app
        .visible_interfaces()
        .into_iter()
        .map(|(idx, i)| (idx, i.clone()))
        .collect();
    let vis = usize::from(list_area.height);
    for (row_i, (orig_idx, iface)) in ifaces
        .iter()
        .skip(app.net_iface_scroll)
        .take(vis)
        .enumerate()
    {
        let r = Rect::new(list_area.x, list_area.y + row_i as u16, list_area.width, 1);
        let selected = *orig_idx == app.selected_iface_idx;
        let hovered = HitRegistry::is_hovered(r, app.hover);
        let bg = if selected {
            pal.selection
        } else if hovered {
            pal.surface_hover
        } else {
            pal.surface
        };
        let state_dot = if iface.is_up { "●" } else { "·" };
        let state_col = if iface.is_up { pal.ok } else { pal.text_muted };
        let line = Line::from(vec![
            Span::styled(
                format!("{state_dot} "),
                Style::default().fg(state_col).bg(bg),
            ),
            Span::styled(
                format!("{:<13}", truncate_str(&iface.name, 12)),
                Style::default()
                    .fg(pal.text)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:<19}", truncate_str(&iface.cidr, 18)),
                Style::default().fg(pal.veil_peach).bg(bg),
            ),
            Span::styled(
                format!(
                    "↓{} ↑{}",
                    format_bps(iface.rx_rate_bps),
                    format_bps(iface.tx_rate_bps)
                ),
                Style::default().fg(pal.text_dim).bg(bg),
            ),
        ]);
        frame.render_widget(Paragraph::new(line).style(Style::default().bg(bg)), r);
        app.hits
            .register(r, ClickAction::SelectNetInterface(*orig_idx));
    }

    // Right: Active interface details & live throughput spline
    if cols[1].width > 12 {
        frame.render_widget(Block::default().style(pal.card_style()), cols[1]);
        if let Some(iface) = app.active_interface().cloned() {
            let speed = iface
                .speed_mbps
                .map(|s| format!("{s} Mbps"))
                .unwrap_or_else(|| "link".to_string());
            let rbody = draw_card_header(
                frame,
                pal,
                cols[1],
                &format!("{} Details", iface.name),
                Some((&speed, pal.moon_violet)),
            );
            let inner = inset_rect(rbody, 1, 0);
            if inner.height >= 4 {
                let parts = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(4), Constraint::Min(2)])
                    .split(inner);
                let gw = iface
                    .gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let dns = if iface.dns_servers.is_empty() {
                    "—".to_string()
                } else {
                    iface.dns_servers.join(", ")
                };
                let mac = iface.mac.map(format_mac).unwrap_or_else(|| "—".to_string());
                let info = vec![
                    Line::from(vec![
                        Span::styled("IPv4: ", Style::default().fg(pal.text_muted)),
                        Span::styled(
                            iface
                                .ipv4
                                .map(|ip| format!("{ip}/{}", iface.prefix_len))
                                .unwrap_or_else(|| "—".to_string()),
                            Style::default().fg(pal.veil_peach),
                        ),
                        Span::styled("  GW: ", Style::default().fg(pal.text_muted)),
                        Span::styled(gw, Style::default().fg(pal.text)),
                    ]),
                    Line::from(vec![
                        Span::styled("MAC: ", Style::default().fg(pal.text_muted)),
                        Span::styled(mac, Style::default().fg(pal.text_dim)),
                        Span::styled("  MTU: ", Style::default().fg(pal.text_muted)),
                        Span::styled(iface.mtu.to_string(), Style::default().fg(pal.text_dim)),
                    ]),
                    Line::from(vec![
                        Span::styled("DNS: ", Style::default().fg(pal.text_muted)),
                        Span::styled(truncate_str(&dns, 30), Style::default().fg(pal.text_dim)),
                    ]),
                    Line::from(vec![
                        Span::styled("Total RX: ", Style::default().fg(pal.ok)),
                        Span::styled(format_bytes(iface.rx_bytes), Style::default().fg(pal.text)),
                        Span::styled("  TX: ", Style::default().fg(pal.moon_violet)),
                        Span::styled(format_bytes(iface.tx_bytes), Style::default().fg(pal.text)),
                    ]),
                ];
                frame.render_widget(Paragraph::new(info), parts[0]);
                if parts[1].height >= 2 {
                    let rate_lbl = format!(
                        "↓{} ↑{}",
                        format_bps(iface.rx_rate_bps),
                        format_bps(iface.tx_rate_bps)
                    );
                    frame.render_widget(
                        SplineChart {
                            series: &[
                                (&iface.rx_history, pal.ok),
                                (&iface.tx_history, pal.moon_violet),
                            ],
                            bg: pal.recessed,
                            max_override: None,
                            unit_label: &rate_lbl,
                        },
                        parts[1],
                    );
                }
            }
        }
    }
}

fn render_sockets_panel(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let top_padded = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        area.height.saturating_sub(1),
    );
    frame.render_widget(Block::default().style(pal.card_style()), top_padded);
    let est_cnt = app
        .snapshot
        .local_sockets
        .iter()
        .filter(|s| s.state == SocketState::Established)
        .count();
    let lis_cnt = app
        .snapshot
        .local_sockets
        .iter()
        .filter(|s| s.state == SocketState::Listen)
        .count();
    let badge = format!("{est_cnt} active • {lis_cnt} listening");
    let body = draw_card_header(
        frame,
        pal,
        top_padded,
        "Local Open & In-Use Sockets",
        Some((&badge, pal.in_use)),
    );
    let inner = inset_rect(body, 1, 0);
    if inner.height < 4 || inner.width < 24 {
        return;
    }

    // Filter row
    let f_row = Rect::new(inner.x, inner.y, inner.width, 1);
    let mut x = f_row.x;
    for &sf in SocketFilter::ALL {
        x = push_pill(
            frame,
            app,
            x,
            f_row.y,
            f_row.right(),
            &format!(" {} ", sf.label()),
            app.socket_filter == sf,
            pal,
            ClickAction::SetSocketFilter(sf),
        );
        x += 1;
    }
    let search_w = f_row.right().saturating_sub(x + 1);
    if search_w >= 14 {
        let s_rect = Rect::new(x + 1, f_row.y, search_w, 1);
        let s_bg = if app.socket_search_focused {
            pal.selection
        } else {
            pal.recessed
        };
        let txt = if app.socket_search.is_empty() && !app.socket_search_focused {
            " Filter process, port, or peer IP…".to_string()
        } else {
            format!(" {}", app.socket_search)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_str(&txt, usize::from(search_w)),
                Style::default()
                    .fg(if app.socket_search.is_empty() {
                        pal.text_muted
                    } else {
                        pal.text
                    })
                    .bg(s_bg),
            )))
            .style(Style::default().bg(s_bg)),
            s_rect,
        );
        app.hits.register(s_rect, ClickAction::FocusSocketSearch);
    }

    let list_area = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    app.hits.register_scroll(list_area, ScrollTarget::Sockets);

    let filtered: Vec<_> = app
        .snapshot
        .local_sockets
        .iter()
        .filter(|s| match app.socket_filter {
            SocketFilter::All => true,
            SocketFilter::Established => s.state == SocketState::Established,
            SocketFilter::Listen => s.state == SocketState::Listen,
        })
        .filter(|s| {
            if app.socket_search.trim().is_empty() {
                return true;
            }
            let q = app.socket_search.to_ascii_lowercase();
            s.local_addr.to_ascii_lowercase().contains(&q)
                || s.remote_addr.to_ascii_lowercase().contains(&q)
                || s.process
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&q)
                || s.proto.to_ascii_lowercase().contains(&q)
        })
        .cloned()
        .collect();

    let vis = usize::from(list_area.height);
    let max_sc = filtered.len().saturating_sub(vis);
    if app.socket_scroll > max_sc {
        app.socket_scroll = max_sc;
    }

    for (idx, sock) in filtered
        .iter()
        .skip(app.socket_scroll)
        .take(vis)
        .enumerate()
    {
        let r = Rect::new(list_area.x, list_area.y + idx as u16, list_area.width, 1);
        let bg = if idx % 2 == 1 {
            pal.surface_alt
        } else {
            pal.surface
        };
        let state_col = match sock.state {
            SocketState::Established => pal.in_use,
            SocketState::Listen => pal.open,
            SocketState::TimeWait | SocketState::CloseWait => pal.warn,
            _ => pal.text_muted,
        };
        let proc_str = match (&sock.process, sock.pid) {
            (Some(p), Some(pid)) => format!("{p}({pid})"),
            (Some(p), None) => p.clone(),
            _ => "kernel/other".to_string(),
        };
        let line = Line::from(vec![
            Span::styled(
                format!("{:<6}", sock.proto),
                Style::default().fg(pal.text_dim).bg(bg),
            ),
            Span::styled(
                format!("{:<12}", sock.state.label()),
                Style::default()
                    .fg(state_col)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:<23}", truncate_str(&sock.local_addr, 22)),
                Style::default().fg(pal.text).bg(bg),
            ),
            Span::styled("→ ", Style::default().fg(pal.text_muted).bg(bg)),
            Span::styled(
                format!("{:<23}", truncate_str(&sock.remote_addr, 22)),
                Style::default().fg(pal.veil_peach).bg(bg),
            ),
            Span::styled(
                truncate_str(&proc_str, 22),
                Style::default().fg(pal.moon_violet).bg(bg),
            ),
        ]);
        frame.render_widget(Paragraph::new(line).style(Style::default().bg(bg)), r);
        if let Some(peer_ip) = sock.remote_ip_v4 {
            app.hits.register(r, ClickAction::JumpToHostIp(peer_ip));
        }
    }
}
