//! Subnet Radar tab: interactive 16x16 clickable /24 IP matrix (.0..255) & topology breakdown.

use std::net::Ipv4Addr;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::net::linux::network_addr;
use crate::net::model::{format_mac, DeviceRole, Host};
use crate::ui::hit::{ClickAction, HitRegistry};
use crate::ui::hosts::push_pill;
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};
use crate::ui::widgets::mix;

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 40 || area.height < 14 {
        return;
    }

    let base_prefix = compute_radar_prefix(app);
    let cols = if area.width >= 100 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(54), Constraint::Length(38)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(19), Constraint::Length(8)])
            .split(area)
    };

    render_matrix(frame, app, cols[0], base_prefix, pal);
    let side = if area.width >= 100 {
        Rect::new(
            cols[1].x + 1,
            cols[1].y,
            cols[1].width.saturating_sub(1),
            cols[1].height,
        )
    } else {
        cols[1]
    };
    render_tile_detail(frame, app, side, base_prefix, pal);
}

fn compute_radar_prefix(app: &App) -> [u8; 3] {
    if let Some(iface) = app.active_interface() {
        if let Some(ip) = iface.ipv4 {
            let base = if iface.prefix_len <= 23 && app.radar_page_offset > 0 {
                let net = u32::from(network_addr(ip, iface.prefix_len)) & 0xFFFF_FF00;
                net.saturating_add(app.radar_page_offset << 8)
            } else {
                u32::from(ip) & 0xFFFF_FF00
            };
            let b = Ipv4Addr::from(base).octets();
            return [b[0], b[1], b[2]];
        }
    }
    [192, 168, 1]
}

fn render_matrix(frame: &mut Frame, app: &mut App, area: Rect, prefix: [u8; 3], pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let title = format!(
        "Subnet Radar • {}.{}.{}.0/24",
        prefix[0], prefix[1], prefix[2]
    );
    let body = draw_card_header(
        frame,
        pal,
        area,
        &title,
        Some(("Click any tile", pal.veil_peach)),
    );
    let inner = inset_rect(body, 1, 0);
    if inner.height < 17 || inner.width < 52 {
        return;
    }

    // Legend & /16 page controls on top row
    let top = Rect::new(inner.x, inner.y, inner.width, 1);
    let mut lx = top.x;
    lx = push_pill(
        frame,
        app,
        lx,
        top.y,
        top.right(),
        " ◀ /24 ",
        false,
        pal,
        ClickAction::RadarPageDelta(-1),
    );
    lx += 1;
    lx = push_pill(
        frame,
        app,
        lx,
        top.y,
        top.right(),
        " /24 ▶ ",
        false,
        pal,
        ClickAction::RadarPageDelta(1),
    );
    lx += 2;
    let legend = Line::from(vec![
        Span::styled("◈ ", Style::default().fg(pal.moon_violet)),
        Span::styled("Self  ", Style::default().fg(pal.text_dim)),
        Span::styled("⬡ ", Style::default().fg(pal.veil_peach)),
        Span::styled("GW  ", Style::default().fg(pal.text_dim)),
        Span::styled("● ", Style::default().fg(pal.ok)),
        Span::styled("Trusted  ", Style::default().fg(pal.text_dim)),
        Span::styled("● ", Style::default().fg(pal.crit)),
        Span::styled("New  ", Style::default().fg(pal.text_dim)),
        Span::styled("· ", Style::default().fg(pal.text_muted)),
        Span::styled("Free", Style::default().fg(pal.text_muted)),
    ]);
    if lx < top.right() {
        frame.render_widget(
            Paragraph::new(legend).style(Style::default().bg(pal.surface)),
            Rect::new(lx, top.y, top.right() - lx, 1),
        );
    }

    let host_map: std::collections::HashMap<Ipv4Addr, &Host> =
        app.snapshot.hosts.iter().map(|h| (h.ip, h)).collect();
    let sweep_octet = if app.scan_progress.active {
        Some((app.tick_count % 256) as u8)
    } else {
        None
    };

    let cell_w = ((inner.width.saturating_sub(4)) / 16).clamp(3, 5);
    let grid_y0 = inner.y + 2;

    for row in 0..16_u8 {
        let y = grid_y0 + u16::from(row);
        if y >= inner.bottom() {
            break;
        }
        // Row header (.00, .16, ...)
        let rh = format!("{:02X}:", row * 16);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                rh,
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ))),
            Rect::new(inner.x, y, 3, 1),
        );

        for col in 0..16_u8 {
            let octet = row * 16 + col;
            let ip = Ipv4Addr::new(prefix[0], prefix[1], prefix[2], octet);
            let tile_rect = Rect::new(inner.x + 4 + u16::from(col) * cell_w, y, cell_w, 1);
            if tile_rect.right() > inner.right() {
                break;
            }
            let hovered = HitRegistry::is_hovered(tile_rect, app.hover);
            let selected = app.radar_selected_octet == octet;
            let host = host_map.get(&ip).copied();
            let is_sweep = sweep_octet == Some(octet);

            let (fg, mut bg, glyph) = if octet == 0 || octet == 255 {
                (pal.text_muted, pal.recessed, "·")
            } else if let Some(h) = host {
                let c = match h.role {
                    DeviceRole::ThisMachine => pal.moon_violet,
                    DeviceRole::Gateway => pal.veil_peach,
                    _ if !h.online => pal.text_muted,
                    _ if !h.trusted => pal.crit,
                    _ => pal.ok,
                };
                (c, pal.surface_alt, h.role.icon())
            } else {
                (pal.text_muted, pal.surface, "·")
            };

            if is_sweep {
                bg = mix(bg, pal.moon_violet, 0.55);
            } else if selected {
                bg = pal.selection;
            } else if hovered {
                bg = pal.hover;
            }

            let label = if cell_w >= 4 {
                format!("{glyph}{octet:02X}")
            } else {
                format!("{glyph}{octet:1X}")
            };
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    truncate_str(&label, usize::from(cell_w)),
                    Style::default()
                        .fg(fg)
                        .bg(bg)
                        .add_modifier(if host.is_some() {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                )))
                .style(Style::default().bg(bg)),
                tile_rect,
            );
            app.hits
                .register(tile_rect, ClickAction::SelectRadarOctet(octet));
        }
    }
}

fn render_tile_detail(frame: &mut Frame, app: &mut App, area: Rect, prefix: [u8; 3], pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let ip = Ipv4Addr::new(prefix[0], prefix[1], prefix[2], app.radar_selected_octet);
    let body = draw_card_header(frame, pal, area, &format!("Tile {ip}"), None);
    let inner = inset_rect(body, 1, 0);
    if inner.height < 4 {
        return;
    }

    if let Some(host) = app.snapshot.hosts.iter().find(|h| h.ip == ip).cloned() {
        let (iu, op, filt, cl) = host.port_counts();
        let lines = vec![
            Line::from(vec![
                Span::styled(host.role.icon(), Style::default().fg(pal.moon_violet)),
                Span::styled(
                    format!(" {}", host.display_name()),
                    Style::default().fg(pal.text).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(Span::styled(
                format!(
                    "MAC: {}",
                    host.mac.map(format_mac).unwrap_or_else(|| "—".into())
                ),
                Style::default().fg(pal.text_dim),
            )),
            Line::from(Span::styled(
                format!("Vendor: {}", host.vendor.as_deref().unwrap_or("—")),
                Style::default().fg(pal.veil_peach),
            )),
            Line::from(Span::styled(
                format!("Ports: {iu} in-use • {op} open • {filt} filt • {cl} closed"),
                Style::default().fg(pal.ok),
            )),
        ];
        let detail_h = inner.height.saturating_sub(2);
        frame.render_widget(
            Paragraph::new(lines)
                .style(Style::default().bg(pal.surface))
                .wrap(Wrap { trim: true }),
            Rect::new(inner.x, inner.y, inner.width, detail_h),
        );
        let btn_y = inner.bottom().saturating_sub(1);
        let _ = push_pill(
            frame,
            app,
            inner.x,
            btn_y,
            inner.right(),
            " Open in Hosts Inspector ",
            true,
            pal,
            ClickAction::JumpToHostIp(ip),
        );
    } else {
        let role_note = if app.radar_selected_octet == 0 {
            "Network base address"
        } else if app.radar_selected_octet == 255 {
            "Subnet broadcast address"
        } else {
            "No live host detected on this IP yet."
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(role_note, Style::default().fg(pal.text_dim))),
                Line::from(Span::styled(
                    "Press 's' or Scan to probe.",
                    Style::default().fg(pal.text_muted),
                )),
            ])
            .style(Style::default().bg(pal.surface))
            .wrap(Wrap { trim: true }),
            inner,
        );
    }
}
