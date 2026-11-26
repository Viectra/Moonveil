//! Subnet Radar tab: clickable 16x16 IPv4 matrix (.0–.255), /24 pager, and selected host summary.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::config::Language;
use crate::net::linux::network_addr;
use crate::net::model::DeviceRole;
use crate::ui::hit::ClickAction;
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};

/// Renders the interactive `16×16` Subnet Radar matrix and selected-tile inspector.
pub fn render(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let cols = if area.width >= 96 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(54), Constraint::Length(36)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(18), Constraint::Length(12)])
            .split(area)
    };

    render_matrix_card(frame, app, cols[0], pal);
    render_tile_detail_card(frame, app, cols[1], pal);
}

fn render_matrix_card(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 1);
    if inner.width < 20 || inner.height < 10 {
        return;
    }

    let lang = app.lang();
    let iface = app.active_interface().cloned();
    let (cidr, page_count, slice_prefix, slice_octets_base) = match &iface {
        Some(i) => {
            let pages = i.slash24_page_count().max(1);
            let page = app.radar_page_offset % pages;
            let base = u32::from(network_addr(i.ip, i.prefix_len)) + page * 256;
            let base_ip = Ipv4Addr::from(base);
            let o = base_ip.octets();
            (
                i.cidr.clone(),
                pages,
                format!("{}.{}.{}.0/24", o[0], o[1], o[2]),
                base,
            )
        }
        None => (
            "—".to_string(),
            1,
            "192.168.1.0/24".to_string(),
            0xC0A8_0100,
        ),
    };

    let title = match lang {
        Language::En => format!("Subnet Radar ({slice_prefix})"),
        Language::Fr => format!("Radar réseau ({slice_prefix})"),
    };
    let badge = if page_count > 1 {
        format!(
            "{cidr} [{}/{}]",
            (app.radar_page_offset % page_count) + 1,
            page_count
        )
    } else {
        cidr
    };
    let mut body = draw_card_header(frame, pal, inner, &title, Some((&badge, pal.veil_peach)));

    if page_count > 1 && body.height >= 2 {
        let ctrl_row = Rect::new(body.x, body.y, body.width, 1);
        let prev_s = lang.t(" ◀ Prev /24 ", " ◀ Préc /24 ");
        let next_s = lang.t(" Next /24 ▶ ", " Suiv /24 ▶ ");
        let prev_rect = Rect::new(ctrl_row.x, ctrl_row.y, prev_s.width() as u16, 1);
        let next_rect = Rect::new(
            ctrl_row.x + prev_s.width() as u16 + 2,
            ctrl_row.y,
            next_s.width() as u16,
            1,
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                prev_s,
                pal.pill_style(false, app.hits.is_hovered(prev_rect)),
            ))),
            prev_rect,
        );
        app.hits.record(prev_rect, ClickAction::RadarPageDelta(-1));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                next_s,
                pal.pill_style(false, app.hits.is_hovered(next_rect)),
            ))),
            next_rect,
        );
        app.hits.record(next_rect, ClickAction::RadarPageDelta(1));
        body.y += 1;
        body.height = body.height.saturating_sub(1);
    }

    let mut host_by_oct = HashMap::new();
    for h in &app.snapshot.hosts {
        let u = u32::from(h.ip);
        if u >= slice_octets_base && u < slice_octets_base + 256 {
            host_by_oct.insert((u - slice_octets_base) as u8, h);
        }
    }

    let col_w = ((usize::from(body.width.saturating_sub(5))) / 16).clamp(3, 5) as u16;
    for row_idx in 0..16_u16 {
        let py = body.y + row_idx;
        if py >= body.bottom().saturating_sub(2) {
            break;
        }
        let row_label = format!(".{:02X} ", row_idx * 16);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                row_label,
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ))),
            Rect::new(body.x, py, 4, 1),
        );

        for col_idx in 0..16_u16 {
            let oct = (row_idx * 16 + col_idx) as u8;
            let px = body.x + 4 + col_idx * col_w;
            if px + col_w > body.right() {
                break;
            }
            let tile_rect = Rect::new(px, py, col_w, 1);
            let is_selected = app.radar_selected_octet == oct;
            let host_opt = host_by_oct.get(&oct).copied();

            let (fg, bg, sym) = match host_opt {
                Some(h) if h.role == DeviceRole::ThisMachine => {
                    (pal.bg, pal.veil_peach, format!("{oct:>2}✦"))
                }
                Some(h) if h.role == DeviceRole::Gateway => {
                    (pal.bg, pal.moon_violet, format!("{oct:>2}◈"))
                }
                Some(h) if h.online => (pal.ok, pal.selection, format!("{oct:>2}●")),
                Some(_) => (pal.warn, pal.surface_alt, format!("{oct:>2}○")),
                None => (pal.text_muted, pal.surface, format!("{oct:>2}·")),
            };

            let style = if is_selected {
                Style::default()
                    .fg(pal.accent_fg)
                    .bg(pal.accent)
                    .add_modifier(Modifier::BOLD)
            } else if app.hits.is_hovered(tile_rect) {
                Style::default().fg(pal.text).bg(pal.hover)
            } else {
                Style::default().fg(fg).bg(bg)
            };

            let cell_str = if col_w >= 4 { format!(" {sym}") } else { sym };
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(cell_str, style))),
                tile_rect,
            );
            app.hits
                .record(tile_rect, ClickAction::SelectRadarOctet(oct));
        }
    }

    let legend_y = body.bottom().saturating_sub(1);
    let legend = Line::from(vec![
        Span::styled("✦ ", Style::default().fg(pal.veil_peach).bg(pal.surface)),
        Span::styled(
            lang.t("This PC   ", "Ce PC   "),
            Style::default().fg(pal.text_dim).bg(pal.surface),
        ),
        Span::styled("◈ ", Style::default().fg(pal.moon_violet).bg(pal.surface)),
        Span::styled(
            lang.t("Gateway   ", "Passerelle   "),
            Style::default().fg(pal.text_dim).bg(pal.surface),
        ),
        Span::styled("● ", Style::default().fg(pal.ok).bg(pal.surface)),
        Span::styled(
            lang.t("Online   ", "En ligne   "),
            Style::default().fg(pal.text_dim).bg(pal.surface),
        ),
        Span::styled("· ", Style::default().fg(pal.text_muted).bg(pal.surface)),
        Span::styled(
            lang.t("Free / Unseen", "Libre"),
            Style::default().fg(pal.text_muted).bg(pal.surface),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(legend),
        Rect::new(body.x, legend_y, body.width, 1),
    );
}

fn render_tile_detail_card(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 1);
    if inner.width < 14 || inner.height < 6 {
        return;
    }

    let lang = app.lang();
    let base = app
        .active_interface()
        .map(|i| {
            let pages = i.slash24_page_count().max(1);
            let page = app.radar_page_offset % pages;
            u32::from(network_addr(i.ip, i.prefix_len)) + page * 256
        })
        .unwrap_or(0xC0A8_0100);
    let tile_ip = Ipv4Addr::from((base & 0xFFFFFF00) + u32::from(app.radar_selected_octet));

    let body = draw_card_header(
        frame,
        pal,
        inner,
        &tile_ip.to_string(),
        Some((lang.t("Tile", "Tuile"), pal.moon_violet)),
    );

    if let Some(host) = app.snapshot.hosts.iter().find(|h| h.ip == tile_ip).cloned() {
        let name = host.display_name_for(lang);
        let (iu, op, _, _) = host.port_counts();
        let vendor = host
            .short_vendor_name()
            .unwrap_or_else(|| host.vendor.clone().unwrap_or_else(|| "—".to_string()));
        let lines = vec![
            Line::from(Span::styled(
                truncate_str(&name, usize::from(body.width)),
                Style::default()
                    .fg(pal.veil_peach)
                    .bg(pal.surface)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!("{}: {}", lang.t("Role", "Rôle"), host.role.label_for(lang)),
                Style::default().fg(pal.text_dim).bg(pal.surface),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: {}",
                    lang.t("Vendor", "Fabricant"),
                    truncate_str(&vendor, usize::from(body.width.saturating_sub(11)))
                ),
                Style::default().fg(pal.text_dim).bg(pal.surface),
            )),
            Line::from(Span::styled(
                format!("MAC: {}", host.mac_string()),
                Style::default().fg(pal.text_dim).bg(pal.surface),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: {} ({} {})",
                    lang.t("Ports", "Ports"),
                    iu + op,
                    iu,
                    lang.t("active", "actifs")
                ),
                Style::default().fg(pal.text).bg(pal.surface),
            )),
        ];
        frame.render_widget(Paragraph::new(lines), body);

        let btn_lbl = lang.t(" Inspect Host → ", " Inspecter l'hôte → ");
        let btn_rect = Rect::new(
            body.x,
            body.bottom().saturating_sub(1),
            (btn_lbl.width() as u16).min(body.width),
            1,
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                btn_lbl,
                Style::default()
                    .fg(pal.accent_fg)
                    .bg(pal.accent)
                    .add_modifier(Modifier::BOLD),
            ))),
            btn_rect,
        );
        app.hits
            .record(btn_rect, ClickAction::JumpToHostIp(tile_ip));
    } else {
        let lines = vec![
            Line::from(Span::styled(
                lang.t(
                    "No host observed at this address.",
                    "Aucun hôte détecté à cette adresse.",
                ),
                Style::default().fg(pal.text_muted).bg(pal.surface),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!(
                    "{}: {}/{} {}",
                    lang.t("Active subnet hosts", "Hôtes actifs"),
                    app.snapshot.hosts.iter().filter(|h| h.online).count(),
                    app.snapshot.hosts.len(),
                    lang.t("total", "total")
                ),
                Style::default().fg(pal.text_dim).bg(pal.surface),
            )),
        ];
        frame.render_widget(Paragraph::new(lines), body);
    }
}
