//! Tableau triable des hôtes : en-têtes cliquables et lignes avec ports, RTT et confiance.

use super::*;

pub(super) fn render_host_table(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let hosts: Vec<Host> = app.filtered_hosts().into_iter().cloned().collect();
    let online_cnt = hosts.iter().filter(|h| h.online).count();
    let lang = app.lang();
    let badge = format!("{online_cnt}/{} {}", hosts.len(), lang.t("up", "actifs"));
    let body = draw_card_header(
        frame,
        pal,
        area,
        &format!(
            "{} ({})",
            lang.t("Discovered Hosts", "Hôtes découverts"),
            app.config.mode.subtitle_for(lang)
        ),
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
                lang.t(
                    "  No hosts match current filter. Press 's' or click Scan.",
                    "  Aucun hôte ne correspond au filtre. Appuyez sur 's' ou cliquez sur Scan.",
                ),
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

        render_host_row(frame, host, row_rect, row_bg, pal, is_adv, lang);
        app.hits
            .register(row_rect, ClickAction::SelectHost(host.ip));
    }
}

pub(super) fn render_table_header(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    is_adv: bool,
) {
    let lang = app.lang();
    let cols: Vec<(&str, HostSortColumn, u16)> = if is_adv {
        vec![
            ("IP", HostSortColumn::Ip, 16),
            (
                lang.t("MAC / Vendor", "MAC / Fabricant"),
                HostSortColumn::Vendor,
                22,
            ),
            ("RTT", HostSortColumn::Rtt, 8),
            (lang.t("Use", "Util"), HostSortColumn::InUsePorts, 5),
            (lang.t("Open", "Ouv"), HostSortColumn::OpenPorts, 6),
            (lang.t("Host / OS", "Hôte / OS"), HostSortColumn::Name, 18),
        ]
    } else {
        vec![
            (lang.t("Device", "Appareil"), HostSortColumn::Name, 20),
            ("IP", HostSortColumn::Ip, 16),
            (lang.t("Vendor", "Fabricant"), HostSortColumn::Vendor, 14),
            ("Ping", HostSortColumn::Rtt, 8),
            ("Services", HostSortColumn::OpenPorts, 16),
        ]
    };

    let mut x = area.x;
    for &(label, col, width) in &cols {
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

pub(super) fn render_host_row(
    frame: &mut Frame,
    host: &Host,
    area: Rect,
    bg: Color,
    pal: Palette,
    is_adv: bool,
    lang: Language,
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
            lang.t("Offline (Saved)", "Hors ligne (enregistré)")
                .to_string()
        } else if tags.is_empty() && iu + op == 0 {
            lang.t("No open ports", "Aucun port ouvert").to_string()
        } else if tags.is_empty() {
            format!(
                "{iu} {} • {op} {}",
                lang.t("use", "utilisés"),
                lang.t("open", "ouverts")
            )
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
