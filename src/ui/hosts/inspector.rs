//! Inspecteur détaillé de l'hôte sélectionné : métadonnées, courbe RTT, filtres/liste de ports et actions.

use super::*;

pub(super) fn render_inspector(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let lang = app.lang();
    let Some(host) = app.selected_host().cloned() else {
        let body = draw_card_header(
            frame,
            pal,
            area,
            lang.t("Host Inspector", "Inspecteur d'hôte"),
            None,
        );
        frame.render_widget(
            Paragraph::new(lang.t(
                "  Click any host to inspect IPs, MACs, ports, and services.",
                "  Cliquez sur un hôte pour inspecter IP, MAC, ports et services.",
            ))
            .style(Style::default().fg(pal.text_muted).bg(pal.surface))
            .wrap(Wrap { trim: true }),
            body,
        );
        return;
    };

    let trust_lbl = if host.trusted {
        lang.t("★ Trusted", "★ De confiance")
    } else {
        lang.t("! Untrusted", "! Non fiable")
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
        .unwrap_or_else(|| lang.t("Unknown", "Inconnue").to_string());
    let vend_str = host
        .vendor
        .as_deref()
        .unwrap_or(lang.t("Unknown vendor", "Fabricant inconnu"));
    let rtt_str = host
        .rtt_ms
        .map(|r| format!("{r:.2} ms"))
        .unwrap_or_else(|| lang.t("offline", "hors ligne").to_string());

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
            Span::styled(
                lang.t("Vendor: ", "Fabricant : "),
                Style::default().fg(pal.text_muted),
            ),
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
                truncate_str(
                    host.os_guess
                        .as_deref()
                        .unwrap_or(lang.t("Unknown", "Inconnu")),
                    20,
                ),
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
            Span::styled(
                lang.t("Role: ", "Rôle : "),
                Style::default().fg(pal.text_muted),
            ),
            Span::styled(host.role.label_for(lang), Style::default().fg(pal.text_dim)),
            Span::styled(
                lang.t("  Status: ", "  Statut : "),
                Style::default().fg(pal.text_muted),
            ),
            Span::styled(
                if host.online {
                    lang.t("Online", "En ligne")
                } else {
                    lang.t("Offline", "Hors ligne")
                },
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
        let lbl = format!(" {}({}) ", pf.label_for(lang), cnt);
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
        let txt = if lang.is_fr() {
            format!(" + {collapsed_closed} ports fermés (cliquer pour déplier) ")
        } else {
            format!(" + {collapsed_closed} Closed ports (click to expand) ")
        };
        let txt_w = unicode_width::UnicodeWidthStr::width(txt.as_str()) as u16;
        let pill_rect = Rect::new(ports_rect.x, row_y, ports_rect.width.min(txt_w), 1);
        let hovered = HitRegistry::is_hovered(pill_rect, app.hover);
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
                lang.t(" - Collapse closed ports ", " - Replier les ports fermés "),
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
            lang.t(" → Trace ", " → Tracer "),
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
            lang.t(" ▶ Deep ", " ▶ Approfondi "),
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
            lang.t(" * Rename ", " * Renommer "),
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
            lang.t(" + Copy IP ", " + Copier IP "),
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
                lang.t(" + Copy MAC ", " + Copier MAC "),
                false,
                pal,
                ClickAction::CopyText("MAC".to_string(), format_mac(mac)),
            );
        }
    }
}
