//! Modales flottantes : aide, renommage d'hôte, ports personnalisés et traceroute.

use super::*;

pub(super) fn centered_rect(area: Rect, w: u16, h: u16) -> Rect {
    let cw = w.min(area.width.saturating_sub(2));
    let ch = h.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + area.width.saturating_sub(cw) / 2,
        area.y + area.height.saturating_sub(ch) / 2,
        cw,
        ch,
    )
}

pub(super) fn render_help_modal(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let modal = centered_rect(area, 64, 24);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(1)])
        .split(inner);

    let lang = app.lang();
    let help_rows: &[(&str, &str)] = &[
        (
            "1-5 / Tab      Switch views (Hosts, Radar, Network, Watch, Settings)",
            "1-5 / Tab      Changer de vue (Hôtes, Radar, Réseau, Veille, Paramètres)",
        ),
        (
            "m              Toggle Normal Mode <-> Advanced Mode",
            "m              Basculer mode Normal <-> mode Avancé",
        ),
        (
            "s              Start or stop subnet + port scan",
            "s              Lancer ou arrêter le scan sous-réseau + ports",
        ),
        (
            "p              Cycle scan preset (Quick, Top100, Full, Web/Dev, Custom)",
            "p              Changer de préréglage (Rapide, Top100, Complet, Web/Dev, Perso)",
        ),
        (
            "w              Toggle background Watch Mode",
            "w              Activer/désactiver le mode Veille en arrière-plan",
        ),
        (
            "/              Search (port:22 state:in-use state:closed vendor:apple)",
            "/              Rechercher (port:22 state:in-use state:closed vendor:apple)",
        ),
        (
            "t / n          Trust toggle / Rename host nickname",
            "t / n          Basculer confiance / Renommer le surnom de l'hôte",
        ),
        (
            "j / k / ↑ / ↓  Navigate host list • Mouse wheel scrolls any list",
            "j / k / ↑ / ↓  Parcourir les hôtes • La molette fait défiler les listes",
        ),
        (
            "e              Export snapshot JSON • q / Esc to close",
            "e              Exporter un instantané JSON • q / Échap pour fermer",
        ),
    ];
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                "MOON",
                Style::default()
                    .fg(pal.moon_violet)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "VEIL",
                Style::default()
                    .fg(pal.veil_peach)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                lang.t(
                    " — Shortcuts & Mouse Controls",
                    " — Raccourcis & contrôles souris",
                ),
                Style::default().fg(pal.text),
            ),
        ]),
        Line::raw(""),
    ];
    lines.extend(help_rows.iter().map(|&(en, fr)| {
        Line::from(Span::styled(
            lang.t(en, fr),
            Style::default().fg(pal.text_dim),
        ))
    }));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[0]);

    let close_lbl = lang.t(" Close (Esc) ", " Fermer (Échap) ");
    let close_r = Rect::new(
        rows[1].x,
        rows[1].y,
        unicode_width::UnicodeWidthStr::width(close_lbl) as u16,
        1,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            close_lbl,
            pal.pill_style(true, false),
        ))),
        close_r,
    );
    app.hits.register(close_r, ClickAction::CloseModal);
}

pub(super) fn render_rename_modal(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    ip: std::net::Ipv4Addr,
    input: &str,
) {
    let modal = centered_rect(area, 52, 7);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);
    let lines = vec![
        Line::from(Span::styled(
            format!("{} ({ip})", app.lang().t("Rename Host", "Renommer l'hôte")),
            Style::default()
                .fg(pal.veil_peach)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            format!(" {input}▏"),
            Style::default().fg(pal.text).bg(pal.recessed),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            app.lang().t(
                "Enter to save • Esc to cancel",
                "Entrée pour enregistrer • Échap pour annuler",
            ),
            Style::default().fg(pal.text_muted),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
    app.hits.register(
        Rect::new(inner.x, inner.bottom().saturating_sub(1), 16, 1),
        ClickAction::CloseModal,
    );
}

pub(super) fn render_custom_ports_modal(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    input: &str,
    error: Option<&str>,
) {
    let modal = centered_rect(area, 58, 8);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);
    let mut lines = vec![
        Line::from(Span::styled(
            app.lang().t(
                "Custom Port Range (e.g. 22,80,443,3000-3010)",
                "Plage de ports perso (ex. 22,80,443,3000-3010)",
            ),
            Style::default()
                .fg(pal.veil_peach)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            format!(" {input}▏"),
            Style::default().fg(pal.text).bg(pal.recessed),
        )),
    ];
    if let Some(err) = error {
        lines.push(Line::from(Span::styled(err, Style::default().fg(pal.crit))));
    } else {
        lines.push(Line::raw(""));
    }
    lines.push(Line::from(Span::styled(
        app.lang().t(
            "Enter to apply & select Custom preset • Esc to cancel",
            "Entrée pour appliquer le préréglage Perso • Échap pour annuler",
        ),
        Style::default().fg(pal.text_muted),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
    app.hits.register(
        Rect::new(inner.x, inner.bottom().saturating_sub(1), 16, 1),
        ClickAction::CloseModal,
    );
}

pub(super) fn render_traceroute_modal(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    ip: std::net::Ipv4Addr,
) {
    let modal = centered_rect(area, 62, 18);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(inner);

    let lang = app.lang();
    let status = if app.trace_running {
        lang.t("Tracing…", "Traçage…")
    } else {
        lang.t("Done", "Terminé")
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("Traceroute -> {ip}  "),
                Style::default()
                    .fg(pal.veil_peach)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(status, Style::default().fg(pal.moon_violet)),
        ])),
        rows[0],
    );

    let hop_lines: Vec<Line> = if app.trace_hops.is_empty() {
        vec![Line::from(Span::styled(
            lang.t("Probing route hops…", "Sondage des sauts de la route…"),
            Style::default().fg(pal.text_muted),
        ))]
    } else {
        app.trace_hops
            .iter()
            .map(|h| {
                let ip_s =
                    h.ip.map(|x| x.to_string())
                        .unwrap_or_else(|| "*".to_string());
                let name_s = h.hostname.as_deref().unwrap_or("");
                let rtt_s = h
                    .rtt_ms
                    .map(|r| format!("{r:.2} ms"))
                    .unwrap_or_else(|| lang.t("timeout", "délai dépassé").to_string());
                Line::from(vec![
                    Span::styled(
                        format!(" {:>2}  ", h.ttl),
                        Style::default().fg(pal.text_muted),
                    ),
                    Span::styled(format!("{ip_s:<16}"), Style::default().fg(pal.text)),
                    Span::styled(
                        format!("{:<22}", truncate_str(name_s, 20)),
                        Style::default().fg(pal.text_dim),
                    ),
                    Span::styled(rtt_s, Style::default().fg(pal.ok)),
                ])
            })
            .collect()
    };
    frame.render_widget(Paragraph::new(hop_lines), rows[1]);

    let close_lbl = lang.t(" Close (Esc) ", " Fermer (Échap) ");
    let close_r = Rect::new(
        rows[2].x,
        rows[2].y,
        unicode_width::UnicodeWidthStr::width(close_lbl) as u16,
        1,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            close_lbl,
            pal.pill_style(true, false),
        ))),
        close_r,
    );
    app.hits.register(close_r, ClickAction::CloseModal);
}
