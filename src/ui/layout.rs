//! Ossature de l'interface : barre latérale avec emblème, topbar compacte, espace de travail et pied de page.

use super::*;

pub(super) fn render_sidebar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar).fg(pal.text)),
        area,
    );
    let inner = inset_rect(area, 1, 1);
    if inner.width < 10 || inner.height < 14 {
        return;
    }

    let mut y = inner.y;
    // Compact half-block logo emblem when height allows
    if inner.height >= 24 {
        render_emblem_compact(
            frame,
            Rect::new(inner.x, y, inner.width, 6),
            pal.sidebar,
            pal,
            app.pulse_phase(),
        );
        y += 6;
    }

    // MOONVEIL wordmark
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "MOON",
                Style::default()
                    .fg(pal.moon_violet)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "VEIL",
                Style::default()
                    .fg(pal.veil_peach)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .alignment(Alignment::Center),
        Rect::new(inner.x, y, inner.width, 1),
    );
    y += 1;

    // Host / privilege status pill
    let dot_col = if app.scan_progress.active {
        mix(pal.moon_violet, pal.veil_peach, app.pulse_phase())
    } else {
        pal.ok
    };
    let priv_badge = app.snapshot.privilege.badge();
    let host_line = format!("{}@{}", app.snapshot.username, app.snapshot.hostname);
    let mut status_spans = vec![
        Span::styled("● ", Style::default().fg(dot_col).bg(pal.sidebar)),
        Span::styled(
            truncate_str(&host_line, inner.width.saturating_sub(8) as usize),
            Style::default().fg(pal.text_dim).bg(pal.sidebar),
        ),
        Span::styled(
            format!(" {priv_badge}"),
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.sidebar)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if app.demo_mode && inner.width >= 20 {
        status_spans = vec![
            Span::styled("● ", Style::default().fg(pal.warn).bg(pal.sidebar)),
            Span::styled(
                app.lang().t("DEMO MODE ", "MODE DÉMO "),
                Style::default()
                    .fg(pal.warn)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                priv_badge,
                Style::default().fg(pal.text_dim).bg(pal.sidebar),
            ),
        ];
    }
    frame.render_widget(
        Paragraph::new(Line::from(status_spans)).style(Style::default().bg(pal.sidebar)),
        Rect::new(inner.x, y, inner.width, 1),
    );
    y += 2;

    // Navigation items
    let hosts_online = app.snapshot.hosts.iter().filter(|h| h.online).count();
    for &tab in Tab::ALL {
        if tab == Tab::Settings && y + 6 < inner.bottom() {
            y += 1;
        }
        if y + 3 >= inner.bottom() {
            break;
        }
        let item_rect = Rect::new(inner.x, y, inner.width, 1);
        let active = app.tab == tab;
        let hovered = HitRegistry::is_hovered(item_rect, app.hover);
        let bg = if active {
            pal.accent
        } else if hovered {
            pal.hover
        } else {
            pal.sidebar
        };
        let fg = if active { pal.accent_fg } else { pal.text };
        let count_hint = match tab {
            Tab::Hosts => format!("{hosts_online}"),
            Tab::Network => format!("{}", app.visible_interfaces().len()),
            Tab::Watch => format!("{}", app.timeline.len()),
            _ => String::new(),
        };
        let label = format!(" {} {}", tab.icon(), tab.label_for(app.lang()));
        let pad = usize::from(inner.width).saturating_sub(
            unicode_width::UnicodeWidthStr::width(label.as_str()) + count_hint.len() + 1,
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    label,
                    Style::default().fg(fg).bg(bg).add_modifier(if active {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
                Span::styled(" ".repeat(pad), Style::default().bg(bg)),
                Span::styled(
                    format!("{count_hint} "),
                    Style::default()
                        .fg(if active {
                            pal.accent_fg
                        } else {
                            pal.text_muted
                        })
                        .bg(bg),
                ),
            ])),
            item_rect,
        );
        app.hits.register(item_rect, ClickAction::SwitchTab(tab));
        y += 1;
    }

    // Bottom Help / Quit pills
    let foot_y = inner.bottom().saturating_sub(1);
    let half_w = inner.width / 2;
    let help_r = Rect::new(inner.x, foot_y, half_w.saturating_sub(1), 1);
    let quit_r = Rect::new(inner.x + half_w, foot_y, inner.width - half_w, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            app.lang().t(" ? Help ", " ? Aide "),
            pal.pill_style(
                matches!(app.modal, Modal::Help),
                HitRegistry::is_hovered(help_r, app.hover),
            ),
        ))),
        help_r,
    );
    app.hits.register(help_r, ClickAction::ToggleHelp);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            app.lang().t(" × Quit ", " × Quitter "),
            pal.pill_style(false, HitRegistry::is_hovered(quit_r, app.hover)),
        ))),
        quit_r,
    );
    app.hits.register(quit_r, ClickAction::Quit);
}

pub(super) fn render_workspace(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let padded = inset_rect(area, 1, 1);
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(1)])
        .split(padded);
    render_active_tab(frame, app, split[0]);
    render_status_footer(frame, app, split[1], pal);
}

pub(super) fn render_compact_topbar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        area,
    );
    let mut x = area.x + 1;
    let brand = Rect::new(x, area.y, 9, 1);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "MOON",
                Style::default()
                    .fg(pal.moon_violet)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "VEIL",
                Style::default()
                    .fg(pal.veil_peach)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
        ])),
        brand,
    );
    x += 10;

    for &tab in Tab::ALL {
        let lbl = format!(" {} ", tab.short_label_for(app.lang()));
        let w = unicode_width::UnicodeWidthStr::width(lbl.as_str()) as u16;
        if x + w + 8 > area.right() {
            break;
        }
        let r = Rect::new(x, area.y, w, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lbl,
                pal.pill_style(app.tab == tab, HitRegistry::is_hovered(r, app.hover)),
            ))),
            r,
        );
        app.hits.register(r, ClickAction::SwitchTab(tab));
        x += w + 1;
    }

    // Compact Mode toggle on right
    let m_lbl = format!(" {} ", app.config.mode.label_for(app.lang()));
    let mw = unicode_width::UnicodeWidthStr::width(m_lbl.as_str()) as u16;
    if area.right() > x + mw + 2 {
        let mr = Rect::new(area.right() - mw - 1, area.y, mw, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                m_lbl,
                pal.pill_style(true, HitRegistry::is_hovered(mr, app.hover)),
            ))),
            mr,
        );
        app.hits.register(mr, ClickAction::ToggleMode);
    }
}

pub(super) fn render_status_footer(frame: &mut Frame, app: &App, area: Rect, pal: Palette) {
    let lang = app.lang();
    let msg = if let Some((toast, _)) = &app.toast {
        toast.clone()
    } else if app.scan_progress.active {
        format!(
            "{} • {} ({}/{})",
            app.scan_progress.phase,
            app.scan_progress.current_target,
            app.scan_progress.probed,
            app.scan_progress.total
        )
    } else {
        let last = app
            .scan_progress
            .last_duration_ms
            .map(|d| format!(" • {} {d}ms", lang.t("Last scan", "Dernier scan")))
            .unwrap_or_default();
        let privilege = app.snapshot.privilege.description_for(lang);
        let mode = app.config.mode.label_for(lang);
        if lang.is_fr() {
            format!(
                "{privilege} • Mode {mode} • 1-5 Vues • m Mode • s Scan • / Recherche • ? Aide{last}"
            )
        } else {
            format!(
                "{privilege} • {mode} Mode • 1-5 Views • m Mode • s Scan • / Search • ? Help{last}"
            )
        }
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate_str(&msg, usize::from(area.width)),
            Style::default()
                .fg(if app.toast.is_some() {
                    pal.veil_peach
                } else {
                    pal.text_muted
                })
                .bg(pal.bg),
        ))),
        area,
    );
}
