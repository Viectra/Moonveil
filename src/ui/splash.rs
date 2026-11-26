//! Écran de démarrage animé et écran « terminal trop petit ».

use super::*;

pub(super) fn render_too_small(frame: &mut Frame, pal: Palette, area: Rect, lang: Language) {
    let lines = vec![
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
        ]),
        Line::from(Span::styled(
            format!(
                "{} ({}x{})",
                lang.t("Window too small", "Fenêtre trop petite"),
                area.width,
                area.height
            ),
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            lang.t("Resize >= 40x12", "Redimensionner >= 40x12"),
            Style::default().fg(pal.text_muted),
        )),
    ];
    let y = area.y + area.height.saturating_sub(3) / 2;
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .style(pal.bg_style()),
        Rect::new(area.x, y, area.width, 3.min(area.height)),
    );
}

pub(super) fn render_splash(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let phase = (app.tick_count % 20) as f64 / 20.0;
    let total_h = 18_u16;
    let y0 = area.y + area.height.saturating_sub(total_h) / 2;
    render_emblem_hero(
        frame,
        Rect::new(area.x, y0, area.width, 14),
        pal.bg,
        pal,
        phase,
    );
    let title = Line::from(vec![
        Span::styled(
            "M O O N ",
            Style::default()
                .fg(pal.moon_violet)
                .bg(pal.bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "V E I L",
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.bg)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    let sub = Line::from(Span::styled(
        app.lang().t(
            "Linux Network Radar & Socket Inspector",
            "Radar réseau Linux & inspecteur de sockets",
        ),
        Style::default().fg(pal.text_dim).bg(pal.bg),
    ));
    frame.render_widget(
        Paragraph::new(vec![Line::raw(""), title, sub]).alignment(Alignment::Center),
        Rect::new(area.x, y0 + 14, area.width, 3),
    );
    app.hits.register(area, ClickAction::SkipSplash);
}
