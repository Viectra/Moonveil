//! Launch splash animation and terminal minimum-size guard screen.

use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::config::Language;
use crate::ui::hit::ClickAction;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_emblem_hero;

/// Renders the animated launch logo screen; clicking anywhere dismisses it immediately.
pub(super) fn render_splash(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    app.hits.record(area, ClickAction::DismissSplash);

    let y_center = area.y + area.height.saturating_sub(14) / 2;
    let logo_area = Rect::new(area.x, y_center, area.width, 8);
    let phase = (f64::from(18_u16.saturating_sub(app.splash_ticks_remaining)) / 18.0) % 1.0;
    render_emblem_hero(frame, logo_area, pal.bg, pal, phase);

    let lang = app.lang();
    let wordmark_y = (y_center + 9).min(area.bottom().saturating_sub(3));
    let lines = vec![
        Line::from(vec![
            Span::styled(
                "MOON",
                Style::default()
                    .fg(pal.moon_violet)
                    .bg(pal.bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "VEIL",
                Style::default()
                    .fg(pal.veil_peach)
                    .bg(pal.bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(pal.text_muted).bg(pal.bg),
            ),
        ]),
        Line::from(Span::styled(
            lang.t(
                "Network & Port Radar by Viectra",
                "Radar réseau & ports par Viectra",
            ),
            Style::default().fg(pal.text_dim).bg(pal.bg),
        )),
        Line::from(Span::styled(
            lang.t(
                "Click or press any key to continue…",
                "Cliquez ou appuyez sur une touche…",
            ),
            Style::default().fg(pal.text_muted).bg(pal.bg),
        )),
    ];
    let text_rect = Rect::new(
        area.x,
        wordmark_y,
        area.width,
        area.bottom().saturating_sub(wordmark_y).min(4),
    );
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        text_rect,
    );
}

/// Renders a friendly notice when the terminal window is below `56x14`.
pub(super) fn render_too_small(frame: &mut Frame, area: Rect, pal: Palette, lang: Language) {
    let msg = vec![
        Line::from(Span::styled(
            "MOONVEIL",
            Style::default()
                .fg(pal.moon_violet)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!(
                "{} ({}x{}, min 56x14)",
                lang.t("Terminal too small", "Terminal trop petit"),
                area.width,
                area.height
            ),
            Style::default().fg(pal.warn),
        )),
    ];
    let y = area.y + area.height.saturating_sub(2) / 2;
    frame.render_widget(
        Paragraph::new(msg).alignment(Alignment::Center),
        Rect::new(area.x, y, area.width, area.height.min(3)),
    );
}
