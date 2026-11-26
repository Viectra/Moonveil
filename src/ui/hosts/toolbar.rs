//! Hosts tab search toolbar and quick match counters.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::config::Language;
use crate::ui::hit::ClickAction;
use crate::ui::theme::{inset_rect, Palette};

pub(super) fn render_toolbar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 1);
    if inner.width < 12 || inner.height == 0 {
        return;
    }

    let lang = app.lang();
    let total_hosts = app.snapshot.hosts.len();
    let shown = app.filtered_hosts().len();
    let online = app.snapshot.hosts.iter().filter(|h| h.online).count();

    let stats_str = match lang {
        Language::En => format!("{shown}/{total_hosts} hosts • {online} online"),
        Language::Fr => format!("{shown}/{total_hosts} hôtes • {online} en ligne"),
    };
    let stats_w = (stats_str.width() as u16).min(inner.width / 2);

    let clear_lbl = " × ";
    let clear_w = if app.search_query.is_empty() { 0 } else { 3 };
    let search_w = inner.width.saturating_sub(stats_w + clear_w + 2);
    let search_rect = Rect::new(inner.x, inner.y, search_w, 1);

    let search_bg = if app.search_focused {
        pal.selection
    } else {
        pal.recessed
    };
    let prompt = if app.search_query.is_empty() && !app.search_focused {
        lang.t(
            " / Search host, IP, MAC, port:22, vendor:...",
            " / Chercher hôte, IP, MAC, port:22, vendor:...",
        )
        .to_string()
    } else if app.search_focused {
        format!(" / {}_", app.search_query)
    } else {
        format!(" / {}", app.search_query)
    };

    let text_color = if app.search_query.is_empty() && !app.search_focused {
        pal.text_muted
    } else {
        pal.text
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            prompt,
            Style::default().fg(text_color).bg(search_bg),
        )))
        .style(Style::default().bg(search_bg)),
        search_rect,
    );
    app.hits.record(search_rect, ClickAction::FocusSearch);

    if clear_w > 0 {
        let clear_rect = Rect::new(search_rect.right(), inner.y, clear_w, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                clear_lbl,
                Style::default()
                    .fg(pal.veil_peach)
                    .bg(pal.surface_alt)
                    .add_modifier(Modifier::BOLD),
            ))),
            clear_rect,
        );
        app.hits.record(clear_rect, ClickAction::ClearSearch);
    }

    let stats_rect = Rect::new(inner.right().saturating_sub(stats_w), inner.y, stats_w, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            stats_str,
            Style::default().fg(pal.text_dim).bg(pal.surface),
        ))),
        stats_rect,
    );
}
