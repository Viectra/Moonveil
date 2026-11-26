//! Settings tab: Mode selector, scan presets/concurrency/timeouts, custom port range, and Theme Studio.

mod scan_options;
mod theme_studio;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::ui::hit::ScrollTarget;
use crate::ui::theme::Palette;

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 36 || area.height < 14 {
        return;
    }

    app.hits.register_scroll(area, ScrollTarget::Settings);
    let cols = if area.width >= 96 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(area)
    };

    scan_options::render_scan_settings(frame, app, cols[0], pal);
    let right = if area.width >= 96 {
        Rect::new(
            cols[1].x + 1,
            cols[1].y,
            cols[1].width.saturating_sub(1),
            cols[1].height,
        )
    } else {
        Rect::new(
            cols[1].x,
            cols[1].y + 1,
            cols[1].width,
            cols[1].height.saturating_sub(1),
        )
    };
    theme_studio::render_appearance_settings(frame, app, right, pal);
}

pub(super) fn draw_label(frame: &mut Frame, x: u16, y: u16, text: &str, pal: Palette) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text,
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.surface)
                .add_modifier(Modifier::BOLD),
        ))),
        Rect::new(
            x,
            y,
            unicode_width::UnicodeWidthStr::width(text) as u16 + 1,
            1,
        ),
    );
}
