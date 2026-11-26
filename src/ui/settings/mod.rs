//! Settings view: responsive layout combining scan preferences, exports, and Theme Studio.

pub mod scan_options;
pub mod theme_studio;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::ui::theme::Palette;

/// Renders the Settings screen.
pub fn render(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
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

    scan_options::render_scan_card(frame, app, cols[0], pal);
    theme_studio::render_theme_card(frame, app, cols[1], pal);
}

pub(super) fn draw_label(frame: &mut Frame, area: Rect, text: &str, pal: Palette) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text,
            Style::default().fg(pal.text_dim).bg(pal.surface),
        ))),
        Rect::new(area.x, area.y, area.width, 1),
    );
}
