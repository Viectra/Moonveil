//! Hosts view (`Hosts` tab): search toolbar, sortable host list, and clean detail inspector.

pub mod inspector;
pub mod table;
pub mod toolbar;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

use crate::app::App;
use crate::ui::theme::Palette;

/// Renders the Hosts screen with top search bar, left host table, and right host inspector.
pub fn render(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(6)])
        .split(area);

    toolbar::render_toolbar(frame, app, rows[0], pal);

    let cols = if rows[1].width >= 84 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(rows[1])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(rows[1])
    };

    table::render_table(frame, app, cols[0], pal);
    inspector::render_inspector(frame, app, cols[1], pal);
}
