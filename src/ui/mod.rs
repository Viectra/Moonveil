//! Root TUI renderer routing splash, shell chrome, 3 core views, toast, and modals.

pub mod hit;
pub mod hosts;
pub mod layout;
pub mod modals;
pub mod radar;
pub mod settings;
pub mod splash;
pub mod theme;
pub mod widgets;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::Block;
use ratatui::Frame;

use crate::app::{App, Tab};
use theme::Palette;

/// Renders one complete interactive frame of Moonveil and populates `app.hits`.
pub fn render(frame: &mut Frame, app: &mut App) {
    app.hits.clear();
    let pal = Palette::from_config(app.config.theme, app.config.accent);
    let area = frame.area();
    frame.render_widget(Block::default().style(pal.bg_style()), area);

    if area.width < 56 || area.height < 14 {
        splash::render_too_small(frame, area, pal, app.lang());
        return;
    }

    if app.is_splash_active() {
        splash::render_splash(frame, app, area, pal);
        return;
    }

    let show_sidebar = area.width >= 100;
    let body_area = if show_sidebar {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(23), Constraint::Min(40)])
            .split(area);
        layout::render_sidebar(frame, app, cols[0], pal);
        cols[1]
    } else {
        area
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(body_area);

    layout::render_topbar(frame, app, rows[0], pal, !show_sidebar);

    match app.tab {
        Tab::Hosts => hosts::render(frame, app, rows[1], pal),
        Tab::Radar => radar::render(frame, app, rows[1], pal),
        Tab::Settings => settings::render(frame, app, rows[1], pal),
    }

    layout::render_footer(frame, app, rows[2], pal);

    if let Some((msg, _)) = app.toast.clone() {
        layout::render_toast(frame, rows[1], pal, &msg);
    }

    modals::render_modal(frame, app, area, pal);
}
