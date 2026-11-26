//! Root UI shell: sidebar with Moonveil emblem, compact topbar, 5 views, splash, and floating modals.

pub mod hit;
pub mod hosts;
pub mod network;
pub mod radar;
pub mod settings;
pub mod theme;
pub mod watch;
pub mod widgets;

mod layout;
mod modals;
mod splash;

use layout::*;
use modals::*;
use splash::*;

use crate::app::{App, Modal, Tab};
use crate::config::Language;
use crate::ui::hit::{ClickAction, HitRegistry};
use crate::ui::theme::{inset_rect, truncate_str, Palette};
use crate::ui::widgets::{mix, render_emblem_compact, render_emblem_hero};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;

/// Renders a full Moonveil frame and records all clickable hit regions.
pub fn render(frame: &mut Frame, app: &mut App) {
    app.hits.clear();
    let area = frame.area();
    let pal = app.palette;

    frame.render_widget(Block::default().style(pal.bg_style()), area);

    if area.width < 40 || area.height < 12 {
        render_too_small(frame, pal, area, app.lang());
        return;
    }

    // Animated logo splash reveal on initial launch (skippable on any click or key).
    if app.is_splash_active() && area.width >= 50 && area.height >= 22 {
        render_splash(frame, app, area, pal);
        return;
    }

    if area.width >= 90 && area.height >= 18 {
        let sidebar_w = if area.width >= 118 { 24 } else { 20 };
        let shell = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(sidebar_w), Constraint::Min(30)])
            .split(area);
        render_sidebar(frame, app, shell[0], pal);
        render_workspace(frame, app, shell[1], pal);
    } else {
        let shell = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(8),
                Constraint::Length(1),
            ])
            .split(area);
        render_compact_topbar(frame, app, shell[0], pal);
        render_active_tab(frame, app, shell[1]);
        render_status_footer(frame, app, shell[2], pal);
    }

    match app.modal.clone() {
        Modal::None => {}
        Modal::Help => render_help_modal(frame, app, area, pal),
        Modal::RenameHost { ip, input } => render_rename_modal(frame, app, area, pal, ip, &input),
        Modal::CustomPorts { input, error } => {
            render_custom_ports_modal(frame, app, area, pal, &input, error.as_deref())
        }
        Modal::Traceroute { ip } => render_traceroute_modal(frame, app, area, pal, ip),
    }
}

fn render_active_tab(frame: &mut Frame, app: &mut App, body: Rect) {
    match app.tab {
        Tab::Hosts => hosts::render(frame, app, body),
        Tab::Radar => radar::render(frame, app, body),
        Tab::Network => network::render(frame, app, body),
        Tab::Watch => watch::render(frame, app, body),
        Tab::Settings => settings::render(frame, app, body),
    }
}
