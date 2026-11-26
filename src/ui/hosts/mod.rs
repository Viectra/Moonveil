//! Hosts tab: top toolbar (search, mode switch, scan, preset, watch), sortable host table, and Host Inspector.

use crate::app::App;
use crate::config::Language;
use crate::net::model::{format_mac, Host, HostSortColumn, PortFilter, PortState, ScanMode};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};
use crate::ui::widgets::{
    mix, render_mode_pill, render_port_ratio_bar, render_scan_wave, SplineChart,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

mod inspector;
mod table;
mod toolbar;
use inspector::*;
use table::*;
use toolbar::*;

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 36 || area.height < 10 {
        return;
    }

    let wave_h = if app.scan_progress.active { 1 } else { 0 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // Top interactive toolbar
            Constraint::Length(wave_h), // Animated scan wave when scanning
            Constraint::Min(6),         // Table + Inspector split
        ])
        .split(area);

    render_toolbar(frame, app, rows[0], pal);
    if app.scan_progress.active {
        let lbl = format!(
            "{}/{} {}",
            app.scan_progress.probed, app.scan_progress.total, app.scan_progress.current_target
        );
        render_scan_wave(
            frame,
            rows[1],
            pal,
            app.scan_progress.ratio(),
            app.tick_count,
            &truncate_str(&lbl, 28),
        );
    }

    let body = rows[2];
    if body.width >= 104 {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(57), Constraint::Percentage(43)])
            .split(body);
        render_host_table(frame, app, pad_right(split[0], 1), pal);
        render_inspector(frame, app, split[1], pal);
    } else if body.height >= 20 {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(body);
        render_host_table(frame, app, split[0], pal);
        render_inspector(frame, app, split[1], pal);
    } else if app.show_inspector_on_compact {
        render_inspector(frame, app, body, pal);
    } else {
        render_host_table(frame, app, body, pal);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn push_pill(
    frame: &mut Frame,
    app: &mut App,
    x: u16,
    y: u16,
    max_x: u16,
    label: &str,
    active: bool,
    pal: Palette,
    action: ClickAction,
) -> u16 {
    let w = unicode_width::UnicodeWidthStr::width(label) as u16;
    if x + w > max_x || w == 0 {
        return x;
    }
    let rect = Rect::new(x, y, w, 1);
    let hovered = HitRegistry::is_hovered(rect, app.hover);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            label,
            pal.pill_style(active, hovered),
        ))),
        rect,
    );
    app.hits.register(rect, action);
    x + w
}

fn pad_right(r: Rect, n: u16) -> Rect {
    Rect::new(r.x, r.y, r.width.saturating_sub(n), r.height)
}
