//! Color interpolation, scan waves, port ratio bars, and mode pills.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::ui::theme::Palette;

/// Linear RGB interpolation (`t = 0.0` -> `a`, `t = 1.0` -> `b`).
pub fn mix(a: Color, b: Color, t: f64) -> Color {
    let t = if t.is_finite() {
        t.clamp(0.0, 1.0)
    } else {
        0.0
    };
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let lerp = |x: u8, y: u8| -> u8 {
                (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round() as u8
            };
            Color::Rgb(lerp(r1, r2), lerp(g1, g2), lerp(b1, b2))
        }
        _ => a,
    }
}

/// Renders the animated violet-to-peach Crescent Scan Wave bar.
pub fn render_scan_wave(
    frame: &mut Frame,
    area: Rect,
    pal: Palette,
    ratio: f64,
    tick: u64,
    label: &str,
) {
    if area.width < 12 || area.height == 0 {
        return;
    }
    let bar_w = area.width.saturating_sub(label.len() as u16 + 3).max(8) as usize;
    let filled = ((ratio.clamp(0.0, 1.0)) * bar_w as f64).round() as usize;
    let pulse_pos = (tick as usize) % bar_w.max(1);

    let mut spans = Vec::with_capacity(bar_w + 2);
    for i in 0..bar_w {
        let t = if bar_w <= 1 {
            0.0
        } else {
            i as f64 / (bar_w - 1) as f64
        };
        if i < filled || filled == 0 {
            let color = if i < filled {
                let wave = if i == pulse_pos || i + 1 == pulse_pos {
                    0.45
                } else {
                    0.0
                };
                mix(
                    mix(pal.moon_violet, pal.veil_peach, t),
                    Color::Rgb(255, 255, 255),
                    wave,
                )
            } else if i == pulse_pos || i == (pulse_pos + 1) % bar_w {
                pal.moon_violet
            } else {
                pal.track
            };
            spans.push(Span::styled(
                "━",
                Style::default().fg(color).bg(pal.surface),
            ));
        } else {
            spans.push(Span::styled(
                "─",
                Style::default().fg(pal.track).bg(pal.surface),
            ));
        }
    }
    spans.push(Span::styled(
        format!("  {label}"),
        Style::default()
            .fg(pal.veil_peach)
            .bg(pal.surface)
            .add_modifier(Modifier::BOLD),
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Renders a compact horizontal segmented bar of port state counts (`InUse` / `Open` / `Filtered` / `Closed`).
pub fn render_port_ratio_bar(
    frame: &mut Frame,
    area: Rect,
    pal: Palette,
    in_use: usize,
    open: usize,
    filtered: usize,
    closed: usize,
) {
    if area.width < 6 || area.height == 0 {
        return;
    }
    let total = in_use + open + filtered + closed;
    let w = usize::from(area.width);
    if total == 0 {
        let empty = "─".repeat(w);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                empty,
                Style::default().fg(pal.track).bg(pal.surface),
            ))),
            area,
        );
        return;
    }

    let counts = [
        (in_use, pal.in_use),
        (open, pal.open),
        (filtered, pal.filtered),
        (closed, pal.closed),
    ];
    let mut spans = Vec::new();
    let mut used = 0;
    for (idx, (cnt, color)) in counts.iter().enumerate() {
        if *cnt == 0 {
            continue;
        }
        let mut cells = ((*cnt as f64 / total as f64) * w as f64).round() as usize;
        if cells == 0 && used < w {
            cells = 1;
        }
        if idx == 3 || used + cells > w {
            cells = w.saturating_sub(used);
        }
        if cells > 0 {
            spans.push(Span::styled(
                "█".repeat(cells),
                Style::default().fg(*color).bg(pal.surface),
            ));
            used += cells;
        }
    }
    if used < w {
        spans.push(Span::styled(
            "─".repeat(w - used),
            Style::default().fg(pal.track).bg(pal.surface),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Renders a subtle animated sliding toggle switch `[Normal ○══● Advanced]`.
pub fn render_mode_pill(
    left_label: &str,
    right_label: &str,
    right_active: bool,
    pal: Palette,
    bg: Color,
) -> Line<'static> {
    let left_style = if !right_active {
        Style::default()
            .fg(pal.veil_peach)
            .bg(pal.selection)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(pal.text_muted).bg(bg)
    };
    let right_style = if right_active {
        Style::default()
            .fg(pal.moon_violet)
            .bg(pal.selection)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(pal.text_muted).bg(bg)
    };
    let switch = if right_active {
        " ──● "
    } else {
        " ●── "
    };
    Line::from(vec![
        Span::styled(format!(" {left_label} "), left_style),
        Span::styled(switch, Style::default().fg(pal.accent).bg(bg)),
        Span::styled(format!(" {right_label} "), right_style),
    ])
}
