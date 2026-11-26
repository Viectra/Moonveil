//! Moonveil TrueColor half-block emblem art, subpixel spline charts, scan waves, and gauges.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};
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

/// Compact 12x12 crescent-and-veil emblem sampled from the Moonveil logo (`12x6` cells).
const SIDEBAR_LOGO_GRID: [&str; 12] = [
    "...PPPP.....",
    "..PPPP......",
    ".PPPP.......",
    "PPPP........",
    "PPPP....V...",
    "PPPP..VVVV..",
    "PPPP.VVV...P",
    ".VVVVVV...PP",
    ".VVVVVP..PPP",
    ".VVVVPPPPPP.",
    "..PPPPPPPP..",
    "...PPPPPP...",
];

/// High-resolution 28x28 crescent-and-veil emblem (`28x14` cells) for splash & Help.
const HERO_LOGO_GRID: [&str; 28] = [
    "............PPPP............",
    ".........PPPPPPPPP..........",
    ".......PPPPPPPP.............",
    ".....PPPPPPPP...............",
    "....PPPPPPPP................",
    "...PPPPPPPP.................",
    "...PPPPPPP..................",
    "..PPPPPPP...................",
    "..PPPPPPP...................",
    ".PPPPPPPP...................",
    ".PPPPPPPP..........VV.......",
    ".PPPPPPPP.......VVVVVVV.....",
    "PPPPPPPPP......VVVVVVVVV....",
    ".PPPPPPPP.....VVVVVVV.......",
    ".PPPPPPPP...VVVVVVV.......PP",
    ".PPPPPPPPP.VVVVVVV........PP",
    "..PPPPPPP.VVVVVVV........PP.",
    ".V.PPPPVVVVVVVVV.........PP.",
    ".VVVVVVVVVVVVVV.........PPP.",
    "..VVVVVVVVVVVV........PPPPP.",
    "..VVVVVVVVVVV.PP...PPPPPPP..",
    "...VVVVVVVVVPPPPPPPPPPPPP...",
    "....VVVVVV.PPPPPPPPPPPPPP...",
    "........VPPPPPPPPPPPPPPP....",
    "......PPPPPPPPPPPPPPPPP.....",
    ".......PPPPPPPPPPPPPP.......",
    "........PPPPPPPPPPPP........",
    "...........PPPPPP...........",
];

/// Renders the compact 12x6 TrueColor Moonveil emblem using half-block characters (`▀`).
pub fn render_emblem_compact(frame: &mut Frame, area: Rect, bg: Color, pal: Palette, phase: f64) {
    render_pixel_grid(
        frame.buffer_mut(),
        area,
        &SIDEBAR_LOGO_GRID,
        bg,
        pal,
        phase,
        false,
    );
}

/// Renders the 28x14 TrueColor Moonveil hero emblem with smooth optional shimmer wave.
pub fn render_emblem_hero(frame: &mut Frame, area: Rect, bg: Color, pal: Palette, phase: f64) {
    render_pixel_grid(
        frame.buffer_mut(),
        area,
        &HERO_LOGO_GRID,
        bg,
        pal,
        phase,
        true,
    );
}

fn render_pixel_grid(
    buf: &mut Buffer,
    area: Rect,
    grid: &[&str],
    bg: Color,
    pal: Palette,
    phase: f64,
    shimmer: bool,
) {
    let rows = grid.len() / 2;
    let cols = grid.first().map_or(0, |r| r.len());
    if area.width < cols as u16 || area.height < rows as u16 {
        return;
    }

    let x0 = area.x + (area.width.saturating_sub(cols as u16)) / 2;
    let y0 = area.y;

    for row in 0..rows {
        let top_bytes = grid[row * 2].as_bytes();
        let bot_bytes = grid[row * 2 + 1].as_bytes();
        let py = y0 + row as u16;
        if py >= area.bottom() {
            break;
        }
        for col in 0..cols {
            let px = x0 + col as u16;
            if px >= area.right() {
                break;
            }
            let top_c =
                grid_pixel_color(top_bytes[col], col, row * 2, cols, bg, pal, phase, shimmer);
            let bot_c = grid_pixel_color(
                bot_bytes[col],
                col,
                row * 2 + 1,
                cols,
                bg,
                pal,
                phase,
                shimmer,
            );
            if let Some(cell) = buf.cell_mut((px, py)) {
                cell.set_char('▀')
                    .set_style(Style::default().fg(top_c).bg(bot_c));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn grid_pixel_color(
    ch: u8,
    x: usize,
    y: usize,
    width: usize,
    bg: Color,
    pal: Palette,
    phase: f64,
    shimmer: bool,
) -> Color {
    let base = match ch {
        b'P' => pal.veil_peach,
        b'V' => pal.moon_violet,
        _ => return bg,
    };
    if !shimmer {
        return base;
    }
    let sweep_x = phase * (width as f64 + 10.0) - 5.0;
    let dist = ((x as f64 + y as f64 * 0.35) - sweep_x).abs();
    let glow = (1.0 - dist / 5.5).clamp(0.0, 1.0);
    mix(base, Color::Rgb(255, 252, 255), glow * 0.38)
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

/// 24-bit TrueColor half-block smooth spline line chart with subtle gradient area glow.
pub struct SplineChart<'a> {
    pub series: &'a [(&'a [f64], Color)],
    pub bg: Color,
    pub max_override: Option<f64>,
    pub unit_label: &'a str,
}

impl<'a> Widget for SplineChart<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 6 || area.height < 2 {
            return;
        }
        let cols = usize::from(area.width);
        let rows = usize::from(area.height);
        let py_total = rows * 2;

        let mut max_val = self.max_override.unwrap_or(0.0);
        if max_val <= 0.0 {
            for (data, _) in self.series {
                for &v in *data {
                    if v.is_finite() && v > max_val {
                        max_val = v;
                    }
                }
            }
            max_val = (max_val * 1.18).max(1.0);
        }

        // Fill subtle grid lines every 2 rows.
        for r in 0..rows {
            for c in 0..cols {
                if let Some(cell) = buf.cell_mut((area.x + c as u16, area.y + r as u16)) {
                    cell.set_char(' ').set_bg(self.bg);
                }
            }
        }

        let mut pixel_colors = vec![vec![self.bg; cols]; py_total];

        for &(data, color) in self.series {
            if data.is_empty() {
                continue;
            }
            let sampled = resample_pchip(data, cols);
            for (c, val_opt) in sampled.iter().enumerate() {
                let Some(val) = val_opt else { continue };
                let norm = (val / max_val).clamp(0.0, 1.0);
                let y_float = (1.0 - norm) * (py_total - 1) as f64;
                let y_px = y_float.round() as usize;
                // Soft vertical glow under curve
                for (py, row_px) in pixel_colors
                    .iter_mut()
                    .enumerate()
                    .take(py_total)
                    .skip(y_px)
                {
                    let depth = (py - y_px) as f64 / (py_total as f64).max(1.0);
                    let alpha = (0.28 * (1.0 - depth)).max(0.04);
                    row_px[c] = mix(row_px[c], color, alpha);
                }
                // Crisp 1px stroke + vertical anti-aliasing neighbor
                pixel_colors[y_px][c] = color;
                if y_px > 0 && (y_float - (y_px as f64)).abs() > 0.25 {
                    pixel_colors[y_px - 1][c] = mix(pixel_colors[y_px - 1][c], color, 0.55);
                }
            }
        }

        for r in 0..rows {
            for c in 0..cols {
                let top = pixel_colors[r * 2][c];
                let bot = pixel_colors[r * 2 + 1][c];
                if let Some(cell) = buf.cell_mut((area.x + c as u16, area.y + r as u16)) {
                    cell.set_char('▀').set_fg(top).set_bg(bot);
                }
            }
        }

        if !self.unit_label.is_empty() && area.width > self.unit_label.len() as u16 + 2 {
            let lbl = self.unit_label;
            let start_x = area.right() - lbl.len() as u16 - 1;
            for (i, ch) in lbl.chars().enumerate() {
                if let Some(cell) = buf.cell_mut((start_x + i as u16, area.y)) {
                    cell.set_char(ch).set_fg(Color::Rgb(158, 163, 188));
                }
            }
        }
    }
}

fn resample_pchip(data: &[f64], cols: usize) -> Vec<Option<f64>> {
    if data.is_empty() || cols == 0 {
        return vec![None; cols];
    }
    if data.len() == 1 {
        return vec![Some(data[0].max(0.0)); cols];
    }
    let mut out = Vec::with_capacity(cols);
    let n = data.len();
    for c in 0..cols {
        let t = (c as f64 / (cols.saturating_sub(1).max(1)) as f64) * (n - 1) as f64;
        let i = (t.floor() as usize).min(n - 2);
        let f = t - i as f64;
        let p0 = data[i].max(0.0);
        let p1 = data[i + 1].max(0.0);
        // Smooth cosine interpolation for jitter-free monotonic curve
        let mu = (1.0 - (f * std::f64::consts::PI).cos()) * 0.5;
        out.push(Some(p0 + (p1 - p0) * mu));
    }
    out
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
