//! Moonveil crescent-and-veil half-block logo art with optional shimmer sweep.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::Frame;

use crate::ui::theme::Palette;

use super::mix;

// 16 cols x 12 rows (renders into 16x6 half-block cells)
const COMPACT_GRID: [&str; 12] = [
    "......PPPPPP....",
    "....PPPPPPPPPP..",
    "...PPPPPPPP.....",
    "..PPPPPP........",
    "..PPPP....VVVV..",
    "..PPP...VVVVVVV.",
    "..VVVV.VVVVV.PP.",
    "...VVVVVVV..PPP.",
    "....VVVV..PPPPPP",
    "....PPPPPPPPPPP.",
    ".....PPPPPPPP...",
    ".......PPPPP....",
];

// 26 cols x 16 rows (renders into 26x8 half-block cells)
const HERO_GRID: [&str; 16] = [
    ".........PPPPPPPPP........",
    "......PPPPPPPPPPPPPP......",
    "....PPPPPPPPPPPPPP........",
    "...PPPPPPPPPP.............",
    "..PPPPPPPP................",
    "..PPPPPPP........VVVVVV...",
    "..PPPPPP......VVVVVVVVVV..",
    "..PPPPP....VVVVVVVVVV.VVV.",
    "..VVVV...VVVVVVV......PPP.",
    "...VVVVVVVVVV.......PPPPP.",
    "....VVVVVVV.......PPPPPPP.",
    ".....VVVV......PPPPPPPPPP.",
    "......PPPPPPPPPPPPPPPPPP..",
    ".......PPPPPPPPPPPPPPP....",
    ".........PPPPPPPPPPP......",
    "............PPPPP.........",
];

/// Renders the compact 16x6 sidebar Moonveil emblem.
pub fn render_emblem_compact(frame: &mut Frame, area: Rect, bg: Color, pal: Palette, phase: f64) {
    render_pixel_grid(frame, area, &COMPACT_GRID, bg, pal, phase, true);
}

/// Renders the full 26x8 splash Moonveil emblem.
pub fn render_emblem_hero(frame: &mut Frame, area: Rect, bg: Color, pal: Palette, phase: f64) {
    render_pixel_grid(frame, area, &HERO_GRID, bg, pal, phase, true);
}

fn render_pixel_grid(
    frame: &mut Frame,
    area: Rect,
    grid: &[&str],
    bg: Color,
    pal: Palette,
    phase: f64,
    shimmer: bool,
) {
    if grid.is_empty() || area.width == 0 || area.height == 0 {
        return;
    }
    let rows = (grid.len() / 2).min(usize::from(area.height));
    let cols = grid[0].len();
    let x0 = area.x + area.width.saturating_sub(cols as u16) / 2;
    let y0 = area.y + area.height.saturating_sub(rows as u16) / 2;
    let buf: &mut Buffer = frame.buffer_mut();

    for row in 0..rows {
        let top_bytes = grid[row * 2].as_bytes();
        let bot_bytes = grid[row * 2 + 1].as_bytes();
        let py = y0 + row as u16;
        if py >= area.bottom() {
            break;
        }
        for col in 0..cols.min(top_bytes.len()).min(bot_bytes.len()) {
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
