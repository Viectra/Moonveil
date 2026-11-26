//! Half-block TrueColor Moonveil crescent-and-veil emblem rendering.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::Frame;

use crate::ui::theme::Palette;

use super::primitives::mix;

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
