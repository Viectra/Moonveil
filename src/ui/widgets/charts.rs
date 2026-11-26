//! 24-bit TrueColor half-block smooth spline line chart with soft curve glow.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::widgets::Widget;

use super::mix;

/// Half-block smooth chart rendering up to N numeric series.
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
            let sampled = resample_cosine(data, cols);
            for (c, val_opt) in sampled.iter().enumerate() {
                let Some(val) = val_opt else { continue };
                let norm = (val / max_val).clamp(0.0, 1.0);
                let y_float = (1.0 - norm) * (py_total - 1) as f64;
                let y_px = y_float.round() as usize;
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

fn resample_cosine(data: &[f64], cols: usize) -> Vec<Option<f64>> {
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
        let mu = (1.0 - (f * std::f64::consts::PI).cos()) * 0.5;
        out.push(Some(p0 + (p1 - p0) * mu));
    }
    out
}
