//! Reusable custom Ratatui widgets: TrueColor half-block emblems, spline charts, and gauges.

pub mod charts;
pub mod logo;
pub mod primitives;

pub use charts::SplineChart;
pub use logo::{render_emblem_compact, render_emblem_hero};
pub use primitives::{mix, render_mode_pill, render_port_ratio_bar, render_scan_wave};
