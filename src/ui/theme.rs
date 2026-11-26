//! Moonveil cosmic navy, electric violet, and warm crescent peach surface palette.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::config::{AccentId, ThemeId};
use crate::net::model::PortState;

/// Resolved TrueColor palette for the active theme and accent.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub bg: Color,
    pub sidebar: Color,
    pub surface: Color,
    pub surface_alt: Color,
    pub surface_hover: Color,
    pub recessed: Color,
    pub selection: Color,
    pub hover: Color,
    pub track: Color,
    pub text: Color,
    pub text_dim: Color,
    pub text_muted: Color,
    pub moon_violet: Color,
    pub veil_peach: Color,
    pub accent: Color,
    pub accent_dim: Color,
    pub accent_fg: Color,
    pub ok: Color,
    pub warn: Color,
    pub crit: Color,
    pub in_use: Color,
    pub open: Color,
    pub filtered: Color,
    pub closed: Color,
}

impl Palette {
    pub fn from_config(theme: ThemeId, accent: AccentId) -> Self {
        let (bg, sidebar, surface, surface_alt, surface_hover, recessed, selection, hover, track) =
            match theme {
                ThemeId::Moonveil => (
                    Color::Rgb(13, 15, 34),
                    Color::Rgb(18, 21, 46),
                    Color::Rgb(24, 28, 58),
                    Color::Rgb(28, 32, 66),
                    Color::Rgb(33, 38, 76),
                    Color::Rgb(10, 12, 27),
                    Color::Rgb(46, 36, 92),
                    Color::Rgb(37, 42, 84),
                    Color::Rgb(32, 37, 74),
                ),
                ThemeId::Obsidian => (
                    Color::Rgb(11, 12, 16),
                    Color::Rgb(17, 18, 25),
                    Color::Rgb(24, 25, 35),
                    Color::Rgb(28, 29, 41),
                    Color::Rgb(31, 32, 46),
                    Color::Rgb(15, 16, 22),
                    Color::Rgb(44, 38, 66),
                    Color::Rgb(42, 44, 58),
                    Color::Rgb(32, 34, 45),
                ),
                ThemeId::Abyss => (
                    Color::Rgb(7, 9, 18),
                    Color::Rgb(11, 14, 28),
                    Color::Rgb(16, 20, 38),
                    Color::Rgb(20, 24, 45),
                    Color::Rgb(25, 30, 54),
                    Color::Rgb(6, 8, 15),
                    Color::Rgb(36, 32, 74),
                    Color::Rgb(30, 36, 66),
                    Color::Rgb(24, 28, 52),
                ),
                ThemeId::Graphite => (
                    Color::Rgb(18, 19, 24),
                    Color::Rgb(24, 25, 32),
                    Color::Rgb(32, 34, 43),
                    Color::Rgb(36, 38, 48),
                    Color::Rgb(41, 43, 55),
                    Color::Rgb(21, 22, 28),
                    Color::Rgb(54, 48, 78),
                    Color::Rgb(52, 54, 68),
                    Color::Rgb(40, 42, 54),
                ),
                ThemeId::Terminal => (
                    Color::Reset,
                    Color::Rgb(18, 20, 32),
                    Color::Rgb(24, 27, 44),
                    Color::Rgb(28, 31, 50),
                    Color::Rgb(33, 37, 58),
                    Color::Rgb(14, 16, 26),
                    Color::Rgb(46, 40, 78),
                    Color::Rgb(44, 48, 72),
                    Color::Rgb(34, 38, 60),
                ),
            };

        let (accent_color, accent_dim, accent_fg) = accent_colors(accent);

        Self {
            bg,
            sidebar,
            surface,
            surface_alt,
            surface_hover,
            recessed,
            selection,
            hover,
            track,
            text: Color::Rgb(240, 241, 248),
            text_dim: Color::Rgb(158, 163, 188),
            text_muted: Color::Rgb(102, 108, 138),
            moon_violet: Color::Rgb(155, 89, 246),
            veil_peach: Color::Rgb(247, 205, 190),
            accent: accent_color,
            accent_dim,
            accent_fg,
            ok: Color::Rgb(74, 222, 128),
            warn: Color::Rgb(251, 191, 36),
            crit: Color::Rgb(251, 113, 133),
            in_use: Color::Rgb(56, 189, 248),
            open: Color::Rgb(74, 222, 128),
            filtered: Color::Rgb(251, 191, 36),
            closed: Color::Rgb(105, 117, 145),
        }
    }

    pub const fn swatch_rgb(accent: AccentId) -> Color {
        accent_colors(accent).0
    }

    pub fn port_color(&self, state: PortState) -> Color {
        match state {
            PortState::InUse => self.in_use,
            PortState::Open => self.open,
            PortState::Filtered => self.filtered,
            PortState::Closed => self.closed,
        }
    }

    pub fn rtt_color(&self, rtt_ms: f64) -> Color {
        if rtt_ms < 5.0 {
            self.ok
        } else if rtt_ms < 25.0 {
            self.veil_peach
        } else if rtt_ms < 80.0 {
            self.warn
        } else {
            self.crit
        }
    }

    pub fn bg_style(&self) -> Style {
        Style::default().bg(self.bg).fg(self.text)
    }

    pub fn card_style(&self) -> Style {
        Style::default().bg(self.surface).fg(self.text)
    }

    pub fn pill_style(&self, active: bool, hovered: bool) -> Style {
        if active {
            Style::default()
                .bg(self.accent)
                .fg(self.accent_fg)
                .add_modifier(Modifier::BOLD)
        } else if hovered {
            Style::default().bg(self.hover).fg(self.text)
        } else {
            Style::default().bg(self.surface_alt).fg(self.text_dim)
        }
    }
}

const fn accent_colors(accent: AccentId) -> (Color, Color, Color) {
    match accent {
        AccentId::Violet => (
            Color::Rgb(155, 89, 246),
            Color::Rgb(92, 52, 158),
            Color::Rgb(250, 248, 255),
        ),
        AccentId::Peach => (
            Color::Rgb(247, 205, 190),
            Color::Rgb(166, 125, 112),
            Color::Rgb(20, 14, 24),
        ),
        AccentId::Cyan => (
            Color::Rgb(56, 189, 248),
            Color::Rgb(30, 110, 152),
            Color::Rgb(10, 18, 28),
        ),
        AccentId::Mint => (
            Color::Rgb(74, 222, 128),
            Color::Rgb(34, 122, 68),
            Color::Rgb(10, 22, 16),
        ),
        AccentId::Rose => (
            Color::Rgb(251, 113, 133),
            Color::Rgb(152, 54, 72),
            Color::Rgb(255, 246, 248),
        ),
        AccentId::Amber => (
            Color::Rgb(251, 191, 36),
            Color::Rgb(156, 112, 18),
            Color::Rgb(22, 18, 10),
        ),
    }
}

/// Renders a crisp section/card title inside `area`, returning the remaining body rect.
pub fn draw_card_header(
    frame: &mut Frame,
    pal: Palette,
    area: Rect,
    title: &str,
    right_badge: Option<(&str, Color)>,
) -> Rect {
    if area.height == 0 || area.width < 4 {
        return Rect::default();
    }
    let header = Rect::new(area.x, area.y, area.width, 1);
    let mut spans = vec![
        Span::styled("▌ ", Style::default().fg(pal.accent).bg(pal.surface)),
        Span::styled(
            title,
            Style::default()
                .fg(pal.text)
                .bg(pal.surface)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some((badge, color)) = right_badge {
        let used = 2 + title.width() + badge.width() + 2;
        if usize::from(area.width) > used {
            let pad = usize::from(area.width) - used;
            spans.push(Span::styled(
                " ".repeat(pad),
                Style::default().bg(pal.surface),
            ));
            spans.push(Span::styled(
                badge,
                Style::default()
                    .fg(color)
                    .bg(pal.surface)
                    .add_modifier(Modifier::BOLD),
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(pal.surface)),
        header,
    );
    Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        area.height.saturating_sub(1),
    )
}

/// Truncates text cleanly to at most `max_cols` terminal display columns.
pub fn truncate_str(s: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    if s.width() <= max_cols {
        return s.to_string();
    }
    let mut out = String::new();
    let mut cols = 0;
    for ch in s.chars() {
        let w = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if cols + w + 1 > max_cols {
            out.push('…');
            break;
        }
        out.push(ch);
        cols += w;
    }
    out
}

/// Insets a `Rect` symmetrically by `(dx, dy)` while saturating safely.
pub fn inset_rect(r: Rect, dx: u16, dy: u16) -> Rect {
    Rect::new(
        r.x.saturating_add(dx),
        r.y.saturating_add(dy),
        r.width.saturating_sub(dx * 2),
        r.height.saturating_sub(dy * 2),
    )
}
