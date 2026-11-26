//! Settings tab: Mode selector, scan presets/concurrency/timeouts, custom port range, and Theme Studio.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::config::{AccentId, ThemeId};
use crate::net::model::{ScanMode, ScanPreset};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::hosts::push_pill;
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 36 || area.height < 14 {
        return;
    }

    app.hits.register_scroll(area, ScrollTarget::Settings);
    let cols = if area.width >= 96 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(area)
    };

    render_scan_settings(frame, app, cols[0], pal);
    let right = if area.width >= 96 {
        Rect::new(
            cols[1].x + 1,
            cols[1].y,
            cols[1].width.saturating_sub(1),
            cols[1].height,
        )
    } else {
        Rect::new(
            cols[1].x,
            cols[1].y + 1,
            cols[1].width,
            cols[1].height.saturating_sub(1),
        )
    };
    render_appearance_settings(frame, app, right, pal);
}

fn render_scan_settings(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let r = Rect::new(area.x, area.y, area.width.saturating_sub(1), area.height);
    frame.render_widget(Block::default().style(pal.card_style()), r);
    let body = draw_card_header(frame, pal, r, "Scanner & Recon Preferences", None);
    let inner = inset_rect(body, 1, 0);
    if inner.height < 10 {
        return;
    }

    let mut y = inner.y;

    // UI Mode
    draw_label(frame, inner.x, y, "Interface Density Mode", pal);
    y += 1;
    let mut x = inner.x;
    for mode in [ScanMode::Normal, ScanMode::Advanced] {
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" {} ({}) ", mode.label(), mode.subtitle()),
            app.config.mode == mode,
            pal,
            ClickAction::SetMode(mode),
        );
        x += 1;
    }
    y += 2;

    // Default Preset
    draw_label(frame, inner.x, y, "Default Port Preset", pal);
    y += 1;
    x = inner.x;
    for &preset in ScanPreset::ALL {
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" {} ", preset.short_label()),
            app.config.default_preset == preset,
            pal,
            ClickAction::SetPreset(preset),
        );
        x += 1;
    }
    y += 2;

    // Custom Port Expression
    if y + 1 < inner.bottom() {
        draw_label(frame, inner.x, y, "Custom Port Range (click to edit)", pal);
        y += 1;
        let lbl = format!(" {} ", truncate_str(&app.config.custom_ports, 36));
        let _ = push_pill(
            frame,
            app,
            inner.x,
            y,
            inner.right(),
            &lbl,
            false,
            pal,
            ClickAction::OpenCustomPortsModal,
        );
        y += 2;
    }

    // Engine knobs
    if y + 4 < inner.bottom() {
        x = inner.x;
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" Concurrency: {} ", app.config.concurrency),
            false,
            pal,
            ClickAction::CycleConcurrency,
        );
        x += 1;
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" Timeout: {}ms ", app.config.timeout_ms),
            false,
            pal,
            ClickAction::CycleTimeout,
        );
        x += 1;
        let _ = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" Watch: {}s ", app.config.watch_interval_secs),
            false,
            pal,
            ClickAction::CycleWatchInterval,
        );
        y += 2;

        x = inner.x;
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            if app.config.grab_banners {
                " ● Banners ON "
            } else {
                " - Banners OFF "
            },
            app.config.grab_banners,
            pal,
            ClickAction::ToggleGrabBanners,
        );
        x += 1;
        let _ = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            if app.config.show_virtual_ifaces {
                " ● Show Virtual (lo/veth) "
            } else {
                " - Hide Virtual (lo/veth) "
            },
            app.config.show_virtual_ifaces,
            pal,
            ClickAction::ToggleVirtualIfaces,
        );
    }
}

fn render_appearance_settings(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let body = draw_card_header(frame, pal, area, "Theme & Visual Effects", None);
    let inner = inset_rect(body, 1, 0);
    if inner.height < 10 {
        return;
    }

    let mut y = inner.y;

    draw_label(frame, inner.x, y, "Surface Theme", pal);
    y += 1;
    let mut x = inner.x;
    for &theme in ThemeId::ALL {
        let lbl = format!(" {} ", theme.label());
        let w = unicode_width::UnicodeWidthStr::width(lbl.as_str()) as u16;
        if x + w > inner.right() {
            x = inner.x;
            y += 1;
        }
        if y >= inner.bottom() {
            break;
        }
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &lbl,
            app.config.theme == theme,
            pal,
            ClickAction::SetTheme(theme),
        );
        x += 1;
    }
    y += 2;

    if y + 2 < inner.bottom() {
        draw_label(frame, inner.x, y, "Accent Swatch", pal);
        y += 1;
        x = inner.x;
        for &accent in AccentId::ALL {
            let sw = Palette::swatch_rgb(accent);
            let active = app.config.accent == accent;
            let lbl = format!(" ● {} ", accent.label());
            let w = unicode_width::UnicodeWidthStr::width(lbl.as_str()) as u16;
            if x + w > inner.right() {
                x = inner.x;
                y += 1;
            }
            if y >= inner.bottom() {
                break;
            }
            let rect = Rect::new(x, y, w, 1);
            let hovered = HitRegistry::is_hovered(rect, app.hover);
            let bg = if active {
                pal.selection
            } else if hovered {
                pal.hover
            } else {
                pal.surface_alt
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(" ● ", Style::default().fg(sw).bg(bg)),
                    Span::styled(
                        format!("{} ", accent.label()),
                        Style::default()
                            .fg(pal.text)
                            .bg(bg)
                            .add_modifier(if active {
                                Modifier::BOLD
                            } else {
                                Modifier::empty()
                            }),
                    ),
                ])),
                rect,
            );
            app.hits.register(rect, ClickAction::SetAccent(accent));
            x += w + 1;
        }
        y += 2;
    }

    if y + 2 < inner.bottom() {
        x = inner.x;
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            if app.config.animations {
                " ● Animations ON "
            } else {
                " - Animations OFF "
            },
            app.config.animations,
            pal,
            ClickAction::ToggleAnimations,
        );
        x += 1;
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            if app.config.splash {
                " ● Splash ON "
            } else {
                " - Splash OFF "
            },
            app.config.splash,
            pal,
            ClickAction::ToggleSplash,
        );
        x += 1;
        let _ = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            " Reset Defaults ",
            false,
            pal,
            ClickAction::ResetDefaults,
        );
    }
}

fn draw_label(frame: &mut Frame, x: u16, y: u16, text: &str, pal: Palette) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text,
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.surface)
                .add_modifier(Modifier::BOLD),
        ))),
        Rect::new(x, y, text.len() as u16 + 1, 1),
    );
}
