//! Settings Theme Studio panel: language toggle (En/Fr), surface themes, accent colors, and motion.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::config::{AccentId, Language, ThemeId};
use crate::ui::hit::ClickAction;
use crate::ui::theme::{draw_card_header, inset_rect, Palette};

use super::draw_label;
use super::scan_options::render_toggle_row;

pub(super) fn render_theme_card(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 1);
    if inner.width < 20 || inner.height < 8 {
        return;
    }

    let lang = app.lang();
    let body = draw_card_header(
        frame,
        pal,
        inner,
        lang.t("Language & Theme Studio", "Langue & Apparence"),
        None,
    );
    let mut y = body.y;

    // 1. Language switcher (English / Français)
    draw_label(
        frame,
        Rect::new(body.x, y, body.width, 1),
        lang.t("Language / Langue:", "Langue / Language :"),
        pal,
    );
    y += 1;
    let mut lx = body.x;
    for &l in Language::ALL {
        let lbl = format!(" {} ", l.label());
        let lw = lbl.width() as u16;
        if lx + lw > body.right() {
            break;
        }
        let r = Rect::new(lx, y, lw, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lbl,
                pal.pill_style(lang == l, app.hits.is_hovered(r)),
            ))),
            r,
        );
        app.hits.record(r, ClickAction::SetLanguage(l));
        lx += lw + 1;
    }
    y += 2;

    // 2. Surface theme selector
    if y < body.bottom() {
        draw_label(
            frame,
            Rect::new(body.x, y, body.width, 1),
            lang.t("Surface Theme:", "Thème de surface :"),
            pal,
        );
        y += 1;
        let mut tx = body.x;
        for &t in ThemeId::ALL {
            let lbl = format!(" {} ", t.label_for(lang));
            let tw = lbl.width() as u16;
            if tx + tw > body.right() {
                tx = body.x;
                y += 1;
            }
            if y >= body.bottom() {
                break;
            }
            let r = Rect::new(tx, y, tw, 1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    lbl,
                    pal.pill_style(app.config.theme == t, app.hits.is_hovered(r)),
                ))),
                r,
            );
            app.hits.record(r, ClickAction::SetTheme(t));
            tx += tw + 1;
        }
        y += 2;
    }

    // 3. Accent swatches
    if y < body.bottom() {
        draw_label(
            frame,
            Rect::new(body.x, y, body.width, 1),
            lang.t("Accent Color:", "Couleur d'accent :"),
            pal,
        );
        y += 1;
        let mut ax = body.x;
        for &a in AccentId::ALL {
            let lbl = format!(" ■ {} ", a.label_for(lang));
            let aw = lbl.width() as u16;
            if ax + aw > body.right() {
                ax = body.x;
                y += 1;
            }
            if y >= body.bottom() {
                break;
            }
            let r = Rect::new(ax, y, aw, 1);
            let active = app.config.accent == a;
            let style = if active {
                pal.pill_style(true, false)
            } else if app.hits.is_hovered(r) {
                pal.pill_style(false, true)
            } else {
                Style::default()
                    .fg(Palette::swatch_rgb(a))
                    .bg(pal.surface_alt)
            };
            frame.render_widget(Paragraph::new(Line::from(Span::styled(lbl, style))), r);
            app.hits.record(r, ClickAction::SetAccent(a));
            ax += aw + 1;
        }
        y += 2;
    }

    // 4. Animations & Splash toggles
    if y + 1 < body.bottom() {
        render_toggle_row(
            frame,
            app,
            Rect::new(body.x, y, body.width, 1),
            pal,
            lang.t("Animations & Shimmer", "Animations & Reflets"),
            app.config.animations,
            ClickAction::ToggleAnimations,
        );
        y += 1;
        render_toggle_row(
            frame,
            app,
            Rect::new(body.x, y, body.width, 1),
            pal,
            lang.t("Launch Splash Emblem", "Écran d'accueil animé"),
            app.config.splash,
            ClickAction::ToggleSplash,
        );
    }
}
