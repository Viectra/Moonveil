//! Theme, language, accent swatches, and visual effects panel for the Settings tab.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::config::{AccentId, Language, ThemeId};
use crate::ui::hit::{ClickAction, HitRegistry};
use crate::ui::hosts::push_pill;
use crate::ui::theme::{draw_card_header, inset_rect, Palette};

use super::draw_label;

pub(super) fn render_appearance_settings(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let lang = app.lang();
    let body = draw_card_header(
        frame,
        pal,
        area,
        lang.t("Theme & Visual Effects", "Thème & effets visuels"),
        None,
    );
    let inner = inset_rect(body, 1, 0);
    if inner.height < 10 {
        return;
    }

    let mut y = inner.y;

    // Interface language
    draw_label(
        frame,
        inner.x,
        y,
        lang.t("Interface Language", "Langue de l'interface"),
        pal,
    );
    y += 1;
    let mut x = inner.x;
    for &l in Language::ALL {
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" {} ", l.label()),
            lang == l,
            pal,
            ClickAction::SetLanguage(l),
        );
        x += 1;
    }
    y += 2;

    draw_label(
        frame,
        inner.x,
        y,
        lang.t("Surface Theme", "Thème de surface"),
        pal,
    );
    y += 1;
    x = inner.x;
    for &theme in ThemeId::ALL {
        let lbl = format!(" {} ", theme.label_for(lang));
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
        draw_label(
            frame,
            inner.x,
            y,
            lang.t("Accent Swatch", "Couleur d'accent"),
            pal,
        );
        y += 1;
        x = inner.x;
        for &accent in AccentId::ALL {
            let sw = Palette::swatch_rgb(accent);
            let active = app.config.accent == accent;
            let lbl = format!(" ● {} ", accent.label_for(lang));
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
                        format!("{} ", accent.label_for(lang)),
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
            lang.t(" Reset Defaults ", " Réinitialiser "),
            false,
            pal,
            ClickAction::ResetDefaults,
        );
    }
}
