//! Settings scan-engine panel: presets, concurrency/timeout sliders, toggles, and snapshot exports.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::net::model::{ExportFormat, ScanPreset};
use crate::ui::hit::ClickAction;
use crate::ui::theme::{draw_card_header, inset_rect, Palette};

use super::draw_label;

pub(super) fn render_scan_card(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
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
        lang.t(
            "Scan Preferences & Exports",
            "Préférences de scan & Exports",
        ),
        None,
    );
    let mut y = body.y;

    // Port presets
    draw_label(
        frame,
        Rect::new(body.x, y, body.width, 1),
        lang.t("Default Port Preset:", "Profil de ports par défaut :"),
        pal,
    );
    y += 1;

    let mut x = body.x;
    for &preset in ScanPreset::ALL {
        let lbl = format!(" {} ", preset.short_label_for(lang));
        let pw = lbl.width() as u16;
        if x + pw > body.right() {
            x = body.x;
            y += 1;
        }
        if y >= body.bottom() {
            break;
        }
        let r = Rect::new(x, y, pw, 1);
        let active = app.config.default_preset == preset;
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lbl,
                pal.pill_style(active, app.hits.is_hovered(r)),
            ))),
            r,
        );
        app.hits.record(
            r,
            if preset == ScanPreset::Custom {
                ClickAction::OpenCustomPortsModal
            } else {
                ClickAction::SetPreset(preset)
            },
        );
        x += pw + 1;
    }
    y += 2;

    if y < body.bottom() {
        let custom_s = format!(
            "{}: {}",
            lang.t("Custom range", "Plage perso"),
            app.config.custom_ports
        );
        let edit_btn = lang.t(" [Edit…] ", " [Modifier…] ");
        let ew = (edit_btn.width() as u16).min(body.width / 2);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                custom_s,
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ))),
            Rect::new(body.x, y, body.width.saturating_sub(ew + 1), 1),
        );
        let er = Rect::new(body.right().saturating_sub(ew), y, ew, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                edit_btn,
                pal.pill_style(false, app.hits.is_hovered(er)),
            ))),
            er,
        );
        app.hits.record(er, ClickAction::OpenCustomPortsModal);
        y += 2;
    }

    // Concurrency & Timeout steppers
    if y + 1 < body.bottom() {
        render_stepper(
            frame,
            app,
            Rect::new(body.x, y, body.width, 1),
            pal,
            &format!(
                "{}: {} sockets",
                lang.t("Concurrency", "Concurrence"),
                app.config.concurrency
            ),
            ClickAction::AdjustConcurrency(-64),
            ClickAction::AdjustConcurrency(64),
        );
        y += 1;
        render_stepper(
            frame,
            app,
            Rect::new(body.x, y, body.width, 1),
            pal,
            &format!(
                "{}: {} ms",
                lang.t("Connect timeout", "Délai TCP"),
                app.config.timeout_ms
            ),
            ClickAction::AdjustTimeout(-50),
            ClickAction::AdjustTimeout(50),
        );
        y += 2;
    }

    // Boolean toggles
    if y + 1 < body.bottom() {
        render_toggle_row(
            frame,
            app,
            Rect::new(body.x, y, body.width, 1),
            pal,
            lang.t(
                "Grab HTTP/TLS/SSH banners",
                "Récupérer bannières HTTP/TLS/SSH",
            ),
            app.config.grab_banners,
            ClickAction::ToggleGrabBanners,
        );
        y += 1;
        render_toggle_row(
            frame,
            app,
            Rect::new(body.x, y, body.width, 1),
            pal,
            lang.t(
                "Show virtual interfaces (docker/wg)",
                "Afficher interfaces virtuelles (docker/wg)",
            ),
            app.config.show_virtual_ifaces,
            ClickAction::ToggleVirtualIfaces,
        );
        y += 2;
    }

    // Export actions
    if y + 1 < body.bottom() {
        draw_label(
            frame,
            Rect::new(body.x, y, body.width, 1),
            lang.t("Export Network Snapshot:", "Exporter la capture réseau :"),
            pal,
        );
        y += 1;
        let mut ex = body.x;
        for fmt in [
            ExportFormat::Json,
            ExportFormat::Csv,
            ExportFormat::Markdown,
        ] {
            let lbl = format!(" Export {} ", fmt.label());
            let fw = lbl.width() as u16;
            if ex + fw > body.right() {
                break;
            }
            let r = Rect::new(ex, y, fw, 1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    lbl,
                    pal.pill_style(false, app.hits.is_hovered(r)),
                ))),
                r,
            );
            app.hits.record(r, ClickAction::ExportSnapshot(fmt));
            ex += fw + 1;
        }
    }
}

pub(super) fn render_toggle_row(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    label: &str,
    enabled: bool,
    action: ClickAction,
) {
    let lang = app.lang();
    let badge = if enabled {
        lang.t(" [ ON ] ", " [ OUI ] ")
    } else {
        lang.t(" [ OFF ] ", " [ NON ] ")
    };
    let bw = badge.width() as u16;
    let r = Rect::new(area.right().saturating_sub(bw), area.y, bw, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            label,
            Style::default().fg(pal.text).bg(pal.surface),
        ))),
        Rect::new(area.x, area.y, area.width.saturating_sub(bw + 1), 1),
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            badge,
            pal.pill_style(enabled, app.hits.is_hovered(r)),
        ))),
        r,
    );
    app.hits.record(r, action);
}

fn render_stepper(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    label: &str,
    dec: ClickAction,
    inc: ClickAction,
) {
    let dec_s = " [-] ";
    let inc_s = " [+] ";
    let inc_r = Rect::new(area.right().saturating_sub(5), area.y, 5, 1);
    let dec_r = Rect::new(inc_r.x.saturating_sub(6), area.y, 5, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            label,
            Style::default().fg(pal.text).bg(pal.surface),
        ))),
        Rect::new(area.x, area.y, dec_r.x.saturating_sub(area.x + 1), 1),
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            dec_s,
            pal.pill_style(false, app.hits.is_hovered(dec_r))
                .add_modifier(Modifier::BOLD),
        ))),
        dec_r,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            inc_s,
            pal.pill_style(false, app.hits.is_hovered(inc_r))
                .add_modifier(Modifier::BOLD),
        ))),
        inc_r,
    );
    app.hits.record(dec_r, dec);
    app.hits.record(inc_r, inc);
}
