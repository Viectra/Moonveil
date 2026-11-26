//! Scanner and reconnaissance preferences panel for the Settings tab.

use ratatui::layout::Rect;
use ratatui::widgets::Block;
use ratatui::Frame;

use crate::app::App;
use crate::net::model::{ScanMode, ScanPreset};
use crate::ui::hit::ClickAction;
use crate::ui::hosts::push_pill;
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};

use super::draw_label;

pub(super) fn render_scan_settings(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let r = Rect::new(area.x, area.y, area.width.saturating_sub(1), area.height);
    frame.render_widget(Block::default().style(pal.card_style()), r);
    let lang = app.lang();
    let body = draw_card_header(
        frame,
        pal,
        r,
        lang.t(
            "Scanner & Recon Preferences",
            "Préférences du scanner & recon",
        ),
        None,
    );
    let inner = inset_rect(body, 1, 0);
    if inner.height < 10 {
        return;
    }

    let mut y = inner.y;

    // UI Mode
    draw_label(
        frame,
        inner.x,
        y,
        lang.t("Interface Density Mode", "Mode de densité de l'interface"),
        pal,
    );
    y += 1;
    let mut x = inner.x;
    for mode in [ScanMode::Normal, ScanMode::Advanced] {
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" {} ({}) ", mode.label_for(lang), mode.subtitle_for(lang)),
            app.config.mode == mode,
            pal,
            ClickAction::SetMode(mode),
        );
        x += 1;
    }
    y += 2;

    // Default Preset
    draw_label(
        frame,
        inner.x,
        y,
        lang.t("Default Port Preset", "Préréglage de ports par défaut"),
        pal,
    );
    y += 1;
    x = inner.x;
    for &preset in ScanPreset::ALL {
        x = push_pill(
            frame,
            app,
            x,
            y,
            inner.right(),
            &format!(" {} ", preset.short_label_for(lang)),
            app.config.default_preset == preset,
            pal,
            ClickAction::SetPreset(preset),
        );
        x += 1;
    }
    y += 2;

    // Custom Port Expression
    if y + 1 < inner.bottom() {
        draw_label(
            frame,
            inner.x,
            y,
            lang.t(
                "Custom Port Range (click to edit)",
                "Plage de ports perso (cliquer pour modifier)",
            ),
            pal,
        );
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
            &format!(
                " {} {} ",
                lang.t("Concurrency:", "Parallélisme :"),
                app.config.concurrency
            ),
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
            &format!(
                " {} {}ms ",
                lang.t("Timeout:", "Délai :"),
                app.config.timeout_ms
            ),
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
            &format!(
                " {} {}s ",
                lang.t("Watch:", "Veille :"),
                app.config.watch_interval_secs
            ),
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
                lang.t(" ● Banners ON ", " ● Bannières ON ")
            } else {
                lang.t(" - Banners OFF ", " - Bannières OFF ")
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
                lang.t(
                    " ● Show Virtual (lo/veth) ",
                    " ● Afficher virtuelles (lo/veth) ",
                )
            } else {
                lang.t(
                    " - Hide Virtual (lo/veth) ",
                    " - Masquer virtuelles (lo/veth) ",
                )
            },
            app.config.show_virtual_ifaces,
            pal,
            ClickAction::ToggleVirtualIfaces,
        );
    }
}
