//! Barre d'outils de l'onglet `Hosts` : recherche, mode Normal/Advanced, scan, preset et watch.

use super::*;

pub(super) fn render_toolbar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let lang = app.lang();
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 0);
    if inner.height < 2 || inner.width < 20 {
        return;
    }

    // Row 0: Interface pill | Mode toggle | Scan / Stop | Preset | Watch | Compact Inspect toggle
    let row0 = Rect::new(inner.x, inner.y, inner.width, 1);
    let mut x = row0.x;

    let iface_label = app
        .active_interface()
        .map(|i| format!(" ⇄ {} ({}) ", i.name, i.cidr))
        .unwrap_or_else(|| lang.t(" ⇄ no-iface ", " ⇄ aucune-iface ").to_string());
    x = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        &iface_label,
        false,
        pal,
        ClickAction::CycleInterface,
    );
    x += 1;

    // Mode toggle pill: Normal <-> Advanced
    let is_adv = app.config.mode == ScanMode::Advanced;
    let mode_line = render_mode_pill(
        ScanMode::Normal.label_for(lang),
        ScanMode::Advanced.label_for(lang),
        is_adv,
        pal,
        pal.surface,
    );
    let mode_w = 24_u16;
    if x + mode_w <= row0.right() {
        let m_rect = Rect::new(x, row0.y, mode_w, 1);
        frame.render_widget(Paragraph::new(mode_line), m_rect);
        app.hits.register(m_rect, ClickAction::ToggleMode);
        x += mode_w + 1;
    }

    let scan_lbl = if app.scan_progress.active {
        lang.t(" ■ Stop ", " ■ Arrêt ")
    } else {
        " ▶ Scan "
    };
    x = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        scan_lbl,
        !app.scan_progress.active,
        pal,
        ClickAction::StartOrStopScan,
    );
    x += 1;

    let preset_lbl = format!(" {} ", app.config.default_preset.short_label_for(lang));
    x = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        &preset_lbl,
        false,
        pal,
        ClickAction::CyclePreset,
    );
    x += 1;

    let watch_lbl = if app.watch_mode {
        lang.t(" ● Watch ON ", " ● Veille ON ")
    } else {
        lang.t(" - Watch ", " - Veille ")
    };
    let _ = push_pill(
        frame,
        app,
        x,
        row0.y,
        row0.right(),
        watch_lbl,
        app.watch_mode,
        pal,
        ClickAction::ToggleWatch,
    );

    // Row 2: Interactive Search & Filter Bar
    let row2 = Rect::new(inner.x, inner.y + 2.min(inner.height - 1), inner.width, 1);
    let clear_lbl = lang.t(" Clear ", " Effacer ");
    let clear_w = if app.search_query.is_empty() {
        0
    } else {
        unicode_width::UnicodeWidthStr::width(clear_lbl) as u16
    };
    let search_w = row2.width.saturating_sub(clear_w + 1);
    let search_rect = Rect::new(row2.x, row2.y, search_w, 1);
    let search_bg = if app.search_focused {
        pal.selection
    } else {
        pal.recessed
    };
    let cursor = if app.search_focused && (app.tick_count / 6).is_multiple_of(2) {
        "▏"
    } else {
        ""
    };
    let display = if app.search_query.is_empty() && !app.search_focused {
        lang.t(
            " / Search IP, MAC, vendor, port:22, state:in-use, state:closed, status:new…",
            " / Rechercher IP, MAC, fabricant, port:22, state:in-use, state:closed, status:new…",
        )
        .to_string()
    } else {
        format!(" / {}{}", app.search_query, cursor)
    };
    let text_color = if app.search_query.is_empty() && !app.search_focused {
        pal.text_muted
    } else {
        pal.text
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate_str(&display, usize::from(search_w)),
            Style::default().fg(text_color).bg(search_bg),
        )))
        .style(Style::default().bg(search_bg)),
        search_rect,
    );
    app.hits.register(search_rect, ClickAction::FocusSearch);

    if clear_w > 0 && row2.right() >= clear_w {
        let clr_rect = Rect::new(row2.right() - clear_w, row2.y, clear_w, 1);
        let hovered = HitRegistry::is_hovered(clr_rect, app.hover);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                clear_lbl,
                pal.pill_style(false, hovered),
            ))),
            clr_rect,
        );
        app.hits.register(clr_rect, ClickAction::ClearSearch);
    }
}
