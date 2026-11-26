//! Application shell layout: sidebar with emblem, compact topbar, toast, and status footer.

use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::{App, Tab};
use crate::config::Language;
use crate::ui::hit::ClickAction;
use crate::ui::theme::{inset_rect, truncate_str, Palette};
use crate::ui::widgets::{render_emblem_compact, render_scan_wave};

pub(super) fn render_sidebar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar).fg(pal.text)),
        area,
    );
    let inner = inset_rect(area, 1, 1);
    if inner.width < 10 || inner.height < 12 {
        return;
    }

    let lang = app.lang();
    let mut y = inner.y;
    if inner.height >= 22 {
        render_emblem_compact(
            frame,
            Rect::new(inner.x, y, inner.width, 6),
            pal.sidebar,
            pal,
            app.pulse_phase(),
        );
        y += 6;
    }

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "MOON",
                Style::default()
                    .fg(pal.moon_violet)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "VEIL",
                Style::default()
                    .fg(pal.veil_peach)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .alignment(Alignment::Center),
        Rect::new(inner.x, y, inner.width, 1),
    );
    y += 1;

    let priv_badge = app.snapshot.privilege.badge();
    let user_line = truncate_str(
        &format!("{}@{}", app.snapshot.username, app.snapshot.hostname),
        usize::from(inner.width),
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            user_line,
            Style::default().fg(pal.text_muted).bg(pal.sidebar),
        )))
        .alignment(Alignment::Center),
        Rect::new(inner.x, y, inner.width, 1),
    );
    y += 2;

    for &tab in Tab::ALL {
        if y >= inner.bottom().saturating_sub(3) {
            break;
        }
        let active = app.tab == tab;
        let row_rect = Rect::new(inner.x, y, inner.width, 1);
        let hovered = app.hits.is_hovered(row_rect);
        let bg = if active {
            pal.selection
        } else if hovered {
            pal.hover
        } else {
            pal.sidebar
        };
        let fg = if active { pal.veil_peach } else { pal.text_dim };

        let count_str = match tab {
            Tab::Hosts => format!("{}", app.snapshot.hosts.len()),
            Tab::Radar => app
                .active_interface()
                .map(|i| format!("/{}", i.prefix_len))
                .unwrap_or_default(),
            Tab::Settings => lang.as_str().to_ascii_uppercase(),
        };
        let label = format!(" {} {}", tab.icon(), tab.label_for(lang));
        let pad = usize::from(inner.width).saturating_sub(label.width() + count_str.width() + 1);
        let line = Line::from(vec![
            Span::styled(
                label,
                Style::default().fg(fg).bg(bg).add_modifier(if active {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
            ),
            Span::styled(" ".repeat(pad), Style::default().bg(bg)),
            Span::styled(
                format!("{count_str} "),
                Style::default().fg(pal.text_muted).bg(bg),
            ),
        ]);
        frame.render_widget(Paragraph::new(line), row_rect);
        app.hits.record(row_rect, ClickAction::SwitchTab(tab));
        y += 2;
    }

    let footer_y = inner.bottom().saturating_sub(2);
    if footer_y > y {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("● {priv_badge}"),
                Style::default().fg(pal.accent).bg(pal.sidebar),
            ))),
            Rect::new(inner.x, footer_y, inner.width, 1),
        );
    }

    let bottom_y = inner.bottom().saturating_sub(1);
    let help_s = lang.t(" ? Help ", " ? Aide ");
    let quit_s = lang.t(" × Quit ", " × Quitter ");
    let help_w = (help_s.width() as u16).min(inner.width / 2);
    let quit_w = (quit_s.width() as u16).min(inner.width.saturating_sub(help_w + 1));
    let help_rect = Rect::new(inner.x, bottom_y, help_w, 1);
    let quit_rect = Rect::new(inner.right().saturating_sub(quit_w), bottom_y, quit_w, 1);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            help_s,
            pal.pill_style(false, app.hits.is_hovered(help_rect)),
        ))),
        help_rect,
    );
    app.hits.record(help_rect, ClickAction::ShowHelp);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            quit_s,
            pal.pill_style(false, app.hits.is_hovered(quit_rect)),
        ))),
        quit_rect,
    );
    app.hits.record(quit_rect, ClickAction::Quit);
}

pub(super) fn render_topbar(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    compact_tabs: bool,
) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let lang = app.lang();
    let row0 = Rect::new(area.x, area.y, area.width, 1);
    let mut x = row0.x + 1;

    if compact_tabs {
        for &tab in Tab::ALL {
            let lbl = format!(" {} ", tab.short_label_for(lang));
            let w = lbl.width() as u16;
            if x + w >= row0.right() {
                break;
            }
            let r = Rect::new(x, row0.y, w, 1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    lbl,
                    pal.pill_style(app.tab == tab, app.hits.is_hovered(r)),
                ))),
                r,
            );
            app.hits.record(r, ClickAction::SwitchTab(tab));
            x += w + 1;
        }
    }

    let ifaces: Vec<(usize, String, bool)> = app
        .snapshot
        .interfaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            (
                i,
                format!(" {} ({}) ", iface.name, iface.cidr),
                i == app.snapshot.active_iface_idx,
            )
        })
        .collect();
    for (idx, lbl, active) in ifaces {
        let w = lbl.width() as u16;
        if x + w + 22 >= row0.right() {
            break;
        }
        let r = Rect::new(x, row0.y, w, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lbl,
                pal.pill_style(active, app.hits.is_hovered(r)),
            ))),
            r,
        );
        app.hits.record(r, ClickAction::SelectInterface(idx));
        x += w + 1;
    }

    let scan_lbl = if app.scan_progress.active {
        lang.t(" ■ Stop ", " ■ Stop ")
    } else {
        lang.t(" ▶ Scan ", " ▶ Scanner ")
    };
    let preset_lbl = format!(" {} ", app.config.default_preset.short_label_for(lang));
    let right_margin = row0.right().saturating_sub(1);
    let preset_w = preset_lbl.width() as u16;
    let scan_w = scan_lbl.width() as u16;

    let preset_rect = Rect::new(right_margin.saturating_sub(preset_w), row0.y, preset_w, 1);
    let scan_rect = Rect::new(preset_rect.x.saturating_sub(scan_w + 1), row0.y, scan_w, 1);

    if scan_rect.x >= x {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                scan_lbl,
                pal.pill_style(app.scan_progress.active, app.hits.is_hovered(scan_rect)),
            ))),
            scan_rect,
        );
        app.hits.record(scan_rect, ClickAction::ToggleScan);

        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                preset_lbl,
                pal.pill_style(false, app.hits.is_hovered(preset_rect)),
            ))),
            preset_rect,
        );
        app.hits.record(preset_rect, ClickAction::CyclePreset);
    }

    if area.height >= 2 {
        let wave_rect = Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), 1);
        let ratio = if app.scan_progress.active {
            app.scan_progress.ratio()
        } else {
            1.0
        };
        let label = if app.scan_progress.active {
            format!("{}/{}", app.scan_progress.probed, app.scan_progress.total)
        } else {
            format!(
                "{} {}",
                app.snapshot.hosts.iter().filter(|h| h.online).count(),
                lang.t("online", "en ligne")
            )
        };
        render_scan_wave(frame, wave_rect, pal, ratio, app.tick, &label);
    }
}

pub(super) fn render_footer(frame: &mut Frame, app: &App, area: Rect, pal: Palette) {
    let lang = app.lang();
    let hints = match lang {
        Language::En => "1-3 Views  •  s Scan  •  / Search  •  p Preset  •  r Deep  •  n Rename  •  ? Help",
        Language::Fr => "1-3 Vues  •  s Scanner  •  / Chercher  •  p Profil  •  r Détail  •  n Renommer  •  ? Aide",
    };
    let max_left = usize::from(area.width).saturating_sub(hints.width() + 4);
    let left = truncate_str(&app.status_message, max_left.max(12));
    let pad = usize::from(area.width).saturating_sub(left.width() + hints.width() + 2);
    let line = Line::from(vec![
        Span::styled(
            format!(" {left}"),
            Style::default().fg(pal.text_dim).bg(pal.bg),
        ),
        Span::styled(" ".repeat(pad), Style::default().bg(pal.bg)),
        Span::styled(
            format!("{hints} "),
            Style::default().fg(pal.text_muted).bg(pal.bg),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

pub(super) fn render_toast(frame: &mut Frame, area: Rect, pal: Palette, msg: &str) {
    let w = (msg.width() as u16 + 4).min(area.width.saturating_sub(4));
    if w < 8 || area.height < 3 {
        return;
    }
    let rect = Rect::new(
        area.right().saturating_sub(w + 2),
        area.bottom().saturating_sub(2),
        w,
        1,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {msg} "),
            Style::default()
                .fg(pal.accent_fg)
                .bg(pal.accent)
                .add_modifier(Modifier::BOLD),
        ))),
        rect,
    );
}
