//! Watch & Exports tab: live change timeline, saved/trusted hosts with WoL, and 1-click snapshot exports.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::net::model::{EventKind, ExportFormat};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::hosts::push_pill;
use crate::ui::theme::{draw_card_header, inset_rect, truncate_str, Palette};

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let pal = app.palette;
    if area.width < 36 || area.height < 12 {
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Export cards & Watch toggle bar
            Constraint::Min(8),    // Split: Timeline + Saved hosts
        ])
        .split(area);

    render_export_bar(frame, app, rows[0], pal);

    let cols = if rows[1].width >= 96 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(rows[1])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(rows[1])
    };

    render_timeline(frame, app, cols[0], pal);
    let right = if rows[1].width >= 96 {
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
    render_saved_hosts(frame, app, right, pal);
}

fn render_export_bar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let card = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(1));
    frame.render_widget(Block::default().style(pal.card_style()), card);
    let lang = app.lang();
    let body = draw_card_header(
        frame,
        pal,
        card,
        lang.t(
            "Watch Monitor & Snapshot Exports",
            "Veille réseau & exports d'instantanés",
        ),
        Some((
            if app.watch_mode {
                lang.t("● Watching", "● En veille")
            } else {
                lang.t("- Idle", "- Inactif")
            },
            if app.watch_mode {
                pal.ok
            } else {
                pal.text_muted
            },
        )),
    );
    let inner = inset_rect(body, 1, 0);
    if inner.height == 0 {
        return;
    }
    let mut x = inner.x;
    x = push_pill(
        frame,
        app,
        x,
        inner.y,
        inner.right(),
        if app.watch_mode {
            lang.t(" ■ Stop Watch ", " ■ Arrêter la veille ")
        } else {
            lang.t(" ● Start Watch ", " ● Démarrer la veille ")
        },
        app.watch_mode,
        pal,
        ClickAction::ToggleWatch,
    );
    x += 2;
    for fmt in [
        ExportFormat::Json,
        ExportFormat::Csv,
        ExportFormat::Markdown,
    ] {
        x = push_pill(
            frame,
            app,
            x,
            inner.y,
            inner.right(),
            &format!(" ↓ {} {} ", lang.t("Export", "Exporter"), fmt.label()),
            false,
            pal,
            ClickAction::ExportSnapshot(fmt),
        );
        x += 1;
    }
    let _ = push_pill(
        frame,
        app,
        x,
        inner.y,
        inner.right(),
        lang.t(" Clear Feed ", " Vider le fil "),
        false,
        pal,
        ClickAction::ClearTimeline,
    );
}

fn render_timeline(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let r = Rect::new(area.x, area.y, area.width.saturating_sub(1), area.height);
    frame.render_widget(Block::default().style(pal.card_style()), r);
    let lang = app.lang();
    let body = draw_card_header(
        frame,
        pal,
        r,
        lang.t(
            "Network Change Timeline",
            "Chronologie des changements réseau",
        ),
        Some((
            &format!("{} {}", app.timeline.len(), lang.t("events", "événements")),
            pal.veil_peach,
        )),
    );
    let inner = inset_rect(body, 1, 0);
    app.hits.register_scroll(inner, ScrollTarget::Timeline);

    if app.timeline.is_empty() {
        frame.render_widget(
            Paragraph::new(lang.t(
                "  No timeline events recorded yet. Enable Watch or run a scan.",
                "  Aucun événement enregistré. Activez la veille ou lancez un scan.",
            ))
            .style(Style::default().fg(pal.text_muted).bg(pal.surface)),
            inner,
        );
        return;
    }

    let vis = usize::from(inner.height);
    let max_sc = app.timeline.len().saturating_sub(vis);
    if app.timeline_scroll > max_sc {
        app.timeline_scroll = max_sc;
    }
    for (idx, ev) in app
        .timeline
        .iter()
        .rev()
        .skip(app.timeline_scroll)
        .take(vis)
        .enumerate()
    {
        let row = Rect::new(inner.x, inner.y + idx as u16, inner.width, 1);
        let badge_col = match ev.kind {
            EventKind::UnknownIntruder => pal.crit,
            EventKind::HostJoined | EventKind::PortOpened => pal.ok,
            EventKind::ActiveSession => pal.in_use,
            EventKind::HostLeft | EventKind::PortClosed => pal.warn,
            EventKind::ScanFinished | EventKind::Action => pal.moon_violet,
        };
        let line = Line::from(vec![
            Span::styled(
                format!("{} ", ev.timestamp),
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ),
            Span::styled(
                format!("{:<6}", ev.kind.badge()),
                Style::default()
                    .fg(badge_col)
                    .bg(pal.surface)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                truncate_str(&ev.summary, inner.width.saturating_sub(16) as usize),
                Style::default().fg(pal.text).bg(pal.surface),
            ),
        ]);
        frame.render_widget(Paragraph::new(line), row);
        if let Some(ip) = ev.ip {
            app.hits.register(row, ClickAction::JumpToHostIp(ip));
        }
    }
}

fn render_saved_hosts(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let lang = app.lang();
    let body = draw_card_header(
        frame,
        pal,
        area,
        lang.t(
            "Saved & Trusted Devices",
            "Appareils enregistrés & de confiance",
        ),
        Some((
            &format!(
                "{} {}",
                app.known_hosts.hosts.len(),
                lang.t("saved", "enregistrés")
            ),
            pal.ok,
        )),
    );
    let inner = inset_rect(body, 1, 0);
    app.hits.register_scroll(inner, ScrollTarget::SavedHosts);

    let entries: Vec<_> = app.known_hosts.hosts.values().cloned().collect();
    if entries.is_empty() {
        frame.render_widget(
            Paragraph::new(lang.t(
                "  Trust or rename any device in Hosts tab to save it for Wake-on-LAN.",
                "  Marquez de confiance ou renommez un appareil (onglet Hôtes) pour l'enregistrer pour le Wake-on-LAN.",
            ))
                .style(Style::default().fg(pal.text_muted).bg(pal.surface)),
            inner,
        );
        return;
    }

    let vis = usize::from(inner.height);
    for (idx, entry) in entries.iter().skip(app.saved_scroll).take(vis).enumerate() {
        let row = Rect::new(inner.x, inner.y + idx as u16, inner.width, 1);
        let hovered = HitRegistry::is_hovered(row, app.hover);
        let bg = if hovered {
            pal.surface_hover
        } else {
            pal.surface
        };
        let name = entry
            .nickname
            .as_deref()
            .or(entry.hostname.as_deref())
            .unwrap_or(&entry.last_ip);
        let wol_w = 7_u16;
        let info_w = row.width.saturating_sub(wol_w + 1);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    if entry.trusted { "★ " } else { "! " },
                    Style::default()
                        .fg(if entry.trusted {
                            pal.ok
                        } else {
                            pal.text_muted
                        })
                        .bg(bg),
                ),
                Span::styled(
                    format!("{:<15}", truncate_str(name, 14)),
                    Style::default().fg(pal.text).bg(bg),
                ),
                Span::styled(
                    format!("{} ", entry.last_ip),
                    Style::default().fg(pal.veil_peach).bg(bg),
                ),
                Span::styled(
                    truncate_str(&entry.mac, info_w.saturating_sub(32) as usize),
                    Style::default().fg(pal.text_dim).bg(bg),
                ),
            ]))
            .style(Style::default().bg(bg)),
            Rect::new(row.x, row.y, info_w, 1),
        );
        if let Ok(ip) = entry.last_ip.parse() {
            let wol_rect = Rect::new(row.right().saturating_sub(wol_w), row.y, wol_w, 1);
            let wol_h = HitRegistry::is_hovered(wol_rect, app.hover);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    " ▲ WoL ",
                    pal.pill_style(false, wol_h),
                ))),
                wol_rect,
            );
            app.hits.register(wol_rect, ClickAction::SendWol(ip));
        }
    }
}
