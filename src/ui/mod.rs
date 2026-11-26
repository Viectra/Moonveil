//! Root UI shell: sidebar with Moonveil emblem, compact topbar, 5 views, splash, and floating modals.

pub mod hit;
pub mod hosts;
pub mod network;
pub mod radar;
pub mod settings;
pub mod theme;
pub mod watch;
pub mod widgets;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Modal, Tab};
use crate::ui::hit::{ClickAction, HitRegistry};
use crate::ui::theme::{inset_rect, truncate_str, Palette};
use crate::ui::widgets::{mix, render_emblem_compact, render_emblem_hero};

/// Renders a full Moonveil frame and records all clickable hit regions.
pub fn render(frame: &mut Frame, app: &mut App) {
    app.hits.clear();
    let area = frame.area();
    let pal = app.palette;

    frame.render_widget(Block::default().style(pal.bg_style()), area);

    if area.width < 40 || area.height < 12 {
        render_too_small(frame, pal, area);
        return;
    }

    // Animated logo splash reveal on initial launch (skippable on any click or key).
    if app.is_splash_active() && area.width >= 50 && area.height >= 22 {
        render_splash(frame, app, area, pal);
        return;
    }

    if area.width >= 90 && area.height >= 18 {
        let sidebar_w = if area.width >= 118 { 24 } else { 20 };
        let shell = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(sidebar_w), Constraint::Min(30)])
            .split(area);
        render_sidebar(frame, app, shell[0], pal);
        render_workspace(frame, app, shell[1], pal);
    } else {
        let shell = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(8),
                Constraint::Length(1),
            ])
            .split(area);
        render_compact_topbar(frame, app, shell[0], pal);
        render_active_tab(frame, app, shell[1]);
        render_status_footer(frame, app, shell[2], pal);
    }

    match app.modal.clone() {
        Modal::None => {}
        Modal::Help => render_help_modal(frame, app, area, pal),
        Modal::RenameHost { ip, input } => render_rename_modal(frame, app, area, pal, ip, &input),
        Modal::CustomPorts { input, error } => {
            render_custom_ports_modal(frame, app, area, pal, &input, error.as_deref())
        }
        Modal::Traceroute { ip } => render_traceroute_modal(frame, app, area, pal, ip),
    }
}

fn render_active_tab(frame: &mut Frame, app: &mut App, body: Rect) {
    match app.tab {
        Tab::Hosts => hosts::render(frame, app, body),
        Tab::Radar => radar::render(frame, app, body),
        Tab::Network => network::render(frame, app, body),
        Tab::Watch => watch::render(frame, app, body),
        Tab::Settings => settings::render(frame, app, body),
    }
}

fn render_too_small(frame: &mut Frame, pal: Palette, area: Rect) {
    let lines = vec![
        Line::from(vec![
            Span::styled(
                "MOON",
                Style::default()
                    .fg(pal.moon_violet)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "VEIL",
                Style::default()
                    .fg(pal.veil_peach)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!("Window too small ({}x{})", area.width, area.height),
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "Resize >= 40x12",
            Style::default().fg(pal.text_muted),
        )),
    ];
    let y = area.y + area.height.saturating_sub(3) / 2;
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .style(pal.bg_style()),
        Rect::new(area.x, y, area.width, 3.min(area.height)),
    );
}

fn render_splash(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let phase = (app.tick_count % 20) as f64 / 20.0;
    let total_h = 18_u16;
    let y0 = area.y + area.height.saturating_sub(total_h) / 2;
    render_emblem_hero(
        frame,
        Rect::new(area.x, y0, area.width, 14),
        pal.bg,
        pal,
        phase,
    );
    let title = Line::from(vec![
        Span::styled(
            "M O O N ",
            Style::default()
                .fg(pal.moon_violet)
                .bg(pal.bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "V E I L",
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.bg)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    let sub = Line::from(Span::styled(
        "Linux Network Radar & Socket Inspector",
        Style::default().fg(pal.text_dim).bg(pal.bg),
    ));
    frame.render_widget(
        Paragraph::new(vec![Line::raw(""), title, sub]).alignment(Alignment::Center),
        Rect::new(area.x, y0 + 14, area.width, 3),
    );
    app.hits.register(area, ClickAction::SkipSplash);
}

fn render_sidebar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar).fg(pal.text)),
        area,
    );
    let inner = inset_rect(area, 1, 1);
    if inner.width < 10 || inner.height < 14 {
        return;
    }

    let mut y = inner.y;
    // Compact half-block logo emblem when height allows
    if inner.height >= 24 {
        render_emblem_compact(
            frame,
            Rect::new(inner.x, y, inner.width, 6),
            pal.sidebar,
            pal,
            app.pulse_phase(),
        );
        y += 6;
    }

    // MOONVEIL wordmark
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

    // Host / privilege status pill
    let dot_col = if app.scan_progress.active {
        mix(pal.moon_violet, pal.veil_peach, app.pulse_phase())
    } else {
        pal.ok
    };
    let priv_badge = app.snapshot.privilege.badge();
    let host_line = format!("{}@{}", app.snapshot.username, app.snapshot.hostname);
    let mut status_spans = vec![
        Span::styled("● ", Style::default().fg(dot_col).bg(pal.sidebar)),
        Span::styled(
            truncate_str(&host_line, inner.width.saturating_sub(8) as usize),
            Style::default().fg(pal.text_dim).bg(pal.sidebar),
        ),
        Span::styled(
            format!(" {priv_badge}"),
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.sidebar)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if app.demo_mode && inner.width >= 20 {
        status_spans = vec![
            Span::styled("● ", Style::default().fg(pal.warn).bg(pal.sidebar)),
            Span::styled(
                "DEMO MODE ",
                Style::default()
                    .fg(pal.warn)
                    .bg(pal.sidebar)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                priv_badge,
                Style::default().fg(pal.text_dim).bg(pal.sidebar),
            ),
        ];
    }
    frame.render_widget(
        Paragraph::new(Line::from(status_spans)).style(Style::default().bg(pal.sidebar)),
        Rect::new(inner.x, y, inner.width, 1),
    );
    y += 2;

    // Navigation items
    let hosts_online = app.snapshot.hosts.iter().filter(|h| h.online).count();
    for &tab in Tab::ALL {
        if tab == Tab::Settings && y + 6 < inner.bottom() {
            y += 1;
        }
        if y + 3 >= inner.bottom() {
            break;
        }
        let item_rect = Rect::new(inner.x, y, inner.width, 1);
        let active = app.tab == tab;
        let hovered = HitRegistry::is_hovered(item_rect, app.hover);
        let bg = if active {
            pal.accent
        } else if hovered {
            pal.hover
        } else {
            pal.sidebar
        };
        let fg = if active { pal.accent_fg } else { pal.text };
        let count_hint = match tab {
            Tab::Hosts => format!("{hosts_online}"),
            Tab::Network => format!("{}", app.visible_interfaces().len()),
            Tab::Watch => format!("{}", app.timeline.len()),
            _ => String::new(),
        };
        let label = format!(" {} {}", tab.icon(), tab.label());
        let pad = usize::from(inner.width).saturating_sub(
            unicode_width::UnicodeWidthStr::width(label.as_str()) + count_hint.len() + 1,
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
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
                    format!("{count_hint} "),
                    Style::default()
                        .fg(if active {
                            pal.accent_fg
                        } else {
                            pal.text_muted
                        })
                        .bg(bg),
                ),
            ])),
            item_rect,
        );
        app.hits.register(item_rect, ClickAction::SwitchTab(tab));
        y += 1;
    }

    // Bottom Help / Quit pills
    let foot_y = inner.bottom().saturating_sub(1);
    let half_w = inner.width / 2;
    let help_r = Rect::new(inner.x, foot_y, half_w.saturating_sub(1), 1);
    let quit_r = Rect::new(inner.x + half_w, foot_y, inner.width - half_w, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " ? Help ",
            pal.pill_style(
                matches!(app.modal, Modal::Help),
                HitRegistry::is_hovered(help_r, app.hover),
            ),
        ))),
        help_r,
    );
    app.hits.register(help_r, ClickAction::ToggleHelp);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " × Quit ",
            pal.pill_style(false, HitRegistry::is_hovered(quit_r, app.hover)),
        ))),
        quit_r,
    );
    app.hits.register(quit_r, ClickAction::Quit);
}

fn render_workspace(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let padded = inset_rect(area, 1, 1);
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(1)])
        .split(padded);
    render_active_tab(frame, app, split[0]);
    render_status_footer(frame, app, split[1], pal);
}

fn render_compact_topbar(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        area,
    );
    let mut x = area.x + 1;
    let brand = Rect::new(x, area.y, 9, 1);
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
        ])),
        brand,
    );
    x += 10;

    for &tab in Tab::ALL {
        let lbl = format!(" {} ", tab.short_label());
        let w = lbl.len() as u16;
        if x + w + 8 > area.right() {
            break;
        }
        let r = Rect::new(x, area.y, w, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lbl,
                pal.pill_style(app.tab == tab, HitRegistry::is_hovered(r, app.hover)),
            ))),
            r,
        );
        app.hits.register(r, ClickAction::SwitchTab(tab));
        x += w + 1;
    }

    // Compact Mode toggle on right
    let m_lbl = format!(" {} ", app.config.mode.label());
    let mw = m_lbl.len() as u16;
    if area.right() > x + mw + 2 {
        let mr = Rect::new(area.right() - mw - 1, area.y, mw, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                m_lbl,
                pal.pill_style(true, HitRegistry::is_hovered(mr, app.hover)),
            ))),
            mr,
        );
        app.hits.register(mr, ClickAction::ToggleMode);
    }
}

fn render_status_footer(frame: &mut Frame, app: &App, area: Rect, pal: Palette) {
    let msg = if let Some((toast, _)) = &app.toast {
        toast.clone()
    } else if app.scan_progress.active {
        format!(
            "{} • {} ({}/{})",
            app.scan_progress.phase,
            app.scan_progress.current_target,
            app.scan_progress.probed,
            app.scan_progress.total
        )
    } else {
        let last = app
            .scan_progress
            .last_duration_ms
            .map(|d| format!(" • Last scan {d}ms"))
            .unwrap_or_default();
        format!(
            "{} • {} Mode • 1-5 Views • m Mode • s Scan • / Search • ? Help{last}",
            app.snapshot.privilege.description(),
            app.config.mode.label()
        )
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate_str(&msg, usize::from(area.width)),
            Style::default()
                .fg(if app.toast.is_some() {
                    pal.veil_peach
                } else {
                    pal.text_muted
                })
                .bg(pal.bg),
        ))),
        area,
    );
}

fn centered_rect(area: Rect, w: u16, h: u16) -> Rect {
    let cw = w.min(area.width.saturating_sub(2));
    let ch = h.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + area.width.saturating_sub(cw) / 2,
        area.y + area.height.saturating_sub(ch) / 2,
        cw,
        ch,
    )
}

fn render_help_modal(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    let modal = centered_rect(area, 64, 24);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(1)])
        .split(inner);

    let lines = vec![
        Line::from(vec![
            Span::styled(
                "MOON",
                Style::default()
                    .fg(pal.moon_violet)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "VEIL",
                Style::default()
                    .fg(pal.veil_peach)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " — Shortcuts & Mouse Controls",
                Style::default().fg(pal.text),
            ),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "1-5 / Tab      Switch views (Hosts, Radar, Network, Watch, Settings)",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "m              Toggle Normal Mode <-> Advanced Mode",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "s              Start or stop subnet + port scan",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "p              Cycle scan preset (Quick, Top100, Full, Web/Dev, Custom)",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "w              Toggle background Watch Mode",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "/              Search (port:22 state:in-use state:closed vendor:apple)",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "t / n          Trust toggle / Rename host nickname",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "j / k / ↑ / ↓  Navigate host list • Mouse wheel scrolls any list",
            Style::default().fg(pal.text_dim),
        )),
        Line::from(Span::styled(
            "e              Export snapshot JSON • q / Esc to close",
            Style::default().fg(pal.text_dim),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[0]);

    let close_r = Rect::new(rows[1].x, rows[1].y, 12, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " Close (Esc) ",
            pal.pill_style(true, false),
        ))),
        close_r,
    );
    app.hits.register(close_r, ClickAction::CloseModal);
}

fn render_rename_modal(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    ip: std::net::Ipv4Addr,
    input: &str,
) {
    let modal = centered_rect(area, 52, 7);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);
    let lines = vec![
        Line::from(Span::styled(
            format!("Rename Host ({ip})"),
            Style::default()
                .fg(pal.veil_peach)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            format!(" {input}▏"),
            Style::default().fg(pal.text).bg(pal.recessed),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            "Enter to save • Esc to cancel",
            Style::default().fg(pal.text_muted),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
    app.hits.register(
        Rect::new(inner.x, inner.bottom().saturating_sub(1), 16, 1),
        ClickAction::CloseModal,
    );
}

fn render_custom_ports_modal(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    input: &str,
    error: Option<&str>,
) {
    let modal = centered_rect(area, 58, 8);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);
    let mut lines = vec![
        Line::from(Span::styled(
            "Custom Port Range (e.g. 22,80,443,3000-3010)",
            Style::default()
                .fg(pal.veil_peach)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            format!(" {input}▏"),
            Style::default().fg(pal.text).bg(pal.recessed),
        )),
    ];
    if let Some(err) = error {
        lines.push(Line::from(Span::styled(err, Style::default().fg(pal.crit))));
    } else {
        lines.push(Line::raw(""));
    }
    lines.push(Line::from(Span::styled(
        "Enter to apply & select Custom preset • Esc to cancel",
        Style::default().fg(pal.text_muted),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
    app.hits.register(
        Rect::new(inner.x, inner.bottom().saturating_sub(1), 16, 1),
        ClickAction::CloseModal,
    );
}

fn render_traceroute_modal(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    pal: Palette,
    ip: std::net::Ipv4Addr,
) {
    let modal = centered_rect(area, 62, 18);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Block::default().style(Style::default().bg(pal.sidebar)),
        modal,
    );
    let inner = inset_rect(modal, 2, 1);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(inner);

    let status = if app.trace_running {
        "Tracing…"
    } else {
        "Done"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("Traceroute -> {ip}  "),
                Style::default()
                    .fg(pal.veil_peach)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(status, Style::default().fg(pal.moon_violet)),
        ])),
        rows[0],
    );

    let hop_lines: Vec<Line> = if app.trace_hops.is_empty() {
        vec![Line::from(Span::styled(
            "Probing route hops…",
            Style::default().fg(pal.text_muted),
        ))]
    } else {
        app.trace_hops
            .iter()
            .map(|h| {
                let ip_s =
                    h.ip.map(|x| x.to_string())
                        .unwrap_or_else(|| "*".to_string());
                let name_s = h.hostname.as_deref().unwrap_or("");
                let rtt_s = h
                    .rtt_ms
                    .map(|r| format!("{r:.2} ms"))
                    .unwrap_or_else(|| "timeout".to_string());
                Line::from(vec![
                    Span::styled(
                        format!(" {:>2}  ", h.ttl),
                        Style::default().fg(pal.text_muted),
                    ),
                    Span::styled(format!("{ip_s:<16}"), Style::default().fg(pal.text)),
                    Span::styled(
                        format!("{:<22}", truncate_str(name_s, 20)),
                        Style::default().fg(pal.text_dim),
                    ),
                    Span::styled(rtt_s, Style::default().fg(pal.ok)),
                ])
            })
            .collect()
    };
    frame.render_widget(Paragraph::new(hop_lines), rows[1]);

    let close_r = Rect::new(rows[2].x, rows[2].y, 12, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " Close (Esc) ",
            pal.pill_style(true, false),
        ))),
        close_r,
    );
    app.hits.register(close_r, ClickAction::CloseModal);
}
