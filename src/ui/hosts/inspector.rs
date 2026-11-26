//! Selected host inspector: identity header, metadata, RTT spline, filterable port table, and actions.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::config::Language;
use crate::net::model::{PortFilter, PortInfo, PortState};
use crate::ui::hit::{ClickAction, ScrollTarget};
use crate::ui::theme::{inset_rect, truncate_str, Palette};
use crate::ui::widgets::{render_port_ratio_bar, SplineChart};

pub(super) fn render_inspector(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 1);
    if inner.width < 22 || inner.height < 6 {
        return;
    }

    let lang = app.lang();
    let Some(host) = app.selected_host().cloned() else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lang.t(
                    "Select a host to inspect.",
                    "Sélectionnez un hôte à inspecter.",
                ),
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ))),
            inner,
        );
        return;
    };

    let mut y = inner.y;

    // 1. Header: Display Name + Trust Star button
    let trust_lbl = if host.trusted {
        lang.t(" ★ Trusted ", " ★ Fiable ")
    } else {
        lang.t(" ☆ Trust ", " ☆ Fiable ")
    };
    let trust_w = (trust_lbl.width() as u16).min(inner.width / 2);
    let title_w = inner.width.saturating_sub(trust_w + 1);
    let title_s = truncate_str(
        &format!("{} {}", host.role.icon(), host.display_name_for(lang)),
        usize::from(title_w),
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            title_s,
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.surface)
                .add_modifier(Modifier::BOLD),
        ))),
        Rect::new(inner.x, y, title_w, 1),
    );
    let trust_rect = Rect::new(inner.right().saturating_sub(trust_w), y, trust_w, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            trust_lbl,
            pal.pill_style(host.trusted, app.hits.is_hovered(trust_rect)),
        ))),
        trust_rect,
    );
    app.hits
        .record(trust_rect, ClickAction::ToggleTrust(host.ip));
    y += 1;

    // 2. IP / MAC / Vendor / Role metadata (clickable copy for IP & MAC)
    let ip_chip = format!("IP: {}", host.ip);
    let mac_chip = format!("  MAC: {}", host.mac_string());
    let ip_rect = Rect::new(inner.x, y, (ip_chip.width() as u16).min(inner.width), 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            ip_chip,
            Style::default().fg(pal.text).bg(pal.surface),
        ))),
        ip_rect,
    );
    app.hits.record(
        ip_rect,
        ClickAction::CopyText {
            label: "IP".to_string(),
            value: host.ip.to_string(),
        },
    );
    if ip_rect.right() + (mac_chip.width() as u16) <= inner.right() {
        let mac_rect = Rect::new(ip_rect.right(), y, mac_chip.width() as u16, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                mac_chip,
                Style::default().fg(pal.text_dim).bg(pal.surface),
            ))),
            mac_rect,
        );
        if let Some(mac) = host.mac {
            app.hits.record(
                mac_rect,
                ClickAction::CopyText {
                    label: "MAC".to_string(),
                    value: crate::net::model::format_mac(mac),
                },
            );
        }
    }
    y += 1;

    let vendor_s = host.vendor.as_deref().unwrap_or("—");
    let os_s = host.os_guess.as_deref().unwrap_or("—");
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate_str(
                &format!(
                    "{}: {}  •  {}",
                    lang.t("Vendor", "Fabricant"),
                    vendor_s,
                    host.role.label_for(lang)
                ),
                usize::from(inner.width),
            ),
            Style::default().fg(pal.text_dim).bg(pal.surface),
        ))),
        Rect::new(inner.x, y, inner.width, 1),
    );
    y += 1;

    let host_line = host
        .hostname
        .as_deref()
        .map(|hn| format!("{}: {hn}  •  OS: {os_s}", lang.t("DNS", "DNS")))
        .unwrap_or_else(|| format!("OS: {os_s}"));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate_str(&host_line, usize::from(inner.width)),
            Style::default().fg(pal.text_muted).bg(pal.surface),
        ))),
        Rect::new(inner.x, y, inner.width, 1),
    );
    y += 1;

    // 3. Optional RTT chart if space allows
    if inner.bottom().saturating_sub(y) >= 12 {
        let rtt_area = Rect::new(inner.x, y, inner.width, 2);
        let rtt_data: Vec<f64> = if host.rtt_history.is_empty() {
            vec![host.rtt_ms.unwrap_or(0.0)]
        } else {
            host.rtt_history.clone()
        };
        let unit = host
            .rtt_ms
            .map(|r| format!("RTT {:.1}ms", r))
            .unwrap_or_else(|| "RTT —".to_string());
        frame.render_widget(
            SplineChart {
                series: &[(&rtt_data, pal.moon_violet)],
                bg: pal.recessed,
                max_override: None,
                unit_label: &unit,
            },
            rtt_area,
        );
        y += 2;
    }

    // 4. Port ratio bar + filter pills
    let (in_use, open, filtered, closed) = host.port_counts();
    if y < inner.bottom().saturating_sub(4) {
        render_port_ratio_bar(
            frame,
            Rect::new(inner.x, y, inner.width, 1),
            pal,
            in_use,
            open,
            filtered,
            closed,
        );
        y += 1;
    }

    let filter_y = y;
    let mut fx = inner.x;
    for &pf in PortFilter::ALL {
        let cnt = match pf {
            PortFilter::All => host.ports.len(),
            PortFilter::InUse => in_use,
            PortFilter::Open => open,
            PortFilter::Closed => filtered + closed,
        };
        let lbl = format!(" {}({cnt}) ", pf.label_for(lang));
        let fw = lbl.width() as u16;
        if fx + fw > inner.right() {
            break;
        }
        let f_rect = Rect::new(fx, filter_y, fw, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lbl,
                pal.pill_style(app.port_filter == pf, app.hits.is_hovered(f_rect)),
            ))),
            f_rect,
        );
        app.hits.record(f_rect, ClickAction::SetPortFilter(pf));
        fx += fw + 1;
    }
    y += 1;

    // 5. Filtered port list (collapsed closed ports unless Closed filter or expanded)
    let list_bottom = inner.bottom().saturating_sub(1);
    let list_h = list_bottom.saturating_sub(y);
    if list_h > 0 {
        let list_rect = Rect::new(inner.x, y, inner.width, list_h);
        app.hits.record_scroll(list_rect, ScrollTarget::PortList);

        let all_matching: Vec<&PortInfo> = host
            .ports
            .iter()
            .filter(|p| app.port_filter.matches(p.state))
            .collect();

        let collapse_closed =
            app.port_filter == PortFilter::All && !app.show_closed_ports && (closed + filtered) > 0;
        let visible_ports: Vec<&PortInfo> = if collapse_closed {
            all_matching
                .into_iter()
                .filter(|p| matches!(p.state, PortState::InUse | PortState::Open))
                .collect()
        } else {
            all_matching
        };

        let max_rows = usize::from(list_h);
        let mut py = y;

        for (idx, p) in visible_ports
            .iter()
            .skip(app.port_scroll)
            .take(max_rows.saturating_sub(usize::from(collapse_closed)))
            .enumerate()
        {
            let row_rect = Rect::new(inner.x, py, inner.width, 1);
            let detail = if let Some(proc_name) = &p.process {
                if let Some(peer) = &p.peer_endpoint {
                    format!("{proc_name} → {peer}")
                } else if let Some(b) = &p.banner {
                    format!("{proc_name} • {b}")
                } else {
                    proc_name.clone()
                }
            } else if let Some(b) = &p.banner {
                b.clone()
            } else if !p.description.is_empty() {
                p.description.clone()
            } else {
                String::new()
            };

            let state_tag = format!("{:<7}", p.state.label_for(lang));
            let port_tag = format!("{:>5}/{:<3}", p.port, p.proto.as_str());
            let svc_tag = format!("{:<10}", truncate_str(&p.service, 10));
            let prefix_len = state_tag.width() + port_tag.width() + svc_tag.width() + 4;
            let detail_s =
                truncate_str(&detail, usize::from(inner.width).saturating_sub(prefix_len));

            let line = Line::from(vec![
                Span::styled(
                    format!("{} ", state_tag),
                    Style::default()
                        .fg(pal.port_color(p.state))
                        .bg(pal.surface)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{port_tag} "),
                    Style::default().fg(pal.text).bg(pal.surface),
                ),
                Span::styled(
                    format!("{svc_tag} "),
                    Style::default().fg(pal.veil_peach).bg(pal.surface),
                ),
                Span::styled(detail_s, Style::default().fg(pal.text_dim).bg(pal.surface)),
            ]);
            frame.render_widget(Paragraph::new(line), row_rect);
            app.hits.record(row_rect, ClickAction::SelectPortRow(idx));
            py += 1;
        }

        if visible_ports.is_empty() && !collapse_closed {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    lang.t(
                        "No ports recorded in this filter (press r for deep scan)",
                        "Aucun port dans ce filtre (r pour scan approfondi)",
                    ),
                    Style::default().fg(pal.text_muted).bg(pal.surface),
                ))),
                Rect::new(inner.x, py, inner.width, 1),
            );
        }

        if collapse_closed && py < list_bottom {
            let hidden = closed + filtered;
            let expand_lbl = match lang {
                Language::En => format!(" + {hidden} closed ports (click to expand) "),
                Language::Fr => format!(" + {hidden} ports fermés (cliquer pour afficher) "),
            };
            let exp_rect = Rect::new(inner.x, py, (expand_lbl.width() as u16).min(inner.width), 1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    expand_lbl,
                    pal.pill_style(false, app.hits.is_hovered(exp_rect)),
                ))),
                exp_rect,
            );
            app.hits.record(exp_rect, ClickAction::ToggleClosedPorts);
        }
    }

    // 6. Action bar at bottom of inspector
    let act_y = inner.bottom().saturating_sub(1);
    let mut ax = inner.x;
    let buttons = [
        (
            lang.t(" Deep Scan ", " Scan complet "),
            ClickAction::DeepScanHost(host.ip),
        ),
        (
            if app.snapshot.ping_active && app.snapshot.ping_target == Some(host.ip) {
                lang.t(" ■ Ping ", " ■ Ping ")
            } else {
                lang.t(" Ping ", " Ping ")
            },
            ClickAction::PingHost(host.ip),
        ),
        (
            lang.t(" Rename ", " Renommer "),
            ClickAction::OpenRenameModal(host.ip),
        ),
        (" WoL ", ClickAction::WakeOnLan(host.ip)),
        (
            lang.t(" Copy IP ", " Copier IP "),
            ClickAction::CopyText {
                label: "IP".to_string(),
                value: host.ip.to_string(),
            },
        ),
    ];

    for (lbl, action) in buttons {
        let bw = lbl.width() as u16;
        if ax + bw > inner.right() {
            break;
        }
        let r = Rect::new(ax, act_y, bw, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                lbl,
                pal.pill_style(false, app.hits.is_hovered(r)),
            ))),
            r,
        );
        app.hits.record(r, action);
        ax += bw + 1;
    }
}
