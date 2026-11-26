//! Sortable discovered hosts table with clickable column headers and row selection.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::config::Language;
use crate::net::model::{Host, HostSortColumn};
use crate::ui::hit::{ClickAction, ScrollTarget};
use crate::ui::theme::{inset_rect, truncate_str, Palette};

pub(super) fn render_table(frame: &mut Frame, app: &mut App, area: Rect, pal: Palette) {
    frame.render_widget(Block::default().style(pal.card_style()), area);
    let inner = inset_rect(area, 1, 1);
    if inner.width < 24 || inner.height < 4 {
        return;
    }

    let lang = app.lang();
    app.hits.record_scroll(inner, ScrollTarget::HostTable);

    // Dynamic column widths
    let w = usize::from(inner.width);
    let ping_w = 8_usize;
    let svc_w = if w >= 56 { 18 } else { 10 };
    let ip_w = 16_usize;
    let dev_w = w.saturating_sub(ping_w + svc_w + ip_w + 3).max(10);

    let header_y = inner.y;
    let mut cx = inner.x;
    let cols = [
        (HostSortColumn::Device, dev_w),
        (HostSortColumn::Ip, ip_w),
        (HostSortColumn::Rtt, ping_w),
        (HostSortColumn::OpenPorts, svc_w),
    ];
    for (col, cw) in cols {
        let active = app.host_sort == col;
        let arrow = if active {
            if app.host_sort_desc {
                " ▼"
            } else {
                " ▲"
            }
        } else {
            ""
        };
        let label = format!("{}{}", col.label_for(lang), arrow);
        let padded = format!("{:<width$}", truncate_str(&label, cw), width = cw);
        let rect = Rect::new(cx, header_y, cw as u16, 1);
        let hovered = app.hits.is_hovered(rect);
        let style = if active {
            Style::default()
                .fg(pal.veil_peach)
                .bg(pal.surface_alt)
                .add_modifier(Modifier::BOLD)
        } else if hovered {
            Style::default()
                .fg(pal.text)
                .bg(pal.hover)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(pal.text_dim)
                .bg(pal.surface_alt)
                .add_modifier(Modifier::BOLD)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(padded, style))),
            rect,
        );
        app.hits.record(rect, ClickAction::SortBy(col));
        cx = cx.saturating_add(cw as u16);
    }

    let visible_rows = usize::from(inner.height.saturating_sub(1));
    let hosts: Vec<Host> = app.filtered_hosts().into_iter().cloned().collect();
    if hosts.is_empty() {
        let empty_msg = match lang {
            Language::En => "No hosts match filter (press s to scan or Esc to clear search)",
            Language::Fr => "Aucun hôte trouvé (s pour scanner ou Échap pour effacer le filtre)",
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_str(empty_msg, w),
                Style::default().fg(pal.text_muted).bg(pal.surface),
            ))),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
        return;
    }

    if let Some(sel_ip) = app.selected_host_ip {
        if let Some(pos) = hosts.iter().position(|h| h.ip == sel_ip) {
            if pos < app.host_scroll {
                app.host_scroll = pos;
            } else if pos >= app.host_scroll + visible_rows {
                app.host_scroll = pos.saturating_sub(visible_rows.saturating_sub(1));
            }
        }
    }

    for (vis_idx, host) in hosts
        .iter()
        .skip(app.host_scroll)
        .take(visible_rows)
        .enumerate()
    {
        let row_y = inner.y + 1 + vis_idx as u16;
        let row_rect = Rect::new(inner.x, row_y, inner.width, 1);
        let selected = app.selected_host_ip == Some(host.ip);
        let hovered = app.hits.is_hovered(row_rect);

        let bg = if selected {
            pal.selection
        } else if hovered {
            pal.hover
        } else if vis_idx % 2 == 1 {
            pal.surface_alt
        } else {
            pal.surface
        };

        let status_dot = if host.online { "●" } else { "○" };
        let status_c = if host.online { pal.ok } else { pal.text_muted };
        let star = if host.trusted { "★ " } else { "  " };
        let name = host.display_name_for(lang);
        let dev_str = truncate_str(
            &format!("{star}{} {name}", host.role.icon()),
            dev_w.saturating_sub(3),
        );
        let dev_pad = dev_w.saturating_sub(2 + dev_str.width());

        let ip_s = format!("{:<width$}", host.ip, width = ip_w);
        let ping_s = match host.rtt_ms {
            Some(r) if r < 10.0 => format!("{:>5.1}ms ", r),
            Some(r) => format!("{:>5.0}ms ", r),
            None => format!("{:>width$}", "— ", width = ping_w),
        };
        let ping_c = host
            .rtt_ms
            .map(|r| pal.rtt_color(r))
            .unwrap_or(pal.text_muted);

        let svc_raw = host.open_ports_summary();
        let svc_s = truncate_str(&svc_raw, svc_w);

        let line = Line::from(vec![
            Span::styled(
                format!("{status_dot} "),
                Style::default().fg(status_c).bg(bg),
            ),
            Span::styled(
                dev_str,
                Style::default()
                    .fg(if selected { pal.veil_peach } else { pal.text })
                    .bg(bg)
                    .add_modifier(if selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled(" ".repeat(dev_pad), Style::default().bg(bg)),
            Span::styled(ip_s, Style::default().fg(pal.text_dim).bg(bg)),
            Span::styled(
                format!("{:<width$}", ping_s, width = ping_w),
                Style::default().fg(ping_c).bg(bg),
            ),
            Span::styled(svc_s, Style::default().fg(pal.accent).bg(bg)),
        ]);

        frame.render_widget(
            Paragraph::new(line).style(Style::default().bg(bg)),
            row_rect,
        );
        app.hits
            .record(row_rect, ClickAction::SelectHostIp(host.ip));
    }
}
