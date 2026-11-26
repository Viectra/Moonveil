//! Floating modal overlays (`Help`, `RenameHost`, `CustomPorts`).

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use unicode_width::UnicodeWidthStr;

use crate::app::{App, Modal};
use crate::config::Language;
use crate::ui::hit::ClickAction;
use crate::ui::theme::{inset_rect, Palette};

pub(super) fn render_modal(frame: &mut Frame, app: &mut App, full: Rect, pal: Palette) {
    let lang = app.lang();
    match &app.modal {
        Modal::None => {}
        Modal::Help => {
            let area = centered_rect(72, 74, full);
            frame.render_widget(Clear, area);
            let title = lang.t(
                " Moonveil — Controls & Smart Filters ",
                " Moonveil — Contrôles & Filtres ",
            );
            let block = Block::default()
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(pal.veil_peach)
                        .bg(pal.surface)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(pal.accent).bg(pal.surface))
                .style(Style::default().bg(pal.surface).fg(pal.text));
            frame.render_widget(block, area);

            let inner = inset_rect(area, 2, 1);
            let body = match lang {
                Language::En => vec![
                    Line::from(Span::styled(
                        "Navigation & Scanning",
                        Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
                    )),
                    Line::from("  1 - 3 / Tab       Switch views (Hosts, Subnet Radar, Settings)"),
                    Line::from("  s / Space         Start or stop active subnet scan"),
                    Line::from("  p                 Cycle port preset (Quick / Top100 / Full / WebDev / Custom)"),
                    Line::from("  r / Double-click  Deep scan all 1000+ ports on selected host"),
                    Line::from("  /                 Focus search bar (Esc to clear/blur)"),
                    Line::from("  t / n / e         Toggle Trusted star  •  Rename host  •  Export JSON"),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Search Query Tokens",
                        Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
                    )),
                    Line::from("  port:22  port:443       Filter hosts where port is Open or In Use"),
                    Line::from("  state:in-use            Show hosts with active ESTABLISHED sockets"),
                    Line::from("  state:open|closed       Match open or closed ports"),
                    Line::from("  vendor:apple            Match IEEE OUI vendor name"),
                    Line::from("  status:online|trusted   Filter reachability or starred devices"),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Press Esc, Enter, or click [Close] to return",
                        Style::default().fg(pal.text_muted),
                    )),
                ],
                Language::Fr => vec![
                    Line::from(Span::styled(
                        "Navigation & Scan",
                        Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
                    )),
                    Line::from("  1 - 3 / Tab       Changer de vue (Hôtes, Radar réseau, Paramètres)"),
                    Line::from("  s / Espace        Lancer ou arrêter le scan réseau"),
                    Line::from("  p                 Changer de profil (Rapide / Top100 / Complet / WebDev / Perso)"),
                    Line::from("  r / Double-clic   Scan approfondi (1000+ ports) sur l'hôte sélectionné"),
                    Line::from("  /                 Activer la barre de recherche (Échap pour fermer)"),
                    Line::from("  t / n / e         Étoile Fiable  •  Renommer l'hôte  •  Exporter JSON"),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Filtres intelligents",
                        Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
                    )),
                    Line::from("  port:22  port:443       Hôtes ayant ce port ouvert ou utilisé"),
                    Line::from("  state:in-use            Hôtes avec connexions actives (UTILISÉ)"),
                    Line::from("  state:open|closed       Filtrer par état ouvert ou fermé"),
                    Line::from("  vendor:apple            Filtrer par fabricant matériel (OUI)"),
                    Line::from("  status:online|trusted   Filtrer par disponibilité ou favoris"),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Échap, Entrée ou cliquez sur [Fermer] pour revenir",
                        Style::default().fg(pal.text_muted),
                    )),
                ],
            };
            frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }), inner);

            let close_lbl = lang.t(" [ Close ] ", " [ Fermer ] ");
            let close_rect = Rect::new(
                inner.right().saturating_sub(close_lbl.width() as u16 + 1),
                inner.bottom().saturating_sub(1),
                close_lbl.width() as u16,
                1,
            );
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    close_lbl,
                    Style::default()
                        .fg(pal.accent_fg)
                        .bg(pal.accent)
                        .add_modifier(Modifier::BOLD),
                ))),
                close_rect,
            );
            app.hits.record(close_rect, ClickAction::CloseModal);
        }
        Modal::RenameHost { ip, input } => {
            let area = centered_rect(54, 28, full);
            frame.render_widget(Clear, area);
            let title = match lang {
                Language::En => format!(" Rename Host ({ip}) "),
                Language::Fr => format!(" Renommer l'hôte ({ip}) "),
            };
            let block = Block::default()
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(pal.veil_peach)
                        .bg(pal.surface)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(pal.accent).bg(pal.surface))
                .style(Style::default().bg(pal.surface).fg(pal.text));
            frame.render_widget(block, area);

            let inner = inset_rect(area, 2, 1);
            let lines = vec![
                Line::from(Span::styled(
                    lang.t(
                        "Custom device nickname (empty clears saved name):",
                        "Nom personnalisé (vide pour réinitialiser) :",
                    ),
                    Style::default().fg(pal.text_dim),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(" > {input}_"),
                    Style::default()
                        .fg(pal.text)
                        .bg(pal.recessed)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    lang.t(
                        "Enter = Save   •   Esc = Cancel",
                        "Entrée = Enregistrer   •   Échap = Annuler",
                    ),
                    Style::default().fg(pal.text_muted),
                )),
            ];
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Modal::CustomPorts { input, error } => {
            let area = centered_rect(60, 32, full);
            frame.render_widget(Clear, area);
            let title = lang.t(" Custom Port Range ", " Plage de ports personnalisée ");
            let block = Block::default()
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(pal.veil_peach)
                        .bg(pal.surface)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(pal.accent).bg(pal.surface))
                .style(Style::default().bg(pal.surface).fg(pal.text));
            frame.render_widget(block, area);

            let inner = inset_rect(area, 2, 1);
            let mut lines = vec![
                Line::from(Span::styled(
                    lang.t(
                        "Comma-separated ports or inclusive ranges (e.g. 22,80,443,8000-8090):",
                        "Ports ou plages séparés par virgules (ex: 22,80,443,8000-8090) :",
                    ),
                    Style::default().fg(pal.text_dim),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(" > {input}_"),
                    Style::default()
                        .fg(pal.text)
                        .bg(pal.recessed)
                        .add_modifier(Modifier::BOLD),
                )),
            ];
            if let Some(err) = error {
                lines.push(Line::from(Span::styled(
                    err.as_str(),
                    Style::default().fg(pal.crit).add_modifier(Modifier::BOLD),
                )));
            } else {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                lang.t(
                    "Enter = Apply   •   Esc = Cancel",
                    "Entrée = Appliquer   •   Échap = Annuler",
                ),
                Style::default().fg(pal.text_muted),
            )));
            frame.render_widget(Paragraph::new(lines).alignment(Alignment::Left), inner);
        }
    }
}

pub(super) fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_v[1])[1]
}
