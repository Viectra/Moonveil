use std::net::Ipv4Addr;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use moonveil::app::{App, Modal, Tab};
use moonveil::config::{AccentId, Config, KnownHostStore, Language, ThemeId};
use moonveil::net::model::{ExportFormat, HostSortColumn, PortFilter, ScanMode, ScanPreset};
use moonveil::ui;
use moonveil::ui::hit::ClickAction;

fn demo_app(mode: ScanMode, language: Language) -> App {
    let cfg = Config {
        splash: false,
        mode,
        theme: ThemeId::Moonveil,
        accent: AccentId::Violet,
        language,
        ..Config::default()
    };
    let mut app = App::new(cfg, true, Some("enp6s18"));
    app.persist_state = false;
    app
}

fn click_action(app: &mut App, action: &ClickAction) {
    let (col, row) = app
        .hits
        .find_action_center(action)
        .unwrap_or_else(|| panic!("Missing hit region for {action:?}"));
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: col,
        row,
        modifiers: KeyModifiers::NONE,
    });
}

#[test]
fn test_headless_render_all_tabs_sizes_and_modals_bilingual() {
    let sizes = [(225, 64), (140, 40), (100, 30), (76, 22), (40, 10), (10, 4)];
    for language in Language::ALL {
        for (w, h) in sizes {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("test terminal");
            let mut app = demo_app(ScanMode::Normal, *language);
            app.scan_progress.active = true;
            app.scan_progress.probed = 128;
            app.scan_progress.total = 254;
            app.scan_progress.current_target = "192.168.1.42".to_string();

            for &tab in Tab::ALL {
                app.tab = tab;
                terminal
                    .draw(|f| ui::render(f, &mut app))
                    .expect("render tab");
            }
            app.tab = Tab::Hosts;
            app.modal = Modal::Help;
            terminal
                .draw(|f| ui::render(f, &mut app))
                .expect("render help modal");

            app.modal = Modal::RenameHost {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                input: "Gateway".to_string(),
            };
            terminal
                .draw(|f| ui::render(f, &mut app))
                .expect("render rename modal");

            app.modal = Modal::CustomPorts {
                input: "22,80,443".to_string(),
                error: Some("Sample warning".to_string()),
            };
            terminal
                .draw(|f| ui::render(f, &mut app))
                .expect("render custom ports modal");
        }
    }
}

#[test]
fn test_mouse_hit_registry_interactions() {
    let mut terminal = Terminal::new(TestBackend::new(140, 42)).expect("test terminal");
    let mut app = demo_app(ScanMode::Normal, Language::En);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    assert_eq!(app.config.default_preset, ScanPreset::Quick);

    click_action(&mut app, &ClickAction::CyclePreset);
    assert_eq!(app.config.default_preset, ScanPreset::Standard);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SortBy(HostSortColumn::OpenPorts));
    assert_eq!(app.host_sort, HostSortColumn::OpenPorts);

    click_action(&mut app, &ClickAction::SetPortFilter(PortFilter::Closed));
    assert_eq!(app.port_filter, PortFilter::Closed);

    click_action(&mut app, &ClickAction::FocusSearch);
    assert!(app.search_focused);
    for ch in ['p', 'o', 'r', 't', ':', '5', '3'] {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
    }
    assert_eq!(app.search_query, "port:53");
    assert_eq!(app.filtered_hosts().len(), 2);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::ClearSearch);
    assert!(app.search_query.is_empty());

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SwitchTab(Tab::Radar));
    assert_eq!(app.tab, Tab::Radar);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SelectRadarOctet(30));
    assert_eq!(app.radar_selected_octet, 30);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(
        &mut app,
        &ClickAction::JumpToHostIp(Ipv4Addr::new(192, 168, 1, 30)),
    );
    assert_eq!(app.tab, Tab::Hosts);
    assert_eq!(app.selected_host_ip, Some(Ipv4Addr::new(192, 168, 1, 30)));

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SwitchTab(Tab::Settings));
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SetTheme(ThemeId::Abyss));
    click_action(&mut app, &ClickAction::SetAccent(AccentId::Peach));
    click_action(&mut app, &ClickAction::SetLanguage(Language::Fr));
    assert_eq!(app.config.theme, ThemeId::Abyss);
    assert_eq!(app.config.accent, AccentId::Peach);
    assert_eq!(app.config.language, Language::Fr);
}

#[test]
fn test_persist_state_clicks_write_config_and_known_hosts() {
    struct EnvDirGuard {
        dir: std::path::PathBuf,
    }
    impl Drop for EnvDirGuard {
        fn drop(&mut self) {
            std::env::remove_var("MOONVEIL_CONFIG_DIR");
            std::env::remove_var("XDG_DATA_HOME");
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    let dir = std::env::temp_dir().join(format!("moonveil_persist_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("MOONVEIL_CONFIG_DIR", &dir);
    std::env::set_var("XDG_DATA_HOME", &dir);
    let _guard = EnvDirGuard { dir: dir.clone() };

    let mut terminal = Terminal::new(TestBackend::new(140, 42)).expect("test terminal");
    let mut app = demo_app(ScanMode::Normal, Language::En);
    app.persist_state = true;
    let target_ip = Ipv4Addr::new(192, 168, 1, 1);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::CyclePreset);
    click_action(&mut app, &ClickAction::OpenRenameModal(target_ip));
    assert!(matches!(app.modal, Modal::RenameHost { .. }));
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(app.modal, Modal::None));

    click_action(&mut app, &ClickAction::SwitchTab(Tab::Settings));
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SetTheme(ThemeId::Abyss));
    click_action(&mut app, &ClickAction::SetAccent(AccentId::Peach));
    click_action(&mut app, &ClickAction::SetLanguage(Language::Fr));
    click_action(&mut app, &ClickAction::ExportSnapshot(ExportFormat::Json));

    assert!(dir.join("config.toml").exists());
    assert!(dir.join("known_hosts.toml").exists());
    let export_entries: Vec<_> = std::fs::read_dir(dir.join("moonveil").join("exports"))
        .expect("export dir created")
        .collect();
    assert_eq!(export_entries.len(), 1);

    let reloaded_cfg = Config::load();
    assert_eq!(reloaded_cfg.default_preset, ScanPreset::Standard);
    assert_eq!(reloaded_cfg.theme, ThemeId::Abyss);
    assert_eq!(reloaded_cfg.accent, AccentId::Peach);
    assert_eq!(reloaded_cfg.language, Language::Fr);

    let reloaded_hosts = KnownHostStore::load();
    let entry = reloaded_hosts
        .hosts
        .get("F0:9F:C2:41:88:01")
        .expect("rename persisted gateway MAC");
    assert_eq!(entry.nickname.as_deref(), Some("Main Router 1"));
}
