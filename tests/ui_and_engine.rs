use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::time::Duration;

use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use moonveil::app::{App, Modal, Tab};
use moonveil::cli::AnsiInputParser;
use moonveil::config::{AccentId, Config, KnownHostStore, ThemeId};
use moonveil::net::demo::build_demo_snapshot;
use moonveil::net::linux::{collect_local_sockets, network_addr, parse_proc_hex_ipv4};
use moonveil::net::model::{
    parse_port_expr, ports_for_preset, ExportFormat, HostSortColumn, PortState, ScanMode,
    ScanPreset,
};
use moonveil::net::oui::{lookup_vendor, parse_oui_csv};
use moonveil::net::scanner::scan_ports_for_host;
use moonveil::net::tools::export_snapshot;
use moonveil::ui;
use moonveil::ui::hit::ClickAction;

fn demo_app(mode: ScanMode) -> App {
    let mut cfg = Config {
        splash: false,
        mode,
        ..Config::default()
    };
    cfg.theme = ThemeId::Moonveil;
    cfg.accent = AccentId::Violet;
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
fn test_parse_port_expr_and_presets() {
    let parsed = parse_port_expr("443, 22, 8000-8002, 22").expect("valid expr");
    assert_eq!(parsed, vec![22, 443, 8000, 8001, 8002]);
    assert!(parse_port_expr("").is_err());
    assert!(parse_port_expr("0").is_err());
    assert!(parse_port_expr("9000-8000").is_err());

    assert_eq!(ports_for_preset(ScanPreset::Quick, "").len(), 32);
    assert_eq!(ports_for_preset(ScanPreset::Standard, "").len(), 100);
    assert!(ports_for_preset(ScanPreset::Full, "").len() >= 1000);
    assert!(ports_for_preset(ScanPreset::WebDev, "").contains(&8096));
    assert_eq!(
        ports_for_preset(ScanPreset::Custom, "22,8080"),
        vec![22, 8080]
    );
}

#[test]
fn test_oui_lookup_and_randomized_mac() {
    let (docker_v, docker_rand) = lookup_vendor([0x02, 0x42, 0xAC, 0x11, 0x00, 0x02]);
    assert_eq!(docker_v.as_deref(), Some("Docker Container"));
    assert!(!docker_rand);

    let (rpi_v, rpi_rand) = lookup_vendor([0xDC, 0xA6, 0x32, 0x11, 0x22, 0x33]);
    assert!(rpi_v.unwrap_or_default().contains("Raspberry Pi"));
    assert!(!rpi_rand);

    let (priv_v, is_rand) = lookup_vendor([0x76, 0xA1, 0x4C, 0x22, 0x90, 0xE3]);
    assert_eq!(priv_v.as_deref(), Some("Private / Randomized MAC"));
    assert!(is_rand);

    let csv = "Registry,Assignment,Organization Name,Organization Address\nMA-L,F09FC2,\"Ubiquiti, Inc.\",USA\n";
    let entries = parse_oui_csv(csv.as_bytes());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, [0xF0, 0x9F, 0xC2]);
    assert_eq!(entries[0].1, "Ubiquiti, Inc.");
}

#[test]
fn test_linux_subnet_and_route_helpers() {
    assert_eq!(
        network_addr(Ipv4Addr::new(192, 168, 1, 12), 24),
        Ipv4Addr::new(192, 168, 1, 0)
    );
    if cfg!(target_endian = "little") {
        assert_eq!(
            parse_proc_hex_ipv4("0101A8C0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }
}

#[test]
fn test_smart_search_filters() {
    let (snap, _) = build_demo_snapshot();
    let gw = snap
        .hosts
        .iter()
        .find(|h| h.ip == Ipv4Addr::new(192, 168, 1, 1))
        .unwrap();
    assert!(gw.matches_query("port:53"));
    assert!(gw.matches_query("state:in-use"));
    assert!(gw.matches_query("state:closed"));
    assert!(gw.matches_query("vendor:ubiquiti"));
    assert!(!gw.matches_query("vendor:apple"));

    let win = snap
        .hosts
        .iter()
        .find(|h| h.ip == Ipv4Addr::new(192, 168, 1, 55))
        .unwrap();
    assert!(win.matches_query("os:windows"));
    assert!(win.matches_query("3389"));

    let offline = snap
        .hosts
        .iter()
        .find(|h| h.ip == Ipv4Addr::new(192, 168, 1, 200))
        .unwrap();
    assert!(offline.matches_query("status:offline"));
}

#[test]
fn test_headless_render_all_tabs_modes_sizes_and_modals() {
    let sizes = [(140, 42), (100, 30), (76, 22), (40, 10), (10, 4)];
    for (w, h) in sizes {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("test terminal");
        for mode in [ScanMode::Normal, ScanMode::Advanced] {
            let mut app = demo_app(mode);
            app.scan_progress.active = true;
            app.scan_progress.probed = 128;
            app.scan_progress.total = 254;
            app.scan_progress.current_target = "192.168.1.42".to_string();
            app.show_closed_ports = true;

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

            app.launch_traceroute(Ipv4Addr::new(192, 168, 1, 1));
            terminal
                .draw(|f| ui::render(f, &mut app))
                .expect("render traceroute modal");
        }
    }
}

#[test]
fn test_mouse_hit_registry_interactions() {
    let mut terminal = Terminal::new(TestBackend::new(140, 42)).expect("test terminal");
    let mut app = demo_app(ScanMode::Normal);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    assert_eq!(app.config.mode, ScanMode::Normal);

    click_action(&mut app, &ClickAction::ToggleMode);
    assert_eq!(app.config.mode, ScanMode::Advanced);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SortBy(HostSortColumn::Rtt));
    assert_eq!(app.host_sort, HostSortColumn::Rtt);

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
    assert_eq!(app.config.theme, ThemeId::Abyss);
    assert_eq!(app.config.accent, AccentId::Peach);
}

#[tokio::test]
async fn test_real_loopback_port_scan_and_banner_grab() {
    // 1. Greeting-first SSH-style banner listener on port 22-like probe
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = ssh_listener.accept().await {
            let _ = sock.write_all(b"SSH-2.0-MoonveilTest_1.0\r\n").await;
        }
    });

    // 2. HTTP listener on 127.0.0.1
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = http_listener.accept().await {
            let mut req = [0u8; 256];
            let _ = sock.read(&mut req).await;
            let _ = sock
                .write_all(
                    b"HTTP/1.0 200 OK\r\nServer: MoonveilHTTP\r\n\r\n<title>Test Page</title>",
                )
                .await;
        }
    });

    // 3. Guaranteed closed port by binding then dropping listener
    let closed_port = {
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        tmp.local_addr().unwrap().port()
    };

    let sockets = collect_local_sockets(false);
    assert!(!sockets.is_empty());

    let results = scan_ports_for_host(
        Ipv4Addr::LOCALHOST,
        &[ssh_port, http_port, closed_port],
        600,
        true,
        &sockets,
        true,
    )
    .await;

    let ssh_res = results.iter().find(|p| p.port == ssh_port).unwrap();
    assert!(matches!(ssh_res.state, PortState::Open | PortState::InUse));
    assert!(ssh_res
        .banner
        .as_deref()
        .unwrap_or("")
        .contains("SSH-2.0-MoonveilTest"));

    let closed_res = results.iter().find(|p| p.port == closed_port).unwrap();
    assert_eq!(closed_res.state, PortState::Closed);
}

#[test]
fn test_snapshot_exports_json_csv_markdown() {
    let (snap, _) = build_demo_snapshot();
    let tmp = std::env::temp_dir();

    let json_p = tmp.join("moonveil_test_export.json");
    let csv_p = tmp.join("moonveil_test_export.csv");
    let md_p = tmp.join("moonveil_test_export.md");

    export_snapshot(&snap, ExportFormat::Json, &json_p).unwrap();
    export_snapshot(&snap, ExportFormat::Csv, &csv_p).unwrap();
    export_snapshot(&snap, ExportFormat::Markdown, &md_p).unwrap();

    let json_s = std::fs::read_to_string(&json_p).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_s).unwrap();
    assert!(parsed["hosts"].as_array().unwrap().len() >= 10);

    let csv_s = std::fs::read_to_string(&csv_p).unwrap();
    assert!(csv_s.starts_with("ip,hostname,nickname,mac,vendor"));
    assert!(csv_s.contains("192.168.1.1"));

    let md_s = std::fs::read_to_string(&md_p).unwrap();
    assert!(md_s.contains("# Moonveil Network Snapshot"));
    assert!(md_s.contains("192.168.1.12"));

    let _ = std::fs::remove_file(json_p);
    let _ = std::fs::remove_file(csv_p);
    let _ = std::fs::remove_file(md_p);
}

#[test]
fn test_config_and_known_hosts_toml_roundtrip() {
    let tmp = std::env::temp_dir();
    let cfg_path = tmp.join("moonveil_test_cfg.toml");
    let hosts_path = tmp.join("moonveil_test_hosts.toml");

    let cfg = Config {
        mode: ScanMode::Advanced,
        theme: ThemeId::Abyss,
        accent: AccentId::Peach,
        animations: false,
        splash: false,
        show_virtual_ifaces: true,
        default_preset: ScanPreset::WebDev,
        custom_ports: "22,80,443,8000-8090".to_string(),
        concurrency: 128,
        timeout_ms: 500,
        grab_banners: false,
        watch_interval_secs: 30,
    };
    cfg.save_to(&cfg_path).unwrap();
    let loaded_cfg = Config::load_from(&cfg_path);
    assert_eq!(loaded_cfg, cfg);

    let mut store = KnownHostStore::default();
    store.upsert(
        "f0:9f:c2:41:88:01",
        Ipv4Addr::new(192, 168, 1, 1),
        Some("Main \"Router\"".to_string()),
        true,
        Some("Ubiquiti".to_string()),
        Some("gateway.lan".to_string()),
    );
    store.save_to(&hosts_path).unwrap();
    let loaded_store = KnownHostStore::load_from(&hosts_path);
    assert_eq!(loaded_store, store);

    let _ = std::fs::remove_file(cfg_path);
    let _ = std::fs::remove_file(hosts_path);
}

#[test]
fn test_persist_state_clicks_write_config_and_known_hosts() {
    struct EnvDirGuard {
        dir: std::path::PathBuf,
    }
    impl Drop for EnvDirGuard {
        fn drop(&mut self) {
            std::env::remove_var("MOONVEIL_CONFIG_DIR");
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    let dir = std::env::temp_dir().join(format!("moonveil_persist_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("MOONVEIL_CONFIG_DIR", &dir);
    let _guard = EnvDirGuard { dir: dir.clone() };

    let mut terminal = Terminal::new(TestBackend::new(140, 42)).expect("test terminal");
    let mut app = demo_app(ScanMode::Normal);
    app.persist_state = true;
    let target_ip = Ipv4Addr::new(192, 168, 1, 1);

    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::ToggleMode);
    click_action(&mut app, &ClickAction::CyclePreset);
    click_action(&mut app, &ClickAction::ToggleTrusted(target_ip));

    click_action(&mut app, &ClickAction::SwitchTab(Tab::Settings));
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    click_action(&mut app, &ClickAction::SetTheme(ThemeId::Abyss));
    click_action(&mut app, &ClickAction::SetAccent(AccentId::Peach));

    assert!(dir.join("config.toml").exists());
    assert!(dir.join("known_hosts.toml").exists());

    let reloaded_cfg = Config::load();
    assert_eq!(reloaded_cfg.mode, ScanMode::Advanced);
    assert_eq!(reloaded_cfg.default_preset, ScanPreset::Standard);
    assert_eq!(reloaded_cfg.theme, ThemeId::Abyss);
    assert_eq!(reloaded_cfg.accent, AccentId::Peach);

    let reloaded_hosts = KnownHostStore::load();
    let entry = reloaded_hosts
        .hosts
        .get("F0:9F:C2:41:88:01")
        .expect("trusted toggle persisted gateway MAC");
    assert!(!entry.trusted);
}

#[test]
fn test_ssh_ansi_parser_large_burst_and_split_packets() {
    let mut stream = Vec::new();
    for i in 0..500 {
        let col = (i % 120) + 100;
        let row = (i % 30) + 10;
        let mut s = String::new();
        let _ = write!(s, "\x1b[<35;{col};{row}M");
        stream.extend_from_slice(s.as_bytes());
    }
    assert!(stream.len() > 6000);

    stream.extend_from_slice(b"\x1b[<0;210;55M\x1b[<0;210;55m");
    stream.extend_from_slice(&[0x1B, b'[', b'M', 32, 33 + 10, 33 + 5]);
    stream.extend_from_slice(b"\x1b[A\x1bOB\x1b[Z/port:22\r\x1b");

    let mut parser = AnsiInputParser::new();
    for chunk in stream.chunks(137) {
        parser.push_bytes(chunk);
    }
    parser.flush_expired(Duration::ZERO);

    let mut events = Vec::new();
    while let Some(ev) = parser.pop_event() {
        events.push(ev);
    }

    assert_eq!(events.len(), 500 + 2 + 1 + 2 + 1 + 8 + 1 + 1);
    for (i, ev) in events[..500].iter().enumerate() {
        assert_eq!(
            *ev,
            Event::Mouse(MouseEvent {
                kind: MouseEventKind::Moved,
                column: ((i % 120) + 99) as u16,
                row: ((i % 30) + 9) as u16,
                modifiers: KeyModifiers::NONE,
            })
        );
    }

    assert_eq!(
        events[500],
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 209,
            row: 54,
            modifiers: KeyModifiers::NONE,
        })
    );
    assert_eq!(
        events[501],
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 209,
            row: 54,
            modifiers: KeyModifiers::NONE,
        })
    );
    assert_eq!(
        events[502],
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        })
    );

    assert_eq!(events[503], Event::Key(KeyCode::Up.into()));
    assert_eq!(events[504], Event::Key(KeyCode::Down.into()));
    assert_eq!(
        events[505],
        Event::Key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT))
    );
    let typed: String = events[506..514]
        .iter()
        .map(|ev| match ev {
            Event::Key(k) => match k.code {
                KeyCode::Char(c) => c,
                other => panic!("Unexpected key {other:?}"),
            },
            other => panic!("Unexpected event {other:?}"),
        })
        .collect();
    assert_eq!(typed, "/port:22");
    assert_eq!(events[514], Event::Key(KeyCode::Enter.into()));
    assert_eq!(events[515], Event::Key(KeyCode::Esc.into()));
}
