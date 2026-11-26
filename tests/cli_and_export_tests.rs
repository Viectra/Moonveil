use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::time::Duration;

use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};

use moonveil::cli::AnsiInputParser;
use moonveil::config::{AccentId, Config, KnownHostStore, Language, ThemeId};
use moonveil::net::demo::build_demo_snapshot;
use moonveil::net::model::{ExportFormat, ScanMode, ScanPreset};
use moonveil::net::tools::export_snapshot;

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
        language: Language::Fr,
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
