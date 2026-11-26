use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use moonveil::net::demo::build_demo_snapshot;
use moonveil::net::linux::{collect_local_sockets, network_addr, parse_proc_hex_ipv4};
use moonveil::net::model::{parse_port_expr, ports_for_preset, PortState, ScanPreset};
use moonveil::net::oui::{lookup_vendor, parse_oui_csv};
use moonveil::net::scanner::scan_ports_for_host;

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
