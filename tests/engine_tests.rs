use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use moonveil::config::Language;
use moonveil::net::demo::build_demo_snapshot;
use moonveil::net::linux::{collect_local_sockets, network_addr, parse_proc_hex_ipv4};
use moonveil::net::model::{
    clean_discovered_hostname, parse_port_expr, ports_for_preset, service_info, ArpState,
    DeviceRole, Host, LocalSocket, PortInfo, PortState, Proto, ScanPreset, SocketState,
};
use moonveil::net::oui::{lookup_vendor, parse_oui_csv};
use moonveil::net::scanner::scan_ports_for_host;

#[test]
fn test_parse_port_expr_and_presets() {
    let parsed = parse_port_expr("443, 22, 8000-8002, 22").expect("valid expr");
    assert_eq!(parsed, vec![22, 443, 8000, 8001, 8002]);
    assert!(parse_port_expr("").is_err());
    assert!(parse_port_expr("0").is_err());
    assert!(parse_port_expr("9000-8000").is_err());

    assert_eq!(ports_for_preset(ScanPreset::Quick, "").len(), 37);
    assert!(ports_for_preset(ScanPreset::Quick, "").contains(&8765));
    assert_eq!(ports_for_preset(ScanPreset::Standard, "").len(), 100);
    assert!(ports_for_preset(ScanPreset::Full, "").len() > 1024);
    assert!(ports_for_preset(ScanPreset::Full, "").contains(&8765));
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
fn test_hostname_cleaning_and_smart_device_display_name() {
    assert_eq!(
        clean_discovered_hostname("wattson1.home"),
        Some("wattson1".to_string())
    );
    assert_eq!(
        clean_discovered_hostname("Freebox-Server.local."),
        Some("Freebox-Server".to_string())
    );
    assert_eq!(
        clean_discovered_hostname("android-2-home-home-home.home"),
        Some("android-2".to_string())
    );
    assert_eq!(clean_discovered_hostname("_gateway"), None);
    assert_eq!(clean_discovered_hostname("none.local"), None);
    assert_eq!(
        clean_discovered_hostname("e6f16a61-1778-46e4-a833-d6638ab8fda4.home"),
        None
    );

    let canon_printer = Host {
        ip: Ipv4Addr::new(192, 168, 1, 36),
        ipv6: None,
        hostname: None,
        nickname: None,
        mac: None,
        oui_prefix: None,
        vendor: Some("CANON INC.".to_string()),
        is_randomized_mac: false,
        online: true,
        trusted: true,
        role: DeviceRole::Host,
        arp_state: ArpState::Reachable,
        ttl: None,
        os_guess: None,
        rtt_ms: Some(10.0),
        rtt_history: vec![10.0],
        jitter_ms: None,
        packet_loss_pct: 0.0,
        ports: vec![PortInfo {
            port: 631,
            proto: Proto::Tcp,
            state: PortState::Open,
            service: "ipp".to_string(),
            description: "Network printing (CUPS)".to_string(),
            banner: None,
            banner_hex: None,
            latency_ms: Some(2.0),
            process: None,
            pid: None,
            peer_endpoint: None,
        }],
        first_seen_epoch: 0,
        last_seen_epoch: 0,
        discovered_tick: 0,
        subnet_cidr: "192.168.1.0/24".to_string(),
        interface: "enp6s18".to_string(),
        is_new: false,
    };
    assert_eq!(canon_printer.display_name(), "Canon Printer");
    assert_eq!(
        canon_printer.display_name_for(Language::Fr),
        "Imprimante Canon"
    );
    assert_ne!(canon_printer.display_name(), "192.168.1.36");

    let bare_device = Host {
        vendor: None,
        ports: Vec::new(),
        ip: Ipv4Addr::new(192, 168, 1, 99),
        ..canon_printer.clone()
    };
    assert_eq!(bare_device.display_name(), "Device .99");
    assert_eq!(bare_device.display_name_for(Language::Fr), "Appareil .99");

    let this_pc = Host {
        role: DeviceRole::ThisMachine,
        vendor: None,
        ports: Vec::new(),
        ..canon_printer
    };
    assert_eq!(this_pc.display_name_for(Language::En), "This PC");
    assert_eq!(this_pc.display_name_for(Language::Fr), "Ce PC");
}

#[tokio::test]
async fn test_real_loopback_port_scan_and_banner_grab() {
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = ssh_listener.accept().await {
            let _ = sock.write_all(b"SSH-2.0-MoonveilTest_1.0\r\n").await;
        }
    });

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

#[tokio::test]
async fn test_port_descriptions_and_local_in_use_accuracy() {
    assert_eq!(service_info(8765).0, "http-alt");
    assert_eq!(service_info(54321), ("tcp", ""));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut req = [0u8; 256];
            let _ = sock.read(&mut req).await;
            let _ = sock
                .write_all(b"HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6\r\n\r\n<title>Dist</title>")
                .await;
        }
    });

    let closed_port = {
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        tmp.local_addr().unwrap().port()
    };

    // Outbound ESTABLISHED socket where remote_port == http_port must NOT mark local port IN USE.
    let fake_outbound = vec![LocalSocket {
        proto: "TCP".to_string(),
        local_addr: "127.0.0.1:51234".to_string(),
        local_ip_v4: Some(Ipv4Addr::LOCALHOST),
        local_port: 51234,
        remote_addr: format!("192.168.1.1:{http_port}"),
        remote_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 1)),
        remote_port: http_port,
        state: SocketState::Established,
        pid: Some(999),
        process: Some("curl".to_string()),
        inode: 123,
    }];

    let results = scan_ports_for_host(
        Ipv4Addr::LOCALHOST,
        &[http_port, closed_port],
        600,
        true,
        &fake_outbound,
        true,
    )
    .await;

    let open_res = results.iter().find(|p| p.port == http_port).unwrap();
    assert_eq!(open_res.state, PortState::Open);
    assert!(open_res
        .banner
        .as_deref()
        .unwrap_or("")
        .contains("SimpleHTTP/0.6"));

    let closed_res = results.iter().find(|p| p.port == closed_port).unwrap();
    assert_eq!(closed_res.state, PortState::Closed);
}
