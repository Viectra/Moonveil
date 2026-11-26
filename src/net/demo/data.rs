//! Static demo interfaces, local sockets, timeline events, and builder helpers.

use std::net::Ipv4Addr;

use crate::net::model::{
    format_oui, service_info, ArpState, DeviceRole, EventKind, Host, LocalSocket, NetworkInterface,
    PortInfo, PortState, Proto, SocketState, TimelineEvent,
};
use crate::net::oui::lookup_vendor;

pub(super) fn build_demo_interfaces() -> Vec<NetworkInterface> {
    vec![
        NetworkInterface {
            name: "enp6s18".to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 12),
            prefix_len: 24,
            cidr: "192.168.1.0/24".to_string(),
            mac: Some([0xBC, 0x24, 0x11, 0xA4, 0x18, 0xB4]),
            is_up: true,
            is_loopback: false,
            is_virtual: false,
            is_wireless: false,
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(1, 1, 1, 1)],
            rx_bytes: 1_840_220_100,
            tx_bytes: 612_409_880,
            rx_bps: 148_200.0,
            tx_bps: 41_900.0,
            rx_history: vec![
                62_000.0, 88_000.0, 120_000.0, 95_000.0, 148_200.0, 132_000.0, 110_000.0,
                164_000.0, 141_000.0, 150_000.0,
            ],
            tx_history: vec![
                18_000.0, 22_000.0, 41_000.0, 35_000.0, 41_900.0, 29_000.0, 31_500.0, 44_000.0,
                38_000.0, 40_200.0,
            ],
        },
        NetworkInterface {
            name: "docker0".to_string(),
            ip: Ipv4Addr::new(172, 17, 0, 1),
            prefix_len: 16,
            cidr: "172.17.0.0/16".to_string(),
            mac: Some([0x02, 0x42, 0x3A, 0x91, 0x12, 0x01]),
            is_up: true,
            is_loopback: false,
            is_virtual: true,
            is_wireless: false,
            gateway: None,
            dns_servers: vec![Ipv4Addr::new(127, 0, 0, 11)],
            rx_bytes: 94_120_000,
            tx_bytes: 88_401_000,
            rx_bps: 24_100.0,
            tx_bps: 19_500.0,
            rx_history: vec![12_000.0, 18_000.0, 21_000.0, 16_000.0, 24_100.0],
            tx_history: vec![9_000.0, 14_000.0, 18_000.0, 15_000.0, 19_500.0],
        },
        NetworkInterface {
            name: "tailscale0".to_string(),
            ip: Ipv4Addr::new(100, 65, 1, 0),
            prefix_len: 32,
            cidr: "100.65.1.0/32".to_string(),
            mac: None,
            is_up: true,
            is_loopback: false,
            is_virtual: true,
            is_wireless: false,
            gateway: None,
            dns_servers: vec![Ipv4Addr::new(100, 100, 100, 100)],
            rx_bytes: 42_100_400,
            tx_bytes: 185_210_900,
            rx_bps: 11_400.0,
            tx_bps: 64_800.0,
            rx_history: vec![8_000.0, 10_000.0, 12_000.0, 9_500.0, 11_400.0],
            tx_history: vec![42_000.0, 58_000.0, 61_000.0, 55_000.0, 64_800.0],
        },
    ]
}

pub(super) fn build_demo_sockets() -> Vec<LocalSocket> {
    vec![
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "192.168.1.12:22".to_string(),
            local_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 12)),
            local_port: 22,
            remote_addr: "192.168.1.30:51842".to_string(),
            remote_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 30)),
            remote_port: 51842,
            state: SocketState::Established,
            pid: Some(1842),
            process: Some("sshd".to_string()),
            inode: 41001,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "100.65.1.0:8765".to_string(),
            local_ip_v4: Some(Ipv4Addr::new(100, 65, 1, 0)),
            local_port: 8765,
            remote_addr: "0.0.0.0:0".to_string(),
            remote_ip_v4: Some(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
            state: SocketState::Listen,
            pid: Some(4120),
            process: Some("python3".to_string()),
            inode: 41002,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "0.0.0.0:80".to_string(),
            local_ip_v4: Some(Ipv4Addr::UNSPECIFIED),
            local_port: 80,
            remote_addr: "0.0.0.0:0".to_string(),
            remote_ip_v4: Some(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
            state: SocketState::Listen,
            pid: Some(980),
            process: Some("nginx".to_string()),
            inode: 41003,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "192.168.1.12:51004".to_string(),
            local_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 12)),
            local_port: 51004,
            remote_addr: "192.168.1.10:53".to_string(),
            remote_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 10)),
            remote_port: 53,
            state: SocketState::Established,
            pid: Some(554),
            process: Some("systemd-resolve".to_string()),
            inode: 41004,
        },
    ]
}

pub(super) fn build_demo_events() -> Vec<TimelineEvent> {
    vec![
        TimelineEvent {
            timestamp: "18:42:05".to_string(),
            kind: EventKind::ScanFinished,
            ip: None,
            summary: "Scanned 192.168.1.0/24 in 843 ms (12 hosts, 28 active ports)".to_string(),
        },
        TimelineEvent {
            timestamp: "18:41:59".to_string(),
            kind: EventKind::HostDiscovered,
            ip: Some(Ipv4Addr::new(192, 168, 1, 67)),
            summary: "Smart Plug ESP32 responded on 192.168.1.67".to_string(),
        },
    ]
}

#[allow(clippy::too_many_arguments)]
pub(super) fn make_port(
    port: u16,
    state: PortState,
    banner: Option<&str>,
    proc_name: Option<&str>,
    pid: Option<u32>,
    peer: Option<&str>,
    latency_ms: f64,
) -> PortInfo {
    let (svc, desc) = service_info(port);
    PortInfo {
        port,
        proto: Proto::Tcp,
        state,
        service: svc.to_string(),
        description: desc.to_string(),
        banner: banner.map(ToString::to_string),
        banner_hex: None,
        latency_ms: Some(latency_ms),
        process: proc_name.map(ToString::to_string),
        pid,
        peer_endpoint: peer.map(ToString::to_string),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn make_host(
    ip: Ipv4Addr,
    hostname: Option<&str>,
    nickname: Option<&str>,
    mac: Option<[u8; 6]>,
    role: DeviceRole,
    trusted: bool,
    online: bool,
    os_guess: &str,
    rtt: Option<f64>,
    ports: Vec<PortInfo>,
    subnet_cidr: &str,
    interface: &str,
) -> Host {
    let (vendor, is_rand) = mac.map(lookup_vendor).unwrap_or((None, false));
    let oui_prefix = mac.map(format_oui);
    let rtt_history = rtt
        .map(|r| vec![(r * 0.92).max(0.1), r, (r * 1.08).max(0.1), r])
        .unwrap_or_default();

    Host {
        ip,
        ipv6: None,
        hostname: hostname.map(ToString::to_string),
        nickname: nickname.map(ToString::to_string),
        mac,
        oui_prefix,
        vendor,
        is_randomized_mac: is_rand,
        online,
        trusted,
        role,
        arp_state: if online {
            ArpState::Reachable
        } else {
            ArpState::Stale
        },
        ttl: Some(if os_guess.contains("Windows") {
            128
        } else {
            64
        }),
        os_guess: Some(os_guess.to_string()),
        rtt_ms: rtt,
        rtt_history,
        jitter_ms: Some(0.15),
        packet_loss_pct: if online { 0.0 } else { 100.0 },
        ports,
        first_seen_epoch: 1_795_690_000,
        last_seen_epoch: 1_795_700_000,
        discovered_tick: 1,
        subnet_cidr: subnet_cidr.to_string(),
        interface: interface.to_string(),
        is_new: false,
    }
}
