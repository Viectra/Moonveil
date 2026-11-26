//! Deterministic, animated simulated network dataset for `--demo` mode and headless tests.

use std::net::Ipv4Addr;

use crate::net::model::{
    format_oui, ArpState, DeviceRole, EventKind, Host, LocalSocket, NetworkInterface,
    NetworkSnapshot, PortInfo, PortState, PrivilegeLevel, Proto, SocketState, TimelineEvent,
    TracerouteHop,
};

/// Builds a rich simulated network snapshot (`enp6s18`, `docker0`, `tailscale0`, 14 hosts, sockets).
pub fn build_demo_snapshot() -> (NetworkSnapshot, Vec<TimelineEvent>) {
    let interfaces = vec![
        NetworkInterface {
            name: "enp6s18".to_string(),
            is_up: true,
            is_loopback: false,
            is_virtual: false,
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 12)),
            prefix_len: 24,
            cidr: "192.168.1.0/24".to_string(),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            broadcast: Some(Ipv4Addr::new(192, 168, 1, 255)),
            ipv6_list: vec![
                "2a01:e0a:11ab:8f30::12".to_string(),
                "fe80::be24:11ff:fea4:18b4".to_string(),
            ],
            mac: Some([0xBC, 0x24, 0x11, 0xA4, 0x18, 0xB4]),
            vendor: Some("Proxmox / QEMU".to_string()),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec!["192.168.1.10".to_string(), "1.1.1.1".to_string()],
            mtu: 1500,
            speed_mbps: Some(2500),
            rx_bytes: 18_420_910_204,
            tx_bytes: 6_192_440_812,
            rx_rate_bps: 4_850_000.0,
            tx_rate_bps: 1_240_000.0,
            rx_history: vec![
                1_200_000.0,
                2_400_000.0,
                3_100_000.0,
                2_800_000.0,
                5_100_000.0,
                4_200_000.0,
                3_900_000.0,
                4_850_000.0,
            ],
            tx_history: vec![
                420_000.0,
                880_000.0,
                910_000.0,
                1_100_000.0,
                1_550_000.0,
                1_050_000.0,
                980_000.0,
                1_240_000.0,
            ],
        },
        NetworkInterface {
            name: "docker0".to_string(),
            is_up: true,
            is_loopback: false,
            is_virtual: false,
            ipv4: Some(Ipv4Addr::new(172, 17, 0, 1)),
            prefix_len: 16,
            cidr: "172.17.0.0/16".to_string(),
            netmask: Some(Ipv4Addr::new(255, 255, 0, 0)),
            broadcast: Some(Ipv4Addr::new(172, 17, 255, 255)),
            ipv6_list: vec!["fe80::42:acff:fe11:1".to_string()],
            mac: Some([0x02, 0x42, 0xAC, 0x11, 0x00, 0x01]),
            vendor: Some("Docker Container".to_string()),
            gateway: None,
            dns_servers: vec!["127.0.0.11".to_string()],
            mtu: 1500,
            speed_mbps: None,
            rx_bytes: 942_120_110,
            tx_bytes: 618_221_992,
            rx_rate_bps: 145_000.0,
            tx_rate_bps: 98_000.0,
            rx_history: vec![90_000.0, 120_000.0, 180_000.0, 145_000.0],
            tx_history: vec![60_000.0, 82_000.0, 110_000.0, 98_000.0],
        },
        NetworkInterface {
            name: "tailscale0".to_string(),
            is_up: true,
            is_loopback: false,
            is_virtual: false,
            ipv4: Some(Ipv4Addr::new(100, 65, 1, 0)),
            prefix_len: 32,
            cidr: "100.65.1.0/32".to_string(),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 255)),
            broadcast: None,
            ipv6_list: vec!["fd7a:115c:a1e0::2f35:9c40".to_string()],
            mac: None,
            vendor: Some("WireGuard / Tailscale".to_string()),
            gateway: None,
            dns_servers: vec!["100.100.100.100".to_string()],
            mtu: 1280,
            speed_mbps: None,
            rx_bytes: 312_004_120,
            tx_bytes: 184_992_100,
            rx_rate_bps: 42_000.0,
            tx_rate_bps: 28_000.0,
            rx_history: vec![20_000.0, 35_000.0, 48_000.0, 42_000.0],
            tx_history: vec![12_000.0, 22_000.0, 31_000.0, 28_000.0],
        },
    ];

    let hosts = vec![
        demo_host(
            [192, 168, 1, 1],
            Some("gateway.lan"),
            Some("Main Router"),
            [0xF0, 0x9F, 0xC2, 0x41, 0x88, 0x01],
            "Ubiquiti",
            false,
            true,
            true,
            DeviceRole::Gateway,
            ArpState::Reachable,
            Some(64),
            "Linux / EdgeOS",
            Some(0.62),
            vec![
                p_open(
                    53,
                    "dns",
                    "Domain Name System resolver",
                    Some("dnsmasq-2.90"),
                    0.58,
                ),
                p_open(
                    80,
                    "http",
                    "Unencrypted web server",
                    Some("HTTP 301 • nginx -> HTTPS"),
                    0.64,
                ),
                p_open(
                    443,
                    "https",
                    "Encrypted HTTPS web server",
                    Some("TLS 1.3 • cert:unifi.lan"),
                    0.89,
                ),
                p_inuse(
                    22,
                    "ssh",
                    "Secure Shell remote login",
                    Some("SSH-2.0-OpenSSH_9.3"),
                    0.72,
                    "ssh",
                    4218,
                    "192.168.1.12:51422",
                ),
                p_closed(21, "ftp", "File Transfer Protocol", 0.55),
                p_closed(23, "telnet", "Unencrypted legacy terminal", 0.54),
                p_filtered(3389, "rdp", "Windows Remote Desktop"),
            ],
        ),
        demo_host(
            [192, 168, 1, 10],
            Some("pihole.lan"),
            Some("DNS Sinkhole"),
            [0xDC, 0xA6, 0x32, 0x7E, 0x19, 0x04],
            "Raspberry Pi",
            false,
            true,
            true,
            DeviceRole::Server,
            ArpState::Reachable,
            Some(64),
            "Linux (Raspberry Pi OS)",
            Some(1.12),
            vec![
                p_inuse(
                    53,
                    "dns",
                    "Domain Name System resolver",
                    Some("FTL-DNS v5.25"),
                    0.91,
                    "dns-resolver",
                    892,
                    "192.168.1.12:41882",
                ),
                p_open(
                    80,
                    "http",
                    "Unencrypted web server",
                    Some("HTTP 200 OK • lighttpd • \"Pi-hole Admin\""),
                    1.24,
                ),
                p_open(
                    22,
                    "ssh",
                    "Secure Shell remote login",
                    Some("SSH-2.0-OpenSSH_9.2p1 Debian"),
                    1.05,
                ),
                p_closed(443, "https", "Encrypted HTTPS web server", 0.99),
                p_closed(445, "smb", "Windows / Samba file sharing", 0.97),
            ],
        ),
        demo_host(
            [192, 168, 1, 12],
            Some("babylone"),
            Some("This Workstation"),
            [0xBC, 0x24, 0x11, 0xA4, 0x18, 0xB4],
            "Proxmox / QEMU",
            false,
            true,
            true,
            DeviceRole::ThisMachine,
            ArpState::Local,
            Some(64),
            "Linux (Ubuntu 24.04)",
            Some(0.05),
            vec![
                p_inuse(
                    22,
                    "ssh",
                    "Secure Shell remote login",
                    Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu"),
                    0.04,
                    "sshd",
                    1142,
                    "192.168.1.42:58104",
                ),
                p_inuse(
                    3000,
                    "dev-web",
                    "Frontend / Node dev server",
                    Some("HTTP 200 OK • \"Hub Workbench\""),
                    0.06,
                    "hub",
                    9410,
                    "192.168.1.42:59210",
                ),
                p_open(
                    5432,
                    "postgres",
                    "PostgreSQL relational database",
                    Some("PostgreSQL wire v3"),
                    0.05,
                ),
                p_open(
                    6379,
                    "redis",
                    "In-memory key-value datastore",
                    Some("+PONG / Redis 7.2"),
                    0.05,
                ),
                p_closed(80, "http", "Unencrypted web server", 0.04),
                p_closed(3306, "mysql", "MySQL / MariaDB database", 0.04),
            ],
        ),
        demo_host(
            [192, 168, 1, 20],
            Some("proxmox.lan"),
            Some("Compute Node 01"),
            [0x00, 0x25, 0x90, 0xC1, 0x33, 0x7A],
            "Supermicro",
            false,
            true,
            true,
            DeviceRole::Server,
            ArpState::Reachable,
            Some(64),
            "Linux (Proxmox VE 8)",
            Some(0.41),
            vec![
                p_inuse(
                    8006,
                    "proxmox",
                    "Proxmox VE virtualization UI",
                    Some("TLS 1.3 • cert:proxmox.lan"),
                    0.55,
                    "firefox",
                    6120,
                    "192.168.1.12:48220",
                ),
                p_open(
                    22,
                    "ssh",
                    "Secure Shell remote login",
                    Some("SSH-2.0-OpenSSH_9.2p1"),
                    0.39,
                ),
                p_open(111, "rpcbind", "ONC RPC portmapper", None, 0.38),
                p_closed(80, "http", "Unencrypted web server", 0.35),
                p_closed(443, "https", "Encrypted HTTPS web server", 0.36),
            ],
        ),
        demo_host(
            [192, 168, 1, 30],
            Some("vault-nas.lan"),
            Some("Synology NAS"),
            [0x00, 0x11, 0x32, 0x8F, 0x44, 0xC2],
            "Synology",
            false,
            true,
            true,
            DeviceRole::Server,
            ArpState::Reachable,
            Some(64),
            "Linux (Synology DSM)",
            Some(0.84),
            vec![
                p_inuse(
                    445,
                    "smb",
                    "Windows / Samba file sharing",
                    Some("SMBv3.1.1 • DiskStation"),
                    0.78,
                    "gvfsd-smb",
                    2914,
                    "192.168.1.12:43910",
                ),
                p_open(
                    5000,
                    "upnp/api",
                    "Local API / Synology DSM / Flask",
                    Some("HTTP 302 • nginx • \"Synology DSM\""),
                    0.92,
                ),
                p_open(
                    5001,
                    "https-dsm",
                    "Synology Encrypted DSM",
                    Some("TLS 1.3 • cert:vault-nas.lan"),
                    1.05,
                ),
                p_open(2049, "nfs", "Network File System share", None, 0.80),
                p_open(
                    22,
                    "ssh",
                    "Secure Shell remote login",
                    Some("SSH-2.0-OpenSSH_8.9"),
                    0.85,
                ),
                p_closed(21, "ftp", "File Transfer Protocol", 0.74),
            ],
        ),
        demo_host(
            [192, 168, 1, 42],
            Some("viectra-mbp.local"),
            Some("MacBook Pro"),
            [0x88, 0x66, 0x5A, 0x10, 0x4E, 0x9D],
            "Apple",
            false,
            true,
            true,
            DeviceRole::Workstation,
            ArpState::Reachable,
            Some(64),
            "macOS Sequoia",
            Some(2.85),
            vec![
                p_open(
                    22,
                    "ssh",
                    "Secure Shell remote login",
                    Some("SSH-2.0-OpenSSH_9.8"),
                    2.91,
                ),
                p_open(548, "afp", "Apple Filing Protocol share", None, 2.75),
                p_filtered(445, "smb", "Windows / Samba file sharing"),
                p_closed(80, "http", "Unencrypted web server", 2.61),
            ],
        ),
        demo_host(
            [192, 168, 1, 55],
            Some("win-rig.lan"),
            Some("Gaming PC"),
            [0x9C, 0xB6, 0xD0, 0x99, 0x0A, 0x12],
            "Rivet Networks",
            false,
            true,
            true,
            DeviceRole::Workstation,
            ArpState::Stale,
            Some(128),
            "Windows 11",
            Some(1.42),
            vec![
                p_open(
                    3389,
                    "rdp",
                    "Windows Remote Desktop",
                    Some("CredSSP / NLA RDP"),
                    1.58,
                ),
                p_open(445, "smb", "Windows / Samba file sharing", None, 1.39),
                p_open(135, "msrpc", "Windows RPC endpoint mapper", None, 1.40),
                p_open(5357, "wsd", "Windows Web Services Discovery", None, 1.44),
                p_filtered(22, "ssh", "Secure Shell remote login"),
                p_closed(80, "http", "Unencrypted web server", 1.31),
            ],
        ),
        demo_host(
            [192, 168, 1, 78],
            Some("iphone-viectra.local"),
            None,
            [0x76, 0xA1, 0x4C, 0x22, 0x90, 0xE3],
            "Private / Randomized MAC",
            true,
            true,
            false,
            DeviceRole::Mobile,
            ArpState::Reachable,
            Some(64),
            "iOS / Mobile",
            Some(9.40),
            vec![
                p_open(
                    62078,
                    "iphone-sync",
                    "Apple mobile wireless sync",
                    None,
                    9.52,
                ),
                p_filtered(22, "ssh", "Secure Shell remote login"),
                p_filtered(80, "http", "Unencrypted web server"),
            ],
        ),
        demo_host(
            [192, 168, 1, 91],
            Some("esp32-weather.local"),
            Some("Studio Sensor"),
            [0x24, 0x0A, 0xC4, 0xD2, 0x14, 0x07],
            "Espressif IoT",
            false,
            true,
            true,
            DeviceRole::IoT,
            ArpState::Reachable,
            Some(64),
            "FreeRTOS / lwIP",
            Some(6.15),
            vec![
                p_open(
                    80,
                    "http",
                    "Unencrypted web server",
                    Some("HTTP 200 OK • \"ESPHome Sensor\""),
                    6.42,
                ),
                p_open(1883, "mqtt", "IoT telemetry message broker", None, 6.20),
                p_closed(22, "ssh", "Secure Shell remote login", 5.95),
            ],
        ),
        demo_host(
            [192, 168, 1, 114],
            Some("media-jellyfin.lan"),
            Some("Media Box"),
            [0x48, 0x2C, 0xA0, 0x55, 0x7E, 0x10],
            "Xiaomi",
            false,
            true,
            true,
            DeviceRole::Server,
            ArpState::Reachable,
            Some(64),
            "Linux",
            Some(1.88),
            vec![
                p_open(
                    8096,
                    "jellyfin",
                    "Media streaming server",
                    Some("HTTP 200 OK • Kestrel • \"Jellyfin\""),
                    2.11,
                ),
                p_open(
                    22,
                    "ssh",
                    "Secure Shell remote login",
                    Some("SSH-2.0-OpenSSH_9.1"),
                    1.85,
                ),
                p_closed(80, "http", "Unencrypted web server", 1.79),
            ],
        ),
        demo_host(
            [192, 168, 1, 136],
            Some("unknown-guest.lan"),
            None,
            [0x14, 0xCC, 0x20, 0xA9, 0x31, 0xFF],
            "TP-Link",
            false,
            true,
            false,
            DeviceRole::Host,
            ArpState::Delay,
            Some(64),
            "Linux / Embedded",
            Some(14.70),
            vec![
                p_open(
                    80,
                    "http",
                    "Unencrypted web server",
                    Some("HTTP 200 OK • \"Smart Plug\""),
                    14.9,
                ),
                p_closed(443, "https", "Encrypted HTTPS web server", 14.2),
            ],
        ),
        demo_host(
            [192, 168, 1, 160],
            Some("laser-printer.lan"),
            Some("Office Printer"),
            [0x40, 0xB0, 0x34, 0x71, 0x20, 0xB8],
            "HP",
            false,
            true,
            true,
            DeviceRole::IoT,
            ArpState::Stale,
            Some(255),
            "Network Appliance / Embedded",
            Some(4.21),
            vec![
                p_open(
                    631,
                    "ipp",
                    "Network printing (CUPS)",
                    Some("HTTP 200 OK • IPP/2.0"),
                    4.30,
                ),
                p_open(9100, "jetdirect", "Raw network printer port", None, 4.18),
                p_open(
                    80,
                    "http",
                    "Unencrypted web server",
                    Some("HTTP 200 OK • \"HP LaserJet\""),
                    4.25,
                ),
                p_closed(22, "ssh", "Secure Shell remote login", 4.11),
            ],
        ),
        demo_host(
            [192, 168, 1, 200],
            Some("render-node.lan"),
            Some("Render Rig (Sleep)"),
            [0x70, 0x85, 0xC2, 0x19, 0x8B, 0x44],
            "ASRock",
            false,
            false,
            true,
            DeviceRole::Workstation,
            ArpState::Unknown,
            Some(64),
            "Linux",
            None,
            vec![],
        ),
        demo_host(
            [172, 17, 0, 2],
            Some("grafana.docker"),
            Some("Grafana Container"),
            [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02],
            "Docker Container",
            false,
            true,
            true,
            DeviceRole::Container,
            ArpState::Reachable,
            Some(64),
            "Linux Container",
            Some(0.14),
            vec![
                p_inuse(
                    3000,
                    "dev-web",
                    "Frontend / Node dev server",
                    Some("HTTP 200 OK • \"Grafana\""),
                    0.16,
                    "docker-proxy",
                    3412,
                    "172.17.0.1:49812",
                ),
                p_closed(22, "ssh", "Secure Shell remote login", 0.12),
            ],
        ),
    ];

    let local_sockets = vec![
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "192.168.1.12:22".to_string(),
            local_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 12)),
            local_port: 22,
            remote_addr: "192.168.1.42:58104".to_string(),
            remote_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 42)),
            remote_port: 58104,
            state: SocketState::Established,
            pid: Some(1142),
            process: Some("sshd".to_string()),
            inode: 41201,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "192.168.1.12:51422".to_string(),
            local_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 12)),
            local_port: 51422,
            remote_addr: "192.168.1.1:22".to_string(),
            remote_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 1)),
            remote_port: 22,
            state: SocketState::Established,
            pid: Some(4218),
            process: Some("ssh".to_string()),
            inode: 41299,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "192.168.1.12:48220".to_string(),
            local_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 12)),
            local_port: 48220,
            remote_addr: "192.168.1.20:8006".to_string(),
            remote_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 20)),
            remote_port: 8006,
            state: SocketState::Established,
            pid: Some(6120),
            process: Some("firefox".to_string()),
            inode: 41488,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "192.168.1.12:43910".to_string(),
            local_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 12)),
            local_port: 43910,
            remote_addr: "192.168.1.30:445".to_string(),
            remote_ip_v4: Some(Ipv4Addr::new(192, 168, 1, 30)),
            remote_port: 445,
            state: SocketState::Established,
            pid: Some(2914),
            process: Some("gvfsd-smb".to_string()),
            inode: 41512,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "0.0.0.0:3000".to_string(),
            local_ip_v4: None,
            local_port: 3000,
            remote_addr: "0.0.0.0:0".to_string(),
            remote_ip_v4: None,
            remote_port: 0,
            state: SocketState::Listen,
            pid: Some(9410),
            process: Some("hub".to_string()),
            inode: 42100,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "127.0.0.1:5432".to_string(),
            local_ip_v4: Some(Ipv4Addr::LOCALHOST),
            local_port: 5432,
            remote_addr: "0.0.0.0:0".to_string(),
            remote_ip_v4: None,
            remote_port: 0,
            state: SocketState::Listen,
            pid: Some(1820),
            process: Some("postgres".to_string()),
            inode: 42211,
        },
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "127.0.0.1:6379".to_string(),
            local_ip_v4: Some(Ipv4Addr::LOCALHOST),
            local_port: 6379,
            remote_addr: "0.0.0.0:0".to_string(),
            remote_ip_v4: None,
            remote_port: 0,
            state: SocketState::Listen,
            pid: Some(1911),
            process: Some("redis-server".to_string()),
            inode: 42304,
        },
    ];

    let timeline = vec![
        TimelineEvent {
            timestamp: "10:42:08".to_string(),
            kind: EventKind::ScanFinished,
            ip: None,
            summary:
                "Completed Quick sweep on 192.168.1.0/24 — 12 online, 28 active/open ports (1.4s)"
                    .to_string(),
        },
        TimelineEvent {
            timestamp: "10:42:19".to_string(),
            kind: EventKind::UnknownIntruder,
            ip: Some(Ipv4Addr::new(192, 168, 1, 136)),
            summary: "Untrusted host 192.168.1.136 (TP-Link) appeared on enp6s18".to_string(),
        },
        TimelineEvent {
            timestamp: "10:42:34".to_string(),
            kind: EventKind::ActiveSession,
            ip: Some(Ipv4Addr::new(192, 168, 1, 30)),
            summary: "Active SMB session 445/tcp <-> gvfsd-smb (pid 2914)".to_string(),
        },
        TimelineEvent {
            timestamp: "10:43:02".to_string(),
            kind: EventKind::HostJoined,
            ip: Some(Ipv4Addr::new(192, 168, 1, 78)),
            summary: "iphone-viectra.local joined with randomized MAC 76:A1:4C:22:90:E3"
                .to_string(),
        },
    ];

    let snapshot = NetworkSnapshot {
        hostname: "babylone".to_string(),
        username: "viectra".to_string(),
        privilege: PrivilegeLevel::IcmpDatagram,
        interfaces,
        local_sockets,
        hosts,
    };

    (snapshot, timeline)
}

/// Generates realistic demo traceroute hops to `target`.
pub fn demo_traceroute(target: Ipv4Addr) -> Vec<TracerouteHop> {
    vec![
        TracerouteHop {
            ttl: 1,
            ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            hostname: Some("gateway.lan".to_string()),
            rtt_ms: Some(0.64),
        },
        TracerouteHop {
            ttl: 2,
            ip: Some(target),
            hostname: None,
            rtt_ms: Some(1.48),
        },
    ]
}

/// Gently perturbs live demo RTT & throughput metrics each animation step.
pub fn tick_demo_snapshot(snapshot: &mut NetworkSnapshot, tick: u64) {
    let wave = (tick as f64 * 0.25).sin();
    for (idx, iface) in snapshot.interfaces.iter_mut().enumerate() {
        let base_rx = if idx == 0 { 4_400_000.0 } else { 140_000.0 };
        let base_tx = if idx == 0 { 1_100_000.0 } else { 85_000.0 };
        let rx = (base_rx + (wave + (idx as f64) * 0.5).sin().abs() * base_rx * 0.45).max(12_000.0);
        let tx = (base_tx + (wave * 1.3 + idx as f64).cos().abs() * base_tx * 0.40).max(8_000.0);
        iface.rx_rate_bps = rx;
        iface.tx_rate_bps = tx;
        iface.rx_history.push(rx);
        iface.tx_history.push(tx);
        if iface.rx_history.len() > 48 {
            iface.rx_history.remove(0);
        }
        if iface.tx_history.len() > 48 {
            iface.tx_history.remove(0);
        }
    }
    for (idx, host) in snapshot.hosts.iter_mut().enumerate() {
        if !host.online || host.role == DeviceRole::ThisMachine {
            continue;
        }
        if let Some(base) = host.rtt_history.first().copied().or(host.rtt_ms) {
            let jitter = ((tick as f64 * 0.4 + idx as f64 * 1.1).sin() * 0.18 + 1.0).max(0.5);
            let sample = (base * jitter).max(0.12);
            host.rtt_ms = Some(sample);
            host.rtt_history.push(sample);
            if host.rtt_history.len() > 32 {
                host.rtt_history.remove(0);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn demo_host(
    octets: [u8; 4],
    hostname: Option<&str>,
    nickname: Option<&str>,
    mac: [u8; 6],
    vendor: &str,
    randomized: bool,
    online: bool,
    trusted: bool,
    role: DeviceRole,
    arp_state: ArpState,
    ttl: Option<u8>,
    os_guess: &str,
    rtt_ms: Option<f64>,
    ports: Vec<PortInfo>,
) -> Host {
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    let subnet_cidr = if octets[0] == 172 {
        "172.17.0.0/16"
    } else {
        "192.168.1.0/24"
    };
    let iface = if octets[0] == 172 {
        "docker0"
    } else {
        "enp6s18"
    };
    let rtt_history = match rtt_ms {
        Some(r) => vec![r * 0.94, r * 1.08, r * 0.98, r * 1.14, r * 0.92, r],
        None => Vec::new(),
    };
    Host {
        ip,
        ipv6: if online {
            Some(format!(
                "fe80::{:02x}{:02x}:ff:fe{:02x}:{:02x}{:02x}",
                mac[0] ^ 2,
                mac[1],
                mac[3],
                mac[4],
                mac[5]
            ))
        } else {
            None
        },
        hostname: hostname.map(str::to_string),
        nickname: nickname.map(str::to_string),
        mac: Some(mac),
        oui_prefix: Some(format_oui(mac)),
        vendor: Some(vendor.to_string()),
        is_randomized_mac: randomized,
        online,
        trusted,
        role,
        arp_state,
        ttl,
        os_guess: Some(os_guess.to_string()),
        rtt_ms,
        rtt_history,
        jitter_ms: rtt_ms.map(|r| (r * 0.09).max(0.02)),
        packet_loss_pct: 0.0,
        ports,
        first_seen_epoch: 1_764_150_000,
        last_seen_epoch: 1_764_150_600,
        discovered_tick: 0,
        subnet_cidr: subnet_cidr.to_string(),
        interface: iface.to_string(),
        is_new: !trusted && online,
    }
}

fn p_open(port: u16, service: &str, desc: &str, banner: Option<&str>, lat: f64) -> PortInfo {
    PortInfo {
        port,
        proto: Proto::Tcp,
        state: PortState::Open,
        service: service.to_string(),
        description: desc.to_string(),
        banner: banner.map(str::to_string),
        banner_hex: banner.map(|b| {
            b.as_bytes()
                .iter()
                .take(16)
                .map(|x| format!("{x:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        }),
        latency_ms: Some(lat),
        process: None,
        pid: None,
        peer_endpoint: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn p_inuse(
    port: u16,
    service: &str,
    desc: &str,
    banner: Option<&str>,
    lat: f64,
    proc_name: &str,
    pid: u32,
    peer: &str,
) -> PortInfo {
    let mut info = p_open(port, service, desc, banner, lat);
    info.state = PortState::InUse;
    info.process = Some(proc_name.to_string());
    info.pid = Some(pid);
    info.peer_endpoint = Some(peer.to_string());
    info
}

fn p_closed(port: u16, service: &str, desc: &str, lat: f64) -> PortInfo {
    PortInfo {
        port,
        proto: Proto::Tcp,
        state: PortState::Closed,
        service: service.to_string(),
        description: desc.to_string(),
        banner: None,
        banner_hex: None,
        latency_ms: Some(lat),
        process: None,
        pid: None,
        peer_endpoint: None,
    }
}

fn p_filtered(port: u16, service: &str, desc: &str) -> PortInfo {
    PortInfo {
        port,
        proto: Proto::Tcp,
        state: PortState::Filtered,
        service: service.to_string(),
        description: desc.to_string(),
        banner: None,
        banner_hex: None,
        latency_ms: None,
        process: None,
        pid: None,
        peer_endpoint: None,
    }
}
