//! Données statiques simulées du mode démo : interfaces, sockets, timeline et constructeurs d'hôtes/ports.

use super::*;

/// Simulated interfaces (`enp6s18`, `docker0`, `tailscale0`, ...).
pub(super) fn demo_interfaces() -> Vec<NetworkInterface> {
    vec![
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
    ]
}

/// Simulated local listening/connected sockets.
pub(super) fn demo_local_sockets() -> Vec<LocalSocket> {
    vec![
        LocalSocket {
            proto: "TCP".to_string(),
            local_addr: "192.168.1.12:22".to_string(),
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
            local_port: 6379,
            remote_addr: "0.0.0.0:0".to_string(),
            remote_ip_v4: None,
            remote_port: 0,
            state: SocketState::Listen,
            pid: Some(1911),
            process: Some("redis-server".to_string()),
            inode: 42304,
        },
    ]
}

/// Simulated initial Watch Mode timeline.
pub(super) fn demo_timeline() -> Vec<TimelineEvent> {
    vec![
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
    ]
}

#[allow(clippy::too_many_arguments)]
pub(super) fn demo_host(
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

pub(super) fn p_open(
    port: u16,
    service: &str,
    desc: &str,
    banner: Option<&str>,
    lat: f64,
) -> PortInfo {
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
pub(super) fn p_inuse(
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

pub(super) fn p_closed(port: u16, service: &str, desc: &str, lat: f64) -> PortInfo {
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

pub(super) fn p_filtered(port: u16, service: &str, desc: &str) -> PortInfo {
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
