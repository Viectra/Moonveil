//! Shared network domain structs and enums (`PortInfo`, `NetworkInterface`, `NetworkSnapshot`, etc.).

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::config::Language;

use super::Host;

/// Transport protocol for a scanned or active port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Observed state of a port (`InUse`, `Open`, `Filtered`, `Closed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PortState {
    InUse,
    Open,
    Filtered,
    Closed,
}

impl PortState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::InUse => "IN USE",
            Self::Open => "OPEN",
            Self::Filtered => "FILTERED",
            Self::Closed => "CLOSED",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.label();
        }
        match self {
            Self::InUse => "UTILISÉ",
            Self::Open => "OUVERT",
            Self::Filtered => "FILTRÉ",
            Self::Closed => "FERMÉ",
        }
    }

    pub const fn badge_icon(self) -> &'static str {
        match self {
            Self::InUse => "●",
            Self::Open => "●",
            Self::Filtered => "◐",
            Self::Closed => "○",
        }
    }

    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::InUse => 0,
            Self::Open => 1,
            Self::Filtered => 2,
            Self::Closed => 3,
        }
    }
}

/// Filter tabs inside the host inspector port table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortFilter {
    #[default]
    All,
    InUse,
    Open,
    Closed,
}

impl PortFilter {
    pub const ALL: &'static [Self] = &[Self::All, Self::InUse, Self::Open, Self::Closed];

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::InUse => "In Use",
            Self::Open => "Open",
            Self::Closed => "Closed",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.label();
        }
        match self {
            Self::All => "Tous",
            Self::InUse => "Utilisés",
            Self::Open => "Ouverts",
            Self::Closed => "Fermés",
        }
    }

    pub const fn matches(self, state: PortState) -> bool {
        match self {
            Self::All => true,
            Self::InUse => matches!(state, PortState::InUse),
            Self::Open => matches!(state, PortState::Open),
            Self::Closed => matches!(state, PortState::Closed | PortState::Filtered),
        }
    }
}

/// Rich information about a discovered or probed port on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub proto: Proto,
    pub state: PortState,
    pub service: String,
    pub description: String,
    pub banner: Option<String>,
    pub banner_hex: Option<String>,
    pub latency_ms: Option<f64>,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub peer_endpoint: Option<String>,
}

/// Inferred device category with clean monochrome ASCII/Unicode icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRole {
    Gateway,
    ThisMachine,
    Server,
    Workstation,
    Printer,
    IoT,
    Mobile,
    Container,
    Host,
}

impl DeviceRole {
    pub const fn icon(self) -> &'static str {
        match self {
            Self::Gateway => "◈",
            Self::ThisMachine => "✦",
            Self::Server => "▣",
            Self::Workstation => "□",
            Self::Printer => "⎙",
            Self::IoT => "◎",
            Self::Mobile => "▯",
            Self::Container => "◫",
            Self::Host => "▪",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Gateway => "Gateway",
            Self::ThisMachine => "This PC",
            Self::Server => "Server",
            Self::Workstation => "Workstation",
            Self::Printer => "Printer",
            Self::IoT => "IoT",
            Self::Mobile => "Mobile",
            Self::Container => "Container",
            Self::Host => "Host",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.label();
        }
        match self {
            Self::Gateway => "Passerelle",
            Self::ThisMachine => "Ce PC",
            Self::Server => "Serveur",
            Self::Workstation => "Poste",
            Self::Printer => "Imprimante",
            Self::IoT => "IoT",
            Self::Mobile => "Mobile",
            Self::Container => "Conteneur",
            Self::Host => "Hôte",
        }
    }
}

/// Linux ARP neighbor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpState {
    Reachable,
    Stale,
    Delay,
    Incomplete,
    Unknown,
}

impl ArpState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reachable => "REACHABLE",
            Self::Stale => "STALE",
            Self::Delay => "DELAY",
            Self::Incomplete => "INCOMPLETE",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.label();
        }
        match self {
            Self::Reachable => "JOIGNABLE",
            Self::Stale => "PÉRIMÉ",
            Self::Delay => "DÉLAI",
            Self::Incomplete => "INCOMPLET",
            Self::Unknown => "INCONNU",
        }
    }
}

/// Privilege capabilities detected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    Root,
    Capabilities,
    User,
}

impl PrivilegeLevel {
    pub const fn badge(self) -> &'static str {
        match self {
            Self::Root => "ROOT / RAW",
            Self::Capabilities => "CAP / ICMP",
            Self::User => "USER",
        }
    }

    pub const fn detail(self) -> &'static str {
        match self {
            Self::Root => "Full ICMP, /proc sockets, and ARP inspection active",
            Self::Capabilities => "CAP_NET_RAW active: ICMP ping + fast TCP connect",
            Self::User => "User-space TCP/ARP/mDNS discovery (run install.sh --caps for raw ICMP)",
        }
    }

    pub const fn detail_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.detail();
        }
        match self {
            Self::Root => "ICMP complet, sockets /proc et inspection ARP actifs",
            Self::Capabilities => "CAP_NET_RAW actif : ping ICMP + connexion TCP rapide",
            Self::User => "Découverte TCP/ARP/mDNS utilisateur (install.sh --caps pour ICMP brut)",
        }
    }
}

/// Local network interface with telemetry & throughput curves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub cidr: String,
    pub mac: Option<[u8; 6]>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_virtual: bool,
    pub is_wireless: bool,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_history: Vec<f64>,
    pub tx_history: Vec<f64>,
}

impl NetworkInterface {
    /// Returns the number of usable host addresses in this interface's subnet (capped for /16+).
    pub fn host_capacity(&self) -> u32 {
        let host_bits = 32_u32.saturating_sub(u32::from(self.prefix_len));
        if host_bits == 0 {
            1
        } else if host_bits >= 20 {
            65_534
        } else {
            (1_u32 << host_bits).saturating_sub(2).max(1)
        }
    }

    /// Number of `/24` pages when visualizing a larger subnet in Subnet Radar.
    pub fn slash24_page_count(&self) -> u32 {
        if self.prefix_len >= 24 {
            1
        } else {
            let pages = 1_u32 << (24 - u32::from(self.prefix_len)).min(8);
            pages.max(1)
        }
    }
}

/// Socket state parsed from Linux `/proc/net/{tcp,tcp6,udp,udp6}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketState {
    Listen,
    Established,
    SynSent,
    SynRecv,
    FinWait,
    TimeWait,
    CloseWait,
    Other,
}

impl SocketState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Listen => "LISTEN",
            Self::Established => "ESTAB",
            Self::SynSent => "SYN-SENT",
            Self::SynRecv => "SYN-RECV",
            Self::FinWait => "FIN-WAIT",
            Self::TimeWait => "TIME-WAIT",
            Self::CloseWait => "CLOSE-WAIT",
            Self::Other => "OTHER",
        }
    }
}

/// Active local socket with owning process correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSocket {
    pub proto: String,
    pub local_addr: String,
    pub local_ip_v4: Option<Ipv4Addr>,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_ip_v4: Option<Ipv4Addr>,
    pub remote_port: u16,
    pub state: SocketState,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub inode: u64,
}

/// Single traceroute hop result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub ttl: u8,
    pub ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// Watch Mode change timeline event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    HostDiscovered,
    HostOnline,
    HostOffline,
    UntrustedHost,
    PortOpened,
    PortClosed,
    ScanFinished,
}

/// Recorded event entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub kind: EventKind,
    pub ip: Option<Ipv4Addr>,
    pub summary: String,
}

/// Live progress tracker for an active network scan.
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub active: bool,
    pub probed: usize,
    pub total: usize,
    pub hosts_found: usize,
    pub ports_found: usize,
    pub current_target: String,
    pub started_at_tick: u64,
}

impl ScanProgress {
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            if self.active {
                0.05
            } else {
                0.0
            }
        } else {
            (self.probed as f64 / self.total as f64).clamp(0.0, 1.0)
        }
    }
}

/// Output serialization format for snapshot export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Markdown,
}

impl ExportFormat {
    pub const fn ext(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Markdown => "md",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Csv => "CSV",
            Self::Markdown => "Markdown",
        }
    }
}

/// Full telemetry state rendered across all Moonveil screens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub interfaces: Vec<NetworkInterface>,
    pub active_iface_idx: usize,
    pub hosts: Vec<Host>,
    pub local_sockets: Vec<LocalSocket>,
    pub events: Vec<TimelineEvent>,
    pub privilege: PrivilegeLevel,
    pub username: String,
    pub hostname: String,
    pub last_scan_epoch: Option<u64>,
    pub scan_duration_ms: Option<u64>,
    pub traceroute_target: Option<Ipv4Addr>,
    pub traceroute_hops: Vec<TracerouteHop>,
    pub ping_target: Option<Ipv4Addr>,
    pub ping_samples: Vec<f64>,
    pub ping_sent: usize,
    pub ping_received: usize,
    pub ping_last_rtt_ms: Option<f64>,
    pub ping_active: bool,
}
