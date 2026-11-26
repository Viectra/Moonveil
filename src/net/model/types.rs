//! Types de données réseau : ports, rôles, interfaces, sockets, timeline, progression et instantané global.

use super::*;

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

impl Proto {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// Distinct port state classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

    pub const fn short(self) -> &'static str {
        match self {
            Self::InUse => "Use",
            Self::Open => "Open",
            Self::Filtered => "Filt",
            Self::Closed => "Closed",
        }
    }
}

/// Port filter tabs in the Host Inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortFilter {
    #[default]
    All,
    InUse,
    Open,
    Closed,
    Filtered,
}

impl PortFilter {
    pub const ALL: &'static [Self] = &[
        Self::All,
        Self::InUse,
        Self::Open,
        Self::Closed,
        Self::Filtered,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::InUse => "In Use",
            Self::Open => "Open",
            Self::Closed => "Closed",
            Self::Filtered => "Filtered",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        match self {
            Self::All => lang.t("All", "Tous"),
            Self::InUse => lang.t("In Use", "Utilisés"),
            Self::Open => lang.t("Open", "Ouverts"),
            Self::Closed => lang.t("Closed", "Fermés"),
            Self::Filtered => lang.t("Filtered", "Filtrés"),
        }
    }

    pub fn matches(self, state: PortState) -> bool {
        match self {
            Self::All => true,
            Self::InUse => state == PortState::InUse,
            Self::Open => state == PortState::Open,
            Self::Closed => state == PortState::Closed,
            Self::Filtered => state == PortState::Filtered,
        }
    }
}

/// Scanned port record for a host.
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

/// Inferred device category for icon & Normal Mode readability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeviceRole {
    ThisMachine,
    Gateway,
    Server,
    Workstation,
    Mobile,
    IoT,
    Container,
    #[default]
    Host,
}

impl DeviceRole {
    pub const fn icon(self) -> &'static str {
        match self {
            Self::ThisMachine => "◈",
            Self::Gateway => "▲",
            Self::Server => "■",
            Self::Workstation => "◆",
            Self::Mobile => "▪",
            Self::IoT => "•",
            Self::Container => "⊞",
            Self::Host => "●",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ThisMachine => "This PC",
            Self::Gateway => "Gateway",
            Self::Server => "Server",
            Self::Workstation => "Workstation",
            Self::Mobile => "Mobile",
            Self::IoT => "IoT / Edge",
            Self::Container => "Container",
            Self::Host => "Host",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        match lang {
            Language::En => self.label(),
            Language::Fr => match self {
                Self::ThisMachine => "Ce PC",
                Self::Gateway => "Passerelle",
                Self::Server => "Serveur",
                Self::Workstation => "Poste de travail",
                Self::Mobile => "Mobile",
                Self::IoT => "IoT / Edge",
                Self::Container => "Conteneur",
                Self::Host => "Hôte",
            },
        }
    }
}

/// Linux neighbor / ARP cache state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArpState {
    Reachable,
    Stale,
    Delay,
    Permanent,
    Probe,
    Local,
    #[default]
    Unknown,
}

impl ArpState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reachable => "REACHABLE",
            Self::Stale => "STALE",
            Self::Delay => "DELAY",
            Self::Permanent => "PERMANENT",
            Self::Probe => "PROBE",
            Self::Local => "LOCAL",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Scan capability level depending on process privilege / `CAP_NET_RAW`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrivilegeLevel {
    Raw,
    IcmpDatagram,
    #[default]
    User,
}

impl PrivilegeLevel {
    pub const fn badge(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::IcmpDatagram => "ICMP",
            Self::User => "USER",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Raw => "Raw sockets active (ICMP/ARP/SYN)",
            Self::IcmpDatagram => "Unprivileged ICMP + TCP/ARP discovery",
            Self::User => "User-space TCP/ARP/mDNS discovery",
        }
    }

    pub const fn description_for(self, lang: Language) -> &'static str {
        match lang {
            Language::En => self.description(),
            Language::Fr => match self {
                Self::Raw => "Sockets bruts actifs (ICMP/ARP/SYN)",
                Self::IcmpDatagram => "Découverte ICMP non privilégiée + TCP/ARP",
                Self::User => "Découverte TCP/ARP/mDNS en espace utilisateur",
            },
        }
    }
}

/// Host table sort criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostSortColumn {
    #[default]
    Ip,
    Name,
    Vendor,
    Rtt,
    OpenPorts,
    InUsePorts,
}

/// Linux network interface metadata and live counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_virtual: bool,
    pub ipv4: Option<Ipv4Addr>,
    pub prefix_len: u8,
    pub cidr: String,
    pub netmask: Option<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub ipv6_list: Vec<String>,
    pub mac: Option<[u8; 6]>,
    pub vendor: Option<String>,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<String>,
    pub mtu: u32,
    pub speed_mbps: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate_bps: f64,
    pub tx_rate_bps: f64,
    pub rx_history: Vec<f64>,
    pub tx_history: Vec<f64>,
}

/// TCP/UDP socket state from `/proc/net`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketState {
    Established,
    Listen,
    TimeWait,
    SynSent,
    CloseWait,
    Other,
}

impl SocketState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Established => "ESTABLISHED",
            Self::Listen => "LISTEN",
            Self::TimeWait => "TIME_WAIT",
            Self::SynSent => "SYN_SENT",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Other => "OTHER",
        }
    }
}

/// Local Linux socket mapped to its owning PID/process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSocket {
    pub proto: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_ip_v4: Option<Ipv4Addr>,
    pub remote_port: u16,
    pub state: SocketState,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub inode: u64,
}

/// One hop in a hop-by-hop traceroute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub ttl: u8,
    pub ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// Category for Watch Mode & Action timeline events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    HostJoined,
    HostLeft,
    UnknownIntruder,
    PortOpened,
    PortClosed,
    ActiveSession,
    ScanFinished,
    Action,
}

impl EventKind {
    pub const fn badge(self) -> &'static str {
        match self {
            Self::HostJoined => "JOIN",
            Self::HostLeft => "LEFT",
            Self::UnknownIntruder => "NEW!",
            Self::PortOpened => "PORT+",
            Self::PortClosed => "PORT-",
            Self::ActiveSession => "INUSE",
            Self::ScanFinished => "SCAN",
            Self::Action => "ACT",
        }
    }
}

/// Chronological event entry recorded by Watch Mode and scan diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub kind: EventKind,
    pub ip: Option<Ipv4Addr>,
    pub summary: String,
}

/// Live progress indicator for an active discovery or port scan.
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub active: bool,
    pub phase: String,
    pub probed: usize,
    pub total: usize,
    pub current_target: String,
    pub hosts_found: usize,
    pub ports_found: usize,
    pub last_duration_ms: Option<u64>,
}

impl ScanProgress {
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.probed as f64 / self.total as f64).clamp(0.0, 1.0)
        }
    }
}

/// Export file formats.
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

/// Complete live or demo network state serialized for exports or UI inspection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkSnapshot {
    pub hostname: String,
    pub username: String,
    pub privilege: PrivilegeLevel,
    pub interfaces: Vec<NetworkInterface>,
    pub local_sockets: Vec<LocalSocket>,
    pub hosts: Vec<Host>,
}
