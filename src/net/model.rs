//! Core network, host, port, socket, interface, and timeline data model.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Display & control density mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    #[default]
    Normal,
    Advanced,
}

impl ScanMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Advanced => "Advanced",
        }
    }

    pub const fn subtitle(self) -> &'static str {
        match self {
            Self::Normal => "Clean Radar",
            Self::Advanced => "Deep Recon",
        }
    }

    pub const fn toggle(self) -> Self {
        match self {
            Self::Normal => Self::Advanced,
            Self::Advanced => Self::Normal,
        }
    }
}

/// Port scan target preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanPreset {
    #[default]
    Quick,
    Standard,
    Full,
    WebDev,
    Custom,
}

impl ScanPreset {
    pub const ALL: &'static [Self] = &[
        Self::Quick,
        Self::Standard,
        Self::Full,
        Self::WebDev,
        Self::Custom,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Quick => "Quick (32)",
            Self::Standard => "Standard (100)",
            Self::Full => "Full (1000)",
            Self::WebDev => "Web & Dev",
            Self::Custom => "Custom",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Quick => "Quick",
            Self::Standard => "Top 100",
            Self::Full => "Top 1000",
            Self::WebDev => "Web/Dev",
            Self::Custom => "Custom",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Quick => Self::Standard,
            Self::Standard => Self::Full,
            Self::Full => Self::WebDev,
            Self::WebDev => Self::Custom,
            Self::Custom => Self::Quick,
        }
    }
}

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

/// Port filter tabs in the Device Inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortFilter {
    #[default]
    Open,
    InUse,
    Closed,
}

impl PortFilter {
    pub const ALL: &'static [Self] = &[Self::Open, Self::InUse, Self::Closed];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::InUse => "In Use",
            Self::Closed => "Closed",
        }
    }

    pub fn matches(self, state: PortState) -> bool {
        match self {
            Self::Open => matches!(state, PortState::InUse | PortState::Open),
            Self::InUse => state == PortState::InUse,
            Self::Closed => matches!(state, PortState::Closed | PortState::Filtered),
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
}

/// Discovered or saved network host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub ipv6: Option<String>,
    pub hostname: Option<String>,
    pub nickname: Option<String>,
    pub mac: Option<[u8; 6]>,
    pub oui_prefix: Option<String>,
    pub vendor: Option<String>,
    pub is_randomized_mac: bool,
    pub online: bool,
    pub trusted: bool,
    pub role: DeviceRole,
    pub arp_state: ArpState,
    pub ttl: Option<u8>,
    pub os_guess: Option<String>,
    pub rtt_ms: Option<f64>,
    pub rtt_history: Vec<f64>,
    pub jitter_ms: Option<f64>,
    pub packet_loss_pct: f64,
    pub ports: Vec<PortInfo>,
    pub first_seen_epoch: u64,
    pub last_seen_epoch: u64,
    pub discovered_tick: u64,
    pub subnet_cidr: String,
    pub interface: String,
    pub is_new: bool,
}

/// Sanitizes a discovered hostname by stripping local domain / DHCP noise and rejecting placeholders.
pub fn clean_discovered_hostname(raw: &str) -> Option<String> {
    let mut cleaned = raw.trim().trim_end_matches('.');
    if cleaned.is_empty() {
        return None;
    }

    let lower = cleaned.to_ascii_lowercase();
    if lower.ends_with(".ts.net") {
        if let Some((first, _)) = cleaned.split_once('.') {
            cleaned = first;
        }
    } else {
        for suffix in [
            ".home.arpa",
            ".localdomain",
            ".local",
            ".home",
            ".lan",
            ".internal",
        ] {
            if lower.ends_with(suffix) && cleaned.len() > suffix.len() {
                cleaned = &cleaned[..cleaned.len() - suffix.len()];
                break;
            }
        }
    }

    let mut had_repeated = false;
    while cleaned.to_ascii_lowercase().ends_with("-home-home") && cleaned.len() > 10 {
        had_repeated = true;
        cleaned = &cleaned[..cleaned.len() - 5];
    }
    if had_repeated && cleaned.to_ascii_lowercase().ends_with("-home") && cleaned.len() > 5 {
        cleaned = &cleaned[..cleaned.len() - 5];
    }

    cleaned = cleaned.trim().trim_end_matches('.');
    if cleaned.is_empty() {
        return None;
    }

    let check = cleaned.to_ascii_lowercase();
    if matches!(
        check.as_str(),
        "none" | "unknown" | "localhost" | "_gateway" | "invalid"
    ) {
        return None;
    }
    if cleaned.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    if is_hex_uuid(cleaned) {
        return None;
    }

    Some(cleaned.to_string())
}

fn is_hex_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Condenses an IEEE/OUI organization name into a clean short brand label.
pub fn short_vendor_name(vendor: &str) -> String {
    let lower = vendor.to_ascii_lowercase();
    for (needle, brand) in [
        ("freebox", "Freebox"),
        ("iliad", "Freebox"),
        ("proxmox", "Proxmox"),
        ("qemu", "QEMU"),
        ("canon", "Canon"),
        ("giga-byte", "Gigabyte"),
        ("gigabyte", "Gigabyte"),
        ("mercusys", "Mercusys"),
        ("belkin", "Belkin"),
        ("amazon", "Amazon"),
        ("raspberry", "Raspberry Pi"),
        ("espressif", "Espressif"),
        ("apple", "Apple"),
        ("tp-link", "TP-Link"),
        ("ubiquiti", "Ubiquiti"),
        ("synology", "Synology"),
        ("tailscale", "Tailscale"),
        ("vmware", "VMware"),
        ("netgear", "Netgear"),
        ("asus", "ASUS"),
        ("google", "Google"),
        ("intel", "Intel"),
        ("realtek", "Realtek"),
        ("samsung", "Samsung"),
        ("xiaomi", "Xiaomi"),
        ("docker", "Docker"),
        ("rivet", "Killer LAN"),
    ] {
        if lower.contains(needle) {
            return brand.to_string();
        }
    }

    let first_part = vendor.split(['/', ',']).next().unwrap_or(vendor).trim();
    let word = first_part.split_whitespace().next().unwrap_or(first_part);
    let trimmed: String = word.chars().take(14).collect();
    if trimmed.is_empty() {
        "Device".to_string()
    } else if trimmed
        .chars()
        .all(|c| !c.is_ascii_lowercase() && c.is_ascii_alphabetic())
        && trimmed.len() > 3
    {
        let mut chars = trimmed.chars();
        match chars.next() {
            Some(first) => {
                let mut out = first.to_ascii_uppercase().to_string();
                out.push_str(&chars.as_str().to_ascii_lowercase());
                out
            }
            None => trimmed,
        }
    } else {
        trimmed
    }
}

impl Host {
    /// Display name prioritizing user nickname, cleaned hostname, then friendly role/vendor ID.
    pub fn display_name(&self) -> String {
        if let Some(nick) = &self.nickname {
            let trimmed = nick.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if let Some(name) = self.hostname.as_deref().and_then(clean_discovered_hostname) {
            return name;
        }
        if self.role == DeviceRole::ThisMachine {
            return "This PC".to_string();
        }
        if self.role == DeviceRole::Gateway {
            if let Some(v) = &self.vendor {
                if !self.is_randomized_mac && !v.trim().is_empty() {
                    return format!("{} Gateway", short_vendor_name(v));
                }
            }
            return "Gateway".to_string();
        }
        if self.is_randomized_mac {
            return format!("Private Device (.{})", self.ip.octets()[3]);
        }
        if let Some(v) = &self.vendor {
            if !v.trim().is_empty() {
                let brand = short_vendor_name(v);
                let has_printer_port = self.ports.iter().any(|p| {
                    matches!(p.state, PortState::Open | PortState::InUse)
                        && matches!(p.port, 631 | 9100)
                });
                if has_printer_port {
                    return format!("{brand} Printer");
                }
                if brand.eq_ignore_ascii_case("Proxmox") {
                    return "Proxmox Host".to_string();
                }
                return match self.role {
                    DeviceRole::IoT => format!("{brand} IoT"),
                    DeviceRole::Mobile => format!("{brand} Mobile"),
                    DeviceRole::Container => format!("{brand} Container"),
                    _ => format!("{brand} Device"),
                };
            }
        }
        format!("Device .{}", self.ip.octets()[3])
    }

    /// Concise summary of open / in-use ports (e.g. `22 ssh · 80 http +1`), or `"—"` if none.
    pub fn open_ports_summary(&self, max_items: usize) -> String {
        let mut active: Vec<&PortInfo> = self
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::InUse | PortState::Open))
            .collect();
        if active.is_empty() {
            return "—".to_string();
        }
        active.sort_by(|a, b| a.state.cmp(&b.state).then_with(|| a.port.cmp(&b.port)));
        let total = active.len();
        let shown: Vec<String> = active
            .into_iter()
            .take(max_items.max(1))
            .map(|p| {
                if p.service == "tcp" {
                    p.port.to_string()
                } else {
                    format!("{} {}", p.port, p.service)
                }
            })
            .collect();
        let mut out = shown.join(" · ");
        if total > max_items.max(1) {
            out.push_str(&format!(" +{}", total - max_items.max(1)));
        }
        out
    }

    /// Formatted MAC address (`AA:BB:CC:DD:EE:FF`) if known.
    pub fn mac_string(&self) -> Option<String> {
        self.mac.map(format_mac)
    }

    /// Counts `(in_use, open, filtered, closed)` ports on this host.
    pub fn port_counts(&self) -> (usize, usize, usize, usize) {
        let mut in_use = 0;
        let mut open = 0;
        let mut filtered = 0;
        let mut closed = 0;
        for p in &self.ports {
            match p.state {
                PortState::InUse => in_use += 1,
                PortState::Open => open += 1,
                PortState::Filtered => filtered += 1,
                PortState::Closed => closed += 1,
            }
        }
        (in_use, open, filtered, closed)
    }

    /// Friendly service tags shown in Normal Mode (e.g., `["SSH", "Web", "SMB"]`).
    pub fn friendly_service_tags(&self) -> Vec<&'static str> {
        let mut tags = Vec::new();
        for p in &self.ports {
            if !matches!(p.state, PortState::Open | PortState::InUse) {
                continue;
            }
            let tag = match p.port {
                22 | 2222 => "SSH",
                80 | 443 | 8000 | 8080 | 8443 | 3000 => "Web",
                445 | 139 | 2049 | 548 => "Files",
                53 => "DNS",
                3389 | 5900 => "Remote",
                3306 | 5432 | 6379 | 27017 | 1433 => "DB",
                1883 | 8883 => "MQTT",
                631 => "Print",
                2375 | 2376 => "Docker",
                _ => continue,
            };
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        tags
    }

    /// Evaluates whether this host matches a search/filter query.
    pub fn matches_query(&self, query: &str) -> bool {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return true;
        }
        for token in trimmed.split_whitespace() {
            let lower = token.to_ascii_lowercase();
            if let Some(arg) = lower.strip_prefix("port:") {
                let Ok(port_num) = arg.parse::<u16>() else {
                    return false;
                };
                if !self.ports.iter().any(|p| p.port == port_num) {
                    return false;
                }
            } else if let Some(arg) = lower.strip_prefix("state:") {
                let target = match arg {
                    "in-use" | "inuse" | "use" => Some(PortState::InUse),
                    "open" => Some(PortState::Open),
                    "closed" => Some(PortState::Closed),
                    "filtered" => Some(PortState::Filtered),
                    _ => None,
                };
                let Some(st) = target else {
                    return false;
                };
                if !self.ports.iter().any(|p| p.state == st) {
                    return false;
                }
            } else if let Some(arg) = lower.strip_prefix("vendor:") {
                let v = self.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
                if !v.contains(arg) {
                    return false;
                }
            } else if let Some(arg) = lower.strip_prefix("os:") {
                let os = self.os_guess.as_deref().unwrap_or("").to_ascii_lowercase();
                if !os.contains(arg) {
                    return false;
                }
            } else if let Some(arg) = lower.strip_prefix("role:") {
                if !self.role.label().to_ascii_lowercase().contains(arg) {
                    return false;
                }
            } else if let Some(arg) = lower.strip_prefix("status:") {
                let matched = match arg {
                    "new" => self.is_new,
                    "online" | "up" => self.online,
                    "offline" | "down" => !self.online,
                    "trusted" => self.trusted,
                    "untrusted" | "unknown" => !self.trusted,
                    _ => false,
                };
                if !matched {
                    return false;
                }
            } else if let Some(arg) = lower.strip_prefix("ip:") {
                if !self.ip.to_string().contains(arg) {
                    return false;
                }
            } else if let Some(arg) = lower.strip_prefix("mac:") {
                let mac_s = self.mac_string().unwrap_or_default().to_ascii_lowercase();
                if !mac_s.contains(arg) {
                    return false;
                }
            } else {
                let ip_s = self.ip.to_string();
                let mac_s = self.mac_string().unwrap_or_default().to_ascii_lowercase();
                let disp_s = self.display_name().to_ascii_lowercase();
                let host_s = self.hostname.as_deref().unwrap_or("").to_ascii_lowercase();
                let nick_s = self.nickname.as_deref().unwrap_or("").to_ascii_lowercase();
                let vendor_s = self.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
                let os_s = self.os_guess.as_deref().unwrap_or("").to_ascii_lowercase();
                let role_s = self.role.label().to_ascii_lowercase();
                let port_match = self.ports.iter().any(|p| {
                    p.port.to_string() == lower
                        || p.service.to_ascii_lowercase().contains(&lower)
                        || p.banner
                            .as_deref()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .contains(&lower)
                        || p.process
                            .as_deref()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .contains(&lower)
                });
                let hit = ip_s.contains(&lower)
                    || mac_s.contains(&lower)
                    || disp_s.contains(&lower)
                    || host_s.contains(&lower)
                    || nick_s.contains(&lower)
                    || vendor_s.contains(&lower)
                    || os_s.contains(&lower)
                    || role_s.contains(&lower)
                    || port_match;
                if !hit {
                    return false;
                }
            }
        }
        true
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

/// Formats a 6-byte MAC address as uppercase colon-separated hex.
pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Formats the 3-byte OUI prefix (`AA:BB:CC`).
pub fn format_oui(mac: [u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2])
}

/// Parses a colon- or dash-separated MAC string (`aa:bb:cc:dd:ee:ff`).
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let clean = s.trim().replace('-', ":");
    let parts: Vec<&str> = clean.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        bytes[idx] = u8::from_str_radix(part, 16).ok()?;
    }
    if bytes == [0; 6] {
        return None;
    }
    Some(bytes)
}

/// Formats throughput (`bytes/s`) concisely.
pub fn format_bps(bps: f64) -> String {
    if !bps.is_finite() || bps <= 0.0 {
        return "0 B/s".to_string();
    }
    const UNITS: &[&str] = &["B/s", "KB/s", "MB/s", "GB/s"];
    let mut val = bps;
    let mut idx = 0;
    while val >= 1024.0 && idx + 1 < UNITS.len() {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{:.0} {}", val, UNITS[idx])
    } else {
        format!("{:.1} {}", val, UNITS[idx])
    }
}

/// Formats byte totals concisely.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    let mut idx = 0;
    while val >= 1024.0 && idx + 1 < UNITS.len() {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.1} {}", UNITS[idx])
    }
}

/// Infers OS family from an observed IPv4 TTL value.
pub fn infer_os_from_ttl(ttl: u8) -> &'static str {
    if ttl == 0 {
        "Unknown"
    } else if ttl <= 64 {
        "Linux / Unix / macOS"
    } else if ttl <= 128 {
        "Windows"
    } else {
        "Network Appliance / Router"
    }
}

/// Infers a friendly `DeviceRole` from IP, gateway, vendor, OS, and open ports.
pub fn infer_device_role(
    is_local: bool,
    is_gateway: bool,
    vendor: Option<&str>,
    hostname: Option<&str>,
    ports: &[PortInfo],
) -> DeviceRole {
    if is_local {
        return DeviceRole::ThisMachine;
    }
    if is_gateway {
        return DeviceRole::Gateway;
    }
    let v = vendor.unwrap_or("").to_ascii_lowercase();
    let h = hostname.unwrap_or("").to_ascii_lowercase();
    if v.contains("docker") || h.contains("docker") || h.contains("container") {
        return DeviceRole::Container;
    }
    if v.contains("espressif")
        || v.contains("tuya")
        || v.contains("sonos")
        || v.contains("philips")
        || v.contains("shelly")
        || ports.iter().any(|p| {
            matches!(p.port, 1883 | 8883) && matches!(p.state, PortState::Open | PortState::InUse)
        })
    {
        return DeviceRole::IoT;
    }
    if ports
        .iter()
        .any(|p| p.port == 62078 && matches!(p.state, PortState::Open | PortState::InUse))
        || h.contains("iphone")
        || h.contains("ipad")
        || h.contains("android")
        || h.contains("pixel")
        || h.contains("galaxy")
    {
        return DeviceRole::Mobile;
    }
    if v.contains("ubiquiti")
        || v.contains("cisco")
        || v.contains("mikrotik")
        || v.contains("synology")
        || v.contains("qnap")
        || h.contains("proxmox")
        || h.contains("nas")
        || h.contains("pihole")
        || ports.iter().any(|p| {
            matches!(
                p.port,
                22 | 80 | 443 | 445 | 548 | 3306 | 5432 | 8006 | 9000
            ) && matches!(p.state, PortState::Open | PortState::InUse)
        })
    {
        return DeviceRole::Server;
    }
    if v.contains("apple") || v.contains("intel") || v.contains("dell") || v.contains("lenovo") {
        return DeviceRole::Workstation;
    }
    DeviceRole::Host
}

/// Parses a custom port specification string (e.g. `22,80,443,8000-8010`).
pub fn parse_port_expr(expr: &str) -> Result<Vec<u16>, String> {
    let mut set = BTreeSet::new();
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err("Port list cannot be empty".to_string());
    }
    for part in trimmed.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = token.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid start port '{start_s}'"))?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid end port '{end_s}'"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("Invalid range '{token}' (must be 1..=65535)"));
            }
            if usize::from(end - start) > 20_000 && set.len() + usize::from(end - start) > 65_535 {
                return Err("Range too large".to_string());
            }
            for port in start..=end {
                set.insert(port);
            }
        } else {
            let port: u16 = token
                .parse()
                .map_err(|_| format!("Invalid port '{token}'"))?;
            if port == 0 {
                return Err("Port 0 is not scannable".to_string());
            }
            set.insert(port);
        }
    }
    if set.is_empty() {
        return Err("No valid ports parsed".to_string());
    }
    Ok(set.into_iter().collect())
}

/// Quick top-37 port list.
pub const QUICK_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 548, 631, 993, 995, 1433, 1883,
    2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8006, 8080, 8123, 8384, 8443, 8765, 9000,
    27017, 32400,
];

/// Web, API, DB, container, and media development port list.
pub const WEB_DEV_PORTS: &[u16] = &[
    22, 53, 80, 81, 300, 443, 1883, 2375, 2376, 3000, 3001, 3306, 4000, 4200, 5000, 5173, 5432,
    5672, 6379, 7000, 8000, 8006, 8008, 8080, 8081, 8096, 8123, 8384, 8443, 8765, 8888, 9000, 9090,
    9200, 9443, 11434, 27017, 32400,
];

/// Extra registered service ports scanned in `Full` mode beyond 1..=1024.
pub const EXTENDED_FULL_PORTS: &[u16] = &[
    1080, 1194, 1433, 1521, 1883, 1900, 2049, 2222, 2375, 2376, 3000, 3001, 3128, 3306, 3389, 4000,
    4200, 4443, 5000, 5001, 5173, 5353, 5355, 5357, 5432, 5555, 5601, 5672, 5900, 5901, 6379, 6443,
    7000, 7443, 7878, 8000, 8006, 8008, 8080, 8081, 8090, 8096, 8112, 8123, 8200, 8384, 8443, 8500,
    8765, 8880, 8883, 8888, 8989, 9000, 9001, 9090, 9091, 9100, 9200, 9418, 9443, 10000, 11211,
    11434, 15672, 19999, 25565, 27015, 27017, 32400, 41641, 51413, 51820, 62078,
];

/// Standard top-100 TCP ports.
pub const STANDARD_TOP_100_PORTS: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1883, 1900,
    2000, 2001, 2049, 2121, 2375, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5353, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 7070, 8000, 8006,
    8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 27017,
];

/// Generates the concrete port list for a given preset and custom expression.
pub fn ports_for_preset(preset: ScanPreset, custom_expr: &str) -> Vec<u16> {
    match preset {
        ScanPreset::Quick => QUICK_PORTS.to_vec(),
        ScanPreset::Standard => STANDARD_TOP_100_PORTS.to_vec(),
        ScanPreset::WebDev => WEB_DEV_PORTS.to_vec(),
        ScanPreset::Full => {
            let mut set: BTreeSet<u16> = (1..=1024).collect();
            for &p in WEB_DEV_PORTS {
                set.insert(p);
            }
            for &p in EXTENDED_FULL_PORTS {
                set.insert(p);
            }
            set.into_iter().collect()
        }
        ScanPreset::Custom => parse_port_expr(custom_expr).unwrap_or_else(|_| QUICK_PORTS.to_vec()),
    }
}

/// Maps common ports to `(service_name, plain_english_description)`.
pub fn service_info(port: u16) -> (&'static str, &'static str) {
    match port {
        21 => ("ftp", "File Transfer Protocol"),
        22 | 2222 => ("ssh", "Secure Shell remote login"),
        23 => ("telnet", "Unencrypted legacy terminal"),
        25 | 465 | 587 => ("smtp", "Mail transfer server"),
        53 => ("dns", "Domain Name System resolver"),
        67 | 68 => ("dhcp", "Dynamic IP lease server"),
        80 | 81 | 8008 => ("http", "Unencrypted web server"),
        110 => ("pop3", "Email retrieval service"),
        111 => ("rpcbind", "ONC RPC portmapper"),
        123 => ("ntp", "Network Time synchronization"),
        135 => ("msrpc", "Windows RPC endpoint mapper"),
        137 | 138 => ("netbios", "NetBIOS Name Service"),
        139 => ("netbios", "NetBIOS file/name session"),
        143 => ("imap", "Mail access server"),
        161 => ("snmp", "Network device telemetry"),
        389 => ("ldap", "Directory authentication service"),
        443 => ("https", "Encrypted HTTPS web server"),
        445 => ("smb", "Windows / Samba file sharing"),
        548 => ("afp", "Apple Filing Protocol share"),
        554 => ("rtsp", "Media / camera video stream"),
        631 => ("ipp", "Network printing (CUPS)"),
        873 => ("rsync", "Remote file synchronization"),
        993 => ("imaps", "Encrypted IMAP mail"),
        995 => ("pop3s", "Encrypted POP3 mail"),
        1080 => ("socks", "SOCKS network proxy"),
        1194 => ("openvpn", "OpenVPN tunnel endpoint"),
        1433 => ("mssql", "Microsoft SQL Server"),
        1521 => ("oracle", "Oracle Database listener"),
        1883 | 8883 => ("mqtt", "IoT telemetry message broker"),
        1900 => ("upnp", "UPnP / SSDP device discovery"),
        2049 => ("nfs", "Network File System share"),
        2375 | 2376 => ("docker", "Docker container engine API"),
        3000 | 3001 | 4000 | 4200 | 5173 => ("dev-web", "Frontend / Node dev server"),
        3128 => ("proxy", "HTTP caching proxy"),
        3306 => ("mysql", "MySQL / MariaDB database"),
        3389 => ("rdp", "Windows Remote Desktop"),
        4443 => ("https-alt", "Alternate HTTPS endpoint"),
        5000 | 5001 => ("upnp/api", "Local API / Synology DSM / Flask"),
        5353 => ("mdns", "Multicast DNS (.local) discovery"),
        5355 => ("llmnr", "LLMNR name resolution"),
        5357 => ("wsd", "Windows Web Services Discovery"),
        5432 => ("postgres", "PostgreSQL relational database"),
        5555 => ("adb", "Android Debug Bridge"),
        5601 => ("kibana", "Kibana analytics dashboard"),
        5672 | 15672 => ("amqp", "RabbitMQ message queue"),
        5900 | 5901 => ("vnc", "Graphical remote screen sharing"),
        6379 => ("redis", "In-memory key-value datastore"),
        6443 => ("k8s-api", "Kubernetes API server"),
        7000 | 7443 => ("http-alt", "Application management service"),
        7878 => ("radarr", "Radarr media manager"),
        8000 | 8090 | 8880 => ("http-alt", "Application / Python web server"),
        8006 => ("proxmox", "Proxmox VE virtualization UI"),
        8080 | 8081 => ("http-proxy", "Web service or reverse proxy"),
        8096 => ("jellyfin", "Media streaming server"),
        8112 => ("deluge", "Deluge web interface"),
        8123 => ("home-assist", "Home Assistant automation hub"),
        8200 => ("vault", "Vault / DLNA media server"),
        8384 => ("syncthing", "Syncthing peer synchronization UI"),
        8443 | 9443 => ("https-alt", "Encrypted management web UI"),
        8500 => ("consul", "HashiCorp Consul service UI"),
        8765 => ("http-alt", "Web / HTTP file server"),
        8888 => ("notebook", "Jupyter / web control panel"),
        8989 => ("sonarr", "Sonarr media manager"),
        9000 | 9001 => ("portainer", "Admin web portal / PHP-FPM"),
        9090 => ("prometheus", "Metrics / Cockpit web console"),
        9091 => ("transmission", "Transmission BitTorrent web UI"),
        9100 => ("jetdirect", "Raw network printer port"),
        9200 => ("elastic", "Elasticsearch HTTP API"),
        9418 => ("git", "Git daemon protocol"),
        10000 => ("webmin", "Webmin system admin UI"),
        11211 => ("memcached", "In-memory object cache"),
        11434 => ("ollama", "Local inference API endpoint"),
        19999 => ("netdata", "Netdata telemetry agent"),
        25565 => ("minecraft", "Minecraft game server"),
        27015 => ("source-ds", "Steam / Source dedicated server"),
        27017 => ("mongodb", "MongoDB document database"),
        32400 => ("plex", "Plex Media Server"),
        41641 => ("tailscale", "Tailscale WireGuard transport"),
        51413 => ("torrent", "BitTorrent peer port"),
        51820 => ("wireguard", "WireGuard VPN tunnel"),
        62078 => ("iphone-sync", "Apple mobile wireless sync"),
        _ => ("tcp", ""),
    }
}

/// Computes live host stats summary `(online, trusted, open_ports, in_use_ports)`.
pub fn summarize_hosts(hosts: &[Host], interfaces: &[NetworkInterface]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let online = hosts.iter().filter(|h| h.online).count();
    let trusted = hosts.iter().filter(|h| h.trusted).count();
    let mut open = 0;
    let mut in_use = 0;
    for h in hosts {
        let (iu, op, _, _) = h.port_counts();
        in_use += iu;
        open += op;
    }
    map.insert("online".into(), online);
    map.insert("trusted".into(), trusted);
    map.insert("open".into(), open);
    map.insert("in_use".into(), in_use);
    map.insert(
        "ifaces_up".into(),
        interfaces.iter().filter(|i| i.is_up).count(),
    );
    map
}
