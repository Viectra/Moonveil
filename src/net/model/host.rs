//! Structure `Host` (hôte découvert) et ses méthodes d'affichage, de tri et de recherche.

use super::*;

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

impl Host {
    /// Display name prioritizing user nickname, resolved hostname, or IP string.
    pub fn display_name(&self) -> String {
        if let Some(nick) = &self.nickname {
            if !nick.is_empty() {
                return nick.clone();
            }
        }
        if let Some(name) = &self.hostname {
            if !name.is_empty() {
                return name.clone();
            }
        }
        self.ip.to_string()
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
