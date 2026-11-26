//! Host entity, localized display naming, smart search query matching, and sorting.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::config::Language;

use super::{format_mac, ArpState, DeviceRole, PortInfo, PortState};

/// Discovered host on the network.
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
    /// Returns the human-friendly label in English (delegates to `display_name_for`).
    pub fn display_name(&self) -> String {
        self.display_name_for(Language::En)
    }

    /// Returns a human-friendly device label localized for the active language.
    pub fn display_name_for(&self, lang: Language) -> String {
        if let Some(nick) = self
            .nickname
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return nick.to_string();
        }
        if let Some(host) = self.hostname.as_deref().and_then(clean_discovered_hostname) {
            return host;
        }
        if self.role == DeviceRole::ThisMachine {
            return lang.t("This PC", "Ce PC").to_string();
        }
        let oct = self.ip.octets()[3];
        let brand = self.short_vendor_name();
        if self.role == DeviceRole::Gateway {
            return match brand {
                Some(b) => match lang {
                    Language::En => format!("{b} Gateway"),
                    Language::Fr => format!("Passerelle {b}"),
                },
                None => lang.t("Gateway", "Passerelle").to_string(),
            };
        }
        if self.is_randomized_mac {
            return match lang {
                Language::En => format!("Private Device (.{oct})"),
                Language::Fr => format!("Appareil privé (.{oct})"),
            };
        }
        if let Some(b) = brand {
            let has_printer_port = self.ports.iter().any(|p| {
                matches!(p.port, 631 | 9100)
                    && matches!(p.state, PortState::Open | PortState::InUse)
            });
            if has_printer_port || self.role == DeviceRole::Printer {
                return match lang {
                    Language::En => format!("{b} Printer"),
                    Language::Fr => format!("Imprimante {b}"),
                };
            }
            if b.eq_ignore_ascii_case("Proxmox")
                && self.ports.iter().any(|p| {
                    p.port == 8006 && matches!(p.state, PortState::Open | PortState::InUse)
                })
            {
                return lang.t("Proxmox Host", "Hôte Proxmox").to_string();
            }
            return match self.role {
                DeviceRole::IoT => format!("{b} IoT"),
                DeviceRole::Mobile => format!("{b} Mobile"),
                DeviceRole::Container => match lang {
                    Language::En => format!("{b} Container"),
                    Language::Fr => format!("Conteneur {b}"),
                },
                _ => match lang {
                    Language::En => format!("{b} Device"),
                    Language::Fr => format!("Appareil {b}"),
                },
            };
        }

        match self.role {
            DeviceRole::Printer => match lang {
                Language::En => format!("Printer .{oct}"),
                Language::Fr => format!("Imprimante .{oct}"),
            },
            DeviceRole::IoT => format!("IoT .{oct}"),
            DeviceRole::Mobile => format!("Mobile .{oct}"),
            DeviceRole::Container => match lang {
                Language::En => format!("Container .{oct}"),
                Language::Fr => format!("Conteneur .{oct}"),
            },
            DeviceRole::Server => match lang {
                Language::En => format!("Server .{oct}"),
                Language::Fr => format!("Serveur .{oct}"),
            },
            _ => match lang {
                Language::En => format!("Device .{oct}"),
                Language::Fr => format!("Appareil .{oct}"),
            },
        }
    }

    /// Extracts a concise readable brand name from the IEEE OUI vendor string.
    pub fn short_vendor_name(&self) -> Option<String> {
        let raw = self.vendor.as_deref()?.trim();
        if raw.is_empty()
            || raw == "—"
            || raw.eq_ignore_ascii_case("unknown")
            || raw.starts_with("Private /")
        {
            return None;
        }
        let lower = raw.to_ascii_lowercase();
        let known = [
            ("canon", "Canon"),
            ("proxmox", "Proxmox"),
            ("freebox", "Freebox"),
            ("iliad", "Freebox"),
            ("asustek", "ASUS"),
            ("asus", "ASUS"),
            ("giga-byte", "Gigabyte"),
            ("gigabyte", "Gigabyte"),
            ("raspberry pi", "Raspberry Pi"),
            ("apple", "Apple"),
            ("amazon", "Amazon"),
            ("espressif", "Espressif"),
            ("mercusys", "Mercusys"),
            ("tp-link", "TP-Link"),
            ("belkin", "Belkin"),
            ("ubiquiti", "Ubiquiti"),
            ("synology", "Synology"),
            ("qnap", "QNAP"),
            ("google", "Google"),
            ("intel", "Intel"),
            ("realtek", "Realtek"),
            ("samsung", "Samsung"),
            ("sony", "Sony"),
            ("docker", "Docker"),
            ("tailscale", "Tailscale"),
            ("micro-star", "MSI"),
            ("hewlett", "HP"),
            ("hp inc", "HP"),
            ("epson", "Epson"),
            ("brother", "Brother"),
            ("cisco", "Cisco"),
            ("mikrotik", "MikroTik"),
            ("netgear", "Netgear"),
            ("dell", "Dell"),
            ("lenovo", "Lenovo"),
            ("xiaomi", "Xiaomi"),
            ("sonos", "Sonos"),
            ("vmware", "VMware"),
            ("qemu", "QEMU"),
        ];
        for (needle, label) in known {
            if lower.contains(needle) {
                return Some(label.to_string());
            }
        }

        let first = raw
            .split([',', '/', '('])
            .next()
            .unwrap_or(raw)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('.');
        if first.is_empty() {
            return None;
        }
        if first.len() <= 4 && first.chars().all(|c| c.is_ascii_uppercase()) {
            return Some(first.to_string());
        }
        let mut chars = first.chars();
        let mut pretty = String::new();
        if let Some(c0) = chars.next() {
            for uc in c0.to_uppercase() {
                pretty.push(uc);
            }
            for ch in chars {
                for lc in ch.to_lowercase() {
                    pretty.push(lc);
                }
            }
        }
        Some(pretty)
    }

    pub fn mac_string(&self) -> String {
        self.mac.map(format_mac).unwrap_or_else(|| "—".to_string())
    }

    /// Returns `(in_use, open, filtered, closed)` port counts on this host.
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

    /// Compact summary of top open / active ports (e.g. `22, 80, 443 +2`).
    pub fn open_ports_summary(&self) -> String {
        let active: Vec<u16> = self
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
            .map(|p| p.port)
            .collect();
        if active.is_empty() {
            return "—".to_string();
        }
        let mut out = String::new();
        for (i, port) in active.iter().take(4).enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "{port}");
        }
        if active.len() > 4 {
            let _ = write!(out, " +{}", active.len() - 4);
        }
        out
    }

    /// Plain-English service tags shown in Normal Mode (e.g. `SSH • Web • DB`).
    pub fn friendly_service_tags(&self) -> String {
        let mut tags: Vec<&'static str> = Vec::new();
        for p in &self.ports {
            if !matches!(p.state, PortState::Open | PortState::InUse) {
                continue;
            }
            let tag = match p.port {
                22 | 2222 => Some("SSH"),
                80 | 443 | 3000 | 8000 | 8006 | 8080 | 8443 | 8765 => Some("Web"),
                53 => Some("DNS"),
                445 | 548 | 2049 => Some("Files"),
                3306 | 5432 | 6379 | 27017 => Some("DB"),
                3389 | 5900 => Some("Remote"),
                631 | 9100 => Some("Print"),
                2375 | 2376 | 9000 => Some("Docker"),
                8096 | 32400 => Some("Media"),
                8123 | 1883 => Some("SmartHome"),
                _ => None,
            };
            if let Some(t) = tag {
                if !tags.contains(&t) {
                    tags.push(t);
                }
            }
        }
        if tags.is_empty() {
            "No open ports".to_string()
        } else {
            tags.into_iter().take(3).collect::<Vec<_>>().join(" • ")
        }
    }

    /// Evaluates smart search queries (`port:22`, `state:in-use`, `vendor:apple`, etc.).
    pub fn matches_query(&self, query: &str) -> bool {
        let q = query.trim();
        if q.is_empty() {
            return true;
        }
        let ip_s = self.ip.to_string();
        let mac_s = self.mac_string().to_ascii_lowercase();
        let vendor_s = self.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
        let host_s = self.hostname.as_deref().unwrap_or("").to_ascii_lowercase();
        let nick_s = self.nickname.as_deref().unwrap_or("").to_ascii_lowercase();
        let disp_en = self.display_name_for(Language::En).to_ascii_lowercase();
        let disp_fr = self.display_name_for(Language::Fr).to_ascii_lowercase();
        let os_s = self.os_guess.as_deref().unwrap_or("").to_ascii_lowercase();

        for token in q.split_whitespace() {
            let tok = token.to_ascii_lowercase();
            let matched = if let Some(val) = tok.strip_prefix("port:") {
                if let Ok(p) = val.parse::<u16>() {
                    self.ports.iter().any(|pi| {
                        pi.port == p && matches!(pi.state, PortState::Open | PortState::InUse)
                    })
                } else {
                    self.ports
                        .iter()
                        .any(|pi| pi.port.to_string().contains(val) || pi.service.contains(val))
                }
            } else if let Some(val) = tok.strip_prefix("state:") {
                match val {
                    "in-use" | "inuse" | "use" | "utilise" => {
                        self.ports.iter().any(|pi| pi.state == PortState::InUse)
                    }
                    "open" | "ouvert" => self.ports.iter().any(|pi| pi.state == PortState::Open),
                    "closed" | "ferme" => self.ports.iter().any(|pi| pi.state == PortState::Closed),
                    "filtered" | "filtre" => {
                        self.ports.iter().any(|pi| pi.state == PortState::Filtered)
                    }
                    _ => false,
                }
            } else if let Some(val) = tok.strip_prefix("vendor:") {
                vendor_s.contains(val)
            } else if let Some(val) = tok.strip_prefix("mac:") {
                mac_s.contains(val)
            } else if let Some(val) = tok.strip_prefix("os:") {
                os_s.contains(val)
            } else if let Some(val) = tok.strip_prefix("status:") {
                match val {
                    "online" | "up" | "en-ligne" => self.online,
                    "offline" | "down" | "hors-ligne" => !self.online,
                    "new" | "nouveau" => self.is_new,
                    "trusted" | "fiable" => self.trusted,
                    _ => true,
                }
            } else {
                let port_hit = tok
                    .parse::<u16>()
                    .map(|p| {
                        self.ports.iter().any(|pi| {
                            pi.port == p && matches!(pi.state, PortState::Open | PortState::InUse)
                        })
                    })
                    .unwrap_or(false);
                port_hit
                    || ip_s.contains(&tok)
                    || mac_s.contains(&tok)
                    || vendor_s.contains(&tok)
                    || host_s.contains(&tok)
                    || nick_s.contains(&tok)
                    || disp_en.contains(&tok)
                    || disp_fr.contains(&tok)
                    || os_s.contains(&tok)
                    || self.ports.iter().any(|pi| {
                        matches!(pi.state, PortState::Open | PortState::InUse)
                            && (pi.service.contains(&tok)
                                || pi
                                    .process
                                    .as_deref()
                                    .unwrap_or("")
                                    .to_ascii_lowercase()
                                    .contains(&tok))
                    })
            };

            if !matched {
                return false;
            }
        }
        true
    }
}

/// Cleans discovered DNS/mDNS/NetBIOS hostnames by stripping noisy router suffixes and bogus placeholders.
pub fn clean_discovered_hostname(raw: &str) -> Option<String> {
    let mut s = raw.trim().trim_end_matches('.').to_string();
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "_gateway"
            | "none"
            | "none.local"
            | "unknown"
            | "local"
            | "-"
    ) {
        return None;
    }
    if s.parse::<Ipv4Addr>().is_ok() {
        return None;
    }

    for suffix in [".localdomain", ".local", ".home", ".lan", ".arpa"] {
        if s.to_ascii_lowercase().ends_with(suffix) && s.len() > suffix.len() {
            s.truncate(s.len() - suffix.len());
            break;
        }
    }
    while s.to_ascii_lowercase().ends_with("-home") && s.len() > 5 {
        s.truncate(s.len() - 5);
    }

    let clean = s.trim();
    if clean.is_empty() {
        return None;
    }
    let clean_low = clean.to_ascii_lowercase();
    if matches!(
        clean_low.as_str(),
        "none" | "unknown" | "_gateway" | "localhost"
    ) {
        return None;
    }
    // Reject bare UUIDs (common in mDNS/AirPlay advertisements without device names).
    if clean.len() >= 32
        && clean.matches('-').count() >= 4
        && clean.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return None;
    }
    if clean.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    Some(clean.to_string())
}

/// Active sort column for the Hosts table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostSortColumn {
    #[default]
    Ip,
    Device,
    Vendor,
    Rtt,
    OpenPorts,
}

impl HostSortColumn {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ip => "IP",
            Self::Device => "Device",
            Self::Vendor => "Vendor",
            Self::Rtt => "Ping",
            Self::OpenPorts => "Open Ports",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.label();
        }
        match self {
            Self::Ip => "IP",
            Self::Device => "Appareil",
            Self::Vendor => "Fabricant",
            Self::Rtt => "Ping",
            Self::OpenPorts => "Ports",
        }
    }
}
