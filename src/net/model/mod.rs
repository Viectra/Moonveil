//! Core network domain model, formatting helpers, port catalogs, and host inference.

pub mod host;
pub mod inference;
pub mod ports;
pub mod types;

use std::net::Ipv4Addr;

pub use host::{clean_discovered_hostname, Host, HostSortColumn};
pub use inference::{guess_os_from_ttl, infer_role, summarize_hosts};
pub use ports::{
    parse_port_expr, ports_for_preset, service_info, ScanMode, ScanPreset, EXTENDED_FULL_PORTS,
    QUICK_PORTS, STANDARD_TOP_100_PORTS, WEB_DEV_PORTS,
};
pub use types::{
    ArpState, DeviceRole, EventKind, ExportFormat, LocalSocket, NetworkInterface, NetworkSnapshot,
    PortFilter, PortInfo, PortState, PrivilegeLevel, Proto, ScanProgress, SocketState,
    TimelineEvent, TracerouteHop,
};

/// Formats 6 MAC bytes as colon-separated uppercase hex (`AA:BB:CC:DD:EE:FF`).
pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Formats an OUI 3-byte prefix (`AA:BB:CC`).
pub fn format_oui(mac: [u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2])
}

/// Parses a colon or hyphen delimited MAC address string.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let clean = s.trim().replace('-', ":");
    let parts: Vec<&str> = clean.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

/// Formats a byte-rate throughput cleanly (`B/s`, `KB/s`, `MB/s`, `GB/s`).
pub fn format_bps(bps: f64) -> String {
    if bps < 1024.0 {
        format!("{:.0} B/s", bps)
    } else if bps < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else if bps < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} MB/s", bps / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB/s", bps / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Formats cumulative byte totals cleanly (`B`, `KB`, `MB`, `GB`).
pub fn format_bytes(bytes: u64) -> String {
    let b = bytes as f64;
    if b < 1024.0 {
        format!("{bytes} B")
    } else if b < 1024.0 * 1024.0 {
        format!("{:.1} KB", b / 1024.0)
    } else if b < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB", b / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", b / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Extracts the last octet of an IPv4 address.
#[inline]
pub fn last_octet(ip: Ipv4Addr) -> u8 {
    ip.octets()[3]
}
