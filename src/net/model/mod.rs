//! Core network, host, port, socket, interface, and timeline data model.

use crate::config::Language;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

mod host;
mod inference;
mod ports;
mod types;
pub use host::*;
pub use inference::*;
pub use ports::*;
pub use types::*;

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
