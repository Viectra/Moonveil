//! Linux system metadata: privilege detection, clock, user/hostname, `/etc/hosts`, DNS, and gateways.

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use super::proc_net::parse_proc_hex_ipv4;
use crate::net::model::PrivilegeLevel;

/// Detects effective privileges (`Root`, `CAP_NET_RAW`, or unprivileged `User`).
pub fn detect_privilege() -> PrivilegeLevel {
    if unsafe { libc::geteuid() } == 0 {
        return PrivilegeLevel::Root;
    }
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                if let Ok(mask) = u64::from_str_radix(hex.trim(), 16) {
                    // CAP_NET_RAW is bit 13
                    if (mask & (1_u64 << 13)) != 0 {
                        return PrivilegeLevel::Capabilities;
                    }
                }
            }
        }
    }
    PrivilegeLevel::User
}

/// Returns current UNIX timestamp in seconds.
pub fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns `(username, local_hostname)`.
pub fn read_user_and_host() -> (String, String) {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string());
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| fs::read_to_string("/etc/hostname"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "linux".to_string());
    (user, host)
}

/// Reads static IPv4 hostnames from `/etc/hosts` (excluding loopback entries).
pub fn read_etc_hosts() -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    let Ok(raw) = fs::read_to_string("/etc/hosts") else {
        return map;
    };
    for line in raw.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }
        let mut parts = code.split_whitespace();
        let Some(ip_s) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_s.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.is_loopback() {
            continue;
        }
        for name in parts {
            let trimmed = name.trim();
            if !trimmed.is_empty()
                && !trimmed.eq_ignore_ascii_case("localhost")
                && !trimmed.eq_ignore_ascii_case("localhost.localdomain")
            {
                map.entry(ip).or_insert_with(|| trimmed.to_string());
                break;
            }
        }
    }
    map
}

/// Parses IPv4 DNS resolvers from `/etc/resolv.conf`.
pub fn read_dns_servers() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let Ok(raw) = fs::read_to_string("/etc/resolv.conf") else {
        return out;
    };
    for line in raw.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            if let Ok(ip) = rest.trim().parse::<Ipv4Addr>() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// Reads default IPv4 gateways per interface from `/proc/net/route`.
pub fn read_gateways() -> HashMap<String, Ipv4Addr> {
    let mut map = HashMap::new();
    let Ok(raw) = fs::read_to_string("/proc/net/route") else {
        return map;
    };
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        if cols[1] == "00000000" {
            if let Some(gw) = parse_proc_hex_ipv4(cols[2]) {
                if !gw.is_unspecified() {
                    map.entry(cols[0].to_string()).or_insert(gw);
                }
            }
        }
    }
    map
}
