//! Informations système Linux : privilèges, horloge, utilisateur/hôte, `/etc/hosts`, DNS et passerelles.

use super::*;

/// Checks current Linux process capabilities (`RAW`, `ICMP`, or `USER`).
pub fn detect_privilege() -> PrivilegeLevel {
    unsafe {
        if libc::geteuid() == 0 {
            return PrivilegeLevel::Raw;
        }
        let raw_fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
        if raw_fd >= 0 {
            libc::close(raw_fd);
            return PrivilegeLevel::Raw;
        }
        let dgram_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
        if dgram_fd >= 0 {
            libc::close(dgram_fd);
            return PrivilegeLevel::IcmpDatagram;
        }
    }
    PrivilegeLevel::User
}

/// Returns current UNIX epoch seconds.
pub fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads `(username, hostname)` from environment and Linux system files.
pub fn read_user_and_host() -> (String, String) {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string());
    let host = fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "linux".to_string());
    (user, host)
}

/// Reads `/etc/hosts` mapping IPv4 addresses to hostnames.
pub fn read_etc_hosts() -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    let Ok(raw) = fs::read_to_string("/etc/hosts") else {
        return map;
    };
    for line in raw.lines() {
        let stripped = line.split('#').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }
        let mut parts = stripped.split_whitespace();
        let Some(ip_str) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.is_loopback() {
            continue;
        }
        if let Some(name) = parts.next() {
            map.entry(ip).or_insert_with(|| name.to_string());
        }
    }
    map
}

/// Reads DNS servers from `/etc/resolv.conf`.
pub fn read_dns_servers() -> Vec<String> {
    let Ok(raw) = fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        let clean = line.split('#').next().unwrap_or("").trim();
        let mut parts = clean.split_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(ns) = parts.next() {
                if !out.contains(&ns.to_string()) {
                    out.push(ns.to_string());
                }
            }
        }
    }
    out
}

/// Reads per-interface default gateway IPv4 addresses from `/proc/net/route`.
pub fn read_gateways() -> HashMap<String, Ipv4Addr> {
    let mut out = HashMap::new();
    let Ok(raw) = fs::read_to_string("/proc/net/route") else {
        return out;
    };
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let iface = cols[0];
        let dest = cols[1];
        let gw_hex = cols[2];
        let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
        // RTF_UP (0x1) & RTF_GATEWAY (0x2), destination 0.0.0.0
        if dest == "00000000" && (flags & 0x0003) == 0x0003 {
            if let Some(gw) = parse_proc_hex_ipv4(gw_hex) {
                if !gw.is_unspecified() {
                    out.entry(iface.to_string()).or_insert(gw);
                }
            }
        }
    }
    out
}
