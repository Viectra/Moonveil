//! Linux network interface discovery via `getifaddrs`, `/sys/class/net`, and `/proc/net/dev`.

use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::net::model::{parse_mac, NetworkInterface};

use super::system::{read_dns_servers, read_gateways};

/// Computes the 32-bit netmask from a CIDR prefix length (`0..=32`).
pub fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

/// Computes the network base IPv4 address for `(ip, prefix)`.
pub fn network_addr(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = prefix_mask(prefix);
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn read_iface_counters() -> HashMap<String, (u64, u64)> {
    let mut map = HashMap::new();
    let Ok(raw) = fs::read_to_string("/proc/net/dev") else {
        return map;
    };
    for line in raw.lines().skip(2) {
        let Some((name_part, stats_part)) = line.split_once(':') else {
            continue;
        };
        let nums: Vec<u64> = stats_part
            .split_whitespace()
            .filter_map(|t| t.parse::<u64>().ok())
            .collect();
        if nums.len() >= 9 {
            map.insert(name_part.trim().to_string(), (nums[0], nums[8]));
        }
    }
    map
}

fn read_iface_mac(name: &str) -> Option<[u8; 6]> {
    let raw = fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    let mac = parse_mac(&raw)?;
    if mac == [0; 6] {
        None
    } else {
        Some(mac)
    }
}

fn is_virtual_iface(name: &str) -> bool {
    let sys_dev = format!("/sys/class/net/{name}/device");
    if !Path::new(&sys_dev).exists() {
        return true;
    }
    let prefixes = [
        "lo",
        "docker",
        "br-",
        "veth",
        "virbr",
        "tun",
        "tap",
        "wg",
        "podman",
        "cni",
        "flannel",
        "tailscale",
    ];
    prefixes.iter().any(|p| name.starts_with(p))
}

/// Enumerates local IPv4 network interfaces with subnet CIDR, MAC, gateway, DNS, and byte counters.
pub fn collect_interfaces(show_virtual: bool) -> Vec<NetworkInterface> {
    let gateways = read_gateways();
    let dns = read_dns_servers();
    let counters = read_iface_counters();

    let mut by_name: BTreeMap<String, NetworkInterface> = BTreeMap::new();
    let mut ptr: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ptr) } != 0 || ptr.is_null() {
        return Vec::new();
    }

    let mut cur = ptr;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        if family != libc::AF_INET {
            continue;
        }

        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let is_up = (ifa.ifa_flags & (libc::IFF_UP as u32)) != 0;
        let is_loopback = (ifa.ifa_flags & (libc::IFF_LOOPBACK as u32)) != 0;
        if is_loopback {
            continue;
        }

        let sin = unsafe { &*(ifa.ifa_addr.cast::<libc::sockaddr_in>()) };
        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let prefix_len = if !ifa.ifa_netmask.is_null() {
            let nsin = unsafe { &*(ifa.ifa_netmask.cast::<libc::sockaddr_in>()) };
            u32::from_be(nsin.sin_addr.s_addr).leading_ones() as u8
        } else {
            24
        };

        let net = network_addr(ip, prefix_len);
        let cidr = format!("{net}/{prefix_len}");
        let is_virtual = is_virtual_iface(&name);
        let keep_tailscale = name.starts_with("tailscale") && is_up;
        if !show_virtual && is_virtual && !keep_tailscale {
            continue;
        }

        let is_wireless = Path::new(&format!("/sys/class/net/{name}/wireless")).exists()
            || name.starts_with("wl");
        let (rx_bytes, tx_bytes) = counters.get(&name).copied().unwrap_or((0, 0));

        by_name
            .entry(name.clone())
            .or_insert_with(|| NetworkInterface {
                name: name.clone(),
                ip,
                prefix_len,
                cidr,
                mac: read_iface_mac(&name),
                is_up,
                is_loopback,
                is_virtual,
                is_wireless,
                gateway: gateways.get(&name).copied(),
                dns_servers: dns.clone(),
                rx_bytes,
                tx_bytes,
                rx_bps: 0.0,
                tx_bps: 0.0,
                rx_history: vec![0.0; 24],
                tx_history: vec![0.0; 24],
            });
    }

    unsafe {
        libc::freeifaddrs(ptr);
    }

    let mut list: Vec<NetworkInterface> = by_name.into_values().collect();
    list.sort_by(|a, b| {
        b.gateway
            .is_some()
            .cmp(&a.gateway.is_some())
            .then_with(|| b.is_up.cmp(&a.is_up))
            .then_with(|| a.is_virtual.cmp(&b.is_virtual))
            .then_with(|| a.name.cmp(&b.name))
    });
    list
}
