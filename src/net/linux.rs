//! Native Linux telemetry collector reading `/proc/net/*`, `/sys/class/net/*`, and `getifaddrs`.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::model::{
    parse_mac, ArpState, LocalSocket, NetworkInterface, PrivilegeLevel, SocketState,
};
use crate::net::oui::lookup_vendor;

/// Parsed entry from `/proc/net/arp` or `ip neigh`.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: Option<[u8; 6]>,
    pub state: ArpState,
    pub interface: String,
    pub ipv6: Option<String>,
}

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

/// Parses a `/proc/net/route` 8-char hex IPv4 word into `Ipv4Addr`.
pub fn parse_proc_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let val = u32::from_str_radix(hex.trim(), 16).ok()?;
    Some(Ipv4Addr::from(val.to_ne_bytes()))
}

/// Collects all Linux network interfaces, addresses, counters, gateways, and DNS.
pub fn collect_interfaces(prev: &[NetworkInterface], elapsed_secs: f64) -> Vec<NetworkInterface> {
    let dev_stats = read_proc_net_dev();
    let gateways = read_gateways();
    let dns = read_dns_servers();
    let ifaddrs = collect_ifaddrs();

    let mut names: Vec<String> = dev_stats.keys().cloned().collect();
    for name in ifaddrs.keys() {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    names.sort_by(|a, b| {
        let rank = |n: &str| {
            if n == "lo" {
                5
            } else if n.starts_with("veth") {
                6
            } else if gateways.contains_key(n) {
                0
            } else if ifaddrs.get(n).and_then(|x| x.ipv4).is_some() {
                if n.starts_with("br-") || n.starts_with("docker") || n.starts_with("virbr") {
                    2
                } else {
                    1
                }
            } else {
                3
            }
        };
        rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
    });

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let sys_dir = Path::new("/sys/class/net").join(&name);
        let operstate = fs::read_to_string(sys_dir.join("operstate"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let is_loopback = name == "lo";
        let is_virtual = is_loopback || name.starts_with("veth");
        let addr_info = ifaddrs.get(&name);
        let is_up = operstate == "up"
            || (operstate == "unknown" && addr_info.and_then(|a| a.ipv4).is_some());

        let mac = fs::read_to_string(sys_dir.join("address"))
            .ok()
            .and_then(|s| parse_mac(s.trim()));
        let vendor = mac.and_then(|m| lookup_vendor(m).0);
        let mtu = fs::read_to_string(sys_dir.join("mtu"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(1500);
        let speed_mbps = fs::read_to_string(sys_dir.join("speed"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .filter(|&v| v > 0)
            .map(|v| v as u32);

        let (rx_bytes, tx_bytes) = dev_stats.get(&name).copied().unwrap_or((0, 0));
        let prev_iface = prev.iter().find(|i| i.name == name);
        let dt = elapsed_secs.max(0.2);
        let (rx_rate_bps, tx_rate_bps, mut rx_history, mut tx_history) = if let Some(p) = prev_iface
        {
            let rx_rate = rx_bytes.saturating_sub(p.rx_bytes) as f64 / dt;
            let tx_rate = tx_bytes.saturating_sub(p.tx_bytes) as f64 / dt;
            let mut rxh = p.rx_history.clone();
            let mut txh = p.tx_history.clone();
            rxh.push(rx_rate);
            txh.push(tx_rate);
            if rxh.len() > 60 {
                rxh.remove(0);
            }
            if txh.len() > 60 {
                txh.remove(0);
            }
            (rx_rate, tx_rate, rxh, txh)
        } else {
            (0.0, 0.0, vec![0.0], vec![0.0])
        };
        if rx_history.is_empty() {
            rx_history.push(0.0);
        }
        if tx_history.is_empty() {
            tx_history.push(0.0);
        }

        let ipv4 = addr_info.and_then(|a| a.ipv4);
        let prefix_len = addr_info.map(|a| a.prefix_len).unwrap_or(24);
        let netmask = addr_info.and_then(|a| a.netmask);
        let broadcast = addr_info.and_then(|a| a.broadcast);
        let ipv6_list = addr_info.map(|a| a.ipv6_list.clone()).unwrap_or_default();
        let cidr = match ipv4 {
            Some(ip) => format!("{}/{}", network_addr(ip, prefix_len), prefix_len),
            None => "no-ipv4".to_string(),
        };

        let gateway = gateways.get(&name).copied();
        let iface_dns = if ipv4.is_some() && !is_loopback {
            dns.clone()
        } else {
            Vec::new()
        };

        out.push(NetworkInterface {
            name,
            is_up,
            is_loopback,
            is_virtual,
            ipv4,
            prefix_len,
            cidr,
            netmask,
            broadcast,
            ipv6_list,
            mac,
            vendor,
            gateway,
            dns_servers: iface_dns,
            mtu,
            speed_mbps,
            rx_bytes,
            tx_bytes,
            rx_rate_bps,
            tx_rate_bps,
            rx_history,
            tx_history,
        });
    }
    out
}

/// Computes the network base address for `ip/prefix_len`.
pub fn network_addr(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = prefix_mask(prefix_len);
    Ipv4Addr::from(u32::from(ip) & mask)
}

/// Computes the 32-bit bitmask for a CIDR prefix length.
pub const fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

#[derive(Default)]
struct RawIfAddrs {
    ipv4: Option<Ipv4Addr>,
    prefix_len: u8,
    netmask: Option<Ipv4Addr>,
    broadcast: Option<Ipv4Addr>,
    ipv6_list: Vec<String>,
}

fn collect_ifaddrs() -> HashMap<String, RawIfAddrs> {
    let mut map: HashMap<String, RawIfAddrs> = HashMap::new();
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    unsafe {
        if libc::getifaddrs(&mut head) != 0 || head.is_null() {
            return map;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let entry = map.entry(name).or_default();
                let family = i32::from((*ifa.ifa_addr).sa_family);
                if family == libc::AF_INET {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if entry.ipv4.is_none() {
                        entry.ipv4 = Some(ip);
                        if !ifa.ifa_netmask.is_null() {
                            let nmask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                            let mask_u32 = u32::from_be(nmask.sin_addr.s_addr);
                            entry.netmask = Some(Ipv4Addr::from(mask_u32));
                            entry.prefix_len = mask_u32.count_ones() as u8;
                        }
                        if (ifa.ifa_flags & (libc::IFF_BROADCAST as u32)) != 0
                            && !ifa.ifa_ifu.is_null()
                        {
                            let bcast = &*(ifa.ifa_ifu as *const libc::sockaddr_in);
                            let bcast_ip = Ipv4Addr::from(u32::from_be(bcast.sin_addr.s_addr));
                            if !bcast_ip.is_unspecified() {
                                entry.broadcast = Some(bcast_ip);
                            }
                        }
                    }
                } else if family == libc::AF_INET6 {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let octets = sin6.sin6_addr.s6_addr;
                    let v6 = std::net::Ipv6Addr::from(octets);
                    let s = v6.to_string();
                    if !entry.ipv6_list.contains(&s) {
                        entry.ipv6_list.push(s);
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    map
}

fn read_proc_net_dev() -> HashMap<String, (u64, u64)> {
    let mut map = HashMap::new();
    let Ok(raw) = fs::read_to_string("/proc/net/dev") else {
        return map;
    };
    for line in raw.lines().skip(2) {
        let Some((name_part, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name_part.trim().to_string();
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() >= 9 {
            let rx = cols[0].parse::<u64>().unwrap_or(0);
            let tx = cols[8].parse::<u64>().unwrap_or(0);
            map.insert(name, (rx, tx));
        }
    }
    map
}

/// Reads `/proc/net/arp` and optionally enriches neighbor states with `ip neigh show`.
pub fn read_arp_entries() -> Vec<ArpEntry> {
    let mut by_key: HashMap<(Ipv4Addr, String), ArpEntry> = HashMap::new();
    if let Ok(raw) = fs::read_to_string("/proc/net/arp") {
        for line in raw.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 {
                continue;
            }
            let Ok(ip) = cols[0].parse::<Ipv4Addr>() else {
                continue;
            };
            let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).unwrap_or(0);
            let mac = parse_mac(cols[3]);
            if flags == 0 || mac.is_none() {
                continue;
            }
            let state = if (flags & 0x04) != 0 {
                ArpState::Permanent
            } else {
                ArpState::Reachable
            };
            let iface = cols[5].to_string();
            by_key.insert(
                (ip, iface.clone()),
                ArpEntry {
                    ip,
                    mac,
                    state,
                    interface: iface,
                    ipv6: None,
                },
            );
        }
    }

    // Enrich with `ip neigh show` for exact REACHABLE/STALE/DELAY states and IPv6 correlation.
    if let Ok(output) = Command::new("ip").args(["neigh", "show"]).output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut mac_to_v6: HashMap<String, String> = HashMap::new();
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let addr_str = parts[0];
                let mut dev = "";
                let mut lladdr = None;
                let mut i = 1;
                while i < parts.len() {
                    if parts[i] == "dev" && i + 1 < parts.len() {
                        dev = parts[i + 1];
                        i += 2;
                    } else if parts[i] == "lladdr" && i + 1 < parts.len() {
                        lladdr = parse_mac(parts[i + 1]);
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                let state = match parts.last().copied().unwrap_or("") {
                    "REACHABLE" => ArpState::Reachable,
                    "STALE" => ArpState::Stale,
                    "DELAY" => ArpState::Delay,
                    "PROBE" => ArpState::Probe,
                    "PERMANENT" => ArpState::Permanent,
                    _ => ArpState::Unknown,
                };
                if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                    if let Some(mac) = lladdr {
                        let key = (ip, dev.to_string());
                        by_key
                            .entry(key)
                            .and_modify(|e| {
                                e.mac = Some(mac);
                                if state != ArpState::Unknown {
                                    e.state = state;
                                }
                            })
                            .or_insert(ArpEntry {
                                ip,
                                mac: Some(mac),
                                state,
                                interface: dev.to_string(),
                                ipv6: None,
                            });
                    }
                } else if addr_str.contains(':') && !addr_str.starts_with("fe80::") {
                    if let Some(mac) = lladdr {
                        mac_to_v6.insert(crate::net::model::format_mac(mac), addr_str.to_string());
                    }
                }
            }
            for entry in by_key.values_mut() {
                if let Some(m) = entry.mac {
                    let ms = crate::net::model::format_mac(m);
                    if let Some(v6) = mac_to_v6.get(&ms) {
                        entry.ipv6 = Some(v6.clone());
                    }
                }
            }
        }
    }

    let mut entries: Vec<ArpEntry> = by_key.into_values().collect();
    entries.sort_by_key(|a| a.ip);
    entries
}

/// Reads active TCP/UDP sockets from `/proc/net/{tcp,tcp6,udp,udp6}` and maps inodes to PIDs.
pub fn collect_local_sockets(resolve_pids: bool) -> Vec<LocalSocket> {
    let inode_map = if resolve_pids {
        build_socket_inode_map()
    } else {
        HashMap::new()
    };

    let mut sockets = Vec::new();
    for (proto, path, is_v6) in [
        ("TCP", "/proc/net/tcp", false),
        ("TCP6", "/proc/net/tcp6", true),
        ("UDP", "/proc/net/udp", false),
        ("UDP6", "/proc/net/udp6", true),
    ] {
        if let Ok(raw) = fs::read_to_string(path) {
            parse_proc_net_sockets(proto, &raw, is_v6, &inode_map, &mut sockets);
        }
    }

    sockets.sort_by(|a, b| {
        let rank = |s: SocketState| match s {
            SocketState::Established => 0,
            SocketState::Listen => 1,
            SocketState::SynSent => 2,
            SocketState::CloseWait => 3,
            SocketState::TimeWait => 4,
            SocketState::Other => 5,
        };
        rank(a.state)
            .cmp(&rank(b.state))
            .then_with(|| a.local_port.cmp(&b.local_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });
    sockets
}

fn parse_proc_net_sockets(
    proto: &str,
    raw: &str,
    is_v6: bool,
    inode_map: &HashMap<u64, (u32, String)>,
    out: &mut Vec<LocalSocket>,
) {
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((local_addr, local_port, _)) = parse_hex_endpoint(cols[1], is_v6) else {
            continue;
        };
        let Some((remote_addr, remote_port, remote_ip_v4)) = parse_hex_endpoint(cols[2], is_v6)
        else {
            continue;
        };
        let state = match cols[3] {
            "01" => SocketState::Established,
            "02" => SocketState::SynSent,
            "06" => SocketState::TimeWait,
            "08" => SocketState::CloseWait,
            "0A" => SocketState::Listen,
            _ => SocketState::Other,
        };
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let (pid, process) = inode_map
            .get(&inode)
            .map(|(p, n)| (Some(*p), Some(n.clone())))
            .unwrap_or((None, None));

        out.push(LocalSocket {
            proto: proto.to_string(),
            local_addr,
            local_port,
            remote_addr,
            remote_ip_v4,
            remote_port,
            state,
            pid,
            process,
            inode,
        });
    }
}

fn parse_hex_endpoint(token: &str, is_v6: bool) -> Option<(String, u16, Option<Ipv4Addr>)> {
    let (ip_hex, port_hex) = token.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if !is_v6 && ip_hex.len() == 8 {
        let ip = parse_proc_hex_ipv4(ip_hex)?;
        let s = format!("{ip}:{port}");
        let v4 = if ip.is_unspecified() { None } else { Some(ip) };
        Some((s, port, v4))
    } else if is_v6 && ip_hex.len() == 32 {
        let mut bytes = [0u8; 16];
        for (chunk_idx, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let word = u32::from_str_radix(&ip_hex[chunk_idx * 8..chunk_idx * 8 + 8], 16).ok()?;
            chunk.copy_from_slice(&word.to_ne_bytes());
        }
        let v6 = std::net::Ipv6Addr::from(bytes);
        let v4 = v6.to_ipv4_mapped().filter(|ip| !ip.is_unspecified());
        Some((format!("[{v6}]:{port}"), port, v4))
    } else {
        None
    }
}

fn build_socket_inode_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let pid_str = fname.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        let mut comm: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = link.to_string_lossy();
            if let Some(rest) = target.strip_prefix("socket:[") {
                if let Some(num) = rest.strip_suffix(']') {
                    if let Ok(inode) = num.parse::<u64>() {
                        let name = comm.get_or_insert_with(|| {
                            fs::read_to_string(entry.path().join("comm"))
                                .map(|s| s.trim().to_string())
                                .unwrap_or_else(|_| "proc".to_string())
                        });
                        map.entry(inode).or_insert_with(|| (pid, name.clone()));
                    }
                }
            }
        }
    }
    map
}
