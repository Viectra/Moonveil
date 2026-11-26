//! Lecture de `/proc/net/*` : table ARP, sockets locaux TCP/UDP et résolution inode → PID.

use super::*;

/// Parsed entry from `/proc/net/arp` or `ip neigh`.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: Option<[u8; 6]>,
    pub state: ArpState,
    pub interface: String,
    pub ipv6: Option<String>,
}

/// Parses a `/proc/net/route` 8-char hex IPv4 word into `Ipv4Addr`.
pub fn parse_proc_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let val = u32::from_str_radix(hex.trim(), 16).ok()?;
    Some(Ipv4Addr::from(val.to_ne_bytes()))
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

pub(super) fn parse_proc_net_sockets(
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

pub(super) fn parse_hex_endpoint(
    token: &str,
    is_v6: bool,
) -> Option<(String, u16, Option<Ipv4Addr>)> {
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

pub(super) fn build_socket_inode_map() -> HashMap<u64, (u32, String)> {
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
