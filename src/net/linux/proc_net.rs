//! Linux `/proc/net` parsers: ARP neighbor table, local TCP/UDP sockets with PIDs, and Tailscale peers.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::net::model::{parse_mac, ArpState, LocalSocket, SocketState};

/// Parsed entry from `/proc/net/arp`.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: Option<[u8; 6]>,
    pub state: ArpState,
    pub iface: String,
}

/// Tailscale mesh peer discovered from local `tailscale status --json`.
#[derive(Debug, Clone)]
pub struct TailscalePeer {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub dns_name: Option<String>,
    pub online: bool,
    pub os: Option<String>,
}

/// Parses an 8-character `/proc/net` hex-encoded IPv4 address using host endianness.
pub fn parse_proc_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(raw.to_ne_bytes()))
}

fn parse_proc_hex_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for word in 0..4 {
        let slice = &hex[word * 8..(word + 1) * 8];
        let val = u32::from_str_radix(slice, 16).ok()?;
        let bytes = val.to_ne_bytes();
        octets[word * 4..word * 4 + 4].copy_from_slice(&bytes);
    }
    Some(Ipv6Addr::from(octets))
}

/// Reads the Linux kernel ARP cache from `/proc/net/arp`.
pub fn read_arp_entries() -> Vec<ArpEntry> {
    let mut out = Vec::new();
    let Ok(raw) = fs::read_to_string("/proc/net/arp") else {
        return out;
    };
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let Ok(ip) = cols[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).unwrap_or(0);
        let mac = parse_mac(cols[3]).filter(|m| *m != [0; 6]);
        let state = if mac.is_none() || flags == 0 {
            ArpState::Incomplete
        } else if (flags & 0x2) != 0 {
            ArpState::Reachable
        } else {
            ArpState::Stale
        };
        out.push(ArpEntry {
            ip,
            mac,
            state,
            iface: cols[5].to_string(),
        });
    }
    out
}

#[derive(Deserialize)]
struct TsStatus {
    #[serde(rename = "Self")]
    self_node: Option<TsNode>,
    #[serde(rename = "Peer")]
    peers: Option<HashMap<String, TsNode>>,
}

#[derive(Deserialize)]
struct TsNode {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Online")]
    online: Option<bool>,
    #[serde(rename = "OS")]
    os: Option<String>,
}

fn push_ts_node(node: TsNode, out: &mut Vec<TailscalePeer>) {
    let Some(ips) = node.tailscale_ips else {
        return;
    };
    let Some(ip) = ips.iter().find_map(|s| s.parse::<Ipv4Addr>().ok()) else {
        return;
    };
    let dns_label = node
        .dns_name
        .as_deref()
        .and_then(|s| s.trim_end_matches('.').split('.').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let hostname = node
        .host_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| dns_label.clone());
    out.push(TailscalePeer {
        ip,
        hostname,
        dns_name: dns_label,
        online: node.online.unwrap_or(false),
        os: node.os,
    });
}

/// Reads active Tailscale peers from local `tailscale status --json` when available.
pub fn read_tailscale_peers() -> Vec<TailscalePeer> {
    let Ok(output) = Command::new("tailscale")
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let Ok(status) = serde_json::from_slice::<TsStatus>(&output.stdout) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(self_node) = status.self_node {
        push_ts_node(self_node, &mut out);
    }
    if let Some(peers) = status.peers {
        for (_, peer) in peers {
            push_ts_node(peer, &mut out);
        }
    }
    out
}

fn map_inode_processes() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for ent in entries.flatten() {
        let fname = ent.file_name();
        let Some(pid_s) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_s.parse::<u32>() else {
            continue;
        };
        let comm = fs::read_to_string(ent.path().join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let fd_dir = ent.path().join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if let Some(t) = target.to_str() {
                    if let Some(inode_s) =
                        t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_s.parse::<u64>() {
                            if !comm.is_empty() {
                                map.entry(inode).or_insert_with(|| (pid, comm.clone()));
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

fn parse_socket_endpoint(token: &str, is_v6: bool) -> Option<(String, Option<Ipv4Addr>, u16)> {
    let (ip_hex, port_hex) = token.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if !is_v6 {
        let ip = parse_proc_hex_ipv4(ip_hex)?;
        Some((format!("{ip}:{port}"), Some(ip), port))
    } else {
        let v6 = parse_proc_hex_ipv6(ip_hex)?;
        let v4 = v6.to_ipv4_mapped();
        let addr_str = match v4 {
            Some(ipv4) => format!("{ipv4}:{port}"),
            None => format!("[{v6}]:{port}"),
        };
        Some((addr_str, v4, port))
    }
}

fn decode_socket_state(hex_state: &str) -> SocketState {
    match u8::from_str_radix(hex_state, 16).unwrap_or(0) {
        0x01 => SocketState::Established,
        0x02 => SocketState::SynSent,
        0x03 => SocketState::SynRecv,
        0x04 | 0x05 => SocketState::FinWait,
        0x06 => SocketState::TimeWait,
        0x08 => SocketState::CloseWait,
        0x0A => SocketState::Listen,
        _ => SocketState::Other,
    }
}

fn parse_proc_socket_file(
    path: &str,
    proto: &str,
    is_v6: bool,
    inodes: &HashMap<u64, (u32, String)>,
    out: &mut Vec<LocalSocket>,
) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((local_addr, local_ip_v4, local_port)) = parse_socket_endpoint(cols[1], is_v6)
        else {
            continue;
        };
        let Some((remote_addr, remote_ip_v4, remote_port)) = parse_socket_endpoint(cols[2], is_v6)
        else {
            continue;
        };
        let state = decode_socket_state(cols[3]);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let (pid, process) = if let Some((p, name)) = inodes.get(&inode) {
            (Some(*p), Some(name.clone()))
        } else {
            (None, None)
        };
        out.push(LocalSocket {
            proto: proto.to_string(),
            local_addr,
            local_ip_v4,
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

/// Collects local TCP/UDP IPv4+IPv6 sockets from `/proc/net` and correlates PIDs via `/proc/<pid>/fd`.
pub fn collect_local_sockets(skip_pid_lookup: bool) -> Vec<LocalSocket> {
    let inodes = if skip_pid_lookup {
        HashMap::new()
    } else {
        map_inode_processes()
    };
    let mut sockets = Vec::new();
    parse_proc_socket_file("/proc/net/tcp", "TCP", false, &inodes, &mut sockets);
    parse_proc_socket_file("/proc/net/tcp6", "TCP6", true, &inodes, &mut sockets);
    parse_proc_socket_file("/proc/net/udp", "UDP", false, &inodes, &mut sockets);
    parse_proc_socket_file("/proc/net/udp6", "UDP6", true, &inodes, &mut sockets);
    sockets
}
