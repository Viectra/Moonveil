//! Collecte des interfaces réseau (`getifaddrs`, `/sys/class/net`, `/proc/net/dev`) et calculs de préfixes.

use super::*;

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
pub(super) struct RawIfAddrs {
    pub(super) ipv4: Option<Ipv4Addr>,
    pub(super) prefix_len: u8,
    pub(super) netmask: Option<Ipv4Addr>,
    pub(super) broadcast: Option<Ipv4Addr>,
    pub(super) ipv6_list: Vec<String>,
}

pub(super) fn collect_ifaddrs() -> HashMap<String, RawIfAddrs> {
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

pub(super) fn read_proc_net_dev() -> HashMap<String, (u64, u64)> {
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
