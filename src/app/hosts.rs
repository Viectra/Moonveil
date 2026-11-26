//! Préparation des hôtes : amorçage initial, métadonnées des hôtes connus et ports « en usage » via sockets locaux.

use super::*;

pub(super) fn seed_initial_hosts(snap: &mut NetworkSnapshot, known: &KnownHostStore) {
    let now = epoch_now();
    let arp = read_arp_entries();

    for iface in &snap.interfaces {
        if iface.is_virtual {
            continue;
        }
        if let Some(ip) = iface.ipv4 {
            snap.hosts.push(Host {
                ip,
                ipv6: iface.ipv6_list.first().cloned(),
                hostname: Some(snap.hostname.clone()),
                nickname: Some("This Machine".to_string()),
                mac: iface.mac,
                oui_prefix: iface.mac.map(format_oui),
                vendor: iface.vendor.clone(),
                is_randomized_mac: false,
                online: true,
                trusted: true,
                role: DeviceRole::ThisMachine,
                arp_state: ArpState::Local,
                ttl: Some(64),
                os_guess: Some("Linux".to_string()),
                rtt_ms: Some(0.05),
                rtt_history: vec![0.05],
                jitter_ms: None,
                packet_loss_pct: 0.0,
                ports: Vec::new(),
                first_seen_epoch: now,
                last_seen_epoch: now,
                discovered_tick: 0,
                subnet_cidr: iface.cidr.clone(),
                interface: iface.name.clone(),
                is_new: false,
            });
        }
        if let Some(gw) = iface.gateway {
            if !snap.hosts.iter().any(|h| h.ip == gw) {
                snap.hosts.push(Host {
                    ip: gw,
                    ipv6: None,
                    hostname: None,
                    nickname: Some("Gateway".to_string()),
                    mac: None,
                    oui_prefix: None,
                    vendor: None,
                    is_randomized_mac: false,
                    online: true,
                    trusted: true,
                    role: DeviceRole::Gateway,
                    arp_state: ArpState::Unknown,
                    ttl: None,
                    os_guess: None,
                    rtt_ms: None,
                    rtt_history: Vec::new(),
                    jitter_ms: None,
                    packet_loss_pct: 0.0,
                    ports: Vec::new(),
                    first_seen_epoch: now,
                    last_seen_epoch: now,
                    discovered_tick: 0,
                    subnet_cidr: iface.cidr.clone(),
                    interface: iface.name.clone(),
                    is_new: false,
                });
            }
        }
    }

    for entry in arp {
        let iface_obj = snap.interfaces.iter().find(|i| i.name == entry.interface);
        let subnet_cidr = iface_obj
            .map(|i| i.cidr.clone())
            .unwrap_or_else(|| "lan".to_string());
        let is_gw = iface_obj.is_some_and(|i| i.gateway == Some(entry.ip));
        let (vendor, rand) = entry.mac.map(lookup_vendor).unwrap_or((None, false));
        if let Some(h) = snap.hosts.iter_mut().find(|h| h.ip == entry.ip) {
            h.mac = entry.mac;
            h.oui_prefix = entry.mac.map(format_oui);
            h.vendor = vendor;
            h.is_randomized_mac = rand;
            h.arp_state = entry.state;
            h.ipv6 = entry.ipv6;
        } else {
            snap.hosts.push(Host {
                ip: entry.ip,
                ipv6: entry.ipv6,
                hostname: None,
                nickname: None,
                mac: entry.mac,
                oui_prefix: entry.mac.map(format_oui),
                vendor: vendor.clone(),
                is_randomized_mac: rand,
                online: true,
                trusted: false,
                role: infer_device_role(false, is_gw, vendor.as_deref(), None, &[]),
                arp_state: entry.state,
                ttl: None,
                os_guess: None,
                rtt_ms: None,
                rtt_history: Vec::new(),
                jitter_ms: None,
                packet_loss_pct: 0.0,
                ports: Vec::new(),
                first_seen_epoch: now,
                last_seen_epoch: now,
                discovered_tick: 0,
                subnet_cidr,
                interface: entry.interface,
                is_new: true,
            });
        }
    }

    // Add offline saved hosts matching primary subnet so Wake-on-LAN is always 1 click away.
    if let Some(primary) = snap
        .interfaces
        .iter()
        .find(|i| i.is_up && !i.is_virtual && i.ipv4.is_some())
    {
        if let Some(local_ip) = primary.ipv4 {
            let net = u32::from(network_addr(local_ip, primary.prefix_len));
            let mask = prefix_mask(primary.prefix_len);
            for k in known.hosts.values() {
                if let Ok(ip) = k.last_ip.parse::<Ipv4Addr>() {
                    if (u32::from(ip) & mask) == net && !snap.hosts.iter().any(|h| h.ip == ip) {
                        snap.hosts.push(Host {
                            ip,
                            ipv6: None,
                            hostname: k.hostname.clone(),
                            nickname: k.nickname.clone(),
                            mac: parse_mac(&k.mac),
                            oui_prefix: parse_mac(&k.mac).map(format_oui),
                            vendor: k.vendor.clone(),
                            is_randomized_mac: false,
                            online: false,
                            trusted: k.trusted,
                            role: DeviceRole::Host,
                            arp_state: ArpState::Unknown,
                            ttl: None,
                            os_guess: None,
                            rtt_ms: None,
                            rtt_history: Vec::new(),
                            jitter_ms: None,
                            packet_loss_pct: 0.0,
                            ports: Vec::new(),
                            first_seen_epoch: now,
                            last_seen_epoch: now,
                            discovered_tick: 0,
                            subnet_cidr: primary.cidr.clone(),
                            interface: primary.name.clone(),
                            is_new: false,
                        });
                    }
                }
            }
        }
    }
}

pub(super) fn apply_known_metadata(hosts: &mut [Host], known: &KnownHostStore) {
    for h in hosts {
        apply_single_known_metadata(h, known);
    }
}

pub(super) fn apply_single_known_metadata(h: &mut Host, known: &KnownHostStore) {
    if let Some(mac) = h.mac {
        let key = format_mac(mac);
        if let Some(entry) = known.hosts.get(&key) {
            h.trusted = entry.trusted;
            if entry.nickname.is_some() {
                h.nickname = entry.nickname.clone();
            }
            h.is_new = !h.trusted && h.online;
        }
    }
}

pub(super) fn refresh_in_use_from_sockets(snap: &mut NetworkSnapshot) {
    for host in &mut snap.hosts {
        let is_local = snap.interfaces.iter().any(|i| i.ipv4 == Some(host.ip));
        for port in &mut host.ports {
            if port.state != PortState::Open && port.state != PortState::InUse {
                continue;
            }
            let active = if is_local {
                snap.local_sockets.iter().find(|s| {
                    s.state == crate::net::model::SocketState::Established
                        && (s.local_port == port.port || s.remote_port == port.port)
                })
            } else {
                snap.local_sockets.iter().find(|s| {
                    s.state == crate::net::model::SocketState::Established
                        && s.remote_ip_v4 == Some(host.ip)
                        && s.remote_port == port.port
                })
            };
            if let Some(sock) = active {
                port.state = PortState::InUse;
                port.pid = sock.pid;
                port.process = sock.process.clone();
                port.peer_endpoint = Some(if is_local {
                    sock.remote_addr.clone()
                } else {
                    sock.local_addr.clone()
                });
            }
        }
    }
}
