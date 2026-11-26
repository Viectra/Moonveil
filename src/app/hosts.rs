//! Host seeding, kernel ARP/known-host metadata merge, and local socket correlation.

use std::collections::{BTreeSet, HashSet};

use crate::net::linux::{read_arp_entries, read_etc_hosts, read_tailscale_peers};
use crate::net::model::{
    clean_discovered_hostname, format_mac, format_oui, infer_role, service_info, ArpState,
    DeviceRole, Host, PortInfo, PortState, Proto, SocketState,
};
use crate::net::oui::lookup_vendor;

use super::App;

impl App {
    /// Pre-populates hosts immediately on startup from ARP, Tailscale peers, and interface defaults.
    pub(super) fn seed_initial_hosts(&mut self) {
        if self.demo_mode {
            return;
        }
        let Some(iface) = self.active_interface().cloned() else {
            return;
        };
        let etc_hosts = read_etc_hosts();
        let mut hosts = Vec::new();
        let mut seen = HashSet::new();

        // Always include This PC on the active interface.
        let (vendor, is_rand) = iface.mac.map(lookup_vendor).unwrap_or((None, false));
        seen.insert(iface.ip);
        hosts.push(Host {
            ip: iface.ip,
            ipv6: None,
            hostname: Some(self.snapshot.hostname.clone()),
            nickname: None,
            mac: iface.mac,
            oui_prefix: iface.mac.map(format_oui),
            vendor,
            is_randomized_mac: is_rand,
            online: true,
            trusted: true,
            role: DeviceRole::ThisMachine,
            arp_state: ArpState::Reachable,
            ttl: Some(64),
            os_guess: Some("Linux / Unix".to_string()),
            rtt_ms: Some(0.1),
            rtt_history: vec![0.1],
            jitter_ms: None,
            packet_loss_pct: 0.0,
            ports: Vec::new(),
            first_seen_epoch: 0,
            last_seen_epoch: 0,
            discovered_tick: 0,
            subnet_cidr: iface.cidr.clone(),
            interface: iface.name.clone(),
            is_new: false,
        });

        for entry in read_arp_entries() {
            if entry.iface != iface.name || !seen.insert(entry.ip) {
                continue;
            }
            let (v, rand_mac) = entry.mac.map(lookup_vendor).unwrap_or((None, false));
            let is_gw = Some(entry.ip) == iface.gateway;
            let hn = etc_hosts
                .get(&entry.ip)
                .and_then(|s| clean_discovered_hostname(s));
            hosts.push(Host {
                ip: entry.ip,
                ipv6: None,
                hostname: hn.clone(),
                nickname: None,
                mac: entry.mac,
                oui_prefix: entry.mac.map(format_oui),
                vendor: v.clone(),
                is_randomized_mac: rand_mac,
                online: entry.state == ArpState::Reachable,
                trusted: is_gw,
                role: infer_role(false, is_gw, v.as_deref(), hn.as_deref(), &[]),
                arp_state: entry.state,
                ttl: None,
                os_guess: None,
                rtt_ms: None,
                rtt_history: Vec::new(),
                jitter_ms: None,
                packet_loss_pct: 0.0,
                ports: Vec::new(),
                first_seen_epoch: 0,
                last_seen_epoch: 0,
                discovered_tick: 0,
                subnet_cidr: iface.cidr.clone(),
                interface: iface.name.clone(),
                is_new: false,
            });
        }

        if iface.name.starts_with("tailscale") || iface.prefix_len == 32 {
            for peer in read_tailscale_peers() {
                if !seen.insert(peer.ip) {
                    continue;
                }
                let hn = peer
                    .hostname
                    .as_deref()
                    .and_then(clean_discovered_hostname)
                    .or_else(|| peer.dns_name.as_deref().and_then(clean_discovered_hostname));
                hosts.push(Host {
                    ip: peer.ip,
                    ipv6: None,
                    hostname: hn,
                    nickname: None,
                    mac: None,
                    oui_prefix: None,
                    vendor: Some("Tailscale".to_string()),
                    is_randomized_mac: false,
                    online: peer.online,
                    trusted: true,
                    role: DeviceRole::Workstation,
                    arp_state: if peer.online {
                        ArpState::Reachable
                    } else {
                        ArpState::Stale
                    },
                    ttl: None,
                    os_guess: peer.os,
                    rtt_ms: None,
                    rtt_history: Vec::new(),
                    jitter_ms: None,
                    packet_loss_pct: 0.0,
                    ports: Vec::new(),
                    first_seen_epoch: 0,
                    last_seen_epoch: 0,
                    discovered_tick: 0,
                    subnet_cidr: iface.cidr.clone(),
                    interface: iface.name.clone(),
                    is_new: false,
                });
            }
        }

        hosts.sort_by_key(|h| h.ip);
        self.snapshot.hosts = hosts;
        self.refresh_in_use_from_sockets();
    }

    pub(super) fn apply_known_hosts_to_snapshot(&mut self) {
        for host in &mut self.snapshot.hosts {
            if let Some(mac) = host.mac {
                let key = format_mac(mac);
                if let Some(saved) = self.known_hosts.get(&key) {
                    if host.nickname.is_none() {
                        host.nickname = saved.nickname.clone();
                    }
                    if saved.trusted {
                        host.trusted = true;
                    }
                }
            }
        }
    }

    /// Re-correlates `/proc/net` sockets with discovered hosts to keep `InUse` & local ports accurate.
    pub(super) fn refresh_in_use_from_sockets(&mut self) {
        let local_ip = self.active_interface().map(|i| i.ip);
        let sockets = &self.snapshot.local_sockets;

        for host in &mut self.snapshot.hosts {
            let is_local = local_ip == Some(host.ip);
            if is_local {
                let mut seen_ports: BTreeSet<u16> = host.ports.iter().map(|p| p.port).collect();
                for s in sockets {
                    if !s.proto.starts_with("TCP") || s.local_port == 0 {
                        continue;
                    }
                    let ip_matches = s
                        .local_ip_v4
                        .map(|lip| lip.is_unspecified() || lip == host.ip || lip.is_loopback())
                        .unwrap_or(true);
                    if ip_matches
                        && s.state == SocketState::Listen
                        && seen_ports.insert(s.local_port)
                    {
                        let (svc, desc) = service_info(s.local_port);
                        host.ports.push(PortInfo {
                            port: s.local_port,
                            proto: Proto::Tcp,
                            state: PortState::Open,
                            service: svc.to_string(),
                            description: desc.to_string(),
                            banner: None,
                            banner_hex: None,
                            latency_ms: Some(0.1),
                            process: s.process.clone(),
                            pid: s.pid,
                            peer_endpoint: None,
                        });
                    }
                }
            }

            for port in &mut host.ports {
                if !matches!(port.state, PortState::Open | PortState::InUse) {
                    continue;
                }
                if is_local {
                    let estab = sockets.iter().find(|s| {
                        s.proto.starts_with("TCP")
                            && s.state == SocketState::Established
                            && s.local_port == port.port
                            && s.local_ip_v4
                                .map(|lip| {
                                    lip.is_unspecified() || lip == host.ip || lip.is_loopback()
                                })
                                .unwrap_or(true)
                    });
                    if let Some(s) = estab {
                        port.state = PortState::InUse;
                        port.process = s.process.clone().or_else(|| port.process.clone());
                        port.pid = s.pid.or(port.pid);
                        port.peer_endpoint = Some(s.remote_addr.clone());
                    } else if let Some(s) = sockets.iter().find(|s| {
                        s.proto.starts_with("TCP")
                            && s.state == SocketState::Listen
                            && s.local_port == port.port
                            && s.local_ip_v4
                                .map(|lip| {
                                    lip.is_unspecified() || lip == host.ip || lip.is_loopback()
                                })
                                .unwrap_or(true)
                    }) {
                        port.state = PortState::Open;
                        if port.process.is_none() {
                            port.process = s.process.clone();
                            port.pid = s.pid;
                        }
                        port.peer_endpoint = None;
                    }
                } else if let Some(s) = sockets.iter().find(|s| {
                    s.proto.starts_with("TCP")
                        && s.state == SocketState::Established
                        && s.remote_ip_v4 == Some(host.ip)
                        && s.remote_port == port.port
                }) {
                    port.state = PortState::InUse;
                    port.process = s.process.clone().or_else(|| port.process.clone());
                    port.pid = s.pid.or(port.pid);
                    port.peer_endpoint = Some(s.local_addr.clone());
                }
            }
        }
    }

    pub fn upsert_host(&mut self, mut host: Host) {
        if let Some(mac) = host.mac {
            let key = format_mac(mac);
            if let Some(saved) = self.known_hosts.get(&key) {
                if host.nickname.is_none() {
                    host.nickname = saved.nickname.clone();
                }
                if saved.trusted {
                    host.trusted = true;
                }
            } else {
                self.known_hosts.upsert(
                    &key,
                    host.ip,
                    host.nickname.clone(),
                    host.trusted,
                    host.vendor.clone(),
                    host.hostname.clone(),
                );
            }
        }
        if let Some(existing) = self.snapshot.hosts.iter_mut().find(|h| h.ip == host.ip) {
            if host.nickname.is_none() {
                host.nickname = existing.nickname.clone();
            }
            if existing.trusted {
                host.trusted = true;
            }
            if host.hostname.is_none() {
                host.hostname = existing.hostname.clone();
            }
            *existing = host;
        } else {
            self.snapshot.hosts.push(host);
            self.snapshot.hosts.sort_by_key(|h| h.ip);
        }
        if self.selected_host_ip.is_none() {
            self.selected_host_ip = self.snapshot.hosts.first().map(|h| h.ip);
        }
    }
}
