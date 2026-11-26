//! Target generation, async subnet sweep orchestration, and concurrent port scanning.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, Semaphore};

use crate::net::linux::{
    collect_local_sockets, epoch_now, network_addr, read_arp_entries, read_etc_hosts,
    read_tailscale_peers, ArpEntry,
};
use crate::net::model::{
    clean_discovered_hostname, format_oui, guess_os_from_ttl, infer_role, ports_for_preset,
    NetworkInterface, PortState, SocketState,
};
use crate::net::oui::lookup_vendor;

use super::discovery::{probe_host_alive, resolve_hostname};
use super::probes::scan_ports_for_host;
use super::{make_skeleton_host, normalize_mac_opt, EngineEvent, ScanConfig};

/// Generates target IPv4 addresses for an interface scan slice.
pub fn compute_scan_targets(iface: &NetworkInterface, radar_page_offset: u32) -> Vec<Ipv4Addr> {
    if iface.prefix_len >= 31 {
        let mut set = BTreeSet::new();
        set.insert(iface.ip);
        if let Some(gw) = iface.gateway {
            set.insert(gw);
        }
        return set.into_iter().collect();
    }
    if iface.prefix_len >= 24 {
        let net = u32::from(network_addr(iface.ip, iface.prefix_len));
        let host_bits = 32 - u32::from(iface.prefix_len);
        let total = 1_u32 << host_bits;
        let mut out = Vec::with_capacity(total.saturating_sub(2) as usize);
        for offset in 1..total.saturating_sub(1) {
            out.push(Ipv4Addr::from(net + offset));
        }
        return out;
    }

    let base_net = u32::from(network_addr(iface.ip, iface.prefix_len));
    let total_pages = iface.slash24_page_count().max(1);
    let page = radar_page_offset % total_pages;
    let slice_base = base_net + page * 256;
    let mut out = Vec::with_capacity(255);
    for last in 1..=254_u32 {
        out.push(Ipv4Addr::from(slice_base + last));
    }
    if !out.contains(&iface.ip) {
        out.insert(0, iface.ip);
    }
    if let Some(gw) = iface.gateway {
        if !out.contains(&gw) {
            out.push(gw);
        }
    }
    out
}

/// Executes a full subnet sweep or single-host deep scan, streaming results via `tx`.
pub async fn run_scan(
    cfg: ScanConfig,
    cancel: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<EngineEvent>,
) {
    let start = Instant::now();
    let etc_hosts = read_etc_hosts();
    let arp_initial = read_arp_entries();
    let tailscale_peers =
        if cfg.interface.name.starts_with("tailscale") || cfg.interface.prefix_len == 32 {
            read_tailscale_peers()
        } else {
            Vec::new()
        };

    let mut ts_map: HashMap<Ipv4Addr, (Option<String>, bool, Option<String>)> = HashMap::new();
    let mut target_set: BTreeSet<Ipv4Addr> = BTreeSet::new();

    if let Some(single) = cfg.single_host {
        target_set.insert(single);
    } else {
        for ip in compute_scan_targets(&cfg.interface, cfg.radar_page_offset) {
            target_set.insert(ip);
        }
        for entry in &arp_initial {
            if entry.iface == cfg.interface.name {
                target_set.insert(entry.ip);
            }
        }
        for peer in tailscale_peers {
            target_set.insert(peer.ip);
            let name = peer
                .hostname
                .as_deref()
                .and_then(clean_discovered_hostname)
                .or_else(|| peer.dns_name.as_deref().and_then(clean_discovered_hostname));
            ts_map.insert(peer.ip, (name, peer.online, peer.os));
        }
    }

    let targets: Vec<Ipv4Addr> = target_set.into_iter().collect();
    let total = targets.len();
    let _ = tx.send(EngineEvent::ScanStarted {
        total_targets: total,
    });

    let arp_by_ip: HashMap<Ipv4Addr, ArpEntry> =
        arp_initial.into_iter().map(|e| (e.ip, e)).collect();
    let sem = Arc::new(Semaphore::new(cfg.concurrency.clamp(16, 512)));
    let probed = Arc::new(AtomicUsize::new(0));
    let timeout_ms = cfg.timeout_ms.clamp(80, 3000);
    let priv_level = cfg.privilege;

    let mut handles = Vec::with_capacity(total);
    for ip in targets {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let permit = Arc::clone(&sem);
        let tx_c = tx.clone();
        let cancel_c = Arc::clone(&cancel);
        let arp_hit = arp_by_ip.get(&ip).and_then(|e| e.mac).is_some()
            || ip == cfg.interface.ip
            || ts_map
                .get(&ip)
                .map(|(_, online, _)| *online)
                .unwrap_or(false);
        let force_single = cfg.single_host == Some(ip);
        let probed_c = Arc::clone(&probed);

        handles.push(tokio::spawn(async move {
            let Ok(_p) = permit.acquire().await else {
                return None;
            };
            if cancel_c.load(Ordering::Relaxed) {
                return None;
            }
            let (alive, ttl, rtt_ms) = match probe_host_alive(ip, timeout_ms, priv_level).await {
                Some((rtt, t)) => (true, t, Some(rtt)),
                None => (arp_hit, None, None),
            };
            let done = probed_c.fetch_add(1, Ordering::Relaxed) + 1;
            if done.is_multiple_of(8) || done == total || alive {
                let _ = tx_c.send(EngineEvent::ScanProgress {
                    probed: done,
                    total,
                    target: ip.to_string(),
                });
            }
            if alive || force_single {
                Some((ip, alive, ttl, rtt_ms))
            } else {
                None
            }
        }));
    }

    let mut live_hosts: Vec<(Ipv4Addr, bool, Option<u8>, Option<f64>)> = Vec::new();
    for h in handles {
        if let Ok(Some(item)) = h.await {
            live_hosts.push(item);
        }
    }

    if cancel.load(Ordering::Relaxed) {
        let _ = tx.send(EngineEvent::ScanCompleted {
            hosts_found: 0,
            ports_found: 0,
            elapsed_ms: start.elapsed().as_millis() as u64,
        });
        return;
    }

    // Re-read kernel ARP table right after probes so newly resolved L2 neighbors have MAC + OUI.
    let fresh_arp: HashMap<Ipv4Addr, ArpEntry> =
        read_arp_entries().into_iter().map(|e| (e.ip, e)).collect();
    let local_sockets = if cfg.local_sockets.is_empty() {
        collect_local_sockets(false)
    } else {
        cfg.local_sockets.clone()
    };

    let base_ports = ports_for_preset(cfg.preset, &cfg.custom_ports);
    let host_sem = Arc::new(Semaphore::new(64));
    let ports_found = Arc::new(AtomicUsize::new(0));
    let cfg_arc = Arc::new(cfg);
    let etc_arc = Arc::new(etc_hosts);
    let ts_arc = Arc::new(ts_map);
    let arp_arc = Arc::new(fresh_arp);
    let sock_arc = Arc::new(local_sockets);

    let mut host_handles = Vec::with_capacity(live_hosts.len());
    for (ip, alive, ttl, rtt_ms) in live_hosts {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let permit = Arc::clone(&host_sem);
        let cfg_c = Arc::clone(&cfg_arc);
        let etc_c = Arc::clone(&etc_arc);
        let ts_c = Arc::clone(&ts_arc);
        let arp_c = Arc::clone(&arp_arc);
        let sock_c = Arc::clone(&sock_arc);
        let tx_c = tx.clone();
        let cancel_c = Arc::clone(&cancel);
        let ports_found_c = Arc::clone(&ports_found);
        let mut scan_ports = base_ports.clone();

        let is_local = ip == cfg_c.interface.ip;
        if is_local {
            let mut set: BTreeSet<u16> = scan_ports.into_iter().collect();
            for s in sock_c.iter() {
                if s.state == SocketState::Listen
                    && s.proto.starts_with("TCP")
                    && s.local_port > 0
                    && s.local_ip_v4
                        .map(|lip| lip.is_unspecified() || lip == ip || lip.is_loopback())
                        .unwrap_or(true)
                {
                    set.insert(s.local_port);
                }
            }
            scan_ports = set.into_iter().collect();
        }

        host_handles.push(tokio::spawn(async move {
            let Ok(_p) = permit.acquire().await else {
                return false;
            };
            if cancel_c.load(Ordering::Relaxed) {
                return false;
            }
            let mut host = make_skeleton_host(ip, &cfg_c);
            host.online = alive;
            let now = epoch_now();
            if host.first_seen_epoch == 0 {
                host.first_seen_epoch = now;
            }
            host.last_seen_epoch = now;

            if let Some(arp) = arp_c.get(&ip) {
                host.mac = normalize_mac_opt(arp.mac).or(host.mac);
                host.arp_state = arp.state;
            }
            if is_local {
                host.mac = normalize_mac_opt(cfg_c.interface.mac).or(host.mac);
            }
            if let Some(mac) = host.mac {
                host.oui_prefix = Some(format_oui(mac));
                let (v, is_rand) = lookup_vendor(mac);
                host.vendor = v.or(host.vendor);
                host.is_randomized_mac = is_rand;
            } else if cfg_c.interface.name.starts_with("tailscale") {
                host.vendor = host.vendor.or_else(|| Some("Tailscale".to_string()));
            }

            if let Some(r) = rtt_ms {
                host.rtt_ms = Some(r);
                host.rtt_history.push(r);
                if host.rtt_history.len() > 24 {
                    host.rtt_history.remove(0);
                }
            }
            host.ttl = ttl.or(host.ttl);

            let ports = scan_ports_for_host(
                ip,
                &scan_ports,
                cfg_c.timeout_ms,
                cfg_c.grab_banners,
                &sock_c,
                is_local,
            )
            .await;

            let active_cnt = ports
                .iter()
                .filter(|p| matches!(p.state, PortState::Open | PortState::InUse))
                .count();
            ports_found_c.fetch_add(active_cnt, Ordering::Relaxed);
            host.ports = ports;

            let ts_hint = ts_c.get(&ip).and_then(|(n, _, _)| n.as_deref());
            let prev_name = ts_hint.or(host.hostname.as_deref());
            if let Some(resolved) = resolve_hostname(ip, &etc_c, prev_name).await {
                host.hostname = Some(resolved);
            } else if is_local {
                let (_, host_name) = crate::net::linux::read_user_and_host();
                if let Some(clean) = clean_discovered_hostname(&host_name) {
                    host.hostname = Some(clean);
                }
            }

            let ts_os = ts_c.get(&ip).and_then(|(_, _, os)| os.clone());
            host.os_guess = ts_os.or_else(|| {
                Some(guess_os_from_ttl(
                    host.ttl,
                    &host.ports,
                    host.vendor.as_deref(),
                ))
            });

            let is_gw = Some(ip) == cfg_c.interface.gateway;
            host.role = infer_role(
                is_local,
                is_gw,
                host.vendor.as_deref(),
                host.hostname.as_deref(),
                &host.ports,
            );

            let _ = tx_c.send(EngineEvent::HostUpsert(Box::new(host)));
            true
        }));
    }

    let mut found = 0_usize;
    for h in host_handles {
        if matches!(h.await, Ok(true)) {
            found += 1;
        }
    }

    let _ = tx.send(EngineEvent::ScanCompleted {
        hosts_found: found,
        ports_found: ports_found.load(Ordering::Relaxed),
        elapsed_ms: start.elapsed().as_millis() as u64,
    });
}
