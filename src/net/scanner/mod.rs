//! Concurrent async network discovery and port scanning engine.

pub mod discovery;
pub mod engine;
pub mod probes;

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::net::model::{
    ArpState, DeviceRole, Host, LocalSocket, NetworkInterface, PrivilegeLevel, ScanPreset,
    TracerouteHop,
};
use crate::net::oui::lookup_vendor;

pub use discovery::{
    icmp_ping, icmp_ping_sync, probe_host_alive, resolve_hostname, reverse_dns_blocking,
};
pub use engine::{compute_scan_targets, run_scan};
pub use probes::scan_ports_for_host;

/// Real-time events streamed from async scan/probe tasks back into `App`.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    ScanStarted {
        total_targets: usize,
    },
    ScanProgress {
        probed: usize,
        total: usize,
        target: String,
    },
    HostUpsert(Box<Host>),
    ScanCompleted {
        hosts_found: usize,
        ports_found: usize,
        elapsed_ms: u64,
    },
    PingSample {
        target: Ipv4Addr,
        rtt_ms: Option<f64>,
    },
    PingUpdate {
        ip: Ipv4Addr,
        rtt_ms: Option<f64>,
        ttl: Option<u8>,
    },
    TraceHop(TracerouteHop),
    TraceComplete,
    TracerouteResult {
        target: Ipv4Addr,
        hops: Vec<TracerouteHop>,
    },
    SocketsUpdated(Vec<LocalSocket>, Vec<NetworkInterface>),
}

/// Parameters passed to a subnet or single-host scan job.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub interface: NetworkInterface,
    pub preset: ScanPreset,
    pub custom_ports: String,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub grab_banners: bool,
    pub privilege: PrivilegeLevel,
    pub radar_page_offset: u32,
    pub single_host: Option<Ipv4Addr>,
    pub local_sockets: Vec<LocalSocket>,
    pub existing_hosts: HashMap<Ipv4Addr, Host>,
}

pub(super) fn normalize_mac_opt(mac: Option<[u8; 6]>) -> Option<[u8; 6]> {
    mac.filter(|m| *m != [0; 6])
}

pub(super) fn make_skeleton_host(ip: Ipv4Addr, cfg: &ScanConfig) -> Host {
    if let Some(prev) = cfg.existing_hosts.get(&ip) {
        return prev.clone();
    }
    let (vendor, is_rand) = if ip == cfg.interface.ip {
        cfg.interface
            .mac
            .map(lookup_vendor)
            .unwrap_or((None, false))
    } else {
        (None, false)
    };
    Host {
        ip,
        ipv6: None,
        hostname: None,
        nickname: None,
        mac: if ip == cfg.interface.ip {
            cfg.interface.mac
        } else {
            None
        },
        oui_prefix: None,
        vendor,
        is_randomized_mac: is_rand,
        online: false,
        trusted: ip == cfg.interface.ip || Some(ip) == cfg.interface.gateway,
        role: if ip == cfg.interface.ip {
            DeviceRole::ThisMachine
        } else if Some(ip) == cfg.interface.gateway {
            DeviceRole::Gateway
        } else {
            DeviceRole::Host
        },
        arp_state: ArpState::Unknown,
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
        subnet_cidr: cfg.interface.cidr.clone(),
        interface: cfg.interface.name.clone(),
        is_new: false,
    }
}
