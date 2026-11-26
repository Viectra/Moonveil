//! Async tokio discovery, port-state classification (`InUse`/`Open`/`Closed`/`Filtered`), and banner probes.

use crate::net::linux::{
    epoch_now, network_addr, prefix_mask, read_arp_entries, read_etc_hosts, ArpEntry,
};
use crate::net::model::{
    format_mac, format_oui, infer_device_role, infer_os_from_ttl, ports_for_preset, service_info,
    ArpState, Host, LocalSocket, NetworkInterface, PortInfo, PortState, PrivilegeLevel, Proto,
    ScanPreset, SocketState, TracerouteHop,
};
use crate::net::oui::lookup_vendor;
use std::collections::{BTreeSet, HashMap};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

mod discovery;
mod engine;
mod probes;
pub use discovery::*;
pub use engine::*;
pub use probes::*;

/// Streamed updates emitted from async network tasks back to the UI state loop.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    ScanStarted {
        total: usize,
        phase: String,
    },
    ScanProgress {
        probed: usize,
        total: usize,
        current_target: String,
        phase: String,
    },
    HostUpsert(Box<Host>),
    ScanCompleted {
        hosts_online: usize,
        ports_open: usize,
        duration_ms: u64,
    },
    PingUpdate {
        ip: Ipv4Addr,
        rtt_ms: Option<f64>,
        ttl: Option<u8>,
    },
    TraceHop(TracerouteHop),
    TraceComplete,
    TelemetryUpdate {
        interfaces: Vec<NetworkInterface>,
        local_sockets: Vec<LocalSocket>,
    },
    StatusToast(String),
}

/// Parameters controlling a network discovery + port scan run.
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

fn make_skeleton_host(ip: Ipv4Addr, iface: &NetworkInterface, now: u64) -> Host {
    Host {
        ip,
        ipv6: None,
        hostname: None,
        nickname: None,
        mac: None,
        oui_prefix: None,
        vendor: None,
        is_randomized_mac: false,
        online: false,
        trusted: false,
        role: if iface.gateway == Some(ip) {
            crate::net::model::DeviceRole::Gateway
        } else {
            crate::net::model::DeviceRole::Host
        },
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
        is_new: true,
    }
}

/// Helper used by saved known-hosts sync to normalize MAC strings.
pub fn normalize_mac_opt(mac: Option<[u8; 6]>) -> Option<String> {
    mac.map(format_mac)
}
