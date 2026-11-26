//! Simulated deterministic LAN, Docker, and Tailscale dataset for `--demo` and tests.

pub mod data;
pub mod hosts;
pub mod simulation;

use std::collections::HashMap;

use crate::net::model::{Host, NetworkSnapshot, PrivilegeLevel};

use data::{build_demo_events, build_demo_interfaces, build_demo_sockets};
use hosts::{build_docker_hosts, build_lan_hosts, build_tailscale_hosts};

pub use simulation::{demo_traceroute, tick_demo_snapshot};

/// Builds a rich multi-interface demo snapshot (`enp6s18`, `docker0`, `tailscale0`).
pub fn build_demo_snapshot() -> (NetworkSnapshot, HashMap<String, Vec<Host>>) {
    let lan_hosts = build_lan_hosts();
    let docker_hosts = build_docker_hosts();
    let ts_hosts = build_tailscale_hosts();

    let mut per_iface = HashMap::new();
    per_iface.insert("enp6s18".to_string(), lan_hosts.clone());
    per_iface.insert("docker0".to_string(), docker_hosts);
    per_iface.insert("tailscale0".to_string(), ts_hosts);

    let snapshot = NetworkSnapshot {
        interfaces: build_demo_interfaces(),
        active_iface_idx: 0,
        hosts: lan_hosts,
        local_sockets: build_demo_sockets(),
        events: build_demo_events(),
        privilege: PrivilegeLevel::Capabilities,
        username: "viectra".to_string(),
        hostname: "babylone".to_string(),
        last_scan_epoch: Some(1_795_700_000),
        scan_duration_ms: Some(843),
        traceroute_target: None,
        traceroute_hops: Vec::new(),
        ping_target: None,
        ping_samples: vec![0.4, 0.5, 0.3, 0.6, 0.4, 0.4],
        ping_sent: 6,
        ping_received: 6,
        ping_last_rtt_ms: Some(0.4),
        ping_active: false,
    };

    (snapshot, per_iface)
}
