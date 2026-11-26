//! Deterministic, animated simulated network dataset for `--demo` mode and headless tests.

use std::net::Ipv4Addr;

use crate::net::model::{
    format_oui, ArpState, DeviceRole, EventKind, Host, LocalSocket, NetworkInterface,
    NetworkSnapshot, PortInfo, PortState, PrivilegeLevel, Proto, SocketState, TimelineEvent,
    TracerouteHop,
};

mod data;
mod hosts;
mod simulation;

pub use simulation::*;

/// Builds a rich simulated network snapshot (`enp6s18`, `docker0`, `tailscale0`, 14 hosts, sockets).
pub fn build_demo_snapshot() -> (NetworkSnapshot, Vec<TimelineEvent>) {
    let interfaces = data::demo_interfaces();
    let hosts = hosts::demo_hosts();
    let local_sockets = data::demo_local_sockets();
    let timeline = data::demo_timeline();

    let snapshot = NetworkSnapshot {
        hostname: "babylone".to_string(),
        username: "viectra".to_string(),
        privilege: PrivilegeLevel::IcmpDatagram,
        interfaces,
        local_sockets,
        hosts,
    };

    (snapshot, timeline)
}
