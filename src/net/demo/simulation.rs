//! Live demo tick simulation and synthetic traceroute generation.

use std::net::Ipv4Addr;

use crate::net::model::{NetworkSnapshot, TracerouteHop};

/// Evolves throughput and RTT telemetry slightly on each tick when demo mode is active.
pub fn tick_demo_snapshot(snapshot: &mut NetworkSnapshot, tick: u64) {
    let phase = (tick as f64) * 0.45;
    for iface in &mut snapshot.interfaces {
        if !iface.is_up {
            continue;
        }
        let rx_val = (iface.rx_bps * (0.85 + 0.3 * phase.sin().abs())).max(1024.0);
        let tx_val = (iface.tx_bps * (0.82 + 0.35 * phase.cos().abs())).max(512.0);
        iface.rx_history.push(rx_val);
        if iface.rx_history.len() > 24 {
            iface.rx_history.remove(0);
        }
        iface.tx_history.push(tx_val);
        if iface.tx_history.len() > 24 {
            iface.tx_history.remove(0);
        }
    }

    for (idx, host) in snapshot.hosts.iter_mut().enumerate() {
        if !host.online {
            continue;
        }
        if let Some(base) = host.rtt_ms {
            let delta = ((tick as f64 + idx as f64) * 0.6).sin() * 0.12;
            let next_rtt = (base + delta).max(0.08);
            host.rtt_ms = Some(next_rtt);
            host.rtt_history.push(next_rtt);
            if host.rtt_history.len() > 24 {
                host.rtt_history.remove(0);
            }
        }
    }

    if snapshot.ping_active {
        let sample = 0.4 + 0.25 * (phase * 1.3).sin().abs();
        snapshot.ping_sent += 1;
        snapshot.ping_received += 1;
        snapshot.ping_last_rtt_ms = Some(sample);
        snapshot.ping_samples.push(sample);
        if snapshot.ping_samples.len() > 36 {
            snapshot.ping_samples.remove(0);
        }
    }
}

/// Returns deterministic traceroute hops for `--demo` targets.
pub fn demo_traceroute(target: Ipv4Addr) -> Vec<TracerouteHop> {
    vec![
        TracerouteHop {
            ttl: 1,
            ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            hostname: Some("Main Router".to_string()),
            rtt_ms: Some(0.7),
        },
        TracerouteHop {
            ttl: 2,
            ip: Some(target),
            hostname: None,
            rtt_ms: Some(1.4),
        },
    ]
}
