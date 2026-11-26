//! Animation du mode démo : perturbation des métriques et traceroute simulé.

use super::*;

/// Generates realistic demo traceroute hops to `target`.
pub fn demo_traceroute(target: Ipv4Addr) -> Vec<TracerouteHop> {
    vec![
        TracerouteHop {
            ttl: 1,
            ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            hostname: Some("gateway.lan".to_string()),
            rtt_ms: Some(0.64),
        },
        TracerouteHop {
            ttl: 2,
            ip: Some(target),
            hostname: None,
            rtt_ms: Some(1.48),
        },
    ]
}

/// Gently perturbs live demo RTT & throughput metrics each animation step.
pub fn tick_demo_snapshot(snapshot: &mut NetworkSnapshot, tick: u64) {
    let wave = (tick as f64 * 0.25).sin();
    for (idx, iface) in snapshot.interfaces.iter_mut().enumerate() {
        let base_rx = if idx == 0 { 4_400_000.0 } else { 140_000.0 };
        let base_tx = if idx == 0 { 1_100_000.0 } else { 85_000.0 };
        let rx = (base_rx + (wave + (idx as f64) * 0.5).sin().abs() * base_rx * 0.45).max(12_000.0);
        let tx = (base_tx + (wave * 1.3 + idx as f64).cos().abs() * base_tx * 0.40).max(8_000.0);
        iface.rx_rate_bps = rx;
        iface.tx_rate_bps = tx;
        iface.rx_history.push(rx);
        iface.tx_history.push(tx);
        if iface.rx_history.len() > 48 {
            iface.rx_history.remove(0);
        }
        if iface.tx_history.len() > 48 {
            iface.tx_history.remove(0);
        }
    }
    for (idx, host) in snapshot.hosts.iter_mut().enumerate() {
        if !host.online || host.role == DeviceRole::ThisMachine {
            continue;
        }
        if let Some(base) = host.rtt_history.first().copied().or(host.rtt_ms) {
            let jitter = ((tick as f64 * 0.4 + idx as f64 * 1.1).sin() * 0.18 + 1.0).max(0.5);
            let sample = (base * jitter).max(0.12);
            host.rtt_ms = Some(sample);
            host.rtt_history.push(sample);
            if host.rtt_history.len() > 32 {
                host.rtt_history.remove(0);
            }
        }
    }
}
