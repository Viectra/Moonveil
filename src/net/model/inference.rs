//! Passive OS / device-role inference and aggregate snapshot host metrics.

use std::collections::HashMap;

use super::{DeviceRole, Host, NetworkInterface, PortInfo, PortState};

/// Infers likely operating system family from observed IPv4 TTL and open service ports.
pub fn guess_os_from_ttl(ttl: Option<u8>, ports: &[PortInfo], vendor: Option<&str>) -> String {
    let has_port = |p: u16| {
        ports
            .iter()
            .any(|pi| pi.port == p && matches!(pi.state, PortState::Open | PortState::InUse))
    };
    if let Some(v) = vendor {
        let low = v.to_ascii_lowercase();
        if low.contains("apple") && (has_port(548) || has_port(62078)) {
            return "Apple macOS / iOS".to_string();
        }
        if low.contains("espressif") || low.contains("tuya") || low.contains("philips") {
            return "Embedded / IoT".to_string();
        }
    }
    if has_port(3389) || (has_port(445) && has_port(135)) {
        return "Windows".to_string();
    }
    if has_port(8006) {
        return "Proxmox VE (Linux)".to_string();
    }
    if has_port(631) && has_port(9100) {
        return "Network Printer / CUPS".to_string();
    }
    if has_port(548) || has_port(62078) {
        return "macOS / iOS".to_string();
    }
    match ttl {
        Some(t) if t >= 200 => "Network Appliance / BSD".to_string(),
        Some(t) if (90..=140).contains(&t) => "Windows (TTL 128)".to_string(),
        Some(t) if (40..=72).contains(&t) => "Linux / Unix (TTL 64)".to_string(),
        _ if has_port(22) => "Linux / Unix".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// Infers `DeviceRole` from IP role hints, MAC/vendor OUI, hostname, and open ports.
pub fn infer_role(
    is_local: bool,
    is_gateway: bool,
    vendor: Option<&str>,
    hostname: Option<&str>,
    ports: &[PortInfo],
) -> DeviceRole {
    if is_local {
        return DeviceRole::ThisMachine;
    }
    if is_gateway {
        return DeviceRole::Gateway;
    }
    let v = vendor.unwrap_or("").to_ascii_lowercase();
    let h = hostname.unwrap_or("").to_ascii_lowercase();

    if v.contains("docker") || h.contains("docker") || h.contains("container") {
        return DeviceRole::Container;
    }
    if ports.iter().any(|p| {
        matches!(p.port, 631 | 9100) && matches!(p.state, PortState::Open | PortState::InUse)
    }) || v.contains("hp")
        || v.contains("epson")
        || v.contains("canon")
        || v.contains("brother")
    {
        return DeviceRole::Printer;
    }
    if v.contains("espressif")
        || v.contains("sonos")
        || v.contains("philips")
        || v.contains("tuya")
        || v.contains("shelly")
        || h.contains("hue")
        || h.contains("plug")
    {
        return DeviceRole::IoT;
    }
    if v.contains("xiaomi") || v.contains("oneplus") || h.contains("iphone") || h.contains("ipad") {
        return DeviceRole::Mobile;
    }
    if v.contains("raspberry")
        || v.contains("proxmox")
        || v.contains("ubiquiti")
        || v.contains("cisco")
        || v.contains("mikrotik")
        || v.contains("synology")
        || v.contains("qnap")
        || h.contains("proxmox")
        || h.contains("nas")
        || h.contains("pihole")
        || ports.iter().any(|p| {
            matches!(
                p.port,
                22 | 80 | 443 | 445 | 548 | 3306 | 5432 | 8006 | 9000
            ) && matches!(p.state, PortState::Open | PortState::InUse)
        })
    {
        return DeviceRole::Server;
    }
    if v.contains("apple") || v.contains("intel") || v.contains("dell") || v.contains("lenovo") {
        return DeviceRole::Workstation;
    }
    DeviceRole::Host
}

/// Computes live host stats summary `(online, trusted, open_ports, in_use_ports, ifaces_up)`.
pub fn summarize_hosts(hosts: &[Host], interfaces: &[NetworkInterface]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let online = hosts.iter().filter(|h| h.online).count();
    let trusted = hosts.iter().filter(|h| h.trusted).count();
    let mut open = 0;
    let mut in_use = 0;
    for h in hosts {
        let (iu, op, _, _) = h.port_counts();
        in_use += iu;
        open += op;
    }
    map.insert("online".into(), online);
    map.insert("trusted".into(), trusted);
    map.insert("open".into(), open);
    map.insert("in_use".into(), in_use);
    map.insert(
        "ifaces_up".into(),
        interfaces.iter().filter(|i| i.is_up).count(),
    );
    map
}
