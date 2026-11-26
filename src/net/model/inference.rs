//! Inférence de l'OS (TTL) et du rôle des équipements, et synthèse des hôtes.

use super::*;

/// Infers OS family from an observed IPv4 TTL value.
pub fn infer_os_from_ttl(ttl: u8) -> &'static str {
    if ttl == 0 {
        "Unknown"
    } else if ttl <= 64 {
        "Linux / Unix / macOS"
    } else if ttl <= 128 {
        "Windows"
    } else {
        "Network Appliance / Router"
    }
}

/// Infers a friendly `DeviceRole` from IP, gateway, vendor, OS, and open ports.
pub fn infer_device_role(
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
    if v.contains("espressif")
        || v.contains("tuya")
        || v.contains("sonos")
        || v.contains("philips")
        || v.contains("shelly")
        || ports.iter().any(|p| {
            matches!(p.port, 1883 | 8883) && matches!(p.state, PortState::Open | PortState::InUse)
        })
    {
        return DeviceRole::IoT;
    }
    if ports
        .iter()
        .any(|p| p.port == 62078 && matches!(p.state, PortState::Open | PortState::InUse))
        || h.contains("iphone")
        || h.contains("ipad")
        || h.contains("android")
        || h.contains("pixel")
        || h.contains("galaxy")
    {
        return DeviceRole::Mobile;
    }
    if v.contains("ubiquiti")
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

/// Computes live host stats summary `(online, trusted, open_ports, in_use_ports)`.
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
