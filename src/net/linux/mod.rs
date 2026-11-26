//! Native Linux telemetry collectors (`/proc`, `/sys`, `getifaddrs`, ARP, and Tailscale).

pub mod interfaces;
pub mod proc_net;
pub mod system;

pub use interfaces::{collect_interfaces, network_addr, prefix_mask};
pub use proc_net::{
    collect_local_sockets, parse_proc_hex_ipv4, read_arp_entries, read_tailscale_peers, ArpEntry,
    TailscalePeer,
};
pub use system::{
    detect_privilege, epoch_now, read_dns_servers, read_etc_hosts, read_gateways,
    read_user_and_host,
};
