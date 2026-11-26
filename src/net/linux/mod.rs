//! Native Linux telemetry collector reading `/proc/net/*`, `/sys/class/net/*`, and `getifaddrs`.

use crate::net::model::{
    parse_mac, ArpState, LocalSocket, NetworkInterface, PrivilegeLevel, SocketState,
};
use crate::net::oui::lookup_vendor;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

mod interfaces;
mod proc_net;
mod system;
pub use interfaces::*;
pub use proc_net::*;
pub use system::*;
