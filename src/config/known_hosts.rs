//! Known and trusted hosts registry persisted to `known_hosts.toml`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{atomic_write_text, escape_toml_str, Config};

/// Persistent bookmark / trust record keyed by MAC address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHostEntry {
    pub mac: String,
    pub last_ip: String,
    pub nickname: Option<String>,
    pub trusted: bool,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
}

/// Store of known / bookmarked devices loaded from `~/.config/moonveil/known_hosts.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KnownHostStore {
    #[serde(default)]
    pub hosts: BTreeMap<String, KnownHostEntry>,
}

impl KnownHostStore {
    pub fn load() -> Self {
        Self::load_from(&Config::known_hosts_path())
    }

    pub fn load_from(path: &Path) -> Self {
        let Ok(raw) = fs::read_to_string(path) else {
            return Self::default();
        };
        toml::from_str(&raw).unwrap_or_default()
    }

    /// Formats known hosts cleanly as deterministic TOML.
    pub fn to_toml_string(&self) -> String {
        let mut out = String::new();
        for (key, entry) in &self.hosts {
            let _ = writeln!(out, "[hosts.\"{}\"]", escape_toml_str(key));
            let _ = writeln!(out, "mac = \"{}\"", escape_toml_str(&entry.mac));
            let _ = writeln!(out, "last_ip = \"{}\"", escape_toml_str(&entry.last_ip));
            if let Some(nick) = &entry.nickname {
                let _ = writeln!(out, "nickname = \"{}\"", escape_toml_str(nick));
            }
            let _ = writeln!(out, "trusted = {}", entry.trusted);
            if let Some(vendor) = &entry.vendor {
                let _ = writeln!(out, "vendor = \"{}\"", escape_toml_str(vendor));
            }
            if let Some(hostname) = &entry.hostname {
                let _ = writeln!(out, "hostname = \"{}\"", escape_toml_str(hostname));
            }
            out.push('\n');
        }
        out
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&Config::known_hosts_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        atomic_write_text(path, &self.to_toml_string(), "known hosts")
    }

    pub fn upsert(
        &mut self,
        mac: &str,
        ip: Ipv4Addr,
        nickname: Option<String>,
        trusted: bool,
        vendor: Option<String>,
        hostname: Option<String>,
    ) {
        let key = mac.to_ascii_uppercase();
        self.hosts.insert(
            key.clone(),
            KnownHostEntry {
                mac: key,
                last_ip: ip.to_string(),
                nickname,
                trusted,
                vendor,
                hostname,
            },
        );
    }
}
