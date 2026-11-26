//! Known hosts registry persisted in `~/.config/moonveil/known_hosts.toml`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{atomic_write_text, escape_toml_str, Config};

/// Persisted identity & metadata for a discovered MAC address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KnownHostEntry {
    pub mac: String,
    pub last_ip: String,
    pub nickname: Option<String>,
    pub trusted: bool,
    pub vendor: Option<String>,
    pub last_hostname: Option<String>,
}

/// Persistent collection of named / previously observed devices keyed by uppercase MAC.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KnownHostStore {
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

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&Config::known_hosts_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
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
            if let Some(host) = &entry.last_hostname {
                let _ = writeln!(out, "last_hostname = \"{}\"", escape_toml_str(host));
            }
            out.push('\n');
        }
        atomic_write_text(path, &out, "known_hosts")
    }

    pub fn get(&self, mac: &str) -> Option<&KnownHostEntry> {
        let key = mac.trim().to_ascii_uppercase();
        self.hosts.get(&key)
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
        let key = mac.trim().to_ascii_uppercase();
        if key.is_empty() {
            return;
        }
        let prev = self.hosts.get(&key);
        let merged_nick = nickname.or_else(|| prev.and_then(|p| p.nickname.clone()));
        let merged_vendor = vendor.or_else(|| prev.and_then(|p| p.vendor.clone()));
        let merged_host = hostname.or_else(|| prev.and_then(|p| p.last_hostname.clone()));
        self.hosts.insert(
            key.clone(),
            KnownHostEntry {
                mac: key,
                last_ip: ip.to_string(),
                nickname: merged_nick,
                trusted,
                vendor: merged_vendor,
                last_hostname: merged_host,
            },
        );
    }
}
