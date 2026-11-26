//! Persistent configuration (`~/.config/moonveil/config.toml`) and known/trusted host store.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::net::model::{ScanMode, ScanPreset};

/// Color surface theme identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThemeId {
    #[default]
    Moonveil,
    Obsidian,
    Abyss,
    Graphite,
    Terminal,
}

impl ThemeId {
    pub const ALL: &'static [Self] = &[
        Self::Moonveil,
        Self::Obsidian,
        Self::Abyss,
        Self::Graphite,
        Self::Terminal,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Moonveil => "Moonveil Navy",
            Self::Obsidian => "Obsidian",
            Self::Abyss => "Deep Abyss",
            Self::Graphite => "Graphite",
            Self::Terminal => "Terminal",
        }
    }

    pub fn from_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "moonveil" | "navy" => Some(Self::Moonveil),
            "obsidian" => Some(Self::Obsidian),
            "abyss" => Some(Self::Abyss),
            "graphite" => Some(Self::Graphite),
            "terminal" => Some(Self::Terminal),
            _ => None,
        }
    }
}

/// Accent swatch identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccentId {
    #[default]
    Violet,
    Peach,
    Cyan,
    Mint,
    Rose,
    Amber,
}

impl AccentId {
    pub const ALL: &'static [Self] = &[
        Self::Violet,
        Self::Peach,
        Self::Cyan,
        Self::Mint,
        Self::Rose,
        Self::Amber,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Violet => "Moon Violet",
            Self::Peach => "Veil Peach",
            Self::Cyan => "Radar Cyan",
            Self::Mint => "Emerald Mint",
            Self::Rose => "Coral Rose",
            Self::Amber => "Solar Amber",
        }
    }

    pub fn from_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "violet" | "moon" => Some(Self::Violet),
            "peach" | "veil" => Some(Self::Peach),
            "cyan" | "sky" => Some(Self::Cyan),
            "mint" => Some(Self::Mint),
            "rose" | "coral" => Some(Self::Rose),
            "amber" => Some(Self::Amber),
            _ => None,
        }
    }
}

/// Application preferences persisted to `~/.config/moonveil/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mode: ScanMode,
    pub theme: ThemeId,
    pub accent: AccentId,
    pub animations: bool,
    pub splash: bool,
    pub show_virtual_ifaces: bool,
    pub default_preset: ScanPreset,
    pub custom_ports: String,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub grab_banners: bool,
    pub watch_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: ScanMode::Normal,
            theme: ThemeId::Moonveil,
            accent: AccentId::Violet,
            animations: true,
            splash: true,
            show_virtual_ifaces: false,
            default_preset: ScanPreset::Quick,
            custom_ports: "22,80,443,3000,5432,8000-8090".to_string(),
            concurrency: 256,
            timeout_ms: 250,
            grab_banners: true,
            watch_interval_secs: 15,
        }
    }
}

impl Config {
    pub fn config_dir() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("moonveil");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".config").join("moonveil");
        }
        PathBuf::from(".moonveil")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn known_hosts_path() -> PathBuf {
        Self::config_dir().join("known_hosts.toml")
    }

    pub fn export_dir() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("moonveil").join("exports");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("moonveil")
                .join("exports");
        }
        PathBuf::from("exports")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        let Ok(raw) = fs::read_to_string(&path) else {
            return Self::default();
        };
        toml::from_str(&raw).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let dir = Self::config_dir();
        fs::create_dir_all(&dir).map_err(|e| format!("Failed creating config dir: {e}"))?;
        let text =
            toml::to_string_pretty(self).map_err(|e| format!("Failed serializing config: {e}"))?;
        fs::write(Self::config_path(), text).map_err(|e| format!("Failed saving config: {e}"))
    }
}

/// Persistent bookmark / trust record keyed by MAC address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHostEntry {
    pub mac: String,
    pub last_ip: String,
    pub nickname: Option<String>,
    pub trusted: bool,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
}

/// Store of known / bookmarked devices loaded from `~/.config/moonveil/known_hosts.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnownHostStore {
    #[serde(default)]
    pub hosts: BTreeMap<String, KnownHostEntry>,
}

impl KnownHostStore {
    pub fn load() -> Self {
        let path = Config::known_hosts_path();
        let Ok(raw) = fs::read_to_string(&path) else {
            return Self::default();
        };
        toml::from_str(&raw).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let dir = Config::config_dir();
        fs::create_dir_all(&dir).map_err(|e| format!("Failed creating config dir: {e}"))?;
        let text = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed serializing known hosts: {e}"))?;
        fs::write(Config::known_hosts_path(), text)
            .map_err(|e| format!("Failed saving known hosts: {e}"))
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
