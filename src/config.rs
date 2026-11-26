//! Persistent configuration (`~/.config/moonveil/config.toml`) and known/trusted host store.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

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

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Moonveil => "moonveil",
            Self::Obsidian => "obsidian",
            Self::Abyss => "abyss",
            Self::Graphite => "graphite",
            Self::Terminal => "terminal",
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

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Violet => "violet",
            Self::Peach => "peach",
            Self::Cyan => "cyan",
            Self::Mint => "mint",
            Self::Rose => "rose",
            Self::Amber => "amber",
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        if let Ok(custom) = std::env::var("MOONVEIL_CONFIG_DIR") {
            if !custom.is_empty() {
                return PathBuf::from(custom);
            }
        }
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
        Self::load_from(&Self::config_path())
    }

    pub fn load_from(path: &Path) -> Self {
        let Ok(raw) = fs::read_to_string(path) else {
            return Self::default();
        };
        toml::from_str(&raw).unwrap_or_default()
    }

    /// Formats configuration cleanly as deterministic TOML without heavy generic reflection.
    pub fn to_toml_string(&self) -> String {
        let mode_s = match self.mode {
            ScanMode::Normal => "normal",
            ScanMode::Advanced => "advanced",
        };
        let preset_s = match self.default_preset {
            ScanPreset::Quick => "quick",
            ScanPreset::Standard => "standard",
            ScanPreset::Full => "full",
            ScanPreset::WebDev => "webdev",
            ScanPreset::Custom => "custom",
        };
        format!(
            "mode = \"{mode_s}\"\n\
             theme = \"{}\"\n\
             accent = \"{}\"\n\
             animations = {}\n\
             splash = {}\n\
             show_virtual_ifaces = {}\n\
             default_preset = \"{preset_s}\"\n\
             custom_ports = \"{}\"\n\
             concurrency = {}\n\
             timeout_ms = {}\n\
             grab_banners = {}\n\
             watch_interval_secs = {}\n",
            self.theme.as_str(),
            self.accent.as_str(),
            self.animations,
            self.splash,
            self.show_virtual_ifaces,
            escape_toml_str(&self.custom_ports),
            self.concurrency,
            self.timeout_ms,
            self.grab_banners,
            self.watch_interval_secs
        )
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&Self::config_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        atomic_write_text(path, &self.to_toml_string(), "config")
    }
}

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

fn escape_toml_str(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn atomic_write_text(path: &Path, text: &str, label: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed creating {label} dir: {e}"))?;
    }
    let tmp_path = path.with_extension("toml.tmp");
    if fs::write(&tmp_path, text).is_ok() {
        if fs::rename(&tmp_path, path).is_ok() {
            return Ok(());
        }
        let _ = fs::remove_file(&tmp_path);
    }
    fs::write(path, text).map_err(|e| format!("Failed saving {label}: {e}"))
}
