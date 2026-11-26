//! Configuration struct, XDG path resolution, and TOML persistence.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::net::model::{ScanMode, ScanPreset};

use super::{atomic_write_text, escape_toml_str, AccentId, Language, ThemeId};

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
    pub language: Language,
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
            language: Language::En,
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
             watch_interval_secs = {}\n\
             language = \"{}\"\n",
            self.theme.as_str(),
            self.accent.as_str(),
            self.animations,
            self.splash,
            self.show_virtual_ifaces,
            escape_toml_str(&self.custom_ports),
            self.concurrency,
            self.timeout_ms,
            self.grab_banners,
            self.watch_interval_secs,
            self.language.as_str()
        )
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&Self::config_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        atomic_write_text(path, &self.to_toml_string(), "config")
    }
}
