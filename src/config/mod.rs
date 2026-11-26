//! Persistent configuration (`~/.config/moonveil/config.toml`) and known/trusted host store.

mod known_hosts;
mod persistence;

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use known_hosts::{KnownHostEntry, KnownHostStore};
pub use persistence::Config;

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

    pub const fn label_for(self, lang: Language) -> &'static str {
        match (self, lang) {
            (Self::Moonveil, Language::Fr) => "Marine Moonveil",
            (Self::Obsidian, Language::Fr) => "Obsidienne",
            (Self::Abyss, Language::Fr) => "Abysses",
            _ => self.label(),
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

    pub const fn label_for(self, lang: Language) -> &'static str {
        match lang {
            Language::En => self.label(),
            Language::Fr => match self {
                Self::Violet => "Violet Lune",
                Self::Peach => "Pêche Voile",
                Self::Cyan => "Cyan Radar",
                Self::Mint => "Menthe Émeraude",
                Self::Rose => "Rose Corail",
                Self::Amber => "Ambre Solaire",
            },
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

/// Interface display language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Fr,
}

impl Language {
    pub const ALL: &'static [Self] = &[Self::En, Self::Fr];

    pub const fn label(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Fr => "Français",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Fr => "fr",
        }
    }

    pub fn from_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "en" | "english" | "anglais" => Some(Self::En),
            "fr" | "french" | "francais" | "français" => Some(Self::Fr),
            _ => None,
        }
    }

    /// Picks the English or French variant of a static UI string.
    pub const fn t(self, en: &'static str, fr: &'static str) -> &'static str {
        match self {
            Self::En => en,
            Self::Fr => fr,
        }
    }

    pub const fn is_fr(self) -> bool {
        matches!(self, Self::Fr)
    }
}

pub(super) fn escape_toml_str(raw: &str) -> String {
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

pub(super) fn atomic_write_text(path: &Path, text: &str, label: &str) -> Result<(), String> {
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
