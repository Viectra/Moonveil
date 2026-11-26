//! Configuration and host-registry module for Moonveil (`mvl`).

pub mod known_hosts;
pub mod persistence;

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use known_hosts::{KnownHostEntry, KnownHostStore};
pub use persistence::Config;

/// Surface theme variants built around Moonveil's cosmic navy + crescent palette.
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
            "moonveil" | "navy" | "default" => Some(Self::Moonveil),
            "obsidian" | "dark" => Some(Self::Obsidian),
            "abyss" | "deep" => Some(Self::Abyss),
            "graphite" | "slate" => Some(Self::Graphite),
            "terminal" | "ansi" => Some(Self::Terminal),
            _ => None,
        }
    }
}

/// Interactive accent color options derived from Moonveil branding.
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
            "violet" | "purple" | "moon" => Some(Self::Violet),
            "peach" | "pink" | "blush" | "veil" => Some(Self::Peach),
            "cyan" | "blue" | "sky" => Some(Self::Cyan),
            "mint" | "green" | "emerald" => Some(Self::Mint),
            "rose" | "red" | "coral" => Some(Self::Rose),
            "amber" | "gold" | "yellow" => Some(Self::Amber),
            _ => None,
        }
    }
}

/// Interface language selection (`English` or `Français`).
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
    #[inline]
    pub const fn t<'a>(self, en: &'a str, fr: &'a str) -> &'a str {
        match self {
            Self::En => en,
            Self::Fr => fr,
        }
    }

    #[inline]
    pub const fn is_fr(self) -> bool {
        matches!(self, Self::Fr)
    }
}

pub(crate) fn escape_toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

pub(crate) fn atomic_write_text(path: &Path, content: &str, label: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed creating {label} dir: {e}"))?;
    }
    let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    if fs::write(&tmp, content).is_ok() {
        if fs::rename(&tmp, path).is_ok() {
            return Ok(());
        }
        let _ = fs::remove_file(&tmp);
    }
    fs::write(path, content).map_err(|e| format!("Failed writing {label}: {e}"))
}
