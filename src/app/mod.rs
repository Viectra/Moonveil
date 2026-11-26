//! Global application state (`App`, `Tab`, `Modal`) and controller sub-modules.

pub mod actions;
pub mod hosts;
pub mod input;
pub mod network;
pub mod state;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::config::{Config, KnownHostStore, Language};
use crate::net::model::{Host, HostSortColumn, NetworkSnapshot, PortFilter, ScanProgress};
use crate::net::scanner::EngineEvent;
use crate::ui::hit::HitRegistry;

/// Top-level navigation views (Hosts, Subnet Radar, Settings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Hosts,
    Radar,
    Settings,
}

impl Tab {
    pub const ALL: &'static [Self] = &[Self::Hosts, Self::Radar, Self::Settings];

    pub const fn icon(self) -> &'static str {
        match self {
            Self::Hosts => "◈",
            Self::Radar => "◎",
            Self::Settings => "⚙",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Hosts => "Hosts",
            Self::Radar => "Subnet Radar",
            Self::Settings => "Settings",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.label();
        }
        match self {
            Self::Hosts => "Hôtes",
            Self::Radar => "Radar réseau",
            Self::Settings => "Paramètres",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Hosts => "Hosts",
            Self::Radar => "Radar",
            Self::Settings => "Settings",
        }
    }

    pub const fn short_label_for(self, lang: Language) -> &'static str {
        if matches!(lang, Language::En) {
            return self.short_label();
        }
        match self {
            Self::Hosts => "Hôtes",
            Self::Radar => "Radar",
            Self::Settings => "Réglages",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Hosts => Self::Radar,
            Self::Radar => Self::Settings,
            Self::Settings => Self::Hosts,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Hosts => Self::Settings,
            Self::Radar => Self::Hosts,
            Self::Settings => Self::Radar,
        }
    }
}

/// Active modal overlay window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Modal {
    #[default]
    None,
    Help,
    RenameHost {
        ip: Ipv4Addr,
        input: String,
    },
    CustomPorts {
        input: String,
        error: Option<String>,
    },
}

/// Root state coordinator connecting network probes, configuration, and Ratatui rendering.
pub struct App {
    pub config: Config,
    pub demo_mode: bool,
    pub snapshot: NetworkSnapshot,
    pub demo_ifaces_hosts: HashMap<String, Vec<Host>>,
    pub tab: Tab,
    pub modal: Modal,
    pub selected_host_ip: Option<Ipv4Addr>,
    pub host_scroll: usize,
    pub host_sort: HostSortColumn,
    pub host_sort_desc: bool,
    pub port_filter: PortFilter,
    pub selected_port_idx: usize,
    pub port_scroll: usize,
    pub show_closed_ports: bool,
    pub search_focused: bool,
    pub search_query: String,
    pub radar_page_offset: u32,
    pub radar_selected_octet: u8,
    pub tick: u64,
    pub splash_ticks_remaining: u16,
    pub status_message: String,
    pub toast: Option<(String, u16)>,
    pub should_quit: bool,
    pub persist_state: bool,
    pub watch_enabled: bool,
    pub scan_progress: ScanProgress,
    pub hits: HitRegistry,
    pub known_hosts: KnownHostStore,
    pub(super) engine_tx: mpsc::UnboundedSender<EngineEvent>,
    pub(super) engine_rx: mpsc::UnboundedReceiver<EngineEvent>,
    pub(super) scan_cancel: Option<Arc<AtomicBool>>,
    pub(super) ping_cancel: Option<Arc<AtomicBool>>,
    pub(super) last_socket_refresh_tick: u64,
    pub(super) host_last_click: Option<(Ipv4Addr, Instant)>,
}
