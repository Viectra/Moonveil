//! Application state controller: event loop ticks, mouse/key handling, Watch diffs, and async scan orchestration.

use crate::config::{Config, KnownHostStore, Language};
use crate::net::demo::{build_demo_snapshot, demo_traceroute, tick_demo_snapshot};
use crate::net::linux::{
    collect_interfaces, collect_local_sockets, detect_privilege, epoch_now, network_addr,
    prefix_mask, read_arp_entries, read_user_and_host,
};
use crate::net::model::{
    format_mac, format_oui, infer_device_role, parse_mac, parse_port_expr, ArpState, DeviceRole,
    EventKind, ExportFormat, Host, HostSortColumn, NetworkInterface, NetworkSnapshot, PortFilter,
    PortState, ScanPreset, TimelineEvent, TracerouteHop,
};
use crate::net::oui::lookup_vendor;
use crate::net::scanner::{run_scan, EngineEvent, ScanConfig};
use crate::net::tools::{
    copy_osc52, export_snapshot, run_ping_monitor, run_traceroute, send_wake_on_lan,
};
use crate::ui::hit::{ClickAction, HitRegistry, ScrollTarget};
use crate::ui::theme::Palette;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

mod actions;
mod hosts;
mod input;
mod network;
mod state;
use hosts::*;

/// Primary workspace view tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Hosts,
    Radar,
    Network,
    Watch,
    Settings,
}

impl Tab {
    pub const ALL: &'static [Self] = &[
        Self::Hosts,
        Self::Radar,
        Self::Network,
        Self::Watch,
        Self::Settings,
    ];

    pub const fn icon(self) -> &'static str {
        match self {
            Self::Hosts => "●",
            Self::Radar => "⊞",
            Self::Network => "⇄",
            Self::Watch => "◈",
            Self::Settings => "◆",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Hosts => "Hosts",
            Self::Radar => "Subnet Radar",
            Self::Network => "Net & Sockets",
            Self::Watch => "Watch & Export",
            Self::Settings => "Settings",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Hosts => "Hosts",
            Self::Radar => "Radar",
            Self::Network => "Sockets",
            Self::Watch => "Watch",
            Self::Settings => "Config",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        match self {
            Self::Hosts => lang.t("Hosts", "Hôtes"),
            Self::Radar => lang.t("Subnet Radar", "Radar sous-réseau"),
            Self::Network => lang.t("Net & Sockets", "Réseau & Sockets"),
            Self::Watch => lang.t("Watch & Export", "Veille & Export"),
            Self::Settings => lang.t("Settings", "Paramètres"),
        }
    }

    pub const fn short_label_for(self, lang: Language) -> &'static str {
        match self {
            Self::Hosts => lang.t("Hosts", "Hôtes"),
            Self::Radar => "Radar",
            Self::Network => "Sockets",
            Self::Watch => lang.t("Watch", "Veille"),
            Self::Settings => "Config",
        }
    }
}

/// Filter tabs for the local sockets view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocketFilter {
    #[default]
    All,
    Established,
    Listen,
}

impl SocketFilter {
    pub const ALL: &'static [Self] = &[Self::All, Self::Established, Self::Listen];

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Established => "In Use",
            Self::Listen => "Open/Listen",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        match self {
            Self::All => lang.t("All", "Tous"),
            Self::Established => lang.t("In Use", "Utilisés"),
            Self::Listen => lang.t("Open/Listen", "Ouverts/Écoute"),
        }
    }
}

/// Active floating modal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
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
    Traceroute {
        ip: Ipv4Addr,
    },
}

/// Root Moonveil application state.
pub struct App {
    pub config: Config,
    pub known_hosts: KnownHostStore,
    pub palette: Palette,
    pub tab: Tab,
    pub demo_mode: bool,
    pub snapshot: NetworkSnapshot,
    pub selected_iface_idx: usize,
    pub selected_host_ip: Option<Ipv4Addr>,
    pub search_query: String,
    pub search_focused: bool,
    pub host_sort: HostSortColumn,
    pub host_sort_desc: bool,
    pub host_scroll: usize,
    pub port_filter: PortFilter,
    pub port_scroll: usize,
    pub show_closed_ports: bool,
    pub show_inspector_on_compact: bool,
    pub radar_selected_octet: u8,
    pub radar_page_offset: u32,
    pub radar_role_filter: Option<DeviceRole>,
    pub socket_filter: SocketFilter,
    pub socket_search: String,
    pub socket_search_focused: bool,
    pub socket_scroll: usize,
    pub net_iface_scroll: usize,
    pub timeline: Vec<TimelineEvent>,
    pub timeline_scroll: usize,
    pub saved_scroll: usize,
    pub settings_scroll: usize,
    pub watch_mode: bool,
    pub last_watch_scan: Instant,
    pub scan_progress: crate::net::model::ScanProgress,
    pub scan_cancel: Option<Arc<AtomicBool>>,
    pub ping_target: Option<Ipv4Addr>,
    pub ping_cancel: Option<Arc<AtomicBool>>,
    pub trace_hops: Vec<TracerouteHop>,
    pub trace_running: bool,
    pub trace_cancel: Option<Arc<AtomicBool>>,
    pub modal: Modal,
    pub toast: Option<(String, Instant)>,
    pub tick_count: u64,
    pub splash_until: Option<Instant>,
    pub hover: Option<(u16, u16)>,
    pub last_click: Option<(Ipv4Addr, Instant)>,
    pub hits: HitRegistry,
    pub persist_state: bool,
    pub should_quit: bool,
    pub engine_tx: mpsc::UnboundedSender<EngineEvent>,
    pub engine_rx: mpsc::UnboundedReceiver<EngineEvent>,
    pub last_telemetry_at: Instant,
    pub telemetry_cycle: u64,
    telemetry_inflight: bool,
    prev_online_set: HashSet<Ipv4Addr>,
    prev_open_ports: HashMap<Ipv4Addr, HashSet<u16>>,
}
