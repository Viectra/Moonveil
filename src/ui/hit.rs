//! Mouse hit-test and scroll-zone registry for clickable terminal UI controls.

use std::net::Ipv4Addr;

use ratatui::layout::Rect;

use crate::app::{SocketFilter, Tab};
use crate::config::{AccentId, Language, ThemeId};
use crate::net::model::{
    DeviceRole, ExportFormat, HostSortColumn, PortFilter, ScanMode, ScanPreset,
};

/// Action dispatched when a registered UI rectangle is clicked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClickAction {
    SwitchTab(Tab),
    ToggleMode,
    SetMode(ScanMode),
    CycleInterface,
    SelectInterface(usize),
    StartOrStopScan,
    CyclePreset,
    SetPreset(ScanPreset),
    ToggleWatch,
    ToggleHelp,
    CloseModal,
    Quit,
    SkipSplash,

    FocusSearch,
    ClearSearch,
    SortBy(HostSortColumn),
    SelectHost(Ipv4Addr),
    ToggleInspectorPane,
    ToggleTrusted(Ipv4Addr),
    OpenRenameModal(Ipv4Addr),
    SetPortFilter(PortFilter),
    ToggleClosedPorts,
    TogglePingMonitor(Ipv4Addr),
    LaunchTraceroute(Ipv4Addr),
    SendWol(Ipv4Addr),
    DeepScanHost(Ipv4Addr),
    CopyText(String, String),

    SelectRadarOctet(u8),
    RadarPageDelta(i32),
    RadarFilterRole(Option<DeviceRole>),

    SelectNetInterface(usize),
    SetSocketFilter(SocketFilter),
    FocusSocketSearch,
    ClearSocketSearch,
    JumpToHostIp(Ipv4Addr),

    ExportSnapshot(ExportFormat),
    ClearTimeline,

    SetLanguage(Language),
    SetTheme(ThemeId),
    SetAccent(AccentId),
    ToggleAnimations,
    ToggleSplash,
    ToggleVirtualIfaces,
    ToggleGrabBanners,
    CycleConcurrency,
    CycleTimeout,
    CycleWatchInterval,
    OpenCustomPortsModal,
    ResetDefaults,
}

/// Mouse-wheel scrollable region target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollTarget {
    Hosts,
    InspectorPorts,
    Sockets,
    Interfaces,
    Timeline,
    SavedHosts,
    Settings,
}

/// Frame-local registry of clickable hit rects and scroll zones.
#[derive(Debug, Default)]
pub struct HitRegistry {
    regions: Vec<(Rect, ClickAction)>,
    scroll_zones: Vec<(Rect, ScrollTarget)>,
}

impl HitRegistry {
    pub fn clear(&mut self) {
        self.regions.clear();
        self.scroll_zones.clear();
    }

    pub fn register(&mut self, rect: Rect, action: ClickAction) {
        if rect.width > 0 && rect.height > 0 {
            self.regions.push((rect, action));
        }
    }

    pub fn register_scroll(&mut self, rect: Rect, target: ScrollTarget) {
        if rect.width > 0 && rect.height > 0 {
            self.scroll_zones.push((rect, target));
        }
    }

    pub fn hit_test(&self, col: u16, row: u16) -> Option<ClickAction> {
        self.regions
            .iter()
            .rev()
            .find(|(r, _)| rect_contains(*r, col, row))
            .map(|(_, a)| a.clone())
    }

    pub fn scroll_target(&self, col: u16, row: u16) -> Option<ScrollTarget> {
        self.scroll_zones
            .iter()
            .rev()
            .find(|(r, _)| rect_contains(*r, col, row))
            .map(|(_, t)| *t)
    }

    pub fn is_hovered(rect: Rect, hover: Option<(u16, u16)>) -> bool {
        match hover {
            Some((c, r)) => rect_contains(rect, c, r),
            None => false,
        }
    }

    pub fn find_action_center(&self, target: &ClickAction) -> Option<(u16, u16)> {
        self.regions
            .iter()
            .rev()
            .find(|(_, a)| a == target)
            .map(|(r, _)| (r.x + r.width / 2, r.y + r.height / 2))
    }
}

pub const fn rect_contains(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x
        && col < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}
