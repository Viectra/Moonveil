//! Per-frame mouse click hit-test regions and wheel scroll targets.

use std::net::Ipv4Addr;

use ratatui::layout::Rect;

use crate::app::Tab;
use crate::config::{AccentId, Language, ThemeId};
use crate::net::model::{ExportFormat, HostSortColumn, PortFilter, ScanPreset};

/// Clickable UI action associated with a bounding terminal `Rect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClickAction {
    SwitchTab(Tab),
    SelectInterface(usize),
    ToggleScan,
    CyclePreset,
    SetPreset(ScanPreset),
    OpenCustomPortsModal,
    FocusSearch,
    ClearSearch,
    SortBy(HostSortColumn),
    SelectHostIp(Ipv4Addr),
    JumpToHostIp(Ipv4Addr),
    SetPortFilter(PortFilter),
    ToggleClosedPorts,
    SelectPortRow(usize),
    OpenRenameModal(Ipv4Addr),
    DeepScanHost(Ipv4Addr),
    PingHost(Ipv4Addr),
    WakeOnLan(Ipv4Addr),
    ToggleTrust(Ipv4Addr),
    CopyText { label: String, value: String },
    SelectRadarOctet(u8),
    RadarPageDelta(i32),
    ExportSnapshot(ExportFormat),
    SetTheme(ThemeId),
    SetAccent(AccentId),
    SetLanguage(Language),
    ToggleAnimations,
    ToggleSplash,
    ToggleGrabBanners,
    ToggleVirtualIfaces,
    AdjustConcurrency(i32),
    AdjustTimeout(i64),
    CloseModal,
    DismissSplash,
    ShowHelp,
    Quit,
}

/// Mouse scroll target region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScrollTarget {
    #[default]
    None,
    HostTable,
    PortList,
}

#[derive(Debug, Clone)]
struct HitRegion {
    rect: Rect,
    action: ClickAction,
}

#[derive(Debug, Clone)]
struct ScrollRegion {
    rect: Rect,
    target: ScrollTarget,
}

/// Tracks clickable regions and scroll panels rendered on the latest frame.
#[derive(Debug, Clone, Default)]
pub struct HitRegistry {
    regions: Vec<HitRegion>,
    scrolls: Vec<ScrollRegion>,
    pub hover_col: Option<u16>,
    pub hover_row: Option<u16>,
}

impl HitRegistry {
    pub fn clear(&mut self) {
        self.regions.clear();
        self.scrolls.clear();
    }

    pub fn record(&mut self, rect: Rect, action: ClickAction) {
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        self.regions.push(HitRegion { rect, action });
    }

    pub fn record_scroll(&mut self, rect: Rect, target: ScrollTarget) {
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        self.scrolls.push(ScrollRegion { rect, target });
    }

    pub fn set_hover(&mut self, col: u16, row: u16) {
        self.hover_col = Some(col);
        self.hover_row = Some(row);
    }

    pub fn is_hovered(&self, rect: Rect) -> bool {
        let (Some(col), Some(row)) = (self.hover_col, self.hover_row) else {
            return false;
        };
        rect_contains(rect, col, row)
    }

    pub fn hit_test(&self, col: u16, row: u16) -> Option<ClickAction> {
        for r in self.regions.iter().rev() {
            if rect_contains(r.rect, col, row) {
                return Some(r.action.clone());
            }
        }
        None
    }

    pub fn scroll_test(&self, col: u16, row: u16) -> ScrollTarget {
        for r in self.scrolls.iter().rev() {
            if rect_contains(r.rect, col, row) {
                return r.target;
            }
        }
        ScrollTarget::None
    }

    pub fn find_action_center(&self, action: &ClickAction) -> Option<(u16, u16)> {
        self.regions.iter().rev().find_map(|r| {
            if &r.action == action && r.rect.width > 0 && r.rect.height > 0 {
                Some((r.rect.x + r.rect.width / 2, r.rect.y + r.rect.height / 2))
            } else {
                None
            }
        })
    }
}

#[inline]
fn rect_contains(r: Rect, col: u16, row: u16) -> bool {
    col >= r.x && col < r.right() && row >= r.y && row < r.bottom()
}
