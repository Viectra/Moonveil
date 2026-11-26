//! Moonveil CLI parsing, SSH-ready terminal lifecycle, and non-blocking event loop.

use std::collections::VecDeque;
use std::env;
use std::io::{self, Stdout, Write};
use std::panic;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(not(unix))]
use crossterm::event;
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use moonveil_imports::*;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

mod args;
mod input;
mod runner;
mod tty;
use args::*;
pub use input::*;
pub use runner::*;
use tty::*;

mod moonveil_imports {
    pub use crate::app::App;
    pub use crate::config::{AccentId, Config, Language, ThemeId};
    pub use crate::net::model::{parse_port_expr, ExportFormat, ScanMode, ScanPreset};
    pub use crate::net::scanner::{run_scan, EngineEvent, ScanConfig};
    pub use crate::net::tools::export_snapshot;
    pub use crate::ui;
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

static RESIZE_REQUESTED: AtomicBool = AtomicBool::new(false);
