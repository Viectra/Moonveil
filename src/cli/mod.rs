//! CLI entrypoint, signal handling, SSH-friendly ANSI input, and terminal lifecycle.

mod args;
mod input;
mod runner;
mod tty;

use std::collections::VecDeque;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, Event,
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use crate::app::App;
use crate::config::{AccentId, Config, Language, ThemeId};
use crate::net::model::{parse_port_expr, ExportFormat, ScanMode, ScanPreset};
use crate::net::scanner::{run_scan, EngineEvent, ScanConfig};
use crate::net::tools::export_snapshot;
use crate::ui;

use args::{parse_cli, CliParseOutcome};
use tty::{install_signal_handlers, poll_tty, tty_readable_bytes, TerminalGuard, TtyPoll};

pub use input::AnsiInputParser;
pub use runner::run_cli;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static RESIZE_REQUESTED: AtomicBool = AtomicBool::new(false);
