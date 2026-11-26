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
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use moonveil_imports::*;

mod moonveil_imports {
    pub use crate::app::App;
    pub use crate::config::{AccentId, Config, ThemeId};
    pub use crate::net::model::{parse_port_expr, ExportFormat, ScanMode, ScanPreset};
    pub use crate::net::scanner::{run_scan, EngineEvent, ScanConfig};
    pub use crate::net::tools::export_snapshot;
    pub use crate::ui;
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static RESIZE_REQUESTED: AtomicBool = AtomicBool::new(false);

struct CliOptions {
    demo_mode: bool,
    no_splash: bool,
    watch: bool,
    iface: Option<String>,
    mode: Option<ScanMode>,
    preset: Option<ScanPreset>,
    custom_ports: Option<String>,
    theme: Option<ThemeId>,
    accent: Option<AccentId>,
    export_job: Option<(ExportFormat, PathBuf)>,
}

enum CliParseOutcome {
    Run(CliOptions),
    ExitZero,
}

fn parse_cli() -> Result<CliParseOutcome, String> {
    let mut opts = CliOptions {
        demo_mode: false,
        no_splash: false,
        watch: false,
        iface: None,
        mode: None,
        preset: None,
        custom_ports: None,
        theme: None,
        accent: None,
        export_job: None,
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-v" | "--version" => {
                println!("Moonveil v{} (Viectra)", env!("CARGO_PKG_VERSION"));
                return Ok(CliParseOutcome::ExitZero);
            }
            "-h" | "--help" => {
                print_help();
                return Ok(CliParseOutcome::ExitZero);
            }
            "--demo" => opts.demo_mode = true,
            "--no-splash" => opts.no_splash = true,
            "--watch" => opts.watch = true,
            "--advanced" => opts.mode = Some(ScanMode::Advanced),
            "--normal" => opts.mode = Some(ScanMode::Normal),
            "-i" | "--iface" | "--interface" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing interface name after --iface".to_string())?;
                opts.iface = Some(v);
            }
            "--preset" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing preset after --preset".to_string())?;
                opts.preset = Some(match v.trim().to_ascii_lowercase().as_str() {
                    "quick" => ScanPreset::Quick,
                    "standard" | "top100" => ScanPreset::Standard,
                    "full" | "top1000" => ScanPreset::Full,
                    "web" | "webdev" => ScanPreset::WebDev,
                    "custom" => ScanPreset::Custom,
                    _ => {
                        return Err(format!(
                            "Unknown preset '{v}' (quick, standard, full, webdev, custom)"
                        ));
                    }
                });
            }
            "--ports" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing port expression after --ports".to_string())?;
                parse_port_expr(&v)?;
                opts.preset = Some(ScanPreset::Custom);
                opts.custom_ports = Some(v);
            }
            "--theme" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing theme after --theme".to_string())?;
                opts.theme = Some(ThemeId::from_cli(&v).ok_or_else(|| {
                    format!("Unknown theme '{v}' (moonveil, obsidian, abyss, graphite, terminal)")
                })?);
            }
            "--accent" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing accent after --accent".to_string())?;
                opts.accent = Some(AccentId::from_cli(&v).ok_or_else(|| {
                    format!("Unknown accent '{v}' (violet, peach, cyan, mint, rose, amber)")
                })?);
            }
            "--export" => {
                let fmt_s = args
                    .next()
                    .ok_or_else(|| "Usage: --export <json|csv|md> <output_path>".to_string())?;
                let path_s = args
                    .next()
                    .ok_or_else(|| "Usage: --export <json|csv|md> <output_path>".to_string())?;
                let fmt = match fmt_s.to_ascii_lowercase().as_str() {
                    "json" => ExportFormat::Json,
                    "csv" => ExportFormat::Csv,
                    "md" | "markdown" => ExportFormat::Markdown,
                    _ => return Err(format!("Unsupported export format '{fmt_s}'")),
                };
                opts.export_job = Some((fmt, PathBuf::from(path_s)));
            }
            other => {
                return Err(format!(
                    "Unknown argument '{other}'. Run 'moonveil --help' for usage."
                ));
            }
        }
    }
    Ok(CliParseOutcome::Run(opts))
}

fn print_help() {
    println!(
        "\
Moonveil (mvl) v{} — Clickable terminal network scanner, subnet radar & socket inspector

USAGE:
    moonveil [OPTIONS]
    mvl [OPTIONS]

OPTIONS:
    --demo                        Run with realistic simulated LAN & Docker telemetry
    -i, --iface <NAME>            Select initial network interface (e.g. enp6s18, wlan0)
    --normal / --advanced         Start in Normal Mode or Advanced Mode
    --preset <PRESET>             quick | standard | full | webdev | custom
    --ports <EXPR>                Custom ports (e.g. 22,80,443,8000-8090)
    --watch                       Enable background Watch Mode on startup
    --theme <THEME>               moonveil | obsidian | abyss | graphite | terminal
    --accent <COLOR>              violet | peach | cyan | mint | rose | amber
    --no-splash                   Skip the animated launch logo reveal
    --export <FMT> <PATH>         Run one-shot scan and write json, csv, or md report
    -h, --help                    Print this help message
    -v, --version                 Print version information",
        env!("CARGO_PKG_VERSION")
    );
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, Clear(ClearType::All))?;
        stdout.write_all(b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h")?;
        stdout.flush()?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_state();
        let _ = self.terminal.show_cursor();
    }
}

fn restore_terminal_state() {
    let mut stdout = io::stdout();
    let _ = stdout.write_all(b"\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[?1000l");
    let _ = execute!(stdout, LeaveAlternateScreen);
    let _ = stdout.flush();
    let _ = disable_raw_mode();
}

fn install_panic_hook() {
    let orig = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        restore_terminal_state();
        orig(info);
    }));
}

#[cfg(unix)]
extern "C" fn handle_posix_signal(sig: libc::c_int) {
    let was_requested = SHUTDOWN_REQUESTED.swap(true, Ordering::SeqCst);
    if was_requested || sig == libc::SIGHUP {
        let seq = b"\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[?1000l\x1b[?25h\x1b[?1049l";
        unsafe {
            let _ = libc::write(
                libc::STDOUT_FILENO,
                seq.as_ptr().cast::<libc::c_void>(),
                seq.len(),
            );
            libc::_exit(0);
        }
    }
}

#[cfg(unix)]
extern "C" fn handle_winch_signal(_sig: libc::c_int) {
    RESIZE_REQUESTED.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_posix_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());

        let mut sa_winch: libc::sigaction = std::mem::zeroed();
        sa_winch.sa_sigaction = handle_winch_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa_winch.sa_mask);
        sa_winch.sa_flags = 0;
        libc::sigaction(libc::SIGWINCH, &sa_winch, std::ptr::null_mut());
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

enum TtyPoll {
    Ready,
    Timeout,
    Hangup,
}

/// Streaming level-triggered ANSI input parser for arbitrary-size SSH mouse & key bursts.
#[derive(Default)]
pub struct AnsiInputParser {
    raw: Vec<u8>,
    events: VecDeque<Event>,
    incomplete_since: Option<Instant>,
}

impl AnsiInputParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.raw.extend_from_slice(bytes);
            self.parse_available(false);
        }
    }

    pub fn flush_expired(&mut self, max_age: Duration) {
        if !self.raw.is_empty()
            && self
                .incomplete_since
                .is_some_and(|started| started.elapsed() >= max_age)
        {
            self.parse_available(true);
        }
    }

    pub fn has_incomplete(&self) -> bool {
        !self.raw.is_empty()
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn parse_available(&mut self, force_incomplete: bool) {
        let mut pos = 0_usize;
        let len = self.raw.len();

        while pos < len {
            let b = self.raw[pos];

            if b == 0x1B {
                if pos + 1 >= len {
                    if force_incomplete {
                        self.events.push_back(Event::Key(KeyCode::Esc.into()));
                        pos += 1;
                    } else {
                        break;
                    }
                    continue;
                }

                let next = self.raw[pos + 1];
                if next == b'[' {
                    if pos + 2 >= len {
                        if force_incomplete {
                            pos += 2;
                            continue;
                        } else {
                            break;
                        }
                    }

                    // SGR Mouse: ESC [ < Cb ; Cx ; Cy M|m
                    if self.raw[pos + 2] == b'<' {
                        let scan_end = len.min(pos + 32);
                        let mut fin_idx = None;
                        for (rel, &ch) in self.raw[(pos + 3)..scan_end].iter().enumerate() {
                            if (0x40..=0x7E).contains(&ch) || ch < 0x20 {
                                fin_idx = Some(pos + 3 + rel);
                                break;
                            }
                        }
                        if let Some(end) = fin_idx {
                            let fin = self.raw[end];
                            if matches!(fin, b'M' | b'm') {
                                if let Some((cb, cx, cy)) =
                                    parse_three_u16s(&self.raw[pos + 3..end])
                                {
                                    let col = cx.saturating_sub(1);
                                    let row = cy.saturating_sub(1);
                                    self.events.push_back(Event::Mouse(decode_mouse_sgr(
                                        cb,
                                        col,
                                        row,
                                        fin == b'm',
                                    )));
                                }
                            }
                            pos = end + 1;
                            continue;
                        } else if !force_incomplete && len - pos < 32 {
                            break;
                        } else {
                            pos += 3;
                            continue;
                        }
                    }

                    // X10 Mouse: ESC [ M Cb Cx Cy
                    if self.raw[pos + 2] == b'M' {
                        if pos + 6 > len {
                            if force_incomplete {
                                pos += 3;
                                continue;
                            } else {
                                break;
                            }
                        }
                        let cb = u16::from(self.raw[pos + 3].wrapping_sub(32));
                        let col = u16::from(self.raw[pos + 4].wrapping_sub(33));
                        let row = u16::from(self.raw[pos + 5].wrapping_sub(33));
                        self.events
                            .push_back(Event::Mouse(decode_mouse_sgr(cb, col, row, false)));
                        pos += 6;
                        continue;
                    }

                    // General CSI sequence
                    let scan_end = len.min(pos + 64);
                    let mut fin_idx = None;
                    let mut aborted = false;
                    for (rel, &ch) in self.raw[(pos + 2)..scan_end].iter().enumerate() {
                        if (0x40..=0x7E).contains(&ch) {
                            fin_idx = Some(pos + 2 + rel);
                            break;
                        } else if !(0x20..=0x3F).contains(&ch) {
                            aborted = true;
                            break;
                        }
                    }
                    if aborted {
                        pos += 2;
                        continue;
                    }
                    if let Some(end) = fin_idx {
                        let fin = self.raw[end];
                        let params = &self.raw[pos + 2..end];
                        if let Some(ev) = decode_csi_event(params, fin) {
                            self.events.push_back(ev);
                        }
                        pos = end + 1;
                        continue;
                    } else if !force_incomplete && len - pos < 64 {
                        break;
                    } else {
                        pos += 2;
                        continue;
                    }
                } else if next == b'O' {
                    if pos + 2 >= len {
                        if force_incomplete {
                            pos += 2;
                            continue;
                        } else {
                            break;
                        }
                    }
                    if let Some(code) = decode_ss3_key(self.raw[pos + 2]) {
                        self.events.push_back(Event::Key(code.into()));
                    }
                    pos += 3;
                    continue;
                } else if next == 0x1B {
                    self.events.push_back(Event::Key(KeyCode::Esc.into()));
                    pos += 1;
                    continue;
                } else {
                    // Alt + character
                    match decode_utf8_at(&self.raw[pos + 1..], force_incomplete) {
                        Utf8Step::NeedMore => break,
                        Utf8Step::Invalid => {
                            pos += 2;
                            continue;
                        }
                        Utf8Step::Char(ch, w) => {
                            self.events.push_back(Event::Key(KeyEvent::new(
                                KeyCode::Char(ch),
                                KeyModifiers::ALT,
                            )));
                            pos += 1 + w;
                            continue;
                        }
                    }
                }
            }

            match b {
                b'\r' | b'\n' => {
                    self.events.push_back(Event::Key(KeyCode::Enter.into()));
                    pos += 1;
                }
                b'\t' => {
                    self.events.push_back(Event::Key(KeyCode::Tab.into()));
                    pos += 1;
                }
                0x7F | 0x08 => {
                    self.events.push_back(Event::Key(KeyCode::Backspace.into()));
                    pos += 1;
                }
                c @ 0x01..=0x1A => {
                    self.events.push_back(Event::Key(KeyEvent::new(
                        KeyCode::Char((c - 1 + b'a') as char),
                        KeyModifiers::CONTROL,
                    )));
                    pos += 1;
                }
                0x00..=0x1F => {
                    pos += 1;
                }
                0x20..=0x7E => {
                    let ch = b as char;
                    let mods = if ch.is_uppercase() {
                        KeyModifiers::SHIFT
                    } else {
                        KeyModifiers::NONE
                    };
                    self.events
                        .push_back(Event::Key(KeyEvent::new(KeyCode::Char(ch), mods)));
                    pos += 1;
                }
                _ => match decode_utf8_at(&self.raw[pos..], force_incomplete) {
                    Utf8Step::NeedMore => break,
                    Utf8Step::Invalid => {
                        pos += 1;
                    }
                    Utf8Step::Char(ch, w) => {
                        let mods = if ch.is_uppercase() {
                            KeyModifiers::SHIFT
                        } else {
                            KeyModifiers::NONE
                        };
                        self.events
                            .push_back(Event::Key(KeyEvent::new(KeyCode::Char(ch), mods)));
                        pos += w;
                    }
                },
            }
        }

        if pos > 0 {
            self.raw.drain(..pos);
        }
        self.incomplete_since = if self.raw.is_empty() {
            None
        } else {
            Some(self.incomplete_since.unwrap_or_else(Instant::now))
        };
    }
}

enum Utf8Step {
    Char(char, usize),
    NeedMore,
    Invalid,
}

fn decode_utf8_at(slice: &[u8], force_incomplete: bool) -> Utf8Step {
    if slice.is_empty() {
        return Utf8Step::NeedMore;
    }
    let first = slice[0];
    let width = if first < 0x80 {
        1
    } else if (first & 0xE0) == 0xC0 {
        2
    } else if (first & 0xF0) == 0xE0 {
        3
    } else if (first & 0xF8) == 0xF0 {
        4
    } else {
        return Utf8Step::Invalid;
    };
    if slice.len() < width {
        return if force_incomplete {
            Utf8Step::Invalid
        } else {
            Utf8Step::NeedMore
        };
    }
    match std::str::from_utf8(&slice[..width]) {
        Ok(s) => match s.chars().next() {
            Some(ch) => Utf8Step::Char(ch, width),
            None => Utf8Step::Invalid,
        },
        Err(_) => Utf8Step::Invalid,
    }
}

fn parse_three_u16s(bytes: &[u8]) -> Option<(u16, u16, u16)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let mut parts = s.split(';');
    let a = parts.next()?.parse::<u16>().ok()?;
    let b = parts.next()?.parse::<u16>().ok()?;
    let c = parts.next()?.parse::<u16>().ok()?;
    Some((a, b, c))
}

fn decode_mouse_sgr(cb: u16, col: u16, row: u16, is_release: bool) -> MouseEvent {
    let mut modifiers = KeyModifiers::NONE;
    if (cb & 4) != 0 {
        modifiers |= KeyModifiers::SHIFT;
    }
    if (cb & 8) != 0 {
        modifiers |= KeyModifiers::ALT;
    }
    if (cb & 16) != 0 {
        modifiers |= KeyModifiers::CONTROL;
    }

    let low = cb & 0b11;
    let is_motion = (cb & 32) != 0;
    let is_scroll = (cb & 64) != 0;

    let kind = if is_scroll {
        match low {
            0 => MouseEventKind::ScrollUp,
            1 => MouseEventKind::ScrollDown,
            2 => MouseEventKind::ScrollLeft,
            _ => MouseEventKind::ScrollRight,
        }
    } else if is_motion {
        match low {
            0 => MouseEventKind::Drag(MouseButton::Left),
            1 => MouseEventKind::Drag(MouseButton::Middle),
            2 => MouseEventKind::Drag(MouseButton::Right),
            _ => MouseEventKind::Moved,
        }
    } else if is_release {
        match low {
            0 => MouseEventKind::Up(MouseButton::Left),
            1 => MouseEventKind::Up(MouseButton::Middle),
            _ => MouseEventKind::Up(MouseButton::Right),
        }
    } else {
        match low {
            0 => MouseEventKind::Down(MouseButton::Left),
            1 => MouseEventKind::Down(MouseButton::Middle),
            2 => MouseEventKind::Down(MouseButton::Right),
            _ => MouseEventKind::Up(MouseButton::Left),
        }
    };

    MouseEvent {
        kind,
        column: col,
        row,
        modifiers,
    }
}

fn decode_csi_modifiers(params_str: &str) -> KeyModifiers {
    let Some((_, mod_s)) = params_str.split_once(';') else {
        return KeyModifiers::NONE;
    };
    let Ok(m) = mod_s.split(';').next().unwrap_or("").parse::<u8>() else {
        return KeyModifiers::NONE;
    };
    let bits = m.saturating_sub(1);
    let mut mods = KeyModifiers::NONE;
    if (bits & 1) != 0 {
        mods |= KeyModifiers::SHIFT;
    }
    if (bits & 2) != 0 {
        mods |= KeyModifiers::ALT;
    }
    if (bits & 4) != 0 {
        mods |= KeyModifiers::CONTROL;
    }
    mods
}

fn decode_csi_event(params: &[u8], fin: u8) -> Option<Event> {
    if fin == b'M' && params.contains(&b';') {
        if let Some((cb_raw, cx, cy)) = parse_three_u16s(params) {
            let cb = cb_raw.saturating_sub(32);
            let col = cx.saturating_sub(1);
            let row = cy.saturating_sub(1);
            return Some(Event::Mouse(decode_mouse_sgr(cb, col, row, false)));
        }
    }

    let params_str = std::str::from_utf8(params).unwrap_or("");
    let mods = decode_csi_modifiers(params_str);
    let key = match fin {
        b'A' => KeyEvent::new(KeyCode::Up, mods),
        b'B' => KeyEvent::new(KeyCode::Down, mods),
        b'C' => KeyEvent::new(KeyCode::Right, mods),
        b'D' => KeyEvent::new(KeyCode::Left, mods),
        b'H' => KeyEvent::new(KeyCode::Home, mods),
        b'F' => KeyEvent::new(KeyCode::End, mods),
        b'Z' => KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
        b'P' => KeyEvent::new(KeyCode::F(1), mods),
        b'Q' => KeyEvent::new(KeyCode::F(2), mods),
        b'S' => KeyEvent::new(KeyCode::F(4), mods),
        b'~' => {
            let num = params_str.split(';').next()?.parse::<u16>().ok()?;
            let code = match num {
                1 | 7 => KeyCode::Home,
                2 => KeyCode::Insert,
                3 => KeyCode::Delete,
                4 | 8 => KeyCode::End,
                5 => KeyCode::PageUp,
                6 => KeyCode::PageDown,
                15 => KeyCode::F(5),
                17 => KeyCode::F(6),
                18 => KeyCode::F(7),
                19 => KeyCode::F(8),
                20 => KeyCode::F(9),
                21 => KeyCode::F(10),
                23 => KeyCode::F(11),
                24 => KeyCode::F(12),
                _ => return None,
            };
            KeyEvent::new(code, mods)
        }
        _ => return None,
    };
    Some(Event::Key(key))
}

fn decode_ss3_key(b: u8) -> Option<KeyCode> {
    match b {
        b'A' => Some(KeyCode::Up),
        b'B' => Some(KeyCode::Down),
        b'C' => Some(KeyCode::Right),
        b'D' => Some(KeyCode::Left),
        b'H' => Some(KeyCode::Home),
        b'F' => Some(KeyCode::End),
        val @ b'P'..=b'S' => Some(KeyCode::F(1 + (val - b'P'))),
        _ => None,
    }
}

#[cfg(unix)]
fn tty_readable_bytes() -> usize {
    let mut avail: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::FIONREAD, &mut avail) };
    if rc == 0 && avail > 0 {
        avail as usize
    } else {
        0
    }
}

#[cfg(unix)]
fn tty_has_readable_bytes() -> bool {
    tty_readable_bytes() > 0
}

#[cfg(unix)]
fn poll_tty(wait_ms: u64) -> io::Result<TtyPoll> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } == 0 {
        return Ok(TtyPoll::Hangup);
    }

    let mut pfd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = wait_ms.min(i32::MAX as u64) as libc::c_int;
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(TtyPoll::Timeout);
        }
        return Ok(TtyPoll::Hangup);
    }
    if rc == 0 {
        return Ok(TtyPoll::Timeout);
    }
    if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
        return Ok(TtyPoll::Hangup);
    }
    if (pfd.revents & libc::POLLIN) != 0 {
        if !tty_has_readable_bytes() {
            return Ok(TtyPoll::Hangup);
        }
        return Ok(TtyPoll::Ready);
    }
    Ok(TtyPoll::Timeout)
}

#[cfg(not(unix))]
fn tty_has_readable_bytes() -> bool {
    true
}

#[cfg(not(unix))]
fn poll_tty(wait_ms: u64) -> io::Result<TtyPoll> {
    if event::poll(Duration::from_millis(wait_ms))? {
        Ok(TtyPoll::Ready)
    } else {
        Ok(TtyPoll::Timeout)
    }
}

/// Runs the Moonveil CLI & TUI event loop.
pub async fn run_cli() {
    let opts = match parse_cli() {
        Ok(CliParseOutcome::ExitZero) => return,
        Ok(CliParseOutcome::Run(o)) => o,
        Err(msg) => {
            eprintln!("error: {msg}");
            std::process::exit(2);
        }
    };

    let mut cfg = Config::load();
    if let Some(m) = opts.mode {
        cfg.mode = m;
    }
    if let Some(p) = opts.preset {
        cfg.default_preset = p;
    }
    if let Some(ports) = opts.custom_ports {
        cfg.custom_ports = ports;
    }
    if let Some(t) = opts.theme {
        cfg.theme = t;
    }
    if let Some(a) = opts.accent {
        cfg.accent = a;
    }
    if opts.no_splash {
        cfg.splash = false;
    }

    if let Some((fmt, out_path)) = opts.export_job {
        let mut app = App::new(cfg, opts.demo_mode, opts.iface.as_deref());
        if !opts.demo_mode {
            if let Some(iface) = app.active_interface().cloned() {
                let (tx, mut rx) = mpsc::unbounded_channel();
                let cancel = Arc::new(AtomicBool::new(false));
                let scan_cfg = ScanConfig {
                    interface: iface,
                    preset: app.config.default_preset,
                    custom_ports: app.config.custom_ports.clone(),
                    concurrency: app.config.concurrency,
                    timeout_ms: app.config.timeout_ms,
                    grab_banners: app.config.grab_banners,
                    privilege: app.snapshot.privilege,
                    radar_page_offset: 0,
                    single_host: None,
                    local_sockets: app.snapshot.local_sockets.clone(),
                    existing_hosts: app
                        .snapshot
                        .hosts
                        .iter()
                        .map(|h| (h.ip, h.clone()))
                        .collect(),
                };
                let handle = tokio::spawn(async move {
                    run_scan(scan_cfg, cancel, tx).await;
                });
                while let Some(ev) = rx.recv().await {
                    match ev {
                        EngineEvent::HostUpsert(host) => {
                            if let Some(existing) =
                                app.snapshot.hosts.iter_mut().find(|h| h.ip == host.ip)
                            {
                                *existing = *host;
                            } else {
                                app.snapshot.hosts.push(*host);
                            }
                        }
                        EngineEvent::ScanCompleted { .. } => break,
                        _ => {}
                    }
                }
                let _ = handle.await;
            }
        }
        if let Err(err) = export_snapshot(&app.snapshot, fmt, &out_path) {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
        println!(
            "Exported {} snapshot to {}",
            fmt.label(),
            out_path.display()
        );
        return;
    }

    install_panic_hook();
    install_signal_handlers();

    let mut guard = match TerminalGuard::enter() {
        Ok(g) => g,
        Err(err) => {
            eprintln!("Failed to initialize terminal: {err}");
            std::process::exit(1);
        }
    };

    let mut app = App::new(cfg, opts.demo_mode, opts.iface.as_deref());
    app.watch_mode = opts.watch;
    app.start_scan(None);

    let mut dirty = true;

    #[cfg(unix)]
    {
        let mut parser = AnsiInputParser::new();
        while !app.should_quit && !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            if RESIZE_REQUESTED.swap(false, Ordering::Relaxed) {
                let _ = guard.terminal.autoresize();
                dirty = true;
            }

            if dirty {
                if guard.terminal.draw(|f| ui::render(f, &mut app)).is_err() {
                    break;
                }
                dirty = false;
            }

            let wait_ms = if parser.has_incomplete() {
                25
            } else if app.is_splash_active() || app.scan_progress.active {
                60
            } else {
                180
            };

            match poll_tty(wait_ms) {
                Ok(TtyPoll::Hangup) | Err(_) => break,
                Ok(TtyPoll::Ready) => {
                    let mut buf = [0u8; 4096];
                    loop {
                        let want = tty_readable_bytes().clamp(1, buf.len());
                        let n = unsafe {
                            libc::read(
                                libc::STDIN_FILENO,
                                buf.as_mut_ptr().cast::<libc::c_void>(),
                                want,
                            )
                        };
                        if n > 0 {
                            parser.push_bytes(&buf[..n as usize]);
                            if tty_readable_bytes() == 0 {
                                break;
                            }
                        } else if n == 0 {
                            app.should_quit = true;
                            break;
                        } else {
                            let err = io::Error::last_os_error();
                            if err.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            if err.kind() != io::ErrorKind::WouldBlock {
                                app.should_quit = true;
                            }
                            break;
                        }
                    }
                }
                Ok(TtyPoll::Timeout) => {
                    parser.flush_expired(Duration::from_millis(20));
                }
            }

            while let Some(ev) = parser.pop_event() {
                match ev {
                    Event::Key(k)
                        if matches!(k.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                    {
                        app.handle_key(k);
                        dirty = true;
                    }
                    Event::Mouse(m) => {
                        if app.handle_mouse(m) {
                            dirty = true;
                        }
                    }
                    Event::Resize(_, _) => {
                        let _ = guard.terminal.autoresize();
                        dirty = true;
                    }
                    _ => {}
                }
                if app.should_quit || SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                    break;
                }
            }

            if app.on_tick() {
                dirty = true;
            }
        }
    }

    #[cfg(not(unix))]
    {
        while !app.should_quit && !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            if dirty {
                if guard.terminal.draw(|f| ui::render(f, &mut app)).is_err() {
                    break;
                }
                dirty = false;
            }

            let wait_ms = if app.is_splash_active() || app.scan_progress.active {
                60
            } else {
                180
            };

            if let Ok(TtyPoll::Ready) = poll_tty(wait_ms) {
                loop {
                    match event::read() {
                        Ok(Event::Key(k))
                            if matches!(k.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                        {
                            app.handle_key(k);
                            dirty = true;
                        }
                        Ok(Event::Mouse(m)) => {
                            if app.handle_mouse(m) {
                                dirty = true;
                            }
                        }
                        Ok(Event::Resize(_, _)) => {
                            let _ = guard.terminal.autoresize();
                            dirty = true;
                        }
                        Ok(_) => {}
                        Err(_) => {
                            app.should_quit = true;
                            break;
                        }
                    }
                    if app.should_quit
                        || SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
                        || !event::poll(Duration::ZERO).unwrap_or(false)
                    {
                        break;
                    }
                }
            }

            if app.on_tick() {
                dirty = true;
            }
        }
    }
}
