//! Moonveil CLI parsing, terminal lifecycle, and interactive event loop.

use std::env;
use std::io::{self, Stdout};
use std::panic;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use crate::app::App;
use crate::config::{AccentId, Config, ThemeId};
use crate::net::model::{ExportFormat, ScanMode};
use crate::net::scanner::{run_scan, EngineEvent, ScanConfig};
use crate::net::tools::export_snapshot;
use crate::ui;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

struct CliOptions {
    demo_mode: bool,
    no_splash: bool,
    iface: Option<String>,
    mode: Option<ScanMode>,
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
        iface: None,
        mode: None,
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
            "--advanced" => opts.mode = Some(ScanMode::Advanced),
            "--normal" => opts.mode = Some(ScanMode::Normal),
            "--iface" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing interface name after --iface".to_string())?;
                opts.iface = Some(v);
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
    --iface <NAME>                Select initial network interface (e.g. enp6s18, wlan0)
    --normal / --advanced         Start in Normal Mode or Advanced Mode
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
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;
        terminal.clear()?;
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
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
}

fn install_panic_hook() {
    let orig = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        restore_terminal_state();
        orig(info);
    }));
}

extern "C" fn handle_sig(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, handle_sig as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_sig as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, handle_sig as *const () as libc::sighandler_t);
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
    app.start_scan(None);

    let tick_interval = Duration::from_millis(80);
    while !app.should_quit && !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        if let Err(err) = guard.terminal.draw(|f| ui::render(f, &mut app)) {
            eprintln!("Render error: {err}");
            break;
        }

        if event::poll(tick_interval).unwrap_or(false) {
            if let Ok(ev) = event::read() {
                match ev {
                    Event::Key(k) if k.kind == KeyEventKind::Press => app.handle_key(k),
                    Event::Mouse(m) => app.handle_mouse(m),
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
        }
        app.on_tick();
    }
}
