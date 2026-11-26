//! Main CLI runner: export jobs and interactive TUI event loop.

use super::*;

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
    if let Some(lang) = opts.language {
        cfg.language = lang;
    }
    if opts.no_splash {
        cfg.splash = false;
    }

    if let Some((fmt, out_path)) = opts.export_job {
        run_export_job(cfg, opts.demo_mode, opts.iface.as_deref(), fmt, out_path).await;
        return;
    }

    install_signal_handlers();

    let mut guard = match TerminalGuard::enter() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed entering terminal UI: {e}");
            std::process::exit(1);
        }
    };

    let mut app = App::new(cfg, opts.demo_mode, opts.iface.as_deref());
    if opts.watch {
        app.watch_enabled = true;
    }
    app.start_scan();

    let mut dirty = true;

    #[cfg(unix)]
    {
        let mut parser = AnsiInputParser::new();
        let mut buf = [0u8; 4096];

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

            let wait_ms = if app.is_splash_active() || app.scan_progress.active {
                60
            } else {
                180
            };

            match poll_tty(wait_ms) {
                Ok(TtyPoll::Hangup) | Err(_) => {
                    app.should_quit = true;
                    break;
                }
                Ok(TtyPoll::Ready) => {
                    loop {
                        let n = unsafe {
                            libc::read(
                                libc::STDIN_FILENO,
                                buf.as_mut_ptr().cast::<libc::c_void>(),
                                buf.len(),
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
                    parser.flush_expired(Duration::from_millis(20));
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
                    match crossterm::event::read() {
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
                        || !crossterm::event::poll(Duration::ZERO).unwrap_or(false)
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

async fn run_export_job(
    cfg: Config,
    demo_mode: bool,
    iface_name: Option<&str>,
    fmt: ExportFormat,
    out_path: PathBuf,
) {
    let mut app = App::new(cfg, demo_mode, iface_name);
    if !demo_mode {
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

    match export_snapshot(&app.snapshot, fmt, &out_path) {
        Ok(()) => println!("Exported snapshot to {}", out_path.display()),
        Err(e) => {
            eprintln!("Export failed: {e}");
            std::process::exit(1);
        }
    }
}
