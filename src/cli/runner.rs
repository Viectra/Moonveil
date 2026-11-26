//! Point d'entrée `run_cli` : export one-shot, initialisation de l'application et boucle d'événements.

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
    if let Some(l) = opts.language {
        cfg.language = l;
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
