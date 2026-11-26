//! Terminal guard lifecycle, POSIX signal handling, and TTY polling.

use super::*;

pub(super) enum TtyPoll {
    Ready,
    Timeout,
    Hangup,
}

#[cfg(unix)]
extern "C" fn handle_posix_signal(sig: libc::c_int) {
    match sig {
        libc::SIGWINCH => RESIZE_REQUESTED.store(true, Ordering::Relaxed),
        _ => SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed),
    }
}

#[cfg(unix)]
pub(super) fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_posix_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;

        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
}

#[cfg(not(unix))]
pub(super) fn install_signal_handlers() {}

fn write_terminal_cleanup_seq(stdout: &mut io::Stdout) {
    let _ = stdout.write_all(b"\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[?1000l\x1b[?1015l");
    let _ = execute!(
        stdout,
        Clear(ClearType::All),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
    let _ = stdout.flush();
}

pub(super) struct TerminalGuard {
    pub(super) terminal: Terminal<CrosstermBackend<io::Stdout>>,
    cleaned: bool,
    #[cfg(unix)]
    orig_stdin_flags: Option<libc::c_int>,
}

impl TerminalGuard {
    pub(super) fn enter() -> io::Result<Self> {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let mut stdout = io::stdout();
            write_terminal_cleanup_seq(&mut stdout);
            prev_hook(info);
        }));

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(
            stdout,
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableMouseCapture,
            crossterm::cursor::Hide
        )?;
        // Enable X10/button-motion/SGR 1006 mouse explicitly so SSH multiplexers route clicks.
        let _ = stdout.write_all(b"\x1b[?1000h\x1b[?1002h\x1b[?1006h");
        let _ = stdout.flush();

        #[cfg(unix)]
        let orig_stdin_flags = unsafe {
            let flags = libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK);
                Some(flags)
            } else {
                None
            }
        };

        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self {
            terminal,
            cleaned: false,
            #[cfg(unix)]
            orig_stdin_flags,
        })
    }

    pub(super) fn restore(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        #[cfg(unix)]
        if let Some(flags) = self.orig_stdin_flags {
            unsafe {
                let _ = libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags);
            }
        }
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        write_terminal_cleanup_seq(&mut stdout);
        let _ = self.terminal.show_cursor();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(unix)]
pub(super) fn tty_readable_bytes() -> usize {
    let mut avail: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::FIONREAD, &mut avail) };
    if rc == 0 && avail > 0 {
        avail as usize
    } else {
        0
    }
}

#[cfg(unix)]
pub(super) fn tty_has_readable_bytes() -> bool {
    tty_readable_bytes() > 0
}

#[cfg(unix)]
pub(super) fn poll_tty(wait_ms: u64) -> io::Result<TtyPoll> {
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
pub(super) fn poll_tty(wait_ms: u64) -> io::Result<TtyPoll> {
    if event::poll(Duration::from_millis(wait_ms))? {
        Ok(TtyPoll::Ready)
    } else {
        Ok(TtyPoll::Timeout)
    }
}
