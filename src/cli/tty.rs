//! Cycle de vie du terminal (`TerminalGuard`), hooks panic/signaux POSIX et lecture non bloquante du TTY.

use super::*;

pub(super) struct TerminalGuard {
    pub(super) terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    pub(super) fn enter() -> io::Result<Self> {
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

pub(super) fn restore_terminal_state() {
    let mut stdout = io::stdout();
    let _ = stdout.write_all(b"\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[?1000l");
    let _ = execute!(stdout, LeaveAlternateScreen);
    let _ = stdout.flush();
    let _ = disable_raw_mode();
}

pub(super) fn install_panic_hook() {
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
pub(super) fn install_signal_handlers() {
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
pub(super) fn install_signal_handlers() {}

pub(super) enum TtyPoll {
    Ready,
    Timeout,
    Hangup,
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
pub(super) fn tty_has_readable_bytes() -> bool {
    true
}

#[cfg(not(unix))]
pub(super) fn poll_tty(wait_ms: u64) -> io::Result<TtyPoll> {
    if event::poll(Duration::from_millis(wait_ms))? {
        Ok(TtyPoll::Ready)
    } else {
        Ok(TtyPoll::Timeout)
    }
}
