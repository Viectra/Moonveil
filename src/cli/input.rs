//! Décodeur ANSI/UTF-8 des entrées TTY (`AnsiInputParser`) : touches, séquences CSI/SS3 et souris SGR.

use super::*;

/// Streaming level-triggered ANSI input parser for arbitrary-size SSH mouse & key bursts.
#[derive(Default)]
pub struct AnsiInputParser {
    pub(super) raw: Vec<u8>,
    pub(super) events: VecDeque<Event>,
    pub(super) incomplete_since: Option<Instant>,
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

    pub(super) fn parse_available(&mut self, force_incomplete: bool) {
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

pub(super) enum Utf8Step {
    Char(char, usize),
    NeedMore,
    Invalid,
}

pub(super) fn decode_utf8_at(slice: &[u8], force_incomplete: bool) -> Utf8Step {
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

pub(super) fn parse_three_u16s(bytes: &[u8]) -> Option<(u16, u16, u16)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let mut parts = s.split(';');
    let a = parts.next()?.parse::<u16>().ok()?;
    let b = parts.next()?.parse::<u16>().ok()?;
    let c = parts.next()?.parse::<u16>().ok()?;
    Some((a, b, c))
}

pub(super) fn decode_mouse_sgr(cb: u16, col: u16, row: u16, is_release: bool) -> MouseEvent {
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

pub(super) fn decode_csi_modifiers(params_str: &str) -> KeyModifiers {
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

pub(super) fn decode_csi_event(params: &[u8], fin: u8) -> Option<Event> {
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

pub(super) fn decode_ss3_key(b: u8) -> Option<KeyCode> {
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
