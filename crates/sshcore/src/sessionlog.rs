//! Session logs: what a server printed, saved as plain text.
//!
//! Only output is logged, never the user's keystrokes (passwords typed at a
//! prompt aren't echoed, so they never reach the log). Escape sequences
//! (colors, cursor moves, window titles) are removed; carriage returns and
//! backspaces are applied the way a terminal would, so a progress bar ends up
//! as its final state instead of a hundred copies. Full-screen programs
//! (vim, htop) can't be turned into sensible text and come out rough.
//!
//! Files are never overwritten, and a log that reaches [`ROTATE_BYTES`]
//! continues in a new file. Clock and folder choices belong to the caller.

use crate::sftp::{safe_local_name, unique_local_path};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A log file this big continues in "<name> part 2.log", and so on.
pub const ROTATE_BYTES: u64 = 100 * 1024 * 1024;
/// A line longer than this (binary junk without newlines) is written out anyway.
const MAX_LINE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Esc,
    /// ESC [ … final byte.
    Csi,
    /// OSC / DCS / PM / APC / SOS: text up to BEL or ESC \.
    Str,
    /// ESC seen inside a string: `\` ends it.
    StrEsc,
    /// ESC ( B and friends: one more byte.
    Charset,
}

/// Turns a terminal byte stream into plain-text lines.
#[derive(Debug)]
pub struct PlainText {
    state: State,
    line: Vec<char>,
    col: usize,
    params: Vec<u8>,
    utf8: Vec<u8>,
}

impl Default for PlainText {
    fn default() -> Self {
        Self { state: State::Ground, line: Vec::new(), col: 0, params: Vec::new(), utf8: Vec::new() }
    }
}

impl PlainText {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends every line completed by `bytes` to `out` (each ending in `\n`).
    pub fn feed(&mut self, bytes: &[u8], out: &mut String) {
        for &b in bytes {
            match self.state {
                State::Ground => self.ground(b, out),
                State::Esc => {
                    self.state = match b {
                        b'[' => {
                            self.params.clear();
                            State::Csi
                        }
                        b']' | b'P' | b'X' | b'^' | b'_' => State::Str,
                        b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/' | b'#' | b'%' => State::Charset,
                        _ => State::Ground,
                    }
                }
                State::Csi => match b {
                    0x20..=0x3f => {
                        if self.params.len() < 64 {
                            self.params.push(b);
                        }
                    }
                    0x40..=0x7e => {
                        self.csi(b);
                        self.state = State::Ground;
                    }
                    0x1b => self.state = State::Esc,
                    _ => {}
                },
                State::Str => match b {
                    0x07 => self.state = State::Ground,
                    0x1b => self.state = State::StrEsc,
                    _ => {}
                },
                State::StrEsc => self.state = if b == b'\\' { State::Ground } else { State::Str },
                State::Charset => self.state = State::Ground,
            }
        }
    }

    /// Writes out a line that hasn't ended yet (before a note, or at the end).
    pub fn finish_line(&mut self, out: &mut String) {
        if !self.line.is_empty() {
            self.flush(out);
        }
        self.col = 0;
    }

    fn ground(&mut self, b: u8, out: &mut String) {
        match b {
            0x1b => {
                self.utf8.clear();
                self.state = State::Esc;
            }
            b'\n' => self.flush(out),
            b'\r' => self.col = 0,
            0x08 => self.col = self.col.saturating_sub(1),
            b'\t' => {
                let next = (self.col / 8 + 1) * 8;
                while self.col < next {
                    self.put(' ');
                }
            }
            0x00..=0x1f | 0x7f => {}
            _ => {
                self.utf8.push(b);
                match std::str::from_utf8(&self.utf8) {
                    Ok(s) => {
                        let c = s.chars().next().unwrap_or('\u{fffd}');
                        self.utf8.clear();
                        self.put(c);
                    }
                    // Wait for the rest of a multi-byte character.
                    Err(e) if e.error_len().is_none() && self.utf8.len() < 4 => {}
                    Err(_) => {
                        self.utf8.clear();
                        self.put('\u{fffd}');
                    }
                }
                if self.line.len() >= MAX_LINE {
                    self.flush(out);
                }
            }
        }
    }

    fn put(&mut self, c: char) {
        if self.col < self.line.len() {
            self.line[self.col] = c;
        } else {
            self.line.resize(self.col, ' ');
            self.line.push(c);
        }
        self.col += 1;
    }

    /// The few cursor / erase sequences that change what a line says.
    fn csi(&mut self, fin: u8) {
        let text = String::from_utf8_lossy(&self.params);
        if text.starts_with(['?', '>', '<', '=']) {
            return; // private modes (cursor visibility, bracketed paste…)
        }
        let n = |default: usize| text.split(';').next().and_then(|p| p.parse::<usize>().ok()).filter(|&v| v > 0).unwrap_or(default);
        match fin {
            b'K' => match text.as_ref() {
                "" | "0" => self.line.truncate(self.col),
                "1" => {
                    for c in self.line.iter_mut().take(self.col + 1) {
                        *c = ' ';
                    }
                }
                "2" => self.line.clear(),
                _ => {}
            },
            b'C' => self.col += n(1),
            b'D' => self.col = self.col.saturating_sub(n(1)),
            b'G' => self.col = n(1) - 1,
            _ => {}
        }
    }

    fn flush(&mut self, out: &mut String) {
        let line: String = self.line.iter().collect();
        out.push_str(line.trim_end());
        out.push('\n');
        self.line.clear();
        self.col = 0;
    }
}

/// One session's log on disk (plain text, appended as output arrives).
#[derive(Debug)]
pub struct SessionLog {
    dir: PathBuf,
    stem: String,
    path: PathBuf,
    file: File,
    written: u64,
    part: u32,
    text: PlainText,
}

impl SessionLog {
    /// Starts `<base>/<host folder>/<stem>.log` (folders created as needed;
    /// an existing file is never touched: " (1)" is added instead) and writes
    /// `header` as its first line.
    pub fn create(base: &Path, host_name: &str, stem: &str, header: &str) -> io::Result<Self> {
        let dir = base.join(safe_local_name(host_name));
        std::fs::create_dir_all(&dir)?;
        let stem = safe_local_name(stem);
        let (path, file) = new_file(&dir, &format!("{stem}.log"))?;
        let mut log = Self { dir, stem, path, file, written: 0, part: 1, text: PlainText::new() };
        log.raw(&format!("{header}\n\n"))?;
        Ok(log)
    }

    /// The file being written now.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The folder holding this host's logs.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Adds server output.
    pub fn output(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut out = String::new();
        self.text.feed(bytes, &mut out);
        self.raw(&out)
    }

    /// Adds a line of Shellwick's own ("Reconnected …"), set apart from the output.
    pub fn note(&mut self, text: &str) -> io::Result<()> {
        let mut out = String::new();
        self.text.finish_line(&mut out);
        out.push_str(&format!("\n--- {text} ---\n\n"));
        self.raw(&out)
    }

    fn raw(&mut self, s: &str) -> io::Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        self.file.write_all(s.as_bytes())?;
        self.written += s.len() as u64;
        if self.written >= ROTATE_BYTES {
            self.rotate()?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.part += 1;
        let (path, mut file) = new_file(&self.dir, &format!("{} part {}.log", self.stem, self.part))?;
        let prev = self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let header = format!("(continued from {prev})\n\n");
        file.write_all(header.as_bytes())?;
        self.path = path;
        self.file = file;
        self.written = header.len() as u64;
        Ok(())
    }
}

/// Creates a new file named `name` in `dir`, or "name (1)…" if it's taken.
fn new_file(dir: &Path, name: &str) -> io::Result<(PathBuf, File)> {
    for _ in 0..3 {
        let path = unique_local_path(dir, name, |p| p.exists());
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => return Ok((path, f)),
            // Someone took the name in between: pick again.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "couldn't find a free log file name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(chunks: &[&[u8]]) -> String {
        let mut p = PlainText::new();
        let mut out = String::new();
        for c in chunks {
            p.feed(c, &mut out);
        }
        p.finish_line(&mut out);
        out
    }

    #[test]
    fn colors_titles_and_modes_are_removed() {
        let s = plain(&[b"\x1b]0;deploy@api-1: ~\x07\x1b[?2004h\x1b[32mdeploy@api-1\x1b[0m:\x1b[34m~\x1b[0m$ ls\r\n\x1b[01;34mapp\x1b[0m  logs\r\n"]);
        assert_eq!(s, "deploy@api-1:~$ ls\napp  logs\n");
    }

    #[test]
    fn carriage_returns_keep_the_final_progress() {
        let s = plain(&[b"Downloading  10%\rDownloading  55%\rDownloading 100%\r\ndone\r\n"]);
        assert_eq!(s, "Downloading 100%\ndone\n");
    }

    #[test]
    fn erase_and_backspace_edit_the_line() {
        // readline redraw: type "lss", backspace, then erase to end of line.
        assert_eq!(plain(&[b"$ lss\x08 \x08\r\n"]), "$ ls\n");
        assert_eq!(plain(&[b"old text\r\x1b[Knew\r\n"]), "new\n");
        assert_eq!(plain(&[b"abc\x1b[2K\rxyz\n"]), "xyz\n");
        assert_eq!(plain(&[b"a\tb\n"]), "a       b\n");
    }

    #[test]
    fn sequences_and_characters_split_across_chunks() {
        let s = plain(&[b"caf\xc3", b"\xa9 \x1b[3", b"1mred\x1b", b"[0m\r", b"\n"]);
        assert_eq!(s, "café red\n");
        assert_eq!(plain(&[b"\xff ok\n"]), "\u{fffd} ok\n");
    }

    #[test]
    fn st_terminated_strings_and_charsets() {
        assert_eq!(plain(&[b"\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\ \x1b(Bend\n"]), "link end\n");
    }

    fn scratch(name: &str) -> PathBuf {
        let base = std::env::current_exe().unwrap().parent().unwrap().join("test-scratch");
        let dir = base.join(format!("sessionlog-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn writes_plain_text_with_notes_and_never_overwrites() {
        let base = scratch("write");
        let mut log = SessionLog::create(&base, "api/1:prod", "2026-11-08 14-30-05", "Shellwick session log: api/1:prod").unwrap();
        log.output(b"\x1b[32m$\x1b[0m uptime\r\n 14:30 up 6 days\r\n$ partial").unwrap();
        log.note("Reconnected 2026-11-08 14:31:00").unwrap();
        log.output(b"$ exit\r\n").unwrap();
        let first = log.path().to_path_buf();
        assert_eq!(first, base.join("api_1_prod").join("2026-11-08 14-30-05.log"), "host name made safe for a folder");
        drop(log);
        assert_eq!(
            std::fs::read_to_string(&first).unwrap(),
            "Shellwick session log: api/1:prod\n\n$ uptime\n 14:30 up 6 days\n$ partial\n\n--- Reconnected 2026-11-08 14:31:00 ---\n\n$ exit\n"
        );
        // Same second again: a new file, the first one untouched.
        let again = SessionLog::create(&base, "api/1:prod", "2026-11-08 14-30-05", "h").unwrap();
        assert_eq!(again.path().file_name().unwrap(), "2026-11-08 14-30-05 (1).log");
        assert!(std::fs::read_to_string(&first).unwrap().starts_with("Shellwick session log"));
    }

    #[test]
    fn a_full_log_continues_in_a_new_part() {
        let base = scratch("rotate");
        let mut log = SessionLog::create(&base, "big", "s", "h").unwrap();
        log.written = ROTATE_BYTES - 5;
        log.output(b"0123456789\n").unwrap();
        assert_eq!(log.path().file_name().unwrap(), "s part 2.log");
        log.output(b"more\n").unwrap();
        assert_eq!(std::fs::read_to_string(log.path()).unwrap(), "(continued from s.log)\n\nmore\n");
    }
}
