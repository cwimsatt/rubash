//! Platform services: well-known directories and the human confirmation
//! prompt.
//!
//! The prompt is harvested from safeexec (`safeexec.sh`, `confirm_or_die`):
//!
//! - it reads the controlling terminal, never stdin, so `echo confirm |`
//!   cannot answer it;
//! - it refuses when this process is not in the terminal's foreground
//!   process group, so a background job cannot steal the answer;
//! - it asks for a one-time token (`confirm 3FA9C1`), so a rote or replayed
//!   "yes" does not run a destructive command;
//! - with no usable terminal it denies instead of half-prompting.
//!
//! Windows reads `CONIN$`/`CONOUT$`; the foreground check there is the
//! console's process list (not implemented yet: the prompt denies on
//! Windows until it is).

use std::path::PathBuf;

/// `$XDG_CONFIG_HOME/safebash` (`~/.config/safebash`); `%APPDATA%\safebash`.
pub fn config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("safebash"));
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home_dir().map(|h| h.join(".config")))
        .map(|d| d.join("safebash"))
}

/// `$XDG_STATE_HOME/safebash` (`~/.local/state/safebash`);
/// `%LOCALAPPDATA%\safebash`.
pub fn state_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("safebash"));
    }
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home_dir().map(|h| h.join(".local").join("state")))
        .map(|d| d.join("safebash"))
}

/// The user's home directory from the process environment at startup.
pub fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The outcome of asking a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    Approved,
    Declined,
    /// No usable terminal, or not in the foreground: nobody could be asked.
    Unavailable,
}

/// Ask on the controlling terminal for the one-time token.
pub fn confirm_on_terminal(summary: &str, command: &str) -> Confirmation {
    imp::confirm(summary, command)
}

fn challenge_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    hasher.write_u32(std::process::id());
    format!("{:06X}", hasher.finish() & 0xFF_FFFF)
}

#[cfg(unix)]
mod imp {
    use super::{challenge_token, Confirmation};
    use std::io::{BufRead, BufReader, Write};

    pub fn confirm(summary: &str, command: &str) -> Confirmation {
        let Ok(input) = std::fs::OpenOptions::new().read(true).open("/dev/tty") else {
            return Confirmation::Unavailable;
        };
        let Ok(mut output) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
            return Confirmation::Unavailable;
        };
        if !in_foreground(&input) {
            return Confirmation::Unavailable;
        }
        let token = challenge_token();
        let expected = format!("confirm {token}");
        let shown = crate::redact::redact(command);
        let prompt = format!(
            "\n\x1b[0;31m[safebash] {summary}\x1b[0m\n  {shown}\nType \"{expected}\" to run it (anything else cancels): "
        );
        if output.write_all(prompt.as_bytes()).is_err() || output.flush().is_err() {
            return Confirmation::Unavailable;
        }
        let mut reply = String::new();
        if BufReader::new(input).read_line(&mut reply).is_err() {
            return Confirmation::Unavailable;
        }
        let _ = output.write_all(b"\n");
        if reply.trim_end_matches(['\n', '\r']) == expected {
            Confirmation::Approved
        } else {
            Confirmation::Declined
        }
    }

    /// This process group owns the terminal (safeexec's
    /// `is_foreground_tty`: pgrp == tpgid).
    fn in_foreground(tty: &std::fs::File) -> bool {
        use std::os::fd::AsRawFd;
        // SAFETY: plain libc queries on a valid open descriptor.
        let (pgrp, tpgid) = unsafe { (libc::getpgrp(), libc::tcgetpgrp(tty.as_raw_fd())) };
        tpgid <= 0 || pgrp == tpgid
    }
}

#[cfg(windows)]
mod imp {
    use super::Confirmation;

    pub fn confirm(_summary: &str, _command: &str) -> Confirmation {
        // Windows phase: CONIN$/CONOUT$ prompt plus a
        // GetConsoleProcessList foreground check. Until then a confirmation
        // can never be obtained, so Confirm findings deny.
        Confirmation::Unavailable
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::Confirmation;

    pub fn confirm(_summary: &str, _command: &str) -> Confirmation {
        Confirmation::Unavailable
    }
}
