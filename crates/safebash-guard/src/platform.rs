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
//! Windows reads `CONIN$`/`CONOUT$`; it has no foreground-process-group
//! test, so it checks only that an interactive console session is attached
//! (`GetConsoleProcessList`/`GetConsoleWindow`) — a weaker guarantee than
//! the Unix foreground check, and stated as such: opening `CONIN$` means a
//! redirected/pipe stdin cannot answer, and with no usable console the
//! prompt denies, but a background process sharing the console could still
//! answer.

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
    use super::{challenge_token, Confirmation};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleProcessList, GetConsoleWindow, ReadConsoleW, WriteConsoleW,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };

    /// Owns a console handle and closes it on drop, so every return path —
    /// including the second open failing — releases the first.
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: a valid handle from CreateFileW, closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Open a console pseudo-file (`CONIN$`/`CONOUT$`). Opening the console
    /// directly, not stdin/stdout, is the Windows analogue of `/dev/tty`: a
    /// redirected or piped standard stream cannot supply the answer.
    fn open(name: &str) -> Option<Handle> {
        let wide: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated; null security attributes/template.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            None
        } else {
            Some(Handle(h))
        }
    }

    /// The console mode, if `h` is a usable console handle. Queried only —
    /// never set — so a failure mid-prompt cannot strand the console.
    fn console_mode(h: HANDLE) -> Option<u32> {
        let mut mode = 0u32;
        // SAFETY: valid handle; writes a single u32.
        if unsafe { GetConsoleMode(h, &mut mode) } != 0 {
            Some(mode)
        } else {
            None
        }
    }

    /// A real interactive console session is attached to this process.
    /// Weaker than Unix foreground detection: it proves a console session
    /// exists, not that no other pane could answer.
    fn console_attached() -> bool {
        // SAFETY: neither call takes input parameters that can be invalid.
        if unsafe { GetConsoleWindow() }.is_null() {
            return false;
        }
        let mut list = [0u32; 1];
        unsafe { GetConsoleProcessList(list.as_mut_ptr(), 1) >= 1 }
    }

    fn write_all(h: HANDLE, text: &str) -> bool {
        let wide: Vec<u16> = text.encode_utf16().collect();
        let mut done = 0usize;
        while done < wide.len() {
            let mut written = 0u32;
            // SAFETY: valid handle; the pointer/length describe the unwritten
            // tail. A WriteConsoleW failure or zero progress means the prompt
            // did not fully reach the console, so the caller must deny rather
            // than treat a partial write as a complete prompt.
            let ok = unsafe {
                WriteConsoleW(
                    h,
                    wide[done..].as_ptr(),
                    (wide.len() - done) as u32,
                    &mut written,
                    std::ptr::null(),
                )
            };
            if ok == 0 || written == 0 {
                return false;
            }
            done += written as usize;
        }
        true
    }

    pub fn confirm(summary: &str, command: &str) -> Confirmation {
        let Some(input) = open("CONIN$") else {
            return Confirmation::Unavailable;
        };
        let Some(output) = open("CONOUT$") else {
            return Confirmation::Unavailable;
        };
        // The input handle must be a usable console input, and a real
        // interactive console session must be attached; otherwise nobody can
        // be asked and a Confirm becomes a denial, exactly as Unix with no
        // tty.
        if console_mode(input.0).is_none() || !console_attached() {
            return Confirmation::Unavailable;
        }
        let token = challenge_token();
        let expected = format!("confirm {token}");
        let shown = crate::redact::redact(command);
        // Red only when the output console already interprets VT sequences;
        // never enable it ourselves (that would mutate the user's console).
        let vt =
            console_mode(output.0).is_some_and(|m| m & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0);
        let prompt = if vt {
            format!(
                "\n\x1b[0;31m[safebash] {summary}\x1b[0m\n  {shown}\nType \"{expected}\" to run it (anything else cancels): "
            )
        } else {
            format!(
                "\n[safebash] {summary}\n  {shown}\nType \"{expected}\" to run it (anything else cancels): "
            )
        };
        if !write_all(output.0, &prompt) {
            return Confirmation::Unavailable;
        }
        // One complete line. A single ReadConsoleW may return a short read
        // (or a full buffer that is not a whole line), and in character mode
        // Enter arrives as `\r`; accumulate until a terminator or a cap, and
        // treat a cap with no terminator as no answer (deny).
        let mut reply = String::new();
        let mut buf = [0u16; 256];
        let mut got_line = false;
        for _ in 0..16 {
            let mut read = 0u32;
            // SAFETY: valid handle; buffer pointer/length consistent; a null
            // input-control pointer is allowed.
            let ok = unsafe {
                ReadConsoleW(
                    input.0,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null(),
                )
            };
            if ok == 0 {
                return Confirmation::Unavailable;
            }
            if read == 0 {
                break; // end of input with no terminator
            }
            let chunk = String::from_utf16_lossy(&buf[..read as usize]);
            if let Some(end) = chunk.find(['\r', '\n']) {
                reply.push_str(&chunk[..end]);
                got_line = true;
                break;
            }
            reply.push_str(&chunk);
            if reply.len() > 4096 {
                break;
            }
        }
        let _ = write_all(output.0, "\n");
        if !got_line {
            return Confirmation::Unavailable;
        }
        if reply.trim_end_matches(['\r', '\n']) == expected {
            Confirmation::Approved
        } else {
            Confirmation::Declined
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::Confirmation;

    pub fn confirm(_summary: &str, _command: &str) -> Confirmation {
        Confirmation::Unavailable
    }
}
