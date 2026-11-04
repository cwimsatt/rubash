//! Host execution gate — a process-wide policy hook (safebash addition).
//!
//! An embedding host (the `safebash` binary in `crates/safebash`) installs
//! one [`ExecGate`] before the first executor runs. The engine then
//! consults it at three boundaries, each one *after* the shell has done
//! its own work (expansion, alias resolution, redirection-target
//! expansion), so the gate judges what will really happen rather than the
//! text the user typed:
//!
//! 1. [`ExecGate::check_command`] — every simple command that reaches the
//!    executor's dispatch funnel, with its fully expanded argv, before it
//!    is dispatched to a function, a builtin, an emulated external or a
//!    child process.
//! 2. [`ExecGate::check_redirect`] — every file redirection, once its
//!    target word has been expanded.
//! 3. [`ExecGate::check_spawn`] — every child process the engine creates
//!    for a user command (pipeline stages, background jobs, coprocesses,
//!    `exec`). This is the completeness backstop: no external program can
//!    start without passing it, whichever executor path launched it.
//!
//! The engine never interprets a verdict beyond allow/deny: policy,
//! confirmation prompts and audit logging belong to the gate. A denied
//! command does not run and finishes with [`DENIED_STATUS`] (126, the
//! status bash uses for a command that was found but could not be
//! executed). Without an installed gate every helper here is a no-op, so
//! the plain `rubash` binary behaves exactly as before.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::OnceLock;

/// Exit status of a command the gate denied.
pub const DENIED_STATUS: i32 = 126;

/// How a redirection uses its target file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectAccess {
    /// `< file`
    Read,
    /// `> file`, `>| file`, `&> file`
    Write,
    /// `>> file`, `&>> file`
    Append,
    /// `<> file`
    ReadWrite,
}

/// A simple command at the dispatch funnel, after expansion.
#[derive(Debug)]
pub struct CommandCheck<'a> {
    /// The expanded words; `argv[0]` is the command name as typed or
    /// produced by expansion (not a resolved path).
    pub argv: &'a [String],
    /// Prefix assignments (`NAME=value cmd`) as the parser recorded them.
    pub assignments: &'a [(String, String)],
    /// The session's working directory.
    pub cwd: &'a Path,
    /// The session's variables (the engine's own table).
    pub env: &'a HashMap<String, String>,
}

/// A file redirection whose target has been expanded.
#[derive(Debug)]
pub struct RedirectCheck<'a> {
    pub fd: Option<u32>,
    pub access: RedirectAccess,
    pub target: &'a str,
    pub cwd: &'a Path,
}

/// A child process about to be created, read back from its [`Command`].
#[derive(Debug, Clone)]
pub struct SpawnCheck {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    /// Environment changes the engine made on the `Command`; `None`
    /// values are removals.
    pub env: Vec<(OsString, Option<OsString>)>,
}

impl SpawnCheck {
    /// Snapshot the program, arguments, working directory and environment
    /// changes of a prepared [`Command`].
    pub fn from_command(command: &Command) -> SpawnCheck {
        SpawnCheck {
            program: command.get_program().to_os_string(),
            args: command.get_args().map(|arg| arg.to_os_string()).collect(),
            cwd: command.get_current_dir().map(Path::to_path_buf),
            env: command
                .get_envs()
                .map(|(key, value)| (key.to_os_string(), value.map(|v| v.to_os_string())))
                .collect(),
        }
    }
}

/// The gate's answer at one boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    Allow,
    /// Do not run. `message` is a complete diagnostic line (without a
    /// trailing newline) that the engine reports on the shell's stderr.
    Deny {
        message: String,
    },
}

/// The policy hook. Implementations must be cheap for the common allow
/// path: `check_command` runs once per simple command.
pub trait ExecGate: Send + Sync {
    fn check_command(&self, check: &CommandCheck<'_>) -> GateVerdict;
    fn check_redirect(&self, check: &RedirectCheck<'_>) -> GateVerdict;
    fn check_spawn(&self, check: &SpawnCheck) -> GateVerdict;

    /// Whether the engine may keep running its in-process emulations of
    /// external utilities (`rm`, `cp`, `chmod`, `cat`, `sed`, ...). Those
    /// emulations never spawn a process, so the spawn backstop cannot see
    /// them; a gate that relies on the backstop returns `false` and the
    /// engine runs the real programs instead.
    fn allows_emulated_externals(&self) -> bool {
        false
    }
}

static GATE: OnceLock<Box<dyn ExecGate>> = OnceLock::new();

/// Install the process-wide gate. Returns `false` when a gate is already
/// installed: the first gate stays in force for the life of the process.
pub fn install(gate: Box<dyn ExecGate>) -> bool {
    GATE.set(gate).is_ok()
}

/// The installed gate, if any.
pub fn active() -> Option<&'static dyn ExecGate> {
    GATE.get().map(|gate| gate.as_ref())
}

/// Whether in-process emulations of external utilities may run.
pub fn emulated_externals_allowed() -> bool {
    active().map_or(true, |gate| gate.allows_emulated_externals())
}

/// The executable a *respawn* must launch — a background job, coproc, trap
/// action or process-substitution child that re-runs this shell on a piece
/// of script. The commands in that script only reach a gate inside the
/// child, so the child MUST be this same gated executable.
///
/// When a gate is installed this returns [`std::env::current_exe`] and
/// nothing else. The engine's own selection chain prefers
/// `CARGO_BIN_EXE_rubash` and a `deps/`-sibling `rubash`, and falls back to
/// a bare `rubash` on `PATH`; any of those can be an *ungated* engine an
/// attacker points the respawn at (for example by setting
/// `CARGO_BIN_EXE_rubash` in the command's environment), which would run
/// the respawned body with no safety checks at all. If we cannot even name
/// our own image, we return a path that cannot execute, so the respawn
/// fails closed instead of silently running ungated.
///
/// Without a gate (plain rubash, including its own test suite, where
/// `CARGO_BIN_EXE_rubash` legitimately selects the freshly built test
/// binary) this returns `unconstrained()` unchanged — the engine keeps its
/// existing behavior.
pub fn respawn_exe(unconstrained: impl FnOnce() -> PathBuf) -> PathBuf {
    if active().is_none() {
        return unconstrained();
    }
    std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("/nonexistent/safebash-respawn-fail-closed"))
}

/// Check a prepared child process against the gate.
pub fn check_command_spawn(command: &Command) -> std::io::Result<()> {
    let Some(gate) = active() else {
        return Ok(());
    };
    match gate.check_spawn(&SpawnCheck::from_command(command)) {
        GateVerdict::Allow => Ok(()),
        GateVerdict::Deny { message } => Err(denied_error(message)),
    }
}

/// [`Command::spawn`] behind the gate: a denied child is never created and
/// the caller sees a `PermissionDenied` error carrying the gate's message,
/// which the engine reports through its normal spawn-failure path (status
/// 126).
pub fn spawn(command: &mut Command) -> std::io::Result<Child> {
    check_command_spawn(command)?;
    command.spawn()
}

/// `CommandExt::exec` behind the gate: returns the gate's denial instead of
/// replacing the process image.
#[cfg(unix)]
pub fn exec(command: &mut Command) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    if let Err(error) = check_command_spawn(command) {
        return error;
    }
    command.exec()
}

fn denied_error(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

/// Map a parsed redirection kind to the file access it performs, or `None`
/// for kinds that never open a named file (duplications, closes, heredocs,
/// here-strings).
pub fn redirect_access(kind: &crate::parser::RedirectKind) -> Option<RedirectAccess> {
    use crate::parser::RedirectKind;
    match kind {
        RedirectKind::Input => Some(RedirectAccess::Read),
        RedirectKind::Output | RedirectKind::ClobberOutput | RedirectKind::CombinedOutput => {
            Some(RedirectAccess::Write)
        }
        RedirectKind::Append | RedirectKind::CombinedAppend => Some(RedirectAccess::Append),
        RedirectKind::ReadWrite => Some(RedirectAccess::ReadWrite),
        RedirectKind::DuplicateInput
        | RedirectKind::DuplicateOutput
        | RedirectKind::CloseInput
        | RedirectKind::CloseOutput
        | RedirectKind::HereString
        | RedirectKind::HereDoc
        | RedirectKind::Unknown => None,
    }
}
