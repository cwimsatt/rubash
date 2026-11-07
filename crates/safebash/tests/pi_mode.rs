//! The pi non-interactive mode: a `Confirm` verdict denies without prompting,
//! selected by the executable itself (its `safebash-pi` name, or the
//! `SAFEBASH_NONINTERACTIVE` environment variable), never by a flag.
//!
//! Tiers (see `C:\CQR\logs\safebash\SAFEBASH-PI\TEST_PLAN.md`):
//!
//!   * the pure selector truth table is a `--lib` unit test in `lib.rs`;
//!   * here, Tier 2 / Tier 2b-marker: the wiring from the selection to
//!     `Guard::interactive_confirm` and the exported marker;
//!   * here, Tier 3 / Tier 2b-inheritance: the end-to-end proof against a
//!     disposable scratch target, including a child inheriting the mode.
//!
//! Need (e): direct coverage of the behaviour this change introduces. Each
//! trap (a case that must be denied) is paired with a control (a healthy case
//! that must pass).

mod common;

use common::Tree;
use safebash::apply_non_interactive;
use safebash_guard::policy::Level;
use safebash_guard::Guard;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MARKER: &str = "SAFEBASH_NONINTERACTIVE";

// `apply_non_interactive` reads and writes this process's `SAFEBASH_NONINTERACTIVE`,
// which is global; serialise the tests that touch it so they do not race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Tier 2: the selection flips `interactive_confirm`.
// Tier 2b (marker): and it exports the marker for children.
// ---------------------------------------------------------------------------

/// Save `SAFEBASH_NONINTERACTIVE` and restore it (or its absence) on drop, so
/// the env-mutating wiring tests leave the process environment as they found it.
struct EnvVar {
    prev: Option<OsString>,
}

impl EnvVar {
    fn capture() -> EnvVar {
        EnvVar {
            prev: std::env::var_os(MARKER),
        }
    }
    fn set(value: &str) {
        std::env::set_var(MARKER, value);
    }
    fn unset() {
        std::env::remove_var(MARKER);
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        match &self.prev {
            Some(value) => std::env::set_var(MARKER, value),
            None => std::env::remove_var(MARKER),
        }
    }
}

/// A guard in the real binary's startup state: `interactive_confirm == true`.
/// The shared fixture turns it off (analysis tests never prompt); the pi
/// selection is what must turn it off, so reset it to the startup default to
/// make the flip observable.
fn startup_guard(tree: &Tree) -> Guard {
    let mut guard = tree.guard(&tree.workspace, Level::Standard);
    guard.interactive_confirm = true;
    guard
}

#[test]
fn name_selection_disables_confirmation_and_exports_marker() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _env = EnvVar::capture();
    EnvVar::unset(); // the NAME alone must select, with the env unset
    let tree = Tree::new("pi-name-sel");
    let mut guard = startup_guard(&tree);

    let engaged = apply_non_interactive(&mut guard, Some(OsStr::new("safebash-pi")));

    assert!(
        engaged,
        "the safebash-pi name must engage non-interactive mode"
    );
    assert!(
        !guard.interactive_confirm,
        "name selection must turn confirmation off"
    );
    assert_eq!(
        std::env::var_os(MARKER).as_deref(),
        Some(OsStr::new("1")),
        "the marker must be exported so children inherit the mode"
    );
}

#[test]
fn env_selection_disables_confirmation() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _env = EnvVar::capture();
    EnvVar::set("1"); // the ENV alone, with an ordinary name
    let tree = Tree::new("pi-env-sel");
    let mut guard = startup_guard(&tree);

    let engaged = apply_non_interactive(&mut guard, Some(OsStr::new("safebash")));

    assert!(engaged, "SAFEBASH_NONINTERACTIVE=1 must engage the mode");
    assert!(!guard.interactive_confirm);
}

#[test]
fn ordinary_invocation_keeps_confirmation_on() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _env = EnvVar::capture();
    EnvVar::unset();
    let tree = Tree::new("pi-plain");
    let mut guard = startup_guard(&tree);

    let engaged = apply_non_interactive(&mut guard, Some(OsStr::new("safebash")));

    assert!(!engaged, "ordinary safebash must not engage the mode");
    assert!(
        guard.interactive_confirm,
        "ordinary safebash must keep confirmation on \
         (removing the flip in apply_non_interactive must fail the selection tests)"
    );
    assert_eq!(
        std::env::var_os(MARKER),
        None,
        "an unselected invocation must not force the marker"
    );
}

// ---------------------------------------------------------------------------
// Tier 3: end to end against a disposable scratch target.
// Tier 2b (inheritance): a child inherits the exported marker.
// ---------------------------------------------------------------------------

fn safebash_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_safebash"))
}

/// The exact stderr signature of a confirmable command denied with no usable
/// terminal (`denial_message(.., confirm = true)`), printed by the engine at
/// `src/executor/exec_gate_checks.rs`. It distinguishes a *guard denial* from a
/// "command not found" (which matters on Windows, where `rm` does not exist):
/// a regression that let the command through would never print this.
const DENIED_CONFIRMABLE: &str = "safebash: CONFIRMATION REQUIRED";

struct Captured {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

/// Run `child`, draining its output on threads (so a full pipe cannot deadlock),
/// and kill it if it outlives `timeout` — so a regression that reintroduces a
/// blocking prompt fails rather than hangs.
fn wait_capture(mut child: Child, timeout: Duration) -> Captured {
    let mut out = child.stdout.take().expect("piped stdout");
    let mut err = child.stderr.take().expect("piped stderr");
    let out_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = out.read_to_string(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = err.read_to_string(&mut buf);
        buf
    });
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            timed_out = true;
            break child.wait().expect("wait after kill");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Captured {
        code: status.code(),
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
        timed_out,
    }
}

/// A disposable scratch tree under the test target's temp dir (never the system
/// temp dir, which the guard trusts: a delete there would be *allowed*, so the
/// trap would not fire). Removed on drop.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("pi-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("make scratch root");
        Scratch { root }
    }

    /// A work subdirectory holding a sentinel file. The work dir is the
    /// command's cwd, so it is also the workspace anchor; a leaked `rm -rf .`
    /// would destroy the sentinel.
    fn work_with_sentinel(&self) -> (PathBuf, PathBuf) {
        let work = self.root.join("work");
        std::fs::create_dir_all(&work).expect("make work dir");
        let sentinel = work.join("sentinel.txt");
        std::fs::write(&sentinel, b"keep me").expect("write sentinel");
        (work, sentinel)
    }

    fn home(&self) -> PathBuf {
        let home = self.root.join("home");
        std::fs::create_dir_all(&home).expect("make home");
        home
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A safebash command with a predictable, isolated guard: anchored to `cwd`,
/// default level, inherited anchors cleared, output piped, stdin null (so a
/// stray prompt reads EOF instead of blocking). TMPDIR is pinned to `/tmp`
/// (ignored on Windows) so the scratch dir under the build tree is NOT a temp
/// root and an in-cwd delete stays confirmable.
fn safebash_command(program: &Path, cwd: &Path, home: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("TMPDIR", "/tmp")
        .env_remove("SAFEBASH_WORKSPACE")
        .env_remove("SAFEBASH_FLOOR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Single-quote a path as one bash token (backslashes are literal inside single
/// quotes, so a Windows path survives intact).
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display())
}

/// Trap, env-selected: `SAFEBASH_NONINTERACTIVE=1` makes a confirmable delete a
/// denial, the scratch target survives, and the process does not hang.
#[test]
fn pi_mode_denies_confirmable_env_selected() {
    let scratch = Scratch::new("trap-env");
    let (work, sentinel) = scratch.work_with_sentinel();
    let home = scratch.home();

    let mut command = safebash_command(&safebash_bin(), &work, &home);
    command.arg("-c").arg("rm -rf .").env(MARKER, "1");
    let captured = wait_capture(
        command.spawn().expect("spawn safebash"),
        Duration::from_secs(60),
    );

    assert!(
        !captured.timed_out,
        "pi-mode must not hang on a confirmable command"
    );
    assert!(
        captured.stderr.contains(DENIED_CONFIRMABLE),
        "the guard must deny the confirmable command (code {:?})\nstdout: {}\nstderr: {}",
        captured.code,
        captured.stdout,
        captured.stderr
    );
    assert!(
        captured.code != Some(0),
        "a denied command must exit non-zero (code {:?})",
        captured.code
    );
    assert!(
        sentinel.exists(),
        "the scratch target must survive the denial"
    );
}

/// Trap, name-selected: a copy named `safebash-pi` denies the same confirmable
/// with no `SAFEBASH_NONINTERACTIVE` in its environment.
#[test]
fn pi_mode_denies_confirmable_name_selected() {
    let scratch = Scratch::new("trap-name");
    let (work, sentinel) = scratch.work_with_sentinel();
    let home = scratch.home();

    let pi_bin = scratch.root.join(if cfg!(windows) {
        "safebash-pi.exe"
    } else {
        "safebash-pi"
    });
    std::fs::copy(safebash_bin(), &pi_bin).expect("copy binary to safebash-pi");

    let mut command = safebash_command(&pi_bin, &work, &home);
    command.arg("-c").arg("rm -rf .").env_remove(MARKER); // selection by NAME only
    let captured = wait_capture(
        command.spawn().expect("spawn safebash-pi"),
        Duration::from_secs(60),
    );

    assert!(!captured.timed_out, "name-selected pi-mode must not hang");
    assert!(
        captured.stderr.contains(DENIED_CONFIRMABLE),
        "name-selected pi-mode must deny the confirmable command (code {:?})\nstdout: {}\nstderr: {}",
        captured.code,
        captured.stdout,
        captured.stderr
    );
    assert!(
        captured.code != Some(0),
        "a denied command must exit non-zero"
    );
    assert!(
        sentinel.exists(),
        "the scratch target must survive the denial"
    );
}

/// Control: a benign command runs and exits 0 under pi-mode, so the mode is not
/// simply denying everything.
#[test]
fn pi_mode_runs_benign_command() {
    let scratch = Scratch::new("control");
    let (work, _sentinel) = scratch.work_with_sentinel();
    let home = scratch.home();

    let mut command = safebash_command(&safebash_bin(), &work, &home);
    command.arg("-c").arg("echo safebash-ok").env(MARKER, "1");
    let captured = wait_capture(
        command.spawn().expect("spawn safebash"),
        Duration::from_secs(60),
    );

    assert!(!captured.timed_out);
    assert_eq!(
        captured.code,
        Some(0),
        "a benign command must run and succeed\nstdout: {}\nstderr: {}",
        captured.stdout,
        captured.stderr
    );
    assert!(
        captured.stdout.contains("safebash-ok"),
        "the benign command's output must appear (stdout: {:?})",
        captured.stdout
    );
}

/// Tier 2b (inheritance), end to end: a NAME-selected parent exports the marker
/// into its environment, so a plain nested `safebash` it launches inherits the
/// mode. The parent is selected by name only (its env has no marker), so the
/// child sees the marker ONLY because `apply_non_interactive` exported it —
/// removing that export makes `$SAFEBASH_NONINTERACTIVE` expand to empty and
/// fails this test.
#[test]
fn pi_mode_marker_inherited_by_child() {
    let scratch = Scratch::new("inherit");
    let (work, _sentinel) = scratch.work_with_sentinel();
    let home = scratch.home();

    let pi_bin = scratch.root.join(if cfg!(windows) {
        "safebash-pi.exe"
    } else {
        "safebash-pi"
    });
    std::fs::copy(safebash_bin(), &pi_bin).expect("copy binary to safebash-pi");

    // The parent (safebash-pi) runs a plain nested safebash that echoes the
    // marker it sees. The inner command is single-quoted, so the PARENT does
    // not expand it; the nested shell expands it from its inherited environment.
    let nested = format!(
        "{} -c 'echo NESTED=${MARKER}'",
        shell_quote(&safebash_bin())
    );
    let mut command = safebash_command(&pi_bin, &work, &home);
    command.arg("-c").arg(&nested).env_remove(MARKER); // parent selected by name only
    let captured = wait_capture(
        command.spawn().expect("spawn safebash-pi"),
        Duration::from_secs(60),
    );

    assert!(!captured.timed_out, "the nested invocation must not hang");
    assert!(
        captured.stdout.contains("NESTED=1"),
        "a child must inherit SAFEBASH_NONINTERACTIVE=1 from a name-selected parent\n\
         stdout: {}\nstderr: {}",
        captured.stdout,
        captured.stderr
    );
}

/// The marker observation emitted from inside the backgrounded compound body.
/// The respawned child expands `$SAFEBASH_NONINTERACTIVE` from ITS OWN inherited
/// environment, so this line reports whether the mode crossed the respawn
/// boundary — the proof that does not depend on the deferred terminal
/// distinction (an ordinary no-terminal child denies a confirmable too, so
/// victim survival alone cannot tell pi-mode from the fail-closed default).
const RESPAWN_MARKER_SEEN: &str = "RESPAWN_MARKER=1";

/// Build a backgrounded COMPOUND body: a brace group run with `&`. A brace group
/// is not a bare external, so the engine cannot take the direct-external
/// background path (`background_direct_external_command` returns `None` on
/// `brace_group`, `src/executor/compound_exec.rs`) and MUST respawn the gated
/// shell on the serialized body (`respawn_exe`, forced to the current gated
/// executable). The body, in order: reports the marker it inherited, then reads
/// its delete target at run time and attempts `rm -rf` on it. Because the target
/// is read inside the respawned child, the parent's static analysis of the body
/// sees only `rm -rf "$t"` (a dynamic target) and cannot judge the concrete
/// path; only the respawned child, expanding `$t`, reaches a verdict — so a
/// delete that is denied here was denied BY THE RESPAWNED CHILD, not pre-empted
/// in the parent.
fn respawn_body(target_file: &Path) -> String {
    format!(
        "{{ printf 'RESPAWN_MARKER=%s\\n' \"${MARKER}\"; \
         t=\"$(cat {tgt})\"; rm -rf \"$t\"; }} & wait; true",
        tgt = shell_quote(target_file),
    )
}

/// Tier 2b (inheritance), background respawn: a backgrounded COMPOUND delete
/// respawns the gated shell on the job body — a DISTINCT spawn path from both a
/// foreground command and a nested `safebash -c`. Selection is by ENV (the
/// respawned child keeps the ordinary `safebash` name, so its pi-mode can only
/// come from the inherited `SAFEBASH_NONINTERACTIVE`, never from its name). Two
/// independent facts are asserted, so the test cannot pass with inheritance
/// broken:
///   * the child reports `RESPAWN_MARKER=1` — the mode crossed the respawn
///     boundary (a respawn that stripped the marker would print an empty value,
///     even though the victim would still survive via the no-terminal default);
///   * the child prints the CONFIRMATION-REQUIRED diagnostic — it reached the
///     guard and denied the confirmable delete (not a "command not found", which
///     matters on Windows where `rm` is engine-provided), and the victim
///     survives.
#[test]
fn pi_mode_backgrounded_delete_denied_by_respawn() {
    let scratch = Scratch::new("bg-trap");
    let home = scratch.home();
    let work = scratch.root.join("work"); // the workspace anchor (cwd)
    std::fs::create_dir_all(&work).expect("make work dir");
    let victim = scratch.root.join("victim"); // OUTSIDE the workspace
    std::fs::create_dir_all(victim.join("data")).expect("make victim dir");
    let target_file = scratch.root.join("target.txt"); // read at run time, in the child
    std::fs::write(&target_file, format!("{}\n", victim.display())).expect("write target file");

    let mut command = safebash_command(&safebash_bin(), &work, &home);
    command
        .arg("-c")
        .arg(respawn_body(&target_file))
        .env(MARKER, "1");
    let captured = wait_capture(
        command.spawn().expect("spawn safebash"),
        Duration::from_secs(60),
    );

    assert!(!captured.timed_out, "the backgrounded job must not hang");
    assert!(
        captured.stdout.contains(RESPAWN_MARKER_SEEN),
        "the respawned child must inherit SAFEBASH_NONINTERACTIVE=1 across the respawn boundary\n\
         stdout: {}\nstderr: {}",
        captured.stdout,
        captured.stderr
    );
    assert!(
        captured.stderr.contains(DENIED_CONFIRMABLE),
        "the respawned child must reach the guard and deny the confirmable delete (code {:?})\n\
         stdout: {}\nstderr: {}",
        captured.code,
        captured.stdout,
        captured.stderr
    );
    assert!(
        victim.join("data").is_dir(),
        "the scratch target outside the workspace must survive the denial\n\
         stdout: {}\nstderr: {}",
        captured.stdout,
        captured.stderr
    );
}

/// Control: the SAME backgrounded compound shape, reading its target the same
/// way, but the target is INSIDE the workspace — so the respawned child allows
/// and really runs the delete. This proves the trap above detects a genuine
/// denial, not a background job that never executed or whose target-read failed,
/// and that the respawned child is not simply denying everything. It too asserts
/// the inherited marker, so the allowed run is confirmed to be under pi-mode.
#[test]
fn pi_mode_backgrounded_allowed_delete_runs() {
    let scratch = Scratch::new("bg-control");
    let home = scratch.home();
    let work = scratch.root.join("work"); // the workspace anchor (cwd)
    std::fs::create_dir_all(&work).expect("make work dir");
    let build = work.join("build"); // INSIDE the workspace
    std::fs::create_dir_all(build.join("data")).expect("make build dir");
    let target_file = scratch.root.join("target.txt"); // same run-time read as the trap
    std::fs::write(&target_file, format!("{}\n", build.display())).expect("write target file");

    let mut command = safebash_command(&safebash_bin(), &work, &home);
    command
        .arg("-c")
        .arg(respawn_body(&target_file))
        .env(MARKER, "1");
    let captured = wait_capture(
        command.spawn().expect("spawn safebash"),
        Duration::from_secs(60),
    );

    assert!(!captured.timed_out, "the backgrounded job must not hang");
    assert!(
        captured.stdout.contains(RESPAWN_MARKER_SEEN),
        "the respawned child must inherit pi-mode for the allowed run too\n\
         stdout: {}\nstderr: {}",
        captured.stdout,
        captured.stderr
    );
    assert!(
        !build.exists(),
        "an in-workspace backgrounded delete must run in the respawned child under pi-mode\n\
         stdout: {}\nstderr: {}",
        captured.stdout,
        captured.stderr
    );
}
