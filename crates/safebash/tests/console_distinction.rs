//! The interactive-terminal distinction: under a REAL controlling terminal,
//! ordinary `safebash` prompts for a confirmable command (and runs it when the
//! one-time token is typed back), while `safebash` with
//! `SAFEBASH_NONINTERACTIVE=1` denies the SAME command WITHOUT prompting.
//!
//! This is the one distinction the no-terminal SAFEBASH-PI tests cannot make:
//! with no terminal, pi mode and an ordinary `safebash` both deny a confirmable
//! (`Confirmation::Unavailable`), so their outcomes are identical. A terminal
//! has to be present and answerable for the difference to show, which needs a
//! pseudo-terminal host: a POSIX pty on Unix, a ConPTY on Windows. The work is
//! done by `tests/support/confirm_pty_probe.py` (reusing the engine's live-
//! console driver pattern); this is the thin launcher, pointed at the safebash
//! binary. It skips cleanly where the platform pseudo-terminal module is absent.
//!
//! Need (e): direct coverage of the behaviour pi mode introduces - ignoring an
//! available terminal. The `pi-no-prompt-deny` trap is paired with the
//! `interactive-approve` and `interactive-decline` controls, which also prove
//! the terminal is genuinely interactive (so the trap cannot pass because the
//! terminal was broken).

use std::process::{Command, Stdio};

const DRIVER: &str = "tests/support/confirm_pty_probe.py";

/// A python interpreter whose platform pseudo-terminal module is importable:
/// `winpty` (pywinpty) on Windows, the standard-library `pty` on Unix.
fn python_interpreter() -> Option<String> {
    let probe = if cfg!(windows) {
        "import winpty"
    } else {
        "import pty"
    };
    for candidate in ["python3", "python", "py"] {
        let ok = Command::new(candidate)
            .arg("-c")
            .arg(probe)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if ok {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Continuous integration sets `SAFEBASH_REQUIRE_PTY=1` so the distinction legs
/// MUST run there: a silently skipped leg proves nothing (DESIGN section 5), so
/// under this flag a missing interpreter or an unavailable pseudo-terminal module
/// is a hard failure, not a skip. Unset locally, the test skips gracefully.
fn require_pty() -> bool {
    std::env::var_os("SAFEBASH_REQUIRE_PTY").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Run the named legs through the driver and require every one to report PASS.
/// The driver prints `leg=PASS` / `leg=FAIL detail` lines and exits 2 (with a
/// `SKIP` line) when the platform pseudo-terminal module is unavailable.
fn run_legs(legs: &[&str]) {
    let Some(python) = python_interpreter() else {
        assert!(
            !require_pty(),
            "SAFEBASH_REQUIRE_PTY is set but no python with the platform \
             pseudo-terminal module (pywinpty on Windows, stdlib pty on Unix) \
             was found; the configured CI job must run the distinction legs"
        );
        eprintln!(
            "skip: no python with the platform pseudo-terminal module \
             (pywinpty on Windows, the stdlib pty module on Unix); \
             the live-console distinction needs a real terminal host"
        );
        return;
    };
    let mut cmd = Command::new(&python);
    cmd.arg(env!("CARGO_MANIFEST_DIR").to_string() + "/" + DRIVER)
        .arg(env!("CARGO_BIN_EXE_safebash"))
        .args(legs)
        .env("SB_SCRATCH_BASE", env!("CARGO_TARGET_TMPDIR"))
        // The driver's leg checks are Python assertions; PYTHONOPTIMIZE would
        // strip them and pass vacuously. Remove it (the driver also refuses to
        // run optimized, so this is belt-and-suspenders).
        .env_remove("PYTHONOPTIMIZE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd
        .output()
        .expect("failed to spawn the confirm pseudo-terminal driver (is python on PATH?)");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    eprintln!("driver output:\n{stdout}");
    if !stderr.trim().is_empty() {
        eprintln!("driver stderr:\n{stderr}");
    }
    if stdout.trim_start().starts_with("SKIP") {
        assert!(
            !require_pty(),
            "SAFEBASH_REQUIRE_PTY is set but the driver reported SKIP \
             (the pseudo-terminal module is unavailable in the resolved interpreter)"
        );
        eprintln!("skip: confirm driver reports the pseudo-terminal module is unavailable");
        return;
    }
    assert!(
        output.status.success(),
        "console-distinction legs failed (see driver output above)"
    );
    for leg in legs {
        assert!(
            stdout.contains(&format!("{leg}=PASS")),
            "leg {leg} did not report PASS (driver output above)"
        );
    }
}

/// Control: under a real terminal, ordinary safebash prompts for the confirmable
/// delete and, given the one-time token, runs it (the victim is deleted). Proves
/// the terminal is answerable; fails (not skips) if no prompt appears.
#[test]
fn console_distinction_interactive_approve() {
    run_legs(&["interactive-approve"]);
}

/// Control: the same prompt, a wrong answer, so the command is declined and the
/// victim survives - the token actually gates execution.
#[test]
fn console_distinction_interactive_decline() {
    run_legs(&["interactive-decline"]);
}

/// Trap: with `SAFEBASH_NONINTERACTIVE=1` and the SAME terminal attached, safebash
/// denies without ever prompting - no prompt in the transcript, the
/// confirmation-required diagnostic present, the victim survives. This is the
/// behaviour the no-terminal tests cannot distinguish from an ordinary denial.
///
/// The trap runs WITH the `interactive-approve` control in the same invocation
/// on purpose: the trap's assertions (no prompt + denial + victim survives) are
/// ALSO met by an ordinary `safebash` on a terminal that is present but not
/// answerable, where `confirm_on_terminal` returns `Unavailable`. The control
/// fails on such a terminal, so pairing them here keeps the trap from passing
/// vacuously when this one test is run on its own.
#[test]
fn console_distinction_pi_denies_without_prompt() {
    run_legs(&["interactive-approve", "pi-no-prompt-deny"]);
}

/// All three legs in one pass (fresh fixture per leg inside the driver).
#[test]
fn console_distinction_full_pass() {
    run_legs(&[
        "interactive-approve",
        "interactive-decline",
        "pi-no-prompt-deny",
    ]);
}
