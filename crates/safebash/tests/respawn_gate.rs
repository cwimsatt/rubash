//! End-to-end proof that a respawn (background job / coproc) cannot escape
//! the gate by selecting an ungated engine.
//!
//! The bug: background jobs, coprocs, traps and process-substitution
//! children respawn the shell on a script body. The engine's exe-selection
//! chain preferred `CARGO_BIN_EXE_rubash` (an ordinary env var) over the
//! current executable, so an agent could point a respawn at a plain,
//! ungated `rubash` and have the respawned body run with no safety checks.
//! The body's danger may only appear after the child expands it (a target
//! read at run time), which the parent's spawn backstop cannot judge — so
//! the child MUST be the gated shell.
//!
//! This test runs the real `safebash` binary with
//! `CARGO_BIN_EXE_rubash` pointed at a plain `rubash` (the strongest form
//! of the attack) and a backgrounded delete whose target is read at run
//! time, outside the workspace. It asserts the victim survives and the
//! "deleted" marker is never written — i.e. the body ran gated regardless
//! of the attack env.

use std::path::{Path, PathBuf};
use std::process::Command;

fn safebash_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_safebash"))
}

/// The plain, ungated rubash binary sitting next to safebash in the target
/// dir (built as the workspace root crate).
fn rubash_bin() -> Option<PathBuf> {
    let candidate = safebash_bin().parent()?.join(if cfg!(windows) {
        "rubash.exe"
    } else {
        "rubash"
    });
    candidate.is_file().then_some(candidate)
}

#[test]
fn backgrounded_dynamic_delete_cannot_escape_via_ungated_respawn() {
    let Some(rubash) = rubash_bin() else {
        eprintln!("skipping: plain rubash binary not built next to safebash");
        return;
    };
    let root =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("respawn-{}", std::process::id()));
    let ws = root.join("ws");
    let home = root.join("home");
    let victim = root.join("victim"); // sibling of ws, OUTSIDE it, not under /tmp
    let vp = root.join("vp.txt");
    let marker = root.join("deleted-marker");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(victim.join("data")).unwrap();
    std::fs::write(&vp, format!("{}\n", victim.display())).unwrap();

    // The target is read at run time, so only a gate inside the respawned
    // child — which must be safebash, not the attacker's rubash — can judge
    // the concrete `rm -rf <victim>`. `&& marker` records an ungated run.
    let script = format!(
        "{{ t=\"$(cat '{vp}')\"; rm -rf \"$t\" && printf x > '{marker}'; }} & wait; true",
        vp = vp.display(),
        marker = marker.display(),
    );

    let output = Command::new(safebash_bin())
        .arg("-c")
        .arg(&script)
        .current_dir(&ws)
        .env("HOME", &home)
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("TMPDIR", "/tmp") // standard temp roots; victim under target/ is NOT temp
        .env("CARGO_BIN_EXE_rubash", &rubash) // the attack: point respawns at ungated rubash
        .env_remove("SAFEBASH_WORKSPACE")
        .env_remove("SAFEBASH_FLOOR")
        .output()
        .expect("run safebash");

    let victim_survived = victim.join("data").is_dir();
    let marker_present = marker.exists();
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        victim_survived && !marker_present,
        "respawn escaped the gate: victim_survived={victim_survived} marker_present={marker_present}\n\
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Control: the same delete, when the target is INSIDE the workspace, is
/// allowed — so the test above is detecting the outside-workspace gate, not
/// a background job that simply never runs.
#[test]
fn backgrounded_delete_inside_workspace_is_allowed() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("respawn-ok-{}", std::process::id()));
    let ws = root.join("ws");
    let home = root.join("home");
    let build = ws.join("build");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(build.join("data")).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = Command::new(safebash_bin())
        .arg("-c")
        .arg("rm -rf build & wait; true")
        .current_dir(&ws)
        .env("HOME", &home)
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("TMPDIR", "/tmp")
        .env_remove("SAFEBASH_WORKSPACE")
        .env_remove("SAFEBASH_FLOOR")
        .output()
        .expect("run safebash");

    let removed = !build.exists();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        removed,
        "in-workspace background delete should be allowed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The gate helper's own contract: with a gate installed, a respawn is
/// forced to the current executable, ignoring the `unconstrained` chain
/// (which an attacker could steer via `CARGO_BIN_EXE_rubash`).
#[test]
fn respawn_exe_is_forced_to_current_exe_under_a_gate() {
    use rubash::exec_gate::{self, CommandCheck, ExecGate, GateVerdict, RedirectCheck, SpawnCheck};

    struct AllowAll;
    impl ExecGate for AllowAll {
        fn check_command(&self, _: &CommandCheck<'_>) -> GateVerdict {
            GateVerdict::Allow
        }
        fn check_redirect(&self, _: &RedirectCheck<'_>) -> GateVerdict {
            GateVerdict::Allow
        }
        fn check_spawn(&self, _: &SpawnCheck) -> GateVerdict {
            GateVerdict::Allow
        }
    }

    let bogus = PathBuf::from("/attacker/controlled/rubash");
    // Before any gate is installed, the unconstrained chain is used.
    assert_eq!(exec_gate::respawn_exe(|| bogus.clone()), bogus);

    // After a gate is installed, the override is refused in favor of the
    // current (gated) executable.
    assert!(exec_gate::install(Box::new(AllowAll)));
    let chosen = exec_gate::respawn_exe(|| bogus.clone());
    assert_ne!(
        chosen, bogus,
        "respawn under a gate must not honor the override"
    );
    assert_eq!(chosen, std::env::current_exe().unwrap());
    assert!(chosen != Path::new("/nonexistent/safebash-respawn-fail-closed").to_path_buf());
}
