//! safebash: a bash-compatible shell (the rubash engine) with built-in
//! LLM-agent safety checks.
//!
//! Layers, outermost first (see `docs/safebash/design.md`):
//!
//! 1. preflight: a `-c` string or script file is analyzed whole before
//!    anything runs, so a denied command line has no partial effects;
//! 2. dispatch: every simple command, after expansion, before it runs;
//! 3. redirect: every file redirection target, after expansion;
//! 4. spawn: every child process the shell creates (backstop).
//!
//! Layers 2-4 are rubash's execution gate (`rubash::exec_gate`); this
//! binary installs the guard behind it and then runs the unmodified
//! rubash entry point.

#[path = "../../../src/main.rs"]
#[allow(dead_code, clippy::all)]
mod engine;

use safebash::{apply_non_interactive, convert, gate, setup};
use safebash_guard::audit::AuditLog;
use safebash_guard::verdict::{Action, Layer};
use safebash_guard::{Decision, Guard};
use std::path::PathBuf;

const DENIED: i32 = 126;

fn build_guard(posix: bool) -> Guard {
    let workspace = setup::workspace();
    let (host, policy) = setup::host_and_policy(workspace.as_deref());
    let audit_dir = safebash_guard::platform::state_dir().map(|d| d.join("audit"));
    let audit = if policy.audit {
        AuditLog::new(audit_dir)
    } else {
        AuditLog::disabled()
    };
    // Children (nested safebash, background respawns) inherit the anchor
    // and can never run weaker than this process.
    if let Some(w) = &workspace {
        std::env::set_var("SAFEBASH_WORKSPACE", w);
    }
    std::env::set_var("SAFEBASH_FLOOR", policy.level.name());
    Guard::new(
        policy,
        host,
        Some(Box::new(convert::RubashParser { posix })),
        audit,
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(flag) = args.get(1).filter(|a| a.starts_with("--guard-")) {
        std::process::exit(guard_cli(flag, &args[2..]));
    }
    let arg0 = args.first().map(PathBuf::from);
    let file_name = arg0.as_deref().and_then(|p| p.file_name());
    let posix = file_name.is_some_and(|n| n == "sh");
    let mut guard = build_guard(posix);
    // Non-interactive host (e.g. the pi coding agent, which runs
    // `safebash -c "<command>"` and cannot answer a prompt): a Confirm
    // verdict becomes a denial and safebash never prompts (the no-approver
    // branch in `Guard::decide`). The executable selects this itself - by its
    // own name (`safebash-pi`) or the `SAFEBASH_NONINTERACTIVE` environment
    // variable - never a command-line flag, because pi passes only `-c` and
    // the command. See `docs/safebash/pi-integration.md`.
    apply_non_interactive(&mut guard, file_name);
    if let Some(code) = preflight(&guard, &args) {
        std::process::exit(code);
    }
    rubash::exec_gate::install(Box::new(gate::SafebashGate::new(guard)));
    engine::main();
}

/// The text a `bash`-style invocation will run: `Some((text, origin))`
/// for `-c STRING` or a script operand.
fn invocation_source(args: &[String]) -> Option<(String, String)> {
    let mut command_mode = false;
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            i += if matches!(long, "rcfile" | "init-file") {
                2
            } else {
                1
            };
            continue;
        }
        if (a.starts_with('-') || a.starts_with('+')) && a.len() > 1 {
            let mut takes_value = false;
            for c in a[1..].chars() {
                match c {
                    'c' => command_mode = true,
                    's' => return None,
                    'o' | 'O' => takes_value = true,
                    _ => {}
                }
            }
            i += if takes_value { 2 } else { 1 };
            continue;
        }
        break;
    }
    let operand = args.get(i)?;
    if command_mode {
        return Some((operand.clone(), "-c".into()));
    }
    let meta = std::fs::metadata(operand).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    let bytes = std::fs::read(operand).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    Some((
        String::from_utf8_lossy(&bytes).into_owned(),
        operand.clone(),
    ))
}

/// Analyze the whole input before anything runs; `Some(126)` when denied.
fn preflight(guard: &Guard, args: &[String]) -> Option<i32> {
    let (source, origin) = invocation_source(args)?;
    let cwd = std::env::current_dir().ok();
    let report = guard.analyze_source(&source, cwd.as_deref());
    // Preflight enforces only the denials that no confirmation can lift:
    // catastrophic rules, the self-protection guards, and the
    // analysis/dynamic-source rules. Blocking these before the first
    // command runs avoids partial effects. Everything confirmable (a
    // destructive git verb, a secret read, a paranoid delete) is left to
    // the dispatch layer, so a person is asked exactly once, immediately
    // before that command runs — and the approval there also covers its
    // spawn.
    let fixed = report
        .findings
        .iter()
        .find(|f| f.action == Action::Deny && safebash_guard::guard::is_fixed(&f.rule))?;
    let shown = if origin == "-c" {
        source.clone()
    } else {
        origin
    };
    let report = safebash_guard::verdict::Report {
        findings: vec![fixed.clone()],
    };
    match guard.decide(&report, Layer::Preflight, &shown, cwd.as_deref(), None) {
        Decision::Allow => None,
        Decision::Deny { message } => {
            eprintln!("{message}");
            Some(DENIED)
        }
    }
}

fn guard_cli(flag: &str, rest: &[String]) -> i32 {
    let mut json = false;
    let mut cwd: Option<PathBuf> = None;
    let mut command: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--json" => json = true,
            "--cwd" => {
                cwd = rest.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            other => {
                command = Some(match command {
                    Some(c) => format!("{c} {other}"),
                    None => other.to_string(),
                })
            }
        }
        i += 1;
    }
    if let Some(dir) = &cwd {
        if std::env::set_current_dir(dir).is_err() {
            eprintln!("safebash: --cwd {}: not a directory", dir.display());
            return 2;
        }
    }
    let mut guard = build_guard(false);
    guard.interactive_confirm = false;
    match flag {
        "--guard-status" => {
            status(&guard);
            0
        }
        "--guard-check" | "--guard-explain" => {
            let Some(command) = command else {
                eprintln!("usage: safebash {flag} [--json] [--cwd DIR] COMMAND");
                return 2;
            };
            let here = std::env::current_dir().ok();
            let report = guard.analyze_source(&command, here.as_deref());
            if flag == "--guard-explain" {
                explain(&report, json);
                return if report.action() == Action::Allow {
                    0
                } else {
                    1
                };
            }
            let decision = guard.decide(&report, Layer::Preflight, &command, here.as_deref(), None);
            if json {
                let primary = report.primary();
                let value = serde_json::json!({
                    "decision": match report.action() { Action::Allow => "allow", Action::Confirm => "confirm", Action::Deny => "deny" },
                    "rule": primary.map(|f| f.rule.to_string()),
                    "reason": primary.map(|f| f.reason.clone()),
                    "message": match &decision { Decision::Deny { message } => Some(message.clone()), Decision::Allow => None },
                });
                println!("{value}");
            } else {
                match &decision {
                    Decision::Allow => println!("allow"),
                    Decision::Deny { message } => println!("{message}"),
                }
            }
            if decision == Decision::Allow {
                0
            } else {
                1
            }
        }
        _ => {
            eprintln!("safebash: unknown option {flag} (try --guard-check, --guard-explain, --guard-status)");
            2
        }
    }
}

fn explain(report: &safebash_guard::verdict::Report, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_default()
        );
        return;
    }
    if report.findings.is_empty() {
        println!("allow: no rule matched");
        return;
    }
    for finding in &report.findings {
        let action = match finding.action {
            Action::Allow => "allow",
            Action::Confirm => "confirm",
            Action::Deny => "deny",
        };
        println!("{action:8} {}  {}", finding.rule, finding.reason);
        if let Some(segment) = &finding.segment {
            println!("         segment: {segment}");
        }
    }
}

fn status(guard: &Guard) {
    let policy = &guard.policy;
    let host = &guard.host;
    println!("level: {}", policy.level.name());
    println!(
        "capabilities: fail_closed={} paranoid_rm={} paranoid_interpreters={}",
        policy.capabilities.fail_closed,
        policy.capabilities.paranoid_rm,
        policy.capabilities.paranoid_interpreters
    );
    println!("confirmation: {:?}", policy.confirm);
    println!(
        "secret protection: {}",
        if policy.secrets_enabled { "on" } else { "off" }
    );
    for (rule, setting) in &policy.rules {
        println!("rule {rule}: {setting:?}");
    }
    let show = |p: &Option<safebash_guard::paths::NormPath>| {
        p.as_ref()
            .map_or("(unknown)".to_string(), |p| p.to_string())
    };
    println!("workspace: {}", show(&host.workspace));
    println!("home: {}", show(&host.home));
    println!(
        "temp roots: {}",
        host.temp_roots
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "protected: {}",
        host.protected
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "git metadata: {}",
        host.git_metadata
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some(dir) = safebash_guard::platform::config_dir() {
        println!("user policy: {}", dir.join("policy.toml").display());
    }
    match guard.audit_dir() {
        Some(dir) => println!("audit log: {}", dir.display()),
        None => println!("audit log: off"),
    }
    for warning in &policy.warnings {
        println!("warning: {warning}");
    }
}
