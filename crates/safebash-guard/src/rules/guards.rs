//! Self-protection (cc-safety-net `src/gate/guards/*`): the agent must not
//! edit or delete what enforces the policy.
//!
//! - `guard.policy-config`: safebash's policy files, policy directories
//!   (and, for recursive deletes and moves, their ancestors) and audit log;
//! - `guard.git-metadata`: writes into Git hooks or onto a `.git` file,
//!   and moves of Git metadata;
//! - `guard.safebash-env`: the variables a parent safebash hands its
//!   children (`SAFEBASH_FLOOR`, `SAFEBASH_WORKSPACE`) cannot be set,
//!   exported or unset by a command.

use crate::analyze::{command_name, Analyzer, Cx, Stage};
use crate::model::{Access, Word};
use crate::paths::NormPath;
use crate::verdict::{Finding, Intent};

const POLICY: &str = "This path contains the protected safebash policy or audit data and you must not modify or delete it.";
const GIT: &str = "Git metadata and hooks are protected. Ask the user before modifying them.";
const ENV: &str = "safebash's inherited protection settings cannot be changed by a command. Ask the user to change the safebash policy instead.";

/// Variables a command may not touch.
pub const PROTECTED_VARS: &[&str] = &["SAFEBASH_FLOOR", "SAFEBASH_WORKSPACE"];

/// Commands that only read their operands.
const READ_ONLY: &[&str] = &[
    "[",
    "cat",
    "file",
    "grep",
    "head",
    "jq",
    "less",
    "ls",
    "more",
    "rg",
    "stat",
    "tail",
    "test",
    "wc",
    "diff",
    "cmp",
    "md5sum",
    "sha256sum",
    "realpath",
    "readlink",
    "dirname",
    "basename",
    "cd",
    "echo",
    "printf",
];

fn deny_policy(an: &Analyzer<'_>, cx: &Cx) {
    let finding = Finding::deny("guard.policy-config", Intent::HardStop, POLICY);
    an.emit(Stage::Guard, with_segment(cx, finding));
}

fn deny_git(an: &Analyzer<'_>, cx: &Cx) {
    let finding = Finding::deny("guard.git-metadata", Intent::HardStop, GIT);
    an.emit(Stage::Guard, with_segment(cx, finding));
}

fn with_segment(cx: &Cx, finding: Finding) -> Finding {
    if cx.segment.is_empty() {
        finding
    } else {
        finding.with_segment(cx.segment.clone())
    }
}

fn resolve(an: &Analyzer<'_>, cx: &Cx, word: &Word) -> Option<NormPath> {
    word.as_lit().and_then(|t| an.host.norm(t, cx.cwd.as_ref()))
}

/// A protected safebash path, or something inside one.
fn is_protected(an: &Analyzer<'_>, path: &NormPath) -> bool {
    an.host.protected.iter().any(|p| path.is_within(p))
}

/// A protected path, something inside one, or (for recursive deletes and
/// moves) an ancestor of a user protected root. The root and home are left
/// to the catastrophic root-or-home rules, whose reason is the one worth
/// reading.
fn contains_protected(an: &Analyzer<'_>, path: &NormPath) -> bool {
    if crate::targets::is_root_or_home(an, path) {
        return false;
    }
    is_protected(an, path) || an.host.protected_roots.iter().any(|p| p.is_within(path))
}

pub fn check_command(an: &Analyzer<'_>, cx: &Cx, argv: &[Word]) {
    let Some(name) = argv.first().and_then(command_name) else {
        return;
    };
    // Variables handed to child shells.
    match name.as_str() {
        "export" | "declare" | "typeset" | "readonly" | "local" | "unset" => {
            let touches = argv[1..].iter().any(|w| {
                let text = w.text();
                let var = text.split('=').next().unwrap_or(text);
                PROTECTED_VARS.contains(&var)
            });
            if touches {
                an.emit(
                    Stage::Guard,
                    with_segment(
                        cx,
                        Finding::deny("guard.safebash-env", Intent::HardStop, ENV),
                    ),
                );
            }
        }
        "env" => {
            let mut iter = argv[1..].iter().peekable();
            while let Some(w) = iter.next() {
                let text = w.text();
                let unset = if text == "-u" || text == "--unset" {
                    iter.next().map(|n| n.text().to_string())
                } else {
                    text.strip_prefix("-u")
                        .or_else(|| text.strip_prefix("--unset="))
                        .map(str::to_string)
                };
                let assigned = text.split_once('=').map(|(n, _)| n.to_string());
                if unset
                    .iter()
                    .chain(assigned.iter())
                    .any(|v| PROTECTED_VARS.contains(&v.as_str()))
                {
                    an.emit(
                        Stage::Guard,
                        with_segment(
                            cx,
                            Finding::deny("guard.safebash-env", Intent::HardStop, ENV),
                        ),
                    );
                    break;
                }
            }
        }
        _ => {}
    }
    if an.host.protected.is_empty() {
        return;
    }
    let operands: Vec<&Word> = argv[1..].iter().collect();
    match name.as_str() {
        "rm" | "rmdir" | "unlink" => {
            let recursive = crate::rules::rm::is_recursive(
                &operands
                    .iter()
                    .copied()
                    .filter(|w| w.text().starts_with('-'))
                    .collect::<Vec<_>>(),
            );
            for word in &operands {
                if let Some(path) = resolve(an, cx, word) {
                    if (recursive && contains_protected(an, &path)) || is_protected(an, &path) {
                        deny_policy(an, cx);
                        return;
                    }
                }
            }
        }
        "find" => {
            // Only when a starting point is itself the protected tree (or
            // inside it); a starting point that merely contains the policy
            // dir as a descendant is left to the find.delete rule.
            let deletes = operands
                .iter()
                .any(|w| matches!(w.text(), "-delete" | "-exec" | "-execdir"));
            if deletes
                && operands
                    .iter()
                    .take_while(|w| !w.text().starts_with('-'))
                    .filter_map(|w| resolve(an, cx, w))
                    .any(|p| is_protected(an, &p))
            {
                deny_policy(an, cx);
            }
        }
        _ if READ_ONLY.contains(&name.as_str()) => {}
        "sed"
            if !operands.iter().any(|w| {
                w.text() == "-i"
                    || w.text().starts_with("--in-place")
                    || (w.text().starts_with("-i") && !w.text().starts_with("--"))
            }) => {}
        _ => {
            for word in &operands {
                let text = word.text();
                let value = text.split_once('=').map_or(text, |(_, v)| v);
                if let Some(path) = an
                    .host
                    .norm(value, cx.cwd.as_ref())
                    .filter(|_| word.is_lit())
                {
                    if is_protected(an, &path) && !is_protected_dir_destination(an, &path) {
                        deny_policy(an, cx);
                        return;
                    }
                }
            }
        }
    }
}

/// `cp x ~/.config/safebash` names the directory as a destination; only
/// the files inside are protected from being overwritten by name.
fn is_protected_dir_destination(an: &Analyzer<'_>, path: &NormPath) -> bool {
    an.host.protected.iter().any(|p| p == path) && std::path::Path::new(path.as_str()).is_dir()
}

/// `mv`: a protected source (or an ancestor of one), or a destination
/// inside Git hooks or onto the protected policy.
pub fn mv(an: &Analyzer<'_>, cx: &Cx, argv: &[Word]) {
    let mut operands: Vec<&Word> = Vec::new();
    let mut target_dir: Option<&Word> = None;
    let mut i = 1;
    while i < argv.len() {
        let t = argv[i].text();
        if t == "-t" || t == "--target-directory" {
            target_dir = argv.get(i + 1);
            i += 2;
            continue;
        }
        if t.starts_with("--target-directory=") {
            i += 1;
            continue;
        }
        if !t.starts_with('-') || t == "-" {
            operands.push(&argv[i]);
        }
        i += 1;
    }
    let (sources, dest): (Vec<&Word>, Option<&Word>) = match target_dir {
        Some(dir) => (operands, Some(dir)),
        None if operands.len() >= 2 => {
            let dest = operands[operands.len() - 1];
            (operands[..operands.len() - 1].to_vec(), Some(dest))
        }
        None => (operands, None),
    };
    for source in &sources {
        if let Some(path) = resolve(an, cx, source) {
            if contains_protected(an, &path) {
                deny_policy(an, cx);
                return;
            }
            if an
                .host
                .git_metadata
                .iter()
                .any(|m| path == *m || m.is_within(&path) || path.is_within(m))
            {
                deny_git(an, cx);
                return;
            }
        }
    }
    if let Some(path) = dest.and_then(|d| resolve(an, cx, d)) {
        if is_protected(an, &path) {
            deny_policy(an, cx);
        } else if an
            .host
            .git_metadata
            .iter()
            .any(|m| path == *m || (path.is_within(m) && m.as_str().ends_with("/hooks")))
        {
            deny_git(an, cx);
        }
    }
}

/// Writes onto protected files or into Git hooks.
pub fn check_redirect(an: &Analyzer<'_>, cx: &Cx, access: Access, target: &Word) {
    if !access.writes() {
        return;
    }
    let Some(path) = resolve(an, cx, target) else {
        return;
    };
    if is_protected(an, &path) {
        deny_policy(an, cx);
        return;
    }
    let into_hooks = an
        .host
        .git_metadata
        .iter()
        .any(|m| m.as_str().ends_with("/hooks") && path.is_within(m));
    let onto_git_file = an.host.git_metadata.iter().any(|m| {
        path == *m && m.file_name() == Some(".git") && std::path::Path::new(m.as_str()).is_file()
    });
    if into_hooks || onto_git_file {
        deny_git(an, cx);
    }
}

/// Prefix assignments of protected variables (`SAFEBASH_FLOOR=standard
/// safebash ...`).
pub fn assignments(an: &Analyzer<'_>, cx: &Cx, assignments: &[(String, Word)]) {
    if assignments
        .iter()
        .any(|(name, _)| PROTECTED_VARS.contains(&name.as_str()))
    {
        an.emit(
            Stage::Guard,
            with_segment(
                cx,
                Finding::deny("guard.safebash-env", Intent::HardStop, ENV),
            ),
        );
    }
}
