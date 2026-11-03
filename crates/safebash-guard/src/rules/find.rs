//! `find` and `rsync` (cc-safety-net `find.ts`, `rsync.ts`).

use super::rm::{is_recursive_force, GIT_METADATA, ROOT_OR_HOME};
use crate::analyze::{command_name, Analyzer, Cx};
use crate::model::Word;
use crate::targets::{contains_git_metadata, is_root_or_home, is_scoped};
use crate::verdict::{Finding, Intent};

const FIND_DELETE: &str = "find -delete permanently removes files. Use -print first to preview.";
const FIND_EXEC_RM: &str = "find -exec rm -rf is dangerous. Use explicit file list instead.";
const RSYNC_DELETE: &str = "rsync --delete permanently removes destination files missing from the source. Mirror only into explicit paths inside the current directory or under /tmp, /var/tmp, or $TMPDIR.";
const RSYNC_ROOT: &str =
    "rsync --delete targeting root or home directory is extremely dangerous and always blocked.";

/// Primaries that take values (skipped while looking for `-delete`).
const VALUE_PRIMARIES: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-regex",
    "-iregex",
    "-type",
    "-xtype",
    "-user",
    "-group",
    "-uid",
    "-gid",
    "-perm",
    "-size",
    "-mtime",
    "-mmin",
    "-atime",
    "-amin",
    "-ctime",
    "-cmin",
    "-newer",
    "-anewer",
    "-cnewer",
    "-maxdepth",
    "-mindepth",
    "-links",
    "-inum",
    "-samefile",
    "-fstype",
    "-used",
    "-printf",
    "-fprintf",
    "-fprint",
    "-fprint0",
    "-fls",
    "-files0-from",
    "-context",
    "-lname",
    "-ilname",
    "-regextype",
    "-newerXY",
];

pub fn check(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    // Starting points: after -H/-L/-P and an optional --, up to the first
    // expression word.
    let mut i = 1;
    let mut follows = false;
    while let Some(w) = argv.get(i).and_then(Word::as_lit) {
        match w {
            "-H" | "-P" => i += 1,
            "-L" => {
                follows = true;
                i += 1;
            }
            _ => break,
        }
    }
    if argv.get(i).and_then(Word::as_lit) == Some("--") {
        i += 1;
    }
    let start = i;
    while let Some(w) = argv.get(i) {
        let t = w.text();
        if t.starts_with('-') || t == "!" || t == "(" || t == ")" {
            break;
        }
        i += 1;
    }
    let starts: Vec<&Word> = argv[start..i].iter().collect();
    let expr = &argv[i..];

    let mut deletes = false;
    let mut exec_bodies: Vec<Vec<Word>> = Vec::new();
    let mut j = 0;
    while j < expr.len() {
        let t = expr[j].text();
        match t {
            "-delete" => deletes = true,
            "-L" | "-follow" | "-f" => follows = true,
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                let body_start = j + 1;
                let mut k = body_start;
                while k < expr.len() {
                    let tk = expr[k].text();
                    if tk == ";"
                        || tk == "\\;"
                        || (tk == "+" && k > body_start && expr[k - 1].text() == "{}")
                    {
                        break;
                    }
                    k += 1;
                }
                exec_bodies.push(expr[body_start..k].to_vec());
                j = k;
            }
            p if VALUE_PRIMARIES.contains(&p) => j += 1,
            _ => {}
        }
        j += 1;
    }

    let rm_exec = exec_bodies.iter().any(|body| {
        body.first()
            .and_then(command_name)
            .is_some_and(|n| n == "rm" || n == "rmdir")
    });
    let deleting = deletes || rm_exec;
    if deleting {
        let mut roots = starts
            .iter()
            .filter_map(|w| w.as_lit())
            .filter_map(|t| an.host.norm(t, cx.cwd.as_ref()));
        if starts
            .iter()
            .any(|w| matches!(w.text(), "~" | "$HOME" | "${HOME}" | "/*"))
            || roots.any(|p| is_root_or_home(an, &p))
        {
            an.rule(
                cx,
                Finding::deny(
                    "rm.recursive-force-root-or-home",
                    Intent::HardStop,
                    ROOT_OR_HOME,
                ),
            );
            return;
        }
        let in_metadata = starts
            .iter()
            .filter_map(|w| w.as_lit())
            .filter_map(|t| an.host.norm(t, cx.cwd.as_ref()))
            .any(|p| contains_git_metadata(an, &p, true));
        if in_metadata {
            an.rule(
                cx,
                Finding::deny("find.delete-git-metadata", Intent::HardStop, GIT_METADATA),
            );
            return;
        }
    }
    if deletes {
        let scoped = !follows && !starts.is_empty() && starts.iter().all(|w| is_scoped(an, cx, w));
        if !scoped {
            an.rule(
                cx,
                Finding::deny("find.delete", Intent::ScopeDown, FIND_DELETE),
            );
        }
    }
    for body in &exec_bodies {
        if body.is_empty() {
            continue;
        }
        let mut child = body.clone();
        // Strip wrappers to find an rm -rf child.
        while child.first().and_then(command_name).is_some_and(|n| {
            matches!(
                n.as_str(),
                "sudo" | "env" | "command" | "builtin" | "busybox"
            )
        }) {
            child.remove(0);
        }
        if child.first().and_then(command_name).as_deref() == Some("rm")
            && is_recursive_force(&child)
        {
            an.rule(
                cx,
                Finding::deny(
                    "find.exec-rm-recursive-force",
                    Intent::ScopeDown,
                    FIND_EXEC_RM,
                ),
            );
        }
        // The body is a full command of its own (with `{}` standing for
        // found paths).
        let mut child_cx = cx.clone();
        child_cx.dynamic_input = true;
        an.command(body, &child_cx, depth);
    }
}

/// `rsync --delete` into anything but scoped destinations.
pub fn rsync(an: &Analyzer<'_>, cx: &Cx, argv: &[Word]) {
    const VALUE_LONG: &[&str] = &[
        "--rsh",
        "--rsync-path",
        "--exclude",
        "--include",
        "--exclude-from",
        "--include-from",
        "--files-from",
        "--filter",
        "--chmod",
        "--chown",
        "--usermap",
        "--groupmap",
        "--timeout",
        "--contimeout",
        "--port",
        "--password-file",
        "--log-file",
        "--log-file-format",
        "--out-format",
        "--partial-dir",
        "--temp-dir",
        "--compare-dest",
        "--copy-dest",
        "--link-dest",
        "--backup-dir",
        "--suffix",
        "--max-size",
        "--min-size",
        "--max-delete",
        "--modify-window",
        "--bwlimit",
        "--iconv",
        "--sockopts",
        "--block-size",
        "--checksum-choice",
        "--compress-choice",
        "--compress-level",
        "--skip-compress",
        "--info",
        "--debug",
        "--stop-after",
        "--stop-at",
        "--write-batch",
        "--only-write-batch",
        "--read-batch",
        "--protocol",
        "--address",
    ];
    let mut delete = false;
    let mut operands: Vec<&Word> = Vec::new();
    let mut i = 1;
    let mut after_dashes = false;
    while i < argv.len() {
        let w = &argv[i];
        let t = w.text();
        if after_dashes {
            operands.push(w);
        } else if t == "--" {
            after_dashes = true;
        } else if t.starts_with("--") {
            let name = t.split('=').next().unwrap_or(t);
            // `--del` or any `--dele...` (`--delay-updates` is not one).
            delete |= name == "--del" || name.starts_with("--dele");
            if VALUE_LONG.contains(&name) && !t.contains('=') {
                i += 1;
            }
        } else if t.starts_with('-') && t.len() > 1 {
            if t.ends_with(['e', 'f', 'B', 'M', 'T', '@']) {
                i += 1;
            }
        } else {
            operands.push(w);
        }
        i += 1;
    }
    if !delete || operands.len() < 2 {
        return;
    }
    for dest in &operands[1..] {
        let text = dest.text();
        let remote = text.contains(':')
            && !text.contains('$')
            && !text.contains('`')
            && !text.starts_with('/');
        if remote {
            continue;
        }
        if let Some(path) = dest.as_lit().and_then(|t| an.host.norm(t, cx.cwd.as_ref())) {
            if is_root_or_home(an, &path) {
                an.rule(
                    cx,
                    Finding::deny(
                        "rm.recursive-force-root-or-home",
                        Intent::HardStop,
                        RSYNC_ROOT,
                    ),
                );
                return;
            }
            if contains_git_metadata(an, &path, true) {
                an.rule(
                    cx,
                    Finding::deny("rm.git-metadata", Intent::HardStop, GIT_METADATA),
                );
                return;
            }
        }
        if !is_scoped(an, cx, dest) {
            an.rule(
                cx,
                Finding::deny("rsync.delete", Intent::ScopeDown, RSYNC_DELETE),
            );
            return;
        }
    }
}
