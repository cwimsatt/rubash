//! Git (cc-safety-net `src/gate/analyzer/git/{index,parse,rules}.ts`).
//!
//! Ported semantics:
//! - global options with a value (`-c -C --git-dir --work-tree
//!   --namespace --super-prefix --config-env`) are skipped; the subcommand
//!   is the first non-option word;
//! - long options match by prefix from four characters (`--fo` is
//!   `--force`, `--f` is not; `--force-with-lease` is not `--force`);
//! - short clusters are split into letters, stopping at a letter that takes
//!   a value (`checkout -bf x` creates branch `f x`, it does not force);
//! - command-line aliases (`-c alias.X=V`, `GIT_CONFIG_COUNT/KEY/VALUE`)
//!   are expanded; shell aliases (`!cmd`) are blocked;
//! - SSH command overrides on network subcommands are blocked.

use crate::analyze::{Analyzer, Cx};
use crate::model::Word;
use crate::verdict::{Finding, Intent};
use std::collections::HashSet;

const CHECKOUT_DOUBLE_DASH: &str =
    "git checkout -- discards uncommitted changes permanently. Use 'git stash' first.";
const CHECKOUT_PATH: &str = "git checkout <path> discards uncommitted changes permanently. Use 'git stash' first, or 'git switch' to change branches.";
const CHECKOUT_FORCE: &str =
    "git checkout --force discards uncommitted changes. Use 'git stash' first.";
const CHECKOUT_REF_PATH: &str =
    "git checkout <ref> -- <path> overwrites working tree with ref version. Use 'git stash' first.";
const CHECKOUT_PATHSPEC_FROM_FILE: &str =
    "git checkout --pathspec-from-file can overwrite multiple files. Use 'git stash' first.";
const CHECKOUT_AMBIGUOUS: &str = "git checkout with multiple positional args may overwrite files. Use 'git switch' for branches or 'git restore' for files.";
const SWITCH_DISCARD: &str =
    "git switch --discard-changes discards uncommitted changes. Use 'git stash' first.";
const SWITCH_FORCE: &str =
    "git switch --force discards uncommitted changes. Use 'git stash' first.";
const RESTORE: &str = "git restore discards uncommitted changes. Use 'git stash' first, or use --staged to only unstage.";
const RESTORE_WORKTREE: &str =
    "git restore --worktree explicitly discards working tree changes. Use 'git stash' first.";
const RESET_HARD: &str =
    "git reset --hard destroys all uncommitted changes permanently. Use 'git stash' first.";
const RESET_MERGE: &str = "git reset --merge can lose uncommitted changes. Use 'git stash' first.";
const CLEAN: &str =
    "git clean -f removes untracked files permanently. Use 'git clean -n' to preview first.";
const RM_FORCE: &str = "git rm --force removes tracked files from the working tree. Use 'git rm --cached' to keep the files, or 'git rm --dry-run' to preview first.";
const PUSH_FORCE: &str =
    "git push --force destroys remote history. Use --force-with-lease for safer force push.";
const PUSH_DELETE: &str =
    "git push deletes remote refs. Ask the user to run it manually if deletion is intended.";
const PUSH_MIRROR: &str = "git push --mirror can force-update and delete remote refs. Ask the user to run it manually if mirror push is intended.";
const BRANCH_DELETE: &str =
    "git branch -D force-deletes without merge check. Use -d for safe delete.";
const REBASE_ABORT: &str =
    "git rebase --abort discards rebase conflict resolutions. Use 'git status' first.";
const MERGE_ABORT: &str =
    "git merge --abort discards merge conflict resolutions. Use 'git status' first.";
const TAG_DELETE: &str =
    "git tag -d permanently deletes tags. Ask the user to run it manually if deletion is intended.";
const REFLOG_DELETE: &str = "git reflog delete removes recovery history. Ask the user to run it manually if deletion is intended.";
const STASH_DROP: &str =
    "git stash drop permanently deletes stashed changes. Consider 'git stash list' first.";
const STASH_CLEAR: &str = "git stash clear deletes ALL stashed changes permanently. Use 'git stash list' to review; ask the user to run it manually if intended.";
const WORKTREE_REMOVE_FORCE: &str =
    "git worktree remove --force can delete uncommitted changes. Remove --force flag.";
const SSH_ENV: &str = "Git SSH command overrides can run arbitrary programs during network operations. Ask the user to run it manually if the override is intended.";
const ALIAS: &str = "Command-line Git aliases that run shell commands or cannot be resolved are blocked. Run the underlying command directly.";

const GLOBAL_OPTS_WITH_VALUE: &[&str] = &[
    "-c",
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
];

/// `matchesGitLongOption`: prefix match of at least four characters.
pub fn long(token: &str, option: &str) -> bool {
    let name = token.split('=').next().unwrap_or(token);
    name.len() >= 4 && option.starts_with(name) && name.starts_with("--") && name.len() - 2 >= 2
}

/// `extractShortOpts`: letters of short clusters before `--`, stopping
/// after a letter that takes a value.
fn short_opts(tokens: &[&str], with_value: &[char]) -> HashSet<char> {
    let mut opts = HashSet::new();
    for token in tokens {
        if *token == "--" {
            break;
        }
        if token.starts_with('-') && !token.starts_with("--") && token.len() > 1 {
            for c in token[1..].chars() {
                if !c.is_ascii_alphabetic() {
                    break;
                }
                opts.insert(c);
                if with_value.contains(&c) {
                    break;
                }
            }
        }
    }
    opts
}

fn split_dashes<'t>(tokens: &'t [&'t str]) -> (&'t [&'t str], &'t [&'t str], bool) {
    match tokens.iter().position(|t| *t == "--") {
        Some(i) => (&tokens[..i], &tokens[i + 1..], true),
        None => (tokens, &[], false),
    }
}

/// Analyze a git command line.
pub fn check(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], _depth: usize) {
    let tokens: Vec<String> = argv.iter().map(|w| w.text().to_string()).collect();
    let mut config: Vec<(String, String)> = Vec::new();
    let mut i = 1;
    let mut git_cwd = cx.cwd.clone();
    // Global options.
    let mut sub_index = None;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        if t == "--" {
            if tokens.get(i + 1).is_some_and(|n| !n.starts_with('-')) {
                sub_index = Some(i + 1);
            }
            break;
        }
        if !t.starts_with('-') {
            sub_index = Some(i);
            break;
        }
        if t == "-c" {
            if let Some(entry) = tokens.get(i + 1) {
                push_config(&mut config, entry);
            }
        } else if let Some(entry) = t.strip_prefix("-c") {
            push_config(&mut config, entry);
        } else if t == "-C" {
            git_cwd = tokens
                .get(i + 1)
                .and_then(|d| an.host.norm(d, git_cwd.as_ref()));
        }
        i += if GLOBAL_OPTS_WITH_VALUE.contains(&t) {
            2
        } else {
            1
        };
    }
    // Environment-supplied config (GIT_CONFIG_COUNT/KEY_n/VALUE_n).
    if let Some(count) = cx.env_value("GIT_CONFIG_COUNT") {
        match count.as_lit().and_then(|c| c.trim().parse::<usize>().ok()) {
            Some(n) if n <= 1024 => {
                for k in 0..n {
                    let key = cx.env_value(&format!("GIT_CONFIG_KEY_{k}"));
                    let value = cx.env_value(&format!("GIT_CONFIG_VALUE_{k}"));
                    match (key.and_then(Word::as_lit), value.and_then(Word::as_lit)) {
                        (Some(key), Some(value)) => {
                            config.push((key.to_ascii_lowercase(), value.to_string()))
                        }
                        _ => {
                            an.rule(
                                cx,
                                Finding::deny("git.alias-config", Intent::ManualOnly, ALIAS),
                            );
                            return;
                        }
                    }
                }
            }
            _ => {
                an.rule(
                    cx,
                    Finding::deny("git.alias-config", Intent::ManualOnly, ALIAS),
                );
                return;
            }
        }
    }
    if let Some(params) = cx.env_value("GIT_CONFIG_PARAMETERS") {
        match params.as_lit() {
            Some(text) => {
                for entry in text.split_whitespace() {
                    push_config(&mut config, entry.trim_matches('\''));
                }
            }
            None => {
                an.rule(
                    cx,
                    Finding::deny("git.alias-config", Intent::ManualOnly, ALIAS),
                );
                return;
            }
        }
    }
    let Some(mut sub_index) = sub_index else {
        return;
    };
    let mut tokens = tokens;
    // Alias expansion, up to five levels.
    for _ in 0..6 {
        let sub = tokens[sub_index].to_ascii_lowercase();
        let Some((_, value)) = config
            .iter()
            .rev()
            .find(|(k, _)| *k == format!("alias.{sub}"))
        else {
            break;
        };
        let value = value.trim();
        if value.is_empty() || value.starts_with('!') {
            // A `!shell` alias runs an arbitrary command; it is blocked as
            // unresolvable rather than executed, so we do not analyze its
            // body (that would report the body's rule instead of naming the
            // real problem — an opaque command-line alias).
            an.rule(
                cx,
                Finding::deny("git.alias-config", Intent::ManualOnly, ALIAS),
            );
            return;
        }
        let expansion: Vec<String> = value.split_whitespace().map(str::to_string).collect();
        let rest: Vec<String> = tokens[sub_index + 1..].to_vec();
        tokens.truncate(sub_index);
        tokens.extend(expansion);
        tokens.extend(rest);
        if tokens.len() <= sub_index {
            return;
        }
        sub_index = tokens.len().min(sub_index);
    }
    let sub = tokens[sub_index].to_ascii_lowercase();
    let rest: Vec<&str> = tokens[sub_index + 1..].iter().map(String::as_str).collect();

    // SSH overrides on network subcommands.
    let ssh_env = ["GIT_SSH_COMMAND", "GIT_SSH", "GIT_SSH_VARIANT"]
        .iter()
        .any(|name| cx.env_value(name).is_some())
        || config.iter().any(|(k, _)| k == "core.sshcommand");
    if ssh_env && is_network(&sub, &rest) {
        an.rule(
            cx,
            Finding::deny("git.ssh-env", Intent::ManualOnly, SSH_ENV),
        );
    }

    let exists = |operand: &str| -> bool {
        git_cwd
            .as_ref()
            .and_then(|cwd| an.host.norm(operand, Some(cwd)))
            .is_some_and(|p| std::path::Path::new(p.as_str()).exists())
    };
    if let Some((rule, intent, reason)) = rule_for(&sub, &rest, &exists) {
        an.rule(cx, Finding::deny(rule, intent, reason));
    }
}

fn push_config(config: &mut Vec<(String, String)>, entry: &str) {
    if let Some((key, value)) = entry.split_once('=') {
        config.push((key.to_ascii_lowercase(), value.to_string()));
    } else {
        config.push((entry.to_ascii_lowercase(), "true".into()));
    }
}

fn is_network(sub: &str, rest: &[&str]) -> bool {
    match sub {
        "clone" | "fetch" | "pull" | "push" | "ls-remote" | "submodule" => true,
        "archive" => rest.iter().any(|t| t.starts_with("--remote")),
        "remote" => rest
            .iter()
            .find(|t| !matches!(**t, "-v" | "--verbose" | "--no-verbose"))
            .is_some_and(|t| *t == "update"),
        _ => false,
    }
}

type Hit = (&'static str, Intent, &'static str);

/// The rule a subcommand's arguments trigger, if any.
pub fn rule_for(sub: &str, rest: &[&str], exists: &dyn Fn(&str) -> bool) -> Option<Hit> {
    use Intent::{ManualOnly, UseAlternative};
    let (before, after, has_dashes) = split_dashes(rest);
    match sub {
        "checkout" => {
            let shorts = short_opts(before, &['b', 'B', 'U']);
            if before.iter().any(|t| long(t, "--force")) || shorts.contains(&'f') {
                return Some(("git.checkout-force", UseAlternative, CHECKOUT_FORCE));
            }
            for t in rest {
                if matches!(*t, "-b" | "-B" | "--orphan") {
                    return None;
                }
                if long(t, "--pathspec-from-file") {
                    return Some((
                        "git.checkout-pathspec-from-file",
                        UseAlternative,
                        CHECKOUT_PATHSPEC_FROM_FILE,
                    ));
                }
            }
            if has_dashes {
                return Some(if before.iter().any(|t| !t.starts_with('-')) {
                    ("git.checkout-ref-path", UseAlternative, CHECKOUT_REF_PATH)
                } else {
                    (
                        "git.checkout-double-dash",
                        UseAlternative,
                        CHECKOUT_DOUBLE_DASH,
                    )
                });
            }
            let positional = checkout_positionals(rest);
            if positional.len() >= 2 {
                return Some(("git.checkout-ambiguous", UseAlternative, CHECKOUT_AMBIGUOUS));
            }
            let operand = positional.first()?;
            if shorts.contains(&'d')
                || shorts.contains(&'t')
                || rest
                    .iter()
                    .any(|t| long(t, "--detach") || long(t, "--track"))
            {
                return None;
            }
            (pathspec_shaped(operand) || exists(operand)).then_some((
                "git.checkout-double-dash",
                UseAlternative,
                CHECKOUT_PATH,
            ))
        }
        "switch" => {
            if before.iter().any(|t| long(t, "--discard-changes")) {
                return Some(("git.switch-discard-changes", UseAlternative, SWITCH_DISCARD));
            }
            let shorts = short_opts(before, &['c', 'C']);
            (before.iter().any(|t| long(t, "--force")) || shorts.contains(&'f')).then_some((
                "git.switch-force",
                UseAlternative,
                SWITCH_FORCE,
            ))
        }
        "restore" => restore(rest),
        "reset" => {
            for t in rest {
                if long(t, "--hard") {
                    return Some(("git.reset-hard", UseAlternative, RESET_HARD));
                }
                if long(t, "--merge") {
                    return Some(("git.reset-merge", UseAlternative, RESET_MERGE));
                }
            }
            None
        }
        "clean" => {
            if rest.iter().any(|t| *t == "-n" || long(t, "--dry-run")) {
                return None;
            }
            let tokens: Vec<&str> = rest.iter().copied().filter(|t| *t != "--").collect();
            let shorts = short_opts(&tokens, &[]);
            (rest.iter().any(|t| long(t, "--force")) || shorts.contains(&'f')).then_some((
                "git.clean-force",
                UseAlternative,
                CLEAN,
            ))
        }
        "rm" => {
            let (mut force, mut cached, mut dry) = (false, false, false);
            for t in before {
                if long(t, "--no-force") {
                    force = false;
                } else if long(t, "--force") {
                    force = true;
                } else if long(t, "--no-cached") {
                    cached = false;
                } else if long(t, "--cached") {
                    cached = true;
                } else if long(t, "--no-dry-run") {
                    dry = false;
                } else if long(t, "--dry-run") {
                    dry = true;
                } else {
                    let shorts = short_opts(&[*t], &[]);
                    force |= shorts.contains(&'f');
                    dry |= shorts.contains(&'n');
                }
            }
            (force && !cached && !dry).then_some(("git.rm-force", UseAlternative, RM_FORCE))
        }
        "push" => {
            let shorts = short_opts(before, &[]);
            if before.iter().any(|t| long(t, "--mirror")) {
                return Some(("git.push-mirror", ManualOnly, PUSH_MIRROR));
            }
            let refspecs: Vec<&str> = before
                .iter()
                .copied()
                .filter(|t| !t.is_empty() && !t.starts_with('-'))
                .chain(after.iter().copied())
                .collect();
            if before.iter().any(|t| long(t, "--force"))
                || shorts.contains(&'f')
                || refspecs
                    .iter()
                    .any(|r| r.starts_with('+') || r.contains(":+"))
            {
                return Some(("git.push-force", UseAlternative, PUSH_FORCE));
            }
            (before.iter().any(|t| long(t, "--delete"))
                || shorts.contains(&'d')
                || refspecs.iter().any(|r| r.len() > 1 && r.starts_with(':')))
            .then_some(("git.push-delete", ManualOnly, PUSH_DELETE))
        }
        "branch" => {
            let shorts = short_opts(before, &[]);
            let delete = shorts.contains(&'D')
                || shorts.contains(&'d')
                || before.iter().any(|t| long(t, "--delete"));
            let force = shorts.contains(&'D')
                || shorts.contains(&'f')
                || before.iter().any(|t| long(t, "--force"));
            (delete && force).then_some(("git.branch-force-delete", UseAlternative, BRANCH_DELETE))
        }
        "rebase" => before.iter().any(|t| long(t, "--abort")).then_some((
            "git.rebase-abort",
            UseAlternative,
            REBASE_ABORT,
        )),
        "merge" => before.iter().any(|t| long(t, "--abort")).then_some((
            "git.merge-abort",
            UseAlternative,
            MERGE_ABORT,
        )),
        "tag" => {
            let shorts = short_opts(before, &[]);
            (shorts.contains(&'d') || before.iter().any(|t| long(t, "--delete"))).then_some((
                "git.tag-delete",
                ManualOnly,
                TAG_DELETE,
            ))
        }
        "reflog" => (rest.first() == Some(&"delete")).then_some((
            "git.reflog-delete",
            ManualOnly,
            REFLOG_DELETE,
        )),
        "stash" => rest.iter().find_map(|t| match *t {
            "drop" => Some(("git.stash-drop", UseAlternative, STASH_DROP)),
            "clear" => Some(("git.stash-clear", ManualOnly, STASH_CLEAR)),
            _ => None,
        }),
        "worktree" => {
            if !before.contains(&"remove") {
                return None;
            }
            let shorts = short_opts(before, &[]);
            (before.iter().any(|t| long(t, "--force")) || shorts.contains(&'f')).then_some((
                "git.worktree-remove-force",
                UseAlternative,
                WORKTREE_REMOVE_FORCE,
            ))
        }
        _ => None,
    }
}

fn pathspec_shaped(operand: &str) -> bool {
    let bytes = operand.as_bytes();
    operand == "."
        || operand == ".."
        || operand.starts_with("./")
        || operand.starts_with("../")
        || operand.starts_with(".\\")
        || operand.starts_with("..\\")
        || operand.starts_with('/')
        || operand.starts_with('\\')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
        || operand.ends_with('/')
        || operand.starts_with(':')
        || operand.contains(['*', '?', '['])
}

fn checkout_positionals<'t>(tokens: &[&'t str]) -> Vec<&'t str> {
    const WITH_VALUE: &[&str] = &[
        "-b",
        "-B",
        "--orphan",
        "--conflict",
        "--inter-hunk-context",
        "--pathspec-from-file",
        "--unified",
    ];
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        if t == "--" {
            break;
        }
        if !t.starts_with('-') {
            out.push(t);
            i += 1;
            continue;
        }
        if WITH_VALUE.contains(&t) {
            i += 2;
            continue;
        }
        if matches!(t, "--recurse-submodules" | "--track" | "-t") {
            let modes: &[&str] = if t == "--recurse-submodules" {
                &["checkout", "on-demand"]
            } else {
                &["direct", "inherit"]
            };
            i += match tokens.get(i + 1) {
                Some(next) if !next.starts_with('-') && modes.contains(next) => 2,
                _ => 1,
            };
            continue;
        }
        i += 1;
    }
    out
}

fn restore(tokens: &[&str]) -> Option<Hit> {
    let (mut pathspec, mut patch, mut worktree, mut explicit) = (false, false, true, false);
    let set_location = |worktree_on: Option<bool>, worktree: &mut bool, explicit: &mut bool| {
        if !*explicit {
            *worktree = false;
            *explicit = true;
        }
        if let Some(on) = worktree_on {
            *worktree = on;
        }
    };
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        match t {
            "--" => {
                pathspec |= i + 1 < tokens.len();
                break;
            }
            "--pathspec-from-file" => {
                pathspec = true;
                i += 2;
                continue;
            }
            "-h" | "--help" | "--version" => return None,
            "--staged" | "--no-staged" => set_location(None, &mut worktree, &mut explicit),
            "--worktree" => set_location(Some(true), &mut worktree, &mut explicit),
            "--no-worktree" => set_location(Some(false), &mut worktree, &mut explicit),
            "--patch" => patch = true,
            "--no-patch" => patch = false,
            "--source" | "--conflict" | "--unified" | "--inter-hunk-context" => {
                i += 2;
                continue;
            }
            _ if t.starts_with("--pathspec-from-file=") => pathspec = true,
            _ if t.starts_with("--") => {}
            "-" => pathspec = true,
            _ if !t.starts_with('-') => pathspec = true,
            _ => {
                let chars: Vec<char> = t[1..].chars().collect();
                for (j, c) in chars.iter().enumerate() {
                    match c {
                        'h' => return None,
                        'S' => set_location(None, &mut worktree, &mut explicit),
                        'W' => set_location(Some(true), &mut worktree, &mut explicit),
                        'p' => patch = true,
                        's' | 'U' => {
                            if j == chars.len() - 1 {
                                i += 1;
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        i += 1;
    }
    if (!pathspec && !patch) || !worktree {
        return None;
    }
    Some(if explicit {
        (
            "git.restore-worktree",
            Intent::UseAlternative,
            RESTORE_WORKTREE,
        )
    } else {
        ("git.restore-unstaged", Intent::UseAlternative, RESTORE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(line: &str) -> Option<&'static str> {
        let words: Vec<&str> = line.split_whitespace().collect();
        rule_for(words[0], &words[1..], &|_| false).map(|h| h.0)
    }

    #[test]
    fn long_option_abbreviations() {
        assert!(long("--forc", "--force"));
        assert!(long("--fo", "--force"));
        assert!(!long("--f", "--force"));
        assert!(!long("--force-with-lease", "--force"));
        assert!(long("--force=x", "--force"));
    }

    #[test]
    fn corpus_examples() {
        assert_eq!(hit("push --forc origin main"), Some("git.push-force"));
        assert_eq!(hit("push --force-with-lease origin main"), None);
        assert_eq!(hit("push origin +main"), Some("git.push-force"));
        assert_eq!(hit("push origin --de"), Some("git.push-delete"));
        assert_eq!(hit("push --mir origin"), Some("git.push-mirror"));
        assert_eq!(hit("checkout -b feature"), None);
        assert_eq!(hit("checkout --force main"), Some("git.checkout-force"));
        assert_eq!(
            hit("checkout -- file.txt"),
            Some("git.checkout-double-dash")
        );
        assert_eq!(hit("checkout HEAD -- f"), Some("git.checkout-ref-path"));
        assert_eq!(hit("checkout main other"), Some("git.checkout-ambiguous"));
        assert_eq!(hit("checkout ."), Some("git.checkout-double-dash"));
        assert_eq!(hit("checkout main"), None);
        assert_eq!(hit("reset --ha HEAD~1"), Some("git.reset-hard"));
        assert_eq!(hit("reset --soft HEAD~1"), None);
        assert_eq!(hit("clean -n -fd"), None);
        assert_eq!(hit("clean -ffdx"), Some("git.clean-force"));
        assert_eq!(hit("rm --force --cached f"), None);
        assert_eq!(hit("rm --no-force --force f"), Some("git.rm-force"));
        assert_eq!(hit("branch -aDtopic"), Some("git.branch-force-delete"));
        assert_eq!(hit("branch -d -F topic"), None);
        assert_eq!(hit("branch --force topic"), None);
        assert_eq!(hit("stash pop"), None);
        assert_eq!(hit("stash drop"), Some("git.stash-drop"));
        assert_eq!(hit("tag -abcd"), Some("git.tag-delete"));
        assert_eq!(hit("switch -Cfixup"), None);
        assert_eq!(hit("switch -f -C feature HEAD~1"), Some("git.switch-force"));
        assert_eq!(hit("restore --no-staged file.txt"), None);
        assert_eq!(
            hit("restore --no-staged -W file.txt"),
            Some("git.restore-worktree")
        );
        assert_eq!(
            hit("restore --source --help file.txt"),
            Some("git.restore-unstaged")
        );
        assert_eq!(hit("restore --staged ."), None);
        assert_eq!(
            hit("worktree remove -fa /tmp/wt"),
            Some("git.worktree-remove-force")
        );
        assert_eq!(hit("rebase --abor"), Some("git.rebase-abort"));
        assert_eq!(hit("reflog delete"), Some("git.reflog-delete"));
    }
}
