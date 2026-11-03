//! `xargs` and GNU `parallel` (cc-safety-net `xargs.ts`, `parallel.ts`).
//!
//! These tools execute a child command with arguments that arrive at run
//! time from stdin, so even safebash's run-time gate never sees the final
//! argv of the child (the tool, not the shell, spawns it). The child is
//! therefore judged statically with "dynamic input" provenance: anything
//! the input could turn into executable source or into `rm -rf` targets
//! is blocked.

use super::rm::is_recursive_force;
use crate::analyze::{command_name, Analyzer, Cx};
use crate::model::{Origin, Word};
use crate::verdict::{Finding, Intent};

const XARGS_RM: &str =
    "xargs rm -rf with dynamic input is dangerous. Use explicit file list instead.";
const XARGS_SHELL: &str = "xargs dynamic input can supply arbitrary executable command source. Use an explicit child command and arguments instead.";
const PARALLEL_RM: &str =
    "parallel rm -rf with dynamic input is dangerous. Use explicit file list instead.";
const PARALLEL_SHELL: &str = "parallel with shell -c can execute arbitrary commands from dynamic input. Run the inner command directly on an explicit file list instead.";
const PARALLEL_STREAM: &str = "parallel without a command reads executable commands from dynamic input. Use an explicit command template or ::: arguments instead.";
const PARALLEL_UNSUPPORTED: &str = "parallel command construction cannot be verified safely. Use the default ::: separator, literal arguments, and built-in replacement strings.";

pub fn xargs(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    const VALUE_SHORT: &[&str] = &[
        "-L", "-n", "-P", "-s", "-a", "-E", "-R", "-S", "-e", "-d", "-J",
    ];
    const VALUE_LONG: &[&str] = &[
        "--max-args",
        "--max-procs",
        "--max-chars",
        "--arg-file",
        "--eof",
        "--delimiter",
        "--max-lines",
        "--process-slot-var",
    ];
    let mut replace: Option<String> = None;
    let mut i = 1;
    while let Some(word) = argv.get(i) {
        let t = word.text();
        if t == "--" {
            i += 1;
            break;
        }
        if !t.starts_with('-') || t == "-" {
            break;
        }
        if t == "-I" || t == "-J" {
            replace = argv.get(i + 1).map(|w| w.text().to_string());
            i += 2;
            continue;
        }
        if t == "-i" || t == "--replace" {
            replace = Some("{}".into());
        } else if let Some(r) = t.strip_prefix("--replace=") {
            replace = Some(r.to_string());
        } else if let Some(r) = t.strip_prefix("-I").or_else(|| t.strip_prefix("-J")) {
            replace = Some(r.to_string());
        } else if VALUE_SHORT.contains(&t) || VALUE_LONG.contains(&t) {
            i += 1;
        }
        i += 1;
    }
    let child = &argv[i.min(argv.len())..];
    if child.is_empty() {
        return;
    }
    let Some(verdict) = child_verdict(an, cx, child, replace.as_deref(), depth, Tool::Xargs) else {
        return;
    };
    an.rule(cx, verdict);
}

#[derive(Clone, Copy, PartialEq)]
enum Tool {
    Xargs,
    Parallel,
}

impl Tool {
    fn rm(self) -> Finding {
        match self {
            Tool::Xargs => Finding::deny(
                "xargs.rm-recursive-force-dynamic",
                Intent::ScopeDown,
                XARGS_RM,
            ),
            Tool::Parallel => Finding::deny(
                "parallel.rm-recursive-force-dynamic",
                Intent::ScopeDown,
                PARALLEL_RM,
            ),
        }
    }

    fn shell(self) -> Finding {
        match self {
            Tool::Xargs => Finding::deny("xargs.shell-dynamic", Intent::ScopeDown, XARGS_SHELL),
            Tool::Parallel => {
                Finding::deny("parallel.shell-dynamic", Intent::ScopeDown, PARALLEL_SHELL)
            }
        }
    }
}

/// Judge a child that receives dynamic input; `None` when the child is
/// safe (after analyzing it as a command of its own).
fn child_verdict(
    an: &Analyzer<'_>,
    cx: &Cx,
    child: &[Word],
    replace: Option<&str>,
    depth: usize,
    tool: Tool,
) -> Option<Finding> {
    let token = replace.unwrap_or("{}");
    let appended = replace.is_none();
    let uses_token = |w: &Word| w.text().contains(token);
    let head = &child[0];
    if uses_token(head) || !head.is_lit() {
        return Some(tool.shell());
    }
    let name = command_name(head)?;
    // A wrapper with nothing after it: the input becomes the command.
    if matches!(
        name.as_str(),
        "sudo"
            | "env"
            | "nice"
            | "nohup"
            | "timeout"
            | "command"
            | "builtin"
            | "exec"
            | "busybox"
            | "doas"
            | "stdbuf"
            | "setsid"
    ) {
        let rest: Vec<&Word> = child[1..]
            .iter()
            .filter(|w| !w.text().starts_with('-'))
            .collect();
        if rest.is_empty() || rest.iter().all(|w| uses_token(w)) {
            return Some(tool.shell());
        }
        let mut peeled = child[1..].to_vec();
        while peeled.first().is_some_and(|w| {
            w.text().starts_with('-') || w.text().chars().all(|c| c.is_ascii_digit())
        }) {
            peeled.remove(0);
        }
        if peeled.is_empty() {
            return Some(tool.shell());
        }
        return child_verdict(an, cx, &peeled, replace, depth, tool);
    }
    if name == "rm" || name == "rmdir" {
        let option_token = child[1..]
            .iter()
            .any(|w| w.text().starts_with('-') && uses_token(w));
        if (is_recursive_force(child) && (appended || child.iter().any(uses_token))) || option_token
        {
            return Some(tool.rm());
        }
    }
    if crate::rules::shells::is_shell(&name, an) {
        let c_index = child.iter().position(|w| {
            w.text() == "-c"
                || (w.text().starts_with('-')
                    && !w.text().starts_with("--")
                    && w.text().contains('c'))
        });
        match c_index.and_then(|i| child.get(i + 1)) {
            Some(body) => {
                let text = body.text();
                if text.contains(token) && an.policy.capabilities.fail_closed {
                    return Some(tool.shell());
                }
                if text.trim_start().starts_with(token)
                    || text.contains("$1")
                    || text.contains("$@")
                    || text.contains("$*")
                    || text.contains("eval")
                    || text.contains("source ")
                    || text.contains(&format!("; {token}"))
                    || text.contains(&format!("&& {token}"))
                {
                    return Some(tool.shell());
                }
                // Worst case: the input is `/`.
                let worst = text.replace(token, "/");
                an.nested(&worst, cx.cwd.clone(), depth, Origin::Nested);
                if text.contains(token) && rm_rf_mentions(&worst) {
                    return Some(tool.shell());
                }
                return None;
            }
            None => return Some(tool.shell()),
        }
    }
    // An interpreter whose program would come from the input runs it. With
    // a literal `-c`/`-e` body already present, appended input is argv
    // (safe); with none, appended input becomes the script to run.
    if crate::rules::interp::is_interpreter(&name) {
        let code_literal = child.windows(2).any(|pair| {
            matches!(
                pair[0].text(),
                "-e" | "-c" | "-p" | "--eval" | "--print" | "-r"
            ) && pair[1].is_lit()
        });
        if child.iter().skip(1).any(uses_token) || (appended && !code_literal) {
            return Some(tool.shell());
        }
    }
    // awk: appended input is data file names (safe), but a program drawn
    // from the input (`-f {}`, `--source {}`, or the program word itself
    // being the token) runs it.
    if crate::rules::interp::is_awk(&name) {
        let program_from_token = child.windows(2).any(|pair| {
            matches!(pair[0].text(), "-f" | "--file" | "-e" | "--source") && uses_token(&pair[1])
        }) || child
            .iter()
            .skip(1)
            .find(|w| !w.text().starts_with('-'))
            .is_some_and(&uses_token);
        if program_from_token {
            return Some(tool.shell());
        }
    }
    if name == "eval" || name == "source" || name == "." {
        return Some(tool.shell());
    }
    if name == "find" && (appended || child.iter().skip(1).any(uses_token)) {
        return Some(tool.shell());
    }
    if name == "git" {
        let sub = child.iter().skip(1).find(|w| !w.text().starts_with('-'));
        match sub {
            None if appended => return Some(tool.shell()),
            Some(sub) if uses_token(sub) => return Some(tool.shell()),
            _ => {}
        }
    }
    // A static child is judged by its own rules.
    let mut child_cx = cx.clone();
    child_cx.dynamic_input = true;
    child_cx.pipe_in = None;
    an.command_without_argv_rules(child, &child_cx, depth);
    None
}

fn rm_rf_mentions(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("rm -rf") || lower.contains("rm -fr") || lower.contains("rm -r ")
}

pub fn parallel(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    if argv.len() == 2 && matches!(argv[1].text(), "--version" | "--help") {
        return;
    }
    if cx
        .env_value("PARALLEL")
        .is_some_and(|v| !v.text().is_empty())
    {
        an.rule(
            cx,
            Finding::deny(
                "parallel.command-stream-dynamic",
                Intent::ScopeDown,
                PARALLEL_UNSUPPORTED,
            ),
        );
        return;
    }
    const VALUE_OPTS: &[&str] = &[
        "-j",
        "--jobs",
        "-N",
        "--max-args",
        "-n",
        "--timeout",
        "--delay",
        "--joblog",
        "--results",
        "--tmpdir",
        "--tag-string",
        "--halt",
        "--retries",
        "-S",
        "--sshlogin",
        "--slf",
        "--sshloginfile",
        "--memfree",
        "--load",
        "--nice",
        "--block",
        "--blocksize",
    ];
    const UNSUPPORTED: &[&str] = &[
        "::::",
        "::::+",
        ":::+",
        "-a",
        "--arg-file",
        "--colsep",
        "--rpl",
        "--arg-sep",
        "--arg-file-sep",
        "--env",
        "--workdir",
        "--wd",
        "--replace",
        "-i",
    ];
    let mut i = 1;
    let mut quote = false;
    let mut dry_run = false;
    while let Some(w) = argv.get(i) {
        let t = w.text();
        if t == ":::" || !t.starts_with('-') {
            break;
        }
        if UNSUPPORTED.contains(&t) || t.starts_with("--env=") || t.starts_with("--workdir=") {
            an.rule(
                cx,
                Finding::deny(
                    "parallel.command-stream-dynamic",
                    Intent::ScopeDown,
                    PARALLEL_UNSUPPORTED,
                ),
            );
            return;
        }
        if t == "-q" || t == "--quote" {
            quote = true;
        }
        if t == "--dry-run" {
            dry_run = true;
        }
        if t == "-I" {
            if argv.get(i + 1).map(|w| w.text()) != Some("{}") {
                an.rule(
                    cx,
                    Finding::deny(
                        "parallel.command-stream-dynamic",
                        Intent::ScopeDown,
                        PARALLEL_UNSUPPORTED,
                    ),
                );
                return;
            }
            i += 1;
        } else if VALUE_OPTS.contains(&t) {
            i += 1;
        }
        i += 1;
    }
    let rest = &argv[i.min(argv.len())..];
    let sep = rest.iter().position(|w| w.text() == ":::");
    if rest
        .iter()
        .any(|w| matches!(w.text(), "::::" | "::::+" | ":::+"))
        || rest.iter().filter(|w| w.text() == ":::").count() > 1
    {
        an.rule(
            cx,
            Finding::deny(
                "parallel.command-stream-dynamic",
                Intent::ScopeDown,
                PARALLEL_UNSUPPORTED,
            ),
        );
        return;
    }
    let template = &rest[..sep.unwrap_or(rest.len())];
    let jobs: Vec<&Word> = sep
        .map(|s| rest[s + 1..].iter().collect())
        .unwrap_or_default();
    if dry_run {
        return;
    }
    if template.is_empty() {
        if jobs.is_empty() {
            an.rule(
                cx,
                Finding::deny(
                    "parallel.command-stream-dynamic",
                    Intent::ScopeDown,
                    PARALLEL_STREAM,
                ),
            );
            return;
        }
        // Each argument is a whole command.
        for job in jobs {
            an.nested(job.text(), cx.cwd.clone(), depth, Origin::Nested);
        }
        return;
    }
    if jobs.is_empty() {
        // Arguments come from stdin.
        if let Some(verdict) = child_verdict(an, cx, template, Some("{}"), depth, Tool::Parallel) {
            an.rule(cx, verdict);
        }
        return;
    }
    let shell_c = template
        .first()
        .and_then(command_name)
        .is_some_and(|n| crate::rules::shells::is_shell(&n, an))
        && template.iter().any(|w| w.text() == "-c");
    if shell_c && !quote && template.iter().any(|w| w.text() == "{}") {
        an.rule(
            cx,
            Finding::deny("parallel.shell-dynamic", Intent::ScopeDown, PARALLEL_SHELL),
        );
        return;
    }
    // Expand the template per job and analyze each concrete command.
    for job in jobs {
        let value = job.text();
        let mut concrete: Vec<Word> = template
            .iter()
            .map(|w| {
                let text = w.text().replace("{}", value).replace("{1}", value);
                if w.is_lit() {
                    Word::Lit(text)
                } else {
                    w.clone()
                }
            })
            .collect();
        if !template.iter().any(|w| w.text().contains('{')) {
            concrete.push(job.clone());
        }
        let mut child_cx = cx.clone();
        child_cx.pipe_in = None;
        an.command_without_argv_rules(&concrete, &child_cx, depth);
    }
}
