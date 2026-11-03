//! Shells, `eval`, `source` and `trap`: code handed to a shell is analyzed
//! as a nested script (cc-safety-net `shell-wrappers.ts`,
//! `shell-execution.ts`).
//!
//! Where cc-safety-net must fail closed on a dynamic source (it never sees
//! the value), safebash defers in standard mode: `eval "$x"`, `source
//! "$f"` and the commands they produce run through the same executor and
//! pass the run-time gate one by one, and a nested `bash -c "$x"` is
//! checked at spawn time with the concrete string. Strict mode still
//! denies them up front.

use crate::analyze::{command_name, shell_quote, Analyzer, Cx, Stage};
use crate::model::{Origin, Word};
use crate::verdict::{Finding, Intent};

pub const DYNAMIC_SOURCE: &str = "shell execution source cannot be verified safely. Use a literal command string or ask the user to run it manually.";
const FETCHERS: &[&str] = &[
    "curl", "wget", "fetch", "aria2c", "http", "https", "xh", "xhs", "nc", "ncat", "netcat",
];
const MAX_SCRIPT_BYTES: u64 = 256 * 1024;

pub fn is_shell(name: &str, an: &Analyzer<'_>) -> bool {
    matches!(
        name,
        "bash"
            | "sh"
            | "zsh"
            | "ksh"
            | "dash"
            | "fish"
            | "csh"
            | "tcsh"
            | "ash"
            | "mksh"
            | "rubash"
    ) || an.host.self_names.iter().any(|n| n == name)
}

/// A producer that downloads content (possibly behind wrappers).
pub fn is_remote_fetch(producer: &[Word]) -> bool {
    producer
        .iter()
        .filter_map(command_name)
        .take(4)
        .any(|n| FETCHERS.contains(&n.as_str()))
}

fn dynamic_source(an: &Analyzer<'_>, cx: &Cx) {
    an.rule(
        cx,
        Finding::deny(
            "analysis.dynamic-shell-source",
            Intent::StopAndExplain,
            DYNAMIC_SOURCE,
        ),
    );
}

/// Static analysis cannot know a source: deny when failing closed,
/// otherwise leave it to the run-time gate.
fn defer_or_deny(an: &Analyzer<'_>, cx: &Cx) {
    if an.policy.capabilities.fail_closed && !an.runtime {
        dynamic_source(an, cx);
    }
}

/// `bash [opts] -c SCRIPT [name args...]`, `bash FILE`, or a shell reading
/// its program from stdin.
pub fn shell(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    // Startup files named by the environment.
    for var in ["BASH_ENV", "ENV"] {
        if let Some(value) = cx.env_value(var) {
            match value.as_lit() {
                Some(path) if !path.is_empty() => script_file(an, cx, path, depth),
                Some(_) => {}
                None => dynamic_source(an, cx),
            }
        }
    }
    let mut i = 1;
    let mut command: Option<usize> = None;
    let mut syntax_only = false;
    while i < argv.len() {
        let w = &argv[i];
        let Some(t) = w.as_lit() else { break };
        if t == "--" || t == "-" {
            i += 1;
            break;
        }
        if t.starts_with("--") {
            if matches!(t, "--rcfile" | "--init-file") {
                match argv.get(i + 1).and_then(Word::as_lit) {
                    Some(path) => script_file(an, cx, path, depth),
                    None => dynamic_source(an, cx),
                }
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if !(t.starts_with('-') || t.starts_with('+')) || t.len() < 2 {
            break;
        }
        let letters = &t[1..];
        if letters.chars().all(|c| c == 'n' || c == 'c') && letters.contains('n') {
            syntax_only = true;
        }
        let mut takes_value = false;
        for c in letters.chars() {
            match c {
                'c' => command = Some(i),
                'o' | 'O' => takes_value = true,
                _ => {}
            }
        }
        i += if takes_value { 2 } else { 1 };
        if command.is_some() {
            break;
        }
    }
    if syntax_only {
        return;
    }
    if let Some(c_index) = command {
        let Some(script) = argv.get(i).or_else(|| argv.get(c_index + 1)) else {
            dynamic_source(an, cx);
            return;
        };
        let text = script.text();
        if text.starts_with('-') && script.is_lit() {
            // `bash -c -x '...'`: the command string cannot be identified.
            dynamic_source(an, cx);
            return;
        }
        let positional: Vec<&Word> = argv[(i + 1).min(argv.len())..].iter().collect();
        match script {
            Word::Lit(body) => {
                let bound = bind_positionals(body, &positional);
                match bound {
                    Some(body) => an.nested(&body, cx.cwd.clone(), depth, Origin::Nested),
                    None => {
                        an.nested(body, cx.cwd.clone(), depth, Origin::Nested);
                        defer_or_deny(an, cx);
                    }
                }
            }
            _ => {
                if crate::words::substitution_bodies(text).iter().any(|b| {
                    b.split_whitespace()
                        .next()
                        .is_some_and(|h| FETCHERS.contains(&h))
                }) {
                    dynamic_source(an, cx);
                    return;
                }
                defer_or_deny(an, cx);
            }
        }
        return;
    }
    // A script operand.
    if let Some(script) = argv.get(i) {
        match script.as_lit() {
            Some(path) => script_file(an, cx, path, depth),
            None => defer_or_deny(an, cx),
        }
        return;
    }
    // The program comes from stdin.
    if let Some(text) = &cx.stdin_text {
        an.nested(text, cx.cwd.clone(), depth, Origin::Nested);
        return;
    }
    if let Some(producers) = &cx.pipe_in {
        let last = producers.last().map(Vec::as_slice).unwrap_or(&[]);
        if producers.iter().any(|p| is_remote_fetch(p)) {
            dynamic_source(an, cx);
            return;
        }
        if let Some(output) = literal_printf_output(last) {
            an.nested(&output, cx.cwd.clone(), depth, Origin::Nested);
            return;
        }
        dynamic_source(an, cx);
        return;
    }
    if cx.stdin_file {
        dynamic_source(an, cx);
    }
}

/// `echo 'cmd' | sh`, `printf 'cmd\n' | sh`: the literal text the producer
/// writes.
fn literal_printf_output(producer: &[Word]) -> Option<String> {
    let name = producer.first().and_then(command_name)?;
    let args: Vec<&str> = producer[1..]
        .iter()
        .map(|w| w.as_lit())
        .collect::<Option<_>>()?;
    match name.as_str() {
        "echo" => Some(
            args.iter()
                .filter(|a| !a.starts_with('-'))
                .copied()
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "printf" => args.first().map(|f| f.replace("\\n", "\n")),
        _ => None,
    }
}

/// Substitute literal positional parameters into a `-c` body (`sh -c 'rm
/// -rf "$1"' _ /`). `None` when the body uses a positional that is
/// dynamic or missing.
fn bind_positionals(body: &str, positional: &[&Word]) -> Option<String> {
    if !body.contains('$') {
        return Some(body.to_string());
    }
    let mut out = body.to_string();
    // positional[0] is $0; $1.. follow.
    let args: Vec<&Word> = positional.iter().skip(1).copied().collect();
    let uses_all = out.contains("$@") || out.contains("$*");
    if uses_all {
        let joined = args
            .iter()
            .map(|w| w.as_lit().map(shell_quote))
            .collect::<Option<Vec<_>>>()?
            .join(" ");
        out = out
            .replace("\"$@\"", &joined)
            .replace("$@", &joined)
            .replace("\"$*\"", &joined)
            .replace("$*", &joined);
    }
    for n in (1..=9).rev() {
        let names = [
            format!("\"${{{n}}}\""),
            format!("\"${n}\""),
            format!("${{{n}}}"),
            format!("${n}"),
        ];
        if names.iter().any(|name| out.contains(name.as_str())) {
            let value = args.get(n - 1).and_then(|w| w.as_lit())?;
            let quoted = shell_quote(value);
            for name in &names {
                out = out.replace(name.as_str(), &quoted);
            }
        }
    }
    Some(out)
}

/// Analyze a script file from disk. Only concrete findings count: uncertain
/// ones (`analysis.*`, `raw-text.*`, `*dynamic*`, paranoid one-liners) are
/// dropped, and the reason names the file.
pub fn script_file(an: &Analyzer<'_>, cx: &Cx, path: &str, depth: usize) {
    let Some(resolved) = an.host.norm(path, cx.cwd.as_ref()) else {
        return;
    };
    let file = std::path::Path::new(resolved.as_str());
    let Ok(meta) = std::fs::metadata(file) else {
        return;
    };
    if !meta.is_file() || meta.len() > MAX_SCRIPT_BYTES {
        return;
    }
    let Ok(bytes) = std::fs::read(file) else {
        return;
    };
    if bytes.contains(&0) {
        return;
    }
    let text = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
    if let Some(first) = text.lines().next() {
        if first.starts_with("#!")
            && !["sh", "bash", "dash", "zsh", "ksh", "safebash", "rubash"]
                .iter()
                .any(|s| first.contains(s))
        {
            return;
        }
    }
    let before = an.findings_len();
    an.nested(&text, cx.cwd.clone(), depth, Origin::Nested);
    an.retain_concrete_since(before, path);
}

pub fn eval(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    let args = &argv[1..];
    if args.iter().all(Word::is_lit) {
        let text = args.iter().map(Word::text).collect::<Vec<_>>().join(" ");
        an.nested(&text, cx.cwd.clone(), depth, Origin::Nested);
        return;
    }
    // `eval "$(ssh-agent -s)"`: the generator was analyzed as a
    // substitution already; the generated text runs through the gate.
    defer_or_deny(an, cx);
}

pub fn trap(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    let mut i = 1;
    while argv
        .get(i)
        .is_some_and(|w| matches!(w.text(), "--" | "-p" | "-l" | "-P"))
    {
        i += 1;
    }
    match argv.get(i) {
        Some(Word::Lit(action)) if argv.len() > i + 1 => {
            an.nested(action, cx.cwd.clone(), depth, Origin::Nested)
        }
        Some(Word::Lit(_)) | None => {}
        Some(_) => defer_or_deny(an, cx),
    }
}

pub fn source(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    let mut i = 1;
    if argv.get(i).map(Word::text) == Some("--") {
        i += 1;
    }
    if argv.get(i).map(Word::text) == Some("-p") {
        i += 2;
    }
    match argv.get(i) {
        Some(Word::Lit(path)) => script_file(an, cx, path, depth),
        Some(_) => defer_or_deny(an, cx),
        None => {}
    }
    let _ = Stage::Rule;
}
