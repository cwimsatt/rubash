//! Windows command processors reached from a POSIX shell: `cmd /c ...`
//! and `powershell`/`pwsh -Command ...` (cc-safety-net `cmd.ts`,
//! `powershell-wrapper.ts`, `powershell/remove-item.ts`).
//!
//! These run on Linux too (WSL interop, Git Bash habits), and they are the
//! native path on the Windows port, so the rules ship with the Linux build.

use crate::analyze::{command_name, Analyzer, Cx};
use crate::model::{Origin, Word};
use crate::targets::{classify, TargetClass};
use crate::verdict::{Finding, Intent};

const CMD_ROOT: &str = "cmd rmdir /s or del /s targeting root or home directory is extremely dangerous and always blocked.";
const CMD_ESCAPED: &str = "cmd rmdir /s or del /s with \\\" quoting or a \\\\?\\ path is blocked: cmd does not treat \\\" as an escape, so the target can split down to the root of the drive. Pass each path as its own quoted argument, or use Remove-Item -LiteralPath.";
const CMD_DYNAMIC: &str = "cmd rmdir /s or del /s target contains wildcards or variables that cannot be verified safely. Use literal paths within cwd.";
const CMD_HOME: &str =
    "cmd rmdir /s or del /s in home directory is dangerous. Change to a project directory first.";
const CMD_OUTSIDE: &str = "cmd rmdir /s or del /s outside cwd is blocked. Retry deleting only explicit paths inside the current directory; escalate for anything outside it.";
const CMD_PARANOID: &str = "cmd rmdir /s or del /s for non-temporary paths is blocked by the active safety policy. Retry deleting only explicit paths inside the current directory; escalate for anything outside it.";
const PS_ROOT: &str = "PowerShell Remove-Item targeting root or home directory is extremely dangerous and always blocked.";
const PS_DYNAMIC: &str = "PowerShell Remove-Item target contains variables or pipeline input that cannot be verified safely. Use literal paths within cwd.";
const PS_HOME: &str = "PowerShell Remove-Item -Recurse -Force in home directory is dangerous. Change to a project directory first.";
const PS_OUTSIDE: &str = "PowerShell Remove-Item -Recurse -Force outside cwd is blocked. Retry deleting only explicit paths inside the current directory; escalate for anything outside it.";
const PS_PARANOID: &str = "PowerShell Remove-Item -Recurse -Force for non-temporary paths is blocked by the active safety policy. Retry deleting only explicit paths inside the current directory; escalate for anything outside it.";
const PS_UNREAD: &str = "Recursive delete handed to powershell or pwsh in a form safebash does not read is blocked: pass the script as a single -Command with literal paths, after only -NoProfile, -NonInteractive, -NoLogo, or -ExecutionPolicy.";
const GIT_METADATA: &str =
    "Git metadata and hooks are protected. Ask the user before modifying them.";

fn dynamic_source(an: &Analyzer<'_>, cx: &Cx) {
    an.rule(
        cx,
        Finding::deny(
            "analysis.dynamic-shell-source",
            Intent::StopAndExplain,
            crate::rules::shells::DYNAMIC_SOURCE,
        ),
    );
}

/// A drive root (`C:`, `C:\`, `C:/`, `C:\*`) or a home spelling.
fn windows_root_or_home(target: &str) -> bool {
    let t = target.trim_matches('"').replace('\\', "/");
    let t = t
        .trim_end_matches('*')
        .trim_end_matches("*.")
        .trim_end_matches('/');
    let bytes = t.as_bytes();
    (bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || t.is_empty()
        || matches!(
            t.to_ascii_lowercase().as_str(),
            "%userprofile%"
                | "%homepath%"
                | "$home"
                | "${home}"
                | "$env:userprofile"
                | "$env:home"
                | "~"
        )
}

fn report_delete(an: &Analyzer<'_>, cx: &Cx, class: TargetClass, ps: bool) {
    let caps = an.policy.capabilities;
    let (rule, intent, reason): (&str, Intent, &str) = match (class, ps) {
        (TargetClass::RootOrHome, false) => (
            "cmd.recursive-delete-root-or-home",
            Intent::HardStop,
            CMD_ROOT,
        ),
        (TargetClass::RootOrHome, true) => (
            "powershell.remove-item-recursive-force-root-or-home",
            Intent::HardStop,
            PS_ROOT,
        ),
        (TargetClass::GitMetadata, false) => (
            "cmd.recursive-delete-git-metadata",
            Intent::HardStop,
            GIT_METADATA,
        ),
        (TargetClass::GitMetadata, true) => (
            "powershell.remove-item-git-metadata",
            Intent::HardStop,
            GIT_METADATA,
        ),
        (TargetClass::Dynamic, false) if caps.fail_closed => (
            "cmd.recursive-delete-dynamic-target",
            Intent::ScopeDown,
            CMD_DYNAMIC,
        ),
        (TargetClass::Dynamic, true) if caps.fail_closed => (
            "powershell.remove-item-recursive-force-dynamic-target",
            Intent::ScopeDown,
            PS_DYNAMIC,
        ),
        (TargetClass::HomeCwd, false) => {
            ("cmd.recursive-delete-home-cwd", Intent::ScopeDown, CMD_HOME)
        }
        (TargetClass::HomeCwd, true) => (
            "powershell.remove-item-recursive-force-home-cwd",
            Intent::ScopeDown,
            PS_HOME,
        ),
        (TargetClass::CwdSelf, false) => (
            "cmd.recursive-delete-cwd-self",
            Intent::ScopeDown,
            CMD_OUTSIDE,
        ),
        (TargetClass::CwdSelf, true) => (
            "powershell.remove-item-recursive-force-cwd-self",
            Intent::ScopeDown,
            PS_OUTSIDE,
        ),
        (TargetClass::Outside, false) => (
            "cmd.recursive-delete-outside-cwd",
            Intent::ScopeDown,
            CMD_OUTSIDE,
        ),
        (TargetClass::Outside, true) => (
            "powershell.remove-item-recursive-force-outside-cwd",
            Intent::ScopeDown,
            PS_OUTSIDE,
        ),
        (TargetClass::Within, false) if caps.paranoid_rm => (
            "cmd.recursive-delete-paranoid",
            Intent::ScopeDown,
            CMD_PARANOID,
        ),
        (TargetClass::Within, true) if caps.paranoid_rm => (
            "powershell.remove-item-recursive-force-paranoid",
            Intent::ScopeDown,
            PS_PARANOID,
        ),
        _ => return,
    };
    an.rule(cx, Finding::deny(rule, intent, reason));
}

/// Classify a Windows-spelled target with the shared ladder.
fn classify_windows(an: &Analyzer<'_>, cx: &Cx, target: &str) -> TargetClass {
    if windows_root_or_home(target) {
        return TargetClass::RootOrHome;
    }
    let cleaned = target.trim_matches('"').replace('\\', "/");
    if cleaned.contains(['%', '$', '*', '?']) {
        return TargetClass::Dynamic;
    }
    let bytes = cleaned.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && an.host.style == crate::paths::PathStyle::Posix {
        // A drive path from a POSIX workspace: never inside it.
        return TargetClass::Outside;
    }
    classify(an, cx, &Word::Lit(cleaned))
}

/// `cmd /c BODY`.
pub fn cmd(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    let Some(start) = argv.iter().position(|w| {
        matches!(
            w.text().to_ascii_lowercase().as_str(),
            "/c" | "/k" | "//c" | "//k"
        )
    }) else {
        return;
    };
    let mut body = argv[start + 1..]
        .iter()
        .map(Word::text)
        .collect::<Vec<_>>()
        .join(" ");
    if body.len() >= 2
        && ((body.starts_with('"') && body.ends_with('"'))
            || (body.starts_with('\'') && body.ends_with('\'')))
    {
        body = body[1..body.len() - 1].to_string();
    }
    let lower = body.to_ascii_lowercase();
    let mentions_recursive_delete = ["rmdir", "rd", "del", "erase"].iter().any(|v| {
        lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|t| t == *v)
    }) && lower
        .split_whitespace()
        .any(|t| t.starts_with('/') && t.split('/').any(|p| p.contains('s')));
    if mentions_recursive_delete
        && (body.contains("\\\"")
            || body.contains("\\\\?\\")
            || body.contains("//?/")
            || body.contains("\\\\.\\")
            || (an.host.style == crate::paths::PathStyle::Posix && body.contains('"')))
    {
        an.rule(
            cx,
            Finding::deny(
                "cmd.recursive-delete-escaped-quote",
                Intent::HardStop,
                CMD_ESCAPED,
            ),
        );
        return;
    }
    for piece in body.split(['&', '|']) {
        let tokens: Vec<&str> = piece.split_whitespace().collect();
        let Some(head) = tokens.first() else { continue };
        let head = head.trim_start_matches('@').to_ascii_lowercase();
        if matches!(head.as_str(), "rmdir" | "rd" | "del" | "erase") {
            let recursive = tokens[1..].iter().any(|t| {
                t.starts_with('/')
                    && t.split('/').any(|p| {
                        p.eq_ignore_ascii_case("s")
                            || (p.len() > 1
                                && p.to_ascii_lowercase().contains('s')
                                && p.chars().all(|c| c.is_ascii_alphabetic()))
                    })
            });
            if !recursive {
                continue;
            }
            for target in tokens[1..].iter().filter(|t| !t.starts_with('/')) {
                report_delete(an, cx, classify_windows(an, cx, target), false);
            }
            continue;
        }
        if matches!(head.as_str(), "if" | "for") {
            // `if exist X rmdir /s /q X`: judge the delete inside.
            if let Some(i) = tokens.iter().position(|t| {
                matches!(
                    t.to_ascii_lowercase().as_str(),
                    "rmdir" | "rd" | "del" | "erase"
                )
            }) {
                let inner = tokens[i..].join(" ");
                cmd(
                    an,
                    cx,
                    &[Word::lit("cmd"), Word::lit("/c"), Word::lit(inner)],
                    depth,
                );
            }
            continue;
        }
        an.nested(piece.trim(), cx.cwd.clone(), depth, Origin::Nested);
    }
    if (body.contains(['^', '%', '!'])
        || body.split_whitespace().any(|t| {
            matches!(
                t.to_ascii_lowercase().as_str(),
                "cd" | "chdir" | "pushd" | "popd"
            ) || t.to_ascii_lowercase().starts_with("cd..")
        }))
        && mentions_recursive_delete
    {
        dynamic_source(an, cx);
    }
}

/// `powershell`/`pwsh`: read only `[-NoProfile|-NonInteractive|-NoLogo|
/// -ExecutionPolicy v] -Command <literal words>`.
pub fn powershell(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    let words: Vec<&str> = argv[1..].iter().map(Word::text).collect();
    let encoded = words.iter().any(|w| {
        let flag = w
            .trim_start_matches(['-', '/', '\u{2013}', '\u{2014}'])
            .to_ascii_lowercase();
        w.len() > flag.len()
            && !flag.is_empty()
            && (flag == "ec"
                || ("encodedcommand".starts_with(&flag)
                    && flag.len() >= 2
                    && flag.starts_with('e')
                    && flag != "ex"
                    && flag != "exe"
                    && !"executionpolicy".starts_with(&flag)))
    });
    if encoded {
        dynamic_source(an, cx);
        return;
    }
    let mut i = 0;
    let readable = argv[1..].iter().all(Word::is_lit) && !words.contains(&"--%");
    while i < words.len() {
        match words[i].to_ascii_lowercase().as_str() {
            "-noprofile" | "-nop" | "-noninteractive" | "-noni" | "-nologo" => i += 1,
            "-executionpolicy" | "-ep" => i += 2,
            _ => break,
        }
    }
    let command_flag = words
        .get(i)
        .is_some_and(|w| matches!(w.to_ascii_lowercase().as_str(), "-command" | "-c"));
    if readable && command_flag {
        let script = words[i + 1..].join(" ");
        script_text(an, cx, &script, depth);
        return;
    }
    let joined = words.join(" ").to_ascii_lowercase();
    let delete_verb = ["remove-item", "ri", "rm", "rmdir", "rd", "del", "erase"]
        .iter()
        .any(|v| {
            joined
                .split(|c: char| c.is_whitespace() || c == ';')
                .any(|t| t == *v)
        });
    let recursive = joined.split_whitespace().any(|t| {
        t.starts_with("-r")
            || t.starts_with("--r")
            || t == "/s"
            || (t.starts_with('-')
                && t.contains('r')
                && t[1..].chars().all(|c| "dfipvwxr".contains(c)))
    });
    if delete_verb && recursive {
        an.rule(
            cx,
            Finding::deny(
                "powershell.nested-recursive-delete-unread",
                Intent::HardStop,
                PS_UNREAD,
            ),
        );
        return;
    }
    // Unknown shape: embedded commands are still analyzed by the caller's
    // suffix scan.
    for index in 1..argv.len() {
        if command_name(&argv[index]).is_some_and(|n| an.is_protectable(&n)) {
            an.command(&argv[index..], cx, depth);
            break;
        }
    }
}

/// A PowerShell script: statements split on `;`, `|` and newlines.
fn script_text(an: &Analyzer<'_>, cx: &Cx, script: &str, depth: usize) {
    let lower = script.to_ascii_lowercase();
    if (lower.contains("iex") || lower.contains("invoke-expression"))
        && (lower.contains("downloadstring")
            || lower.contains("downloaddata")
            || lower.contains("irm ")
            || lower.contains("iwr ")
            || lower.contains("invoke-restmethod")
            || lower.contains("invoke-webrequest"))
    {
        dynamic_source(an, cx);
        return;
    }
    let mut piped = false;
    for raw in script.split(['\n']) {
        for (index, statement) in raw.split(['|']).enumerate() {
            for part in statement.split(';') {
                let tokens = ps_tokens(part);
                if tokens.is_empty() {
                    continue;
                }
                let head = tokens[0]
                    .trim_start_matches(['&', '.'])
                    .to_ascii_lowercase();
                if matches!(
                    head.as_str(),
                    "remove-item" | "ri" | "del" | "erase" | "rd" | "rm" | "rmdir"
                ) {
                    remove_item(an, cx, &tokens[1..], piped || index > 0);
                } else {
                    let words: Vec<Word> = tokens.iter().map(|t| Word::lit(t.clone())).collect();
                    an.command(&words, cx, depth);
                }
            }
            piped = true;
        }
        piped = false;
    }
}

fn ps_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in text.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            None => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn remove_item(an: &Analyzer<'_>, cx: &Cx, args: &[String], piped: bool) {
    let mut recurse = false;
    let mut force = false;
    let mut targets: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let lower = a.to_ascii_lowercase();
        if let Some(param) = lower.strip_prefix('-') {
            let (name, inline) = param
                .split_once(':')
                .map_or((param, None), |(n, v)| (n, Some(v)));
            if "whatif".starts_with(name) && name.len() >= 2 && inline != Some("$false") {
                return;
            }
            if "recurse".starts_with(name) && !name.is_empty() {
                recurse = true;
            } else if "force".starts_with(name) && name.len() >= 2 {
                force = true;
            } else if ("path".starts_with(name) || "literalpath".starts_with(name))
                && !name.is_empty()
            {
                match inline {
                    Some(_) => targets.push(&a[a.find(':').map_or(a.len(), |p| p + 1)..]),
                    None => {
                        if let Some(v) = args.get(i + 1) {
                            targets.push(v);
                            i += 1;
                        }
                    }
                }
            }
            i += 1;
            continue;
        }
        targets.push(a);
        i += 1;
    }
    if targets.is_empty() {
        if piped
            && (recurse || an.policy.capabilities.fail_closed)
            && an.policy.capabilities.fail_closed
        {
            an.rule(
                cx,
                Finding::deny(
                    "powershell.remove-item-pipeline-dynamic-target",
                    Intent::ScopeDown,
                    PS_DYNAMIC,
                ),
            );
        }
        return;
    }
    for target in targets {
        let class = classify_windows(an, cx, target);
        if class == TargetClass::RootOrHome && !(recurse && force) {
            an.rule(
                cx,
                Finding::deny(
                    "powershell.remove-item-root-or-home",
                    Intent::HardStop,
                    PS_ROOT,
                ),
            );
            continue;
        }
        if class == TargetClass::GitMetadata {
            report_delete(an, cx, class, true);
            continue;
        }
        if recurse && force {
            report_delete(an, cx, class, true);
        }
    }
}
