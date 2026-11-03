//! Interpreter one-liners and awk (cc-safety-net `interpreters.ts`,
//! `awk.ts`).
//!
//! Code an interpreter runs is text the shell cannot expand, so the guard
//! judges it heuristically:
//! - a native recursive delete of the root or home blocks everywhere;
//! - dangerous shell text (`rm -rf`, `git reset --hard`, ...) blocks when
//!   it can reach an execution call (strict: whenever a sink exists);
//! - with `paranoid_interpreters`, every one-liner blocks.

use crate::analyze::{command_name, Analyzer, Cx};
use crate::model::{Origin, Word};
use crate::verdict::{Finding, Intent};
use regex::Regex;
use std::sync::OnceLock;

const DANGEROUS: &str = "Interpreter code contains a dangerous command. Run the underlying command directly so it can be analyzed, or use the safer alternative for that command.";
const PARANOID: &str = "Interpreter one-liners are blocked by the active safety policy. Write the code to a script file and run it, or run the equivalent shell command directly.";
const AWK: &str = "Detected awk system(), pipe, or getline command with dynamic command that cannot be safely analyzed. Use a literal command or process the data without system(), pipes, or getline.";
const DYNAMIC_SOURCE: &str = "shell execution source cannot be verified safely. Use a literal command string or ask the user to run it manually.";

pub fn is_interpreter(name: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let python = RE.get_or_init(|| Regex::new(r"^python(?:[23](?:\.\d+)*)?$").expect("pattern"));
    python.is_match(name)
        || matches!(
            name,
            "node" | "nodejs" | "ruby" | "perl" | "php" | "deno" | "bun"
        )
}

pub fn is_awk(name: &str) -> bool {
    matches!(name, "awk" | "gawk" | "nawk" | "mawk")
}

/// The code a one-liner runs, if any: `(code, reads_stdin_program)`.
fn code_argument(name: &str, argv: &[Word]) -> (Option<String>, bool) {
    let (code_flags, value_flags, syntax_only): (&[&str], &[&str], &[&str]) = match name {
        n if n.starts_with("python") => (&["-c"], &["-W", "-X", "-m"], &[]),
        "node" | "nodejs" | "bun" | "deno" => (
            &["-e", "--eval", "-p", "--print"],
            &[
                "-C",
                "-r",
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "--conditions",
                "--inspect-port",
                "--title",
            ],
            &["-c", "--check"],
        ),
        "ruby" => (&["-e"], &["-C", "-E", "-F", "-I", "-r"], &["-c"]),
        "perl" => (&["-e", "-E"], &["-F", "-I", "-M", "-m"], &["-c"]),
        "php" => (&["-r"], &["-d", "-c"], &["-l"]),
        _ => (&[], &[], &[]),
    };
    let mut i = 1;
    let mut code = None;
    while i < argv.len() {
        let t = argv[i].text();
        if syntax_only.contains(&t) {
            return (None, false);
        }
        if t == "-" {
            return (code, true);
        }
        if !t.starts_with('-') {
            break;
        }
        if let Some(v) = t
            .strip_prefix("--eval=")
            .or_else(|| t.strip_prefix("--print="))
        {
            code = Some(v.to_string());
            i += 1;
            continue;
        }
        if code_flags.contains(&t) {
            code = argv.get(i + 1).map(|w| w.text().to_string());
            if name.starts_with("python") {
                return (code, false);
            }
            i += 2;
            continue;
        }
        if value_flags.contains(&t) {
            i += 2;
            continue;
        }
        // Clusters: python -uc CODE, perl -lne CODE, ruby -eCODE.
        if !t.starts_with("--") {
            let body = &t[1..];
            let code_letters: Vec<char> = code_flags
                .iter()
                .filter_map(|f| f.strip_prefix('-'))
                .filter(|f| f.len() == 1)
                .filter_map(|f| f.chars().next())
                .collect();
            if let Some(pos) = body.find(|c| code_letters.contains(&c)) {
                let rest = &body[pos + 1..];
                code = if rest.is_empty() {
                    argv.get(i + 1).map(|w| w.text().to_string())
                } else {
                    Some(rest.to_string())
                };
                i += if rest.is_empty() { 2 } else { 1 };
                if name.starts_with("python") {
                    return (code, false);
                }
                continue;
            }
        }
        i += 1;
    }
    let reads_stdin = i >= argv.len() && code.is_none();
    (code, reads_stdin)
}

pub fn check(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    let name = command_name(&argv[0]).unwrap_or_default();
    let (code, stdin_program) = code_argument(&name, argv);
    let code = match code {
        Some(code) => Some(code),
        None if stdin_program => cx.stdin_text.clone(),
        None => None,
    };
    // A program read from the network.
    if stdin_program && cx.stdin_text.is_none() {
        if let Some(producers) = &cx.pipe_in {
            if producers
                .iter()
                .any(|p| crate::rules::shells::is_remote_fetch(p))
            {
                an.rule(
                    cx,
                    Finding::deny(
                        "analysis.dynamic-shell-source",
                        Intent::StopAndExplain,
                        DYNAMIC_SOURCE,
                    ),
                );
                return;
            }
        }
    }
    let Some(code) = code else {
        return;
    };
    if an.policy.capabilities.paranoid_interpreters {
        an.rule(
            cx,
            Finding::deny(
                "interpreter.one-liner-paranoid",
                Intent::UseAlternative,
                PARANOID,
            ),
        );
    }
    if code.contains("$(") && code.contains("curl") {
        an.rule(
            cx,
            Finding::deny(
                "analysis.dynamic-shell-source",
                Intent::StopAndExplain,
                DYNAMIC_SOURCE,
            ),
        );
    }
    if dangerous_code(&code, an.policy.capabilities.fail_closed) {
        an.rule(
            cx,
            Finding::deny(
                "interpreter.dangerous-command",
                Intent::UseAlternative,
                DANGEROUS,
            ),
        );
    }
    crate::rules::secrets::check_code(an, cx, &code);
    let _ = depth;
}

/// cc-safety-net `containsDangerousCode`.
pub fn dangerous_code(code: &str, strict: bool) -> bool {
    let code = code.replace("\\\n", "");
    if native_root_or_home_delete(&code) {
        return true;
    }
    if crate::rules::text::danger_label(&code).is_none() {
        return false;
    }
    // Dangerous text outside string literals (bare code, comments).
    let stripped = strip_string_literals(&code);
    if crate::rules::text::danger_label(&stripped).is_some() {
        return true;
    }
    static SINK: OnceLock<Regex> = OnceLock::new();
    let sink = SINK.get_or_init(|| {
        Regex::new(r"(?i)`|%x|\b(system|exec|execsync|spawn|spawnsync|popen|subprocess|child_process|open3|eval|fork|qx)\b").expect("pattern")
    });
    if !sink.is_match(&code) {
        return false;
    }
    if strict {
        return true;
    }
    // Standard: a dangerous literal must reach an execution call.
    static CALL: OnceLock<Regex> = OnceLock::new();
    let call = CALL.get_or_init(|| {
        Regex::new(r#"(?is)\b(system|exec|execSync|spawn|spawnSync|popen|run|call|check_call|check_output|Popen|getoutput|getstatusoutput|qx)\s*\(?\s*\(?\s*(\[?\s*)?(f?r?["'`])"#).expect("pattern")
    });
    call.find_iter(&code).any(|m| {
        let tail = &code[m.start()..];
        let window: String = tail.chars().take(400).collect();
        crate::rules::text::danger_label(&window).is_some()
    }) || code.contains('`') && crate::rules::text::danger_label(&code).is_some()
}

fn strip_string_literals(code: &str) -> String {
    let mut out = String::new();
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            let quote = c;
            out.push(' ');
            while let Some(n) = chars.next() {
                if n == '\\' {
                    chars.next();
                    continue;
                }
                if n == quote {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// `shutil.rmtree('/')`, `fs.rmSync(os.homedir(), {recursive: true})`,
/// `FileUtils.rm_rf(Dir.home)`, `rmtree($ENV{HOME})`.
fn native_root_or_home_delete(code: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\b(rmtree|remove_tree|rm_rf|rm_r|remove_dir_all|remove_dir|remove_entry_secure|remove_entry|rmSync|rmdirSync|rm|rmdir)\s*\(")
            .expect("pattern")
    });
    re.captures_iter(code).any(|caps| {
        let func = caps.get(1).map_or("", |m| m.as_str());
        let open = caps.get(0).map_or(0, |m| m.end());
        let (first, rest) = call_arguments(&code[open..]);
        let needs_recursive = matches!(func, "rmSync" | "rmdirSync" | "rm" | "rmdir");
        if needs_recursive && !rest.contains("recursive") {
            return false;
        }
        let arg = first.trim();
        let literal = arg.trim_matches(|c| c == '\'' || c == '"' || c == '`');
        let root = matches!(literal, "/" | "/*" | "~" | "C:\\" | "C:/" | "C:\\\\");
        const HOME: &[&str] = &[
            "os.path.expanduser('~')",
            "os.path.expanduser(\"~\")",
            "Path.home()",
            "os.environ['HOME']",
            "os.environ[\"HOME\"]",
            "os.getenv('HOME')",
            "os.getenv(\"HOME\")",
            "$ENV{HOME}",
            "homedir()",
            "process.env.HOME",
            "Dir.home",
            "ENV['HOME']",
            "ENV[\"HOME\"]",
        ];
        root || HOME.iter().any(|h| arg.ends_with(h))
    })
}

/// Split the text after a call's `(` into its first argument and the
/// rest of the argument list, honoring nested brackets and quotes.
fn call_arguments(text: &str) -> (String, String) {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut first_end = None;
    for (i, c) in text.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth > 0 => depth -= 1,
            ')' => {
                let end = first_end.unwrap_or(i);
                return (text[..end].to_string(), text[end..i].to_string());
            }
            ',' if depth == 0 && first_end.is_none() => first_end = Some(i),
            _ => {}
        }
    }
    let end = first_end.unwrap_or(text.len());
    (text[..end].to_string(), text[end..].to_string())
}

/// awk `system()`, `| getline` and `print | "cmd"`.
pub fn awk(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    let mut program: Option<String> = None;
    let mut i = 1;
    while i < argv.len() {
        let t = argv[i].text();
        match t {
            "-f" | "--file" => return,
            "-e" | "--source" => {
                program = argv.get(i + 1).map(|w| w.text().to_string());
                break;
            }
            "-F" | "-v" | "--assign" | "--field-separator" => i += 2,
            "--" => {
                program = argv.get(i + 1).map(|w| w.text().to_string());
                break;
            }
            _ if t.starts_with('-') && t.len() > 1 => i += 1,
            _ => {
                program = Some(t.to_string());
                break;
            }
        }
    }
    let Some(program) = program else {
        return;
    };
    static CALL: OnceLock<Regex> = OnceLock::new();
    let call = CALL.get_or_init(|| {
        Regex::new(r#"\bsystem\s*\(([^()]*)\)|("[^"]*"|[A-Za-z_$][\w$]*)\s*\|\s*getline|\|\s*("[^"]*"|[A-Za-z_$][\w$]*)"#).expect("pattern")
    });
    for caps in call.captures_iter(&program) {
        let arg = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .map_or("", |m| m.as_str())
            .trim();
        let literal = arg.len() >= 2
            && arg.starts_with('"')
            && arg.ends_with('"')
            && !arg[1..arg.len() - 1].contains('"');
        if !literal || arg.contains('$') || arg.contains('`') || arg.contains("{}") {
            an.rule(
                cx,
                Finding::deny("awk.system-dynamic", Intent::StopAndExplain, AWK),
            );
            return;
        }
        an.nested(
            &arg[1..arg.len() - 1],
            cx.cwd.clone(),
            depth,
            Origin::Nested,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_code_examples() {
        assert!(dangerous_code("import os; os.system('rm -rf /')", false));
        assert!(dangerous_code(
            "import subprocess; subprocess.run('git reset --hard', shell=True)",
            false
        ));
        assert!(dangerous_code("import shutil; shutil.rmtree('/')", false));
        assert!(dangerous_code(
            "require('fs').rmSync(require('os').homedir(), {recursive: true, force: true})",
            false
        ));
        assert!(dangerous_code(
            "require 'fileutils'; FileUtils.rm_rf(Dir.home)",
            false
        ));
        assert!(!dangerous_code("print(1)", false));
        assert!(!dangerous_code("print(\"rm -rf /tmp/x\")", false));
        assert!(!dangerous_code(
            "import shutil; shutil.rmtree('dist')",
            false
        ));
        assert!(!dangerous_code(
            "require('fs').rmSync(require('os').homedir())",
            false
        ));
        assert!(dangerous_code("x = 1 # rm -rf /tmp/x", false));
    }
}
