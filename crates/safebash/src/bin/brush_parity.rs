//! safebash keystone A1: the offline two-parser comparison utility
//! (DESIGN.md Section 7).
//!
//! Feeds a corpus of command lines through BOTH `RubashParser` (the live
//! parser) and `BrushParser` (the candidate), projects each resulting guard
//! `Script` to a scope-number-independent summary, and reports where they
//! agree and where they diverge. It is OFF the live enforcement path: it
//! installs no guard and runs nothing it parses.
//!
//! Usage: `brush_parity [corpus-file]`. A corpus file holds one command line
//! per line; blank lines and lines beginning with `#` are skipped. The
//! built-in corpus is always included and covers the DESIGN's known cases.
//!
//! The summary deliberately omits scope index numbers (an arbitrary artifact
//! of allocation order) and compares the semantic shape of each command site:
//! function ownership, pipeline position, origin, words, assignments,
//! redirections and here-text, plus the parse-error flag. A divergence here is
//! a real difference in what the guard would analyze.

use safebash::brush_convert::BrushParser;
use safebash::convert::RubashParser;
use safebash_guard::model::{Arg, Script, ScriptParser};

fn summarize(script: &Script) -> String {
    let mut out = String::new();
    out.push_str(&format!("parse_error={}\n", script.parse_error.is_some()));
    for (index, site) in script.sites.iter().enumerate() {
        let command = &site.command;
        let words: Vec<&str> = command.words.iter().map(Arg::text).collect();
        let assigns: Vec<String> = command
            .assignments
            .iter()
            .map(|(name, value)| format!("{name}={}", value.text()))
            .collect();
        let redirs: Vec<String> = command
            .redirects
            .iter()
            .map(|r| {
                let fd = r.fd.map(|f| f.to_string()).unwrap_or_else(|| "-".to_string());
                format!("{:?}:fd{fd}:{}", r.access, r.target.text())
            })
            .collect();
        let pipeline = site
            .pipeline
            .as_ref()
            .map(|p| p.index as isize)
            .unwrap_or(-1);
        out.push_str(&format!(
            "site{index} fn={:?} pl={pipeline} origin={:?} words={:?} assigns={:?} redirs={:?} stdin={:?}\n",
            site.function, site.origin, words, assigns, redirs, command.stdin_text,
        ));
    }
    out
}

/// The built-in corpus: the DESIGN's known cases plus ordinary shell forms.
fn corpus() -> Vec<&'static str> {
    vec![
        // Round-2 finding 1: suffix assignment-shaped arguments.
        "echo x=y",
        "bash -c 'rm -rf \"$1\"' tag=value /",
        "declare x=1",
        "export PATH=/usr/bin",
        "FOO=bar rm -rf /tmp/x",
        // Round-3 finding 2 (class II): variable-named descriptor allocation.
        "bash {log}>trace.log -c 'rm -rf /'",
        "exec {fd}</dev/null",
        // Class I: constructs brush rejects (parse error).
        "for x in a b; { echo $x; }",
        "select x in a b; do echo $x; done",
        // Round-1 finding 3 / round-3 finding 1: process substitution.
        "cat <(printf hi) value",
        "diff <(ls) <(ls -a)",
        "tee >(cat) < in.txt",
        // Ordinary forms.
        "cd /tmp && rm -rf x | cat; echo hi",
        "ls | grep foo | wc -l",
        "git push -f origin main",
        "cat > out.txt 2>&1 < in.txt",
        "echo hi >> log.txt",
        "rm -rf \"$HOME/x\" '/a b'",
        "if true; then rm -rf /tmp/z; fi",
        "f() { rm -rf /; }",
        "while read x; do echo $x; done",
        "for i in 1 2 3; do echo $i; done",
        "case $x in a) echo a ;; esac",
        "(( x = 1 + 2 ))",
        "[[ -f $x ]]",
        "true & echo bg",
        "bash -c 'echo hi'",
        ": > file",
        "bash <<'EOF'\nrm -rf ~\nEOF\n",
    ]
}

fn main() {
    let rubash = RubashParser { posix: false };
    let brush = BrushParser { posix: false };

    let mut lines: Vec<String> = corpus().into_iter().map(String::from).collect();
    if let Some(path) = std::env::args().nth(1) {
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for line in text.lines() {
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if trimmed.trim().is_empty() || trimmed.trim_start().starts_with('#') {
                        continue;
                    }
                    lines.push(trimmed.to_string());
                }
            }
            Err(error) => {
                eprintln!("cannot read corpus file {path}: {error}");
                std::process::exit(2);
            }
        }
    }

    println!("# safebash A1 two-parser comparison (rubash vs brush), offline parity utility");
    println!("# cases: {}", lines.len());

    let mut agree = 0usize;
    let mut diverge = 0usize;
    for line in &lines {
        let rubash_summary = summarize(&rubash.parse(line));
        let brush_summary = summarize(&brush.parse(line));
        let shown = line.replace('\n', "\\n");
        if rubash_summary == brush_summary {
            agree += 1;
            println!("\nAGREE    | {shown}");
        } else {
            diverge += 1;
            println!("\nDIVERGE  | {shown}");
            println!("  --- rubash ---");
            for l in rubash_summary.lines() {
                println!("    {l}");
            }
            println!("  --- brush ---");
            for l in brush_summary.lines() {
                println!("    {l}");
            }
        }
    }

    println!(
        "\n# summary: {} cases, {agree} agree, {diverge} diverge",
        lines.len()
    );
}
