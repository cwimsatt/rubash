//! False-positive guard: brush's bash-compatibility corpus is ordinary
//! shell, so safebash must not block it. Every `stdin` script from
//! `brush-shell/tests/cases/compat/**` (extracted into
//! `tests/data/brush-compat-scripts.jsonl`, MIT, (c) 2024 reuben olinsky)
//! is run through static analysis in a scratch workspace. The test fails
//! if the block rate rises above a ceiling, and records every blocked
//! script so a new false positive is visible.
//!
//! A handful of scripts legitimately trip a rule (they delete the current
//! directory, write to a device, or run a recursive delete) — those are
//! allowed by the ceiling, not whitelisted, and listed in the artifact.

mod common;

use common::Tree;
use safebash_guard::policy::Level;
use std::collections::BTreeMap;

/// At most this fraction of the corpus may block. The corpus holds no
/// `rm -rf`, curl, or `curl | sh`, so almost everything should pass;
/// raise the ceiling only with evidence, never to silence a regression.
const CEILING: f64 = 0.03;

#[test]
fn brush_compat_corpus_is_not_over_blocked() {
    let tree = Tree::new("brush-compat");
    let guard = tree.guard(&tree.workspace, Level::Standard);
    let data = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/brush-compat-scripts.jsonl"
    ))
    .unwrap();
    let mut total = 0usize;
    let mut blocked: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in data.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let script = row["script"].as_str().unwrap();
        total += 1;
        let report = guard.analyze_source(script, Some(&tree.workspace));
        if let Some(finding) = report.primary() {
            let where_ = format!(
                "{}::{}",
                row["file"].as_str().unwrap_or(""),
                row["name"].as_str().unwrap_or("")
            );
            blocked
                .entry(finding.rule.to_string())
                .or_default()
                .push(where_);
        }
    }
    let rate = blocked.values().map(Vec::len).sum::<usize>() as f64 / total as f64;
    let mut report = format!("{total} scripts, {:.2}% blocked\n", rate * 100.0);
    for (rule, cases) in &blocked {
        report.push_str(&format!("  {:4}  {rule}\n", cases.len()));
        for case in cases.iter().take(4) {
            report.push_str(&format!("          {case}\n"));
        }
    }
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("brush-compat-blocks.txt");
    std::fs::write(&out, &report).unwrap();
    println!("{report}");
    assert!(
        rate <= CEILING,
        "block rate {:.3} over ceiling {CEILING}\n{report}",
        rate
    );
}
