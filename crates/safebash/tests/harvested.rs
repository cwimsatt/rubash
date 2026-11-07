//! Cross-check against cc-safety-net's harvested verdict corpus.
//!
//! Every literal of `tests/data/ccsn-harvested-verdicts.jsonl` is analyzed
//! by safebash's static (preflight) layer in an equivalent fixture tree and
//! compared with the verdict cc-safety-net recorded. The test reports the
//! agreement and fails if block/allow agreement drops below the recorded
//! floor, so a rule regression shows up as a number, not a silent change.
//!
//! Known, deliberate differences (see docs/safebash/harvest.md):
//! - safebash defers dynamic sources (`eval "$x"`, `source "$f"`, `bash -c
//!   "$x"`) to its run-time gate in standard mode instead of denying them
//!   statically; cc-safety-net cannot see run time and must deny;
//! - safebash expands the allowlisted variables (`$HOME/x`) where
//!   cc-safety-net treats them as dynamic.

mod common;

use common::{verdict, Tree};
use safebash_guard::policy::Level;
use std::collections::BTreeMap;

/// Block/allow agreement floors (fractions), per column. Raise them when
/// the port improves; never lower them to make a change pass.
// Measured baseline floors. The gap from 100% is the documented set of
// deliberate differences (docs/safebash/harvest.md): safebash defers
// dynamic shell sources to its run-time gate in standard mode, expands the
// allowlisted variables, does not port cc-safety-net's `policy apply`
// self-guard or base64 literal decoding, and relies on rubash's fuller
// parser instead of denying every "partial" parse in strict mode. Raise a
// floor when the port improves; never lower one to make a change pass.
const FLOORS: &[(&str, f64)] = &[
    ("work/standard", 0.92),
    ("work/strict", 0.90),
    ("repo/standard", 0.92),
    ("repo/strict", 0.90),
];

fn expected_rule(cell: &str) -> Option<&str> {
    if cell == "allow" {
        return None;
    }
    cell.split_whitespace().nth(1)
}

/// Rule ids that name the same outcome.
fn same_rule(ours: &str, theirs: &str) -> bool {
    if ours == theirs {
        return true;
    }
    let root_like =
        |r: &str| matches!(r, "guard.policy-config" | "rm.recursive-force-root-or-home");
    root_like(ours) && root_like(theirs)
}

#[test]
fn harvested_corpus_agreement() {
    let tree = Tree::new("harvested");
    let data = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/ccsn-harvested-verdicts.jsonl"
    ))
    .unwrap();
    let rows: Vec<serde_json::Value> = data
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let mut report = String::new();
    let mut failures = Vec::new();
    for (column, floor) in FLOORS {
        let (place_name, level_name) = column.split_once('/').unwrap();
        let place = if place_name == "work" {
            &tree.workspace
        } else {
            &tree.repository
        };
        let level = Level::parse(level_name).unwrap();
        let guard = tree.guard(place, level);
        let (mut total, mut block_agree, mut rule_agree, mut both_block) =
            (0usize, 0usize, 0usize, 0usize);
        let mut confusion: BTreeMap<(String, String), usize> = BTreeMap::new();
        let mut examples: BTreeMap<(String, String), String> = BTreeMap::new();
        for row in &rows {
            let Some(cell) = row.get(*column).and_then(|v| v.as_str()) else {
                continue;
            };
            let literal = row["literal"].as_str().unwrap();
            let literal = literal.replace("<home>", &tree.home.to_string_lossy());
            let theirs = expected_rule(cell);
            let ours = verdict(&guard, &literal, place);
            let ours_blocks = ours != "allow";
            total += 1;
            if ours_blocks == theirs.is_some() {
                block_agree += 1;
            }
            if let (true, Some(t)) = (ours_blocks, theirs) {
                both_block += 1;
                if same_rule(&ours, t) {
                    rule_agree += 1;
                }
            }
            let key = (theirs.unwrap_or("allow").to_string(), ours.clone());
            if !(key.0 == key.1 || (ours_blocks && theirs.is_some_and(|t| same_rule(&ours, t)))) {
                *confusion.entry(key.clone()).or_default() += 1;
                examples
                    .entry(key)
                    .or_insert_with(|| literal.chars().take(100).collect());
            }
        }
        let agreement = block_agree as f64 / total as f64;
        report.push_str(&format!(
            "{column}: {total} rows, block/allow agreement {:.1}%, rule agreement {:.1}% of {both_block} co-blocked\n",
            agreement * 100.0,
            rule_agree as f64 * 100.0 / both_block.max(1) as f64,
        ));
        let mut worst: Vec<_> = confusion.into_iter().collect();
        worst.sort_by_key(|x| std::cmp::Reverse(x.1));
        for ((theirs, ours), count) in worst.iter().take(12) {
            report.push_str(&format!(
                "    {count:4}  ccsn={theirs:42} safebash={ours:38} e.g. {}\n",
                examples[&(theirs.clone(), ours.clone())].replace('\n', "\\n")
            ));
        }
        if agreement < *floor {
            failures.push(format!("{column}: {:.3} < floor {floor}", agreement));
        }
    }
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("harvested-agreement.txt");
    std::fs::write(&out, &report).unwrap();
    println!("{report}");
    assert!(
        failures.is_empty(),
        "agreement below floor: {failures:?}\n{report}"
    );
}
