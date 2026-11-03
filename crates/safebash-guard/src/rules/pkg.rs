//! Package-manager force audits (harvested from safeexec's pkgmgr
//! wrapper): `npm|pnpm|bun audit fix --force` and `yarn [npm] audit fix
//! --force` rewrite the dependency tree across major versions.

use crate::analyze::{Analyzer, Cx};
use crate::model::Word;
use crate::verdict::{Finding, Intent};

const AUDIT_FORCE: &str = "audit fix --force can upgrade dependencies across breaking major versions and rewrite the lockfile. Run 'audit fix' without --force, or ask the user to run the forced fix manually.";

fn has_sequence(words: &[&str], seq: &[&str]) -> bool {
    let mut i = 0;
    for w in words {
        if *w == seq[i] {
            i += 1;
            if i == seq.len() {
                return true;
            }
        }
    }
    false
}

pub fn check(an: &Analyzer<'_>, cx: &Cx, name: &str, argv: &[Word]) {
    if !matches!(name, "npm" | "pnpm" | "bun" | "yarn") {
        return;
    }
    let words: Vec<&str> = argv[1..].iter().map(Word::text).collect();
    let force = words.iter().any(|w| matches!(*w, "--force" | "-f"));
    let audit_fix =
        has_sequence(&words, &["audit", "fix"]) || has_sequence(&words, &["audit", "--fix"]);
    if force && audit_fix {
        an.rule(
            cx,
            Finding::confirm("pkg.audit-fix-force", Intent::ManualOnly, AUDIT_FORCE),
        );
    }
}
