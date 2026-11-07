//! `rm` / `rmdir` (cc-safety-net `src/gate/analyzer/rm.ts`).
//!
//! Recursion alone is enough (`rm -r ../x` is judged like `rm -rf ../x`);
//! flags may follow operands; everything after `--` is a target. A
//! non-recursive rm only checks Git metadata.

use super::{long_matches, short_cluster};
use crate::analyze::{Analyzer, Cx};
use crate::model::Word;
use crate::targets::{classify, contains_git_metadata, TargetClass};
use crate::verdict::{Finding, Intent};

pub const ROOT_OR_HOME: &str =
    "rm -rf targeting root or home directory is extremely dangerous and always blocked.";
pub const GIT_METADATA: &str =
    "Git metadata and hooks are protected. Ask the user before modifying them.";
const DYNAMIC: &str = "rm -rf target contains shell variables that cannot be verified safely. Use literal paths within cwd, /tmp, /var/tmp, or $TMPDIR.";
const HOME_CWD: &str =
    "rm -rf in home directory is dangerous. Change to a project directory first.";
const OUTSIDE: &str = "rm -rf outside cwd is blocked. Retry deleting only explicit paths inside the current directory; escalate for anything outside it.";
const PARANOID: &str = "rm -rf for non-temporary paths is blocked by the active safety policy. Retry deleting only explicit paths inside the current directory; escalate for anything outside it.";

/// Whether any option word makes this rm recursive.
pub fn is_recursive(options: &[&Word]) -> bool {
    options.iter().any(|w| match w.as_lit() {
        Some(t) if t.starts_with("--") => long_matches(t, "--recursive", 3),
        Some(t) => short_cluster(t).is_some_and(|c| c.contains(['r', 'R'])),
        None => false,
    })
}

/// Both recursive and force (for find -exec / xargs / parallel children).
pub fn is_recursive_force(argv: &[Word]) -> bool {
    let (options, _) = split(argv);
    let force = options.iter().any(|w| match w.as_lit() {
        Some(t) if t.starts_with("--") => long_matches(t, "--force", 3),
        Some(t) => short_cluster(t).is_some_and(|c| c.contains('f')),
        None => false,
    });
    force && is_recursive(&options)
}

/// Options (before `--`) and targets.
fn split(argv: &[Word]) -> (Vec<&Word>, Vec<&Word>) {
    let mut options = Vec::new();
    let mut targets = Vec::new();
    let mut after_dashes = false;
    for word in argv.iter().skip(1) {
        if after_dashes {
            targets.push(word);
            continue;
        }
        match word.as_lit() {
            Some("--") => after_dashes = true,
            Some(t) if t.starts_with('-') && t.len() > 1 => options.push(word),
            _ => targets.push(word),
        }
    }
    (options, targets)
}

pub fn check(an: &Analyzer<'_>, cx: &Cx, argv: &[Word]) {
    let (options, targets) = split(argv);
    let recursive = is_recursive(&options) && !argv[0].text().ends_with("rmdir");
    for target in targets {
        if !recursive {
            // Non-recursive: only protected Git metadata.
            if let Some(path) = target
                .as_lit()
                .and_then(|t| an.host.norm(t, cx.cwd.as_ref()))
            {
                if contains_git_metadata(an, &path, false) {
                    an.rule(
                        cx,
                        Finding::deny("rm.git-metadata", Intent::HardStop, GIT_METADATA),
                    );
                }
            }
            continue;
        }
        report(an, cx, classify(an, cx, target), "rm");
    }
}

/// Report a classified recursive-delete target with the `<family>.*` IDs
/// (`rm` for rm/find/rsync).
pub fn report(an: &Analyzer<'_>, cx: &Cx, class: TargetClass, family: &str) {
    let caps = an.policy.capabilities;
    let finding = match class {
        TargetClass::RootOrHome => Finding::deny(
            "rm.recursive-force-root-or-home",
            Intent::HardStop,
            ROOT_OR_HOME,
        ),
        TargetClass::GitMetadata => {
            Finding::deny("rm.git-metadata", Intent::HardStop, GIT_METADATA)
        }
        TargetClass::Temp | TargetClass::Allowed => return,
        TargetClass::Dynamic if caps.fail_closed => Finding::deny(
            "rm.recursive-force-dynamic-target",
            Intent::ScopeDown,
            DYNAMIC,
        ),
        TargetClass::Dynamic => return,
        TargetClass::HomeCwd => {
            Finding::deny("rm.recursive-force-home-cwd", Intent::ScopeDown, HOME_CWD)
        }
        TargetClass::CwdSelf => {
            Finding::deny("rm.recursive-force-cwd-self", Intent::ScopeDown, OUTSIDE)
        }
        TargetClass::Within if caps.paranoid_rm => {
            Finding::deny("rm.recursive-force-paranoid", Intent::ScopeDown, PARANOID)
        }
        TargetClass::Within => return,
        TargetClass::Outside => {
            Finding::deny("rm.recursive-force-outside-cwd", Intent::ScopeDown, OUTSIDE)
        }
    };
    let _ = family;
    an.rule(cx, finding);
}
