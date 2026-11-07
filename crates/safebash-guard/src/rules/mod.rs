//! The rule set. Each module ports one family of cc-safety-net analyzers
//! (rule IDs, triggers and reason texts kept identical so the harvested
//! verdict corpus can cross-check this port), plus the safeexec package
//! manager gate (`pkg`).

pub mod device;
pub mod find;
pub mod git;
pub mod guards;
pub mod interp;
pub mod network;
pub mod pkg;
pub mod redirect;
pub mod rm;
pub mod secrets;
pub mod shells;
pub mod text;
pub mod windows;
pub mod xargs;

use crate::model::Word;

/// GNU-style long option abbreviation: `--forc` names `--force` when it is
/// a prefix of at least `min` characters (cc-safety-net matches from four
/// characters for git, from `--r` for rm).
pub fn long_matches(word: &str, option: &str, min: usize) -> bool {
    let Some(body) = word.strip_prefix("--") else {
        return false;
    };
    let name = body.split('=').next().unwrap_or(body);
    let full = option.trim_start_matches("--");
    name.len() + 2 >= min && !name.is_empty() && full.starts_with(name)
}

/// A short-option cluster (`-rf`, `-Rv`).
pub fn short_cluster(word: &str) -> Option<&str> {
    let body = word.strip_prefix('-')?;
    (!body.is_empty() && !body.starts_with('-') && body.chars().all(|c| c.is_ascii_alphabetic()))
        .then_some(body)
}

/// The literal words before a `--`.
pub fn before_double_dash(argv: &[Word]) -> &[Word] {
    let end = argv
        .iter()
        .position(|w| w.as_lit() == Some("--"))
        .unwrap_or(argv.len());
    &argv[..end]
}
