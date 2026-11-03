//! Classification of recursive-delete targets, shared by `rm`, `find`,
//! `rsync`, `cmd rd /s` and `Remove-Item` (cc-safety-net
//! `recursive-delete-targets.ts` `classifyRecursiveDeleteTarget`).
//!
//! The ladder, first match wins:
//!
//! 1. root or home (catastrophic): `/`, `/*`, `C:\`, `~`, `$HOME/*`, ...;
//! 2. protected Git metadata (catastrophic, inside a repository);
//! 3. temp: under a trusted temp root, no `..`;
//! 4. dynamic: not literal (denied only when failing closed);
//! 5. a configured allow-path;
//! 6. working in home;
//! 7. the working directory itself;
//! 8. within the workspace (denied only by paranoid rm);
//! 9. outside the workspace.
//!
//! At run time the target is also canonicalized (deepest existing ancestor
//! resolved, missing suffix re-attached), so `ln -s / r; rm -rf r/` is the
//! root, not a child of the workspace.

use crate::analyze::{Analyzer, Cx};
use crate::model::Word;
use crate::paths::{canonicalize, has_trailing_separator, NormPath};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    RootOrHome,
    GitMetadata,
    Temp,
    Dynamic,
    Allowed,
    HomeCwd,
    CwdSelf,
    Within,
    Outside,
}

/// Classify one recursive-delete target.
pub fn classify(an: &Analyzer<'_>, cx: &Cx, target: &Word) -> TargetClass {
    let host = an.host;
    let text = target.text();
    if is_root_or_home_spelling(an, target) {
        return TargetClass::RootOrHome;
    }
    let Word::Lit(raw) = target else {
        // Globs and dynamic words: a pattern made only of stars over the
        // root is still the root (`/*/*`); `$TMPDIR/x` with a trusted
        // TMPDIR is temp.
        if let Word::Glob(pattern) = target {
            if let Some(base) = glob_base(pattern) {
                if let Some(path) = host.norm(&base, cx.cwd.as_ref()) {
                    if pattern_is_all_stars_below(pattern, &base) && is_root_or_home(an, &path) {
                        return TargetClass::RootOrHome;
                    }
                    if contains_git_metadata(an, &path, true) && pattern_reaches_dotfiles(pattern) {
                        return TargetClass::GitMetadata;
                    }
                }
            }
        }
        if text.contains("..") {
            return TargetClass::Dynamic;
        }
        return TargetClass::Dynamic;
    };
    let Some(lexical) = host.norm(raw, cx.cwd.as_ref()) else {
        // Relative target with an unknown cwd: outside (static analysis
        // defers to the run-time gate unless failing closed).
        return if an.policy.capabilities.fail_closed {
            TargetClass::Outside
        } else {
            TargetClass::Dynamic
        };
    };
    let canonical = if an.runtime || has_trailing_separator(raw) {
        canonicalize(&lexical, host.style)
    } else {
        lexical.clone()
    };
    for path in [&lexical, &canonical] {
        if is_root_or_home(an, path) {
            return TargetClass::RootOrHome;
        }
    }
    if [&lexical, &canonical]
        .iter()
        .any(|p| contains_git_metadata(an, p, true))
    {
        return TargetClass::GitMetadata;
    }
    let has_dotdot = raw.split(['/', '\\']).any(|c| c == "..");
    if !has_dotdot && is_temp(an, &canonical) && is_temp(an, &lexical) {
        return TargetClass::Temp;
    }
    if an
        .policy
        .allow_delete
        .iter()
        .filter_map(|p| allow_path(an, p))
        .any(|root| canonical.is_within(&root))
    {
        return TargetClass::Allowed;
    }
    let Some(workspace) = host.workspace.as_ref() else {
        return TargetClass::Outside;
    };
    if let Some(home) = &host.home {
        if workspace == home || cx.cwd.as_ref() == Some(home) {
            return TargetClass::HomeCwd;
        }
    }
    let cwd = cx.cwd.as_ref().unwrap_or(workspace);
    if canonical == *cwd || lexical == *cwd || matches!(raw.as_str(), "." | "./" | ".\\") {
        return TargetClass::CwdSelf;
    }
    let tilde = raw.starts_with('~') || raw.starts_with("$HOME") || raw.starts_with("${HOME}");
    if !tilde
        && !raw.starts_with("../")
        && lexical.is_within(workspace)
        && canonical.is_within(workspace)
    {
        return TargetClass::Within;
    }
    TargetClass::Outside
}

/// `~`, `~/`, `~/*`, `$HOME`, `${HOME}/*` and friends, as written.
fn is_root_or_home_spelling(an: &Analyzer<'_>, target: &Word) -> bool {
    let text = target.text().trim_end_matches(['/', '\\']);
    let text = text.strip_suffix("/*").unwrap_or(text);
    let text = text.trim_matches('"');
    matches!(
        text,
        "~" | "$HOME" | "${HOME}" | "\"$HOME\"" | "$env:USERPROFILE" | "%USERPROFILE%"
    ) || (target.is_lit() && an.host.home.is_some() && target.text() == "~")
}

/// The literal directory a glob pattern starts from (`/etc/*` -> `/etc`).
fn glob_base(pattern: &str) -> Option<String> {
    let first_meta = pattern.find(['*', '?', '['])?;
    let prefix = &pattern[..first_meta];
    let base = match prefix.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => prefix[..i].to_string(),
        None => ".".to_string(),
    };
    Some(base)
}

/// The pattern below `base` is only `*` / `**` components (`/*/*/`).
fn pattern_is_all_stars_below(pattern: &str, base: &str) -> bool {
    let rest = pattern
        .strip_prefix(base)
        .unwrap_or(pattern)
        .trim_matches('/');
    !rest.is_empty() && rest.split('/').all(|c| c == "*" || c == "**")
}

/// A glob that can match dot entries (`./.*`, `/.`).
fn pattern_reaches_dotfiles(pattern: &str) -> bool {
    pattern.contains("/.") || pattern.starts_with('.')
}

/// A file-system root, the real home, or an ancestor of home.
pub fn is_root_or_home(an: &Analyzer<'_>, path: &NormPath) -> bool {
    if path.is_root() {
        return true;
    }
    match &an.host.home {
        Some(home) => path == home || path.is_ancestor_of(home),
        None => false,
    }
}

/// `path` is protected Git metadata, or (for a recursive delete) contains
/// a protected root.
pub fn contains_git_metadata(an: &Analyzer<'_>, path: &NormPath, recursive: bool) -> bool {
    an.host.git_metadata.iter().any(|meta| {
        path == meta
            || (path.is_within(meta) && meta.as_str().contains("/hooks"))
            || (recursive && meta.is_within(path))
    })
}

/// Under a trusted temp root (the root itself included, as for rm).
pub fn is_temp(an: &Analyzer<'_>, path: &NormPath) -> bool {
    an.host.temp_roots.iter().any(|root| path.is_within(root))
        && an
            .host
            .workspace
            .as_ref()
            .map_or(true, |w| !w.is_within(path))
}

/// A temp descendant (not a temp root itself), for find/rsync scoping.
pub fn is_temp_descendant(an: &Analyzer<'_>, path: &NormPath) -> bool {
    an.host
        .temp_roots
        .iter()
        .any(|root| path.is_within(root) && path != root)
        && an
            .host
            .workspace
            .as_ref()
            .map_or(true, |w| !w.is_within(path))
}

fn allow_path(an: &Analyzer<'_>, configured: &str) -> Option<NormPath> {
    let expanded = match configured.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", an.host.home.as_ref()?.as_str()),
        None => configured.to_string(),
    };
    let path = an.host.norm(&expanded, None)?;
    // Never the home directory or one of its ancestors.
    match &an.host.home {
        Some(home) if path == *home || path.is_ancestor_of(home) => None,
        _ if path.is_root() => None,
        _ => Some(path),
    }
}

/// A target find/rsync may delete under: within the workspace (unless
/// paranoid) or a temp descendant.
pub fn is_scoped(an: &Analyzer<'_>, cx: &Cx, target: &Word) -> bool {
    let Word::Lit(raw) = target else {
        return false;
    };
    let Some(path) = an.host.norm(raw, cx.cwd.as_ref()) else {
        return false;
    };
    if is_temp_descendant(an, &path) && !raw.split('/').any(|c| c == "..") {
        return true;
    }
    if an.policy.capabilities.paranoid_rm {
        return false;
    }
    let Some(workspace) = an.host.workspace.as_ref() else {
        return false;
    };
    let cwd = cx.cwd.as_ref().unwrap_or(workspace);
    path != *cwd
        && path.is_within(workspace)
        && path != *workspace
        && !raw.starts_with("../")
        && an.host.home.as_ref() != Some(workspace)
}
