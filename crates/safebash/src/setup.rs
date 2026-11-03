//! Process setup: the facts the guard judges against, gathered once at
//! startup from the environment the shell was started with.

use safebash_guard::analyze::Host;
use safebash_guard::paths::{default_temp_roots, normalize_abs, NormPath, PathStyle};
use safebash_guard::platform;
use safebash_guard::policy::{Policy, PolicySources};
use safebash_guard::words::KNOWN_VARIABLES;
use std::path::{Path, PathBuf};

/// The workspace root: inherited from a parent safebash when it is an
/// existing absolute directory containing our cwd, else the cwd.
pub fn workspace() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok();
    if let Some(inherited) = std::env::var_os("SAFEBASH_WORKSPACE").map(PathBuf::from) {
        let usable = inherited.is_absolute()
            && inherited.is_dir()
            && cwd.as_ref().is_some_and(|c| c.starts_with(&inherited));
        if usable {
            return Some(inherited);
        }
    }
    cwd
}

/// Protected Git metadata for the repository containing `start`: the
/// `.git` entry, git dir, common dir and their hook directories.
pub fn git_metadata(start: &Path, style: PathStyle) -> Vec<NormPath> {
    let mut out = Vec::new();
    let mut dir = Some(start);
    while let Some(current) = dir {
        let entry = current.join(".git");
        if entry.is_dir() {
            out.push(entry.clone());
            out.push(entry.join("hooks"));
            break;
        }
        if entry.is_file() {
            out.push(entry.clone());
            if let Ok(text) = std::fs::read_to_string(&entry) {
                if let Some(gitdir) = text.lines().find_map(|l| l.strip_prefix("gitdir:")) {
                    let gitdir = current.join(gitdir.trim());
                    out.push(gitdir.join("hooks"));
                    if let Ok(common) = std::fs::read_to_string(gitdir.join("commondir")) {
                        let common = gitdir.join(common.trim());
                        out.push(common.join("hooks"));
                    }
                    out.push(gitdir);
                }
            }
            break;
        }
        dir = current.parent();
    }
    let mut norm: Vec<NormPath> = Vec::new();
    for path in out {
        for candidate in [Some(path.clone()), std::fs::canonicalize(&path).ok()]
            .into_iter()
            .flatten()
        {
            if let Some(n) = normalize_abs(&candidate, style) {
                if !norm.contains(&n) {
                    norm.push(n);
                }
            }
        }
    }
    norm
}

/// Build the host facts and the effective policy.
pub fn host_and_policy(workspace: Option<&Path>) -> (Host, Policy) {
    let style = PathStyle::native();
    let home = platform::home_dir().and_then(|h| normalize_abs(&h, style));
    let workspace_norm = workspace.and_then(|w| normalize_abs(w, style));
    let tmpdir = std::env::var(if cfg!(windows) { "TEMP" } else { "TMPDIR" }).ok();
    let mut temp_roots = default_temp_roots(style, tmpdir.as_deref());
    if cfg!(windows) {
        if let Some(t) = normalize_abs(&std::env::temp_dir(), style) {
            temp_roots.push(t);
        }
    }
    let protected_roots: Vec<NormPath> = [platform::config_dir(), platform::state_dir()]
        .into_iter()
        .flatten()
        .filter_map(|p| normalize_abs(&p, style))
        .collect();
    let mut protected = protected_roots.clone();
    if let Some(w) = workspace {
        if let Some(p) = normalize_abs(&w.join(".safebash"), style) {
            protected.push(p);
        }
    }
    let mut vars = std::collections::HashMap::new();
    for name in KNOWN_VARIABLES {
        if let Ok(value) = std::env::var(name) {
            vars.insert((*name).to_string(), value);
        }
    }
    if let Some(w) = workspace {
        vars.insert("PWD".into(), w.to_string_lossy().into_owned());
    }
    let mut self_names = vec!["safebash".to_string()];
    if let Some(name) = std::env::current_exe().ok().and_then(|p| {
        p.file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
    }) {
        if !self_names.contains(&name) {
            self_names.push(name);
        }
    }
    let host = Host {
        style,
        home,
        git_metadata: workspace
            .map(|w| git_metadata(w, style))
            .unwrap_or_default(),
        workspace: workspace_norm,
        temp_roots,
        protected,
        protected_roots,
        vars,
        self_names,
    };
    let policy = Policy::load(&PolicySources::discover(workspace));
    (host, policy)
}
