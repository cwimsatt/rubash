//! Shared fixtures: a throwaway tree with a home, a plain workspace and a
//! Git repository, and guards configured against it.

#![allow(dead_code)]

use safebash::convert::RubashParser;
use safebash::setup::git_metadata;
use safebash_guard::analyze::Host;
use safebash_guard::audit::AuditLog;
use safebash_guard::paths::{default_temp_roots, normalize_abs, PathStyle};
use safebash_guard::policy::{Level, Policy};
use safebash_guard::Guard;
use std::path::{Path, PathBuf};

pub struct Tree {
    pub root: PathBuf,
    pub home: PathBuf,
    pub workspace: PathBuf,
    pub repository: PathBuf,
}

impl Tree {
    /// Under the system temp dir, like cc-safety-net's `createGateTree`.
    pub fn new(name: &str) -> Tree {
        let root = std::env::temp_dir().join(format!("safebash-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let tree = Tree {
            home: root.join("home"),
            workspace: root.join("workspace"),
            repository: root.join("repository"),
            root,
        };
        for dir in [&tree.home, &tree.workspace, &tree.repository] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let _ = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .arg(&tree.repository)
            .status();
        tree
    }

    pub fn host(&self, place: &Path) -> Host {
        let style = PathStyle::native();
        let norm = |p: &Path| normalize_abs(p, style);
        // A dedicated scratch root, not the system temp dir: the whole
        // fixture lives under /tmp, so trusting /tmp would make the
        // workspace itself look temporary. The guard consults only this
        // list, so `$TMPDIR/x` is temp while `workspace/build` is not.
        let scratch = self.root.join("scratch");
        let _ = std::fs::create_dir_all(&scratch);
        let temp_roots: Vec<_> = [scratch.clone()].iter().filter_map(|p| norm(p)).collect();
        let _ = default_temp_roots; // not used in tests
        let mut vars = std::collections::HashMap::new();
        vars.insert("HOME".to_string(), self.home.to_string_lossy().into_owned());
        vars.insert("TMPDIR".to_string(), scratch.to_string_lossy().into_owned());
        vars.insert("PWD".to_string(), place.to_string_lossy().into_owned());
        vars.insert("USER".to_string(), "agent".to_string());
        Host {
            style,
            home: norm(&self.home),
            workspace: norm(place),
            temp_roots,
            protected: [
                self.home.join(".config/safebash"),
                self.home.join(".local/state/safebash"),
                place.join(".safebash"),
            ]
            .iter()
            .filter_map(|p| norm(p))
            .collect(),
            protected_roots: [
                self.home.join(".config/safebash"),
                self.home.join(".local/state/safebash"),
            ]
            .iter()
            .filter_map(|p| norm(p))
            .collect(),
            git_metadata: git_metadata(place, style),
            vars,
            self_names: vec!["safebash".into()],
        }
    }

    pub fn guard(&self, place: &Path, level: Level) -> Guard {
        let mut guard = Guard::new(
            Policy::preset(level),
            self.host(place),
            Some(Box::new(RubashParser { posix: false })),
            AuditLog::disabled(),
        );
        guard.interactive_confirm = false;
        guard
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// `allow`, or the deciding rule id.
pub fn verdict(guard: &Guard, command: &str, cwd: &Path) -> String {
    let report = guard.analyze_source(command, Some(cwd));
    match report.primary() {
        None => "allow".to_string(),
        Some(finding) => finding.rule.to_string(),
    }
}
