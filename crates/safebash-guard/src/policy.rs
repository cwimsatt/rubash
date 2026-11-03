//! Policy: safety level, capabilities, per-rule overrides and paths.
//!
//! Harvested from cc-safety-net's policy model (`src/core/policy/*`):
//! three presets that map to capabilities, environment variables that can
//! only *raise* protection, and a broken or hostile config that falls back
//! to protective defaults instead of locking the agent out. Differences:
//!
//! - project policy files (`<workspace>/.safebash/policy.toml`) are always
//!   tighten-only: a repository the agent can write to must never weaken
//!   protection;
//! - a parent safebash hands its effective level to child shells through
//!   `SAFEBASH_FLOOR`, so a nested shell is never weaker than its parent.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The preset protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Helpful, non-adversarial agents: block what is clearly destructive,
    /// let the run-time gate resolve what static analysis cannot.
    Standard,
    /// Adversarial assumptions: anything unverifiable is denied, and no
    /// confirmation prompts.
    Strict,
    /// Strict, plus every recursive delete and every interpreter
    /// one-liner is denied.
    Paranoid,
}

impl Level {
    pub fn parse(text: &str) -> Option<Level> {
        match text.trim().to_ascii_lowercase().as_str() {
            "standard" => Some(Level::Standard),
            "strict" => Some(Level::Strict),
            "paranoid" => Some(Level::Paranoid),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Level::Standard => "standard",
            Level::Strict => "strict",
            Level::Paranoid => "paranoid",
        }
    }

    fn capabilities(self) -> Capabilities {
        Capabilities {
            fail_closed: self >= Level::Strict,
            paranoid_rm: self >= Level::Paranoid,
            paranoid_interpreters: self >= Level::Paranoid,
        }
    }
}

/// What a level switches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct Capabilities {
    /// Deny whatever cannot be verified (dynamic shell sources, dynamic
    /// recursive-delete targets, unparseable input).
    pub fail_closed: bool,
    /// Deny every recursive force delete, even inside the workspace.
    pub paranoid_rm: bool,
    /// Deny every interpreter one-liner (`python -c`, `node -e`, ...).
    pub paranoid_interpreters: bool,
}

impl Capabilities {
    fn union(self, other: Capabilities) -> Capabilities {
        Capabilities {
            fail_closed: self.fail_closed || other.fail_closed,
            paranoid_rm: self.paranoid_rm || other.paranoid_rm,
            paranoid_interpreters: self.paranoid_interpreters || other.paranoid_interpreters,
        }
    }
}

/// A per-rule override from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetting {
    Off,
    Confirm,
    Deny,
}

/// When a `Confirm` finding may prompt a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfirmMode {
    /// Prompt on the controlling terminal when one is usable and this
    /// shell is in the foreground; deny otherwise.
    Tty,
    /// Never prompt: every `Confirm` is a denial.
    Never,
}

/// The effective policy.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Policy {
    pub level: Level,
    pub capabilities: Capabilities,
    pub rules: BTreeMap<String, RuleSetting>,
    /// Extra trees where recursive deletes are allowed (never `$HOME`
    /// itself or one of its ancestors).
    pub allow_delete: Vec<String>,
    pub secrets_enabled: bool,
    /// Extra secret paths (globs relative to `~` allowed).
    pub secret_paths: Vec<String>,
    /// Secret basenames that are not secrets here (e.g. `.env.local` in a
    /// repo that keeps no secrets in it).
    pub secret_allow: Vec<String>,
    pub confirm: ConfirmMode,
    pub audit: bool,
    pub audit_allowed: bool,
    /// Problems met while loading config; shown by `--guard-status` and
    /// appended to audit records.
    pub warnings: Vec<String>,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::preset(Level::Standard)
    }
}

impl Policy {
    pub fn preset(level: Level) -> Policy {
        Policy {
            level,
            capabilities: level.capabilities(),
            rules: BTreeMap::new(),
            allow_delete: Vec::new(),
            secrets_enabled: true,
            secret_paths: Vec::new(),
            secret_allow: Vec::new(),
            confirm: if level >= Level::Strict {
                ConfirmMode::Never
            } else {
                ConfirmMode::Tty
            },
            audit: true,
            audit_allowed: false,
            warnings: Vec::new(),
        }
    }

    /// The configured setting for a rule, if any.
    pub fn rule_setting(&self, rule: &str) -> Option<RuleSetting> {
        self.rules.get(rule).copied()
    }

    /// Raise the level (never lowers it).
    pub fn raise_to(&mut self, level: Level) {
        if level > self.level {
            self.level = level;
            self.capabilities = self.capabilities.union(level.capabilities());
            if level >= Level::Strict {
                self.confirm = ConfirmMode::Never;
            }
        }
    }

    /// Load the effective policy: user file, then the project file
    /// (tighten-only), then environment raises.
    pub fn load(sources: &PolicySources) -> Policy {
        let mut policy = Policy::default();
        if let Some(path) = &sources.user_file {
            if let Some(file) = read_policy_file(path, &mut policy.warnings) {
                policy.apply_user(file);
            }
        }
        if let Some(path) = &sources.project_file {
            if let Some(file) = read_policy_file(path, &mut policy.warnings) {
                policy.apply_project(file);
            }
        }
        for (name, value) in &sources.env {
            match name.as_str() {
                "SAFEBASH_LEVEL" | "SAFEBASH_FLOOR" => match Level::parse(value) {
                    Some(level) => policy.raise_to(level),
                    None => policy
                        .warnings
                        .push(format!("{name}={value:?} is not a level; ignored")),
                },
                "SAFEBASH_STRICT" if truthy(value) => policy.raise_to(Level::Strict),
                "SAFEBASH_PARANOID" if truthy(value) => policy.raise_to(Level::Paranoid),
                _ => {}
            }
        }
        policy
    }

    fn apply_user(&mut self, file: PolicyFile) {
        if let Some(level) = file.level {
            *self = Policy {
                warnings: std::mem::take(&mut self.warnings),
                ..Policy::preset(level)
            };
        }
        if let Some(caps) = file.capabilities {
            if let Some(v) = caps.fail_closed {
                self.capabilities.fail_closed = v;
            }
            if let Some(v) = caps.paranoid_rm {
                self.capabilities.paranoid_rm = v;
            }
            if let Some(v) = caps.paranoid_interpreters {
                self.capabilities.paranoid_interpreters = v;
            }
        }
        for (rule, setting) in file.rules.unwrap_or_default() {
            self.rules.insert(rule, setting);
        }
        if let Some(paths) = file.paths {
            self.allow_delete
                .extend(paths.allow_delete.unwrap_or_default());
        }
        if let Some(secrets) = file.secrets {
            if let Some(enabled) = secrets.enabled {
                self.secrets_enabled = enabled;
            }
            self.secret_paths.extend(secrets.extra.unwrap_or_default());
            self.secret_allow.extend(secrets.allow.unwrap_or_default());
        }
        if let Some(confirm) = file.confirm {
            self.confirm = confirm;
        }
        if let Some(audit) = file.audit {
            if let Some(enabled) = audit.enabled {
                self.audit = enabled;
            }
            if let Some(allowed) = audit.log_allowed {
                self.audit_allowed = allowed;
            }
        }
    }

    /// Apply a project file, keeping only the parts that tighten.
    fn apply_project(&mut self, file: PolicyFile) {
        let mut dropped = Vec::new();
        if let Some(level) = file.level {
            if level >= self.level {
                self.raise_to(level);
            } else {
                dropped.push("a lower level");
            }
        }
        if let Some(caps) = file.capabilities {
            let wanted = Capabilities {
                fail_closed: caps.fail_closed.unwrap_or(false),
                paranoid_rm: caps.paranoid_rm.unwrap_or(false),
                paranoid_interpreters: caps.paranoid_interpreters.unwrap_or(false),
            };
            self.capabilities = self.capabilities.union(wanted);
            if caps.fail_closed == Some(false)
                || caps.paranoid_rm == Some(false)
                || caps.paranoid_interpreters == Some(false)
            {
                dropped.push("disabled capabilities");
            }
        }
        for (rule, setting) in file.rules.unwrap_or_default() {
            let current = self.rules.get(&rule).copied();
            let tightens = match setting {
                RuleSetting::Deny => true,
                RuleSetting::Confirm => !matches!(current, Some(RuleSetting::Deny)),
                RuleSetting::Off => false,
            };
            if tightens {
                self.rules.insert(rule, setting);
            } else {
                dropped.push("a rule switched off");
            }
        }
        if file
            .paths
            .is_some_and(|p| p.allow_delete.is_some_and(|a| !a.is_empty()))
        {
            dropped.push("delete allow-paths");
        }
        if let Some(secrets) = file.secrets {
            if secrets.enabled == Some(false) {
                dropped.push("disabled secret protection");
            }
            self.secret_paths.extend(secrets.extra.unwrap_or_default());
            if secrets.allow.is_some_and(|a| !a.is_empty()) {
                dropped.push("secret allow-list entries");
            }
        }
        if file.confirm == Some(ConfirmMode::Never) {
            self.confirm = ConfirmMode::Never;
        }
        dropped.sort_unstable();
        dropped.dedup();
        for item in dropped {
            self.warnings.push(format!(
                "project policy tried to weaken protection ({item}); ignored (project policy is tighten-only)"
            ));
        }
    }
}

fn truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "yes" | "on")
}

/// Where the policy comes from.
#[derive(Debug, Clone, Default)]
pub struct PolicySources {
    pub user_file: Option<PathBuf>,
    pub project_file: Option<PathBuf>,
    /// `SAFEBASH_*` environment entries.
    pub env: Vec<(String, String)>,
}

impl PolicySources {
    /// The standard locations for this platform and workspace.
    pub fn discover(workspace: Option<&Path>) -> PolicySources {
        let user_file = crate::platform::config_dir().map(|dir| dir.join("policy.toml"));
        let project_file = workspace.map(|w| w.join(".safebash").join("policy.toml"));
        let env = std::env::vars()
            .filter(|(name, _)| name.starts_with("SAFEBASH_"))
            .collect();
        PolicySources {
            user_file,
            project_file,
            env,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    level: Option<Level>,
    capabilities: Option<CapabilitiesFile>,
    rules: Option<BTreeMap<String, RuleSetting>>,
    paths: Option<PathsFile>,
    secrets: Option<SecretsFile>,
    confirm: Option<ConfirmMode>,
    audit: Option<AuditFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesFile {
    fail_closed: Option<bool>,
    paranoid_rm: Option<bool>,
    paranoid_interpreters: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathsFile {
    allow_delete: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretsFile {
    enabled: Option<bool>,
    extra: Option<Vec<String>>,
    allow: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    enabled: Option<bool>,
    log_allowed: Option<bool>,
}

/// Read and parse one policy file. A missing file is silent; an unreadable
/// or invalid file is a warning and contributes nothing (protective
/// defaults stay in force).
fn read_policy_file(path: &Path, warnings: &mut Vec<String>) -> Option<PolicyFile> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        warnings.push(format!(
            "{}: policy files may not be symlinks; ignored",
            path.display()
        ));
        return None;
    }
    if meta.len() > 256 * 1024 {
        warnings.push(format!("{}: larger than 256 KiB; ignored", path.display()));
        return None;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            warnings.push(format!("{}: {error}; ignored", path.display()));
            return None;
        }
    };
    match toml::from_str::<PolicyFile>(&text) {
        Ok(file) => Some(file),
        Err(error) => {
            let first_line = error.to_string().lines().next().unwrap_or("").to_string();
            warnings.push(format!(
                "{}: invalid policy ({first_line}); protective defaults apply",
                path.display()
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn presets_map_to_capabilities() {
        assert!(!Policy::preset(Level::Standard).capabilities.fail_closed);
        assert!(Policy::preset(Level::Strict).capabilities.fail_closed);
        let paranoid = Policy::preset(Level::Paranoid).capabilities;
        assert!(paranoid.paranoid_rm && paranoid.paranoid_interpreters);
        assert_eq!(Policy::preset(Level::Strict).confirm, ConfirmMode::Never);
    }

    #[test]
    fn env_only_raises() {
        let sources = PolicySources {
            env: vec![("SAFEBASH_LEVEL".into(), "strict".into())],
            ..PolicySources::default()
        };
        assert_eq!(Policy::load(&sources).level, Level::Strict);
        let dir = tempfile::tempdir().unwrap();
        let user = write(dir.path(), "user.toml", "level = \"paranoid\"\n");
        let sources = PolicySources {
            user_file: Some(user),
            project_file: None,
            env: vec![("SAFEBASH_LEVEL".into(), "standard".into())],
        };
        assert_eq!(Policy::load(&sources).level, Level::Paranoid);
    }

    #[test]
    fn project_policy_is_tighten_only() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "level = \"strict\"\n[rules]\n\"git.push-force\" = \"deny\"\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "level = \"standard\"\n[rules]\n\"git.push-force\" = \"off\"\n\"git.branch-force-delete\" = \"deny\"\n[secrets]\nenabled = false\n",
        );
        let policy = Policy::load(&PolicySources {
            user_file: Some(user),
            project_file: Some(project),
            env: Vec::new(),
        });
        assert_eq!(policy.level, Level::Strict);
        assert_eq!(
            policy.rule_setting("git.push-force"),
            Some(RuleSetting::Deny)
        );
        assert_eq!(
            policy.rule_setting("git.branch-force-delete"),
            Some(RuleSetting::Deny)
        );
        assert!(policy.secrets_enabled);
        assert!(policy.warnings.iter().any(|w| w.contains("tighten-only")));
    }

    #[test]
    fn broken_file_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(dir.path(), "user.toml", "level = \"off\"\n");
        let policy = Policy::load(&PolicySources {
            user_file: Some(user),
            ..PolicySources::default()
        });
        assert_eq!(policy.level, Level::Standard);
        assert!(policy.secrets_enabled);
        assert_eq!(policy.warnings.len(), 1);
    }
}
