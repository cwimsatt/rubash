//! Path reasoning: lexical normalization, canonicalization and the
//! classification ladder recursive deletes are judged by.
//!
//! Paths are handled as `/`-separated strings so one implementation serves
//! both platform styles. Windows paths are folded to `c:/users/me` form
//! (lower-cased drive and components, MSYS `/c/...` mapped to `c:/...`),
//! which also makes comparisons case-insensitive there, as the file system
//! is.

use std::path::{Path, PathBuf};

/// Which path grammar applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStyle {
    Posix,
    Windows,
}

impl PathStyle {
    pub fn native() -> PathStyle {
        if cfg!(windows) {
            PathStyle::Windows
        } else {
            PathStyle::Posix
        }
    }
}

/// A normalized absolute path: `/`-separated, no `.`/`..` components, no
/// trailing slash (except the root itself), folded for Windows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormPath(String);

impl NormPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is a file-system root (`/`, `c:/`, `//server/share`).
    pub fn is_root(&self) -> bool {
        self.0 == "/" || is_drive_root(&self.0) || is_unc_root(&self.0)
    }

    /// `self` equals `other` or lies below it.
    pub fn is_within(&self, other: &NormPath) -> bool {
        if self.0 == other.0 {
            return true;
        }
        let prefix = if other.0.ends_with('/') {
            other.0.clone()
        } else {
            format!("{}/", other.0)
        };
        self.0.starts_with(&prefix)
    }

    /// `self` lies strictly above `other`.
    pub fn is_ancestor_of(&self, other: &NormPath) -> bool {
        self != other && other.is_within(self)
    }

    pub fn components(&self) -> Vec<&str> {
        self.0.split('/').filter(|c| !c.is_empty()).collect()
    }

    /// Number of components below the root.
    pub fn depth(&self) -> usize {
        let comps = self.components();
        if is_drive_root(&self.0)
            || self.0.starts_with(|c: char| c.is_ascii_alphabetic())
                && self.0.get(1..2) == Some(":")
        {
            comps.len().saturating_sub(1)
        } else {
            comps.len()
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            return None;
        }
        self.0.rsplit('/').next().filter(|s| !s.is_empty())
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(&self.0)
    }
}

impl std::fmt::Display for NormPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_drive_root(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

fn is_unc_root(text: &str) -> bool {
    text.starts_with("//") && text[2..].split('/').filter(|c| !c.is_empty()).count() <= 2
}

/// Fold a raw path into `/`-separated form for `style`, mapping
/// `C:\x`, `c:/x` and MSYS `/c/x` to `c:/x` on Windows.
fn fold(raw: &str, style: PathStyle) -> String {
    match style {
        PathStyle::Posix => raw.to_string(),
        PathStyle::Windows => {
            let mut text = raw.replace('\\', "/");
            if let Some(rest) = text.strip_prefix("//?/") {
                text = rest.to_string();
            }
            let bytes = text.as_bytes();
            // MSYS / Git Bash / rubash display form: /c or /c/...
            if bytes.len() >= 2
                && bytes[0] == b'/'
                && bytes[1].is_ascii_alphabetic()
                && (bytes.len() == 2 || bytes[2] == b'/')
            {
                let drive = (bytes[1] as char).to_ascii_lowercase();
                let rest = if bytes.len() > 2 { &text[2..] } else { "/" };
                text = format!("{drive}:{rest}");
            }
            text.to_ascii_lowercase()
        }
    }
}

fn is_absolute_folded(text: &str, style: PathStyle) -> bool {
    match style {
        PathStyle::Posix => text.starts_with('/'),
        PathStyle::Windows => {
            let bytes = text.as_bytes();
            text.starts_with("//")
                || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        }
    }
}

/// Lexically normalize `raw` against `cwd` (both in `style`). `~` must
/// already be expanded. Returns `None` for a relative path with no cwd.
pub fn normalize(raw: &str, cwd: Option<&NormPath>, style: PathStyle) -> Option<NormPath> {
    let folded = fold(raw, style);
    let joined = if is_absolute_folded(&folded, style) {
        folded
    } else {
        let base = cwd?;
        if base.0.ends_with('/') {
            format!("{}{}", base.0, folded)
        } else {
            format!("{}/{}", base.0, folded)
        }
    };
    Some(NormPath(collapse(&joined, style)))
}

/// Normalize an already-absolute host path (cwd, home, temp dirs).
pub fn normalize_abs(path: &Path, style: PathStyle) -> Option<NormPath> {
    let text = path.to_string_lossy();
    let folded = fold(&text, style);
    is_absolute_folded(&folded, style).then(|| NormPath(collapse(&folded, style)))
}

fn collapse(path: &str, style: PathStyle) -> String {
    let (prefix, rest) = match style {
        PathStyle::Windows if path.starts_with("//") => {
            // //server/share/...: keep server and share as the root.
            let mut parts = path[2..].splitn(3, '/');
            let server = parts.next().unwrap_or("");
            let share = parts.next().unwrap_or("");
            (
                format!("//{server}/{share}"),
                parts.next().unwrap_or("").to_string(),
            )
        }
        PathStyle::Windows if path.as_bytes().get(1) == Some(&b':') => {
            (path[..2].to_string(), path[2..].to_string())
        }
        _ => (String::new(), path.to_string()),
    };
    let mut stack: Vec<&str> = Vec::new();
    for component in rest.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let body = stack.join("/");
    if prefix.starts_with("//") {
        if body.is_empty() {
            prefix
        } else {
            format!("{prefix}/{body}")
        }
    } else {
        format!("{prefix}/{body}")
    }
}

/// Canonicalize against the real file system: resolve the deepest existing
/// ancestor with `realpath` and re-attach the missing suffix, so a symlink
/// alias (`ln -s / r; rm -rf r/`) cannot hide the real target even when the
/// final component does not exist yet. Falls back to the lexical path.
pub fn canonicalize(path: &NormPath, style: PathStyle) -> NormPath {
    if style != PathStyle::native() {
        return path.clone();
    }
    let mut existing = PathBuf::from(path.as_str());
    let mut missing: Vec<String> = Vec::new();
    for _ in 0..256 {
        if let Ok(real) = std::fs::canonicalize(&existing) {
            let mut text = real.to_string_lossy().into_owned();
            for component in missing.iter().rev() {
                if !text.ends_with('/') && !text.ends_with('\\') {
                    text.push('/');
                }
                text.push_str(component);
            }
            return normalize_abs(Path::new(&text), style).unwrap_or_else(|| path.clone());
        }
        let Some(name) = existing
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
        else {
            break;
        };
        missing.push(name);
        if !existing.pop() {
            break;
        }
    }
    path.clone()
}

/// Whether a raw operand names something only through a trailing slash
/// (`dir/`), which makes `rm -r` follow a symlink to its target.
pub fn has_trailing_separator(raw: &str) -> bool {
    raw.len() > 1 && (raw.ends_with('/') || raw.ends_with('\\'))
}

/// Default trusted temporary roots for a platform.
pub fn default_temp_roots(style: PathStyle, env_tmpdir: Option<&str>) -> Vec<NormPath> {
    let mut roots: Vec<NormPath> = match style {
        PathStyle::Posix => [
            "/tmp",
            "/var/tmp",
            "/private/tmp",
            "/private/var/tmp",
            "/dev/shm",
        ]
        .iter()
        .filter_map(|p| normalize_abs(Path::new(p), style))
        .collect(),
        PathStyle::Windows => Vec::new(),
    };
    if let Some(tmp) = env_tmpdir.filter(|t| trusted_tmpdir_value(t)) {
        if let Some(norm) = normalize_abs(Path::new(tmp), style) {
            // A TMPDIR is trusted only when it is itself below a known
            // temp root (Windows: below the user profile's Temp folder).
            let below_root = roots
                .iter()
                .any(|root| norm.is_within(root) && &norm != root);
            let windows_temp = style == PathStyle::Windows
                && norm
                    .components()
                    .iter()
                    .any(|c| *c == "temp" || *c == "tmp");
            let macos_var_folders = norm.as_str().starts_with("/var/folders/")
                || norm.as_str().starts_with("/private/var/folders/");
            if below_root || windows_temp || macos_var_folders {
                roots.push(norm);
            }
        }
    }
    roots
}

/// A TMPDIR value is trusted only if it carries no expansion or pattern
/// characters (harvested from cc-safety-net `src/core/paths/tmpdir.ts`).
fn trusted_tmpdir_value(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '$' | '`' | '*' | '?' | '[' | '{' | '}'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posix(raw: &str, cwd: &str) -> String {
        let cwd = normalize_abs(Path::new(cwd), PathStyle::Posix).unwrap();
        normalize(raw, Some(&cwd), PathStyle::Posix).unwrap().0
    }

    #[test]
    fn posix_normalization() {
        assert_eq!(posix("build", "/w/proj"), "/w/proj/build");
        assert_eq!(posix("../x", "/w/proj"), "/w/x");
        assert_eq!(posix("/a/./b/../c/", "/"), "/a/c");
        assert_eq!(posix("../../../..", "/w/proj"), "/");
        assert_eq!(posix(".", "/w/proj"), "/w/proj");
    }

    #[test]
    fn windows_folding() {
        let cwd = normalize_abs(Path::new("C:\\Users\\Me\\proj"), PathStyle::Windows).unwrap();
        assert_eq!(cwd.as_str(), "c:/users/me/proj");
        let n = |raw: &str| normalize(raw, Some(&cwd), PathStyle::Windows).unwrap().0;
        assert_eq!(n("build\\out"), "c:/users/me/proj/build/out");
        assert_eq!(n("/c/Users/Me"), "c:/users/me");
        assert_eq!(n("D:\\"), "d:/");
        assert!(normalize("D:\\", None, PathStyle::Windows)
            .unwrap()
            .is_root());
        assert_eq!(n("\\\\server\\share\\x"), "//server/share/x");
    }

    #[test]
    fn ancestry() {
        let home = NormPath("/home/me".into());
        let root = NormPath("/".into());
        let proj = NormPath("/home/me/proj".into());
        assert!(proj.is_within(&home));
        assert!(home.is_ancestor_of(&proj));
        assert!(root.is_ancestor_of(&home));
        assert!(!NormPath("/home/mex".into()).is_within(&home));
        assert!(root.is_root());
    }

    #[test]
    fn tmpdir_trust() {
        let roots = default_temp_roots(PathStyle::Posix, Some("/tmp/agent-1"));
        assert!(roots.iter().any(|r| r.as_str() == "/tmp/agent-1"));
        let roots = default_temp_roots(PathStyle::Posix, Some("/home/me"));
        assert!(!roots.iter().any(|r| r.as_str() == "/home/me"));
        let roots = default_temp_roots(PathStyle::Posix, Some("/tmp/$x"));
        assert!(!roots.iter().any(|r| r.as_str().contains('$')));
    }
}
