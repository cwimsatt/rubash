//! Append-only JSONL audit log of decisions (harvested from cc-safety-net's
//! `src/audit/writer.ts` record shape). Every text field is redacted; any
//! I/O error is swallowed — auditing never changes a decision.
//!
//! Location: `<state dir>/audit/<YYYY-MM-DD>.jsonl`, directories `0700`,
//! files `0600` on Unix.

use crate::verdict::{Action, Finding, Layer};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize)]
struct Record<'a> {
    ts: String,
    pid: u32,
    decision: &'a str,
    layer: Layer,
    level: &'a str,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent: Option<crate::verdict::Intent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    config_warning: bool,
}

/// One decision to record.
pub struct Entry<'a> {
    pub decision: &'a str,
    pub layer: Layer,
    pub level: &'a str,
    pub command: &'a str,
    pub cwd: Option<&'a str>,
    pub finding: Option<&'a Finding>,
    pub config_warning: bool,
}

/// Where audit records go.
#[derive(Debug, Clone)]
pub struct AuditLog {
    dir: Option<PathBuf>,
}

impl AuditLog {
    pub fn new(dir: Option<PathBuf>) -> AuditLog {
        AuditLog { dir }
    }

    pub fn disabled() -> AuditLog {
        AuditLog { dir: None }
    }

    pub fn dir(&self) -> Option<&std::path::Path> {
        self.dir.as_deref()
    }

    pub fn record(&self, entry: &Entry<'_>) {
        let Some(dir) = &self.dir else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let (date, ts) = utc_timestamp(now.as_secs(), now.subsec_millis());
        let record = Record {
            ts,
            pid: std::process::id(),
            decision: entry.decision,
            layer: entry.layer,
            level: entry.level,
            command: truncate(&crate::redact::redact(entry.command), 10_000),
            cwd: entry.cwd.map(crate::redact::redact),
            rule: entry.finding.map(|f| f.rule.as_ref()),
            intent: entry.finding.map(|f| f.intent),
            reason: entry.finding.map(|f| crate::redact::redact(&f.reason)),
            config_warning: entry.config_warning,
        };
        let Ok(mut line) = serde_json::to_string(&record) else {
            return;
        };
        line.push('\n');
        let _ = append(dir, &format!("{date}.jsonl"), line.as_bytes());
    }
}

/// The decision word for an action.
pub fn decision_word(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Confirm => "confirm",
        Action::Deny => "deny",
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn append(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(dir.join(name))?;
    file.write_all(bytes)
}

/// `(YYYY-MM-DD, RFC 3339 UTC timestamp)` for a Unix time.
fn utc_timestamp(secs: u64, millis: u32) -> (String, String) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let date = format!("{year:04}-{month:02}-{day:02}");
    let ts = format!("{date}T{h:02}:{m:02}:{s:02}.{millis:03}Z");
    (date, ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_civil_utc() {
        assert_eq!(utc_timestamp(0, 0).1, "1970-01-01T00:00:00.000Z");
        assert_eq!(utc_timestamp(1_793_664_000, 5).0, "2026-11-03");
        assert_eq!(utc_timestamp(951_782_400, 0).0, "2000-02-29");
    }

    #[test]
    fn records_are_redacted_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(Some(dir.path().join("audit")));
        log.record(&Entry {
            decision: "deny",
            layer: Layer::Dispatch,
            level: "standard",
            command: "API_TOKEN=hunter2 rm -rf /",
            cwd: Some("/w"),
            finding: None,
            config_warning: false,
        });
        let file = std::fs::read_dir(dir.path().join("audit"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let text = std::fs::read_to_string(file).unwrap();
        assert!(text.contains("\"decision\":\"deny\""));
        assert!(text.contains("API_TOKEN=<redacted>"));
        assert!(!text.contains("hunter2"));
    }
}
