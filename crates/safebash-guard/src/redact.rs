//! Secret redaction for everything the guard writes: denial messages and
//! audit records. Patterns harvested from cc-safety-net
//! (`src/core/redaction.ts`), rewritten for the `regex` crate, which has no
//! look-around or back-references: header and quoted forms are matched
//! with explicit alternatives instead.

use regex::Regex;
use std::sync::OnceLock;

struct Patterns {
    replacements: Vec<(Regex, &'static str)>,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let rules: &[(&str, &str)] = &[
            // Private key blocks.
            (
                r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                "<redacted>",
            ),
            // Connection strings and DSNs.
            (
                r#"(?i)\b((?:DATABASE|POSTGRES|POSTGRESQL|MYSQL|MARIADB|REDIS|MONGO(?:DB)?|DB)_(?:DSN|URL|URI|CONNECTION_STRING)|CONNECTION_STRING)=("[^"]*"|'[^']*'|\S+)"#,
                "${1}=<redacted>",
            ),
            // NAME=value where the name says secret.
            (
                r#"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|KEY|CREDENTIALS?)[A-Z0-9_]*)=("[^"]*"|'[^']*'|\S+)"#,
                "${1}=<redacted>",
            ),
            // Credential-bearing headers.
            (
                r#"(?i)((?:authorization|cookie|x-api-key|api-key|proxy-authorization)\s*:\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^'"\r\n]+)"#,
                "${1}<redacted>",
            ),
            // user:password@ and token@ in URLs.
            (r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s@/]+@", "${1}<redacted>:<redacted>@"),
            (r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]+@", "${1}<redacted>@"),
            // Signed URL parameters.
            (
                r#"(?i)(^|[\s?&;|])((?:x-amz-signature|x-goog-signature|sig|signature)=)[^&#\s'"`;|<>()]*"#,
                "${1}${2}<redacted>",
            ),
            // curl -u user:password
            (r"(^|\s)((?:-u|--user)(?:\s+|=))[^\s:]+:\S+", "${1}${2}<redacted>:<redacted>"),
            // Provider token shapes.
            (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "<redacted>"),
            (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "<redacted>"),
            (r"\bglpat-[A-Za-z0-9_-]{20,}\b", "<redacted>"),
            (r"\bxox[abeprs]-[A-Za-z0-9-]{20,}\b", "<redacted>"),
            (r"\bnpm_[A-Za-z0-9_]{20,}\b", "<redacted>"),
            (r"\bpypi-[A-Za-z0-9_-]{20,}\b", "<redacted>"),
            (r"\b[rs]k_(?:live|test)_[A-Za-z0-9_]{20,}\b", "<redacted>"),
            (r"\bsk-[A-Za-z0-9_-]{20,}\b", "<redacted>"),
            (r"\bsk_[A-Za-z0-9]{20,}\b", "<redacted>"),
            (r"\bgsk_[A-Za-z0-9]{52,}\b", "<redacted>"),
            (r"\bxai-[A-Za-z0-9_-]{80,}\b", "<redacted>"),
            (r"\bpplx-[A-Za-z0-9_-]{20,}\b", "<redacted>"),
            (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b", "<redacted>"),
            (r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "<redacted>"),
        ];
        Patterns {
            replacements: rules
                .iter()
                .map(|(pattern, replacement)| {
                    (
                        Regex::new(pattern).expect("redaction pattern compiles"),
                        *replacement,
                    )
                })
                .collect(),
        }
    })
}

/// Replace secret-shaped substrings with `<redacted>`.
pub fn redact(text: &str) -> String {
    patterns()
        .replacements
        .iter()
        .fold(text.to_string(), |acc, (regex, replacement)| {
            regex.replace_all(&acc, *replacement).into_owned()
        })
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn redacts_assignment_values_tokens_and_url_credentials() {
        assert_eq!(redact("API_TOKEN=abc123 make"), "API_TOKEN=<redacted> make");
        assert_eq!(
            redact("curl -H 'Authorization: Bearer abc' https://x"),
            "curl -H 'Authorization: <redacted>' https://x"
        );
        assert_eq!(
            redact("git clone https://user:hunter2@example.com/r.git"),
            "git clone https://<redacted>:<redacted>@example.com/r.git"
        );
        assert_eq!(
            redact("echo ghp_abcdefghijklmnopqrstuvwxyz0123"),
            "echo <redacted>"
        );
        assert_eq!(redact("aws AKIAABCDEFGHIJKLMNOP"), "aws <redacted>");
        assert_eq!(redact("ls -la"), "ls -la");
    }
}
