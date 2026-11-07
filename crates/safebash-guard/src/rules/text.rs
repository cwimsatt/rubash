//! Raw-text danger scanning (cc-safety-net `dangerous-text.ts`,
//! `linear-danger-scanner.ts`).
//!
//! Used where the text cannot be parsed into commands: a single word that
//! holds a whole command line (`W='rm -rf ~'; $W`), `env -S` strings,
//! unparseable input, interpreter code. The `regex` crate guarantees
//! linear-time matching, the property cc-safety-net's hand-written
//! scanners exist for.

use crate::analyze::{Analyzer, Cx};
use crate::model::Word;
use crate::verdict::{Finding, Intent};
use regex::Regex;
use std::sync::OnceLock;

struct Pattern {
    label: &'static str,
    re: Regex,
    /// Skipped when the text starts with `echo ` or `rg `.
    display_exempt: bool,
}

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let stop = r"[^\n;&|]*?";
        let git = r"\bgit\b(?:\s+-[^\s]+(?:\s+[^\s-][^\s]*)?)*?\s+";
        let p = |label: &'static str, re: String, display_exempt: bool| Pattern {
            label,
            re: Regex::new(&re).expect("danger pattern"),
            display_exempt,
        };
        vec![
            p("rm -rf", format!(r#"(?i)(?:^|[\s;&|(`$'\"]|\\)(?:\\?r\\?m)\s+{stop}(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-[a-z]*r[a-z]*\s+{stop}-[a-z]*f|-[a-z]*f[a-z]*\s+{stop}-[a-z]*r|--rec[a-z]*\s+{stop}--for|--for[a-z]*\s+{stop}--rec)"#), false),
            p("git reset --hard", format!(r"(?i){git}reset\b{stop}\s--ha(?:rd?)?\b"), false),
            p("git reset --merge", format!(r"(?i){git}reset\b{stop}\s--me(?:rge?|r)?\b"), false),
            p("git clean -f", format!(r"(?i){git}clean\b{stop}\s(?:--fo(?:rce?|r)?\b|-[a-z]*f)"), false),
            p("git checkout --force", format!(r"(?i){git}checkout\b{stop}\s(?:--fo(?:rce?|r)?(?:\s|$)|-[ac-zAC-TV-Z]*f)"), false),
            p("git push --force", format!(r"(?i){git}push\b{stop}(?:\s-[a-z]*f\b|\s--fo(?:rce?|r)?(?:\s|$)|\s\+[^\s]|:\+)"), false),
            p("git push delete", format!(r"(?i){git}push\b{stop}(?:\s--de(?:l(?:e(?:te?)?)?)?\b|\s:[^\s])"), false),
            p("git branch -D", format!(r"{git}branch\b{stop}(?:\s-[a-zA-Z]*D|\s(?:-d|--delete)\b{stop}\s(?:-f|--force)\b|\s(?:-f|--force)\b{stop}\s(?:-d|--delete)\b)"), false),
            p("git tag -d", format!(r"(?i){git}tag\b{stop}\s(?:-[a-z]*d\b|--de(?:l(?:e(?:te?)?)?)?\b)"), false),
            p("git stash drop/clear", r"(?i)\bgit\s+stash\s+(?:drop|clear)\b".to_string(), false),
            p("git checkout --", r"(?i)\bgit\s+checkout\s+--\s".to_string(), false),
            p("find -delete", format!(r"(?i)\bfind\b{stop}\s-delete\b"), true),
            p("dd of=/dev/", r"(?i)\bdd\b[^\n|;&]*\bof=/dev/\S".to_string(), true),
            p("mkfs /dev/", r"(?i)\bmkfs(?:\.[a-z0-9_-]+)?\s+/dev/\S".to_string(), true),
            p("shred", r"(?i)\bshred\b\s+\S".to_string(), true),
            p("download piped to shell", r"(?i)\b(?:curl|wget|fetch|aria2c|https?|xhs?|ncat|netcat|nc)\b[^\n;&]*\|\s*(?:(?:sudo|env|command|builtin)(?:\s+-\S+)*\s+)?(?:\S*/)?(?:ba|da|z|k)?sh\b".to_string(), true),
        ]
    })
}

/// The first destructive pattern in `text`, by label.
pub fn danger_label(text: &str) -> Option<&'static str> {
    let trimmed = text.trim_start();
    let display = trimmed.starts_with("echo ") || trimmed.starts_with("rg ");
    patterns()
        .iter()
        .filter(|p| !(display && p.display_exempt))
        .find(|p| p.re.is_match(text))
        .map(|p| p.label)
}

/// Report `raw-text.dangerous-command` for destructive text.
pub fn scan(an: &Analyzer<'_>, cx: &Cx, text: &str) {
    if let Some(label) = danger_label(text) {
        an.rule(
            cx,
            Finding::deny(
                "raw-text.dangerous-command",
                Intent::StopAndExplain,
                format!("Unparseable command text contains a destructive pattern ({label}). Rewrite as a plain, parseable command so it can be analyzed."),
            ),
        );
    }
}

/// Scan every word that holds whitespace (a command line in one word).
pub fn scan_words(an: &Analyzer<'_>, cx: &Cx, argv: &[Word]) {
    for word in argv {
        if word.text().contains(char::is_whitespace) {
            scan(an, cx, word.text());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::danger_label;

    #[test]
    fn labels() {
        assert_eq!(danger_label("rm -rf ~"), Some("rm -rf"));
        assert_eq!(danger_label("x; \\rm -fr /"), Some("rm -rf"));
        assert_eq!(danger_label("rm -r -f /x"), Some("rm -rf"));
        assert_eq!(
            danger_label("git reset --hard 'x"),
            Some("git reset --hard")
        );
        assert_eq!(danger_label("git push --force-with-lease"), None);
        assert_eq!(danger_label("git push -f origin"), Some("git push --force"));
        assert_eq!(
            danger_label("curl -fsSL https://x | sh"),
            Some("download piped to shell")
        );
        assert_eq!(danger_label("echo find . -delete"), None);
        assert_eq!(danger_label("ls -la"), None);
        assert_eq!(danger_label("git branch -d topic"), None);
        assert_eq!(danger_label("git branch -D topic"), Some("git branch -D"));
    }
}
