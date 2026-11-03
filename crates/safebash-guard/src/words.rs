//! Static evaluation of a shell word from its source text.
//!
//! The host parser hands the guard each word as written (`raw`). This
//! module decides what is knowable before the command runs:
//!
//! - quote removal (`'..'`, `".."`, `\x`, ANSI-C `$'..'`, locale `$".."`);
//! - a leading `~` and the allowlisted variables (`$HOME`, `$TMPDIR`,
//!   `$PWD`, ...) whose values the shell inherited — expanded only when the
//!   reference is plain (`$NAME` or `${NAME}`, no operators);
//! - unquoted pathname-pattern characters (the word becomes a [`Word::Glob`]);
//! - brace expansion of unquoted `{a,b}` / `{1..3}` lists (bounded);
//! - the bodies of command and process substitutions, which execute and so
//!   are analyzed as nested scripts.
//!
//! Anything else (`$other`, `${x:-y}`, arithmetic, `$(...)` in the value)
//! makes the word [`Word::Dyn`]: its value is unknown until run time, where
//! the dispatch gate sees the real expansion.

use crate::model::Word;

/// Variables whose inherited values static analysis may substitute
/// (harvested from cc-safety-net `src/core/paths/canonicalization.ts`).
pub const KNOWN_VARIABLES: &[&str] = &[
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "PWD",
    "USER",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
];

/// The static reading of one word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluated {
    /// The word's possible values: one entry normally, several after brace
    /// expansion.
    pub words: Vec<Word>,
    /// Bodies of `$(...)`, backquotes, `<(...)`, `>(...)` in the word.
    pub substitutions: Vec<String>,
}

/// Evaluate `raw` with `lookup` resolving allowlisted variables.
pub fn evaluate(raw: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Evaluated {
    let substitutions = substitution_bodies(raw);
    let alternatives = brace_expand(raw, 64);
    let words = alternatives
        .iter()
        .map(|alt| evaluate_one(alt, lookup))
        .collect();
    Evaluated {
        words,
        substitutions,
    }
}

#[derive(PartialEq)]
enum Kind {
    Lit,
    Glob,
    Dyn,
}

fn evaluate_one(raw: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Word {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut kind = Kind::Lit;
    let mut i = 0;
    let bump = |kind: &mut Kind, to: Kind| {
        if to == Kind::Dyn || (*kind == Kind::Lit && to == Kind::Glob) {
            *kind = to;
        }
    };
    // Tilde prefix.
    if chars.first() == Some(&'~') {
        let end = chars.iter().position(|c| *c == '/').unwrap_or(chars.len());
        let user: String = chars[1..end].iter().collect();
        if user.is_empty() {
            match lookup("HOME") {
                Some(home) => {
                    out.push_str(&home);
                    i = end;
                }
                None => bump(&mut kind, Kind::Dyn),
            }
        } else {
            bump(&mut kind, Kind::Dyn);
        }
    }
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                if let Some(next) = chars.get(i + 1) {
                    if *next != '\n' {
                        out.push(*next);
                    }
                    i += 2;
                } else {
                    out.push('\\');
                    i += 1;
                }
            }
            '\'' => {
                let end = find_char(&chars, i + 1, '\'').unwrap_or(chars.len());
                out.extend(&chars[i + 1..end]);
                i = end + 1;
            }
            '"' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '"' {
                    match chars[j] {
                        '\\' if matches!(chars.get(j + 1), Some('$' | '`' | '"' | '\\' | '\n')) => {
                            if chars[j + 1] != '\n' {
                                out.push(chars[j + 1]);
                            }
                            j += 2;
                        }
                        '$' | '`' => {
                            let (text, end, dynamic) = dollar_or_backquote(&chars, j, lookup);
                            out.push_str(&text);
                            if dynamic {
                                bump(&mut kind, Kind::Dyn);
                            }
                            j = end;
                        }
                        other => {
                            out.push(other);
                            j += 1;
                        }
                    }
                }
                i = j + 1;
            }
            '$' if chars.get(i + 1) == Some(&'\'') => {
                let (text, end) = ansi_c(&chars, i + 2);
                out.push_str(&text);
                i = end;
            }
            '$' if chars.get(i + 1) == Some(&'"') => {
                // Locale string: same as a double-quoted word here.
                i += 1;
            }
            '$' | '`' => {
                let (text, end, dynamic) = dollar_or_backquote(&chars, i, lookup);
                out.push_str(&text);
                if dynamic {
                    bump(&mut kind, Kind::Dyn);
                }
                i = end;
            }
            '*' | '?' | '[' => {
                out.push(c);
                bump(&mut kind, Kind::Glob);
                i += 1;
            }
            '@' | '!' | '+' if chars.get(i + 1) == Some(&'(') => {
                // extglob pattern
                out.push(c);
                bump(&mut kind, Kind::Glob);
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    match kind {
        Kind::Lit => Word::Lit(out),
        Kind::Glob => Word::Glob(out),
        Kind::Dyn => Word::Dyn(raw.to_string()),
    }
}

fn find_char(chars: &[char], from: usize, needle: char) -> Option<usize> {
    (from..chars.len()).find(|&i| chars[i] == needle)
}

/// A `$...` or backquote at `i`: returns the substituted text (known
/// variable value, or the raw text), the index after it, and whether the
/// value is unknown.
fn dollar_or_backquote(
    chars: &[char],
    i: usize,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> (String, usize, bool) {
    if chars[i] == '`' {
        let end = matching_backquote(chars, i + 1);
        return (chars[i..end].iter().collect(), end, true);
    }
    match chars.get(i + 1) {
        Some('(') => {
            let end = matching_paren(chars, i + 2);
            (chars[i..end].iter().collect(), end, true)
        }
        Some('{') => {
            let Some(close) = find_char(chars, i + 2, '}') else {
                // Unterminated `${`: unknown to the end of the word.
                return (chars[i..].iter().collect(), chars.len(), true);
            };
            let inner: String = chars[i + 2..close].iter().collect();
            let end = close + 1;
            if is_name(&inner) && KNOWN_VARIABLES.contains(&inner.as_str()) {
                if let Some(value) = lookup(&inner) {
                    return (value, end, false);
                }
            }
            (chars[i..end].iter().collect(), end, true)
        }
        Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
            let mut end = i + 1;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            let name: String = chars[i + 1..end].iter().collect();
            if KNOWN_VARIABLES.contains(&name.as_str()) {
                if let Some(value) = lookup(&name) {
                    return (value, end, false);
                }
            }
            (chars[i..end].iter().collect(), end, true)
        }
        Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(*c) => {
            (chars[i..i + 2].iter().collect(), i + 2, true)
        }
        _ => ("$".to_string(), i + 1, false),
    }
}

fn is_name(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Index just past the `)` closing a `$(`/`<(`/`>(` whose body starts at
/// `from`, honoring quotes and nesting.
fn matching_paren(chars: &[char], from: usize) -> usize {
    let mut depth = 1usize;
    let mut i = from;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '\'' => i = find_char(chars, i + 1, '\'').unwrap_or(chars.len()),
            '"' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '"' {
                    if chars[j] == '\\' {
                        j += 1;
                    }
                    j += 1;
                }
                i = j;
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    chars.len()
}

fn matching_backquote(chars: &[char], from: usize) -> usize {
    let mut i = from;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '`' => return i + 1,
            _ => {}
        }
        i += 1;
    }
    chars.len()
}

/// Decode an ANSI-C quoted string whose body starts at `from`; returns the
/// text and the index after the closing quote.
fn ansi_c(chars: &[char], from: usize) -> (String, usize) {
    let mut out = String::new();
    let mut i = from;
    while i < chars.len() && chars[i] != '\'' {
        if chars[i] != '\\' || i + 1 >= chars.len() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let e = chars[i + 1];
        i += 2;
        match e {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'e' | 'E' => out.push('\x1b'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            '\\' | '\'' | '"' | '?' => out.push(e),
            'x' | 'u' | 'U' => {
                let max = match e {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let digits: String = chars[i..]
                    .iter()
                    .take(max)
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                i += digits.len();
                if let Some(ch) = u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(ch);
                }
            }
            '0'..='7' => {
                let mut digits = e.to_string();
                while digits.len() < 3 && i < chars.len() && ('0'..='7').contains(&chars[i]) {
                    digits.push(chars[i]);
                    i += 1;
                }
                if let Some(ch) = u32::from_str_radix(&digits, 8)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(ch);
                }
            }
            'c' => {
                if let Some(next) = chars.get(i) {
                    out.push(char::from((*next as u8) & 0x1f));
                    i += 1;
                }
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    (out, i + 1)
}

/// The bodies of every command or process substitution in `raw` that the
/// shell would execute (not those inside single quotes).
pub fn substitution_bodies(raw: &str) -> Vec<String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut bodies = Vec::new();
    let mut i = 0;
    let mut in_double = false;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '\'' if !in_double => {
                i = find_char(&chars, i + 1, '\'').map_or(chars.len(), |e| e + 1);
            }
            '"' => {
                in_double = !in_double;
                i += 1;
            }
            '$' if chars.get(i + 1) == Some(&'\'') && !in_double => {
                let (_, end) = ansi_c(&chars, i + 2);
                i = end;
            }
            '$' if chars.get(i + 1) == Some(&'(') => {
                let arithmetic = chars.get(i + 2) == Some(&'(');
                let end = matching_paren(&chars, i + 2);
                let body: String = chars[i + 2..end.saturating_sub(1).max(i + 2)]
                    .iter()
                    .collect();
                if arithmetic {
                    // $(( ... )): only substitutions inside it execute.
                    bodies.extend(substitution_bodies(&body));
                } else {
                    bodies.push(body);
                }
                i = end;
            }
            '<' | '>' if chars.get(i + 1) == Some(&'(') && !in_double => {
                let end = matching_paren(&chars, i + 2);
                bodies.push(
                    chars[i + 2..end.saturating_sub(1).max(i + 2)]
                        .iter()
                        .collect(),
                );
                i = end;
            }
            '`' => {
                let end = matching_backquote(&chars, i + 1);
                let body: String = chars[i + 1..end.saturating_sub(1).max(i + 1)]
                    .iter()
                    .collect();
                bodies.push(
                    body.replace("\\`", "`")
                        .replace("\\$", "$")
                        .replace("\\\\", "\\"),
                );
                i = end;
            }
            _ => i += 1,
        }
    }
    bodies
}

/// Brace-expand the unquoted `{a,b}` and `{x..y}` lists of `raw` (bash
/// semantics, left to right), keeping at most `limit` results; a word
/// with no expandable list comes back unchanged.
pub fn brace_expand(raw: &str, limit: usize) -> Vec<String> {
    let chars: Vec<char> = raw.chars().collect();
    let Some((open, close, items)) = first_brace_list(&chars) else {
        return vec![raw.to_string()];
    };
    let prefix: String = chars[..open].iter().collect();
    let suffix: String = chars[close + 1..].iter().collect();
    let mut out = Vec::new();
    for item in items {
        for rest in brace_expand(&format!("{item}{suffix}"), limit) {
            if out.len() >= limit {
                return out;
            }
            out.push(format!("{prefix}{rest}"));
        }
    }
    out
}

fn first_brace_list(chars: &[char]) -> Option<(usize, usize, Vec<String>)> {
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '\'' => i = find_char(chars, i + 1, '\'').map_or(chars.len(), |e| e + 1),
            '"' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '"' {
                    if chars[j] == '\\' {
                        j += 1;
                    }
                    j += 1;
                }
                i = j + 1;
            }
            '$' if chars.get(i + 1) == Some(&'{') => {
                i = find_char(chars, i + 2, '}').map_or(chars.len(), |e| e + 1);
            }
            '{' => {
                if let Some((close, items)) = brace_items(chars, i) {
                    return Some((i, close, items));
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Parse the list opened at `open`: comma alternatives at depth 0, or a
/// `{a..b}` sequence. `None` when the braces do not form a list.
fn brace_items(chars: &[char], open: usize) -> Option<(usize, Vec<String>)> {
    let mut depth = 0usize;
    let mut items = Vec::new();
    let mut current = String::new();
    let mut i = open + 1;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                current.push(c);
                if let Some(next) = chars.get(i + 1) {
                    current.push(*next);
                }
                i += 2;
                continue;
            }
            '\'' | '"' => {
                let end = find_char(chars, i + 1, c).unwrap_or(chars.len() - 1);
                current.extend(&chars[i..=end]);
                i = end + 1;
                continue;
            }
            '{' => depth += 1,
            '}' if depth > 0 => depth -= 1,
            '}' => {
                items.push(std::mem::take(&mut current));
                if items.len() >= 2 {
                    return Some((i, items));
                }
                return sequence(&items[0]).map(|seq| (i, seq));
            }
            ',' if depth == 0 => {
                items.push(std::mem::take(&mut current));
                i += 1;
                continue;
            }
            _ => {}
        }
        current.push(c);
        i += 1;
    }
    None
}

fn sequence(body: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = body.split("..").collect();
    if parts.len() != 2 && parts.len() != 3 {
        return None;
    }
    let step: i64 = parts
        .get(2)
        .map_or(Some(1i64), |s| s.parse::<i64>().ok())?
        .checked_abs()
        .unwrap_or(1)
        .max(1);
    if let (Ok(a), Ok(b)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
        // Span and length computed without overflow (`i64::MIN..i64::MAX`
        // is a valid brace list to reject, not to panic on).
        let span = (a as i128 - b as i128).unsigned_abs();
        if span / step as u128 > 64 {
            return None;
        }
        let range: Vec<i64> = if a <= b {
            (a..=b).step_by(step as usize).collect()
        } else {
            (b..=a).rev().step_by(step as usize).collect()
        };
        return Some(range.iter().map(i64::to_string).collect());
    }
    let (a, b) = (parts[0].chars().next()?, parts[1].chars().next()?);
    if parts[0].chars().count() == 1
        && parts[1].chars().count() == 1
        && a.is_ascii_alphabetic()
        && b.is_ascii_alphabetic()
    {
        let (lo, hi) = (a.min(b) as u8, a.max(b) as u8);
        let mut seq: Vec<String> = (lo..=hi).map(|c| (c as char).to_string()).collect();
        if a > b {
            seq.reverse();
        }
        return Some(seq);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(name: &str) -> Option<String> {
        match name {
            "HOME" => Some("/home/me".into()),
            "TMPDIR" => Some("/tmp/agent".into()),
            _ => None,
        }
    }

    fn eval(raw: &str) -> Vec<Word> {
        evaluate(raw, &lookup).words
    }

    #[test]
    fn quote_removal_and_ansi_c() {
        assert_eq!(eval(r#"'a b'"c"\d"#), vec![Word::lit("a bcd")]);
        assert_eq!(eval(r"$'\x72m\t'"), vec![Word::lit("rm\t")]);
        assert_eq!(eval(r#""\$HOME""#), vec![Word::lit("$HOME")]);
        assert_eq!(eval(r"\rm"), vec![Word::lit("rm")]);
    }

    #[test]
    fn known_variables_tilde_and_dynamic() {
        assert_eq!(eval("~/x"), vec![Word::lit("/home/me/x")]);
        assert_eq!(eval("\"$HOME\"/.ssh"), vec![Word::lit("/home/me/.ssh")]);
        assert_eq!(eval("${TMPDIR}/b"), vec![Word::lit("/tmp/agent/b")]);
        assert_eq!(eval("$target"), vec![Word::Dyn("$target".into())]);
        assert_eq!(eval("${HOME:-/}"), vec![Word::Dyn("${HOME:-/}".into())]);
        assert_eq!(eval("$(pwd)/x"), vec![Word::Dyn("$(pwd)/x".into())]);
        assert_eq!(eval("~root"), vec![Word::Dyn("~root".into())]);
    }

    #[test]
    fn globs_and_braces() {
        assert_eq!(eval("/tmp/a*"), vec![Word::Glob("/tmp/a*".into())]);
        assert_eq!(eval("'*'"), vec![Word::lit("*")]);
        assert_eq!(
            eval("/tmp/{safe,../Users}"),
            vec![Word::lit("/tmp/safe"), Word::lit("/tmp/../Users")]
        );
        assert_eq!(eval("{rm,-rf,/}").len(), 3);
        assert_eq!(
            eval("a{1..3}"),
            vec![Word::lit("a1"), Word::lit("a2"), Word::lit("a3")]
        );
        assert_eq!(eval("'{a,b}'"), vec![Word::lit("{a,b}")]);
        assert_eq!(eval("{a}"), vec![Word::lit("{a}")]);
    }

    #[test]
    fn substitution_bodies_are_extracted() {
        assert_eq!(substitution_bodies("$(rm -rf /)"), vec!["rm -rf /"]);
        assert_eq!(
            substitution_bodies("`git reset --hard`x"),
            vec!["git reset --hard"]
        );
        assert_eq!(substitution_bodies("'$(no)'"), Vec::<String>::new());
        assert_eq!(substitution_bodies("\"$(a \")\" b)\""), vec!["a \")\" b"]);
        assert_eq!(substitution_bodies("$(( $(echo 1) + 2 ))"), vec!["echo 1"]);
        assert_eq!(substitution_bodies("<(cat x)"), vec!["cat x"]);
    }
}
