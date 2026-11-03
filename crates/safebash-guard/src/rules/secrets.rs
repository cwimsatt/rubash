//! Secret protection (cc-safety-net `src/core/rules/secret.ts` lists,
//! `src/gate/secret/secret-protection.ts` matching).
//!
//! Every operand of every command is a candidate path (wrappers
//! included), as are `X=V` / `--opt=V` values, redirect targets and the
//! string literals of interpreter code. Exceptions keep ordinary work
//! possible: `echo`/`printf` operands, commit messages, search patterns,
//! and in standard mode metadata-only commands (`ls`, `stat`, `test -f`,
//! `wc -l`, `grep -l`). Matching follows cc-safety-net's tier order.

use crate::analyze::{command_name, Analyzer, Cx, Stage};
use crate::model::{Access, Word};
use crate::paths::NormPath;
use crate::verdict::{Finding, Intent};

const REASON: &str = "Access to a sensitive path is not allowed.";

const BASENAMES: &[(&str, &str)] = &[
    (".env", "secret.basename.env"),
    (".npmrc", "secret.basename.npmrc"),
    (".pypirc", "secret.basename.pypirc"),
    (".netrc", "secret.basename.netrc"),
    (".git-credentials", "secret.basename.git-credentials"),
    ("id_rsa", "secret.basename.id-rsa"),
    ("id_ed25519", "secret.basename.id-ed25519"),
    ("id_ecdsa", "secret.basename.id-ecdsa"),
    ("credentials", "secret.basename.credentials"),
];

/// `~/<suffix>` trees, with their rule slugs.
const HOME_PATHS: &[(&str, &str)] = &[
    (".ssh", "ssh"),
    (".aws", "aws"),
    (".gcp", "gcp"),
    (".config/gcloud", "gcloud-config"),
    (".kube/config", "kube-config"),
    (".docker/config.json", "docker-config"),
    (".config/gh/hosts.yml", "gh-hosts"),
];
const HOME_CONFIG_VARIANT_SUFFIXES: &[&str] = &[
    ".bak",
    ".backup",
    ".copy",
    ".disabled",
    ".old",
    ".orig",
    ".save",
    ".tmp",
];

const VARIANT_PREFIXES: &[(&str, &str)] = &[
    ("id_rsa", "id-rsa"),
    ("id_dsa", "id-dsa"),
    ("id_ed25519", "id-ed25519"),
    ("id_ecdsa", "id-ecdsa"),
    ("credentials", "credentials"),
];
const DOT_VARIANT_SUFFIXES: &[&str] = &[
    ".bak",
    ".backup",
    ".copy",
    ".disabled",
    ".key",
    ".old",
    ".orig",
    ".pem",
    ".save",
    ".tmp",
];
const EXTENSIONS: &[&str] = &[
    "agilekeychain",
    "asc",
    "bek",
    "cscfg",
    "fve",
    "gnucash",
    "jks",
    "keychain",
    "kwallet",
    "mdf",
    "ovpn",
    "p12",
    "pcap",
    "pem",
    "pfx",
    "pkcs12",
    "psafe3",
    "rdp",
    "sdf",
    "tblk",
    "tpm",
];

/// Coding-CLI credential files (the default-on credential tier): `(rule,
/// home-relative files, home-relative directories)`.
const CODING_CLI: &[(&str, &[&str], &[&str])] = &[
    (
        "secret.cli.claude-code",
        &[".claude/.credentials.json"],
        &[],
    ),
    (
        "secret.cli.codex",
        &[".codex/auth.json", ".codex/.credentials.json"],
        &[".codex/secrets", ".codex/.sandbox-secrets"],
    ),
    (
        "secret.cli.gemini",
        &[
            ".gemini/oauth_creds.json",
            ".gemini/mcp-oauth-tokens.json",
            ".gemini/a2a-oauth-tokens.json",
            ".gemini/gemini-credentials.json",
        ],
        &[],
    ),
    (
        "secret.cli.copilot-cli",
        &[".copilot/config.json"],
        &[".copilot/mcp-oauth-config", ".copilot/mcp-secrets"],
    ),
    (
        "secret.cli.kimi-code",
        &[".kimi-code/server.token"],
        &[
            ".kimi-code/credentials",
            ".kimi/credentials",
            ".kimi/mcp-oauth",
        ],
    ),
    (
        "secret.cli.opencode",
        &[
            ".local/share/opencode/auth.json",
            ".local/share/opencode/mcp-auth.json",
            ".local/share/opencode/opencode.db",
        ],
        &[],
    ),
    ("secret.cli.pi", &[".pi/agent/auth.json"], &[]),
    (
        "secret.cli.amp",
        &[".local/share/amp/secrets.json"],
        &[".amp/oauth"],
    ),
    (
        "secret.cli.cursor",
        &[".cursor/auth.json", ".config/cursor/auth.json"],
        &[],
    ),
    (
        "secret.cli.grok-build",
        &[".grok/auth.json", ".grok/mcp_credentials.json"],
        &[],
    ),
    (
        "secret.cli.droid",
        &[
            ".factory/auth.encrypted",
            ".factory/auth.v2.file",
            ".factory/auth.v2.key",
            ".factory/auth.v2.loginkeychain",
        ],
        &[],
    ),
    (
        "secret.cli.devin",
        &[".local/share/devin/credentials.toml"],
        &[".local/share/devin/mcp/oauth"],
    ),
];

/// The secret rule a path matches, if any. `raw` is the operand as the
/// command will use it; `cwd` resolves relative paths.
pub fn match_path(an: &Analyzer<'_>, raw: &str, cwd: Option<&NormPath>) -> Option<String> {
    let raw = raw.strip_prefix("file://").unwrap_or(raw);
    if raw.is_empty() || is_remote_url(raw) {
        return None;
    }
    let host = an.host;
    let path = host.norm(raw, cwd);
    let lower_path = path.as_ref().map(|p| p.as_str().to_ascii_lowercase());
    let name = raw
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw)
        .to_ascii_lowercase();
    let policy = an.policy;
    // Configured deny paths first.
    for extra in &policy.secret_paths {
        let expanded = expand_home(an, extra);
        if let (Some(p), Some(deny)) = (&path, expanded.and_then(|e| host.norm(&e, None))) {
            if p.is_within(&deny) {
                return Some("secret.deny-path".into());
            }
        }
    }
    let allowed = |rule: &str| -> bool {
        !rule.starts_with("secret.cli.")
            && policy.secret_allow.iter().any(|a| {
                a.eq_ignore_ascii_case(&name)
                    || path.as_ref().is_some_and(|p| {
                        expand_home(an, a)
                            .and_then(|e| host.norm(&e, None))
                            .is_some_and(|allow| p.is_within(&allow))
                    })
            })
    };
    let hit = |rule: String| -> Option<String> { (!allowed(&rule)).then_some(rule) };
    // 1. Home trees.
    if let (Some(path), Some(home)) = (&path, &host.home) {
        for (suffix, slug) in HOME_PATHS {
            let base = format!("{}/{}", home.as_str(), suffix);
            let base = host.norm(&base, None)?;
            if path.is_within(&base) {
                return hit(format!("secret.home.{slug}"));
            }
            if matches!(*slug, "kube-config" | "docker-config") {
                for variant in HOME_CONFIG_VARIANT_SUFFIXES {
                    if path.as_str() == format!("{}{variant}", base.as_str()) {
                        return hit(format!("secret.home.{slug}.{}", &variant[1..]));
                    }
                }
            }
        }
    }
    // 2. Template exemptions.
    if name == ".env.defaults"
        || (name.starts_with(".env.")
            && [".example", ".sample", ".template", ".tpl"]
                .iter()
                .any(|s| name.ends_with(s)))
        || name.starts_with(".env.example.")
        || name.starts_with(".env.sample.")
    {
        return None;
    }
    // 3. Coding-CLI credentials.
    if let (Some(lower), Some(home)) = (&lower_path, &host.home) {
        for (rule, files, dirs) in CODING_CLI {
            let under = |rel: &str| format!("{}/{}", home.as_str().to_ascii_lowercase(), rel);
            if files.iter().any(|f| *lower == under(f))
                || dirs
                    .iter()
                    .any(|d| *lower == under(d) || lower.starts_with(&format!("{}/", under(d))))
            {
                return Some((*rule).to_string());
            }
        }
    }
    // 4. Public keys are not secrets.
    if matches!(
        name.as_str(),
        "id_rsa.pub" | "id_ed25519.pub" | "id_ecdsa.pub"
    ) {
        return None;
    }
    // 5. Exact basenames.
    if let Some((_, rule)) = BASENAMES.iter().find(|(b, _)| *b == name) {
        return hit((*rule).to_string());
    }
    let filename_shaped = !name.chars().any(char::is_whitespace);
    // 6. .env.* variants.
    if name.starts_with(".env.") && filename_shaped {
        return hit("secret.pattern.env-variant".into());
    }
    // 7-8. Variants of key and credential names.
    for (prefix, slug) in VARIANT_PREFIXES {
        if name.len() > prefix.len() && name.starts_with(prefix) {
            let rest = &name[prefix.len()..];
            if (rest.starts_with('-') || rest.starts_with('_')) && filename_shaped {
                return hit(format!("secret.variant.{slug}.separator"));
            }
            if let Some(suffix) = DOT_VARIANT_SUFFIXES.iter().find(|s| rest == **s) {
                return hit(format!("secret.variant.{slug}.{}", &suffix[1..]));
            }
        }
    }
    // 9. Vendored trees skip the broad tiers.
    if let Some(lower) = &lower_path {
        let segments: Vec<&str> = lower.split('/').collect();
        if segments
            .iter()
            .any(|s| matches!(*s, "node_modules" | "__pycache__"))
            || segments
                .windows(2)
                .any(|w| w[0] == "vendor" && matches!(w[1], "bundle" | "cache"))
        {
            return None;
        }
    }
    // 10. Extensionless SSH private-key-like names.
    if !name.contains('.') {
        for kind in ["_rsa", "_dsa", "_ed25519", "_ecdsa"] {
            if name.ends_with(kind) && name.len() > kind.len() {
                return hit("secret.pattern.ssh-key-basename".into());
            }
        }
    }
    // 11. URL-ish query parameters.
    if (raw.contains("?") || raw.contains('&')) && raw.contains("key=") {
        return None;
    }
    // 12. Extensions.
    let ext = name.rfind('.').filter(|&i| i > 0).map(|i| &name[i + 1..])?;
    if EXTENSIONS.contains(&ext) {
        return hit(format!("secret.ext.{ext}"));
    }
    match ext {
        "key" | "keypair" => hit("secret.ext-pattern.key".into()),
        "keystore" | "keyring" => hit("secret.ext-pattern.keystore".into()),
        "kdb" | "kdbx" => hit("secret.ext-pattern.kdbx".into()),
        _ => None,
    }
}

fn expand_home(an: &Analyzer<'_>, text: &str) -> Option<String> {
    match text.strip_prefix("~/") {
        Some(rest) => Some(format!("{}/{rest}", an.host.home.as_ref()?.as_str())),
        None if text == "~" => an.host.home.as_ref().map(|h| h.as_str().to_string()),
        None => Some(text.to_string()),
    }
}

fn is_remote_url(text: &str) -> bool {
    match text.split_once("://") {
        Some((scheme, rest)) => {
            !scheme.eq_ignore_ascii_case("file")
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
                && !rest.is_empty()
                && !rest.starts_with('/')
        }
        None => false,
    }
}

fn report(an: &Analyzer<'_>, cx: &Cx, rule: String) {
    let finding = Finding::deny(rule, Intent::HardStop, REASON);
    let finding = if cx.segment.is_empty() {
        finding
    } else {
        finding.with_segment(cx.segment.clone())
    };
    an.emit(Stage::Secret, finding);
}

/// Tiers that name a file by its name (not by its home location): these
/// are relaxed in standard mode for things that cannot leak content.
fn is_name_tier(rule: &str) -> bool {
    !rule.starts_with("secret.home.")
        && !rule.starts_with("secret.cli.")
        && rule != "secret.deny-path"
}

/// Check every candidate operand of a command.
pub fn check_command(an: &Analyzer<'_>, cx: &Cx, argv: &[Word]) {
    if !an.policy.secrets_enabled || argv.is_empty() {
        return;
    }
    let name = command_name(&argv[0]).unwrap_or_default();
    let standard = !an.policy.capabilities.fail_closed;
    if standard && metadata_only(&name, argv) {
        return;
    }
    if matches!(name.as_str(), "echo" | "printf") {
        return;
    }
    let candidates = candidates(&name, argv);
    for word in candidates {
        let Word::Lit(text) = word else { continue };
        for value in candidate_values(text) {
            if let Some(rule) = match_path(an, value, cx.cwd.as_ref()) {
                if standard && is_name_tier(&rule) && relaxed(an, cx, &name, value) {
                    continue;
                }
                report(an, cx, rule);
                return;
            }
        }
    }
}

/// `X=V`, `--opt=V`, `@file` and `<file` forms carry a path after the
/// punctuation.
fn candidate_values(text: &str) -> Vec<&str> {
    let mut values = vec![text];
    if let Some((_, v)) = text.split_once('=') {
        values.push(v);
        if let Some(file) = v.strip_prefix('@').or_else(|| v.strip_prefix('<')) {
            values.push(file.split(';').next().unwrap_or(file));
        }
    }
    if let Some(file) = text.strip_prefix('@').or_else(|| text.strip_prefix('<')) {
        values.push(file.split(';').next().unwrap_or(file));
    }
    values
}

/// Standard-mode relaxations for name tiers: existing directories and
/// operands of commands that only create names.
fn relaxed(an: &Analyzer<'_>, cx: &Cx, name: &str, value: &str) -> bool {
    if matches!(name, "mkdir" | "touch") {
        return true;
    }
    an.host
        .norm(value, cx.cwd.as_ref())
        .is_some_and(|p| std::path::Path::new(p.as_str()).is_dir())
}

/// Commands that only look at names or metadata (standard mode).
fn metadata_only(name: &str, argv: &[Word]) -> bool {
    let args: Vec<&str> = argv[1..].iter().map(Word::text).collect();
    match name {
        "ls" | "stat" => true,
        "test" | "[" => args
            .first()
            .is_some_and(|a| matches!(*a, "-e" | "-f" | "-d" | "-s" | "-r")),
        "wc" => args.iter().filter(|a| a.starts_with('-')).all(|a| {
            matches!(
                *a,
                "-l" | "-w" | "-c" | "-m" | "--lines" | "--words" | "--bytes" | "--chars"
            )
        }),
        "grep" | "rg" => {
            let names_only = args.iter().any(|a| {
                matches!(
                    *a,
                    "-l" | "-c" | "-q" | "--files-with-matches" | "--count" | "--quiet"
                ) || (name == "grep" && *a == "-L")
            });
            names_only
                && !args
                    .iter()
                    .any(|a| matches!(*a, "-f" | "--pre" | "--json" | "--format"))
        }
        "find" => !args.iter().any(|a| {
            matches!(
                *a,
                "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir" | "-fls" | "-files0-from"
            ) || a.starts_with("-fprint")
        }),
        "git" => args.first() == Some(&"check-ignore"),
        _ => false,
    }
}

/// The operands of a command that may name files.
fn candidates<'w>(name: &str, argv: &'w [Word]) -> Vec<&'w Word> {
    let mut out = Vec::new();
    let mut skip_next = false;
    let mut first_positional_is_pattern = matches!(name, "grep" | "rg" | "egrep" | "fgrep");
    if first_positional_is_pattern
        && argv[1..].iter().any(|w| {
            matches!(w.text(), "-e" | "-f" | "--regexp" | "--file" | "--files")
                || w.text().starts_with("--regexp=")
                || w.text().starts_with("--file=")
        })
    {
        first_positional_is_pattern = false;
    }
    let git_sub = (name == "git")
        .then(|| {
            argv[1..]
                .iter()
                .find(|w| !w.text().starts_with('-'))
                .map(|w| w.text().to_string())
        })
        .flatten();
    let message_flags: &[&str] = match (name, git_sub.as_deref()) {
        ("git", Some("commit" | "merge" | "notes" | "stash" | "tag")) => {
            &["-m", "--message", "--grep"]
        }
        ("git", _) => &["--grep"],
        ("gh", _) => &[
            "--search", "-S", "--title", "-t", "--body", "-b", "--jq", "-q",
        ],
        ("find", _) => &[
            "-name",
            "-iname",
            "-path",
            "-ipath",
            "-regex",
            "-iregex",
            "-wholename",
        ],
        ("curl", _) => &["-H", "--header", "-A", "--user-agent", "-u", "--user"],
        ("tar", _) => &["-f", "--file"],
        _ => &[],
    };
    let jq = matches!(name, "jq" | "gojq" | "jaq");
    let mut jq_program_seen = false;
    for word in argv.iter().skip(1) {
        let text = word.text();
        if skip_next {
            skip_next = false;
            continue;
        }
        if message_flags.contains(&text) {
            skip_next = true;
            continue;
        }
        if message_flags
            .iter()
            .any(|f| f.starts_with("--") && text.starts_with(&format!("{f}=")))
        {
            continue;
        }
        if !text.starts_with('-') {
            if first_positional_is_pattern {
                first_positional_is_pattern = false;
                continue;
            }
            if jq && !jq_program_seen {
                jq_program_seen = true;
                continue;
            }
        }
        if name == "curl"
            && matches!(
                text,
                "-d" | "--data" | "--data-binary" | "--data-raw" | "--json" | "-F" | "--form"
            )
        {
            continue;
        }
        out.push(word);
    }
    out
}

/// A redirect target naming a secret.
pub fn check_redirect(an: &Analyzer<'_>, cx: &Cx, access: Access, target: &Word, argv: &[Word]) {
    if !an.policy.secrets_enabled {
        return;
    }
    let Word::Lit(path) = target else { return };
    let Some(rule) = match_path(an, path, cx.cwd.as_ref()) else {
        return;
    };
    let standard = !an.policy.capabilities.fail_closed;
    if standard && is_name_tier(&rule) && access.writes() && access != Access::ReadWrite {
        // `> .env` creating a new file cannot leak an existing secret.
        let exists = an
            .host
            .norm(path, cx.cwd.as_ref())
            .is_some_and(|p| std::path::Path::new(p.as_str()).exists());
        if !exists {
            return;
        }
    }
    let _ = argv;
    report(an, cx, rule);
}

/// String literals in interpreter code that name secrets.
pub fn check_code(an: &Analyzer<'_>, cx: &Cx, code: &str) {
    if !an.policy.secrets_enabled {
        return;
    }
    let mut chars = code.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c != '\'' && c != '"' {
            continue;
        }
        let mut end = None;
        for (i, n) in chars.by_ref() {
            if n == c {
                end = Some(i);
                break;
            }
        }
        let Some(end) = end else { break };
        let literal = &code[start + 1..end];
        if literal.is_empty() || literal.contains(char::is_whitespace) {
            continue;
        }
        if let Some(rule) = match_path(an, literal, cx.cwd.as_ref()) {
            report(an, cx, rule);
            return;
        }
    }
}
