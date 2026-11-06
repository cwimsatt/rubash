//! Network: cloud metadata endpoints and uploads to remote hosts
//! (cc-safety-net `src/gate/analyzer/network.ts`).

use crate::analyze::{command_name, Analyzer, Cx};
use crate::model::Word;
use crate::verdict::{Finding, Intent};
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

/// The cloud-metadata addresses, as canonical values (not text). IPv4 covers
/// AWS/GCP (169.254.169.254), ECS task roles (169.254.170.2) and the task
/// metadata endpoint (169.254.170.23), and Alibaba (100.100.100.200). IPv6
/// is AWS IMDSv6 (fd00:ec2::254) and its task-roles sibling (fd00:ec2::23).
const METADATA_IPV4: [Ipv4Addr; 4] = [
    Ipv4Addr::new(169, 254, 169, 254),
    Ipv4Addr::new(169, 254, 170, 23),
    Ipv4Addr::new(169, 254, 170, 2),
    Ipv4Addr::new(100, 100, 100, 200),
];
const METADATA_IPV6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254),
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x23),
];

const METADATA: &str = "This reaches a cloud metadata endpoint, which hands out instance credentials. Ask the user to run metadata requests manually if they are needed.";
const UPLOAD: &str = "This uploads data to a remote host, which can send local files or secrets off the machine. Send it to localhost instead, or ask the user to run the upload manually if it is needed.";

pub const REQUEST_CLIENTS: &[&str] = &[
    "curl",
    "wget",
    "aria2c",
    "http",
    "https",
    "xh",
    "xhs",
    "httpie",
    "fetch",
    "lwp-request",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
];

pub fn is_request_client(name: &str) -> bool {
    REQUEST_CLIENTS.contains(&name)
}

fn metadata_host() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // The `regex` crate has no look-around: boundaries are checked by hand
    // in `names_metadata_host`.
    RE.get_or_init(|| {
        Regex::new(r"(?i)169\.254\.169\.254|169\.254\.170\.23|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|metadata\.goog|fd00:ec2::254|fd00:ec2::23")
            .expect("pattern")
    })
}

/// The existing boundary-checked literal scan of `text` for a metadata host
/// spelling (`169.254.169.2540` and `metadata.google.internal.example.com` do
/// not match). Run on the raw token AND, in `names_metadata_host`, on the
/// percent-decoded host.
fn metadata_regex_match(text: &str) -> bool {
    metadata_host().find_iter(text).any(|m| {
        let before = text[..m.start()].chars().next_back();
        let after_text = &text[m.end()..];
        let after = after_text.chars().next();
        let is_v6 = m.as_str().contains(':');
        let ok_before = match before {
            None => true,
            Some(c) if is_v6 => !(c.is_alphanumeric() || c == '_' || c == ':'),
            Some(c) => !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-'),
        };
        let ok_after = match after {
            None => true,
            Some(c) if is_v6 => !(c.is_alphanumeric() || c == '_' || c == ':'),
            Some('.') => !after_text[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-'),
            Some(c) => !(c.is_alphanumeric() || c == '_' || c == '-'),
        };
        // `.2` must not continue as `.23` etc.: digits after the match
        // were rejected above as alphanumeric.
        ok_before && ok_after
    })
}

/// Whether `token` names a metadata host. ADDITIVE and fail-safe (a false
/// positive only adds a DENY): the untouched literal regex on the raw token,
/// OR the same regex on the percent-decoded host (an encoded hostname such as
/// `%6d%65%74%61%64%61%74%61.google.internal` curl decodes and resolves), OR
/// a canonical-IP match (numeric spellings such as `0xA9FEA9FE`). curl
/// percent-decodes the host before resolving, so the metadata comparison
/// decodes too (the loopback allowance deliberately does not: see `is_loopback`).
pub fn names_metadata_host(token: &str) -> bool {
    if metadata_regex_match(token) {
        return true;
    }
    if let Some(raw_host) = extract_host(token) {
        let decoded = percent_decode_host(&raw_host);
        if metadata_regex_match(&decoded) {
            return true;
        }
        if is_metadata_ip(&decoded) {
            return true;
        }
    }
    false
}

/// Extract the bare host from a URL/host token, for canonicalization. Returns
/// None for an unresolvable host (an unexpanded `$`/backtick, a malformed
/// bracket literal, or empty). The returned host is RAW (not percent-decoded):
/// the metadata caller decodes it; the loopback caller does not.
fn extract_host(token: &str) -> Option<String> {
    // Strip a `scheme://` wherever it occurs (so `--url=http://HOST/` yields
    // HOST, not `--url=http`), then path/query/fragment, then userinfo at the
    // LAST `@` (curl's delimiter).
    let rest = token.split_once("://").map_or(token, |(_, r)| r);
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = host_port.rsplit_once('@').map_or(host_port, |(_, h)| h);
    let host = if let Some(after_lb) = host_port.strip_prefix('[') {
        // Bracketed IPv6: require a matching `]`; take the inner literal,
        // discard any `:port` after `]`. A `[` with no `]` is malformed.
        match after_lb.split_once(']') {
            Some((inner, _)) => inner.to_string(),
            None => return None,
        }
    } else {
        // An unbracketed IPv6 literal has >=2 colons and cannot carry a port
        // (that needs brackets), so take it whole; exactly one colon is
        // `host:port`; none is a bare host.
        match host_port.matches(':').count() {
            0 | 1 => host_port.split(':').next().unwrap_or(host_port).to_string(),
            _ => host_port.to_string(),
        }
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host.contains('$') || host.contains('`') {
        return None;
    }
    Some(host)
}

/// Percent-decode a host component in place (valid `%XX` -> its byte; an
/// invalid escape is left literal). The host was already structurally
/// extracted, so a decoded delimiter is NOT re-split (a decoded `/` or `:` is
/// a literal character, never a new boundary): this both matches curl, which
/// rejects such hosts, and keeps the decode from moving component boundaries.
fn percent_decode_host(host: &str) -> String {
    let bytes = host.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Canonicalize a (bracket/port-stripped) host to an address. Returns the IPv4
/// (direct or inet_aton, or a STRICT IPv4-mapped IPv6's embedded v4 via
/// `to_ipv4_mapped`), and/or the IPv6. IPv4-compatible (`::a.b.c.d`) and NAT64
/// addresses yield only the IPv6 value (no embedded v4), so they never acquire
/// a v4 loopback/metadata identity.
fn canonical_addr(host: &str) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    if let Some(v4) = canonicalize_ipv4(host) {
        return (Some(v4), None);
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return (v6.to_ipv4_mapped(), Some(v6));
    }
    (None, None)
}

fn is_metadata_ip(host: &str) -> bool {
    let (v4, v6) = canonical_addr(host);
    v4.is_some_and(|a| METADATA_IPV4.contains(&a)) || v6.is_some_and(|a| METADATA_IPV6.contains(&a))
}

fn is_loopback_ip(host: &str) -> bool {
    let (v4, v6) = canonical_addr(host);
    v4.is_some_and(|a| a.is_loopback() || a.is_unspecified()) || v6.is_some_and(|a| a.is_loopback())
}

/// inet_aton-style IPv4 parsing: 1-4 dot parts, each decimal, octal (leading
/// `0`) or hex (leading `0x`). Returns None on a sign, invalid digit, empty
/// part, too many parts, or arithmetic overflow (no wrapping) - the host is
/// then treated as a name, never a concrete address.
fn canonicalize_ipv4(host: &str) -> Option<Ipv4Addr> {
    if host.is_empty() {
        return None;
    }
    let mut vals: Vec<u64> = Vec::with_capacity(4);
    for part in host.split('.') {
        vals.push(parse_inet_part(part)?);
        if vals.len() > 4 {
            return None;
        }
    }
    let bytes: [u8; 4] = match vals.as_slice() {
        [a] => {
            let a = u32::try_from(*a).ok()?;
            a.to_be_bytes()
        }
        [a, b] => {
            if *a > 0xff || *b > 0x00ff_ffff {
                return None;
            }
            [*a as u8, (*b >> 16) as u8, (*b >> 8) as u8, *b as u8]
        }
        [a, b, c] => {
            if *a > 0xff || *b > 0xff || *c > 0xffff {
                return None;
            }
            [*a as u8, *b as u8, (*c >> 8) as u8, *c as u8]
        }
        [a, b, c, d] => {
            if *a > 0xff || *b > 0xff || *c > 0xff || *d > 0xff {
                return None;
            }
            [*a as u8, *b as u8, *c as u8, *d as u8]
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(bytes))
}

fn parse_inet_part(part: &str) -> Option<u64> {
    if part.starts_with('+') || part.starts_with('-') {
        return None;
    }
    let (radix, digits) =
        if let Some(h) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (16u32, h)
        } else if part.len() > 1 && part.starts_with('0') {
            (8u32, &part[1..])
        } else {
            (10u32, part)
        };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

pub fn check(an: &Analyzer<'_>, cx: &Cx, name: &str, argv: &[Word]) {
    let launcher = matches!(name, "xargs" | "find");
    let client_index = if is_request_client(name) || crate::rules::interp::is_interpreter(name) {
        Some(0)
    } else if launcher {
        argv.iter()
            .position(|w| command_name(w).is_some_and(|n| is_request_client(&n)))
    } else {
        None
    };
    let Some(client_index) = client_index else {
        return;
    };
    let mut skip_next = false;
    for word in &argv[client_index..] {
        let t = word.text();
        if skip_next {
            skip_next = false;
            continue;
        }
        if t == "--noproxy" {
            skip_next = true;
            continue;
        }
        if t.starts_with("--noproxy=") {
            continue;
        }
        if names_metadata_host(t) {
            an.rule(
                cx,
                Finding::deny("network.cloud-metadata", Intent::ManualOnly, METADATA),
            );
            break;
        }
    }
    let client = command_name(&argv[client_index]).unwrap_or_default();
    let mut end = argv.len();
    if launcher {
        if let Some(stop) = argv[client_index..]
            .iter()
            .position(|w| matches!(w.text(), ";" | "\\;" | "+"))
        {
            end = client_index + stop;
        }
    }
    match client.as_str() {
        "curl" => curl(an, cx, &argv[client_index + 1..end]),
        "wget" => wget(an, cx, &argv[client_index + 1..end]),
        _ => {}
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    Data,
    Upload,
    Url,
    Source,
    Local,
    Get,
    Value,
    Flag,
}

fn curl_role(option: &str) -> Role {
    match option {
        "-d" | "--data" | "--data-ascii" | "--data-binary" | "--data-raw" | "--data-urlencode"
        | "--json" => Role::Data,
        "-F" | "--form" | "--form-string" | "-T" | "--upload-file" => Role::Upload,
        "--url" | "-x" | "--proxy" | "--preproxy" => Role::Url,
        "-K" | "--config" => Role::Source,
        "--unix-socket" | "--abstract-unix-socket" => Role::Local,
        "-G" | "--get" => Role::Get,
        "-A"
        | "-C"
        | "-D"
        | "-E"
        | "-H"
        | "-P"
        | "-Q"
        | "-U"
        | "-X"
        | "-Y"
        | "-b"
        | "-c"
        | "-e"
        | "-h"
        | "-m"
        | "-o"
        | "-r"
        | "-t"
        | "-u"
        | "-w"
        | "-y"
        | "-z"
        | "--user-agent"
        | "--header"
        | "--request"
        | "--output"
        | "--user"
        | "--cookie"
        | "--cookie-jar"
        | "--referer"
        | "--max-time"
        | "--connect-timeout"
        | "--retry"
        | "--cacert"
        | "--cert"
        | "--key"
        | "--resolve"
        | "--connect-to"
        | "--range"
        | "--write-out"
        | "--proxy-user"
        | "--limit-rate"
        | "--max-filesize"
        | "--interface"
        | "--dns-servers"
        | "--output-dir"
        | "--retry-delay"
        | "--retry-max-time"
        | "--noproxy"
        | "--capath"
        | "--ciphers"
        | "--continue-at"
        | "--dump-header"
        | "--engine"
        | "--expect100-timeout"
        | "--happy-eyeballs-timeout-ms"
        | "--keepalive-time"
        | "--local-port"
        | "--login-options"
        | "--mail-from"
        | "--mail-rcpt"
        | "--netrc-file"
        | "--oauth2-bearer"
        | "--pass"
        | "--proto"
        | "--proto-redir"
        | "--pubkey"
        | "--quote"
        | "--sasl-authzid"
        | "--service-name"
        | "--socks4"
        | "--socks4a"
        | "--socks5"
        | "--socks5-hostname"
        | "--telnet-option"
        | "--tls-max"
        | "--trace"
        | "--trace-ascii"
        | "--unix-socket-path"
        | "--variable"
        | "--aws-sigv4" => Role::Value,
        _ => Role::Flag,
    }
}

fn wget_role(option: &str) -> Role {
    match option {
        "--post-data" | "--post-file" | "--body-data" | "--body-file" => Role::Upload,
        "-i" | "--input-file" => Role::Source,
        "-A" | "-B" | "-D" | "-I" | "-O" | "-P" | "-Q" | "-R" | "-T" | "-U" | "-X" | "-a"
        | "-e" | "-l" | "-o" | "-t" | "-w" | "--output-document" | "--user-agent" | "--header"
        | "--method" | "--directory-prefix" | "--tries" | "--timeout" | "--wait" | "--user"
        | "--password" | "--load-cookies" | "--save-cookies" | "--referer" | "--level" => {
            Role::Value
        }
        _ => Role::Flag,
    }
}

/// Walk options with role lookup: long `--x=v`, short clusters where the
/// first value-taking letter consumes the rest or the next word.
fn parse(args: &[Word], role_of: fn(&str) -> Role) -> (Vec<Role>, Vec<String>) {
    let mut roles = Vec::new();
    let mut urls = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let t = args[i].text();
        if t == "--" {
            urls.extend(args[i + 1..].iter().map(|w| w.text().to_string()));
            break;
        }
        if let Some(long) = t.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v.to_string())),
                None => (t.to_string(), None),
            };
            let role = role_of(&name);
            roles.push(role);
            let takes = !matches!(role, Role::Flag | Role::Get);
            let value = if takes && inline.is_none() {
                i += 1;
                args.get(i).map(|w| w.text().to_string())
            } else {
                inline
            };
            if role == Role::Url {
                if let Some(v) = value.filter(|v| !v.is_empty()) {
                    urls.push(v);
                }
            }
            i += 1;
            continue;
        }
        if t.starts_with('-') && t.len() > 1 {
            let chars: Vec<char> = t[1..].chars().collect();
            for (j, c) in chars.iter().enumerate() {
                let role = role_of(&format!("-{c}"));
                roles.push(role);
                if !matches!(role, Role::Flag | Role::Get) {
                    let value = if j + 1 < chars.len() {
                        chars[j + 1..].iter().collect::<String>()
                    } else {
                        i += 1;
                        args.get(i)
                            .map(|w| w.text().to_string())
                            .unwrap_or_default()
                    };
                    if role == Role::Url && !value.is_empty() {
                        urls.push(value);
                    }
                    break;
                }
            }
            i += 1;
            continue;
        }
        urls.push(t.to_string());
        i += 1;
    }
    (roles, urls)
}

fn is_loopback(url: &str) -> bool {
    // The RAW (un-decoded) host. A loopback result is an ALLOWANCE: it
    // suppresses the upload-remote deny, so it must be EXACT and never broader
    // than the resolver (an over-broad loopback would PERMIT an exfiltrating
    // upload). We do not percent-decode here (decoding is metadata-only), and a
    // host that does not canonicalize to a concrete loopback/unspecified
    // address and is not localhost is NOT loopback. `extract_host` returns None
    // for an unexpanded `$`/backtick host, which is likewise not loopback.
    let Some(host) = extract_host(url) else {
        return false;
    };
    host == "localhost" || host.ends_with(".localhost") || is_loopback_ip(&host)
}

fn judge(an: &Analyzer<'_>, cx: &Cx, roles: &[Role], urls: &[String]) {
    let get = roles.contains(&Role::Get);
    let sends = roles.contains(&Role::Upload) || (roles.contains(&Role::Data) && !get);
    if !sends || roles.contains(&Role::Local) {
        return;
    }
    if !urls.is_empty() && urls.iter().all(|u| is_loopback(u)) {
        return;
    }
    an.rule(
        cx,
        Finding::deny("network.upload-remote", Intent::ManualOnly, UPLOAD),
    );
}

fn curl(an: &Analyzer<'_>, cx: &Cx, args: &[Word]) {
    let (roles, urls) = parse(args, curl_role);
    judge(an, cx, &roles, &urls);
}

fn wget(an: &Analyzer<'_>, cx: &Cx, args: &[Word]) {
    let (roles, urls) = parse(args, wget_role);
    judge(an, cx, &roles, &urls);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_boundaries() {
        assert!(names_metadata_host(
            "http://169.254.169.254/latest/meta-data/"
        ));
        assert!(names_metadata_host(
            "169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
        ));
        assert!(names_metadata_host("http://[fd00:ec2::254]/"));
        assert!(!names_metadata_host("http://169.254.169.2540/"));
        assert!(!names_metadata_host(
            "http://metadata.google.internal.example.com/"
        ));
    }

    #[test]
    fn loopback() {
        assert!(is_loopback("http://localhost:3000/api"));
        assert!(is_loopback("127.0.0.1:8080"));
        assert!(is_loopback("http://[::1]:8080/"));
        assert!(is_loopback("http://api.localhost/"));
        assert!(!is_loopback("http://localhost.example.com/"));
        assert!(!is_loopback("http://$HOST:3000/api"));
    }

    // Need (a): the reproduced numeric-IP bypass (IP-BYPASS\probe_result.txt).
    // Need (e): direct coverage of canonicalize_ipv4 / extract_host / the
    // decoded metadata terms. Each trap is paired with a control.

    #[test]
    fn metadata_numeric_and_mapped() {
        // traps: numeric and mapped spellings of 169.254.169.254, now DETECTED
        assert!(names_metadata_host("http://0xA9FEA9FE/"));
        assert!(names_metadata_host("http://2852039166/"));
        assert!(names_metadata_host("http://[::ffff:a9fe:a9fe]/"));
        // controls
        assert!(names_metadata_host("http://169.254.169.254/")); // literal, untouched regex
        assert!(!names_metadata_host("http://169.254.169.2540/")); // boundary
        assert!(!names_metadata_host("http://12345/")); // -> 0.0.48.57, remote
        assert!(!names_metadata_host("http://[::ffff:a9fe:a9fd]/")); // mapped 169.254.169.253
    }

    #[test]
    fn metadata_unbracketed_ipv6() {
        // round-2 finding 1: an unbracketed IPv6 host must not be truncated
        assert!(names_metadata_host("fd00:0ec2:0:0:0:0:0:254")); // standalone (e.g. nc -6 ... 80)
        assert!(names_metadata_host("http://[fd00:0ec2:0:0:0:0:0:254]/")); // bracketed expanded
                                                                           // controls
        assert!(!names_metadata_host("fd00:0ec2:0:0:0:0:0:253"));
        assert!(!names_metadata_host("http://example.com:8080/")); // one-colon host:port
    }

    #[test]
    fn metadata_percent_encoded() {
        // round-2 finding 2: percent-encoded numeric host
        assert!(names_metadata_host(
            "http://%31%36%39.254.169.254/latest/meta-data/"
        ));
        assert!(!names_metadata_host("http://%31%36%39.254.169.253/"));
        // the encoded-hostname blocker: regex must run on the decoded host
        assert!(names_metadata_host(
            "http://%6d%65%74%61%64%61%74%61.google.internal/"
        ));
        assert!(!names_metadata_host(
            "http://%6d%65%74%61%64%61%74%61.google.example.com/"
        ));
    }

    #[test]
    fn loopback_numeric_and_mapped() {
        // numeric spellings of loopback, now recognized (upload permitted = local)
        assert!(is_loopback("http://127.1/"));
        assert!(is_loopback("http://2130706433/"));
        assert!(is_loopback("http://0x7f.0.0.1/"));
        assert!(is_loopback("http://0177.0.0.1/"));
        assert!(is_loopback("http://[::ffff:7f00:1]/"));
        assert!(is_loopback("http://127.0.0.1/"));
        assert!(is_loopback("http://0.0.0.0/"));
        // controls: NON-local hosts must stay NOT loopback (upload denied)
        assert!(!is_loopback("http://12345/")); // 0.0.48.57
        assert!(!is_loopback("http://example.com/"));
        assert!(!is_loopback("http://[::ffff:5db8:d822]/")); // mapped 93.184.216.34, remote
        assert!(!is_loopback("http://[::127.0.0.1]/")); // IPv4-COMPATIBLE, pins to_ipv4_mapped
        assert!(!is_loopback("http://[::]/")); // bare unspecified IPv6 not exempted
    }

    #[test]
    fn loopback_allowance_does_not_decode() {
        // a percent-encoded loopback spelling is NOT granted the exemption
        // (fail-safe: the allowance uses the raw host). curl would reach
        // 127.0.0.1, but the gate denies the upload rather than over-permit.
        assert!(!is_loopback("http://%31%32%37.0.0.1/"));
    }

    #[test]
    fn inet_aton_canonicalization() {
        // byte-absorption pair: 43518 = 0xA9FE, 43517 = 0xA9FD
        assert_eq!(
            canonicalize_ipv4("169.254.43518"),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert_eq!(
            canonicalize_ipv4("169.254.43517"),
            Some(Ipv4Addr::new(169, 254, 169, 253))
        );
        // bases
        assert_eq!(
            canonicalize_ipv4("0x7f.0.0.1"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            canonicalize_ipv4("0177.0.0.1"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            canonicalize_ipv4("2130706433"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        // rejections (no wrapping, no sign, no empty, no 5-part, no bad octet)
        assert_eq!(canonicalize_ipv4("4294967296"), None); // > u32::MAX
        assert_eq!(canonicalize_ipv4("169.254.169.2540"), None); // octet > 255
        assert_eq!(canonicalize_ipv4("1.2.3.4.5"), None); // too many parts
        assert_eq!(canonicalize_ipv4("169..254.1"), None); // empty part
        assert_eq!(canonicalize_ipv4("+127.0.0.1"), None); // sign
        assert_eq!(canonicalize_ipv4("0x"), None); // empty hex
    }

    #[test]
    fn extract_host_shapes() {
        assert_eq!(
            extract_host("--url=http://0xA9FEA9FE/").as_deref(),
            Some("0xa9fea9fe")
        );
        assert_eq!(
            extract_host("http://user:tok@127.0.0.1:8080/x").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            extract_host("fd00:0ec2:0:0:0:0:0:254").as_deref(),
            Some("fd00:0ec2:0:0:0:0:0:254")
        );
        assert_eq!(extract_host("http://[::1]:8080/").as_deref(), Some("::1"));
        assert_eq!(extract_host("http://[::ffff:7f00:1/").as_deref(), None); // malformed bracket
        assert_eq!(extract_host("http://$HOST/").as_deref(), None); // unexpanded var
    }
}
