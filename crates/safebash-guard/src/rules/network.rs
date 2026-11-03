//! Network: cloud metadata endpoints and uploads to remote hosts
//! (cc-safety-net `src/gate/analyzer/network.ts`).

use crate::analyze::{command_name, Analyzer, Cx};
use crate::model::Word;
use crate::verdict::{Finding, Intent};
use regex::Regex;
use std::sync::OnceLock;

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

/// Whether `token` names a metadata host with proper boundaries
/// (`169.254.169.2540` and `metadata.google.internal.example.com` do not).
pub fn names_metadata_host(token: &str) -> bool {
    metadata_host().find_iter(token).any(|m| {
        let before = token[..m.start()].chars().next_back();
        let after_text = &token[m.end()..];
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
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = host_port.rsplit_once('@').map_or(host_port, |(_, h)| h);
    let host = if host_port.starts_with('[') {
        host_port
            .split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or(host_port).to_string()
    };
    let host = host.to_ascii_lowercase();
    if host.contains('$') || host.contains('`') {
        return false;
    }
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "0.0.0.0"
        || host == "[::1]"
        || host.split('.').next() == Some("127") && host.split('.').count() == 4
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
}
