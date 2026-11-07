//! Executor side of the host execution gate (`crate::exec_gate`).
//!
//! Two consult points live here:
//!
//! - [`Executor::exec_gate_denies`] — the dispatch funnel in
//!   `execute_command` asks it about every expanded simple command, and
//!   about that command's file redirections, before dispatching.
//! - [`Executor::exec_gate_redirect_target`] — `expand_redirect_target`
//!   passes every expanded file-redirection operand through it, whichever
//!   executor path (simple command, compound command, `exec`, pipeline
//!   stage) is about to open the file. A denied operand is replaced by
//!   [`DENIED_REDIRECT_TARGET`], a path that cannot be opened, so the
//!   redirection fails and the command never runs.

use super::*;
use crate::exec_gate::{self, CommandCheck, GateVerdict, RedirectAccess, RedirectCheck};

/// The operand a denied redirection is rewritten to. Opening it fails on
/// every platform (a path below a file that is not a directory on Unix; an
/// illegal name on Windows), so the redirection — and its command — fails.
#[cfg(unix)]
pub(crate) const DENIED_REDIRECT_TARGET: &str = "/dev/null/safebash-denied-redirection";
#[cfg(not(unix))]
pub(crate) const DENIED_REDIRECT_TARGET: &str = "\\\\?\\safebash-denied-redirection<>";

impl Executor {
    /// Whether the gate denies the expanded command `cmd` (its words or
    /// one of its file redirections). The gate's diagnostic has been
    /// reported on stderr when this returns `true`.
    pub(in crate::executor) fn exec_gate_denies(&self, cmd: &CommandNode) -> bool {
        let Some(gate) = exec_gate::active() else {
            return false;
        };
        let redirect_denied = cmd.redirects.iter().any(|redirect| {
            redirect_file_access(redirect).is_some()
                && self.expand_redirect_target(redirect) == DENIED_REDIRECT_TARGET
        });
        if redirect_denied {
            return true;
        }
        if cmd.words.is_empty() {
            return false;
        }
        let check = CommandCheck {
            argv: &cmd.words,
            assignments: &cmd.assignments,
            cwd: &self.shell_state.cwd,
            env: &self.shell_state.env_vars,
        };
        match gate.check_command(&check) {
            GateVerdict::Allow => false,
            GateVerdict::Deny { message } => {
                eprintln!("{message}");
                true
            }
        }
    }

    /// Pass one expanded redirection operand through the gate: the operand
    /// itself when allowed, [`DENIED_REDIRECT_TARGET`] (after reporting the
    /// gate's diagnostic) when denied.
    pub(in crate::executor) fn exec_gate_redirect_target(
        &self,
        redirect: &crate::parser::Redirect,
        expanded: String,
    ) -> String {
        let Some(gate) = exec_gate::active() else {
            return expanded;
        };
        let Some(access) = redirect_file_access(redirect) else {
            return expanded;
        };
        let target = expanded.strip_prefix('&').unwrap_or(&expanded);
        let check = RedirectCheck {
            fd: redirect.fd,
            access,
            target,
            cwd: &self.shell_state.cwd,
        };
        match gate.check_redirect(&check) {
            GateVerdict::Allow => expanded,
            GateVerdict::Deny { message } => {
                eprintln!("{message}");
                DENIED_REDIRECT_TARGET.to_string()
            }
        }
    }
}

/// The file access a redirection performs, including the `>&word` /
/// `<&word` forms whose operand names a file rather than a descriptor
/// (GNU redir.c: a non-numeric `>&word` is `&>word`).
fn redirect_file_access(redirect: &crate::parser::Redirect) -> Option<RedirectAccess> {
    if let Some(access) = exec_gate::redirect_access(&redirect.kind) {
        return Some(access);
    }
    let operand = redirect
        .target
        .strip_prefix('&')
        .unwrap_or(&redirect.target);
    let names_descriptor =
        operand == "-" || (!operand.is_empty() && operand.bytes().all(|b| b.is_ascii_digit()));
    match redirect.kind {
        crate::parser::RedirectKind::DuplicateOutput if !names_descriptor => {
            Some(RedirectAccess::Write)
        }
        _ => None,
    }
}
