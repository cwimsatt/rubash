//! The rubash execution gate backed by the guard.

use rubash::exec_gate::{
    CommandCheck, ExecGate, GateVerdict, RedirectAccess, RedirectCheck, SpawnCheck,
};
use safebash_guard::analyze::{command_name, shell_quote};
use safebash_guard::model::{Access, Word};
use safebash_guard::verdict::Layer;
use safebash_guard::{Decision, Guard};
use std::collections::HashMap;

/// Environment variables whose *change during the session* is judged
/// like a prefix assignment (`export GIT_SSH_COMMAND=...; git push`).
/// Values inherited from the user's environment are trusted.
const SESSION_SENSITIVE: &[&str] = &[
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_SSH_VARIANT",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "BASH_ENV",
    "ENV",
    "PARALLEL",
];

pub struct SafebashGate {
    guard: Guard,
    initial: HashMap<String, Option<String>>,
}

impl SafebashGate {
    pub fn new(guard: Guard) -> SafebashGate {
        let initial = SESSION_SENSITIVE
            .iter()
            .map(|name| ((*name).to_string(), std::env::var(name).ok()))
            .collect();
        SafebashGate { guard, initial }
    }

    fn verdict(decision: Decision) -> GateVerdict {
        match decision {
            Decision::Allow => GateVerdict::Allow,
            Decision::Deny { message } => GateVerdict::Deny { message },
        }
    }
}

/// The approval key of a command: its name and arguments, so the dispatch
/// layer's `rm` and the spawn layer's `/usr/bin/rm` are the same command.
fn approval_key(argv: &[String]) -> Vec<String> {
    let mut key = argv.to_vec();
    if let Some(first) = key.first_mut() {
        if let Some(name) = command_name(&Word::Lit(first.clone())) {
            *first = name;
        }
    }
    key
}

fn display(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

impl ExecGate for SafebashGate {
    fn check_command(&self, check: &CommandCheck<'_>) -> GateVerdict {
        let mut assignments: Vec<(String, String)> = check.assignments.to_vec();
        for name in SESSION_SENSITIVE {
            let now = check.env.get(*name);
            let before = self.initial.get(*name).cloned().flatten();
            if let Some(value) = now {
                if before.as_deref() != Some(value.as_str())
                    && !assignments.iter().any(|(n, _)| n == name)
                {
                    assignments.push(((*name).to_string(), value.clone()));
                }
            }
        }
        let report = self.guard.analyze_argv(check.argv, &assignments, check.cwd);
        let key = approval_key(check.argv);
        Self::verdict(self.guard.decide(
            &report,
            Layer::Dispatch,
            &display(check.argv),
            Some(check.cwd),
            Some(&key),
        ))
    }

    fn check_redirect(&self, check: &RedirectCheck<'_>) -> GateVerdict {
        let access = match check.access {
            RedirectAccess::Read => Access::Read,
            RedirectAccess::Write => Access::Write,
            RedirectAccess::Append => Access::Append,
            RedirectAccess::ReadWrite => Access::ReadWrite,
        };
        let report = self
            .guard
            .analyze_redirect(check.fd, access, check.target, check.cwd);
        let op = match check.access {
            RedirectAccess::Read => "<",
            RedirectAccess::Write => ">",
            RedirectAccess::Append => ">>",
            RedirectAccess::ReadWrite => "<>",
        };
        let text = format!("{op} {}", shell_quote(check.target));
        Self::verdict(
            self.guard
                .decide(&report, Layer::Redirect, &text, Some(check.cwd), None),
        )
    }

    fn check_spawn(&self, check: &SpawnCheck) -> GateVerdict {
        let mut argv = vec![check.program.to_string_lossy().into_owned()];
        argv.extend(check.args.iter().map(|a| a.to_string_lossy().into_owned()));
        let cwd = check
            .cwd
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_default();
        let report = self.guard.analyze_argv(&argv, &[], &cwd);
        let key = approval_key(&argv);
        Self::verdict(self.guard.decide(
            &report,
            Layer::Spawn,
            &display(&argv),
            Some(&cwd),
            Some(&key),
        ))
    }
}
