//! The second-opinion hook (phase 2: TypeSafe Jev).
//!
//! A secondary check is consulted only for commands the deterministic rules
//! already let through (or would let a person confirm), at the dispatch
//! layer, where the command is fully expanded. It can only *escalate* the
//! verdict — Allow < Confirm < Deny — never relax a rule's decision: a
//! model can be steered by the very text it judges, so it must not be able
//! to unblock anything. The guard owns redaction, the deadline, the mode
//! and the audit record; a checker only answers.
//!
//! See `docs/safebash/design.md`, "Phase 2: Jev secondary check", for the
//! question set and the wire mapping.

use crate::verdict::Action;
use std::path::Path;
use std::time::Instant;

/// How the guard uses a registered checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryMode {
    /// Not consulted.
    Off,
    /// Consulted and audited; never changes a decision. The rollout mode.
    Shadow,
    /// Consulted; an escalation is applied.
    Enforce,
}

/// What the checker sees. Every string is already redacted.
#[derive(Debug, Clone)]
pub struct CommandFacts<'a> {
    /// The expanded words.
    pub argv: &'a [String],
    /// Names (never values) of prefix assignments.
    pub env_names: &'a [String],
    pub cwd: &'a Path,
    /// The deterministic verdict so far.
    pub rule_action: Action,
    /// Rule ids that matched (empty for a clean Allow).
    pub rules: &'a [&'static str],
}

/// A checker's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum SecondOpinion {
    NoObjection,
    /// Raise the verdict to `to` (ignored unless stricter than the rule
    /// verdict). `reason` is fixed wording tied to the question that fired.
    Escalate {
        to: Action,
        reason: String,
    },
    /// The checker could not answer (timeout, unavailable, budget). Never
    /// recorded as a clean pass.
    NotRun {
        why: &'static str,
    },
}

/// A second-opinion checker.
pub trait SecondaryCheck: Send + Sync {
    /// Must return by `deadline`; the guard treats a late answer as
    /// `NotRun`.
    fn check(&self, facts: &CommandFacts<'_>, deadline: Instant) -> SecondOpinion;
}

/// Combine a rule verdict with a second opinion under `mode`.
pub fn merge(rule: Action, opinion: &SecondOpinion, mode: SecondaryMode) -> Action {
    match (mode, opinion) {
        (SecondaryMode::Enforce, SecondOpinion::Escalate { to, .. }) => rule.max(*to),
        _ => rule,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_opinion_only_escalates() {
        let deny = SecondOpinion::Escalate {
            to: Action::Deny,
            reason: "destroys data".into(),
        };
        let allow = SecondOpinion::Escalate {
            to: Action::Allow,
            reason: String::new(),
        };
        assert_eq!(
            merge(Action::Allow, &deny, SecondaryMode::Enforce),
            Action::Deny
        );
        assert_eq!(
            merge(Action::Deny, &allow, SecondaryMode::Enforce),
            Action::Deny
        );
        assert_eq!(
            merge(Action::Allow, &deny, SecondaryMode::Shadow),
            Action::Allow
        );
        assert_eq!(
            merge(
                Action::Confirm,
                &SecondOpinion::NotRun { why: "timeout" },
                SecondaryMode::Enforce
            ),
            Action::Confirm
        );
    }
}
