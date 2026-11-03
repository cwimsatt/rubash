//! Findings, decisions and the agent-facing denial text.

use serde::Serialize;
use std::borrow::Cow;

/// What the guard wants done with a command. Ordered: a stricter action
/// always wins when findings are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    /// Run only after a human confirms on the controlling terminal. With
    /// no usable terminal this is a denial.
    Confirm,
    Deny,
}

/// The follow-up an agent should take after a block (harvested from
/// cc-safety-net's block intents, `src/core/denial.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    /// Never acceptable: stop, report, carry on with the rest of the task.
    HardStop,
    /// A safer form exists and is described in the reason.
    UseAlternative,
    /// Retry with a narrower, explicit target.
    ScopeDown,
    /// Only a human should run this.
    ManualOnly,
    /// The command could not be analyzed: simplify it.
    StopAndExplain,
}

impl Intent {
    fn footer(self) -> &'static str {
        match self {
            Intent::HardStop => {
                "Do not retry this operation or attempt any workaround (other tools, flags, or paths). Report the block to the user and continue with the rest of the task."
            }
            Intent::UseAlternative => {
                "Do not retry the blocked form. Continue the task using the safer alternative described above."
            }
            Intent::ScopeDown => {
                "Retry with a narrower, explicit target as described above. Escalate to the user if the broad operation is truly required."
            }
            Intent::ManualOnly => {
                "If this operation is truly needed, ask the user for explicit permission and have them run the command manually."
            }
            Intent::StopAndExplain => {
                "Do not brute-force variants. Simplify or restructure the command so it can be analyzed, or report the block to the user."
            }
        }
    }
}

/// Where in the shell a finding was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    /// Whole input analyzed before anything ran.
    Preflight,
    /// One expanded command at the dispatch funnel.
    Dispatch,
    /// One expanded redirection target.
    Redirect,
    /// One child process about to start.
    Spawn,
}

/// One rule match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule: Cow<'static, str>,
    pub action: Action,
    pub intent: Intent,
    pub reason: String,
    /// The part of the command that triggered the rule, when narrower than
    /// the whole command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment: Option<String>,
}

impl Finding {
    pub fn deny(
        rule: impl Into<Cow<'static, str>>,
        intent: Intent,
        reason: impl Into<String>,
    ) -> Finding {
        Finding {
            rule: rule.into(),
            action: Action::Deny,
            intent,
            reason: reason.into(),
            segment: None,
        }
    }

    pub fn confirm(
        rule: impl Into<Cow<'static, str>>,
        intent: Intent,
        reason: impl Into<String>,
    ) -> Finding {
        Finding {
            rule: rule.into(),
            action: Action::Confirm,
            intent,
            reason: reason.into(),
            segment: None,
        }
    }

    pub fn with_segment(mut self, segment: impl Into<String>) -> Finding {
        self.segment = Some(segment.into());
        self
    }
}

/// The combined result of analyzing one command or script.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    /// The strictest action among the findings.
    pub fn action(&self) -> Action {
        self.findings
            .iter()
            .map(|finding| finding.action)
            .max()
            .unwrap_or(Action::Allow)
    }

    /// The finding that decides the outcome: the first one with the
    /// strictest action.
    pub fn primary(&self) -> Option<&Finding> {
        let action = self.action();
        self.findings
            .iter()
            .find(|finding| finding.action == action && action != Action::Allow)
    }

    pub fn extend(&mut self, findings: impl IntoIterator<Item = Finding>) {
        for finding in findings {
            if !self.findings.contains(&finding) {
                self.findings.push(finding);
            }
        }
    }
}

/// Render the denial an agent (or person) reads on stderr.
pub fn denial_message(
    finding: &Finding,
    command: &str,
    cwd: Option<&str>,
    confirm: bool,
) -> String {
    const MAX: usize = 200;
    let excerpt = |text: &str| -> String {
        let text = crate::redact::redact(text);
        if text.chars().count() > MAX {
            let cut: String = text.chars().take(MAX).collect();
            format!("{cut}...")
        } else {
            text
        }
    };
    let mut lines = vec![
        if confirm {
            "safebash: CONFIRMATION REQUIRED (no usable terminal; command not run)".to_string()
        } else {
            "safebash: BLOCKED by safety policy".to_string()
        },
        format!("  Reason: {}", crate::redact::redact(&finding.reason)),
        format!("  Rule: {}", finding.rule),
        format!("  Command: {}", excerpt(command)),
    ];
    if let Some(segment) = &finding.segment {
        if segment != command {
            lines.push(format!("  Segment: {}", excerpt(segment)));
        }
    }
    if let Some(cwd) = cwd {
        lines.push(format!("  Working directory: {}", excerpt(cwd)));
    }
    let footer = if confirm {
        "A human must approve this command at a terminal. Ask the user to run it themselves, or to rerun it in an interactive safebash session."
    } else {
        finding.intent.footer()
    };
    lines.push(format!("  {footer}"));
    lines.join("\n")
}
