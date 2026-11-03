//! The guard facade: analysis entry points and the decision procedure.

use crate::analyze::{Analyzer, Host, Stage, Staged};
use crate::audit::{decision_word, AuditLog, Entry};
use crate::model::{Access, Arg, CommandSite, Redirect, ScriptParser, SimpleCommand};
use crate::paths::NormPath;
use crate::platform::{confirm_on_terminal, Confirmation};
use crate::policy::{ConfirmMode, Policy, RuleSetting};
use crate::secondary::{merge, CommandFacts, SecondOpinion, SecondaryCheck, SecondaryMode};
use crate::verdict::{denial_message, Action, Finding, Layer, Report};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Rules no configuration can switch off or soften.
pub const CATASTROPHIC: &[&str] = &[
    "rm.recursive-force-root-or-home",
    "rm.git-metadata",
    "find.delete-git-metadata",
    "powershell.remove-item-root-or-home",
    "powershell.remove-item-recursive-force-root-or-home",
    "powershell.remove-item-git-metadata",
    "powershell.nested-recursive-delete-unread",
    "cmd.recursive-delete-root-or-home",
    "cmd.recursive-delete-escaped-quote",
    "cmd.recursive-delete-git-metadata",
];

/// Whether a rule is fixed: catastrophic, a self-protection guard, or an
/// analysis-limit rule.
pub fn is_fixed(rule: &str) -> bool {
    CATASTROPHIC.contains(&rule) || rule.starts_with("guard.") || rule.starts_with("analysis.")
}

/// What the shell does with a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { message: String },
}

/// The configured guard for one process.
pub struct Guard {
    pub policy: Policy,
    pub host: Host,
    parser: Option<Box<dyn ScriptParser>>,
    audit: AuditLog,
    secondary: Option<(Box<dyn SecondaryCheck>, SecondaryMode)>,
    approvals: Mutex<Vec<(String, Instant)>>,
    /// Ask on the terminal for confirmable findings (off in tests).
    pub interactive_confirm: bool,
}

impl Guard {
    pub fn new(
        policy: Policy,
        host: Host,
        parser: Option<Box<dyn ScriptParser>>,
        audit: AuditLog,
    ) -> Guard {
        Guard {
            policy,
            host,
            parser,
            audit,
            secondary: None,
            approvals: Mutex::new(Vec::new()),
            interactive_confirm: true,
        }
    }

    /// Register a second-opinion checker (phase 2: Jev).
    pub fn with_secondary(mut self, check: Box<dyn SecondaryCheck>, mode: SecondaryMode) -> Guard {
        self.secondary = Some((check, mode));
        self
    }

    /// Run an analysis; an internal failure (a panic) is a denial, never
    /// an allow (cc-safety-net `analysis.failed-closed`).
    fn guarded(&self, analysis: impl FnOnce() -> Report) -> Report {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(analysis)) {
            Ok(report) => report,
            Err(_) => Report {
                findings: vec![Finding::deny(
                    "analysis.failed-closed",
                    crate::verdict::Intent::StopAndExplain,
                    "safebash failed closed because command analysis failed unexpectedly. This is not caused by your command. Report it to the user.",
                )],
            },
        }
    }

    fn analyzer(&self, runtime: bool) -> Analyzer<'_> {
        Analyzer::new(&self.policy, &self.host, self.parser.as_deref(), runtime)
    }

    fn cwd_of(&self, cwd: Option<&Path>) -> Option<NormPath> {
        cwd.and_then(|c| self.host.norm_abs(c))
            .or_else(|| self.host.workspace.clone())
    }

    /// Static analysis of script text (the preflight layer).
    pub fn analyze_source(&self, source: &str, cwd: Option<&Path>) -> Report {
        self.guarded(|| self.analyze_source_inner(source, cwd))
    }

    fn analyze_source_inner(&self, source: &str, cwd: Option<&Path>) -> Report {
        let an = self.analyzer(false);
        match &self.parser {
            Some(parser) => {
                let script = parser.parse(source);
                an.script(&script, self.cwd_of(cwd), 0);
            }
            None => {
                crate::rules::text::scan(&an, &crate::analyze::Cx::new(self.cwd_of(cwd)), source)
            }
        }
        self.report(an.take_findings())
    }

    /// One expanded command (the dispatch and spawn layers).
    pub fn analyze_argv(
        &self,
        argv: &[String],
        assignments: &[(String, String)],
        cwd: &Path,
    ) -> Report {
        self.guarded(|| self.analyze_argv_inner(argv, assignments, cwd))
    }

    fn analyze_argv_inner(
        &self,
        argv: &[String],
        assignments: &[(String, String)],
        cwd: &Path,
    ) -> Report {
        let an = self.analyzer(true);
        let cwd = self.cwd_of(Some(cwd));
        let site = CommandSite::new(SimpleCommand {
            assignments: assignments
                .iter()
                .map(|(n, v)| (n.clone(), Arg::Value(v.clone())))
                .collect(),
            words: argv.iter().map(|w| Arg::Value(w.clone())).collect(),
            redirects: Vec::new(),
            stdin_text: None,
        });
        an.site(&site, cwd, 0);
        self.report(an.take_findings())
    }

    /// One expanded redirection target.
    pub fn analyze_redirect(
        &self,
        fd: Option<u32>,
        access: Access,
        target: &str,
        cwd: &Path,
    ) -> Report {
        self.guarded(|| self.analyze_redirect_inner(fd, access, target, cwd))
    }

    fn analyze_redirect_inner(
        &self,
        fd: Option<u32>,
        access: Access,
        target: &str,
        cwd: &Path,
    ) -> Report {
        let an = self.analyzer(true);
        let site = CommandSite::new(SimpleCommand {
            redirects: vec![Redirect {
                fd,
                access,
                target: Arg::Value(target.to_string()),
            }],
            ..SimpleCommand::default()
        });
        an.site(&site, self.cwd_of(Some(cwd)), 0);
        self.report(an.take_findings())
    }

    /// Apply per-rule settings and order the findings: strictest action
    /// first, then the earliest stage, then emission order.
    fn report(&self, staged: Vec<Staged>) -> Report {
        let confirmable = self.policy.confirm == ConfirmMode::Tty;
        let mut kept: Vec<(Stage, usize, Finding)> = Vec::new();
        for (index, Staged { stage, mut finding }) in staged.into_iter().enumerate() {
            let fixed = is_fixed(&finding.rule);
            match self.policy.rule_setting(&finding.rule) {
                Some(RuleSetting::Off) if !fixed => continue,
                Some(RuleSetting::Deny) => finding.action = Action::Deny,
                Some(RuleSetting::Confirm) if !fixed => finding.action = Action::Confirm,
                _ => {
                    // A person at the terminal may approve anything that is
                    // not fixed (safeexec's confirmation gate).
                    if confirmable && !fixed && finding.action == Action::Deny {
                        finding.action = Action::Confirm;
                    }
                }
            }
            kept.push((stage, index, finding));
        }
        kept.sort_by(|a, b| {
            b.2.action
                .cmp(&a.2.action)
                .then(a.0.cmp(&b.0))
                .then(a.1.cmp(&b.1))
        });
        Report {
            findings: kept.into_iter().map(|(_, _, f)| f).collect(),
        }
    }

    /// Turn a report into a decision: prompt for confirmation where allowed,
    /// consult the secondary check, write the audit record.
    pub fn decide(
        &self,
        report: &Report,
        layer: Layer,
        command: &str,
        cwd: Option<&Path>,
        argv: Option<&[String]>,
    ) -> Decision {
        let cwd_text = cwd.map(|c| c.to_string_lossy().into_owned());
        let mut action = report.action();
        let mut finding = report.primary().cloned();
        if action == Action::Allow && layer == Layer::Dispatch {
            if let (Some((check, mode)), Some(argv)) = (&self.secondary, argv) {
                if *mode != SecondaryMode::Off {
                    let opinion = check.check(
                        &CommandFacts {
                            argv,
                            env_names: &[],
                            cwd: cwd.unwrap_or(Path::new("/")),
                            rule_action: action,
                            rules: &[],
                        },
                        Instant::now() + Duration::from_secs(2),
                    );
                    let merged = merge(action, &opinion, *mode);
                    if let SecondOpinion::Escalate { reason, .. } = &opinion {
                        let shadow = Finding::deny(
                            "secondary.escalation",
                            crate::verdict::Intent::ManualOnly,
                            reason.clone(),
                        );
                        self.record(
                            if merged > action {
                                decision_word(merged)
                            } else {
                                "shadow"
                            },
                            layer,
                            command,
                            cwd_text.as_deref(),
                            Some(&shadow),
                        );
                        if merged > action {
                            action = merged;
                            finding = Some(shadow);
                        }
                    }
                }
            }
        }
        match action {
            Action::Allow => {
                if self.policy.audit_allowed {
                    self.record("allow", layer, command, cwd_text.as_deref(), None);
                }
                Decision::Allow
            }
            Action::Confirm => {
                let finding = finding.expect("a confirm action has a finding");
                let key = argv
                    .map(|a| a.join("\u{1f}"))
                    .unwrap_or_else(|| command.to_string());
                if self.consume_approval(&key) {
                    return Decision::Allow;
                }
                let answer = if self.interactive_confirm {
                    confirm_on_terminal(&format!("{} ({})", finding.reason, finding.rule), command)
                } else {
                    Confirmation::Unavailable
                };
                match answer {
                    Confirmation::Approved => {
                        self.record(
                            "confirmed",
                            layer,
                            command,
                            cwd_text.as_deref(),
                            Some(&finding),
                        );
                        self.remember_approval(key);
                        Decision::Allow
                    }
                    Confirmation::Declined => {
                        self.record(
                            "declined",
                            layer,
                            command,
                            cwd_text.as_deref(),
                            Some(&finding),
                        );
                        Decision::Deny {
                            message: format!("safebash: cancelled by user: {command}"),
                        }
                    }
                    Confirmation::Unavailable => {
                        self.record("deny", layer, command, cwd_text.as_deref(), Some(&finding));
                        Decision::Deny {
                            message: denial_message(&finding, command, cwd_text.as_deref(), true),
                        }
                    }
                }
            }
            Action::Deny => {
                let finding = finding.expect("a deny action has a finding");
                self.record("deny", layer, command, cwd_text.as_deref(), Some(&finding));
                Decision::Deny {
                    message: denial_message(&finding, command, cwd_text.as_deref(), false),
                }
            }
        }
    }

    fn record(
        &self,
        decision: &str,
        layer: Layer,
        command: &str,
        cwd: Option<&str>,
        finding: Option<&Finding>,
    ) {
        if !self.policy.audit {
            return;
        }
        self.audit.record(&Entry {
            decision,
            layer,
            level: self.policy.level.name(),
            command,
            cwd,
            finding,
            config_warning: !self.policy.warnings.is_empty(),
        });
    }

    /// An approval given at the dispatch layer covers the spawn of the same
    /// command a moment later, so a person is asked once.
    fn remember_approval(&self, key: String) {
        if let Ok(mut approvals) = self.approvals.lock() {
            approvals.retain(|(_, at)| at.elapsed() < Duration::from_secs(30));
            approvals.push((key, Instant::now()));
        }
    }

    fn consume_approval(&self, key: &str) -> bool {
        let Ok(mut approvals) = self.approvals.lock() else {
            return false;
        };
        approvals.retain(|(_, at)| at.elapsed() < Duration::from_secs(30));
        match approvals.iter().position(|(k, _)| k == key) {
            Some(index) => {
                approvals.remove(index);
                true
            }
            None => false,
        }
    }

    /// Approve a key without prompting (tests and the spawn layer's
    /// argv-to-key mapping).
    pub fn audit_dir(&self) -> Option<&Path> {
        self.audit.dir()
    }
}
