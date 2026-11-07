//! The analyzer: walks a script's commands and applies every rule.
//!
//! One traversal per command, in the order cc-safety-net evaluates a
//! segment (`src/gate/analyzer/segment.ts`):
//!
//! 1. substitutions inside the words run first, so they are analyzed first;
//! 2. redirections (device writes, secrets, protected files);
//! 3. the prelude: leading assignments, `sudo`, `env`, `command`,
//!    `builtin` are peeled with their option grammars;
//! 4. exec wrappers (`timeout`, `nice`, `nohup`, ...) are unwrapped by
//!    scanning forward for a protectable command name;
//! 5. shells, `eval`, `source`, `trap`, interpreters and awk recurse into
//!    the code they run;
//! 6. the command's own rules;
//! 7. an unknown head gets the embedded-suffix scan, so `ssh h rm -rf /`
//!    and `watch rm -rf /` are caught without per-tool knowledge.
//!
//! Findings carry a stage (guards, secrets, rules); the decision takes the
//! strictest action and, among those, the earliest stage, so the reported
//! rule matches cc-safety-net's "first stage that denies wins".

use crate::model::{Access, Arg, CommandSite, Origin, Script, ScriptParser, SimpleCommand, Word};
use crate::paths::{normalize, normalize_abs, NormPath, PathStyle};
use crate::policy::Policy;
use crate::rules;
use crate::verdict::{Finding, Intent};
use crate::words;
use std::cell::Cell;
use std::collections::HashMap;
use std::path::Path;

/// Maximum nesting of `bash -c`, `eval`, sourced files and called
/// functions (cc-safety-net: 10).
pub const MAX_DEPTH: usize = 10;
/// Work units (analyzed words) per evaluation before failing closed.
const WORK_BUDGET: usize = 200_000;

/// Facts about the host the rules judge against.
#[derive(Debug, Clone)]
pub struct Host {
    pub style: PathStyle,
    /// The real home directory (from the environment at startup).
    pub home: Option<NormPath>,
    /// The session's starting directory: "inside the workspace" is judged
    /// against it, never against a later `cd`.
    pub workspace: Option<NormPath>,
    pub temp_roots: Vec<NormPath>,
    /// safebash's own policy and state locations (self-protection):
    /// nothing may write into or delete these trees.
    pub protected: Vec<NormPath>,
    /// The subset of `protected` whose ancestors are also protected from
    /// recursive deletes and moves (the user config/state dirs, so
    /// `rm -rf ~/.config` is caught). A project `.safebash` is not one:
    /// a project may be deleted as a whole.
    pub protected_roots: Vec<NormPath>,
    /// Protected Git metadata of the workspace repository: the `.git`
    /// entry, git dir, common dir and hook directories.
    pub git_metadata: Vec<NormPath>,
    /// Values of the allowlisted variables static analysis may expand.
    pub vars: HashMap<String, String>,
    /// Command names that invoke safebash itself.
    pub self_names: Vec<String>,
}

impl Host {
    pub fn lookup(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }

    pub fn norm(&self, raw: &str, cwd: Option<&NormPath>) -> Option<NormPath> {
        normalize(raw, cwd, self.style)
    }

    pub fn norm_abs(&self, path: &Path) -> Option<NormPath> {
        normalize_abs(path, self.style)
    }
}

/// Which pass produced a finding; earlier stages win ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Guard,
    Secret,
    Rule,
}

/// A finding with its stage.
#[derive(Debug, Clone)]
pub struct Staged {
    pub stage: Stage,
    pub finding: Finding,
}

/// The per-command context rules read.
#[derive(Debug, Clone)]
pub struct Cx {
    /// Effective working directory (`None` when unknown).
    pub cwd: Option<NormPath>,
    /// Assignments in effect for this command (prefix, `env` wrapper).
    pub env: Vec<(String, Word)>,
    /// The producer stages when stdin is a pipe.
    pub pipe_in: Option<Vec<Vec<Word>>>,
    /// Heredoc or here-string text fed to stdin.
    pub stdin_text: Option<String>,
    /// stdin is redirected from a file.
    pub stdin_file: bool,
    /// The command runs as an xargs/parallel child: more arguments may be
    /// appended at run time.
    pub dynamic_input: bool,
    /// The command text (for `Segment:` lines).
    pub segment: String,
}

impl Cx {
    pub fn new(cwd: Option<NormPath>) -> Cx {
        Cx {
            cwd,
            env: Vec::new(),
            pipe_in: None,
            stdin_text: None,
            stdin_file: false,
            dynamic_input: false,
            segment: String::new(),
        }
    }

    /// The value of an assignment in effect, if known.
    pub fn env_value(&self, name: &str) -> Option<&Word> {
        self.env
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, w)| w)
    }
}

/// Walks scripts and commands.
pub struct Analyzer<'a> {
    pub policy: &'a Policy,
    pub host: &'a Host,
    pub parser: Option<&'a dyn ScriptParser>,
    /// Values are concrete (run-time gate) rather than source text.
    pub runtime: bool,
    work: Cell<usize>,
    out: std::cell::RefCell<Vec<Staged>>,
    functions: std::cell::RefCell<HashMap<String, Vec<CommandSite>>>,
    calling: std::cell::RefCell<Vec<String>>,
}

impl<'a> Analyzer<'a> {
    pub fn new(
        policy: &'a Policy,
        host: &'a Host,
        parser: Option<&'a dyn ScriptParser>,
        runtime: bool,
    ) -> Analyzer<'a> {
        Analyzer {
            policy,
            host,
            parser,
            runtime,
            work: Cell::new(0),
            out: Default::default(),
            functions: Default::default(),
            calling: Default::default(),
        }
    }

    /// Everything found so far, in emission order.
    pub fn take_findings(&self) -> Vec<Staged> {
        std::mem::take(&mut self.out.borrow_mut())
    }

    pub fn findings_len(&self) -> usize {
        self.out.borrow().len()
    }

    /// Keep only concrete findings emitted since `start` (a script file's
    /// uncertain results do not block), naming the file in each reason.
    pub fn retain_concrete_since(&self, start: usize, file: &str) {
        let mut out = self.out.borrow_mut();
        let tail: Vec<Staged> = out.drain(start..).collect();
        for mut staged in tail {
            let rule = staged.finding.rule.as_ref();
            let uncertain = rule.starts_with("analysis.")
                || rule.starts_with("raw-text.")
                || (rule.contains("dynamic") && !rule.starts_with("custom."))
                || rule == "interpreter.one-liner-paranoid";
            if uncertain {
                continue;
            }
            staged.finding.reason = format!("{file}: {}", staged.finding.reason);
            out.push(staged);
        }
    }

    pub fn emit(&self, stage: Stage, finding: Finding) {
        let mut out = self.out.borrow_mut();
        if !out
            .iter()
            .any(|s| s.finding.rule == finding.rule && s.finding.segment == finding.segment)
        {
            out.push(Staged { stage, finding });
        }
    }

    pub fn rule(&self, cx: &Cx, finding: Finding) {
        self.emit(Stage::Rule, with_segment(cx, finding));
    }

    pub fn capability_fail_closed(&self) -> bool {
        self.policy.capabilities.fail_closed
    }

    /// Charge work; `false` once the budget is exhausted (the caller stops
    /// and the evaluation fails closed).
    fn charge(&self, units: usize) -> bool {
        let used = self.work.get() + units;
        self.work.set(used);
        if used > WORK_BUDGET {
            self.emit(
                Stage::Rule,
                Finding::deny(
                    "analysis.derived-command-limit",
                    Intent::StopAndExplain,
                    "Command analysis exceeds safebash's work limit. Reduce nested or embedded command complexity and retry.",
                ),
            );
            return false;
        }
        true
    }

    /// Analyze a whole script (preflight), starting in `cwd`.
    pub fn script(&self, script: &Script, cwd: Option<NormPath>, depth: usize) {
        if let Some(error) = &script.parse_error {
            self.unparseable(error, script, depth);
        }
        // Function bodies count only where the function is called.
        for site in &script.sites {
            if let Some(name) = &site.function {
                self.functions
                    .borrow_mut()
                    .entry(name.clone())
                    .or_default()
                    .push(site.clone());
            }
        }
        let mut scope_cwd: HashMap<usize, Option<NormPath>> = HashMap::new();
        scope_cwd.insert(0, cwd.clone());
        for site in script.sites.iter().filter(|s| s.function.is_none()) {
            let here = match scope_cwd.get(&site.scope) {
                Some(cwd) => cwd.clone(),
                None => {
                    let parent = script.scope_parents.get(site.scope).copied().unwrap_or(0);
                    let inherited = scope_cwd.get(&parent).cloned().unwrap_or(cwd.clone());
                    scope_cwd.insert(site.scope, inherited.clone());
                    inherited
                }
            };
            let next = self.site(site, here.clone(), depth);
            scope_cwd.insert(site.scope, next);
        }
    }

    /// Analyze one command site; returns the cwd after it (for `cd`).
    pub fn site(
        &self,
        site: &CommandSite,
        cwd: Option<NormPath>,
        depth: usize,
    ) -> Option<NormPath> {
        let command = &site.command;
        let mut cx = Cx::new(cwd.clone());
        cx.stdin_text = command.stdin_text.clone();
        cx.segment = display_command(command);
        let lookup = |name: &str| self.lookup_var(name, &cx_env_names(&command.assignments));
        // Substitutions in assignments, words and redirect targets run
        // before the command: analyze them first.
        let mut bodies = Vec::new();
        let assignments: Vec<(String, Word)> = command
            .assignments
            .iter()
            .map(|(name, arg)| {
                let (word, subs) = self.eval_single(arg, &lookup);
                bodies.extend(subs);
                (name.clone(), word)
            })
            .collect();
        let mut argv: Vec<Word> = Vec::new();
        for arg in &command.words {
            let (mut list, subs) = self.eval_list(arg, &lookup);
            bodies.extend(subs);
            argv.append(&mut list);
        }
        let redirects: Vec<(Option<u32>, Access, Word)> = command
            .redirects
            .iter()
            .map(|r| {
                let (word, subs) = self.eval_single(&r.target, &lookup);
                bodies.extend(subs);
                (r.fd, r.access, word)
            })
            .collect();
        for body in bodies {
            self.nested(&body, cwd.clone(), depth, Origin::Substitution);
        }
        cx.env = assignments.clone();
        cx.stdin_file = redirects
            .iter()
            .any(|(fd, access, _)| access.reads() && fd.unwrap_or(0) == 0);
        if let Some(pipeline) = &site.pipeline {
            if pipeline.index > 0 {
                cx.pipe_in = Some(
                    pipeline.stages[..pipeline.index]
                        .iter()
                        .map(|stage| {
                            stage
                                .iter()
                                .flat_map(|arg| self.eval_list(arg, &lookup).0)
                                .collect()
                        })
                        .collect(),
                );
            }
        }
        for (fd, access, target) in &redirects {
            rules::redirect::check(self, &cx, *fd, *access, target, &argv);
        }
        rules::guards::assignments(self, &cx, &assignments);
        if argv.is_empty() {
            return cwd;
        }
        self.command(&argv, &cx, depth);
        // Static cd tracking within this scope.
        self.cd_after(&argv, cwd)
    }

    /// Analyze a concrete command (run time): every word is a value.
    pub fn runtime_command(
        &self,
        argv: &[String],
        assignments: &[(String, String)],
        cwd: &NormPath,
    ) {
        let site = CommandSite::new(SimpleCommand {
            assignments: assignments
                .iter()
                .map(|(n, v)| (n.clone(), Arg::Value(v.clone())))
                .collect(),
            words: argv.iter().map(|w| Arg::Value(w.clone())).collect(),
            redirects: Vec::new(),
            stdin_text: None,
        });
        self.site(&site, Some(cwd.clone()), 0);
    }

    fn lookup_var(&self, name: &str, prefix_names: &[String]) -> Option<String> {
        // A prefix assignment to the same name makes the inherited value
        // stale for this command.
        if prefix_names.iter().any(|n| n == name) {
            return None;
        }
        self.host.lookup(name)
    }

    fn eval_list(
        &self,
        arg: &Arg,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> (Vec<Word>, Vec<String>) {
        match arg {
            Arg::Value(text) => (vec![Word::Lit(text.clone())], Vec::new()),
            Arg::Raw(raw) => {
                let ev = words::evaluate(raw, lookup);
                (ev.words, ev.substitutions)
            }
        }
    }

    fn eval_single(
        &self,
        arg: &Arg,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> (Word, Vec<String>) {
        match arg {
            Arg::Value(text) => (Word::Lit(text.clone()), Vec::new()),
            Arg::Raw(raw) => {
                // Assignment values and redirect targets are not brace
                // expanded by the shell.
                let ev = words::evaluate(&raw.replace('{', "\u{0}").replace('}', "\u{1}"), lookup);
                let restore = |w: Word| -> Word {
                    let fix = |s: &str| s.replace('\u{0}', "{").replace('\u{1}', "}");
                    match w {
                        Word::Lit(s) => Word::Lit(fix(&s)),
                        Word::Glob(s) => Word::Glob(fix(&s)),
                        Word::Dyn(_) => Word::Dyn(raw.clone()),
                    }
                };
                let word = ev
                    .words
                    .into_iter()
                    .next()
                    .map(restore)
                    .unwrap_or(Word::Lit(String::new()));
                (word, words::substitution_bodies(raw))
            }
        }
    }

    /// Parse `source` as a nested script and analyze it.
    pub fn nested(&self, source: &str, cwd: Option<NormPath>, depth: usize, origin: Origin) {
        if depth + 1 >= MAX_DEPTH {
            self.emit(
                Stage::Rule,
                Finding::deny(
                    "analysis.recursion-limit",
                    Intent::StopAndExplain,
                    "Command exceeds maximum recursion depth and cannot be safely analyzed. Flatten the nesting and retry.",
                ),
            );
            return;
        }
        if !self.charge(source.len() / 8 + 1) {
            return;
        }
        let Some(parser) = self.parser else {
            rules::text::scan(self, &Cx::new(cwd), source);
            return;
        };
        let mut script = parser.parse(source);
        for site in &mut script.sites {
            if origin != Origin::Main {
                site.origin = origin;
            }
        }
        self.script(&script, cwd, depth + 1);
    }

    fn unparseable(&self, error: &str, script: &Script, depth: usize) {
        let _ = (script, depth);
        if self.policy.capabilities.fail_closed {
            self.emit(
                Stage::Rule,
                Finding::deny(
                    "analysis.strict-unparseable",
                    Intent::StopAndExplain,
                    format!("Command could not be safely analyzed (strict mode): {error}. Simplify the command and retry, or ask the user to verify."),
                ),
            );
        }
    }

    /// The per-command pipeline over evaluated words.
    pub fn command(&self, argv: &[Word], cx: &Cx, depth: usize) {
        if !self.charge(argv.len() + 1) {
            return;
        }
        // Secrets and self-protection look at every operand of every
        // command, wrappers included.
        rules::secrets::check_command(self, cx, argv);
        rules::guards::check_command(self, cx, argv);

        let (argv, cx) = match self.peel_prelude(argv, cx) {
            Some(peeled) => peeled,
            None => return,
        };
        if argv.is_empty() {
            return;
        }
        let head = &argv[0];
        let Some(name) = command_name(head) else {
            // The head is non-literal. A pure arithmetic expansion
            // (`$(( expr ))`) yields a number, not substitution output, so
            // it is not a dynamic *executable*; only command substitution,
            // backquotes or a parameter head are.
            if self.policy.capabilities.fail_closed && !is_arithmetic_only(head.text()) {
                self.rule(
                    &cx,
                    Finding::deny(
                        "shell.dynamic-executable",
                        Intent::ManualOnly,
                        "dynamic command name contains shell substitution output and cannot be verified safely. Use a literal executable name.",
                    ),
                );
            }
            // A word holding spaces may carry a whole command line.
            rules::text::scan_words(self, &cx, &argv);
            return;
        };
        if head.as_lit().is_some_and(|w| w.contains(' ')) {
            rules::text::scan(self, &cx, head.text());
        }

        if TRANSPARENT_WRAPPERS.contains(&name.as_str()) {
            self.transparent_wrapper(&argv, &cx, depth);
            return;
        }
        match name.as_str() {
            "eval" => rules::shells::eval(self, &cx, &argv, depth),
            "trap" => rules::shells::trap(self, &cx, &argv, depth),
            "source" | "." => rules::shells::source(self, &cx, &argv, depth),
            "busybox" => {
                if argv.len() > 1 {
                    self.command(&argv[1..], &cx, depth);
                }
            }
            n if rules::shells::is_shell(n, self) => rules::shells::shell(self, &cx, &argv, depth),
            n if rules::interp::is_interpreter(n) => rules::interp::check(self, &cx, &argv, depth),
            n if rules::interp::is_awk(n) => rules::interp::awk(self, &cx, &argv, depth),
            "rm" | "rmdir" | "unlink" => rules::rm::check(self, &cx, &argv),
            "git" => rules::git::check(self, &cx, &argv, depth),
            "find" => rules::find::check(self, &cx, &argv, depth),
            "rsync" => rules::find::rsync(self, &cx, &argv),
            "xargs" => rules::xargs::xargs(self, &cx, &argv, depth),
            "parallel" => rules::xargs::parallel(self, &cx, &argv, depth),
            "cmd" => rules::windows::cmd(self, &cx, &argv, depth),
            "powershell" | "pwsh" => rules::windows::powershell(self, &cx, &argv, depth),
            "mv" => rules::guards::mv(self, &cx, &argv),
            "unshare" => rules::device::unshare(self, &cx, &argv, depth),
            _ => {}
        }
        rules::device::check(self, &cx, &name, &argv);
        rules::network::check(self, &cx, &name, &argv);
        rules::pkg::check(self, &cx, &name, &argv);
        if self.functions.borrow().contains_key(&name) {
            self.call_function(&name, &cx, depth);
        }
        if !has_analyzer(&name) && !DISPLAY_COMMANDS.contains(&name.as_str()) {
            self.embedded_suffixes(&argv, &cx, depth);
        }
    }

    fn call_function(&self, name: &str, cx: &Cx, depth: usize) {
        if self.calling.borrow().iter().any(|n| n == name) || depth + 1 >= MAX_DEPTH {
            return;
        }
        let Some(sites) = self.functions.borrow().get(name).cloned() else {
            return;
        };
        self.calling.borrow_mut().push(name.to_string());
        let mut cwd = cx.cwd.clone();
        for site in &sites {
            let mut site = site.clone();
            site.function = None;
            cwd = self.site(&site, cwd, depth + 1);
        }
        self.calling.borrow_mut().pop();
    }

    /// Peel leading `NAME=value` words, `sudo`, `env`, `command` and
    /// `builtin` (cc-safety-net `wrapper-prelude.ts`). `None` stops the
    /// analysis (already reported).
    fn peel_prelude(&self, argv: &[Word], cx: &Cx) -> Option<(Vec<Word>, Cx)> {
        let mut argv: Vec<Word> = argv.to_vec();
        let mut cx = cx.clone();
        for _ in 0..20 {
            // Leading assignment words (after a wrapper).
            while let Some(Word::Lit(text)) = argv.first() {
                match text.split_once('=') {
                    Some((name, value)) if is_name(name) => {
                        cx.env
                            .push((name.to_string(), Word::Lit(value.to_string())));
                        argv.remove(0);
                    }
                    _ => break,
                }
            }
            let Some(name) = argv.first().and_then(command_name) else {
                return Some((argv, cx));
            };
            let rest = match name.as_str() {
                "sudo" | "doas" => peel_sudo(&argv, &mut cx, self.host),
                "env" => peel_env(&argv, &mut cx, self)?,
                "command" => {
                    let mut i = 1;
                    while let Some(Word::Lit(w)) = argv.get(i) {
                        if w == "--" {
                            i += 1;
                            break;
                        }
                        if w.starts_with('-')
                            && w[1..].chars().all(|c| matches!(c, 'p' | 'v' | 'V'))
                        {
                            if w.contains('v') || w.contains('V') {
                                // `command -v X` only describes X.
                                return Some((Vec::new(), cx));
                            }
                            i += 1;
                        } else {
                            break;
                        }
                    }
                    argv[i.min(argv.len())..].to_vec()
                }
                "builtin" => {
                    let skip = if argv.get(1).and_then(Word::as_lit) == Some("--") {
                        2
                    } else {
                        1
                    };
                    argv[skip.min(argv.len())..].to_vec()
                }
                _ => return Some((argv, cx)),
            };
            argv = rest;
        }
        self.emit(
            Stage::Rule,
            Finding::deny(
                "analysis.derived-command-limit",
                Intent::StopAndExplain,
                "Command analysis exceeds safebash's wrapper limit. Reduce nested wrappers and retry.",
            ),
        );
        None
    }

    /// `timeout 5 rm -rf /`, `nice -n 5 git push -f`: every later word
    /// naming a protectable command starts a candidate child.
    fn transparent_wrapper(&self, argv: &[Word], cx: &Cx, depth: usize) {
        let wrapper = command_name(&argv[0]).unwrap_or_default();
        let mut explicit = false;
        for index in 1..argv.len() {
            let word = &argv[index];
            if word.as_lit() == Some("--") {
                explicit = true;
                continue;
            }
            let Some(child) = command_name(word) else {
                if explicit {
                    break;
                }
                continue;
            };
            if child != wrapper && self.is_protectable(&child) {
                self.command(&argv[index..], cx, depth);
            } else if DISPLAY_COMMANDS.contains(&child.as_str()) && !word.text().starts_with('-') {
                break;
            }
            if explicit {
                break;
            }
        }
    }

    /// Unknown heads: analyze every suffix whose head is protectable.
    fn embedded_suffixes(&self, argv: &[Word], cx: &Cx, depth: usize) {
        for index in 1..argv.len() {
            if let Some(child) = command_name(&argv[index]) {
                if self.is_protectable(&child) && !argv[index].text().starts_with('-') {
                    let mut child_cx = cx.clone();
                    child_cx.pipe_in = None;
                    self.command_without_argv_rules(&argv[index..], &child_cx, depth);
                }
            }
        }
    }

    /// Embedded and xargs/parallel children skip the device, network and
    /// namespace argv rules (cc-safety-net §0.5).
    pub fn command_without_argv_rules(&self, argv: &[Word], cx: &Cx, depth: usize) {
        let Some(name) = argv.first().and_then(command_name) else {
            return;
        };
        match name.as_str() {
            "dd" | "shred" | "wipefs" | "sgdisk" | "parted" | "diskutil" | "unshare" => {}
            n if n.starts_with("mkfs") || n.starts_with("newfs") || n == "mke2fs" => {}
            n if rules::network::is_request_client(n) => {}
            _ => self.command(argv, cx, depth),
        }
    }

    pub fn is_protectable(&self, name: &str) -> bool {
        PROTECTABLE.contains(&name)
            || TRANSPARENT_WRAPPERS.contains(&name)
            || rules::shells::is_shell(name, self)
            || rules::interp::is_interpreter(name)
            || rules::interp::is_awk(name)
            || rules::network::is_request_client(name)
            || name.starts_with("mkfs")
            || name.starts_with("newfs")
            || matches!(name, "cmd" | "powershell" | "pwsh")
    }

    /// The working directory after a literal `cd` (static tracking).
    fn cd_after(&self, argv: &[Word], cwd: Option<NormPath>) -> Option<NormPath> {
        if self.runtime || command_name(&argv[0]).as_deref() != Some("cd") {
            return cwd;
        }
        let operands: Vec<&Word> = argv[1..]
            .iter()
            .filter(|w| !matches!(w.as_lit(), Some("-L" | "-P" | "--")))
            .collect();
        match operands.as_slice() {
            [] => self.host.home.clone(),
            [Word::Lit(target)] if target == "-" => None,
            [Word::Lit(target)] if target.starts_with('-') => None,
            [Word::Lit(target)] => self.host.norm(target, cwd.as_ref()),
            _ => None,
        }
    }
}

fn cx_env_names(assignments: &[(String, Arg)]) -> Vec<String> {
    assignments.iter().map(|(n, _)| n.clone()).collect()
}

fn with_segment(cx: &Cx, finding: Finding) -> Finding {
    if finding.segment.is_none() && !cx.segment.is_empty() {
        finding.with_segment(cx.segment.clone())
    } else {
        finding
    }
}

/// Human-readable text of a command, for `Segment:` lines.
pub fn display_command(command: &SimpleCommand) -> String {
    let mut parts: Vec<String> = command
        .assignments
        .iter()
        .map(|(n, a)| format!("{n}={}", a.text()))
        .collect();
    parts.extend(command.words.iter().map(|a| match a {
        Arg::Raw(t) => t.clone(),
        Arg::Value(v) => shell_quote(v),
    }));
    parts.join(" ")
}

/// Quote a value for display.
pub fn shell_quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c))
    {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

pub fn is_name(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The normalized command name of a head word: basename, lower-cased,
/// `.exe` stripped. `None` when the head is not literal.
/// A word that is only an arithmetic expansion (`$(( expr ))` or
/// `$[ expr ]`), with no command substitution or backquote inside — it
/// evaluates to a number, so it is not dynamic executable *source*.
pub fn is_arithmetic_only(text: &str) -> bool {
    let trimmed = text.trim();
    let inner = trimmed
        .strip_prefix("$((")
        .and_then(|r| r.strip_suffix("))"))
        .or_else(|| trimmed.strip_prefix("$[").and_then(|r| r.strip_suffix(']')));
    match inner {
        Some(inner) => !inner.contains("$(") && !inner.contains('`'),
        None => false,
    }
}

pub fn command_name(word: &Word) -> Option<String> {
    let text = word.as_lit()?;
    let base = text.rsplit(['/', '\\']).next().unwrap_or(text);
    let lower = base.to_ascii_lowercase();
    Some(lower.strip_suffix(".exe").unwrap_or(&lower).to_string())
}

fn has_analyzer(name: &str) -> bool {
    matches!(
        name,
        "rm" | "rmdir"
            | "unlink"
            | "git"
            | "find"
            | "rsync"
            | "xargs"
            | "parallel"
            | "cmd"
            | "eval"
            | "trap"
            | "source"
            | "."
            | "busybox"
            | "mv"
    )
}

/// `sudo`'s options taking a value; `-D` changes the cwd.
fn peel_sudo(argv: &[Word], cx: &mut Cx, host: &Host) -> Vec<Word> {
    let mut i = 1;
    while let Some(word) = argv.get(i) {
        let Some(text) = word.as_lit() else { break };
        if text == "--" {
            i += 1;
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        if text == "-i" || text == "--login" {
            cx.cwd = None;
            i += 1;
            continue;
        }
        if let Some(dir) = text.strip_prefix("--chdir=") {
            cx.cwd = host.norm(dir, cx.cwd.as_ref());
            i += 1;
            continue;
        }
        if text == "--chdir" || text == "-D" {
            cx.cwd = argv
                .get(i + 1)
                .and_then(Word::as_lit)
                .and_then(|d| host.norm(d, cx.cwd.as_ref()));
            i += 2;
            continue;
        }
        if let Some(dir) = text.strip_prefix("-D") {
            cx.cwd = host.norm(dir, cx.cwd.as_ref());
            i += 1;
            continue;
        }
        let takes_value = text.len() == 2
            && matches!(
                &text[1..],
                "u" | "g" | "C" | "h" | "p" | "r" | "t" | "T" | "U"
            );
        i += if takes_value { 2 } else { 1 };
    }
    argv[i.min(argv.len())..].to_vec()
}

/// `env [-i] [-u N] [-C dir] [-S str] [N=V ...] cmd`. `None` when a split
/// string was reported.
fn peel_env(argv: &[Word], cx: &mut Cx, an: &Analyzer<'_>) -> Option<Vec<Word>> {
    let mut i = 1;
    while let Some(word) = argv.get(i) {
        let Some(text) = word.as_lit() else { break };
        match text {
            "--" => {
                i += 1;
                break;
            }
            "-i" | "--ignore-environment" | "-" => {
                cx.env.clear();
                cx.env.push(("TMPDIR".into(), Word::lit("")));
                i += 1;
            }
            "-0" | "--null" | "-v" | "--debug" => i += 1,
            "-u" | "--unset" | "-P" => i += 2,
            "-C" | "--chdir" => {
                cx.cwd = argv
                    .get(i + 1)
                    .and_then(Word::as_lit)
                    .and_then(|d| an.host.norm(d, cx.cwd.as_ref()));
                i += 2;
            }
            "-S" | "--split-string" => {
                let split = argv
                    .get(i + 1)
                    .map(|w| w.text().to_string())
                    .unwrap_or_default();
                return Some(split_string(
                    an,
                    cx,
                    &split,
                    &argv[(i + 2).min(argv.len())..],
                ));
            }
            t if t.starts_with("--split-string=") || (t.starts_with("-S") && t.len() > 2) => {
                let split = t
                    .strip_prefix("--split-string=")
                    .or_else(|| t.strip_prefix("-S"))
                    .unwrap_or("")
                    .to_string();
                return Some(split_string(an, cx, &split, &argv[i + 1..]));
            }
            t if t.starts_with("--chdir=") || (t.starts_with("-C") && t.len() > 2) => {
                let dir = t
                    .strip_prefix("--chdir=")
                    .or_else(|| t.strip_prefix("-C"))
                    .unwrap_or("");
                cx.cwd = an.host.norm(dir.trim_start_matches('='), cx.cwd.as_ref());
                i += 1;
            }
            t if t.starts_with("--unset=") || (t.starts_with("-u") && t.len() > 2) => i += 1,
            t if t.starts_with('-') => i += 1,
            t => match t.split_once('=') {
                Some((name, value)) if is_name(name) => {
                    cx.env.push((name.to_string(), Word::lit(value)));
                    i += 1;
                }
                _ => break,
            },
        }
    }
    Some(argv[i.min(argv.len())..].to_vec())
}

/// `env -S 'rm -rf /'`: the split text becomes words (cc-safety-net
/// `segment.ts` L139-168).
fn split_string(an: &Analyzer<'_>, cx: &mut Cx, split: &str, rest: &[Word]) -> Vec<Word> {
    let joined = std::iter::once(split.to_string())
        .chain(rest.iter().map(|w| w.text().to_string()))
        .collect::<Vec<_>>()
        .join(" ");
    rules::text::scan(an, cx, &joined);
    if an.policy.capabilities.fail_closed {
        an.rule(
            cx,
            Finding::deny(
                "analysis.dynamic-shell-source",
                Intent::StopAndExplain,
                "shell execution source cannot be verified safely. Use a literal command string or ask the user to run it manually.",
            ),
        );
        return Vec::new();
    }
    if split.chars().any(|c| "'\"\\$`{}#".contains(c)) {
        return Vec::new();
    }
    cx.cwd = None;
    split
        .split_whitespace()
        .take(64)
        .map(Word::lit)
        .chain(rest.iter().cloned())
        .collect()
}

/// Exec wrappers unwrapped without an option grammar.
pub const TRANSPARENT_WRAPPERS: &[&str] = &[
    "caffeinate",
    "exec",
    "nice",
    "nohup",
    "setsid",
    "stdbuf",
    "time",
    "timeout",
    "ionice",
    "chrt",
    "taskset",
    "flock",
    "watch",
    "unbuffer",
    "script",
    "xvfb-run",
    "systemd-run",
    "strace",
    "ltrace",
    "chroot",
    "runuser",
    "su",
];

/// Commands whose appearance after a wrapper starts a child command.
pub const PROTECTABLE: &[&str] = &[
    "git", "unshare", "busybox", "sudo", "doas", "env", "command", "builtin", "rm", "rmdir",
    "unlink", "find", "rsync", "xargs", "parallel", "dd", "shred", "mke2fs", "diskutil", "wipefs",
    "sgdisk", "parted", "eval", "source", "mv", "npm", "yarn", "pnpm", "bun",
];

/// Commands that only display their operands (no embedded-suffix scan).
pub const DISPLAY_COMMANDS: &[&str] = &[
    "echo",
    "printf",
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "grep",
    "rg",
    "ag",
    "ack",
    "sed",
    "cut",
    "tr",
    "sort",
    "uniq",
    "wc",
    "tee",
    "man",
    "help",
    "info",
    "type",
    "which",
    "whereis",
    "whatis",
    "apropos",
    "file",
    "stat",
    "ls",
    "ll",
    "dir",
    "tree",
    "pwd",
    "date",
    "cal",
    "uptime",
    "whoami",
    "id",
    "groups",
    "hostname",
    "uname",
    "printenv",
    "set",
    "export",
    "alias",
    "history",
    "jobs",
    "fg",
    "bg",
    "test",
    "[",
    "true",
    "false",
    "read",
    "return",
    "exit",
    "break",
    "continue",
    "shift",
    "wait",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "md5sum",
    "sha256sum",
    "base64",
    "xxd",
    "od",
    "hexdump",
    "strings",
    "diff",
    "cmp",
    "comm",
    "join",
    "paste",
    "column",
    "fmt",
    "fold",
    "nl",
    "pr",
    "expand",
    "unexpand",
    "rev",
    "tac",
    "shuf",
    "seq",
    "yes",
    "sleep",
    "logger",
    "write",
    "wall",
    "mesg",
    "notify-send",
    "cd",
    "local",
    "declare",
    "typeset",
    "readonly",
    "unset",
    ":",
    "jq",
];
