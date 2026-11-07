//! brush-parser AST -> guard model (safebash keystone, step A1).
//!
//! OFFLINE PARITY PATH ONLY. The live guard keeps [`crate::convert::RubashParser`]
//! (installed in `main.rs`); this converter is used only by the two-parser
//! comparison utility (`src/bin/brush_parity.rs`) and an opt-in advisory check.
//! It is never installed in a running gate, so A1 changes no runtime decision.
//! See DESIGN.md Sections 5 ("A1") and 7.
//!
//! The walk mirrors [`crate::convert`] (the rubash walker) so the two produce
//! comparable [`Script`]s. Where brush and rubash diverge, the comparison
//! utility surfaces it; the known cases are enumerated in DESIGN.md Section 5
//! "A2" item 2 (class I: brush rejects -> parse error; class II: brush accepts
//! but mis-structures -> detected here or denied).

use brush_parser::ast;
use brush_parser::ast::SourceLocation;
use brush_parser::{Parser, ParserOptions};
use safebash_guard::model::{
    Access, Arg, CommandSite, Origin, PipelineInfo, Redirect, Script, ScriptParser, SimpleCommand,
};

/// The parts of a simple command in position order: environment assignments
/// `(name, value)`, words, redirects, and here-document / here-string stdin text.
type SimpleCommandParts = (Vec<(String, Arg)>, Vec<Arg>, Vec<Redirect>, Option<String>);

/// The brush-parser as a [`ScriptParser`], for offline parity only.
pub struct BrushParser {
    pub posix: bool,
}

impl ScriptParser for BrushParser {
    fn parse(&self, source: &str) -> Script {
        let options = ParserOptions {
            posix_mode: self.posix,
            ..ParserOptions::default()
        };
        let mut walker = Walker {
            source,
            script: Script {
                scope_parents: vec![0],
                ..Script::default()
            },
        };
        let mut parser = Parser::new(source.as_bytes(), &options);
        match parser.parse_program() {
            Ok(program) => {
                for command in &program.complete_commands {
                    walker.list(command, 0, None);
                }
            }
            Err(error) => {
                // Class I (DESIGN Section 5 "A2" item 2): input brush rejects
                // (for example `select`, or a word-list for-loop with a brace
                // body) is a parse error. rubash records the same through its
                // `__RUBASH_PARSE_ERROR` marker; under A2 a parse error is a
                // fail-closed denial.
                walker.script.parse_error = Some(format!("{error}"));
            }
        }
        walker.script
    }
}

struct Walker<'a> {
    source: &'a str,
    script: Script,
}

impl Walker<'_> {
    fn new_scope(&mut self, parent: usize) -> usize {
        self.script.scope_parents.push(parent);
        self.script.scope_parents.len() - 1
    }

    /// A compound list (a sequence of and-or lists). A trailing `&` opens a
    /// new background scope, matching rubash's `background_command`.
    fn list(&mut self, list: &ast::CompoundList, scope: usize, function: Option<&str>) {
        for ast::CompoundListItem(and_or, separator) in &list.0 {
            let item_scope = match separator {
                ast::SeparatorOperator::Async => self.new_scope(scope),
                ast::SeparatorOperator::Sequence => scope,
            };
            self.and_or(and_or, item_scope, function);
        }
    }

    /// An and-or list: every pipeline runs in the same scope; `&&`/`||` are
    /// transparent (rubash flattens them into the body).
    fn and_or(&mut self, and_or: &ast::AndOrList, scope: usize, function: Option<&str>) {
        self.pipeline(&and_or.first, scope, function);
        for item in &and_or.additional {
            let pipeline = match item {
                ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => pipeline,
            };
            self.pipeline(pipeline, scope, function);
        }
    }

    /// A pipeline. `timed` and `bang` are transparent. A single-command
    /// pipeline keeps the enclosing scope and carries no pipeline context; a
    /// real multi-stage pipeline allocates a stage scope per stage (matching
    /// rubash, DESIGN Section 5 "Walker mapping").
    fn pipeline(&mut self, pipeline: &ast::Pipeline, scope: usize, function: Option<&str>) {
        if pipeline.seq.len() <= 1 {
            if let Some(command) = pipeline.seq.first() {
                self.command(command, scope, function, None);
            }
            return;
        }
        let stages: Vec<Vec<Arg>> = pipeline.seq.iter().map(|c| self.stage_words(c)).collect();
        for (index, command) in pipeline.seq.iter().enumerate() {
            let stage_scope = self.new_scope(scope);
            let info = PipelineInfo {
                index,
                stages: stages.clone(),
            };
            self.command(command, stage_scope, function, Some(info));
        }
    }

    fn command(
        &mut self,
        command: &ast::Command,
        scope: usize,
        function: Option<&str>,
        pipeline: Option<PipelineInfo>,
    ) {
        match command {
            ast::Command::Simple(simple) => {
                if denied_fd_var_allocation(simple) {
                    // A variable-named file-descriptor allocation (`{name}>...`,
                    // no space) that this converter does not reconstruct:
                    // either `{name}` is the command word (dropping it would
                    // promote a following word to the command and hide it,
                    // DESIGN rev 2 Section 4.1 case 3), or the redirect is a
                    // here-document, here-string, or combined-output (`&>`)
                    // form whose allocation semantics are not mapped (case 4).
                    // Fail-closed: deny. The common suffix-position allocation
                    // onto an ordinary file redirect IS reconstructed, in
                    // `simple_parts` (case 2), using the operator span the fork
                    // now records on `IoRedirect`.
                    if self.script.parse_error.is_none() {
                        self.script.parse_error = Some(
                            "unsupported: variable-named file-descriptor allocation ({name}> ...) in the command-word position, or onto a here-document / here-string / combined-output redirect".to_string(),
                        );
                    }
                    return;
                }
                let (assignments, words, redirects, stdin_text) = self.simple_parts(simple);
                let command = SimpleCommand {
                    assignments,
                    words,
                    redirects,
                    stdin_text,
                };
                if command.words.is_empty()
                    && command.assignments.is_empty()
                    && command.redirects.is_empty()
                {
                    return;
                }
                self.script.sites.push(CommandSite {
                    command,
                    pipeline,
                    origin: Origin::Main,
                    scope,
                    function: function.map(str::to_string),
                });
            }
            ast::Command::Compound(compound, redirects) => {
                self.compound(compound, redirects.as_ref(), scope, function);
            }
            ast::Command::Function(definition) => {
                // Walk the body tagged with the function name; analyzed only
                // where the function is called.
                self.function_body(
                    &definition.body,
                    scope,
                    Some(definition.fname.value.as_str()),
                );
            }
        }
    }

    /// Emit a redirects-only site for redirections attached to a compound or
    /// extended-test command (`{ ...; } > file`, `[[ ... ]] > file`).
    fn push_redirect_site(
        &mut self,
        redirects: Option<&ast::RedirectList>,
        scope: usize,
        function: Option<&str>,
    ) {
        if let Some(list) = redirects {
            let redirects = self.redirect_list(list);
            if !redirects.is_empty() {
                self.script.sites.push(CommandSite {
                    command: SimpleCommand {
                        redirects,
                        ..SimpleCommand::default()
                    },
                    pipeline: None,
                    origin: Origin::Main,
                    scope,
                    function: function.map(str::to_string),
                });
            }
        }
    }

    fn function_body(&mut self, body: &ast::FunctionBody, scope: usize, function: Option<&str>) {
        self.compound(&body.0, body.1.as_ref(), scope, function);
    }

    fn compound(
        &mut self,
        compound: &ast::CompoundCommand,
        redirects: Option<&ast::RedirectList>,
        scope: usize,
        function: Option<&str>,
    ) {
        use ast::CompoundCommand as Compound;
        match compound {
            Compound::BraceGroup(group) => self.list(&group.list, scope, function),
            Compound::Subshell(subshell) => {
                let inner = self.new_scope(scope);
                self.list(&subshell.list, inner, function);
            }
            Compound::IfClause(clause) => {
                self.list(&clause.condition, scope, function);
                self.list(&clause.then, scope, function);
                if let Some(elses) = &clause.elses {
                    for branch in elses {
                        if let Some(condition) = &branch.condition {
                            self.list(condition, scope, function);
                        }
                        self.list(&branch.body, scope, function);
                    }
                }
            }
            Compound::WhileClause(clause) | Compound::UntilClause(clause) => {
                self.list(&clause.0, scope, function);
                self.list(&clause.1.list, scope, function);
            }
            Compound::ForClause(clause) => {
                // The word list expands (and may substitute) before the body.
                if let Some(values) = &clause.values {
                    self.words_only(values.iter().map(|w| w.value.clone()), scope, function);
                }
                self.list(&clause.body.list, scope, function);
            }
            Compound::ArithmeticForClause(clause) => {
                for expr in [&clause.initializer, &clause.condition, &clause.updater]
                    .into_iter()
                    .flatten()
                {
                    self.words_only(std::iter::once(quoted_arith(expr)), scope, function);
                }
                self.list(&clause.body.list, scope, function);
            }
            Compound::CaseClause(clause) => {
                self.words_only(std::iter::once(clause.value.value.clone()), scope, function);
                for item in &clause.cases {
                    if let Some(body) = &item.cmd {
                        self.list(body, scope, function);
                    }
                }
            }
            Compound::Arithmetic(command) => {
                // `(( a[$(cmd)] ))` runs its substitutions.
                self.words_only(
                    std::iter::once(quoted_arith(&command.expr)),
                    scope,
                    function,
                );
            }
            Compound::Coprocess(coproc) => {
                let inner = self.new_scope(scope);
                self.command(&coproc.body, inner, function, None);
            }
            Compound::ExtendedTest(test) => {
                // `[[ ... ]]`: the conditional-args site. On this fork (upstream
                // main) `ExtendedTest` is a `CompoundCommand` variant; any
                // redirects are the enclosing `Command::Compound` redirects,
                // handled by the trailing `push_redirect_site` below.
                let mut words = Vec::new();
                collect_test_words(&test.expr, &mut words);
                self.words_only(words.into_iter(), scope, function);
            }
        }
        self.push_redirect_site(redirects, scope, function);
    }

    /// A site that only expands words (for lists, case words, `[[ ]]`),
    /// emitted only when a word carries a substitution. Mirrors
    /// [`crate::convert`]'s `words_only`.
    fn words_only(
        &mut self,
        words: impl Iterator<Item = String>,
        scope: usize,
        function: Option<&str>,
    ) {
        let words: Vec<String> = words.collect();
        if words.iter().any(|w| w.contains('$') || w.contains('`')) {
            let site = CommandSite {
                command: SimpleCommand {
                    words: std::iter::once(Arg::value(":"))
                        .chain(words.into_iter().map(Arg::raw))
                        .collect(),
                    ..SimpleCommand::default()
                },
                pipeline: None,
                origin: Origin::Main,
                scope,
                function: function.map(str::to_string),
            };
            self.script.sites.push(site);
        }
    }

    /// The parts of a simple command, mapped by position (DESIGN Section 5
    /// "Walker mapping" and "Special sites").
    fn simple_parts(&self, simple: &ast::SimpleCommand) -> SimpleCommandParts {
        let mut assignments = Vec::new();
        let mut words = Vec::new();
        let mut redirects = Vec::new();
        let mut stdin_text = None;

        // Prefix: a prefix AssignmentWord is a real environment assignment;
        // a prefix IoRedirect is a redirect.
        if let Some(prefix) = &simple.prefix {
            for item in &prefix.0 {
                match item {
                    ast::CommandPrefixOrSuffixItem::AssignmentWord(assignment, _word) => {
                        assignments.push(assignment_pair(assignment));
                    }
                    ast::CommandPrefixOrSuffixItem::IoRedirect(io) => {
                        self.apply_redirect(io, &mut redirects, &mut stdin_text);
                    }
                    ast::CommandPrefixOrSuffixItem::Word(word) => {
                        words.push(Arg::raw(word.value.clone()));
                    }
                    ast::CommandPrefixOrSuffixItem::ProcessSubstitution(kind, subshell) => {
                        words.push(Arg::raw(self.process_substitution(kind, subshell)));
                    }
                }
            }
        }

        if let Some(word) = &simple.word_or_name {
            words.push(Arg::raw(word.value.clone()));
        }

        // Suffix: ordinary arguments, suffix assignment-shaped arguments (kept
        // as arguments, DESIGN round-2 finding 1), redirects and process
        // substitutions. A variable-named descriptor allocation (`{name}>...`,
        // DESIGN round-3 finding 2 / class II) is denied earlier in
        // `command()` (see `has_fd_var_allocation`), so no `{name}` fd-var
        // reaches here as an argument.
        if let Some(suffix) = &simple.suffix {
            let items = &suffix.0;
            for (index, item) in items.iter().enumerate() {
                match item {
                    ast::CommandPrefixOrSuffixItem::Word(word) => {
                        // A `{name}` descriptor allocation contiguous with the
                        // next ordinary file redirect is claimed by that
                        // redirect, not an argument - drop it (DESIGN rev 2
                        // Section 4.1 case 2). The command-word-position and the
                        // here-document / here-string / `&>` allocation shapes
                        // are denied earlier in `command()`.
                        if is_fd_var(&word.value)
                            && next_is_contiguous_file_redirect(word, items.get(index + 1))
                        {
                            continue;
                        }
                        words.push(Arg::raw(word.value.clone()));
                    }
                    ast::CommandPrefixOrSuffixItem::AssignmentWord(_assignment, word) => {
                        // An ordinary argument that merely looks like an
                        // assignment (`echo x=y`, `declare x=y`), preserved
                        // with its full `name=value` text in position.
                        words.push(Arg::raw(word.value.clone()));
                    }
                    ast::CommandPrefixOrSuffixItem::IoRedirect(io) => {
                        self.apply_redirect(io, &mut redirects, &mut stdin_text);
                    }
                    ast::CommandPrefixOrSuffixItem::ProcessSubstitution(kind, subshell) => {
                        words.push(Arg::raw(self.process_substitution(kind, subshell)));
                    }
                }
            }
        }

        (assignments, words, redirects, stdin_text)
    }

    /// Reconstruct a process-substitution argument so the guard's existing raw
    /// `substitution_bodies` scan analyzes its body exactly once (DESIGN
    /// Section 5 "Special sites", route (b)).
    ///
    /// DESIGN round-3 finding 1 requires this argument to evaluate to
    /// `Word::Dyn`, not `Word::Lit`. A1 does NOT change the shared
    /// `words::evaluate` (that would alter the live rubash path too), so the
    /// word currently classifies as `Word::Lit` for BOTH parsers - the shared
    /// blind spot Section 7 calls out - and the Word::Dyn upgrade is the A2
    /// evaluator change. A1's job is the structural mapping: preserve the
    /// substitution as an argument in position, with one body analysis.
    fn process_substitution(
        &self,
        kind: &ast::ProcessSubstitutionKind,
        subshell: &ast::SubshellCommand,
    ) -> String {
        let operator = match kind {
            ast::ProcessSubstitutionKind::Read => '<',
            ast::ProcessSubstitutionKind::Write => '>',
        };
        let span = &subshell.loc;
        let body = if span.end.index > span.start.index {
            slice_chars(self.source, span.start.index, span.end.index)
        } else {
            String::new()
        };
        if body.starts_with('(') {
            format!("{operator}{body}")
        } else if body.is_empty() {
            format!("{operator}({})", subshell.list)
        } else {
            format!("{operator}({body})")
        }
    }

    fn redirect_list(&self, list: &ast::RedirectList) -> Vec<Redirect> {
        let mut redirects = Vec::new();
        let mut stdin_text = None;
        for io in &list.0 {
            self.apply_redirect(io, &mut redirects, &mut stdin_text);
        }
        redirects
    }

    fn apply_redirect(
        &self,
        io: &ast::IoRedirect,
        redirects: &mut Vec<Redirect>,
        stdin_text: &mut Option<String>,
    ) {
        match io {
            ast::IoRedirect::File(fd, kind, target, ..) => {
                let fd = fd.and_then(|n| u32::try_from(n).ok());
                let access = match kind {
                    ast::IoFileRedirectKind::Read => Access::Read,
                    ast::IoFileRedirectKind::Write | ast::IoFileRedirectKind::Clobber => {
                        Access::Write
                    }
                    ast::IoFileRedirectKind::Append => Access::Append,
                    ast::IoFileRedirectKind::ReadAndWrite => Access::ReadWrite,
                    ast::IoFileRedirectKind::DuplicateInput => Access::Read,
                    ast::IoFileRedirectKind::DuplicateOutput => Access::Write,
                };
                if let Some(target) = self.redirect_target(target) {
                    redirects.push(Redirect { fd, access, target });
                }
            }
            ast::IoRedirect::OutputAndError(word, append, ..) => {
                redirects.push(Redirect {
                    fd: None,
                    access: if *append {
                        Access::Append
                    } else {
                        Access::Write
                    },
                    target: Arg::raw(word.value.clone()),
                });
            }
            ast::IoRedirect::HereDocument(fd, here_doc, ..) => {
                if fd.unwrap_or(0) == 0 && stdin_text.is_none() {
                    *stdin_text = Some(here_doc.doc.value.clone());
                }
            }
            ast::IoRedirect::HereString(fd, word, ..) => {
                if fd.unwrap_or(0) == 0 && stdin_text.is_none() {
                    *stdin_text = Some(word.value.clone());
                }
            }
        }
    }

    fn redirect_target(&self, target: &ast::IoFileRedirectTarget) -> Option<Arg> {
        match target {
            ast::IoFileRedirectTarget::Filename(word) => Some(Arg::raw(word.value.clone())),
            // A pure file-descriptor operand (`>&2`, `<&0`) has no file target.
            ast::IoFileRedirectTarget::Fd(_) => None,
            ast::IoFileRedirectTarget::ProcessSubstitution(kind, subshell) => {
                Some(Arg::raw(self.process_substitution(kind, subshell)))
            }
            ast::IoFileRedirectTarget::Duplicate(word) => {
                let operand = word.value.trim_start_matches('&');
                if operand == "-"
                    || (!operand.is_empty() && operand.chars().all(|c| c.is_ascii_digit()))
                {
                    None
                } else {
                    Some(Arg::raw(operand.to_string()))
                }
            }
        }
    }

    fn stage_words(&self, command: &ast::Command) -> Vec<Arg> {
        match command {
            ast::Command::Simple(simple) => {
                let (_, words, _, _) = self.simple_parts(simple);
                words
            }
            _ => Vec::new(),
        }
    }
}

/// A prefix assignment as `(name, raw value)`, matching rubash's
/// `(name, Arg::raw(raw))`.
fn assignment_pair(assignment: &ast::Assignment) -> (String, Arg) {
    // An append assignment (`A+=x`) keeps its `+` on the name, so the guard
    // sees `A+=x` as rubash does, not `A=x`.
    let name = if assignment.append {
        format!("{}+", assignment.name)
    } else {
        assignment.name.to_string()
    };
    let value = match &assignment.value {
        ast::AssignmentValue::Scalar(word) => word.value.clone(),
        ast::AssignmentValue::Array(elements) => {
            let rendered: Vec<String> = elements
                .iter()
                .map(|(key, value)| match key {
                    Some(key) => format!("[{}]={}", key.value, value.value),
                    None => value.value.clone(),
                })
                .collect();
            format!("({})", rendered.join(" "))
        }
    };
    (name, Arg::raw(value))
}

/// `{name}` where `name` is a shell identifier - the shape rubash claims as a
/// redirect's descriptor variable when it adjoins a redirection operator.
fn is_fd_var(word: &str) -> bool {
    match word.strip_prefix('{').and_then(|w| w.strip_suffix('}')) {
        Some(name) => {
            let mut chars = name.chars();
            match chars.next() {
                Some(first) if first.is_ascii_alphabetic() || first == '_' => {
                    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
                }
                _ => false,
            }
        }
        None => false,
    }
}

/// True when a simple command carries a variable-named file-descriptor
/// allocation (`{name}>...`, no space) that this converter does NOT reconstruct
/// and therefore denies (fail-closed), per DESIGN rev 2 Section 4.1:
///   - case 3: `{name}` is the command word and the first suffix item is a
///     redirect contiguous with it (dropping `{name}` would promote a following
///     word to the command and hide it); or
///   - case 4: a suffix `{name}` is contiguous with a here-document, here-string
///     or combined-output (`&>`) redirect, whose allocation is not mapped.
///
/// The common, safe case - a suffix `{name}` contiguous with an ordinary file
/// redirect - is reconstructed in `simple_parts` (case 2), not denied here. A
/// `{name}` not contiguous with any redirect is an ordinary argument (case 1).
fn denied_fd_var_allocation(simple: &ast::SimpleCommand) -> bool {
    // Case 3: `{name}` in the command-word position, contiguous with the first
    // suffix redirect.
    if let Some(word) = &simple.word_or_name {
        if is_fd_var(&word.value) {
            if let Some(ast::CommandPrefixOrSuffixItem::IoRedirect(redirect)) =
                simple.suffix.as_ref().and_then(|s| s.0.first())
            {
                if is_contiguous(word, redirect) {
                    return true;
                }
            }
        }
    }
    // Case 4: a suffix `{name}` contiguous with an ineligible redirect (here
    // document, here string, or combined output). A contiguous ordinary file
    // redirect is the reconstructed case (case 2) and is not denied.
    if let Some(suffix) = &simple.suffix {
        let items = &suffix.0;
        for (index, item) in items.iter().enumerate() {
            if let ast::CommandPrefixOrSuffixItem::Word(word) = item {
                if is_fd_var(&word.value) {
                    if let Some(ast::CommandPrefixOrSuffixItem::IoRedirect(redirect)) =
                        items.get(index + 1)
                    {
                        if is_contiguous(word, redirect)
                            && !matches!(redirect, ast::IoRedirect::File(..))
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// A suffix `{name}` word whose next item is an ordinary file redirect contiguous
/// with it - the reconstructed descriptor allocation (DESIGN rev 2 Section 4.1
/// case 2), which `simple_parts` drops from the argument list.
fn next_is_contiguous_file_redirect(
    word: &ast::Word,
    next: Option<&ast::CommandPrefixOrSuffixItem>,
) -> bool {
    let Some(ast::CommandPrefixOrSuffixItem::IoRedirect(redirect)) = next else {
        return false;
    };
    matches!(redirect, ast::IoRedirect::File(..)) && is_contiguous(word, redirect)
}

/// True when `word` ends exactly where `redirect`'s operator begins (no space) -
/// the physical adjacency that marks a `{name}>file` descriptor allocation. Uses
/// the operator span the fork records on `IoRedirect`; with either span absent
/// (which should not happen on the fork), it is not treated as contiguous.
fn is_contiguous(word: &ast::Word, redirect: &ast::IoRedirect) -> bool {
    match (word.loc.as_ref(), redirect.location()) {
        (Some(word_span), Some(operator_span)) => word_span.end.index == operator_span.start.index,
        _ => false,
    }
}

/// An arithmetic expression as a quoted word (so `words_only` treats it as a
/// single substitution-bearing word), matching rubash's
/// `format!("\"{}\"", text.replace('"', ""))`.
fn quoted_arith(expr: &impl std::fmt::Display) -> String {
    format!("\"{}\"", expr.to_string().replace('"', ""))
}

fn collect_test_words(expr: &ast::ExtendedTestExpr, out: &mut Vec<String>) {
    use ast::ExtendedTestExpr as Expr;
    match expr {
        Expr::And(left, right) | Expr::Or(left, right) => {
            collect_test_words(left, out);
            collect_test_words(right, out);
        }
        Expr::Not(inner) | Expr::Parenthesized(inner) => collect_test_words(inner, out),
        Expr::UnaryTest(_predicate, word) => out.push(word.value.clone()),
        Expr::BinaryTest(_predicate, left, right) => {
            out.push(left.value.clone());
            out.push(right.value.clone());
        }
    }
}

fn slice_chars(source: &str, start: usize, end: usize) -> String {
    source
        .chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

#[cfg(test)]
mod tests {
    // Inline sanity checks, parallel to `crate::convert`'s own test module
    // (every converter in this crate carries one). The substantive parity
    // testing is the two-parser comparison utility (DESIGN Section 7), not
    // these.
    use super::*;

    fn parse(source: &str) -> Script {
        BrushParser { posix: false }.parse(source)
    }

    fn words(site: &CommandSite) -> Vec<&str> {
        site.command.words.iter().map(Arg::text).collect()
    }

    #[test]
    fn simple_pipeline_and_lists() {
        let script = parse("cd /tmp && rm -rf x | cat; echo hi");
        let heads: Vec<&str> = script
            .sites
            .iter()
            .map(|s| s.command.words[0].text())
            .collect();
        assert_eq!(heads, vec!["cd", "rm", "cat", "echo"]);
        let rm = &script.sites[1];
        assert_eq!(rm.pipeline.as_ref().map(|p| p.index), Some(0));
        assert_eq!(rm.command.words[1].text(), "-rf");
    }

    #[test]
    fn suffix_assignment_word_is_an_argument() {
        // DESIGN round-2 finding 1: `x=y` after the command word is an
        // argument, not an environment assignment.
        let script = parse("echo x=y");
        let echo = &script.sites[0];
        assert!(echo.command.assignments.is_empty());
        assert_eq!(words(echo), vec!["echo", "x=y"]);
    }

    #[test]
    fn prefix_assignment_is_an_assignment() {
        let script = parse("FOO=bar rm -rf /tmp/x");
        let site = &script.sites[0];
        assert_eq!(site.command.assignments.len(), 1);
        assert_eq!(site.command.assignments[0].0, "FOO");
        assert_eq!(words(site), vec!["rm", "-rf", "/tmp/x"]);
    }

    #[test]
    fn wrapped_shell_keeps_positional_parameters() {
        // DESIGN round-2 finding 1: the suffix `tag=value` stays an argument,
        // so the shell's name and first positional parameter are preserved.
        let script = parse("bash -c 'rm -rf \"$1\"' tag=value /");
        let site = &script.sites[0];
        assert_eq!(
            words(site),
            vec!["bash", "-c", "'rm -rf \"$1\"'", "tag=value", "/"]
        );
    }

    #[test]
    fn fd_var_allocation_in_command_word_position_is_denied() {
        // DESIGN rev 2 Section 4.1 case 3: `{fd}` is the command word and the
        // redirect is contiguous with it. Dropping `{fd}` would promote `echo`
        // to the command word and hide it, so deny (fail-closed).
        assert!(parse("{fd}>out.txt echo hi").parse_error.is_some());
    }

    #[test]
    fn fd_var_allocation_onto_heredoc_or_combined_output_is_denied() {
        // DESIGN rev 2 Section 4.1 case 4: a suffix `{fd}` contiguous with a
        // here-string or combined-output redirect, whose allocation is not
        // mapped, is denied.
        assert!(parse("exec {fd}<<< hi").parse_error.is_some());
        assert!(parse("printf x {fd}&>out.txt").parse_error.is_some());
    }

    #[test]
    fn fd_var_allocation_onto_file_redirect_is_reconstructed() {
        // DESIGN rev 2 Section 4.1 case 2: a suffix `{name}` contiguous with an
        // ordinary file redirect is a descriptor allocation - claimed by the
        // redirect, dropped from the arguments - so the real command reaches the
        // guard intact. The operator span the fork records makes this safe.
        let allocated = parse("bash {log}>trace.log -c 'rm -rf /'");
        assert!(allocated.parse_error.is_none());
        assert_eq!(words(&allocated.sites[0]), vec!["bash", "-c", "'rm -rf /'"]);
        assert_eq!(allocated.sites[0].command.redirects.len(), 1);

        let exec = parse("exec {fd}>out.txt");
        assert!(exec.parse_error.is_none());
        assert_eq!(words(&exec.sites[0]), vec!["exec"]);
    }

    #[test]
    fn spaced_fd_var_is_an_ordinary_argument() {
        // DESIGN rev 2 Section 4.1 case 1: with a space, `{fd}` is a normal
        // argument and the redirect is separate - no longer over-denied.
        let spaced = parse("exec {fd} >out.txt");
        assert!(spaced.parse_error.is_none());
        assert_eq!(words(&spaced.sites[0]), vec!["exec", "{fd}"]);

        // A `{x}` not adjoining any redirect is an ordinary argument too.
        let ok = parse("echo {x}");
        assert!(ok.parse_error.is_none());
        assert_eq!(words(&ok.sites[0]), vec!["echo", "{x}"]);
    }

    #[test]
    fn select_is_a_parse_error() {
        // DESIGN round-2 (class I): brush has no `select` clause, so it is a
        // parse error (the A2 fail-closed deny covers it).
        let script = parse("select x in a b; do echo $x; done");
        assert!(script.parse_error.is_some());
    }

    #[test]
    fn redirects_and_heredocs() {
        let script = parse("cat > out.txt < in.txt\nbash <<'EOF'\nrm -rf ~\nEOF\n");
        let cat = &script.sites[0].command;
        assert_eq!(cat.redirects.len(), 2);
        let bash = &script.sites[1].command;
        assert!(bash
            .stdin_text
            .as_deref()
            .unwrap_or("")
            .contains("rm -rf ~"));
    }
}
