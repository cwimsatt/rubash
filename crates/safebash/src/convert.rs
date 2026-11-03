//! rubash AST -> guard model: the guard reads scripts with the very parser
//! the shell executes them with.

use rubash::parser::{CommandNode, RedirectKind};
use safebash_guard::model::{
    Access, Arg, CommandSite, Origin, PipelineInfo, Redirect, Script, ScriptParser, SimpleCommand,
};

/// The rubash parser as a [`ScriptParser`].
pub struct RubashParser {
    pub posix: bool,
}

impl ScriptParser for RubashParser {
    fn parse(&self, source: &str) -> Script {
        let tokens = rubash::lexer::tokenize_with_initial_posix(source, self.posix);
        let ast = rubash::parser::parse(&tokens);
        let mut walker = Walker {
            script: Script {
                scope_parents: vec![0],
                ..Script::default()
            },
        };
        for command in &ast.commands {
            walker.node(command, 0, None, None);
        }
        walker.script
    }
}

struct Walker {
    script: Script,
}

impl Walker {
    fn new_scope(&mut self, parent: usize) -> usize {
        self.script.scope_parents.push(parent);
        self.script.scope_parents.len() - 1
    }

    fn body(&mut self, body: &[CommandNode], scope: usize, function: Option<&str>) {
        for command in body {
            self.node(command, scope, function, None);
        }
    }

    fn node(
        &mut self,
        command: &CommandNode,
        scope: usize,
        function: Option<&str>,
        pipeline: Option<PipelineInfo>,
    ) {
        if let Some(list) = &command.and_or_list {
            self.body(&list.commands, scope, function);
            return;
        }
        if let Some(pipe) = &command.pipeline_command {
            let stages: Vec<Vec<Arg>> = pipe.stages.iter().map(stage_words).collect();
            for (index, stage) in pipe.stages.iter().enumerate() {
                let stage_scope = self.new_scope(scope);
                let info = PipelineInfo {
                    index,
                    stages: stages.clone(),
                };
                self.node(stage, stage_scope, function, Some(info));
            }
            return;
        }
        if let Some(time) = &command.time_command {
            self.node(&time.command, scope, function, pipeline);
            return;
        }
        if let Some(background) = &command.background_command {
            let inner = self.new_scope(scope);
            self.node(&background.command, inner, function, pipeline);
            return;
        }
        if let Some(inverted) = &command.inverted_command {
            self.node(&inverted.command, scope, function, pipeline);
            return;
        }
        if let Some(subshell) = &command.subshell_command {
            let inner = self.new_scope(scope);
            self.body(&subshell.body, inner, function);
            self.simple_redirects_only(command, scope, function);
            return;
        }
        if let Some(group) = &command.brace_group {
            self.body(&group.body, scope, function);
            self.simple_redirects_only(command, scope, function);
            return;
        }
        if let Some(if_command) = &command.if_command {
            self.body(&if_command.condition, scope, function);
            self.body(&if_command.then_body, scope, function);
            for branch in &if_command.elif_branches {
                self.body(&branch.condition, scope, function);
                self.body(&branch.body, scope, function);
            }
            if let Some(else_body) = &if_command.else_body {
                self.body(else_body, scope, function);
            }
            self.simple_redirects_only(command, scope, function);
            return;
        }
        if let Some(loop_command) = &command.loop_command {
            self.body(&loop_command.condition, scope, function);
            self.body(&loop_command.body, scope, function);
            self.simple_redirects_only(command, scope, function);
            return;
        }
        if let Some(for_command) = &command.for_command {
            // The word list expands (and may substitute) before the body.
            self.words_only(&for_command.words, scope, function);
            self.body(&for_command.body, scope, function);
            return;
        }
        if let Some(select) = &command.select_command {
            self.words_only(&select.words, scope, function);
            self.body(&select.body, scope, function);
            return;
        }
        if let Some(case_command) = &command.case_command {
            self.words_only(std::slice::from_ref(&case_command.word), scope, function);
            for clause in &case_command.clauses {
                self.body(&clause.body, scope, function);
            }
            return;
        }
        if let Some(definition) = &command.function_command {
            self.body(&definition.body, scope, Some(&definition.name));
            return;
        }
        if let Some(coproc) = &command.coproc_command {
            let inner = self.new_scope(scope);
            match &coproc.body {
                Some(body) => self.body(body, inner, function),
                None => {
                    let site = CommandSite {
                        command: SimpleCommand {
                            words: coproc.words.iter().map(|w| Arg::raw(w.clone())).collect(),
                            ..SimpleCommand::default()
                        },
                        pipeline: None,
                        origin: Origin::Main,
                        scope: inner,
                        function: function.map(str::to_string),
                    };
                    self.script.sites.push(site);
                }
            }
            return;
        }
        if let Some(arith) = &command.arithmetic_command {
            // `(( a[$(cmd)] ))` runs its substitutions.
            let text = arith
                .raw_expression
                .clone()
                .unwrap_or_else(|| arith.expression.clone());
            self.words_only(&[format!("\"{}\"", text.replace('"', ""))], scope, function);
            return;
        }
        if let Some(conditional) = &command.conditional_command {
            self.words_only(&conditional.args, scope, function);
            return;
        }
        self.simple(command, scope, function, pipeline);
    }

    /// A site that only expands words (for lists, case words, `[[ ]]`).
    fn words_only(&mut self, words: &[String], scope: usize, function: Option<&str>) {
        if words.iter().any(|w| w.contains('$') || w.contains('`')) {
            let site = CommandSite {
                command: SimpleCommand {
                    words: std::iter::once(Arg::value(":"))
                        .chain(words.iter().map(|w| Arg::raw(w.clone())))
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

    /// Redirections attached to a compound command (`{ ...; } > file`).
    fn simple_redirects_only(
        &mut self,
        command: &CommandNode,
        scope: usize,
        function: Option<&str>,
    ) {
        let redirects = redirects(command);
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

    fn simple(
        &mut self,
        command: &CommandNode,
        scope: usize,
        function: Option<&str>,
        pipeline: Option<PipelineInfo>,
    ) {
        let mut assignments = Vec::new();
        let raws_aligned = command.assignment_raws.len() == command.assignments.len();
        for (index, (name, value)) in command.assignments.iter().enumerate() {
            if name.starts_with("__RUBASH_PARSE_ERROR") {
                if self.script.parse_error.is_none() {
                    self.script.parse_error = Some(format!("syntax error near {value:?}"));
                }
                continue;
            }
            if name.starts_with("__RUBASH_") {
                continue;
            }
            let raw = if raws_aligned {
                command.assignment_raws[index].clone()
            } else {
                value.clone()
            };
            assignments.push((name.clone(), Arg::raw(raw)));
        }
        let words = stage_words(command);
        let stdin_text = command
            .heredoc_redirects
            .iter()
            .filter(|h| h.fd.unwrap_or(0) == 0)
            .find_map(|h| h.body.clone())
            .or_else(|| command.here_string.clone());
        let simple = SimpleCommand {
            assignments,
            words,
            redirects: redirects(command),
            stdin_text,
        };
        if simple.words.is_empty() && simple.assignments.is_empty() && simple.redirects.is_empty() {
            return;
        }
        self.script.sites.push(CommandSite {
            command: simple,
            pipeline,
            origin: Origin::Main,
            scope,
            function: function.map(str::to_string),
        });
    }
}

/// The words of a simple command as written.
fn stage_words(command: &CommandNode) -> Vec<Arg> {
    if command.word_metadata.len() == command.words.len() && !command.words.is_empty() {
        command
            .word_metadata
            .iter()
            .map(|m| Arg::raw(m.raw.clone()))
            .collect()
    } else {
        command
            .words
            .iter()
            .map(|w| Arg::raw(strip_carriers(w)))
            .collect()
    }
}

/// Drop the engine's in-band quoting carriers from a word that has no
/// recorded source text.
fn strip_carriers(word: &str) -> String {
    word.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

fn redirects(command: &CommandNode) -> Vec<Redirect> {
    command
        .redirects
        .iter()
        .filter_map(|r| {
            let access = match r.kind {
                RedirectKind::Input => Access::Read,
                RedirectKind::Output
                | RedirectKind::ClobberOutput
                | RedirectKind::CombinedOutput => Access::Write,
                RedirectKind::Append | RedirectKind::CombinedAppend => Access::Append,
                RedirectKind::ReadWrite => Access::ReadWrite,
                RedirectKind::DuplicateOutput => {
                    let operand = r.target.trim_start_matches('&');
                    if operand == "-" || operand.chars().all(|c| c.is_ascii_digit()) {
                        return None;
                    }
                    Access::Write
                }
                _ => return None,
            };
            let raw = if r.target_metadata.raw.is_empty() {
                r.target.clone()
            } else {
                r.target_metadata.raw.clone()
            };
            Some(Redirect {
                fd: r.fd,
                access,
                target: Arg::raw(raw.trim_start_matches('&').to_string()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Script {
        RubashParser { posix: false }.parse(source)
    }

    #[test]
    fn simple_pipeline_and_lists() {
        let script = parse("cd /tmp && rm -rf x | cat; echo $(git status)");
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
    fn compound_bodies_and_functions() {
        let script = parse(
            "if true; then git push -f; fi; f() { rm -rf /; }; for i in a b; do echo $i; done",
        );
        assert!(script
            .sites
            .iter()
            .any(|s| s.command.words.first().map(Arg::text) == Some("git")));
        let rm = script
            .sites
            .iter()
            .find(|s| s.command.words.first().map(Arg::text) == Some("rm"))
            .unwrap();
        assert_eq!(rm.function.as_deref(), Some("f"));
    }

    #[test]
    fn redirects_and_heredocs() {
        let script = parse("cat > out.txt 2>&1 < in.txt\nbash <<'EOF'\nrm -rf ~\nEOF\n");
        let cat = &script.sites[0].command;
        assert_eq!(cat.redirects.len(), 2);
        assert_eq!(cat.redirects[0].access, Access::Write);
        assert_eq!(cat.redirects[1].access, Access::Read);
        let bash = &script.sites[1].command;
        assert!(bash
            .stdin_text
            .as_deref()
            .unwrap_or("")
            .contains("rm -rf ~"));
    }

    #[test]
    fn quoted_words_keep_source_text() {
        let script = parse("rm -rf \"$x\" '/a b'");
        let words: Vec<&str> = script.sites[0]
            .command
            .words
            .iter()
            .map(Arg::text)
            .collect();
        assert_eq!(words, vec!["rm", "-rf", "\"$x\"", "'/a b'"]);
    }
}
