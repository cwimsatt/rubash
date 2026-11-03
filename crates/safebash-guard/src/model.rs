//! The neutral command model the analyzer reads.
//!
//! The guard never parses shell syntax itself. The host shell (safebash,
//! on top of the rubash engine) converts what its own parser produced into
//! these values, so the analyzer and the executor always agree on the
//! structure of a command: there is no second parser to disagree with.
//! Word *semantics* (quoting, known variables, globs, brace lists,
//! substitutions) stay in the guard (`crate::words`), so every host gets
//! the same reading.

/// One argument as the host knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// Source text of a word that has not been expanded (static analysis).
    Raw(String),
    /// A concrete value produced by the shell's own expansion (run time).
    Value(String),
}

impl Arg {
    pub fn raw(text: impl Into<String>) -> Arg {
        Arg::Raw(text.into())
    }

    pub fn value(text: impl Into<String>) -> Arg {
        Arg::Value(text.into())
    }

    pub fn text(&self) -> &str {
        match self {
            Arg::Raw(text) | Arg::Value(text) => text,
        }
    }
}

/// One evaluated shell word, as the rules read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Word {
    /// Fully known text, quotes removed.
    Lit(String),
    /// Text with an unquoted pathname pattern (`*`, `?`, `[`); the string
    /// is the pattern with quotes removed.
    Glob(String),
    /// Text that depends on run-time state (parameter, command or
    /// arithmetic expansion); the string is the word as written. Static
    /// analysis cannot know its value; the run-time gate will.
    Dyn(String),
}

impl Word {
    pub fn lit(text: impl Into<String>) -> Word {
        Word::Lit(text.into())
    }

    /// The literal value, when fully known.
    pub fn as_lit(&self) -> Option<&str> {
        match self {
            Word::Lit(text) => Some(text),
            _ => None,
        }
    }

    /// The best available text: the value, the pattern, or the source.
    pub fn text(&self) -> &str {
        match self {
            Word::Lit(text) | Word::Glob(text) | Word::Dyn(text) => text,
        }
    }

    pub fn is_lit(&self) -> bool {
        matches!(self, Word::Lit(_))
    }
}

/// How a redirection uses its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Append,
    ReadWrite,
}

impl Access {
    pub fn writes(self) -> bool {
        !matches!(self, Access::Read)
    }

    pub fn reads(self) -> bool {
        matches!(self, Access::Read | Access::ReadWrite)
    }
}

/// A file redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub fd: Option<u32>,
    pub access: Access,
    pub target: Arg,
}

/// A simple command: prefix assignments, words, file redirections and the
/// text fed to its stdin by a heredoc or here-string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimpleCommand {
    pub assignments: Vec<(String, Arg)>,
    pub words: Vec<Arg>,
    pub redirects: Vec<Redirect>,
    pub stdin_text: Option<String>,
}

impl SimpleCommand {
    /// A command made of concrete words (run time).
    pub fn from_values<I, S>(argv: I) -> SimpleCommand
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        SimpleCommand {
            words: argv
                .into_iter()
                .map(|word| Arg::Value(word.into()))
                .collect(),
            ..SimpleCommand::default()
        }
    }
}

/// Where a command sits, for messages and for rules that care.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Origin {
    /// Runs as part of the script's own flow.
    #[default]
    Main,
    /// Inside `$(...)`, backquotes or a process substitution.
    Substitution,
    /// Text handed to another shell (`bash -c`, `eval`, a sourced file),
    /// analyzed as a nested script.
    Nested,
}

/// Pipeline context of a command: every stage's words, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineInfo {
    /// This command's position, 0-based.
    pub index: usize,
    pub stages: Vec<Vec<Arg>>,
}

/// One command of a script, with its context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSite {
    pub command: SimpleCommand,
    pub pipeline: Option<PipelineInfo>,
    pub origin: Origin,
    /// The shell environment this command runs in: `cd` in one scope does
    /// not move another. Scope 0 is the script's top level; a subshell,
    /// pipeline stage or substitution opens a new scope.
    pub scope: usize,
    /// The function whose body holds this command; such commands are
    /// analyzed only where the function is called.
    pub function: Option<String>,
}

impl CommandSite {
    pub fn new(command: SimpleCommand) -> CommandSite {
        CommandSite {
            command,
            pipeline: None,
            origin: Origin::Main,
            scope: 0,
            function: None,
        }
    }
}

/// A parsed script: its commands in source order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    pub sites: Vec<CommandSite>,
    /// `scope_parents[i]` is the scope that opened scope `i` (scope 0 is
    /// its own parent).
    pub scope_parents: Vec<usize>,
    /// The parser's first error, when the text did not parse completely.
    pub parse_error: Option<String>,
}

/// The guard's view of a shell parser: the host converts script text into
/// a [`Script`]. Implemented by safebash with the rubash parser, so nested
/// scripts (`bash -c '...'`, `eval`, command substitutions) are read
/// exactly the way the shell itself will read them.
pub trait ScriptParser: Send + Sync {
    fn parse(&self, source: &str) -> Script;
}
