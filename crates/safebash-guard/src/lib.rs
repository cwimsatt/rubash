//! safebash-guard: the command-safety policy engine behind safebash.
//!
//! The guard decides whether a shell command an LLM agent issued may run.
//! It is the "what to block" half of safebash; the rubash engine's
//! execution gate (`rubash::exec_gate`) is the "where to block" half. The
//! rule set and many techniques are harvested from cc-safety-net (static
//! pre-execution analysis of agent tool calls) and safeexec (terminal
//! confirmation of destructive commands); see `docs/safebash/` for the
//! provenance of each rule.

pub mod analyze;
pub mod audit;
pub mod guard;
pub mod model;
pub mod paths;
pub mod platform;
pub mod policy;
pub mod redact;
pub mod rules;
pub mod secondary;
pub mod targets;
pub mod verdict;
pub mod words;

pub use guard::{Decision, Guard};
