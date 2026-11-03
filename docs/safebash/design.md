# safebash: a bash-compatible shell with built-in LLM-agent safety checks

safebash is the [rubash](../../README.md) engine with a safety gate wired
into its execution path. The checks an LLM coding agent normally gets from
an *external* PreToolUse hook (cc-safety-net) or a *wrapper* on each binary
(safeexec) are moved **inside the shell itself**, so they apply to every
command the shell runs — including commands produced at run time by
`eval`, `$(...)`, functions, variables and `bash -c`, which a static
pre-execution hook cannot see.

It is built from four source projects (the user's harvesting plan):

- **rubash** — the primary engine: a from-scratch GNU Bash 5.3 engine in
  Rust, embeddable and natively cross-platform (no POSIX emulation layer).
  safebash adds a process-wide execution gate to it and ships a binary that
  installs the gate, then runs the unmodified engine.
- **brush** — a second Rust bash. Harvested for its bash-compatibility
  corpus (3,230 `stdin` scripts), used as a false-positive oracle: ordinary
  shell must not be blocked.
- **cc-safety-net** — a TypeScript PreToolUse analyzer. Harvested for *what
  to block* (its ~74 destructive rules, ~140 secret rules, the block-intent
  denial format) and *how* (unwrapping, the recursive-delete classifier,
  fail-closed budgets, the tighten-only policy merge). Its hand-edited
  verdict corpus (6,983 rows) is a cross-check.
- **safeexec** — a Bash wrapper that gates destructive commands behind a
  TTY one-time-token confirmation. Harvested for the confirmation gate and
  the package-manager `audit fix --force` rule.

awesome-jev-compaction and the two harness repos are reference only; a
TypeSafe **Jev** second-opinion check is planned for a later phase and has
an interface reserved today (§7).

## Layout

```
crates/safebash-guard/   the policy engine (no rubash dependency)
  model.rs      neutral command model the rules read
  words.rs      static word evaluation (quote removal, known vars, globs, braces, substitutions)
  paths.rs      path normalization, canonicalization, temp-root trust
  targets.rs    the recursive-delete classification ladder
  policy.rs     levels, capabilities, per-rule overrides, tighten-only merge
  rules/        one module per family (rm, git, find, xargs, device, network, interp, secrets, guards, windows, text, pkg)
  verdict.rs    findings, actions, the agent-facing denial text
  secondary.rs  the reserved Jev second-opinion interface
  audit.rs      append-only JSONL decision log
  platform.rs   config/state dirs and the TTY confirmation prompt
  guard.rs      the facade: analysis entry points + the decision procedure

crates/safebash/         the gated shell binary
  convert.rs    rubash AST -> guard model (the shell's own parser feeds the guard)
  setup.rs      host facts (workspace, home, temp roots, git metadata, protected paths)
  gate.rs       implements rubash::exec_gate::ExecGate with the guard
  main.rs       installs the gate, runs the rubash engine; also the --guard-* CLI

src/exec_gate.rs         the engine-side hook (rubash); no-op without a gate
```

The guard crate has **no dependency on rubash**: it is a reusable policy
engine. The binding to the engine lives entirely in `crates/safebash` and
in the single new engine module `src/exec_gate.rs`.

## Threat model

- **Adversary:** an LLM agent that issues shell commands, assumed helpful
  but fallible (hallucinated `rm -rf`, a wrong path, a copied-in
  `curl | sh`) at the standard level, and assumed capable of obfuscation
  (dynamic construction, indirection) at strict/paranoid.
- **Protected:** the user's data and machine — destructive filesystem and
  disk operations, exfiltration of local secrets, and the integrity of
  safebash's own policy and the repo's Git metadata.
- **Not a sandbox.** safebash gates what *this shell* runs. It does not
  contain a child process once started, set filesystem permissions, or
  watch network egress. A program the shell launches that itself deletes
  files (a Makefile recipe, `python tool.py`) is outside the gate — the
  same boundary cc-safety-net documents (RR-9). The honest guarantee is:
  no command the shell *dispatches* runs without passing the gate, judged
  on its real expanded form.

## Where the gate runs: four layers

The engine consults the gate at four boundaries, each *after* the shell has
done its own work, so the gate judges what will really happen — not the
text the user typed.

1. **Preflight** (`main.rs`): a `-c` string or a script operand is parsed
   and analyzed as a whole before anything runs. It enforces only the
   denials no confirmation can lift (catastrophic rules, the
   self-protection guards, dynamic-source and other `analysis.*` rules), so
   those are stopped with zero partial effects. Confirmable findings are
   left to layer 2.
2. **Dispatch** (`exec_gate::check_command`, hooked in
   `executor/command_execute.rs` at the funnel every simple command
   reaches after expansion and alias resolution): the fully expanded argv
   and prefix assignments, before dispatch to a function, builtin, emulated
   external or child process. This is where `x=-rf; rm $x /`,
   `$(printf r)m`, `c="rm -rf d"; $c`, and a function body become concrete.
3. **Redirect** (`exec_gate::check_redirect`, hooked in
   `executor/expand_word.rs::expand_redirect_target`): every file
   redirection target once expanded, before the file is opened. A denied
   target is rewritten to an unopenable path so the redirection — and its
   command — fails.
4. **Spawn** (`exec_gate::check_spawn`, hooked at every `Command::spawn` /
   `exec` for a user command): the completeness backstop. No external
   process starts without passing it, whichever executor path launched it
   (pipeline stage, background job, coproc, `exec`, process substitution).

A denied command finishes with status **126** (bash's "found but not
executable"), and the gate's diagnostic is written to the shell's stderr.
Without an installed gate, every `exec_gate` helper is a no-op, so the
plain `rubash` binary is byte-for-byte unchanged.

### Why four layers, not one

A static pre-execution hook (cc-safety-net) sees only the command text and
must deny the whole line up front; it cannot know a variable's value or
whether a `cd` succeeded. safebash's dispatch/redirect/spawn layers see the
*real* expansion, which closes the documented static-analysis gaps
(cc-safety-net RR-1, RR-2, RR-3, RR-6, RR-7, RR-8: dynamic executables,
substituted structure, unverifiable targets, glob/IFS/brace emulation,
runtime shell-state, quoting tricks). The preflight layer keeps the one
thing a runtime gate loses — stopping a dangerous *first* command before
any earlier command in the line has run — for the cases where it matters
most (catastrophic and un-confirmable denials).

Nested shells are handled by analysis, not interception: `bash -c '...'`,
`eval`, `source`, `trap`, interpreter one-liners and `find -exec` bodies
are parsed with the **same rubash parser** and analyzed as nested scripts
(bounded to depth 10). For the standard level, a dynamic source the static
pass cannot resolve (`eval "$x"`, `bash -c "$x"`) is deferred: the command
it ultimately runs still reaches the dispatch gate. Strict denies the
unresolvable source up front.

## Policy

Three preset **levels** map to capabilities (harvested from
cc-safety-net):

| Level | `fail_closed` | `paranoid_rm` | `paranoid_interpreters` |
|-------|---------------|---------------|-------------------------|
| standard (default) | off | off | off |
| strict | on | off | off |
| paranoid | on | on | on |

- **standard** targets a helpful agent: block what is clearly destructive;
  let the runtime gate resolve what static analysis cannot; allow a person
  to confirm a borderline command at the terminal.
- **strict** (`fail_closed`) denies anything unverifiable — dynamic shell
  sources, dynamic recursive-delete targets — and never prompts.
- **paranoid** additionally denies every recursive force-delete outside a
  temp root and every interpreter one-liner.

Resolution order (each step can only *raise* protection): user policy file
→ project policy file (tighten-only) → `SAFEBASH_*` environment. A broken
or hostile config file falls back to protective defaults with a warning,
never locks the agent out.

- **User policy:** `~/.config/safebash/policy.toml` (`%APPDATA%\safebash`
  on Windows).
- **Project policy:** `<workspace>/.safebash/policy.toml`, always
  tighten-only — a repository an agent can write to must never weaken the
  user's protection. Weakening fields are dropped with a warning; this is
  stricter than cc-safety-net, where tighten-only is opt-in
  (`CC_SAFETY_NET_PROJECT_TIGHTEN_ONLY`).
- **Environment:** `SAFEBASH_LEVEL`/`SAFEBASH_FLOOR`, `SAFEBASH_STRICT`,
  `SAFEBASH_PARANOID`. A parent safebash exports `SAFEBASH_FLOOR` and
  `SAFEBASH_WORKSPACE` so a nested shell is never weaker and is anchored to
  the same workspace; those two variables are themselves protected
  (`guard.safebash-env`) from being set, exported or unset by a command.

Per-rule overrides are `off` / `confirm` / `deny`. Catastrophic rules, the
self-protection guards and the `analysis.*` rules cannot be switched off.

## Decisions and confirmation

A finding carries an **action** — `Allow` < `Confirm` < `Deny` — and a
**block intent** (`hard_stop`, `use_alternative`, `scope_down`,
`manual_only`, `stop_and_explain`, harvested verbatim from cc-safety-net)
that tells the agent what to do next. The strictest action across a
command's findings wins; among equal actions the earliest stage (guard,
then secret, then rule) is reported, matching cc-safety-net's "first stage
that denies wins."

At the standard level a non-fixed `Deny` is offered to a **person** as a
`Confirm`: the safeexec gate, ported to Rust (`platform.rs`). It reads the
controlling terminal (never stdin, so `echo confirm |` cannot answer it),
refuses when the shell is not in the terminal's foreground process group,
and asks for a one-time token (`confirm 3FA9C1`). With no usable terminal a
`Confirm` becomes a denial. An approval at the dispatch layer is remembered
briefly so the spawn backstop for the same command does not ask again.

## Audit

Every decision (denials always; allowed commands when
`audit.log_allowed`) is appended as redacted JSONL to
`~/.local/state/safebash/audit/<date>.jsonl` (dirs `0700`, files `0600`).
Redaction patterns are harvested from cc-safety-net and cover provider
tokens, private keys, URL credentials, auth headers and `NAME=secret`
assignments. I/O errors are swallowed — auditing never changes a decision.

## Windows

Linux is the first port; the design is Windows-aware throughout:

- the engine already runs natively on Windows (rubash's fork-free model);
- `paths.rs` folds `C:\x`, `c:/x` and MSYS `/c/x` to one case-insensitive
  form, and handles drive and UNC roots;
- the `cmd /c` and `powershell`/`pwsh` analyzers (`rules/windows.rs`) ship
  in the Linux build because they are reachable from a POSIX shell (WSL
  interop, Git Bash habits) and are the native path on Windows;
- `platform.rs` has a Windows arm for config/state dirs; the one piece not
  yet implemented is the Windows console confirmation prompt
  (`CONIN$`/`CONOUT$` plus a `GetConsoleProcessList` foreground check) —
  until then a `Confirm` denies on Windows rather than prompting.

## Phases

1. **This change (Linux):** the guard engine, the four-layer gate, the
   policy model, the confirmation gate, audit, self-protection, the
   `--guard-check`/`--guard-explain`/`--guard-status` CLI, and the test
   suites. Windows-aware but not yet verified on Windows.
2. **Jev secondary check:** wire a TypeSafe Jev second opinion behind the
   deterministic rules (§7), in shadow mode first.
3. **Windows verification:** the console confirmation prompt and the
   `full-check-windows`-style CI cross-check.

## 7. The reserved Jev interface

`secondary.rs` defines the hook for the planned phase-2 check without
building it. A `SecondaryCheck` is consulted only for commands the
deterministic rules already allow (or would let a person confirm), at the
dispatch layer, with the fully expanded command. It can only **raise** the
verdict (`Allow` < `Confirm` < `Deny`) — a model can be steered by the very
text it judges, so it must never be able to unblock anything. The guard
owns redaction, the mode (`Off`/`Shadow`/`Enforce`), the deadline and the
audit record; a checker only answers. This matches how the reference repos
use Jev: a deterministic gate first, a one-hop model second opinion after,
disagreements surfaced to the owner, rolled out in shadow mode. Jev is a
remote, non-generative model call (typed yes/no answers, no free text); it
is not a security boundary and only tightens the deterministic decision.
