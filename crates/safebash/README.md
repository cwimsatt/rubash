# safebash

A bash-compatible shell — the [rubash](../../README.md) engine — with
LLM-agent safety checks built into its execution path. The destructive-
command and secret-access blocks an AI coding agent usually gets from an
external pre-tool-call hook run *inside the shell*, so they apply to every
command it runs, including ones built at run time by `eval`, `$(...)`,
variables, functions and `bash -c` that a static pre-execution hook cannot
see.

It is a first Linux port. The design is cross-platform (Windows-aware) and
documented in [`docs/safebash/design.md`](../../docs/safebash/design.md);
rule provenance is in [`docs/safebash/harvest.md`](../../docs/safebash/harvest.md).

## Build

```bash
cargo build -p safebash
```

## Use it as a shell

```bash
safebash -c 'rm -rf build'          # allowed (inside the workspace)
safebash -c 'rm -rf /'              # blocked (status 126)
safebash -c 'cat ~/.ssh/id_rsa'     # blocked / asks to confirm at a terminal
safebash script.sh                  # analyzed, then run
```

A blocked command finishes with status 126 and a diagnostic naming the
rule and what to do next. At the standard level a person can approve a
borderline command at the terminal with a one-time token; with no terminal
it is denied.

## Check a command without running it

```bash
safebash --guard-check 'git reset --hard'       # prints the decision
safebash --guard-explain --json 'rm -rf $x /'   # full report as JSON
safebash --guard-status                         # effective policy + host facts
```

## Policy

Three levels — `standard` (default), `strict`, `paranoid` — configured in
`~/.config/safebash/policy.toml` and, per repository, in
`<workspace>/.safebash/policy.toml` (tighten-only). Environment variables
`SAFEBASH_LEVEL`, `SAFEBASH_STRICT`, `SAFEBASH_PARANOID` can only raise
protection. Example:

```toml
level = "strict"

[rules]
"git.push-force" = "off"          # allow force-push in this setup
"pkg.audit-fix-force" = "deny"    # never even offer to confirm it

[secrets]
allow = [".env.local"]            # not a secret in this project
```

## What it is not

Not a sandbox. It gates what *this shell* dispatches, judged on the real
expanded command; it does not contain a child process once started, set
filesystem permissions, or watch network egress. A program the shell
launches that itself deletes files is outside the gate.
