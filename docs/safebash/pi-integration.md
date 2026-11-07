# safebash as pi's shell

This is a **first-draft** integration guide for using safebash as the command-safety gate of the
[pi coding agent](https://github.com/earendil-works/pi) in **pure Rust, with no TypeScript**. It
accompanies the code change that adds safebash's non-interactive mode. The design under review is
`SAFEBASH-PI` (Codex design rounds 1 to 3, verdict ready).

## How it works

pi resolves the shell for its `bash` tool from the `shellPath` setting and runs
`<shellPath> -c "<command>"` for every bash tool call (`utils/shell.ts`, `tools/bash.ts`). Point
`shellPath` at safebash and pi runs every command through the gate: safebash parses the command,
applies the safebash-guard policy, and - on allow - executes it with the built-in rubash engine, so
all three runtime enforcement boundaries (command dispatch, redirect target, spawn backstop) stay in
force. The gate *is* the shell; there is no extension and no TypeScript.

```jsonc
// ~/.pi/agent/settings.json
{
  "shellPath": "C:\\path\\to\\safebash-pi.exe"   // or "~/bin/safebash-pi" on Unix
}
```

## Non-interactive mode (Confirm becomes deny)

pi runs the shell unattended and cannot answer a confirmation prompt. safebash must therefore
**never prompt** on this path: a Confirm verdict becomes a denial (the existing no-approver branch in
`Guard::decide`). Because pi passes only `-c` and the command - never a safebash flag - the
executable selects this mode **itself**, one of two ways:

1. **By its own name.** Invoke safebash as `safebash-pi` - a dedicated build, or a renamed copy /
   hardlink / symlink of `safebash`. `main` detects the `safebash-pi` file stem (the same mechanism
   that detects `sh` for POSIX mode) and runs non-interactive. This is the recommended setup: point
   `shellPath` at `safebash-pi` and nothing else is needed.
2. **By configuration.** Set the environment variable `SAFEBASH_NONINTERACTIVE` to a non-empty value
   other than `0` in the environment pi runs in. Use this when renaming the binary is inconvenient.

When the mode is active, safebash also sets `SAFEBASH_NONINTERACTIVE=1` for its children, so nested
safebash invocations and background respawns stay non-interactive too.

A denied command exits non-zero; safebash writes the guard verdict (rule id and reason, secrets
redacted) to stderr, and pi records the failed command so the agent sees why. A command that needs
human approval is denied, not queued: run it yourself in an interactive shell when you intend it.

## What is gated, and what is not

| pi execution surface | Gated by safebash? |
|---|---|
| `bash` tool (model-issued), and nested/tool-initiated bash that reaches the standard local backend | **yes** |
| Custom operations that replace the local bash backend | **no** - a separate route an extension can install |
| User `!` / `!!` (`user_bash`) | **unverified** - the backend chooser (`agent-session.ts`) was not traced; do not assume it is gated |
| `powershell` tool (Windows) | **no** - PowerShell ignores `shellPath`; disable the tool (below) |
| Extension `pi.exec` / inline-bash / interactive-shell | **no** - spawns directly; pi treats extensions as trusted |

### Disabling the `powershell` tool

`powershell` is **not** a default tool (the startup default is `read`, `bash`, `edit`, `write`), so
this route is open only if you have enabled it. To close it, removing it from `defaultTools` and
running `/reload` is **not enough**: `/reload` enables newly added tools but does not disable a tool
removed from the selection, and a project `.pi/settings.json` list or a `--tools` command-line
selection can override the user setting. To disable it reliably:

1. Remove `powershell` from the effective startup selection in `~/.pi/agent/settings.json`
   (and from any `+powershell` entry).
2. Confirm no project `.pi/settings.json` list and no `--tools` command-line option re-adds it.
3. **Restart pi** (not `/reload`) - this is also pi's own instruction for changing the PowerShell
   tool.

## Not in this draft

- **The Jev secondary check is deliberately out of scope** for this integration (owner decision):
  safebash as pi's shell runs the rule-based gate only; no secondary checker is installed on this
  path. A later change may fold in separate Jev work.
- The `user_bash` trace, the PowerShell gap, and the custom-operations / `pi.exec` routes are
  documented limits, not closed here.
