# safebash — Windows port handoff

**For:** a fresh Opus coding session that will finish the Windows port of
safebash.
**From:** the session that built the Linux-first, Windows-aware
implementation.
**Branch:** `caseyf/adoring-albattani-q3wtas` on `cwimsatt/rubash`
(commits `c12d80b` engine gate, `5801dcc` safebash layer). Work on that
same branch unless told otherwise.

> **Round 2 update (two cross-platform safety fixes already landed on this
> branch — rebase before you start):**
>
> 1. **Ungated respawn exe-selection (FIXED).** Background jobs, coprocs,
>    `trap` actions and process-substitution children respawn the shell on a
>    script body; the exe-selection chain preferred `CARGO_BIN_EXE_rubash`
>    (an ordinary, agent-settable env var) and a `deps/`-sibling / `PATH`
>    `rubash` over the current executable, so a respawn could run the body
>    in an **ungated** engine (e.g. `coproc { read t; rm -rf "$t"; }`). Fixed
>    with one engine helper, `rubash::exec_gate::respawn_exe` (`src/exec_gate.rs`):
>    when a gate is installed, a respawn is forced to `current_exe()` (the
>    gated shell) or fails closed; the four chains at
>    `src/executor/compound_exec.rs` (background + coproc),
>    `src/executor/trap_exec.rs`, and `src/executor/external_setup.rs` now go
>    through it. Proof: `crates/safebash/tests/respawn_gate.rs`.
> 2. **Workspace-widening respawn (FIXED).** `setup::workspace()` fell
>    through to the cwd when an inherited `SAFEBASH_WORKSPACE` didn't contain
>    it, so a parent could `cd` to a sibling tree and background a delete
>    whose child re-anchored to the wider cwd. Now an inherited, usable
>    `SAFEBASH_WORKSPACE` is always the anchor (never widened); see
>    `resolve_workspace` + its unit tests in `crates/safebash/src/setup.rs`
>    and the rule in `design.md`.
>
> Both affected the **shipped Linux build**, not just Windows. T4 below is
> narrowed accordingly — your remaining job there is to confirm the
> exe-forcing invariant holds on the Windows spawn paths.

Read these first, in order, then this file's task list:
1. `docs/safebash/design.md` — the whole architecture (four-layer gate,
   policy model, confirmation, audit, the "Windows" section).
2. `docs/safebash/harvest.md` — rule provenance and deliberate differences.
3. `AGENTS.md` — rubash's engineering rules. **The "Windows verification"
   section is mandatory process for you** (probe branches, the
   `full-check-windows` CI job, no local Windows repro on a Linux/macOS box).

Everything compiles and all tests pass on Linux today. The Windows target
could **not** be built in the origin environment (the cloud box is Linux
and `rustup target add x86_64-pc-windows-msvc` is blocked by its proxy), so
**nothing here is Windows-verified** — that is your job. rubash itself
already runs natively on Windows (fork-free model, `windows-sys`,
`src/fd/windows_impl.rs`), and `cargo check --target x86_64-pc-windows-msvc`
runs in CI for the engine; extend that to the new crates.

---

## 0. What you are porting

Two new crates plus one engine hook (see `design.md` for the full map):

- `src/exec_gate.rs` — engine hook, no-op without an installed gate.
- `crates/safebash-guard/` — the policy engine (no rubash dep).
- `crates/safebash/` — the gated shell binary: installs the gate, runs the
  unmodified rubash engine.

The gate fires at four layers: **preflight** (whole `-c`/script up front),
**dispatch** (every expanded simple command), **redirect** (every expanded
redirection target), **spawn** (every child process, as a backstop).

### What already works on Windows by construction (verify, don't rebuild)

- **The dispatch layer is platform-agnostic.** `Executor::exec_gate_denies`
  is called from `src/executor/command_execute.rs` for every expanded
  command regardless of OS. This is the primary layer; it already judges
  `rm`, `git`, `cmd /c …`, `powershell …`, secrets, etc. on Windows.
- **The spawn backstop fires on Windows.** Every `exec_gate::spawn(&mut
  process)` site wraps a `std::process::Command`, and on Windows
  `Command::spawn` calls `CreateProcessW` internally — so user external
  commands pass `check_command_spawn` on Windows exactly as on Linux. (The
  list of sites: `grep -rn 'exec_gate::spawn' src`.)
- **`crates/safebash-guard/src/rules/windows.rs`** — the `cmd /c` and
  `powershell`/`pwsh` analyzers already ship in the Linux build (they are
  reachable from a POSIX shell via WSL/Git Bash) and are covered by
  `contract.rs` and the harvested corpus. On Windows they become the native
  path; the logic is the same.
- **`crates/safebash-guard/src/paths.rs`** — `PathStyle::Windows` already
  folds `C:\x`, `c:/x`, MSYS `/c/x` → `c:/…` (lower-cased), handles drive
  roots and UNC roots, and `default_temp_roots` handles the Windows `TEMP`.
  It has unit tests (`windows_folding`). `PathStyle::native()` returns
  `Windows` on a Windows build, so `setup.rs` picks it up automatically.
- **`crates/safebash-guard/src/platform.rs`** — `config_dir`
  (`%APPDATA%\safebash`), `state_dir` (`%LOCALAPPDATA%\safebash`),
  `home_dir` (`%USERPROFILE%`) already have Windows arms.
- **`crates/safebash/src/setup.rs`** — `git_metadata` discovery, workspace
  anchoring, protected paths are path-style-generic.

---

## 1. The task list (in priority order)

### T1 — Windows confirmation prompt (REQUIRED; currently denies everything confirmable)

**File:** `crates/safebash-guard/src/platform.rs`, the `#[cfg(windows)] mod
imp` block. It currently returns `Confirmation::Unavailable`, which turns
**every `Confirm` finding into a denial on Windows** — so a human can never
approve a borderline command at a Windows terminal. The Unix arm
(`#[cfg(unix)] mod imp`) is the reference: read `/dev/tty`, require
foreground, demand a one-time token.

Implement the Windows equivalent:
1. Open the console directly, not stdin/stdout: `CreateFileW("CONIN$", …)`
   and `CreateFileW("CONOUT$", …)`. This defeats `echo confirm | …` the
   same way `/dev/tty` does on Unix.
2. Foreground/console check: there is **no process-group `tpgid` on
   Windows**. Use `GetConsoleProcessList` and/or `GetConsoleWindow` to
   require that this process is attached to a real interactive console
   (and, best-effort, is the one the user is typing into). Document plainly
   in the code that this guarantee is **weaker than Unix foreground
   detection** — Windows has no cheap "am I the foreground job" test, so
   the honest promise is "a real console session is present," not "no
   background pane can answer." If no interactive console → return
   `Unavailable` (denies), same as Unix with no tty.
3. Write the red `[safebash] …` prompt + the `confirm <TOKEN>` line to
   `CONOUT$`, read one line from `CONIN$`, compare to the expected
   `confirm <token>`. Approved / Declined / Unavailable exactly as Unix.
4. Reuse `super::challenge_token()` (already cross-platform).

**Cargo:** add to `crates/safebash-guard/Cargo.toml`:
```toml
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.61", features = [
  "Win32_Foundation", "Win32_Storage_FileSystem", "Win32_System_Console",
] }
```
Match the `windows-sys` major version the engine already pins (`0.61.2` in
the root `Cargo.toml`) so the workspace resolves one copy.

**Acceptance:** on a Windows console, `safebash -c 'git reset --hard'`
prompts for `confirm <token>`; the correct token runs it once, a wrong
reply cancels (exit 126), and a redirected/no-console invocation denies.
Mirror the Unix pseudo-terminal check that the origin session did (it drove
the prompt through a PTY and asserted approve-runs-once / decline-cancels).

### T2 — Windows device-destruction rules (REQUIRED; current rules are Linux-only)

**Files:** `crates/safebash-guard/src/rules/device.rs` and the
`redirect.block-device` check in `crates/safebash-guard/src/rules/redirect.rs`.
Both only know Linux device paths (`/dev/sda`, `dd of=/dev/…`, `mkfs …
/dev/…`). On Windows the dangerous disk operations are different and
currently **unguarded**:

- `format` (e.g. `format C: /q`), `format.com`.
- `diskpart` with destructive scripts (`clean`, `delete`).
- PowerShell storage cmdlets: `Clear-Disk`, `Remove-Partition`,
  `Reset-PhysicalDisk`, `Clear-Content` on a device, `Initialize-Disk
  -Force`, `Format-Volume`.
- `cipher /w:` (wipe free space), `sdelete`.
- A redirect whose literal target is a raw device: `\\.\PhysicalDrive0`,
  `\\.\C:`, `\\.\Volume{…}`.

Add a Windows device family (either a `#[cfg(windows)]`-gated extension of
`device.rs`, or — better — make the patterns part of the always-compiled
rule set the way `windows.rs` already is, so they are testable from the
Linux build too). Give each a catastrophic/manual_only intent matching the
Linux analogues. Add `redirect.block-device` patterns for the `\\.\…`
device namespace. Put the new rule ids in `docs/safebash/harvest.md` and
add contract cases to `crates/safebash/tests/contract.rs` with
`Place`/expectations (these run on Linux since the analyzer is static).

**Also review `rules/windows.rs`:** it already blocks `cmd /c rmdir /s` and
PowerShell `Remove-Item -Recurse -Force` on root/home/git-metadata. Confirm
the root/drive-root detection (`windows_root_or_home`) is complete for the
real Windows filesystem (it is currently exercised against synthetic paths
on Linux; verify `C:\`, `C:\*`, `\\server\share`, `%USERPROFILE%` on a real
box).

### T3 — Reconcile the cwd/path form the engine hands the guard (CORRECTNESS RISK)

This is the subtlest risk. At run time, the gate passes the engine's cwd to
the guard:
- `crates/safebash/src/gate.rs` → `CommandCheck`/`RedirectCheck` carry
  `check.cwd`, which is `&self.shell_state.cwd` (a `PathBuf`) from the
  engine.
- `crates/safebash-guard/src/analyze.rs` → `Host::norm` / `norm_abs` fold
  it via `paths::fold`.

On Windows, **rubash renders `$PWD`/cwd in POSIX `/d/…` form** under its
MSYS persona (see `docs/host-contract.md` and `docs/windows-path-contract.md`
— rubash#537 pins `$PWD` to `/d/…` because drive-form PWD breaks
`nvm_find_up`). So `shell_state.cwd` on Windows may be `/d/proj`, not
`D:\proj`. `paths::fold()` already maps MSYS `/c/x` → `c:/x`, so this
*should* work — **but you must verify it end to end**:
1. What exact string is `shell_state.cwd` on a Windows build? (`/d/proj`,
   `D:\proj`, or `\\?\D:\proj`?) Check `src/executor` and the host
   contract.
2. Does `fold()` produce the same `NormPath` for the cwd AND for a relative
   target resolved against it, so "inside the workspace" is judged
   correctly? Add `paths.rs` unit tests for the actual rubash cwd form.
3. `setup.rs::workspace()` uses `std::env::current_dir()` (gives `D:\…` or
   `\\?\…` on Windows) while the engine's cwd may be `/d/…`. Both go
   through `norm_abs`/`fold`; confirm they converge to the **same**
   `NormPath` so the workspace anchor matches the per-command cwd. A
   mismatch would make every in-workspace `rm -rf build` look "outside" (a
   false positive) or vice-versa.

Read `docs/windows-path-contract.md` §5 and the `tests/path_contract_boundary_*.rs`
suite before touching anything here; the guard must agree with that
contract, not invent its own.

### T4 — Spawn/exec completeness audit on Windows (REDUCED: the exe-identity hole is already fixed)

The respawn exe-identity bypass (Round 2, #1 above) is fixed centrally in
`rubash::exec_gate::respawn_exe`: **when a gate is active every respawn
re-runs `current_exe()`**, so the respawned child is always the gated shell
and re-judges its body at the dispatch layer. Your remaining Windows job is
to confirm that invariant actually holds on Windows:

- **`std::env::current_exe()` must resolve to the safebash `.exe` on
  Windows** (it does by design, but verify — symlinks/`\\?\` prefixes).
- **The oversized respawn uses `crate::fd::spawn_whitelisted`**
  (`src/executor/compound_exec.rs`, Windows impl `CreateProcessW` in
  `src/fd/windows_impl.rs`) with the `exe` now chosen by `respawn_exe` — so
  the child is safebash and re-gates. Confirm the child re-installs the gate
  on Windows (it runs `build_guard` + `exec_gate::install` in
  `crates/safebash/src/main.rs` before `engine::main()`), inheriting
  `SAFEBASH_FLOOR`/`SAFEBASH_WORKSPACE`. Port the Linux proof
  (`crates/safebash/tests/respawn_gate.rs`) to run on the Windows CI job.
- The dispatch layer already judges every command, so the rest is
  belt-and-braces; still verify no external-process path escapes **both**
  the dispatch gate and the spawn backstop on Windows:

- **`exec_gate::exec` is `#[cfg(unix)]` only** (`src/exec_gate.rs:168`).
  On Windows there is no `CommandExt::exec`; rubash *simulates* `exec` via
  `replace_process_image` (`src/builtins/exec.rs:154`,
  `enable_process_replacement` at :100). Confirm the Windows simulation
  spawns through a `exec_gate::spawn`-gated `Command` **or** that the
  dispatch layer already judged the exec target. Note: `exec` is in
  `TRANSPARENT_WRAPPERS` in `analyze.rs`, so `exec rm -rf /` is analyzed as
  its child `rm -rf /` at the dispatch layer — that already covers it.
  Decide whether to add a Windows `exec`-simulation spawn gate anyway.
- **`crate::fd::spawn_whitelisted`** (`src/executor/compound_exec.rs:1893`,
  Windows impl in `src/fd/windows_impl.rs` `CreateProcessW` at :1697) is
  **not** routed through `exec_gate`. It is a respawn of **safebash
  itself** (`current_exe`) for background jobs / oversized `-c` strings, so
  the respawned safebash re-installs the gate and re-judges every command —
  transitively gated. **Verify this on Windows** (the child must inherit
  `SAFEBASH_FLOOR`/`SAFEBASH_WORKSPACE` and re-install the gate; see
  `crates/safebash/src/main.rs::build_guard`). If a respawn can run a raw
  command without a dispatch pass, add a `check_command_spawn` call at the
  `spawn_whitelisted` boundary.
- The `windows-shim` `bash.exe`/`sh.exe` face (`src/bin/bash.rs`, Cargo
  feature `windows-shim`) forwards to a host shell. safebash must **not**
  ship that shim as its own face without gating; confirm safebash's binary
  does not enable `windows-shim` in a way that bypasses the gate.

### T5 — Windows CI + the new crates (REQUIRED to call the port done)

- `.github/workflows/ci.yml` already runs `cargo check --tests --target
  x86_64-pc-windows-msvc` for the engine (`full-check-windows` job +
  cross-target check). **Add `safebash-guard` and `safebash` to that
  check**, and ideally run their unit + integration tests on the native
  Windows job (`contract.rs`, `brush_compat.rs`, `harvested.rs`,
  `safebash-guard` lib tests — all static analysis, so they run anywhere).
- Follow `AGENTS.md` "Windows verification": branch
  `tmp/<topic>-windows-probe` from `origin/main` in a `git worktree`, add a
  `test.skipIf(cfg!(not(windows)))`-style red test, `gh workflow run
  ci.yml --ref <branch>`, read the failure in the job's build/test step,
  fix, re-run green, clean up the worktree. **There is no local Windows
  repro on the dev box** — CI is the only oracle.
- Keep the engine's own Windows tests green: run `cargo build --workspace`
  and `cargo test -p rubash --lib` on the Windows job to confirm the gate
  hook did not regress the engine on Windows (it is a no-op without a host,
  and the 1033 lib tests pass on Linux).

### T6 — Windows secret paths (HARDENING; optional for a first cut)

`crates/safebash-guard/src/rules/secrets.rs` home-tree rules (`~/.ssh`,
`~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`) already resolve under
`%USERPROFILE%` on Windows because git/aws/kubectl use the same dot-dirs
there. Coding-CLI credential paths key off env vars (`CLAUDE_CONFIG_DIR`,
`CODEX_HOME`, …) that are cross-platform. Gaps to consider adding:
- `%APPDATA%` / `%LOCALAPPDATA%` credential stores for tools that use them
  on Windows instead of a dotfile.
- Windows-native secret stores are out of scope (DPAPI blobs, Credential
  Manager) — a filename gate can't meaningfully cover them; note that in
  the docs rather than pretending to.

---

## 2. Acceptance criteria ("done")

1. `cargo build --workspace --target x86_64-pc-windows-msvc` is clean; the
   new crates build on Windows.
2. On a real Windows console: the confirmation prompt works (T1 acceptance)
   and the Windows device rules block `format C:`, `diskpart` clean,
   `Clear-Disk`, and a redirect to `\\.\PhysicalDrive0` (T2).
3. `safebash -c 'rm -rf build'` inside a Windows workspace is **allowed**
   and `rm -rf /` / `rm -rf C:\` is blocked — i.e. the cwd/path
   reconciliation (T3) produces no false positives on in-workspace deletes
   and no false negatives on drive roots. Prove it with the same kind of
   smoke matrix the Linux session used.
4. `safebash`'s pass counts on the Oils spec sweep (see §3) equal plain
   `rubash`'s on Windows — the gate stays transparent to bash
   compatibility on Windows as it is on Linux.
5. The Windows CI job runs the safebash crates' tests and is green (T5).
6. `docs/safebash/design.md` "Windows" section and `harvest.md` are updated
   to say Windows is verified, and any new Windows rule ids are documented.

---

## 3. How to test compatibility against the oracle (bash) on Windows

A prior research pass (see the session transcript / `docs/safebash`) found
the comprehensive oracle-bash corpora. The fastest confidence that the gate
stays transparent on Windows:

- **Oils spec tests** are vendored at `third_party/oil` (Apache-2.0, 222
  files, 135 use bash as oracle). The in-tree `test/sh_spec.py` is a stale
  **Python-2** harness and `spec/bin` helpers are absent, so to *run* it you
  need the current upstream py3 harness (`git clone --depth 1
  https://github.com/oils-for-unix/oils`) or the small py2→py3 shims the
  Linux session used (`cgi`→`html`, `cStringIO`→`io`, inject `xrange`,
  decode pipe bytes, drop `json.loads(encoding=)`). Run a file as:
  `python3 test/sh_spec.py --format ansi --tmp-env <dir> --path-env <PATH>
  spec/arith.test.sh <oracle-bash> <path-to-safebash.exe>` and compare
  safebash's column to a plain-rubash run — they must match.
- **brush** (`/home/user/brush` on the origin box; or clone
  `reubeno/brush`) has a live run-both-and-diff harness: `BRUSH_PATH=<safebash.exe>
  BASH_PATH=<oracle bash> cargo test -p brush-shell --test compat_tests`
  (strip brush-only default args per that repo's notes). It has Windows
  platform tags.
- **Oracle bash version:** pin **GNU bash 5.3** at rubash's vendored
  patchlevel (`third_party/bash/patchlevel.h`), not distro bash. On Windows
  use the owner-compiled 5.3.x per `AGENTS.md` / WSL, never Git Bash as the
  oracle (`AGENTS.md` says Git Bash produces wrong baselines for
  quoting/escaping/braces).

The compatibility suites are destructive in places (`rm`, `touch`), so run
safebash at a permissive gate level for pure engine-parity runs, or expect
gate-induced DIFFs where it blocks a destructive case — compare against
**plain rubash**, not against bash, to isolate gate effects from engine
gaps.

---

## 4. Risks & gotchas, ranked

1. **cwd/path form mismatch (T3)** — the most likely source of silent false
   positives/negatives. rubash's `$PWD` is `/d/…` MSYS form on Windows; the
   guard must fold both that and `std::env::current_dir()`'s `D:\…` to the
   same `NormPath`. Test with the real engine cwd string, not an assumed
   one.
2. **Confirmation "foreground" is weaker on Windows (T1)** — no process
   groups. Don't claim safeexec-equivalent background-theft protection;
   state the real guarantee.
3. **Device rules are net-new (T2)** — Windows disk destruction has no
   `/dev` analogue; you are writing rules, not porting them. Keep them
   falsifiable (name the realistic mistake each prevents) per the project's
   scope-discipline rule.
4. **No local Windows repro** — CI is the only truth. Budget for the
   probe-branch loop; it is slower than Linux iteration.
5. **`windows-sys` version skew** — resolve to the engine's pinned major so
   the workspace links one copy.
6. **Don't touch `third_party/**`** — GPL vendored bash, and the Oils copy
   is a case source, not a runnable harness. Run oracle suites in place or
   from a fresh clone; never copy GPL `.tests`/`.right` into the MIT crates.
7. **Attribution & hooks** — rubash's pre-commit normally runs `cargo fmt
   --check`; keep the new crates formatted (`cargo fmt -p safebash-guard -p
   safebash`). The `core.hooksPath` hook was not installed in the origin
   cloud checkout — do not assume it is absent on yours.

---

## 5. Suggested phase order

1. **T3 first** (path reconciliation) — it underpins every rule's
   correctness on Windows; get the smoke matrix in §2.3 green before
   anything else.
2. **T1** (confirmation prompt) — self-contained, high user value.
3. **T2** (device rules) — net-new, testable from Linux immediately.
4. **T4** (spawn/exec audit) — mostly verification.
5. **T5** (CI wiring) — lock it in so it can't regress.
6. **T6** (secret hardening) — optional.

Commit per logical unit with clear messages; push to
`caseyf/adoring-albattani-q3wtas`. Update `design.md`/`harvest.md` as you
land each piece so the next reader sees current state.
