# What safebash harvested, and where it deliberately differs

This records the provenance of safebash's rules and the known differences
from the sources, so the cross-check numbers in `tests/harvested.rs` are
interpretable rather than mysterious.

## From cc-safety-net (`src/core/rules/*`, `src/gate/*`)

Ported, with rule ids and reason text kept identical so the harvested
verdict corpus can cross-check the port:

- **rm / rmdir** — recursion alone triggers (`rm -r` is judged like
  `rm -rf`); the recursive-delete classification ladder
  (`targets.rs`): root-or-home and git-metadata (catastrophic), temp,
  dynamic (strict), allow-paths, home-cwd, cwd-self, within (paranoid),
  outside.
- **git** — the full subcommand set (checkout/switch/restore/reset/clean/
  rm/push/branch/rebase/merge/tag/reflog/stash/worktree), long-option
  prefix matching from four characters, short-cluster splitting, `-c`/env
  config aliases, and SSH-override network rules.
- **find / rsync / xargs / parallel** — `-delete` scoping, `-exec` bodies
  analyzed as full commands, `-exec rm -rf`, rsync `--delete`
  destinations, and the dynamic-input child analysis (input that can
  become executable source or `rm -rf` targets).
- **device / network** — dd/mkfs/disk-erase/shred/`>` to a block device,
  cloud-metadata endpoints, and curl/wget upload role tables.
- **interpreters / awk** — native root/home deletes, dangerous shell text
  reaching an exec sink, paranoid one-liners, awk `system()`.
- **dynamic source** — `curl | sh`, `bash -c "$(curl …)"`, download-then-run.
- **secrets** — the basename, home-tree, variant, extension and coding-CLI
  lists; the template exemptions; the standard-mode metadata-only and
  name-tier relaxations.
- **self-protection** — the policy-config and git-metadata guards, applied
  to safebash's own policy/state and the repo's `.git`.
- **windows** — `cmd /c` rmdir/del and `powershell`/`pwsh` Remove-Item.
- **machinery** — block intents and the denial message format; the
  fail-closed budget (recursion depth 10, work budget); the tighten-only
  project-policy merge; redaction patterns; the audit record shape.

## From safeexec (`safeexec.sh`)

- The TTY one-time-token confirmation gate (`platform.rs`): read
  `/dev/tty`, require foreground, demand `confirm <token>`, block when no
  usable terminal.
- The package-manager rule `pkg.audit-fix-force` (`npm|pnpm|bun|yarn …
  audit fix --force`), as a `Confirm`.
- safeexec's `git`/`rm` gating is a strict subset of cc-safety-net's and is
  already covered by the ported rules.

## From brush

The bash-compatibility corpus (`tests/data/brush-compat-scripts.jsonl`,
3,230 `stdin` scripts) as a false-positive oracle: `tests/brush_compat.rs`
requires the block rate on real shell to stay under 3% (currently 0.00%).

## Windows device family (this port)

The Windows disk-destruction rules are net-new: `format`/`format.com`,
`diskpart` (clean/delete or a `/s` script), `cipher /w`, `sdelete`, the
PowerShell storage cmdlets (`clear-disk`, `remove-partition`,
`reset-physicaldisk`, `format-volume`), `Clear-Content` to a raw device, and
writes to a `\\.\PhysicalDrive` / `\\.\<drive>:` / `\\.\Volume{…}` device.
New rule ids: `device.format-volume`, `device.diskpart`,
`device.cipher-wipe`, `device.sdelete`, `device.ps-storage-cmdlet`,
`device.raw-device-write` (plus the existing `redirect.block-device`
extended to the `\\.\…` device namespace). There is no bash-suite corpus
for these (they are not shell builtins), so the provenance is
cc-safety-net's `device.ts` / `powershell` rule semantics plus the Windows
admin command surface, turned into authored `tests/contract.rs` cases; each
is `ManualOnly` (confirmable), matching the Linux `disk.erase` family. The
PowerShell storage recognition is best-effort inspection of the `-Command`
argument (the cmdlet runs inside the `powershell.exe` child); a
dynamically-built cmdlet name is outside it, as for the other windows text
rules.

## Deliberate differences from cc-safety-net

safebash analyzes at execution time, after expansion, inside the shell;
cc-safety-net analyzes command text before anything runs. This closes some
of cc-safety-net's documented gaps and opens a few intentional divergences.
These account for the gap from 100% in `tests/harvested.rs` (measured
~93% standard / ~91% strict block/allow agreement):

1. **Dynamic sources deferred, not denied (standard).** `eval "$x"`,
   `source "$f"`, `. "$FILE"`, `bash -c "$x"`: cc-safety-net cannot see run
   time and denies (`analysis.dynamic-shell-source`). safebash lets the
   command they actually produce reach the dispatch gate, so it allows the
   wrapper and gates the real command. Strict still denies up front.
2. **Allowlisted variables expanded.** `$HOME/x`, `$TMPDIR/y`, `~` are
   resolved from the inherited environment; cc-safety-net treats them as
   dynamic. safebash knows the real value, so `rm -rf $HOME/build` is
   classified on its true target.
3. **`guard.policy-apply` not ported.** cc-safety-net blocks
   `cc-safety-net policy apply` (its own CLI rewriting its config).
   safebash's policy is a file, not applied through a shell subcommand, so
   there is no equivalent command to block; the ~38 corpus rows for it are
   not applicable.
4. **No base64 literal decoding.** cc-safety-net decodes `base64 -d`
   literals to recover a hidden secret path; safebash does not (niche;
   ~45 rows).
5. **Partial parses not denied in strict.** cc-safety-net's parser marks
   many inputs "partial" and strict-denies them; rubash's parser is fuller
   and parses most of them, so safebash analyzes the real commands instead
   of denying (`analysis.strict-unparseable`, ~66 strict rows).
6. **Project policy is always tighten-only** (cc-safety-net: opt-in).

Where both engines block, the rule id agrees ~90% of the time; the
remaining differences are a more specific root-or-home or git-metadata
rule firing where cc-safety-net reported a broader guard, which the
cross-check treats as equivalent.

## Primary tests (authoritative)

- `tests/contract.rs` — exact expected verdict per command for every rule
  family, plus everyday commands that must stay allowed.
- `tests/brush_compat.rs` — zero false positives on 3,230 real scripts.
- `crates/safebash-guard/src/**` unit tests — per-rule logic.

`tests/harvested.rs` is a *differential cross-check*, not a contract: it
guards against regression from a measured baseline with documented
floors.
