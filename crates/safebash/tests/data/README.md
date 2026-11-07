# Test data

## `ccsn-harvested-verdicts.jsonl`

A trimmed copy of `tests/fixtures/gate/harvested-verdicts.jsonl` from
[cc-safety-net](https://github.com/kenryu42/cc-safety-net) (MIT License,
Copyright (c) 2026 J Liew), commit `3434e63`. Each row is a command
literal and the verdict cc-safety-net reached for it in a plain workspace
(`work/*`) and in a Git repository (`repo/*`), at the standard and strict
levels. The paranoid columns were dropped.

`tests/harvested.rs` replays every literal through safebash's static
(preflight) analysis and reports how often the two engines agree. The
literals include prose (test titles that were harvested as inputs); they are
kept, because a prose line is also an input an engine must not mis-block.

## `contract.tsv`

safebash's own behavioral contract: `level<TAB>expected<TAB>command`, where
`expected` is `allow` or a rule id. Commands in it are data for static
analysis only — `tests/contract.rs` never hands them to a shell.
