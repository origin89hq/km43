# Working in this repository

For hosted PR reviews, follow `Code Review Rules` below without running the local
skills refresh. For other tasks, run `just skills-sync` from the repository root.
Read `skills/origin89-working/SKILL.md` and the relevant domain skills under the
immutable `path` printed by that command. Keep that snapshot for the task; do not
refresh it halfway through work. Before branch, commit, push, or PR operations,
read `skills/origin89-commits/SKILL.md` from that snapshot. Read local instructions
and preserve stronger project constraints and project-specific skills.

If refresh reports cached content, continue with that verified cache and mention
that the script could not check for updates. If no cache is available or
validation fails, report the error; do not claim the shared rules loaded. Local
instructions and the user's request still apply. Do not overwrite local skill
files to fix a conflict without reconciling them.

[Origin89 engineering](https://github.com/origin89hq/engineering) owns the shared
rules. Keep only repository-specific architecture, commands, target constraints,
and exceptions below. Internal RFCs and research belong in
[internal-research](https://github.com/origin89hq/internal-research). Add documentation
only when its value and upkeep are clear; remove AI filler from every message.

Confirmed problems left outside the current fix need an issue in the owning
repository: search with `gh`, reuse a matching issue or create one with evidence,
and return its URL. Follow the shared working skill's unfinished-work rule.
Respect posting restrictions; if filing is blocked, provide the draft and say why.
Finish authorized fixes instead of replacing them with backlog issues.

## Repository map

| Path | What it is |
| --- | --- |
| `docs/PROTOCOL.md`, `docs/protocol/LINK.md` | The normative spec: every `P-nnn` and `L-nnn` requirement |
| `docs/PROTOCOL-RATIONALE.md`, `docs/protocol/*.md` | Reasoning, verification plan, deferred decisions, generated registry and map |
| `docs/protocol/vectors/v1.json` | Published known-good bytes, written only by `cargo xtask vectors` |
| `docs/protocol/traceability.toml` | The requirement-coverage ratchet the gate enforces |
| `crates/km43/` | The implementation: `no_std`, no allocator, host-tested and cross-compiled |
| `crates/km43/protocol.toml` | The registry. The only place a number is allocated |
| `crates/km43/src/generated.rs`, `packages/km43/src/generated.ts` | Bindings, written only by `cargo xtask registry` |
| `crates/xtask/` | The gate and the generators. Must never depend on `km43` |

## Commands

`just --list` for the full set. `just check` is what CI runs. `just test-fast`
while working. `just registry` and `just vectors` after a registry or generator
change; commit the regenerated files with the change. `cargo xtask check`
alone runs the specification gate, including the cross-compile for
`thumbv6m-none-eabi` and `riscv32imac-unknown-none-elf`. `just msrv-check`
builds with the compiler `rust-version` names.

## Rules that are not preferences

[CLAUDE.md](CLAUDE.md) carries the full set with the failure each one names.
The ones a change most often breaks:

- Absence is representable. Never a default that could be mistaken for a value.
- Nothing is unbounded. Every collection is a fixed array with a named capacity
  and a documented behaviour when full; refuse rather than evict.
- No `unwrap`, `expect`, `panic!`, `[]` indexing or unchecked arithmetic outside
  `#[cfg(test)]`.
- No `_` arm on an enum this repository owns.
- A number is allocated once, in `protocol.toml`, and never reused.
- A committed artefact is read by the test that checks it, never retyped into it.
- Never `#[allow(...)]`. `#[expect(..., reason = "...")]` only when the alternative
  is worse, and the reason says what makes it safe.
- No milestone names or dates anywhere. Write the condition instead.

## Code Review Rules

Read the shared `origin89-review` skill and relevant domain skills when available.
In hosted review jobs that already provide `.origin89/engineering/skills/`, use
that checkout without running the local refresh. If shared context is missing,
review against the rules below and disclose that limit.

- Flag changes that bypass authorization, lose data or provenance, break a
  supported contract, or turn unknown or stale equipment input into permission
  to act. Check callers and existing guards before reporting a defect.
- Require meaningful success, invalid-input, boundary, and failure coverage for
  changed nontrivial behavior. Respect simpler contracts with fewer paths;
  hazardous behavior needs its full fault matrix and relevant bench evidence.
- For Rust domain logic, prefer typed state, errors, units, and identifiers.
  Strings at text boundaries are expected; flag strings that discard useful
  invariants or leave invalid domain states representable.
- Report the trigger, consequence, and precise location. Distinguish checks run
  from missing evidence. Leave formatting to the configured linters, and avoid
  duplicate or speculative findings. A review request does not authorize implementation.
- Keep current PR defects in the review. Track confirmed pre-existing or explicitly
  deferred problems as issues when filing is authorized; comments-only reviewers
  provide a draft and state that it was not filed.
- For this repository, also flag: a wire number written as a literal instead of
  taken from the registry; a reused or renumbered registry entry; a vector, tag
  or key transcribed into a test instead of read from `v1.json`; a spec change
  without its regenerated registry, bindings and vectors; a message that changes
  state and is not on the signed list; a `_` arm on an owned enum; a new
  `unwrap`, `expect`, `[]` index or unchecked arithmetic outside tests; a
  `#[allow]`; and a `traceability.toml` count lowered without the test that
  earned it.
