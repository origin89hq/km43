# Contributing

Follow the [Origin89 engineering standards](https://github.com/origin89hq/engineering)
for working practices, tests, writing and commits. `AGENTS.md` loads the shared
skills at the start of a task; `just skills-sync` refreshes them from
engineering. The rules specific to this repository are in [CLAUDE.md](CLAUDE.md)
and apply to everyone, not only to an assistant.

## Setup

- just 1.58.0 and Python 3.9 or newer, for the recipes and the skill bootstrap.
- The Rust toolchain in `rust-toolchain.toml`. rustup installs it, with the
  `thumbv6m-none-eabi` and `riscv32imac-unknown-none-elf` targets, on first use.
- Node 24 or newer and pnpm, pinned by `packageManager` in `package.json`. Run
  `pnpm install --frozen-lockfile`.

## Before a pull request

`just check` runs everything CI runs. While working, `just test-fast` runs the
unit and integration tests; the rest of `just test` is the doctests, including
the compile-fail ones that guard the type-state types. They are not something
to cut if the gate ever feels slow.

## Releasing the bindings

A change that reaches users of `@origin89/km43` needs a changeset: run
`pnpm changeset`, pick the bump, describe the result for them, and commit the
generated file with the change. Merging to `main` then opens or updates a
release PR; merging that publishes. See [docs/releases.md](docs/releases.md).

## Changing the protocol

Read [`docs/PROTOCOL.md`](docs/PROTOCOL.md) first. A fielded unit will meet a
newer app and neither side can be updated first, so:

- Integer keys only, and a number is never reused. A retired number stays
  retired.
- Unknown keys are skipped, not rejected. New fields are optional; a field
  whose absence has no sane default is a new message.
- Every message that changes anything is on the signed list, and the MAC
  covers its type.
- Bump the minor for an addition and the major only when old clients cannot
  cope.

Allocate numbers in `crates/km43/protocol.toml` and nowhere else, then run
`just registry` and `just vectors` and commit the regenerated files with the
change. The generator in `crates/xtask` must stay independent of the `km43`
crate: it is the witness the vectors are checked against, and a witness that
shares the accused's code is not a witness. `cargo xtask check` enforces this.

Read the spec back and confirm every field it promises exists on the wire. Two
holes got through review that way: an ack told clients to read a counter that
was not in its body, and a hello referenced a challenge that discovery never
sent.

Every numbered requirement (`P-nnn`, `L-nnn`) should have a test named after it
that can fail. `docs/protocol/traceability.toml` records how many do not, and
the gate refuses that number going up. See
[`docs/protocol/VERIFICATION.md`](docs/protocol/VERIFICATION.md).

## Where the reasoning lives

Design reasoning goes in [`docs/PROTOCOL-RATIONALE.md`](docs/PROTOCOL-RATIONALE.md)
and the documents under `docs/protocol/`, not in doc comments. Internal
research and RFCs belong in
[internal-research](https://github.com/origin89hq/internal-research).
