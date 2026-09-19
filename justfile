# The compiler `rust-version` names, read from the manifest so it is pinned once.
msrv := `sed -nE 's/^rust-version = "([0-9.]+)"/\1/p' Cargo.toml`

default:
    @just --list --unsorted

# Refresh the shared skills once at the start of a task.
skills-sync:
    python3 .origin89/sync-engineering.py

fmt:
    cargo fmt --all
    pnpm run format

fmt-check:
    cargo fmt --all --check
    pnpm run format:check

# The second pass builds the crate's tests with `defmt` on. Without it
# `tests/defmt.rs` is compiled by nothing, because the plain pass leaves the
# feature off and the cross-compile builds only the library.
lint:
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo clippy --locked -p km43 --all-targets --features defmt -- -D warnings
    pnpm run lint

typecheck:
    pnpm run typecheck

# The unit and integration tests. The rest of `just test` is the compile-fail
# doctests, one compiler run each; they are the type-state guards.
test-fast:
    cargo test --locked --workspace --lib --tests
    pnpm run test

test:
    cargo test --locked --workspace
    pnpm run test

build:
    cargo build --locked --workspace
    pnpm run build

# Rustdoc under deny-warnings: an intra-doc link to a constant that was renamed
# or made private is a broken reference nothing else in the gate reads.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps

# The specification gate: vectors, registry, bindings, traceability, and the
# cross-compile of the crate for the target. Read-only.
spec:
    cargo xtask check

# Regenerate REGISTRY.md, MAP.md and both bindings from protocol.toml.
registry:
    cargo xtask registry

# Regenerate the published vectors with the generator that shares no code
# with the crate.
vectors:
    cargo xtask vectors

# Fetch the equipment dataset's published vocabulary, show which words moved, and move the pin with `--accept`.
vocabulary *args:
    cargo xtask vocabulary {{args}}

# Consumers may still build with the compiler `rust-version` names. Not part of
# `check` because it needs a second toolchain installed: `rustup toolchain
# install {{msrv}} --profile minimal`. Warnings are errors here because the older
# compiler lints differently: 1.88 reported seven dead constants that 1.98 did
# not, and a plain `check` stayed green over them.
msrv-check:
    RUSTFLAGS="-D warnings" cargo +{{msrv}} check --locked --workspace

check: fmt-check lint typecheck test build doc spec
