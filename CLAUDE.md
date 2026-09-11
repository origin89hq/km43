@AGENTS.md

# Working on KM43

KM43 is what a controller speaks from an unattended site four hours from a
road, to a client that may be a year newer or a year older than it. That sets
the standard: a number allocated here is allocated forever, a byte on the wire
has to mean the same thing to two implementations that have never met, and
nobody is there to unwind a session that went wrong.

Read [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the rules and
[`docs/PROTOCOL-RATIONALE.md`](docs/PROTOCOL-RATIONALE.md) for the reasoning.
This file is what to do while writing. The shared standards in
[engineering](https://github.com/origin89hq/engineering) apply underneath it;
where this file is stricter, this file wins.

## Before anything else

**The spec is the source of truth, and it explains why.** If a change
contradicts it, the spec is either wrong, in which case say so and change it in
the same commit, or the change is. Do not leave them disagreeing.

**Ask what fails, not what works.** Every rule in the protocol came from naming
a specific failure: a counter that livelocked when two clients connected, an
ack that told the client to read a field its body did not carry, a MAC that
covered the payload and not the message type. If you cannot name the failure a
piece of code prevents, you probably do not need it yet.

## Rules that are not preferences

### Absence is representable

A missing reading is not zero. Every value carries its quality, and a decoder
that does not know a field's value says so rather than defaulting it. Never
introduce a default that could be mistaken for a measurement.

### Nothing is unbounded

No allocator on the target, and none in the tests either, so the two cannot
disagree; the crate is `no_std` without `alloc`, which is the proof rather
than the claim. Every collection is a fixed array with a **named capacity** and
a **documented behaviour when full**. Prefer refusing to evicting: silently
dropping a message stops a client with nothing to point at.

### No panic path in production

- Indexing goes through `get` / `get_mut` with an error, not `[]`.
- No `unwrap`, no `expect`, no `panic!` outside `#[cfg(test)]`.
- Arithmetic that can overflow uses `checked_` or `saturating_`.
- Garbage input must never panic. A resynchronising receiver hands the decoder
  arbitrary bytes, and every truncation of every frame is a test.
- `expect` in a test is fine and encouraged. A fixture that cannot be built
  should fail at the line that broke.

If a lint fires, fix it. `#[expect(...)]` with a `reason` is allowed only when
the alternative is genuinely worse, and the reason must say what makes it safe.

### A number is allocated once

`crates/km43/protocol.toml` is the only place a wire number exists. Code takes
it from the generated bindings; a literal is a second opinion that agrees until
the registry moves. `cargo xtask check` refuses a link-local code written as a
literal, a number allocated twice, and a live number no document can reach.
A retired number stays retired forever.

### Exhaustive matching

No `_` wildcard arms on our own enums. Adding a variant should break every
place that has to think about it. That is the compiler doing review.

### Type-state over rules somebody remembers

A `SignedClaim` cannot be read before it verifies. A `Wrapper<Unverified>`
cannot hand out a payload. Each of those is a `compile_fail` doctest, and each
is the difference between a rule in a document and a program that does not
compile. Do not delete one to make the test run shorter.

## Testing

### The gate is fast, or the gate is wrong

`cargo check`, `cargo test`, `cargo clippy`, `cargo fmt`: seconds, not
minutes. If one of them takes more than about a minute, that is the finding: a
dependency that should not be there, a test doing real I/O, a generic
instantiated per call site. Fix the cause.

**Measure before you act on that.** If `cargo test` ever reads as slow, the
first suspects are the `compile_fail` doctests: they are separate `rustc` runs
that have to be *made* to fail and cannot be merged. They are also the
type-state guards, so the answer is `just test-fast` while working and the
full `just test` once before committing, never deleting one.

### Nothing has shipped, so nothing is owed compatibility

Until a unit is in a cabin, a wire format, a file layout and a public
signature are all free to change. Change them. Do not carry a shim, do not
keep an old variant "just in case", do not version something with one caller.

The exception is the short list that genuinely cannot be retrofitted once
hardware exists: key derivation, protocol versioning, serial numbers. Those
are frozen by the first paired unit and not before.

### A check you have not watched fail is not a check

Break the thing it guards, on purpose, and see it fire. Then put it back.

Two checks were written in this codebase, both reported *all checks pass*,
and both were comparing nothing: one had its field list truncated before the
comparison, the other compared a description to a description while the bytes
underneath had already diverged. A green check that has never been red is an
assertion about the author's intent, not about the code.

### Put it back from a copy, never from git

The rule above asks you to hold a file in a deliberately wrong state several
times a day. **Copy it first, restore from the copy.**

`git checkout -- <file>` is not an undo: it restores the last commit, so it
takes the break *and* every uncommitted change in that file. It has cost an
hour of work three times in one session, each time noticed only when the next
build failed. `git stash` moves every uncommitted change in the tree, not the
one file, and is not the fix either.

```bash
cp crates/km43/src/handshake.rs "$SCRATCH/handshake.bak"   # before the break
# ... break it, run the test, watch it go red ...
cp "$SCRATCH/handshake.bak" crates/km43/src/handshake.rs   # after
```

### A vector you retyped is not a vector

If a committed artefact is the witness, **read the artefact**. A hex string
copied out of `v1.json` and pasted into a `const` in the module it is supposed
to check is the same opinion in two places, and the file it came from is then
free to move. This was found four times, in four modules, each wearing the
artefact's name in its own doc comment: the framing layer round-tripped with
no wire vector at all; the envelope was never compared to `v1.json`; the MAC
and the KDF each compared against hex transcribed into their own file.

The test to apply: **move the artefact and see what goes red.** Nothing does,
if the answer was retyped. The fix is an integration test that `include_str!`s
the file and drives the public API. `cargo xtask check` refuses a published
vector no test reads.

### The generator is a witness, not a mirror

`crates/xtask` produces the vectors and must never depend on `km43`. Depend on
it and the vectors become a round-trip test, which cannot catch an encoder and
a decoder that are wrong the same way. The gate reads the manifest and refuses
the dependency.

### Verify by diff, never by memory

A number remembered from an earlier console line is not evidence. Twenty
minutes once went into a key that had "changed" and had not; the comparison
was against stale scrollback rather than the two files. If two things must
agree, make the machine say so.

### A generator's refactor proves itself with an empty diff

Anything that emits a committed artefact has a free acceptance test: the
artefact must not move. Reshape the code, run `just registry` and
`just vectors`, `git diff`. An empty diff means the change was pure shape.

### Refactor by rewriting, not by patching

`sed` and regex across a function you are restructuring will break the build
in a way that costs more than writing the region out. Read the region, write
the region. Scripted edits are for mechanical substitutions that are the same
everywhere.

### More lines of test than of code, and the tests are about failure

Every public function gets at least three: normal, edge or empty, and
rejection. Beyond that, each of these earns its place:

| Kind | What it catches |
| --- | --- |
| **Known vectors** | Agreement with the world, not just with ourselves: the CRC check value, the COBS paper's examples, RFC 4231 |
| **Round trips over every length** | Off-by-one at a boundary that only bites on a frame of one particular size |
| **Every single-bit flip** | A checksum or a MAC that is a false witness |
| **Every truncation** | A decoder that reads past the end of what it was given |
| **A requirement's test** | `P-nnn` and `L-nnn` each have a test named after them that can fail; the ratchet in `traceability.toml` refuses the count going up |

A test named `it_works` is worth nothing. Name the failure it prevents:
`two_frames_run_together_are_rejected`, `a_counter_that_moved_backwards_is_refused`.
Write the test comment as the story: what went wrong, or would have.

### Running

`just --list`. `just check` before any commit; it is what CI runs. The first
three cargo checks build for **this laptop**, where `std` is present and
`usize` is 64 bits, so a size assertion can pass all three and fail the
firmware. `cargo xtask check` cross-compiles the crate for the target and finds
it by reading the tree rather than from a list.

## Documentation

`///` on every public item, `//!` on every module. Say **why**, not what; the
signature already says what. Two or three sentences at most: what the caller
needs and the one thing that will bite them. No headings, no bullet lists, no
ceremonial `# Errors` section repeating what the `Result` says. The reasoning
goes in `docs/`, not in a doc comment.

The voice is plain and concrete. It names the thing that went wrong, in the
words somebody would use out loud. If a comment could apply to any codebase,
it is not carrying its weight.

### A type with methods, not a module of functions

Free functions that all take the same first argument are a struct asking to
exist. Before every commit, list the free functions in the file you touched;
if two or more take the same first argument, they are methods and the argument
is the receiver. The exception is a genuinely free function that belongs to no
state: `fn crc16(data: &[u8]) -> u16` is not a method looking for a home.

### No stringly-typed code

A `String` for something with a fixed set of values is a validation function
somebody has to remember to call. An enum is the same thing checked by the
compiler, and with serde the parse *is* the validation. The same goes for a
bare `u8` standing in for an outcome: give it a name, derive `Display` where a
person reads it, and let a missing arm be a compile error.

### Never `#[allow(...)]`

A lint that fires is the compiler reviewing the code, and silencing it is
deleting the review rather than answering it. `too_many_lines` means split the
function. `dead_code` means delete it or use it. `too_many_arguments` means
the arguments are a struct. `#[expect(..., reason = "...")]` is the only
escape, and the reason must say what makes it safe. The one settled exception
is at the manifest: `missing_errors_doc` is allowed there because it
contradicts the rustdoc rule above.

### No section banners in code

Never divide a file with a comment banner. It goes stale the moment something
moves, and it is a file asking to be split. If a file needs sections, it needs
modules.

### Never reference a milestone or a date

Not in code, not in comments, not in docs. Write the **condition** instead:
not "before M3" but "before the first unit ships with a locked bootloader". A
date rots silently; a condition is either true or it is not, and anybody can
check which.

## Commits

One logical change each. A short imperative subject with a conventional
prefix, and a body only when the diff cannot say **why it mattered**: the
failure it prevents or the decision it records. No attribution trailers. If
the change was reviewed and something was wrong, say so in the body rather
than quietly fixing it. The log is the project's memory of its own mistakes.

## The target

The crate runs on an STM32G0B1 (Cortex-M0+, no FPU, an image budget of about
256 KB) and on an ESP32-C6. Generics monomorphise; prefer enum dispatch for
closed sets and traits only at the seams. No floating point in anything that
could run in an interrupt. The crate never names a peripheral: a caller hands
it bytes, which is what makes every test host-runnable.

## When you are unsure

Look for a similar decision already made and follow it: the spec, the
rationale and the existing modules all show the house style. If the decision
is genuinely new, write down the failure it prevents, pick the smaller option,
and say in the commit what you were unsure about.
