---
title: Verification plan
description: The end-to-end tests, hostile-link cases, and traceability gates required to verify KM43.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

# KM43 — end-to-end test and verification plan

<p class="o89-doc-kicker">KM43 / proof plan</p>

<p class="o89-doc-deck">The evidence required before two independent KM43 implementations can be trusted together: specification checks, property tests, hostile-link exercises, and end-to-end conformance.</p>

<dl class="o89-doc-facts">
  <div>
    <dt>Status</dt>
    <dd>Active plan with completed repair stages</dd>
  </div>
  <div>
    <dt>Commit gate</dt>
    <dd><code>cargo xtask check</code></dd>
  </div>
  <div>
    <dt>Coverage ledger</dt>
    <dd><code>traceability.toml</code></dd>
  </div>
  <div>
    <dt>End state</dt>
    <dd>Independent Rust and TypeScript implementations interoperate</dd>
  </div>
</dl>

<nav class="o89-doc-links" aria-label="Verification resources">
  <a href="/km43/test-vectors/">Test vectors <span aria-hidden="true">→</span></a>
  <a href="/km43/traceability.toml">Coverage ledger <span aria-hidden="true">→</span></a>
  <a href="/km43/specification/">Specification <span aria-hidden="true">→</span></a>
</nav>

## Current baseline

Scope check first, because two of the numbers in the brief are wrong and one of them changes the plan.

`docs/PROTOCOL.md` carries **123** numbered requirements, not ~150 (`grep -o '\*\*P-[0-9]\{3\}\*\*' | sort -u`). `docs/protocol/LINK.md` carried **zero** and **zero** RFC-2119 keywords — two instances of "shall never" and otherwise plain prose — while holding the connection lifecycle, the heartbeat ladder, the `TimeOffer` floor/cap/rate-limit, the backpressure ladder and the comms release flow, with PROTOCOL.md leaning on it normatively ("one floor, both doors", P-114). Roughly a third of the enforceable behaviour of this protocol could not be cited by a test name at all. It now carries **68**, which is the first thing stage 1 did.

Second, and this was the finding that mattered: `cargo xtask check` existed, passed, and **nothing ran it**. No `.github/`, a pre-commit skill that ran fmt/clippy/test only, and `cargo test` that never reached xtask — while `main.rs` called `check` "the one CI runs". Eight checks that were, in practice, a command somebody remembered to type. Both gates exist now and both run the whole set. Every gate below is worth exactly what enforces it, which is why this paragraph came before the plan rather than inside it.

Third: the repo had **zero tests** when this was written, and has 29 now — all of them in xtask, standing behind the traceability gate rather than behind a requirement. `crates/km43` is still generated numbers and an 11-line `lib.rs`. This is a plan for a greenfield, which is the cheapest moment it will ever be, and the ratchet in `traceability.toml` is what stops that staying true by accident.

---

## Stage 0 — spec repair, before a test is written — **done**

Not a test stage. It was here because surviving findings made the stages below
**unwritable**, not merely wrong, and a plan that starts at stage 1 produces a
firmware that encodes an arbitrary branch of a contradiction. All of it has
landed; it stays in the file because what it fixed is the shape of defect the
stages below exist to keep out.

**0a. The dedup table could not be implemented.** P-004 puts `MAX_CMD_DEDUP`'s 10
minutes on the monotonic tick and gives the attack that forbids the wall clock.
P-121 requires the entry to survive a reset. P-122 forbids eviction. P-120's
16-byte entry had no time field, and the tick is zero at the boot the entry must
survive. No conforming implementation existed, so `p_121_*` and `p_122_*` could
not be written against anything, and both branches an implementer might pick were
testable — one of them a site that answers error 7 to every command. The entry is
now 25 bytes carrying `inserted:u64` and a status byte, re-based to tick zero on
boot, written in the same FRAM transaction as the counter and ahead of `execute`.

**0b. P-024 could not be satisfied for `Discover`, `Pair` or `Hello`.** The
controller stamps the connection handle into `session_id` (P-021, P-026) and the
client sent 0, so the response's `(session_id, req_id)` was provably not the pair
the client sent, on message one of every session — which stage 4 would have hit in
its first exchange. A pre-session client now matches on `req_id` alone and takes
the answered `session_id` as its connection handle.

**0c. Everything that was cheap then and frozen later.** P-049's `107` → `105`,
now derived on the page and emitted as a vector; the `seq` inclusivity convention
stated once as P-029, with P-104, P-056 and P-099 rewritten against it; LINK.md's
`0x0804` paragraph; LINK.md's "rather than floored" sentence, which told an
implementer to apply no floor to a known-clock `Time 0x0A`; P-006's "largest that
fits", which stage 2 turns into a `const { assert!(...) }` so the claim is generated rather
than counted.

**What this caught that nothing else can:** a requirement no implementation can
satisfy. Every stage below assumes the target exists.

**Gate:** `cargo xtask check` runs in `.claude/skills/pre-commit/SKILL.md` and in
CI, which is the enforcement for the edits above.

---

## 1. Requirement traceability

**What it catches that stage 0 cannot:** stage 0 says the corpus is consistent. This says it is *covered* — that every MUST has something standing behind it and that the things with nothing behind them are a written, defended list rather than an accident.

**Numbering — done, and it came to 68 rather than the ~30 estimated here.** The handle range and reuse rule, the eight connection rows, allocated-vs-bound, `boot_id` invalidation in both directions, the 2 s / 6 s / 60 s / 3-per-hour ladder, the `TimeOffer` bounds, the credential push rule, the release-flow steps, and the three error codes that reach a client. The estimate was low because the ladder, the credential cache and the release flow each hold four to six separable rules rather than one, and separable is the whole point — a test cites one rule, not a paragraph.

The risk in an exercise like this is inventing normative text while numbering it, so every proposed rule had to quote the sentence it came from, and a separate pass diffed all 68 against `git show HEAD:` looking for rules with no source. It found three inventions and four silently strengthened bounds, all reverted. That pass was worth more than the numbering.

**Convention.** `p_nnn_names_the_failure` / `l_nnn_names_the_failure`, in that order — the citation is a prefix so `grep p_049` finds every test, and the rest obeys the house rule: name the failure, not the function.

```
p_024_a_discover_response_completes_the_request_that_asked
p_049_a_scanner_refuses_a_label_it_could_not_reprint
p_077_a_subscribed_session_still_expires_while_events_flow
p_121_a_dedup_entry_written_before_a_reset_still_answers_duplicate
l_014_a_time_offer_five_seconds_wide_is_drift_and_an_hour_is_a_different_tuesday
```

A requirement may be cited by more than one test and a test may cite more than one requirement; the second is expressed as extra empty `#[test]` shims or a `//! cites: P-024, P-072` header — pick the header, it survives refactoring.

**A header is a claim by a whole file, and that is the weakest thing this matrix counts.** Any asserting test in the file makes every requirement the header names count, with nothing linking the rule to a test. That is right for one test genuinely standing behind two rules and wrong for a rule the file does not implement: `envelope.rs` claimed P-143 — which refusal a session-requiring request gets — and no test in the tree asserts either refusal, no code in the tree performs one, and the decision belongs to a request dispatcher that does not exist. The header stood over nothing for as long as it had been there.

So the check prints how many covered rules have no test named after them. **Fifty-six of a hundred and sixty-one**, a third of the count. Most are honest — `crc.rs` claiming the CRC rule is a file about nothing else — and the list is a reading queue rather than a defect list. It warns rather than failing for that reason: a check that cannot tell an honest header from a hollow one would be asking for seventy renames instead of seventy readings.

**Measurement.** A ninth xtask check, `every_requirement_is_cited`, in the same list as the eight that exist:

- walk `**P-nnn**` in PROTOCOL.md and `**L-nnn**` in LINK.md — that is the denominator, and it moves when the spec moves;
- walk `fn p_nnn_` / `fn l_nnn_` across the workspace, plus the `cites` field of every transcript in the conformance corpus (stage 9), plus the name of any xtask check an entry nominates;
- **reject a citation whose test body contains no assertion** and any `#[ignore]`. A requirement cited by a test that cannot fail is uncovered, and that is the failure mode of every traceability matrix ever built.

**Two trees, two counts.** The protocol and the controller are separate repositories, and each keeps its own `traceability.toml` over the same specification. The count in this one is what the wire crate's tests stand behind; the controller's obligations, which are most of the `P-` rules about sessions, enrolment and concerns and every `L-` rule, are tested in origin89, whose copy of this check walks this repository beside its own crates and so counts both. Neither number is the whole truth on its own, and the one that says *every requirement has a test somewhere* is the controller's, because that is where the two halves meet.

Three buckets, and the middle one is the whole design:

| Bucket | Meaning | Build fails? |
|---|---|---|
| covered | ≥1 asserting test or a nominated spec check — **and a test per clause**, for a rule that declares them | no |
| declared untestable | an entry in `docs/protocol/traceability.toml` with a `kind` and a `reason` | no |
| uncovered | everything else | **yes** |

**What to do about requirements no test can reach.** Not delete them, not fake them. Move them into `traceability.toml` where the reason is written down, reviewed in a pull request, and countable. The file's line count is a number somebody defends at each audit round — the same instrument as `#[expect(reason = "...")]` one layer up. Four kinds, with real examples from this corpus:

| kind | example | what stands in for a test |
|---|---|---|
| `hardware` | P-033 — RTS/CTS on the **production connector** | a dated `bench-logs/YYYY-MM-DD.md` entry, named in the toml. Stage 8 owns it |
| `spec-check` | P-045 "no key is ever transmitted" | `no_response_carries_key_material` — a check over the corpus, not over an implementation. This generalises what already exists |
| `deferred` | P-103's `shadow` key number | DEFERRED entry 9. The entry's trigger *is* the test's due date, which is what stops this bucket being a graveyard |
| `judgement` | P-075 (SHOULD; a board swap regresses `seq` legitimately) | a test proves the surfacing happened; nothing proves an operator read it. Say so |

**A rule that states two things needs a test for each, and a count of tests cannot see that.** `[[clauses]]` in the same toml names the sentences and a fragment of the test name standing behind each one; a requirement with a clause nobody has tested is **uncovered**, however many tests cite it. This exists because P-164 sat covered for months with half of it unbuilt — *report `unnamed_state` with no value* was tested and *raise a concern carrying the source's own code* did not exist, there was no concern table in the crate at all, and the only thing that said so was a paragraph in a design document. A half-built rule reading greener than an unbuilt one is the worst direction for this file to be wrong in: nobody goes looking at a number that is already the right colour.

A fragment of a test name and not a count, because two tests about the same clause satisfy a count and prove nothing. A `//! cites:` header never satisfies a clause — it stands for a whole file and cannot say which sentence it is about. Renaming a test that stands behind a clause turns the check red on purpose: the rename is exactly when somebody should be asked whether the clause still has a test. The table is for rules that say two things; most say one, and listing those would make it a tax rather than a check.

**And the table only holds rules somebody has already read, which is its real limit.** So the check also prints the reading list: every **covered** requirement whose own text states two or more obligations and which stands on **one** test, with no clauses declared. P-164 sat in that intersection for months. There are 34 of them today, and each is a rule to read beside its code — some will be one behaviour stated twice (`MUST do X and MUST NOT do the opposite of X`), and the ones that are not get a `[[clauses]]` entry and drop off the list.

Counting `MUST`/`SHALL` is a smell and not a rule, which is why it warns. Making it fail would force an entry for all thirty-four, and filling this file to make a number go down is what it says out loud it must not become.

**Reporting the gap.** `cargo xtask check` prints the three counts, the uncovered list, every clause nobody has tested, the reading list above, and — as a warning the audit round reads, not a build failure — every MUST cited by exactly one test. A MUST that names a receiver behaviour wants a normal, an edge and a rejection case (`.claude/rules/testing.md`); one test means somebody wrote the happy path and stopped.

**What this changes today.** P-049 is the worked example: a MUST with a normative character count, no vector, and `crates/xtask/src/vectors.rs` never builds the string. It is not untestable — it is uncovered, and the fix is one line in the generator emitting `{"payload": "km43:1:...", "len": 105}` beside the `device_id` and `printed_secret` it already holds. That is the difference this stage exists to force: *uncovered* and *untestable* are different words, and only one of them is allowed to be silent.

**Also fixed here, and one thing deliberately not.** The client capability mask and LINK.md's codes 256–264 were not in `protocol.toml` at all, so nothing *could* reach them; both are rows now, and the bindings emit `LinkErrorCode` and `ClientCapability` from them. `Codegen::write` refuses when REGISTRY.md holds a `##` heading whose table no section claimed, because the tooling was asymmetric in the unsafe direction — data that disappears fails loudly at `splice`, and a hand-kept table is silent forever, which is exactly how the capability mask stayed outside the registry.

`Registry::unreachable` gained the link errors and now includes the local controller requirements in its scan, but it still does **not** walk `codes.*` or `enums.*`, and DEFERRED entry 11 records the gap rather than the entry claiming coverage that does not exist. Both ways were built and neither is honest yet. By member it reports all eighteen: a member of one of those spaces is a label, `quality = estimated` decides nothing on the wire, no rule quotes it, and requiring one means writing eighteen sentences that repeat the table. By space name it reported four that *are* reached, under their field name rather than their space name — `source` for `time_source`, `section` for `config_section`. A check that cries wolf gets switched off, and that is worse than a gap somebody wrote down.

**Cost:** LINK.md numbering, half a day. The check, a day. The toml is written as tests land, not up front.

---

## 2. Unit and property testing, per layer

**What it catches that stage 1 cannot:** stage 1 proves a test exists and has an assertion. It has no opinion on whether the assertion is any good. This is where a rule implemented wrongly on an input somebody thought of (unit) or on an input nobody thought of within one layer (property) dies.

**Enforce the environment before the first test.** `no_std` in the crate **and no `alloc`**:

```rust
#![no_std]        // and deliberately no `extern crate alloc`
```

Without `alloc` in scope there is no `Vec` and no `Box` to reach for, so "nothing allocates" is not a claim and not a runtime assertion — it is a compile error, checked on every build including the host test build. That is stronger than what an earlier revision of this plan asked for, and simpler.

What it asked for was an aborting `#[global_allocator]` under `#[cfg(test)]`. **That does not work and it is worth writing down why, because it looks obviously right.** `libtest` allocates before it runs a single test — test names, the harness's own bookkeeping, every panic message — so an allocator that aborts on the first call aborts the run, not the offending code. The workable version of that idea is a *counting* allocator with an assertion scoped to a measured region, and it is only worth building if a dependency ever drags an allocator in. Denying `alloc` costs nothing and catches the case that actually matters: our own code reaching for a growable buffer.

Same file: `const { assert!(...) }` for every size derivation, so a derivation cannot rot into a comment. Edition 2024 has const-block assertions natively; no `static_assertions` dependency, and a dependency in the crate the firmware links is not free.

**Prove rather than sample.** Proving means exhaustive over a bounded input — `kani` (CBMC), run in a nightly job, not per-commit. Four candidates and no more, because each proof costs a day and most of this is better sampled:

| Prove | Why proof and not sampling |
|---|---|
| The framing decoder is **total**: for all byte strings up to *n*, `Ok(Frame)` or `Err(code)`, never a panic, never an OOB read, never a loop past an iteration bound | Conformance item 5 says a million random frames. A million samples of a 1032-byte space is nothing; the resynchroniser is handed arbitrary bytes *by definition* (P-032) and the property is a safety property, which is what bounded model checking is for. Prove at n ≤ 64 and hand n > 64 to stage 3 — say so honestly rather than claiming a proof you did not run |
| No arithmetic in the `seq`/`counter`/tick path overflows | `checked_`/`saturating_` is a rule; a proof is what says every path took it |
| `cobs_len(n) = n + ceil(n/254)` and `cobs_len(1026) + 1 ≤ MAX_FRAME` | A `const { assert!(...) }`, free, and it is the derivation MAX_FRAME already prints |
| Every reported cap sits under a ceiling computed from the encoder's own widths — `MAX_SAMPLES ≤ SAMPLE_CEILING`, `MAX_INVENTORY_PAGE_ROWS ≤ INVENTORY_PAGE_ROWS_CEILING`, and the rest of the pairs `limits.rs` asserts | This was the P-006 finding turned into code, over `MAX_CHANNELS` and a worst-case `Snapshot`. That message and its derivation are retired, but the finding generalised: a ceiling counted by hand is how the document came to say 32 was the largest that fits when 35 did, and every cap the reading and inventory planes added is derived rather than chosen for exactly that reason. `MAX_CHANNELS` is now the one number with no ceiling over it, which P-006's entry in `PROTOCOL.md` says out loud |

Everything else is sampled. **`bolero`** is the right tool for a `no_std` crate: one `check!().with_type::<T>()` body runs as a proptest-style sampled test under `cargo test`, as a libFuzzer target under `cargo bolero fuzz`, and as a Kani harness under `cargo bolero kani`. That is stages 2, 3 and the provable subset of 2 from one property, which is what stops a fuzz corpus rotting into a directory nobody runs. `arbitrary` for structured inputs, `proptest` where a shrinker matters more than fuzz reuse.

**Per layer — the properties worth writing, and what each catches:**

**Framing.** Round trip every length 0..`MAX_FRAME` × four fill patterns (already in `crates/xtask/src/vectors.rs` self-check — move it into the crate too, so both the generator and the implementation carry it). The Cheshire & Baker examples as known vectors, including 254-then-zero, where an encoder and a decoder wrong the same way agree with each other and with nobody else. **Every single-bit flip in a framed message is caught by the CRC or the MAC** (conformance item 3) — 8 × len flips per message, cheap, and it is the test that says the CRC is not a false witness. Two frames run together are rejected, not concatenated.

**Envelope.** The array length is the extension point (P-028): a five-element envelope rejects with error 1 **before element 0 is read**. Make that structural rather than tested — the decoder returns `Err` from the header, so there is no code path that could have read it.

**Wrapper.** Exactly keys 1 and 2; P-013 switched off; a duplicate integer key rejected before anything in the map is interpreted. Then the one that is worth more than a test: **type-state.** `Wrapper<Unverified>` has no accessor for `payload`; `verify(&self, key) -> Wrapper<Verified>` is the only constructor of the other. P-051's verify-before-decode is then not a rule an implementer can get wrong, it is a program that does not compile. That is the seam where the CLAUDE.md type-state preference genuinely earns itself.

**MAC.** The vectors are the known-answer half. The property half is domain separation: for all distinct label pairs and all payloads, tags differ — which is what says `km43/v1/req` and `km43/v1/wrq` are not two spellings. Truncation is leftmost-16 and that is a vector, not a property. Comparison through `subtle::ConstantTimeEq`; constant time is not provable here, so it is a review item and it goes in `traceability.toml` as `judgement`.

**Session state.** A bounded action-sequence property over `{Discover, Pair, Hello, wrq, signed, Goodbye, expire, ClientDisconnected, comms_reboot}` with invariants rather than expected outputs: at most one challenge per connection row at any moment (P-060); a challenge is consumed exactly once (P-061); no `session_key` is derived twice from the same `(challenge, client_nonce, session_id)`; an accepted `req_id` is never accepted again. The invariant form matters — a property that asserts an expected output is a unit test with a generator in front of it.

**The log cursor.** A model in the test — a `Vec<(seq, class)>` — against the implementation, over `{append(class), subscribe(from), read_log(from, max), queue_full, crc_fail}`. Invariants: every `seq` the model says is deliverable arrives exactly once; none arrives twice; a hole is either explained by a `0x0701` carrying a count or surfaced. **This property is unwritable until stage 0c states the inclusivity convention**, and that is the useful thing about writing it first: the property is where the ambiguity becomes a compile error instead of a paragraph.

**Cost:** the bulk of the plan. Budget it as more lines than the code, which is the house rule anyway.

---

## 3. Fuzzing

**What it catches that stage 2 cannot:** a property generator produces values from a grammar — a `Frame`, a `Value`, an action. A fuzzer produces bytes from nothing. The inputs that matter here are the ones that never form a valid structure: the resynchroniser is handed arbitrary bytes by definition (P-032), and no `Arbitrary` impl will ever generate the byte sequence that walks a length field off a buffer.

A fuzzer without an oracle is a panic-finder. Panics are already the cheapest thing to find here (`#![deny(unsafe_code)]`, no `unwrap`, an aborting allocator), so the oracle is the whole of the value. One per target, stated:

| Target | Input | Oracle |
|---|---|---|
| `resync` | arbitrary bytes, streamed | no panic; no allocation (the aborting allocator); an iteration budget proportional to input length, exceeded = failure, which is what "no unbounded loop" means mechanically; and every frame it *emits* re-encodes to a subsequence of the input it was given |
| `cobs` | arbitrary bytes | `decode(encode(x)) == x`; `encode(x)` contains no `0x00`; `len(encode(x)) == x.len() + ceil((x.len()+1)/254)` exactly, not merely ≤ — the bound is derived in the spec and an encoder that is short by one is the 254-then-zero bug |
| `cobs_diff` | arbitrary bytes | differential against the second, independently written encoder in `crates/xtask/src/vectors.rs`. The check that already forbids xtask depending on `km43` is what makes this a witness rather than a round trip |
| `cbor_body` | arbitrary bytes as a body | no panic; depth ≤ `MAX_DEPTH`; string ≤ `MAX_STRING`; **duplicate integer key rejected**; and the negative oracle that matters — the decoder never re-encodes (P-017), enforced by the decoder borrowing its input and never owning a buffer it could have re-serialised |
| `envelope` | arbitrary bytes | the classification oracle: **exactly one** of {`Err(code)` with no observable state change, `Ok` with `(type, session_id, req_id, body-span)` fully determined}. "Partial accept" is any mutation before the reject, and it is unrepresentable if the decode is a pure function `&[u8] -> Result<Frame<'_>, ErrorCode>`. The fuzzer's job is to prove nobody added a `&mut self` |
| `wrapper_verify` | arbitrary `(key, bytes)` | never accepts on a tag mismatch; differential against RustCrypto `hmac` inside the harness only |
| `log_cursor` | arbitrary action sequence, coverage-guided | the stage-2 model, run with fuzz feedback instead of a sampler — the difference is that the fuzzer finds the 40-step sequence a sampler never reaches |
| `dedup` | arbitrary command sequence with crash points | **no oracle exists today.** No `(client_id, cmd_id)` executes twice, and a refused command retried executes — those two cannot both be asserted until stage 0a lands. Writing the target now and leaving it red is the honest version of a TODO |

Corpus seeded from `vectors/v1.json` and from the stage-9 transcripts. Run in a nightly job with the corpus committed; a crash gets a regression test at the same P-nnn before the fix, per `.claude/rules/workflow.md`.

---

## 4. Two-implementation interoperability

**What it catches that stage 3 cannot:** stages 2 and 3 were written by one person from one reading of the spec. Both implementations pass their own tests and disagree about what the spec said. That is the defect class this corpus has produced five times and it is invisible to any test either side writes.

**Neither is the reference, and here is what that means mechanically.**

For **computed values**, the reference already exists and it is neither implementation: `vectors/v1.json`, generated by a tool that is forbidden to depend on `km43`. Nothing to add except the missing entries — the QR payload, and a worst-case `Snapshot` at `MAX_CHANNELS` with every `Value` at its widest (conformance item 11 has no bytes behind it today).

For **behaviour**, no artefact is the reference, and the mechanism is a **third artefact plus a citation rule**:

1. **A transcript corpus.** JSON-lines, one file per conformance item, generated by xtask from the spec: `{step, direction, bytes_hex, expect: accept | reject(code) | emit(bytes_hex), cites: ["P-024"]}`. Generated by neither implementation, in the crate that may not depend on either.
2. **A stdio harness, one per implementation.** Reads framed bytes on stdin, writes its decisions on stdout as JSON lines: `{action, code?, cites: ["P-072"]}`. About 100 lines each. This is the *only* integration either side writes, and it is the same harness stage 9 hands to a third party — one artefact, or the third party runs something we never ran.
3. **Four pairings, not one.** Rust↔Rust, TS↔TS, Rust↔TS, TS↔Rust, over an in-process byte pipe. The pairing matrix is the diagnosis: a divergence that appears only in the cross pairings is *two readings*; one that appears identically in both same-language pairings is *one shared misreading*, and only the transcript corpus or an outside implementation catches that. Running only R↔T conflates them.

**What a failure looks like, concretely.** The harness stops at the first divergent step and emits both sides' `cites`:

```
transcript: conformance-10-error-matching.jsonl   step 3
  sent:  88 03 00000011 a2 01 ... (Discover 0x80, session_id=0x0007)
  rust:  { action: "complete_request", cites: ["P-072", "P-026"] }
  ts:    { action: "drop",             cites: ["P-024"] }
  DIVERGENCE: both sides cite a rule. The specification is the bug.
```

That last line is the rule that makes "neither is the reference" operational: **when the two sides cite different requirements for the same bytes, neither implementation is wrong and the fix is a P-nnn.** When one side cites nothing, it is a code bug. When both cite the same rule and disagree, one of them read it wrong and a bench hour settles it. Three outcomes, three different owners, decided by the report rather than by whoever is louder.

**This exact divergence is what stage 0b prevents**, and it is the first exchange of every session, so it is what the first interop run hits. Put the pre-session transcript first in the corpus regardless — `Discover`, `Pair`, `Hello` before any MAC'd exchange — because a stage that fails on message one has told you something and a stage that fails on message forty has told you less.

**Also first, from the findings:** a `Hello` whose response was dropped, followed by `Discover` and a second `Hello` on the same bound row. LINK.md does not say what a second success does, P-076 covers only `Hello`-after-`Goodbye`, and the client that lost its response cannot derive `session_key` at all (P-072 takes `session_id` from the response envelope), so it cannot even send `Goodbye`. It is reachable from the most ordinary transient the threat model explicitly accepts. Two implementations will fill it two different ways, which is the P-104 shape exactly.

---

## 5. The state machine — model it or not

**What it catches that stage 4 cannot:** everything above tests a sequence somebody chose. A model checker enumerates the ones nobody chose. Three of the surviving findings are interleavings — the double-`Hello` on a bound row, a P-078 reclaim while a session on that `client_id` is still live, and the P-080/P-121 crash ordering — and all three were found by review, after five rounds, one at a time.

**Recommendation: yes, twice, with different lifetimes. No to everything else.**

**(a) TLA+/PlusCal, once, throwaway — for the crash-ordering question.** ~300 lines of PlusCal over: verify MAC → check counter → persist counter → reserve dedup entry → execute → complete entry, with a `crash` action available at every point and FRAM modelled as *a write either lands or does not, and a read-back may disagree*. TLC enumerates the interleavings; the invariants are `NoCommandExecutesTwice`, `NoCounterRegresses`, `EveryRefusedCommandRetriesSuccessfully`. What it finds that review did not: the reachable state where an entry left *in flight* by a reset meets a retry, and no ordering answers it on its own — which is the state P-121 is actually about. **Its deliverable is edits to P-079, P-080, P-120, P-121 and P-122, not a model in CI.** Delete it in the same commit as the edits, with the model preserved under `docs/models/` marked non-normative, because a model kept green is a second specification and this corpus's named failure mode is two documents disagreeing. The counter-argument is real — a deleted model cannot catch the next change — and the answer is that the next change to that subsystem re-runs it from that commit, which is cheaper than keeping it green against code it does not track. **Cost: 3 days, and the invariants take longer than the model.**

**(b) `stateright`, kept, for the connection/session lifecycle — but only under one condition.** BFS with state dedup over `{ClientConnected, Discover, Pair, Hello, wrq, signed, Goodbye, expire, ClientDisconnected, comms_reboot, controller_reboot}` × 2 connections × 2 clients. The cheapest thing it gives you is not an invariant violation, it is **the undefined-transition check**: a reachable `(state, action)` pair with no written transition. That is precisely the double-`Hello` finding, found mechanically in the first run. The condition: **`Model::next_state` must call the real `o89-core` session module, not a re-modelled copy.** A re-modelled copy is a second spec that drifts, which is the thing being avoided. If the session module cannot be driven that way, the seam is in the wrong place (CLAUDE.md's own rule) and fixing the seam is worth more than the model. **Cost: a week, of which most is making the module drivable — and that cost is the one people underestimate.**

**No** to Alloy (nothing here is relational), no to a proof assistant (the properties are safety properties on a small state space, which is TLC's job), no to Kani over the whole state machine (it will not close).

**The failure mode of this stage, named:** a model is only as good as its invariants, and a model with weak invariants explores a broken specification and reports success — a green tick over an unread table, which is DEFERRED entry 11's own argument one layer up. Budget the invariants first and write them from the findings above, not from the happy path.

---

## 6. Fault injection

**What it catches that stage 5 cannot:** the model says a crash between two writes is bad. This says the code actually crashes there, and recovers, on the storage the target has. A model has no torn write.

**Mechanism, and it is the whole stage:** a deterministic step counter behind the `Storage`/`Clock`/`Io` seams. Run the same operation N times, crashing at step *k* for every *k* in `0..N`, and assert a recovery invariant. That is crash-at-every-instant as a loop rather than a list somebody curated, and it is the difference between this stage and a table of scenarios. `xtask`-driven, host-only, `no_std`, no hardware.

| Instant | Invariant after recovery | Notes |
|---|---|---|
| After MAC verify, before counter persist | operation did not execute; client's retry with a new counter succeeds | P-080's stated fail-closed |
| After counter persist, before execute | the retry succeeds and executes exactly once | P-080 says lost-and-retried; P-121 says the retry must not start a second time. **These two want opposite things and stage 0a decides which** — until then this row has no invariant, and writing it red is the honest form |
| Mid-`execute`, before dedup complete | answer from the state store, not from the entry | the case P-121 is about |
| Torn FRAM write of a counter row | no counter ever regresses; a half-written row reads as the old value or fails its CRC, never as a lower number | |
| **Between epoch increment and client-table clear** | never a cleared table at a stale epoch | P-085 has *no* fail-closed rule and P-079 gives the neighbouring write one. A cut here re-mints a byte-identical `client_key` into slot 1 — the failure P-085 quotes as its own reason for existing, produced by the remedy. This row is the reason the stage is a loop and not a list: nobody put it on a list |
| Mid A/B config pointer flip | the config in effect is *old* or *new*, never a mix | P-102 |
| Mid NOR append | a torn record fails CRC, is skipped, raises `0x0702`, and leaves a `seq` hole | and see below |
| Comms reboot (new `boot_id`) | every row and binding dropped; the next client frame gets 259; `conns` agrees within one heartbeat | LINK.md |

**FRAM write failure (not a crash — a refusal).** P-079's exit: error 7, class A `0x0501`, and the operation MUST NOT execute. Extend the same treatment to the dedup write and to P-085's epoch write, and test all three, because a write that fails is a fault this corpus already accepts as real rather than a speculative one.

**Corrupted log record.** P-096 claims no hole the controller creates hides a class A record. Test it, and note what the test shows: a class A record that fails its CRC produces a hole a client cannot distinguish from a class B drop under queue pressure. Either the ring's `class` byte has to survive the CRC failure of its payload, or P-096's claim is narrower than it reads.

**Backpressure.** Deassert CTS and drain at a configured bytes-per-tick. Assert: class B dropped oldest-first and counted, `0x0701` delivered *to that session* carrying its own count; a class A event that cannot be queued closes the session with `shedding`; the first shed in an hour logs `0x0804`; three in an hour enters the ladder at `0x0801`. This is the one lever the threat model calls out as *not the same as dropping frames*, and it is a state transition the untrusted peer drives on demand.

**A clock moved under a running session.** The point of P-004, and the test that fails today: set the wall clock forward eleven minutes mid-session and assert that **nothing measured on the tick moves** — the dedup entry has not aged, the session has not expired, the `MAX_AUTH_FAILURES` window is unchanged, the challenge is still live. That is exactly the attack P-004 spells out (advance the clock, age the entry, retry with a new counter, start the generator twice), and it is currently unassertable because the entry has no time field at all. One test, and it is the acceptance criterion for stage 0a.

---

## 7. Adversarial testing, from the threat model

**What it catches that stage 6 cannot:** fault injection assumes the environment is unlucky. This assumes it is *chosen*. A sequence that is legal at every step and wrong as a whole — a withheld frame delivered four hours later, a replay timed to a reclaim, a suppression that leaves no hole — is invisible to a stage that injects faults at random.

**Three attackers, from the corpus's own model.** Every test names one:

- **A — the comms processor.** Assumed compromised. May drop, delay, reorder, replay, hold CTS, invent connections, offer times, read everything, and stamp `session_id`.
- **B — an enrolled client whose key leaked.** A stolen phone, a compromised relay. Holds a real `client_key` and a mask fixed at enrolment.
- **C — somebody who photographed the label.** Can derive `pair_key` and every `client_key` at the current epoch; needs the button to enrol.

Out of scope and stated: physical possession of the STM32.

**The harness.** A `HostileComms` implementation of the link seam with an explicit capability set — `drop(pred)`, `delay(pred, ticks)`, `reorder`, `replay(frame)`, `withhold_until(pred)`, `stamp(session_id)`, `invent_connection`, `slow_drain(bytes_per_tick)`, `offer_time(t)`, `reboot`. Every test declares the capabilities it uses. **The coverage measure for this stage is the capability list checked against the "what a compromised comms processor can do, and we accept" bullets in PROTOCOL-RATIONALE.md**: a capability with no test is a capability nobody bounded, and the rationale's own argument is that naming a capability is what lets it be bounded.

| Test | Attacker | What it proves |
|---|---|---|
| A response moved to another outstanding `req_id` fails its MAC | A | P-047, conformance 8 |
| A live `session_id` stamped onto a different connection's frame fails | A | `session_key` binds `session_id` (P-072) |
| **A signed write withheld for hours, delivered after later requests on the same session, is refused before it acts** | A | **Fails today.** Nothing measures a request's age; `counter` proves ordering, not recency; no client-side timeout is specified anywhere. This test is the artefact that drives the receiver-side `req_id` rule, and it is free now because `Command` is reserved |
| **Every `0x04` suppressed while responses flow; the client renders silence as health** | A | **Fails today.** `type` is in the clear, so the relay selects `0x04` without decoding a body. Total suppression produces no hole, so P-096/P-097's evidence-from-holes machinery never fires. The test asserts the client surfaces *broken*, and there is no rule requiring it to — so this stage's output here is a MUST beside P-097, not a code fix |
| Slow drain until eight sessions shed; `0x0804`, then `0x0801` | A | LINK.md item 6, and the record must survive the pressure that produced it |
| A `wrq` replayed to hold a session past its 15-minute expiry | A | P-077 measures inbound frames only, so a read-only replay is a keep-alive an attacker holds |
| **A signed frame captured before a P-078 reclaim, replayed after it** | B | **Fails today.** The reclaim sets the counter to 0 and unbinds nothing; the still-bound session reads the row the reclaim just zeroed. The live exposure is a `SetConfig` section nobody else edited; the reserved exposure is `Command` |
| A cloud client (mask bit 3 clear) sends `Time 0x0A` | B | `TimeAck` outcome 3, inside the MAC'd response, never an `Error` (P-105, P-141) |
| **Poll `Discover` for the `pairing_open` rising edge, fire a pre-computed backward `Time 0x0A` inside a millisecond** | B | **The press oracle.** `Discover` is unauthenticated and any peer may poll it; the press it rides is often the *remedy* (a factory reset), during which the leaked key is still live. P-116 lifts the floor entirely, so the landing zone is 1970 |
| `2^64 − 1` written into another client's counter row | B | P-084 refuses with error 12 *before* the counter is read |
| A `Pair` with a correct proof and no open window | C | outcome 2, MAC'd (P-066) — never a bare error, or a forged refusal sends somebody back to press a button that was never needed |
| Eight bad-proof `Pair`s in sixty seconds | C | connection closed, reason 3, and the row and its challenge go with it. The question this row used to say was open — does a failed `Pair` proof count? — P-051 answers: outcome 3 counts, outcomes 2 `window_closed` and 4 `table_full` do not, because refusing to look at a proof costs nothing and counting it would let anybody close a technician's connection. `Outcome::failed_a_proof` is that sentence; the count is on the connection row |
| Seven bad-proof `Pair`s, a `Goodbye` and a fresh `Hello`, then one more | C | still closed. A threshold the peer resets by handshaking again is not a threshold, and this is the one case a per-session counter passes every other test and fails |
| An old-epoch `client_key` after a factory reset | C | P-085. Paired with stage 6's epoch-write-failure row, which is the same property from the other side |

---

## 8. Bench and hardware-in-the-loop

**What it catches that stage 7 cannot:** every stage above runs on a machine where the UART is a `Vec` and the FRAM is a `HashMap`. This catches a physical assumption.

**The dividing rule is already written:** if a piece of *logic* needs hardware to test, the seam is in the wrong place, and `o89-core` names no peripheral. So the list of things that genuinely need hardware is short, and everything not on it belongs above.

**Needs hardware:**

- RTS/CTS at 921600 (P-033) — the one requirement whose subject is a connector.
- The 50 ms incomplete-frame timeout and the resynchroniser against a line that drops bytes rudely rather than politely.
- The DMA circular RX ring wrapping under load.
- FRAM torn writes and NOR ring rotation at a supply that actually sags. A simulated brown-out is a coin flip; a bench PSU on a script is a thousand of them.
- **The physical button** — and this is the one to say out loud. P-066 defines a *120-second window a press opens*, surfaced as `pairing_open`; P-116 requires the contact *held* at the instant a `Time 0x0A` is processed; DEFERRED entry 6 adds a third gesture for a firmware downgrade; factory reset is a fourth use of the same word. No host test can distinguish a window from a hold, because on the host they are the same boolean. Until the gestures are distinguished in prose, the bench cannot prove anything about them either — so this is a stage-0 dependency wearing a hardware hat.
- The RTC backup domain and LSE. BENCH.md already names the two false-PASS traps (SB26 strapping VBAT to VDD; RTCCLK on LSI), and a false PASS is worse here than a failure.
- The ESP32 rail cut, the heartbeat ladder, and the thermal behaviour of hammering a load switch.
- The three timing numbers DEFERRED entry 4 is blocked on: one `ReadLog` page, one full `Snapshot`, and the UART with eight sessions subscribed and events going out eight times. Those are measurements, and the entry's trigger is *the first time a browser talks to real hardware*.

**What the first bench session should prove, in order, and it is not the protocol:**

1. `Discover` answers over USB CDC and one frame round-trips. No auth, no session. The point is that the framer works against a real serial stack.
2. **A worst-case `MAX_FRAME` frame ten thousand times at 921600 with RTS/CTS, zero CRC failures — and the same run with the flow-control lines disconnected, which must fail.** Proving the requirement by demonstrating its absence is the only way P-033 stops being a sentence, and it is worth an hour because when it fails in a cabin it looks exactly like a protocol bug.
3. The resynchroniser against a real line: pull the pair mid-frame a thousand times, assert recovery inside one delimiter, no panic, no allocation.
4. Cut power during a FRAM write a thousand times overnight on a USB relay, assert no counter regresses.

Nothing cryptographic until framing is boring. That is BENCH.md's own bring-up order and it is right: the first bench session proves the **link**, and the protocol is proven on a laptop.

**Discipline, unchanged:** every bench finding becomes a simulator fault first, then a fix. A bench that teaches something the host tests did not know means the host tests were wrong, and fixing them is the deliverable.

---

## 9. Conformance, for the first third party

**What it catches that stage 8 cannot:** everything above was written by the people who wrote the spec. This catches our own reading of it — the shared misreading that both implementations pass and both are wrong about.

**What "conforming" should mean.** Five clauses, and one of them is a negative:

1. Reproduces every vector in `vectors/v1.json` exactly (P-001) — including the two that do not exist yet: the QR payload and its length, and the worst-case `Snapshot` at `MAX_CHANNELS`.
2. Passes the transcript corpus: the same accept/reject decision on every step, and byte-identical emissions on the deterministic subset.
3. Passes the hostile corpus without panicking, without allocating after init, and without acting on an unauthenticated message.
4. Reaches every cap under load and **refuses**, and evicts nowhere except `MAX_EVENT_QUEUE` under its written rule.
5. Names its transports. Conformance is claimed for **UART, USB CDC and WebSocket**; BLE and MQTT are specified, unimplemented, unverified, and not conformance surface.

And what it must **not** mean: passing our unit tests. Those cite our module boundaries and our type-state, and a third party that has to adopt them has been handed an implementation, not a specification.

**The suite they can run themselves.** A self-contained repo, `km43-conformance`, containing:

| | |
|---|---|
| `vectors/v1.json` | exists; add the QR entry and the worst-case snapshot |
| `transcripts/*.jsonl` | one file per conformance item, generated by xtask, each step carrying its `cites` |
| `hostile/*.jsonl` | stage 7's scripts with expected refusals, each naming its attacker |
| `HARNESS.md` | the stdio protocol from stage 4 — read framed bytes on stdin, write decisions as JSON lines. ~100 lines to implement, and it is the same harness we use, or they are running something we never ran |
| `REPORT.md` | template: which of the 14 items passed, which transports are claimed, the corpus version |

**Of the 14 conformance items, six are computable from bytes alone (1–5 and 11) and eight need a driven implementation (6–10, 12–14).** That split is why the runner protocol exists: the second half is not portable without it, and today the second half is prose.

**Items the findings say to add:**

- the QR payload reproduces byte for byte and its length matches the figure in P-049 (its own item — item 2 is COBS and is the wrong home);
- a `Discover 0x80` and a `Pair 0x8B` arriving with a non-zero `session_id` complete their outstanding requests, and a `Hello 0x81` binds the session it names;
- a `Hello` whose response is dropped, followed by `Discover` and a second `Hello`, yields a working session and not error 8;
- a dedup entry written before a simulated reset still answers `duplicate` after it, and ages out ten minutes later rather than never;
- a power cut between reserve and execute, and again between execute and complete, leaves the retry answering from the state store;
- a command refused `inhibited`, retried with identical bytes after the inhibition clears, executes and does not answer `duplicate`;
- a signed frame captured before a reclaim, replayed after it, is refused;
- a session whose events are suppressed while its responses flow is surfaced as broken, not rendered as current;
- eight bad-proof `Pair`s close the connection; eight `window_closed` refusals do not;
- one client filling its own dedup share does not cause a second client's first `Command` to be refused;
- a `Subscribe` from `oldest_seq` delivers the event at `oldest_seq`, and a `Subscribe` from 0 delivers nothing already in the log.

**The acceptance test for the suite itself, and this is the stage nobody runs.** A conformance corpus is worth what it can fail. Run `cargo-mutants` over `km43` and require that the corpus kills the mutants that matter: **removing any single MAC check fails at least one item** (that is already conformance item 9, and it should be measured rather than asserted), and **dropping the operation-hash from the dedup key fails item 13's second direction**. A corpus that passes a mutated implementation is a corpus that will pass a third party's mistake, which is the failure this whole stage exists to prevent.

---

## The gate, and where each stage runs

| | Per commit | Nightly | Per release | Scheduled |
|---|---|---|---|---|
| `cargo xtask check` (9 checks) | ● | | | |
| fmt, clippy `--all-targets`, `cargo test` | ● | | | |
| Properties (bolero, sampled) | ● | | | |
| Fuzz targets, corpus committed | | ● | | |
| Kani proofs | | ● | | |
| Interop, four pairings | ● (host pipe) | | ● | |
| `stateright` lifecycle | ● | | | |
| PlusCal crash model | | | | once, then deleted |
| Fault injection sweep | ● (short) | ● (full) | | |
| Adversarial corpus | ● | | | |
| `cargo-mutants` over the corpus | | | ● | |
| Bench session | | | | dated, written down |

**The one change to make today, before any of this:** put `cargo xtask check` in the pre-commit skill and in a CI workflow, or change `crates/xtask/src/main.rs:40` to stop claiming CI runs it. Eight checks that pass and that nothing runs are the same instrument as reading the table carefully, which is what DEFERRED entry 11 was written to replace — and entry 11 currently says the checks do not exist, which makes the file wrong about the one thing it is for.
