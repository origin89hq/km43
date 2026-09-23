---
title: Proposed topology design
description: The candidate multi-device model for KM43, proposed and not yet normative.
---

# Two planes and a revision

<p class="o89-doc-kicker">KM43 / proposal</p>

<p class="o89-doc-deck">A candidate answer to DEFERRED entry 13. Proposed, costed against the six fixtures, and not yet normative.</p>

**Status: proposal.** Nothing here is settled. It is written in PROTOCOL.md's
shape so it can be argued with in the form it would ship in, and so the byte
counts can be checked rather than believed. The settled protocol is
[PROTOCOL.md](../PROTOCOL.md); the evidence is
[COVERAGE-RESEARCH.md](COVERAGE-RESEARCH.md); the gap it answers is
[DEFERRED entry 13](DEFERRED.md).

It came from four independent designs — *Three Tables and a Revision*, *Cached
topology, packed samples*, *Slotted Profiles* and *Nodepath* — each costed
against all six fixtures and judged on three lenses. This is the synthesis, not
a vote. An adversarial review then raised sixty findings against it, fifty-two
of which survived a reader whose job was to refute them; where each of those
landed is in [What the review changed](#what-the-review-changed).

## The shape and why it won

**The shape.** Everything a client needs to *interpret* a number is a descriptor, fetched once, paged, authenticated, and stamped with one `rev`. Everything that *is* a number is a reading, selected by the client, referencing a descriptor by `sig`. Two planes, one revision joining them, and nothing else.

```text
controller (dev 0) → bus → physical device → component → signal → element
```

- **bus** is a physical port. Bus health is counter signals on the controller's own device row, not a special case.
- **device** is one serial-numbered enclosure. `parent` links a sub-device to the product that contains it, so a modular all-in-one is one identity with modules under it — not several fake instruments, not one flat `DeviceKind`.
- **component** is where *every* instance number lives: `role` + 1-based `index` within `(dev, parent, role)`. `cmp = 0` is reserved everywhere it appears and names the device as a whole.
- **signal** is a quantity on a device, at a component or at the device as a whole.
- **element** is a position inside a series signal, addressable in a `Concern` by `sig` + `elem`.

**Why this spine won.** Two of the three judges ranked *Cached topology, packed samples* first, and both did it for the same two fields, which no other design had together:

`rollup` separates **containment** from **accounting** — *my values are already inside that component's values*. It is one pointer, so it recurses for free: fixture 1's four trackers roll up to the PV array; fixture 5's two 240 V legs roll up to the merged circuit and the merged circuit rolls up to the meter. *Slotted Profiles* had a two-valued `agg` flag and physically could not encode fixture 5, where one component must be a member and an aggregate at once. *Nodepath*'s structural `idx 63 AGGREGATE` swept the merged parent and both legs into one total and rendered a confidently wrong panel. *Three Tables* made containment *mean* aggregation, and its own fixture 1 then laid the aggregate and the trackers out as siblings.

`esp` names which enum space an enum-shaped value is drawn from, in a field. That is what retires P-125: a client learns a value is a charge stage from the descriptor instead of from a hardcoded list of three metric kinds. A `vtype` of `3 enum` on its own says *that* it is an enum and never *which*, which puts the client straight back on the hardcoded map.

Plus: presence as a hot signal against membership as a cold descriptor (fixture 6 in one sentence — liveness is cheap, inventory is rare); and the `(rev, digest)` pair in `Hello`, which is the only mechanism in any of the four that can catch a controller changing a descriptor row *without* moving its revision.

**Grafted from *Three Tables and a Revision* (2nd on every lens, 1st on bounds discipline):** the whole bounds method. Two arms per page — rows **or** bytes, whichever binds first — each cap sitting under a derived ceiling with a stated margin and an assertion in `limits.rs`, in exactly the shape `MAX_LOG_PAGE_BYTES` sits under its 964 of headroom and `MAX_OPERATION` under `MAX_OPERATION_CEILING`. Also its paging discipline: rows in ascending id, a row never split, the cursor living entirely in the request so the controller holds zero resumption state.

**Grafted from *Slotted Profiles* (1st on the house-rules lens):** `Concern` key `elem`, which is the only way any design could say *cell 23 of pack 2 is over voltage*. Per-element validity, which the winner had only per-series — one open sense wire must not blank fifteen good cells. `cmds` on a component row, so a client draws exactly the buttons that component accepts instead of aiming a `Command` and learning from the `Ack`. A raw vendor state that cannot be mistaken for a normalized one. And its flash argument, which was the only one in four designs: the row encoder is one table-driven loop, not a codec per row kind, because generics monomorphise and the budget on this part is ~256 KB of image, not 144 KB of RAM.

**Grafted from *Nodepath* (4th, one very good idea):** `DeviceRow.since` — the `rev` at which the physical instrument behind a row last changed — and the rule that `History` stops at a `since` boundary rather than plotting a smooth line across two different chargers. That is the only explicit answer anywhere to DEFERRED entry 1's *same quantity, new hardware* case, and it costs nothing on the live path. Also its monotonic `age` applied to concerns as well as samples, which the winner left as a wall-clock `since` that a controller with no clock cannot fill.

**Two things the winner had that this deliberately does not take.**

The packed `bstr` of positional records is dropped. The constraint was "keep CBOR with integer keys unless you have measured evidence against it," and there is no measurement — there is a projection. DEFERRED entry 3 has already settled the argument in this repo's own words: a positional encoding is right on flash, where both ends are the same firmware and the `class` byte versions the record, and *disqualifying on the wire*, where a fielded controller meets a newer app and neither can be updated first. Writing it anyway would make two documents disagree about one decision. The CBOR encoding below costs about 2× the bytes of the blob and buys back the property that a `Readings` response can be read in a generic hex dump at 2 a.m. and, more usefully, that it parses *without the cache* — scalars and series are two separate arrays, so no key's type depends on a descriptor fetched under a different message.

The reading push is dropped. The winner added an unsolicited `Samples` message with its own MAC label, per-session selector and interval state, changed-only publication state, and a back-pressure rule — and its own admission test counted signals rather than bytes, so a legal subscription committed the controller to 40 frames every half second. A client polls what it renders. `Subscribe 0x03` is untouched and stays the event stream.

**What is polled and what is pushed, in one sentence each.** A number that moves continuously is polled: `Readings` is the only way to learn what a value *is*. A change of *state* — a validity transition, a concern, a presence change, a revision bump — is pushed as a class A event and is **applied directly, not treated as a hint to poll** (P-152, P-182). Two implementers read the earlier draft's two adjacent sentences two ways, and one of those two clients was silently wrong.

## The wire

### Retired: Snapshot — `0x02` / `0x82`

Both numbers are **retired, not reused**. The space has 83 free request opcodes; scarcity is not a reason, and a bench build still sending the old body should meet error 2 rather than a body it misparses into plausible readings.

### Inventory — `0x0D` / `0x8D`

The cold plane. Buses, devices, components, signals and parameters are five row kinds in one paged message, because they are all descriptors and they all move together under one `rev`.

**Two conventions apply to every body below, and both are load-bearing.** P-015 makes every key REQUIRED unless it is marked *optional*, and a missing required key is error 1 — so a key that is present only under a condition is marked *optional* **and** carries the condition, because marking it neither way makes a conforming decoder refuse every row that legitimately omits it. And **`bus`, `dev`, `cmp`, `sig`, `pid` and `cid` are each one flat space across the whole controller, not per-device numbering**: `rollup` names a component of another device with a bare `u16`, a `Sel` names a `cmp` with no `dev` beside it, and P-173's canonical order is *id ascending within a kind*, none of which has an answer under per-device ids.

```text
ReadInventory  0x0D          wrapper
  1: rev          u32      the revision the client is assembling; 0 on the first call
  2: what         u8       1 buses · 2 devices · 3 components · 4 signals · 5 parameters
  3: from         u16      first row id to include, inclusive (P-029);
                           0 means from the beginning
  4: dev          u16      optional; what = 5 only, parameters of this device

Inventory  0x8D              wrapper under session_key
  1: rev          u32      the controller's current revision
  2: what         u8       echoed, so the response is self-describing
  3: rows         [ BusRow | DeviceRow | ComponentRow | SignalRow | ParamRow ]
                           empty unless outcome is 1
  4: next         u16      the id to pass as `from` for the next page;
                           0 when this page ends the kind
  5: total        u16      rows this request resolves to at this rev — of this
                           kind, and of this `dev` when key 4 of the request set one
  6: outcome      u8       1 ok · 2 superseded · 3 unknown_kind · 4 out_of_range
  7: digest       bstr8    optional; present iff outcome is 1 and key 4 is 0 —
                           the topology digest, computed exactly as P-173 writes it
```

On any outcome other than 1, `next` is 0 and `digest` is absent (P-190). Without that rule `next = 0` is the natural encoding of *nothing follows*, which under key 7's condition makes the whole-topology digest mandatory on a response that answered nothing — and on outcome 4 the `rev` matches, so neither P-151 nor P-152 fires and a client can stamp a cache it never assembled.

```text
BusRow
  1: bus          u8       1..MAX_BUSES; 0 is the controller's own local I/O
  2: transport    u8       1 rs485 · 2 can · 3 ve_direct · 4 local_io · 5 ip
                           · 6 onewire · 7 internal
  3: label        text     optional; ≤ MAX_LABEL
  4: rate         u32      optional; baud or bitrate

DeviceRow
  1: dev          u16      1..; 0 is the Origin 89 controller itself
  2: bus          u8
  3: addr         bstr     optional; ≤ MAX_ADDR, as the bus defines an address.
                           REQUIRED on an addressed transport, absent otherwise,
                           unique within a bus (P-189)
  4: product      u16      product registry; 0xF000–0xFFFF vendor, skip-unknown
  5: dialect      u16      driver dialect registry; vendor range, skip-unknown
  6: role         u16      device role registry; vendor range, skip-unknown
  7: parent       u16      optional; the device this is a sub-device of.
                           Absent = attached directly to its bus
  8: serial       text     optional; ≤ MAX_IDENT
  9: hw           text     optional; ≤ MAX_IDENT
 10: fw           text     optional; ≤ MAX_IDENT
 11: label        text     optional; ≤ MAX_LABEL
 12: since        u32      the rev at which this row's physical identity last changed
 13: cmds         [ u16 ]  optional; ≤ MAX_COMPONENT_CMDS Command kinds legal at
                           this device's own scope, cmp = 0. Absent = none (P-175)

ComponentRow
  1: cmp          u16      1..; 0 is reserved and MUST NOT be allocated —
                           it names the device as a whole (P-174)
  2: dev          u16
  3: parent       u16      optional; owning component. Absent = the device is the parent
  4: role         u16      component role registry; vendor range, skip-unknown
  5: index        u16      optional; 1-based instance within (dev, parent, role).
                           Absent = the only one of its role there. Never 0
  6: rollup       u16      optional; the component whose signals already account
                           for mine. May name a component of an ancestor device (P-162)
  7: label        text     optional; ≤ MAX_LABEL
  8: cmds         [ u16 ]  optional; ≤ MAX_COMPONENT_CMDS Command kinds legal here.
                           Absent = this component accepts none (P-175)
  9: since        u32      the rev at which this row's meaning last changed (P-156)

SignalRow
  1: sig          u16      1..; 0 is reserved (P-174)
  2: dev          u16      REQUIRED
  3: cmp          u16      REQUIRED; 0 = the device as a whole (P-174)
  4: kind         u16      metric kind registry; 0xF000–0xFFFF vendor
  5: shape        u8       the container: 1 scalar · 2 series
  6: vtype        u8       what one value is: 1 gauge · 2 counter · 3 enum · 4 flags
  7: domain       u8       1 live · 2 lifetime · 3 since_reset · 4 today · 5 yesterday
                           · 6 limit_upper · 7 limit_lower · 8 max · 9 min
  8: point        u16      optional; measurement point registry; vendor range,
                           skip-unknown
  9: dir          u8       optional; 1 positive is in · 2 positive is out
                           · 3 magnitude only
 10: n            u8       optional; REQUIRED iff shape is 2, absent otherwise.
                           Series length, 2..MAX_SERIES_LEN
 11: erole        u16      optional; shape 2 only; the component role each element
                           would have if it were a component
 12: ebase        u16      optional; shape 2 only; the label of element 0.
                           Element k's label is `ebase` + k. Default 1 (P-178)
 13: esp          u16      optional; enum space registry.
                           REQUIRED iff vtype is 3 or 4, absent otherwise
 14: unit         u8       optional; unit registry. REQUIRED iff key 4 is in the
                           vendor range, absent otherwise (P-160)
 15: scale        i8       optional; same condition as key 14 (P-160)
 16: vns          u16      optional; vendor namespace. REQUIRED iff key 4 is in
                           the vendor range, absent otherwise
 17: hist         u8       optional; present iff this signal has history — the
                           finest bucket it is stored at. The space runs coarse
                           to fine (1 day · 2 hour · 3 quarter_hour), so a
                           request for a finer value is outcome 6 and a coarser
                           one is aggregated from this by P-195. MUST be absent
                           when vtype is 3 or 4. Absent = no history, and
                           ReadHistory answers outcome 5
 18: label        text     optional; ≤ MAX_LABEL

ParamRow
  1: pid          u16      1..; 0 is reserved (P-174)
  2: dev          u16
  3: cmp          u16      REQUIRED; 0 = the device as a whole (P-174)
  4: kind         u16      metric kind registry
  5: v            int      optional; i32 (P-185). Absent = never read
  6: vtype        u8       REQUIRED; 1 gauge · 2 counter · 3 enum · 4 flags,
                           as SignalRow key 6. A parameter has no `shape`:
                           it is always one value
  7: domain       u8       as SignalRow key 7
  8: point        u16      optional; as SignalRow key 8
  9: dir          u8       optional; as SignalRow key 9
 10: esp          u16      optional; enum space registry.
                           REQUIRED iff key 6 is 3 or 4, absent otherwise
 11: lo           int      optional; i32; the device's permitted floor
 12: hi           int      optional; i32; the device's permitted ceiling
 13: via          u16      optional; the Command kind that writes it. Absent = read-only
 14: unit         u8       optional; REQUIRED iff key 4 is in the vendor range,
                           absent otherwise (P-160)
 15: scale        i8       optional; same condition as key 14 (P-160)
 16: vns          u16      optional; same condition as key 14
 17: label        text     optional; ≤ MAX_LABEL
```

A **parameter** is what a downstream device says about itself and does not change with the weather — a nameplate rating, an input current limit, a permitted floor and ceiling. Origin 89's own configuration stays entirely in `GetConfig`/`SetConfig`. A *derated* limit — a BMS's present CCL, a charger derating in heat — is an ordinary signal with `domain = 6 limit_upper` and `prov = 5 reported`, because it moves. That is the whole of the separation: a parameter changes when the hardware changes, so it belongs to a descriptor under `rev`.

**A `ParamRow` carries no validity, and that is deliberate.** An earlier draft gave it the `Sample` pair `v`/`q`, which put a moving value inside the revisioned, digested plane: marking a pulled module's parameters `absent` without bumping makes the digest diverge under a fixed `rev` and fires P-151's controller-fault MUST against a correct controller, while bumping discards every client's cache twice per bay flap. Here `v` is present when the controller has read it and absent when it has not, a change to `v` *is* a topology change and bumps `rev` by P-150, and whether the instrument is reachable at all is `presence` — a signal, on the hot plane, where it belongs. Nothing that moves lives in this row.

**A parameter write therefore costs every client its cached inventory, and that is accepted rather than overlooked.** A `via` write is a person at a laptop changing an absorption voltage, on the order of once per commissioning; a rev bump is the honest signal that a descriptor changed, and P-154 already limits how often one can land. The alternative was to carve keys 5, 11 and 12 out of P-173's preimage, which would make the digest cover *most* of a row — and a hash with an exception list is a hash nobody can reproduce from the specification.

**Key 6 exists because a parameter is not always a number.** A charger's *battery type*, its charge algorithm, a relay's configured function — these are settings drawn from a vendor's enumeration, and a `ParamRow` with no `vtype` and no `esp` can only render one as a bare integer, which is the failure P-164 exists against, one plane over. There is no `shape` on this row because a parameter is one value: a device that reports sixteen of something reports a series signal, not sixteen parameters.

**Keys 7, 8 and 9 are what stop four rows all called *DC voltage*.** A charger's absorption, float, equalize and maximum-regulation voltages are one `kind` on one component; without a discriminator an installer reads four identical rows and picks one. P-188 makes `(dev, cmp, kind, shape, vtype, domain, point, dir)` unique within a `rev` for signals and `(dev, cmp, kind, vtype, domain, point, dir)` unique for parameters, refused at registration the way `rollup` cycles are. Note what that uniqueness does and does not do here: it is what stops one row being published twice, not what tells these four apart. Keys 7, 8 and 9 are what tell them apart, and dropping one from the tuple does not produce four indistinguishable rows — it produces one row and three refusals.

### Readings — `0x0E` / `0x8E`

```text
ReadSignals  0x0E            wrapper
  1: rev          u32      the revision the client's cache holds
  2: sel          [ Sel ]  optional; ≤ MAX_SELECTORS. Absent means every signal
  3: from         u16      first `sig` of the resolved selection to include,
                           inclusive; 0 means from the beginning

Sel
  1: dev          u16      optional; a device and, transitively, its sub-devices
  2: cmp          u16      optional; a component and, transitively, its children.
                           0 is not a selector — error 1; use key 1 for device scope
  3: sig          u16      optional
                           exactly one of the three; none or two is error 1

Readings  0x8E               wrapper under session_key
  1: seq          u64      log position these readings reflect
  2: rev          u32      the controller's current revision
  3: at           u64      optional; omitted when the clock has never been set
  4: s            [ Sample ]   optional; every signal whose shape is 1 scalar
  5: v            [ Series ]   optional; every signal whose shape is 2 series
  6: next         u16      the `sig` to pass as `from` for the next page;
                           0 when this page ends the selection
  7: total        u16      signals the selection resolved to
  8: outcome      u8       1 ok · 2 superseded · 3 unknown_selector · 4 out_of_range

Sample
  1: sig          u16
  2: v            int      optional; i32 (P-185). Present iff validity is 1 or 2
  3: q            u8       validity<<4 | provenance
  4: age          u32      optional; seconds on P-004's tick.
                           REQUIRED when validity is 2 stale

Series
  1: sig          u16
  2: q            bstr     exactly `n` bytes; byte k is element k's
                           validity<<4 | provenance
  3: v            [ int ]  exactly as many integers as key 2 has bytes whose
                           validity is 1 or 2, in ascending element order. Each i32
  4: age          u32      optional; seconds. REQUIRED when any element's validity
                           is 2, and it is the age of the **oldest** such element (P-179)
```

**The cursor is a `sig`, not an ordinal.** P-153 makes the controller hold zero resumption state, so it reproduces the selection from scratch on every page — and only a normative order makes that reproducible. P-183 fixes it: the resolved selection is the set union of the selectors, deduplicated by `sig`, in ascending `sig`, and a page is a prefix of that order. An ordinal into an order nobody wrote is how a client resumes at 40, receives a set that overlaps what it holds and omits signals it will never see, with `next` and `total` reconciling perfectly and the MAC verifying. A `sig` cursor is self-checking: a client can watch the ids ascend.

**Scalars and series are two arrays on purpose.** A key whose CBOR type depends on a `shape` that lives in a different message, fetched under a different `rev`, is a response a client cannot parse until its cache is warm — and this crate's reader is typed per call, so a wrong guess discards a MAC-verified body whole. Split, a `Readings` decodes with no descriptor at all; only its *meaning* needs one.

**Validity** — is this number usable now?

| | | |
|---|---|---|
| 1 | `ok` | current |
| 2 | `stale` | was good; `v` is the last known, `age` says how old |
| 3 | `initialising` | the source is up and has not produced a first reading |
| 4 | `unsupported` | this device does not implement it — including a vendor's in-band absence pattern (P-176) |
| 5 | `sensor_fault` | the source reports it bad, or the reply did not arrive intact — open, short, reversed, bad CRC |
| 6 | `out_of_range` | a number arrived and was refused: impossible for this installation, or outside the `i32` range at the registry's scale (P-185) |
| 7 | `absent` | the component or device is not present |
| 8 | `unnamed_state` | the source reported an operating state we have no value for |

**Provenance** — where did the number come from?

| | | |
|---|---|---|
| 0 | — | there is no number |
| 1 | `measured` | read directly from an instrument |
| 2 | `counted` | integrated or accumulated by the source, trustworthy as a total |
| 3 | `derived` | this controller computed it from other signals |
| 4 | `estimated` | inferred from a proxy — state of charge from terminal voltage |
| 5 | `reported` | the device states it — a limit, a setpoint it says it is honouring |
| 6 | `commanded` | what was asked for, never what was observed |

`counted` **and** `stale` is `0x22`, which is the case the single `quality` byte could not express and the reason the ledger names it. `estimated` splits from `reported`, which the old word ran together at two different trust levels. Provenance rides on the sample rather than the descriptor: a BMS reports state of charge as `counted` after a full charge and `estimated` after a reset, and that is not a topology change.

**4, 5 and 6 are three findings, and the driver currently has two words for them.** `map.rs` gives a register cell an `Absent` pattern — `AllOnes`, or the one raw value the vendor documents — and `driver.rs` answers `Reading::NotOnThisUnit` when it matches, which is `4 unsupported`: the ordinary shape of a model that omits a register, and not a fault. Everything else that fails becomes `Reading::Unreadable`, and that one word covers two different sentences. *The reply was shorter than the block* is a dialect or a bus somebody has to go and look at — `5 sensor_fault`. *The number arrived and will not fit the registry's scale* is a healthy bus carrying a value we refuse to publish — `6 out_of_range`, under P-185, which forbids clamping it into range for the same reason P-176 forbids passing a sentinel through.

So `Reading::Unreadable` has to split before step 5 can encode the difference. That is a real edit to `map.rs` and `driver.rs` and it is named here rather than discovered there, because the two collapse into one `write_absent` call today and a broken bus and a scale that is one decimal place wrong currently read identically at a client.

### Concerns — `0x0F` / `0x8F`

Snapshotable active state, separate from the transition events entry 10 owns.

```text
ReadConcerns  0x0F           wrapper
  1: rev          u32
  2: from         u16      cid to resume from; 0 means from the beginning

Concerns  0x8F               wrapper under session_key
  1: rev          u32
  2: seq          u64      log position this list reflects
  3: c            [ Concern ]
  4: next         u16      cid to resume from; 0 when complete
  5: total        u16      active concerns the table holds
  6: refused      u16      concerns the table could not hold since boot
  7: outcome      u8       1 ok · 2 superseded · 3 out_of_range

Concern
  1: cid          u16      1..; 0 is reserved (P-174). Stable while active, released only after
                           the 0x0502 announcing state 5 is committed (P-180)
  2: dev          u16
  3: cmp          u16      REQUIRED; 0 = the device as a whole (P-174)
  4: sig          u16      optional; the signal it is about
  5: elem         u8       optional; 1-based **position** in a series signal, 1..n.
                           The label a client renders is `ebase` + `elem` − 1 (P-178)
  6: cond         u16      normalized condition registry; vendor range, skip-unknown
  7: sev          u8       1 info · 2 warning · 3 fault · 4 protection
  8: state        u8       1 active · 2 active_acked · 3 latched_cleared
                           · 4 clearing_blocked · 5 cleared
  9: age          u32      seconds since first observed, on P-004's tick, carried
                           across a restart (P-181). Always present
 10: since        u64      optional; controller time first observed,
                           omitted when the clock has never been set
 11: raw          u32      optional; the source's own code, preserved verbatim
 12: vns          u16      optional; vendor namespace.
                           REQUIRED when key 11 is present, absent otherwise
 13: seq          u64      the log seq of the `concern raised` record that opened it
```

Key 9 is always present and key 10 is not, for the same reason `age` beats a timestamp on a `Sample`: a controller with no wall clock can still say how long something has been wrong. Key 5 is what makes *cell 23 of pack 2 is over voltage* sayable at all — the cells cost no component rows and are still addressable.

**That cell is `elem = 7` on the wire and *cell 23* on the screen, and both numbers are correct.** Pack 2 is the second half of a 32-cell string, so its series signal has `ebase = 17`; `elem` is the position — the seventh element of that signal — and the label a person reads is `ebase` + `elem` − 1. P-178 is the sentence that joins them, and until it existed this document said *cell 7* in one paragraph and *cell 23* in the next about the same cell, which is precisely how two implementers each render a different one and somebody drives four hours and pulls the wrong cell.

`cond` is skip-unknown, so a condition nobody has allocated still renders as *protection, pack 2, cell 23, code 0x4A12*, which is a sentence somebody can act on.

**The lifecycle has a state meaning *over*, and it did not.** A pack low-temperature protection clears at dawn, and under the earlier four states every legal value was a form of *still there*: one controller sent `3 latched_cleared` and the panel said the latch was holding so nobody started the charger; another sent nothing and the panel showed an active protection that ended six hours ago. Both leave a screen confidently wrong about whether charging is safe, and detection-by-disappearance does not save it — concerns do not move `rev`, so P-152 never fires a refetch.

| | | |
|---|---|---|
| 1 | `active` | the condition is present |
| 2 | `active_acked` | somebody has read it. The condition is still present |
| 3 | `latched_cleared` | the condition is gone; the source's latch is not, and will clear on the source's own terms |
| 4 | `clearing_blocked` | the condition is gone and the source states it *cannot* reset the latch yet — a BMS protection that needs a completed charge cycle. The difference between *wait* and *drive out* |
| 5 | `cleared` | over. Terminal, and the only state a row carries as it leaves the table |

### History — `0x10` / `0x90`

```text
ReadHistory  0x10            wrapper
  1: rev          u32
  2: sig          u16      MUST NOT be a series signal — outcome 4
  3: bucket       u8       1 day · 2 hour · 3 quarter_hour
  4: first        u32      bucket index: whole `bucket` periods **elapsed** since
                           this controller's first closed bucket, so a period in
                           which no bucket closed still consumes an index.
                           Keys 4, 10, 11 and 12 are all in the requested
                           `bucket`'s units; the FRAM counter is kept at the
                           signal's `hist` and divided down (P-194)
  5: count        u8       buckets requested; ≤ MAX_HISTORY_POINTS, or error 1

History  0x90                wrapper under session_key
  1: rev          u32
  2: sig          u16
  3: bucket       u8
  4: first        u32      the bucket index of the first bucket in this response
  5: q            bstr     one byte per bucket **returned**: validity<<4 | provenance.
                           Its own length is authoritative and MAY be shorter than
                           the request's `count` (P-184). A bucket is never
                           2 stale or 3 initialising — both describe a live
                           reading's relation to now, and a closed window has
                           neither (P-184)
  6: v            [ int ]  one i32 per bucket at validity 1 `ok`,
                           in ascending bucket order
  7: n            bstr     optional; one u8 per bucket, readings that went into it,
                           saturating at 255, and at least 1 for a bucket at
                           validity 1. Same length as key 5. REQUIRED whenever
                           any bucket is validity 1 (P-184)
  8: reset        bstr     optional; ceil(len(key 5) / 8) bytes. REQUIRED iff the
                           signal's vtype is 2 counter. Bit order in P-184
  9: src          bstr     one byte per bucket, same length as key 5:
                           1 device_reported · 2 controller_derived
 10: next         u32      optional; the bucket index to resume from.
                           Absent when this response completed the request
 11: oldest       u32      the oldest bucket index the store holds for this signal,
                           in the requested `bucket`'s units (P-194)
 12: newest       u32      the newest closed bucket index, same units
 13: stopped      u8       optional; why the response is short —
                           1 device_replaced · 2 component_reassigned
                           · 3 gap_in_record · 4 end_of_record
                           · 5 older_than_store · 6 page_full
 14: outcome      u8       1 ok · 2 superseded · 3 unknown_signal
                           · 4 series_not_historable · 5 no_history
                           · 6 out_of_range
 15: at           u64      optional; controller time at the start of bucket `first`
```

**Key 5's own length is the length of the response, and every other array is sized from it.** The earlier draft pinned `q` to the request's `count` while P-156 required a short response at a device-replacement seam; the two cannot both hold, and keys 6, 7 and 8 are all sized off the same number, so one wrong sentence mis-indexes the values, the sample counts and the reset bits together. A client written to the literal words discards a MAC-verified body whole. `LogPage` solved this next door with `next_seq`, `oldest_seq` and `complete`; keys 10 to 13 are that shape.

**Key 7** is what stops a mean over 3 of 92 readings rendering identically to a mean over 92 — the smooth-line lie, one aggregation layer up from a room card showing 0.0 °C for a probe that is not there. It is required whenever any bucket is usable rather than left optional, because a chart a client cannot audit is a chart it should not have been given. It is also what weights P-195's mean, so a window where one constituent had three readings and another ninety-two aggregates honestly instead of averaging two means.

**Key 8** is required for a different reason, and a sharper one: its absence has a natural reading and the natural reading is the unsafe one. A client meeting no bitmap concludes no bucket had a counter reset, when the truth may be that this store does not track them — a missing capability silently converted into a positive safety claim. That is why it is mandatory for every counter rather than offered, and why P-184 writes its bit order out instead of leaving it to be inferred.

Key 9 keeps Victron's own day record distinguishable from what this controller integrated, **per bucket**, because a window can span the day the device stopped supplying one: a controller down for three days in January comes back and reads the charger's 30-day backlog, which exists for exactly that reader. One byte for a whole response is false for part of such a window. Where the controller cannot place a device-reported bucket on its own axis — it closed before the controller's first bucket — it MUST NOT invent an index; those buckets are dropped and `oldest` reflects what it can place.

The vendor documents are explicit that page 20's day record is a *different signal set* from the live registers, which is why history is not modelled as "the same signals, bucketed": the extras — Voc max, panel voltage max, time in bulk, in absorption, in float — are their own signals, each with its own `kind`, `domain` and `hist`, and each historable on its own. `point` never names a charge stage; a stage duration is a quantity and belongs in the metric-kind registry.

### Command — `0x08`, operation body

```text
operation body of Command  0x08
  1: cmd_id       u32      unchanged
  2: kind         u16      unchanged, at its existing key; entry 8 still owns
                           the argument schema
  3: dev          u16      REQUIRED; 0 is the Origin 89 controller itself
  4: cmp          u16      REQUIRED; 0 means the device as a whole (P-174)
  5: rev          u32      REQUIRED; the revision keys 3 and 4 were read under
  6: args         map      unchanged content, moved from key 3 to key 6
```

`cmd_id` is `u32`, which is what PROTOCOL.md's operation body, `Ack 0x88` and P-120's 25-byte FRAM dedup entry have always said. An earlier draft wrote `u64 unchanged` — the word *unchanged* being the cue not to check — and claimed in the same row that `kind` moved to key 2, where it already was. Only `args` moves.

Two new outcomes: **7 `stale_topology`** and **8 `wrong_target`**. Both are specified in [PROTOCOL.md](../PROTOCOL.md) beside `Command 0x08` rather than here, together with P-166's refusal rule.

**That is a general rule and not a one-off, because of how the gate actually works.** `every_live_number_is_reachable` reads `docs/PROTOCOL.md` and `docs/protocol/LINK.md` and nothing else, and it only sweeps allocations whose `status` is `live`. So **nothing this document allocates goes `live` until the rule that produces it is written into one of those two files**; until then it is `reserved`, which the sweep skips. Outcomes 7 and 8 become live in the commit that puts P-166 in PROTOCOL.md. The four new response outcome spaces stay reserved until this design is promoted out of proposal. Adding this file to the swept list was the other option and it is the wrong one: it would make a proposal load-bearing for a gate on the settled protocol.

Two things about that gate are worth writing down while somebody is looking at it, because neither is what its name suggests. It does **not** sweep `metrics` or `events` at all — only messages, errors, outcome spaces and the link-local ones — so the metric kinds and event kinds below can be allocated `live` with no rule anywhere and nothing goes red. And DEFERRED entry 11 records the omission as `enums.*` and `codes.*`, which is a shorter list than the code's. Neither is this design's to fix, and both are reasons step 2 cannot lean on the gate to tell it whether it finished.

### Hello — `0x81`

```text
 13: RETIRED (was max_channels)
 18: rev                  u32   the topology revision
 19: topo_digest          bstr8 computed exactly as P-173 writes it
 20: max_buses            u8
 21: max_devices          u16
 22: max_components       u16
 23: max_signals          u16
 24: max_series_elements  u16
 25: max_params           u16
 26: max_concerns         u16
 27: max_selectors        u8
 28: max_history_signals  u16
 29: max_topology_depth   u8
```

**Keys 24 and up cost two CBOR bytes for the key itself**, because a map key is an unsigned integer under the same shortest-form rule as everything else and 24 is where one byte stops holding it. That is the only place in this document where a key number crosses the boundary, and the derivation below pays for it.

Keys 18 and 19 are what let a reconnecting client know in one round trip whether its cached inventory is still good, without walking anything — and, when the `rev` matches but the digest does not, that the controller has a defect.

**The page byte caps are not reported, and that is the rule rather than an omission.** `MAX_READINGS_BYTES`, `MAX_INVENTORY_PAGE_BYTES` and `MAX_CONCERN_PAGE_BYTES` decide how many rows arrive; no client can predict which rows fit, and every client already learns the answer from `next`. Reporting one invites exactly the misuse P-171 warns about — a client reading three caps as simultaneous. So the membership rule is: **a `Hello` key is for a capacity this controller chose and a different one may choose differently; everything a client can rely on across every conforming controller is published in the fixed table and reported nowhere.** That is what puts 880 in one table under one rule instead of two tables under opposite ones.

### Event bodies

Every body that names a `dev`, `cmp`, `sig`, `elem` or `cid` carries `rev` as key 1, and P-152 covers event bodies and `LogEntry` as well as the four responses.

```text
0x0101  RETIRED (was value changed, class B)

0x0102  signal validity changed        class A   (was value quality changed)
  1: rev        u32
  2: e          [ VChange ]  1..MAX_VALIDITY_SWEEP, coalesced by P-182

VChange
  1: sig        u16
  2: q          u8       the new validity<<4 | provenance
  3: prev       u8       the **last announced** one, not the last observed —
                         coalescing means a signal may move twice between
                         events, and `prev` is what the client actually holds

0x0501  concern raised                 class A   (was alarm raised)
  1: rev        u32
  2: c          the Concern body above, keys 1–13

0x0502  concern changed                class A   (was alarm cleared)
  1: rev        u32
  2: cid        u16
  3: dev        u16
  4: cond       u16
  5: state      u8       the new state; 5 cleared is the row leaving the table
  6: prev       u8       the state last **announced** (P-212), not the last
                         held — the coalescing sends one record for a row that
                         moved twice inside a tick

0x0901  topology changed               class A   (new)
  1: rev        u32      the new revision
  2: reason     u8       1 boot · 2 config write · 3 sub-device adopted
                         · 4 sub-device removed · 5 device replaced
  3: added      u16
  4: removed    u16

0x0902  device presence changed        class A   (new)
  1: rev        u32
  2: e          [ PChange ]  1..MAX_PRESENCE_SWEEP, coalesced by P-182

PChange
  1: dev        u16
  2: presence   u8
  3: prev       u8
```

`0x0101 value changed` is retired rather than redefined. It was the only class B kind, its rate followed a sampling loop rather than anything happening at the site, and at fixture 5's cardinality it overruns `MAX_EVENT_QUEUE` every tick — so the hint a client was supposed to lean on is the first thing dropped, and P-097's hole accounting carries nothing. A value moving is what polling is for.

**And that alone would have made the failure worse, not better.** Retiring the only class B kind moves that cardinality into the class whose overflow rule is *close the session*, not *drop and count*. One RS-485 pair going intermittent at −30 °C flips every signal behind it in one pass — up to 384 at the site cap — into a 16-deep queue across 8 sessions; P-098 closes each one, the reconnect replays the burst from the log and closes again. [LINK.md](LINK.md) L-023 logs the first shed in an hour, and L-022 puts the controller on the ladder at the third: every connection and session dropped, and `comms link lost` (`0x0801`) written against a chip that answered every heartbeat. If the cable keeps flapping the ladder does the rest, and its far end is L-112 — fifteen minutes with no cycling, the rail off on a board that can switch it back on, and `comms unrecoverable`. A fault four hours away in a cabinet takes the radio off the air and misnames itself in the log on the way.

P-182 is the fix, and it is a coalescing rule rather than a bigger queue: at most one `0x0102` and one `0x0902` per tick, each carrying an array, each carrying what fits and leaving the rest for the next tick without dropping any of it. A 384-signal sweep is eight ticks of one event, not 384 events. The class A production ceiling per tick is then derived in [Bounds](#the-class-a-burst-one-tick-can-produce) and asserted against `MAX_EVENT_QUEUE`, which is the one existing bound this design multiplies by ten and which appeared in no bounds table, no `Hello` key and no build step.

**Class B is now empty, and three documents said otherwise until this landed.** P-096's three causes for a `seq` hole become **one** — two of the three name class B outright, so only the failed-CRC skip survives — P-098's drop-oldest-first path is unreachable from a queue, and `0x0701 records dropped` stays allocated with nothing able to produce it. The class stays defined on the wire — a later kind may need it, and the column costs nothing — and P-003, P-096, P-097, P-098 and REGISTRY.md's *Today class B is exactly one kind* paragraph were edited in the same commit that retired the kind. Three documents describing a path that can no longer happen is the thing this repo does not permit.

***The code did not stay, and that was decided rather than assumed.*** *The class staying defined is a statement about the wire; it says nothing about `Outbound` keeping a branch no input can reach. Retiring `0x0101` left `EVENT_IS_CLASS_A` with no `false` in it, so `Queued::droppable` was permanently false, and* four *tests — not the two the plan expected — had no fixture left to build: the two P-097 ones, `shedding_takes_the_oldest_droppable_record_and_not_the_newest`, and the one asserting class B is exactly one kind. Keeping the mechanism meant carrying sixty lines that no test could ever turn red, which is a worse thing to own than a rewrite git remembers. So the shedding retired with the kind, and one test replaced the four: class B has no members, and it goes red the day something is allocated into it — which is the day the code comes back.*

## Bounds

### The framing correction every derivation below rests on

`ENVELOPE_BYTES = 11` counts `[type, session_id, req_id, body]` **including the body's own map header**, with a one-byte `type`. `WRAPPER_BYTES = 23` counts the wrapper map, the payload `bstr` header, and the 16-byte MAC — **including that same map header**. The two double-count one byte, and every response `type` is `0x8x`, which costs one CBOR byte more than the constant assumes. The two errors cancel exactly, which is why 11 + 23 = 34 has been the right answer for every response in this document and one byte conservative for every request.

That is luck, and luck that will be spent the first time somebody corrects one constant without the other. Split them:

```rust
const ENVELOPE_BYTES: usize = 11;         // request: array, type, session, req_id, body map header
const WRAPPER_CONTENTS_BYTES: usize = 22; // wrapper map contents; no map header
const RESPONSE_TYPE_EXTRA_BYTE: usize = 1;// a 0x8x type is two CBOR bytes
```

```text
response framing  = 11 + 22 + 1 = 34
request framing   = 11 + 22     = 33
inner body budget = 1024 − 34   = 990
```

Every existing derivation in this document keeps its answer, including the two that look as though they should not: `MAX_OPERATION_CEILING` is untouched because a signed request has no wrapper, and `MAX_EVENT_BODY` is exact for a reason set out beside the event bounds below.

Every width below comes from `cbor.rs`'s shortest-form encoder: a value ≤ 23 costs one byte, 24–255 two, up to 65 535 three, up to 2³²−1 five, wider nine. A map or array header follows the same rule on its element count. Map keys ascend and the encoding is canonical, which is what makes P-173's digest well defined.

### What the six fixtures actually cost

The deck says *costed against all six fixtures*, and until this table existed the six appeared only as arguments about shape. Cardinalities are counted from [DEFERRED.md](DEFERRED.md)'s own fixture list and the committed catalogue.

| Fixture | Devices | Components | Signals | Params | Series elements |
|---|---:|---:|---:|---:|---:|
| 1 — charger, four MPPT trackers, per-tracker day record | 1 | 7 | 37 | 7 | 0 |
| 2 — inverter/charger, two AC inputs, split phase, bypass | 1 | 13 | 47 | 9 | 0 |
| 3 — bank, two packs, 16 cells each, probes, balancing | 1 | 7 | 35 | 8 | 72 |
| 4 — dual-bank charger with an identified start battery | 1 | 4 | 17 | 4 | 0 |
| 5 — nineteen-circuit meter, merged circuits, import/export | 1 | 22 | 71 | 20 | 0 |
| 6 — modular all-in-one, three runtime sub-devices | 4 | 14 | 41 | 4 | 0 |
| controller itself (dev 0, bus counters, local I/O) | 1 | 0 | 28 | 0 | 0 |
| **all six at one site** | **10** | **67** | **276** | **52** | **72** |

**Fixture 3's wording had to be resolved before it could be counted, and the resolution is the vendor's.** *At least two packs, sixteen cells, four temperature probes* reads as a flat list, and under that reading the fixture is 16 cells total. The EG4 LifePower4 response payload is per module — *cell count, 16 cell voltages, sensor count, 4 cell temps* in one addressed pack, address 1–15 — so sixteen cells and four probes are **per pack**, and two packs is 32 cells and 8 probes. That is 2 × (16 cell voltages + 4 cell temperatures + 16 balancing bits) = 72 series elements, and it is the reading the `ebase` 1 and 17 example has assumed all along. The two readings differ by 16 cells, 4 probes and a series signal, which is exactly the arithmetic a fixture table exists to settle.

The six are a conformance set rather than a plausible site, but the cap has to hold for them at once or the claim is not a claim. Two things fall out and one of them changed a number:

- **`MAX_SIGNALS` was 320 with 64 reserved, and 276 does not fit 256 writable.** An installer adding a tank probe and a shunt would have met a refused config write four hours from a road. It is 384 with 64 reserved — 320 writable against 276, 44 spare, one more mid-size device. The RAM cost is 3.6 KB — 64 more rows at 56 bytes, plus the announced-validity byte each — and it is in the table below.
- Everything else fits with room: **9** config-written devices of 16 writable — the tenth row is the controller's own `dev 0`, which nobody writes — 67 components of 128 writable, 52 parameters of 80 writable, and 72 series elements of 512. The 512 pool is sized for fixture 3 at fourteen packs (504), not for six fixtures.

### Fixed on the wire

**None of these is negotiable and none is reported**, for one of two reasons: either a decoder sizes an array from it before a byte arrives, or it is a page stop the controller applies and a client observes only as `next` being non-zero. Both are facts of this protocol version rather than of this controller, which is why they are published here and not in `Hello`.

`MAX_BUSES` is deliberately **not** here. `1..MAX_BUSES` on `BusRow` key 1 is a range a client checks against a capacity a controller chose, so it belongs in the reported table below, and it appears in exactly one of the two. A bound in both tables under opposite rules is the thing this section exists not to do.

| Name | Value | Behaviour when reached |
|---|---:|---|
| `MAX_SERIES_LEN` | 16 elements | A driver declaring a longer series **fails to register that signal**: the device attaches, the signal does not, and a `Concern` `series_too_long` names it. A 32-cell string is two 16-element signals on two half-string components, with `ebase` 1 and 17. Never truncated |
| `MAX_LABEL` | 32 bytes UTF-8 | Refused at config write with `SetConfigAck` outcome 3 `invalid`, and refused again by the row encoder with error 1. **Never truncated** — "pump hous" is a different label and somebody acts on it wrongly |
| `MAX_IDENT` | 24 bytes UTF-8 | Serial, hardware and firmware strings. Same rule |
| `MAX_ADDR` | 8 bytes | A bus address longer than this cannot be expressed; the driver is refused at registration |
| `MAX_ROW_BYTES` | 184 | The scratch a single descriptor row is encoded into, 14 over the widest row in the table below. A row that would exceed it is **refused at registration** — the component or signal does not attach and a `Concern` names it, which is a fact somebody can act on rather than a page that silently stops |
| `MAX_SAMPLES` | 40 | The response stops; `next` names the first unanswered `sig`. Not an error |
| `MAX_SERIES` | 7 | Same |
| `MAX_READINGS_BYTES` | 880 | Same |
| `MAX_INVENTORY_PAGE_ROWS` | 48 | The page stops; `next` names the next id. Not an error |
| `MAX_INVENTORY_PAGE_BYTES` | 880 | Same |
| `MAX_CONCERN_PAGE_ROWS` | 12 | Same |
| `MAX_CONCERN_PAGE_BYTES` | 832 | Same |
| `MAX_HISTORY_POINTS` | 96 | `count` above it is error 1 — a client can check its own number |
| `MAX_COMPONENT_CMDS` | 4 | A component needing a fifth is a component that should be a parent and a child. Refused at registration |
| `MAX_VALIDITY_SWEEP` | 48 | Entries beyond it wait for the next tick and are **not** dropped (P-182) |
| `MAX_PRESENCE_SWEEP` | 24 | Same |
| `MAX_CONCERN_EVENTS_PER_TICK` | 4 | Same |
| `MIN_REV_INTERVAL_MS` | 30 s | A sub-device discovered inside the window is **staged** and adopted at the next boundary. The descriptor tables and `rev` move together, atomically, at most twice a minute |

`MAX_READINGS_BYTES` is the one spelling of that bound. It was `MAX_READINGS_ROW_BYTES` in one table and `max_readings_bytes` in another, which is one bound under two names in a section whose own COBS story is about exactly that.

### Reported by the controller, `Hello 0x81`

P-005 applies unchanged: the controller reports what it enforces, and a client MUST use the reported value. P-005's key list becomes **12, 14–29**.

| Name | This controller | Key | Behaviour when full |
|---|---:|---:|---|
| `MAX_BUSES` | 8 | 20 | Config write refused, outcome 5 `exceeds_cap` |
| `MAX_DEVICES` | 24, of which 8 reserved for runtime adoption | 21 | Config write refused, outcome 5. A sub-device discovered past the cap is **not adopted**, `rev` does not move, and a `Concern` `inventory_full` is raised against the enclosing device. Nothing evicted |
| `MAX_COMPONENTS` | 160, of which 32 reserved | 22 | Same |
| `MAX_SIGNALS` | 384, of which 64 reserved | 23 | Same |
| `MAX_SERIES_ELEMENTS` | 512, a shared pool | 24 | A series signal that does not fit the remainder is **refused at registration, never shortened** (P-172) |
| `MAX_PARAMS` | 96, of which 16 reserved for runtime adoption | 25 | Same. A sub-device brings parameters with it, so a params table with no reserve fails the adoption that fixture 6 exists to prove — at the table nobody was watching |
| `MAX_CONCERNS` | 48, of which at most `MAX_CONCERNS_BELOW_FAULT` = 24 are `info` or `warning` | 26 | **Refused and counted** in `Concerns` key 6. Nothing evicted |
| `MAX_SELECTORS` | 12 per `ReadSignals` | 27 | Error 1 |
| `MAX_HISTORY_SIGNALS` | 24 | 28 | Config write refused, outcome 5 |
| `MAX_TOPOLOGY_DEPTH` | 4 | 29 | A `parent` chain deeper than this is refused at config write **and** at runtime adoption (P-187) |

`MAX_BUSES`, `MAX_SERIES_ELEMENTS` and `MAX_TOPOLOGY_DEPTH` have keys because they are **enforced against a client's write**, which is the whole membership test for this table. `MAX_BUSES` was previously a normative range with no value anywhere in the repo; `MAX_SERIES_ELEMENTS` had its key given as *implied by* the signal cap, which is false — 384 signals imply nothing about a 512-element pool, and a driver's fourteenth pack lost its signal against a budget the client was never told; and `MAX_TOPOLOGY_DEPTH` sat in the fixed table, where a commissioning laptop writing a bank → pack → module → cell chain would meet a refusal it had no way to have predicted, four hours from a road. That is the same failure `MAX_BUSES`'s key was added to fix, so it gets the same answer.

The **reserved block** is what fixture 6 needs and what the winner's own dynamic block did not survive: its fixture assigned five of eight reserved device ids statically and left three for the runtime adoption the fixture exists to prove. A reserved block is a subtraction from the config-writable range, not a separate space.

### `Readings 0x8E` — the binding message

```text
map header (8 pairs)                                  1
key 1  seq        1 + 9  (u64)                       10
key 2  rev        1 + 5  (u32)                        6
key 3  at         1 + 9  (u64)                       10
key 4  s          1 + 2  (array header, 24..255)      3
key 5  v          1 + 1  (array header, ≤23)          2
key 6  next       1 + 3  (u16)                        4
key 7  total      1 + 3  (u16)                        4
key 8  outcome    1 + 1  (u8 ≤23)                     2
                                                   ────
READINGS_HEADER_BYTES                                42
headroom = 990 − 42                                 948
```

```text
Sample at its widest
  map header 1 + sig 4 + v 6 (i32) + q 3 + age 6           =  20

Series at MAX_SERIES_LEN, every element present and stale
  map header 1 + sig 4
    + q  1 + bstr(16) header 1 + 16                        =  18
    + v  1 + array(16) header 1 + 16 × 5                   =  82
    + age 6                                                = 111
```

```text
SAMPLE_CEILING = 948 / 20  = 47      MAX_SAMPLES = 40, margin 7
SERIES_CEILING = 948 / 111 =  8      MAX_SERIES  =  7, margin 1

MAX_READINGS_BYTES = 880 under a headroom of 948, margin 68
   40 × 20 = 800 ≤ 880          the row arm binds for scalars
    7 × 111 = 777 ≤ 880          the row arm binds for series
   both at once = 1,577 > 880    the byte arm binds

widest response = 34 + 42 + 880 = 956 ≤ 1024, 68 spare
a Sample two bytes wider at the cap = 40 × 22 = 880 ≤ 948
```

The 68 is the same margin `MAX_LOG_PAGE_BYTES` keeps under its 964 of headroom, for the same reason: a `Sample` gaining an optional key must not turn a legal response into a frame the controller builds and then refuses.

**`age` stays one field on a `Series` and P-179 says which element it describes.** Per-element age was the alternative and it costs 76 bytes net — one array of sixteen ages at 82, less the 6 the single field spent — so the widest `Series` goes 111 → 187, `SERIES_CEILING` 8 → 5, and `MAX_SERIES` below 7. The failure it was meant to fix is real — cell 3's sense wire intermittent at two hours, fifteen cells read eight seconds ago — but per-element **validity** already separates them, so the only question is what one number means. It is the age of the *oldest* element at validity 2, and an element at validity 1 has no age at all. Two stale elements of different ages both render at the older one's, which over-reports; PROTOCOL.md's own re-basing rule goes the same way, because the direction that makes an operator cautious is the safe one.

**The row caps and the byte cap are not jointly reachable, and that is stated rather than hidden.** `MAX_SAMPLES` and `MAX_SERIES` are what a decoder sizes a fixed array at; `MAX_READINGS_BYTES` is what decides how many arrive. P-171 says so, because reporting a number the controller does not enforce is worse than not reporting it, and three caps a client reads as simultaneous is exactly that.

### `Inventory 0x8D`

```text
map header 1 + rev 6 + what 2 + rows key/header 3 + next 4
  + total 4 + outcome 2 + digest 10                        =  32
headroom = 990 − 32                                          958
MAX_INVENTORY_PAGE_BYTES = 880, margin 78
widest page = 34 + 32 + 880 = 946 ≤ 1024, 78 spare
```

Row widths at their widest — every optional key present, every string at its cap, **and every field costed at the widest it may legally carry** — with rows per page as `min(row cap, byte cap ÷ width)`, which is P-171 applied rather than quoted.

That last clause is a rule and not a detail, and it has been written two ways. An earlier revision costed some fields at their *space's* widest — `transport` at one value byte because the space has seven members — and others at their *type's*, and said which nowhere. That was corrected to *cost everything by type*, on the grounds that a space can gain a member and a width that assumed it would not is a page that overruns the day somebody allocates the twenty-fourth.

**The correction was right about the inconsistency and wrong about the fix, and the reason it was wrong is that this table and the published vector are the same bytes.** `signal_widest` is not only a size; it is a row other implementations check themselves against, and a row costed at its type's widest carries `domain 200`, `dir 255` and `hist 255` — numbers no registry allocates and P-019 gives no vendor range, so every conforming reader is required to refuse it. A vector both ends reject is not a vector.

So the rule is *legal*, uniformly: the type where the field is open, the space where it is closed. The objection it was written against is answered by not assuming anything — the width fixture **asks** the generated space for its largest member on every run, so allocating a twenty-fourth moves the number, moves the width, and turns the encoder test red naming the new figure. An assumption nobody can see is the thing that overruns; a derivation that re-runs is not one.

**This is the third time these five numbers have moved, and every time they have moved toward the ones directly below**, which were derived by hand before any of it was built. 96 and 101 became 94 and 100 when the encoder learned P-204's conditional keys; 94 became 93 when it learned `n` and `ebase`'s ranges; and 48, 93 and 100 are 47, 90 and 98 now that it reads the six closed spaces. Each round, the table was edited to match the encoder — and each round the hand derivation had been right and the encoder had been missing a check the field list already stated. Not one rows-per-page figure has moved in any of them.

**The ceiling asks the opposite question and takes the opposite answer.** A width is what a row can cost at most, so it is costed at the top of each type. `INVENTORY_PAGE_ROWS_CEILING` is how many rows the byte cap could *ever* admit, so it is costed at the bottom: a `BusRow` with neither optional key and both values small is five bytes, not seven. The committed vector is what settled it — the generator built the genuinely narrowest row while the encoder test had assumed required-keys-at-widest, and the two disagreed by two bytes.


| Row | Widest bytes | Byte arm | Row arm | Rows per page |
|---|---:|---:|---:|---:|
| Bus | 47 | 18 | 48 | **18** |
| Device | 170 | 5 | 48 | **5** |
| Component | 80 | 11 | 48 | **11** |
| Signal | 90 | 9 | 48 | **9** |
| Param | 98 | 8 | 48 | **8** |

**Every byte between the type's widest and these is a rule the field lists state**, and there are three kinds of them:

- **A condition pins the value.** `shape` is 2 and `vtype` is 4, because `n` and `esp` are legal *only* under exactly those, and a row is widest with every optional key present. One byte each, where the type's widest is two.
- **The field list states a range.** `n` at `MAX_SERIES_LEN`, because a longer series has elements no `Concern` can name — `ElementAt` stops there — and `ebase` sixteen below the top of `u16`, because a higher base promises labels that do not exist (P-206). One byte for `n`; `ebase` is two either way.
- **The value is a member of a closed space.** `transport` 7, `domain` 9, `dir` 3, `hist` 3. None of the six closed spaces has a vendor range, so a number outside one is error 1 and not a value to skip — which is the difference between these and `product`, `dialect` and the two `role`s, all of which stay at `u16::MAX` and must.

**The widest row the types permit is a row the field lists forbid**, and it was what the encoder test and the committed vector both measured — three times, each time until a check caught up with a sentence that had been in the field list the whole time.

```text
narrowest legal row  BusRow with neither optional key, both small
                     map header 1 + bus 2 + transport 2            =   5
INVENTORY_PAGE_ROWS_CEILING = 880 / 5                                176
MAX_INVENTORY_PAGE_ROWS = 48, margin 128
```

That is the one cap in this section whose margin is large rather than tight, and the reason is worth stating: the row cap is what a **decoder** sizes its array at, and its ceiling is the most rows the byte cap could ever admit — which only happens at a row near the five-byte minimum. At 48 the byte arm binds for every row kind at its widest and for a typical signal, component and parameter row alike, and the row arm binds only for pathologically narrow pages. Both arms are real; P-171 is which one wins, not which one exists.

**Every page count in the earlier draft divided the row cap away.** It read 51 signal rows to a page where the arithmetic gives 38, and 14 pages for a six-fixture walk where it is 17 — having caught the same mistake one paragraph earlier for `Bus` and forgotten it immediately. The row cap moved from 16 to 48 in the same edit, because at 16 a typical row wasted most of an 880-byte page and the walk was several times longer than the number `MIN_REV_INTERVAL_MS` was justified against.

A **typical** row here is the row a real fixture produces, and the three kinds are listed key by key rather than by a rule about optionality — because they carry different optional keys as a matter of course, and one sentence covering all three reads three ways:

| Typical row | Keys | Bytes | To a page |
|---|---|---:|---:|
| Signal | every required key and nothing else — `sig`, `dev`, `cmp`, `kind`, `shape`, `vtype`, `domain` | 23 | 38 |
| Component | the required four plus `parent` and `index`, which a repeated part under an owner has | 27 | 32 |
| Param | the required six plus `v`, `lo`, `hi` and `via` | 43 | 20 |

The one that bites is `ComponentRow` key 9 `since`: it is **not** optional, so a component row is never below 19 bytes however bare, and a page count that forgets it overruns. The walk below uses the with-parent figure, because a page count that assumes the narrow row is a page count that overruns.

```text
the six-fixture walk, at typical widths
  buses        8 rows ÷ 18  =  1 page
  devices     10 rows ÷  5  =  2 pages
  components  67 rows ÷ 32  =  3 pages
  signals    276 rows ÷ 38  =  8 pages
  params      52 rows ÷ 20  =  3 pages
                             ────
                              17 pages

the same walk at the reported caps, every row at its widest
  8 ÷ 18 + 24 ÷ 5 + 160 ÷ 11 + 384 ÷ 9 + 96 ÷ 8 = 76 pages
```

**`MIN_REV_INTERVAL_MS` has to outlast a walk, and 30 s covers the first figure and not the second.** Seventeen pages in 30 s is 1.7 s per page, which is the number to measure the first time a browser talks to real hardware over BLE; if a page costs more than that, `MIN_REV_INTERVAL_MS` moves rather than the walk. Seventy-six pages does not fit at any plausible per-page cost, which is why P-191 exists: a bay that stages and un-stages repeatedly is quarantined and named in a `Concern` rather than allowed to ratchet `rev` while a client restarts its walk forever. This project has already met that shape once, as a counter that livelocked when two clients connected.

**The row-width table is a check on the encoder, not a second copy of it.** A page is built by encoding each row into a `MAX_ROW_BYTES` scratch, measuring what came out, and appending it with `CborWriter::raw` only if it fits the remaining budget — then writing the array header once the rows are counted. The check is a `#[test]` that encodes a worst-case row of each of the five kinds through the public encoder and asserts the byte count equals the constant in this table. It **cannot** be a `const_assert!`: that macro expands to `const _: () = assert!(…)` in `lib.rs`, and `CborWriter` is not `const fn`. The earlier draft prescribed one, which is a check that cannot compile standing in for the one named defence against the COBS defect — two formulas for one bound in `limits.rs`, disagreeing by a byte at every multiple of 254 while both stayed safe. `const_assert!` keeps the arithmetic it can actually do.

### `Concerns 0x8F`

```text
map header 1 + rev 6 + seq 10 + c key/header 2 + next 4
  + total 4 + refused 4 + outcome 2                        =  33
headroom = 990 − 33                                          957

Concern at its widest
  map header 1 + cid 4 + dev 4 + cmp 4 + sig 4 + elem 2 + cond 4
    + sev 2 + state 2 + age 6 + since 10 + raw 6 + vns 4 + seq 10  = 63

CONCERN_CEILING = 957 / 63 = 15      MAX_CONCERN_PAGE_ROWS = 12, margin 3
MAX_CONCERN_PAGE_BYTES = 832, margin 125
   12 × 63 = 756 ≤ 832
widest page = 34 + 33 + 832 = 899 ≤ 1024, 125 spare
```

**The row arm always binds here, and the byte cap is a backstop that is never reached.** Twelve concerns at their widest are 756 bytes against 832, and at the narrowest legal `Concern` — no `sig`, no `elem`, no `since`, no `raw`, no `vns`, so 37 bytes — 832 would admit 22 where the row cap admits 12. That is stated rather than left for a client to discover, because a cap nothing can reach is a cap somebody eventually plans against. It stays in `limits.rs` as the assertion that keeps a future key on `Concern` from turning a legal page into a frame the controller builds and then refuses.

`elem` costs two bytes and not three, because P-178 makes it a position in `1..MAX_SERIES_LEN` rather than a label that can exceed 23. The earlier draft costed it at three, which was one of the two things pointing at the other reading.

`MAX_CONCERNS = 48` in the store, at most `MAX_CONCERNS_BELOW_FAULT = 24` of them `info` or `warning`. Two packs of sixteen cells is thirty-two potential per-cell concerns, and under a single flat cap a cold soak fills the table before the pack-level protections arrive — allow-charge false, contactor open, the CCL collapsing to zero. Refusing beats evicting when the members of a collection are interchangeable, and here they are not: the ones that arrive first are per-cell and the ones that decide whether a charger may start arrive later. Two counters, two bands, nothing evicted, and the refused count on every page. `MAX_CONCERNS_BELOW_FAULT` was named in P-169's arithmetic and defined nowhere.

### `History 0x90`

```text
map header 1 + rev 6 + sig 4 + bucket 2 + first 6            =  19
  + q      1 + bstr(96) header 2 + 96                        =  99
  + v      1 + array(96) header 2 + 96 × 5                   = 483
  + n      1 + bstr(96) header 2 + 96                        =  99
  + reset  1 + bstr(12) header 1 + 12                        =  14
  + src    1 + bstr(96) header 2 + 96                        =  99
  + next 6 + oldest 6 + newest 6                             =  18
  + stopped 2 + outcome 2 + at 10                            =  14
                                                            ────
widest body at MAX_HISTORY_POINTS                             845
spare = 990 − 845                                             145
widest response = 34 + 845 = 879 ≤ 1024, 145 spare

per point = q 1 + v 5 + n 1 + reset 1/8 + src 1            8.125
fixed     = 845 − 96 × 8.125                                   65
POINT_CEILING = (990 − 65) / 8.125 = 113
MAX_HISTORY_POINTS = 96, margin 17
```

**The index counts elapsed periods, not closed buckets, and that is the difference between a chart and a lie.** Under a count of *closed* buckets a controller down for three days in January closes nothing, index n+1 sits three days after index n, and a client dating the rest of the window from key 15 — the one anchor it has — plots a seventy-two-hour outage as one quarter-hour and mis-dates every point after it. That is the smooth-line lie key 7 exists against, arriving one layer up and immune to it. Counting elapsed periods puts the gap on the axis, where P-184 stops the response at it with `stopped = 3` and `next` names the far side.

**And every index in one exchange is in the units the request asked for.** Keys 4 and 10 are positions in the response; keys 11 and 12 describe the store; P-193's outcome 6 then compares them — *`first` is past `newest`* — which is not a comparison at all unless they share a unit. A client asking for the last 96 days sends `first = newest − 95`, and against a controller holding its axis in quarter-hours that is 24 hours, answered or refused with both sides conforming to the words. The FRAM counter is kept at the signal's finest `hist` and divided down per request, which costs one division and removes the whole class.

96 is one day of quarter-hour buckets, which is the window DEFERRED entry 3's aggregate record uses — so the client-facing page and the flash record agree about what a day is. The cursor, the two store bounds, and the move of `src` from one byte per response to one per bucket take the widest body from 730 to 845 — the stop reason is not in that list, having replaced `truncated` at the same two bytes. The 145 that remains is still a wider margin than `Readings` keeps at its own cap.

A series signal is refused with outcome 4 rather than answered: 96 buckets × 16 cells is about 9.2 KB against a 990-byte body, so `may be a series signal` was a sentence with no encoding behind it. It is numbered **below** `no_history` on purpose — a series signal never carries `hist` either, and P-193 returns the first outcome that applies, so the other order would make this one unreachable.

### `Hello 0x81`

```text
keys 1–17, both fw strings at MAX_STRING, every reported cap
  at the widest its declared type permits                         213
  less retired key 13                                              −3
  plus keys 18–29, key bytes included                             +59
  plus one map-header byte: 28 pairs is past 23                    +1
                                                                 ────
                                                                  270
widest response = 34 + 270 = 304 ≤ 1024, 720 spare

  the +59, key byte + value byte, at each type's widest
    18 rev 1+5   19 digest 1+1+8   20 buses 1+2   21 dev 1+3
    22 cmp 1+3   23 sig 1+3        24 elem 2+3    25 par 2+3
    26 con 2+3   27 sel 2+2        28 hist 2+3    29 depth 2+2
```

**Every value below is costed at the widest its declared type permits — a `u8` at 2 value bytes, a `u16` at 3 — and not at this controller's value**, because P-005 tells a client to use what it was told, and the budget has to hold for what a *different* controller might tell it.

**That convention runs through the row tables too, and it is why `bus` costs two value bytes there.** An earlier revision of this section costed `BusRow` key 1 and `DeviceRow` key 2 at one byte on the grounds that `MAX_BUSES` is 8 — which was true of this controller and not of the protocol, and which contradicted the same section's decision to make `MAX_BUSES` a reported capacity rather than a fixed one. A controller reporting `max_buses = 24` is legal under the only rule that bounds it, and its `BusRow` is 47 bytes rather than 46. The whole point of splitting the two tables was that a number cannot be fixed for the arithmetic and negotiable for the client, so the arithmetic follows the reported reading.

The 213 is derived here rather than carried. An earlier draft printed 207, with no derivation behind it, no map-header byte for a map that grows from 17 pairs to 27, and the two single-byte `protocol_major`/`protocol_minor` keys costed as though 255 encodes in one byte.

### The class A burst one tick can produce

```text
0x0102 signal validity changed, coalesced
  body   map header 1 + rev 6 + e key/array header 3          =  10
  entry  map header 1 + sig 4 + q 3 + prev 3                  =  11
  SWEEP_CEILING = (965 − 10) / 11 = 86    MAX_VALIDITY_SWEEP = 48, margin 38
  at the cap  10 + 48 × 11 = 538 ≤ MAX_EVENT_BODY 965

0x0902 device presence changed, coalesced
  body   map header 1 + rev 6 + e key/array header 3          =  10
  entry  map header 1 + dev 4 + presence 2 + prev 2           =   9
  at MAX_PRESENCE_SWEEP = MAX_DEVICES = 24  10 + 216 = 226 ≤ 965

class A events one tick can produce, from THIS design
  0x0102                                    1
  0x0902                                    1
  0x0501 + 0x0502 concern raised/changed    4   MAX_CONCERN_EVENTS_PER_TICK
  0x0901 topology changed                   1   at most one per MIN_REV_INTERVAL_MS
                                          ───
  this design's contribution                7   of MAX_EVENT_QUEUE 16
  left for the sixteen it does not bound    9
```

**The nine is not a margin, and calling it one would be the same mistake in a smaller font.** REGISTRY.md allocates twenty event kinds and nineteen of them are class A. This design redefines and bounds three — `0x0102`, `0x0501`, `0x0502` — and adds two more that it bounds. **The remaining sixteen have no per-tick bound anywhere in this repo**: output changed, behaviour decision, generator state changed, the four `0x08xx` comms records, boot, config changed, time set and the rest. Until now none needed one, because class B absorbed the pressure and class A was rare. This design empties class B and multiplies class A by ten, which makes that missing bound load-bearing.

So `CLASS_A_TICK_CEILING` is the **total** across every class A kind, this design's and the existing ones', and P-182's MUST is against the total. Three of the nineteen are kinds this design redefines and bounds, and two more are new here; the remaining sixteen have no per-tick bound at all. Bounding the other sixteen — most of which are trivially bounded by physics, since a controller boots once and a clock is set by a person — is work that lands in build step 8, with the arithmetic written out the way this table is. A ceiling that counts only the kinds its author happened to be thinking about is the shape of the defect this section exists to fix.

`0x0502` is counted with `0x0501` and not separately. P-180 makes an `0x0502` mandatory as each concern leaves the table, and thirty-two per-cell concerns clearing at dawn is one tick — so a cap on raises alone leaves the clears unbounded and reproduces the burst this whole section exists to stop, arriving through the requirement that gave the lifecycle a state meaning *over*.

`MAX_EVENT_BODY` is already derived in `limits.rs` as `1024 − 11 − 23 − 25 = 965`. Without the coalescing rule this design's own column reads 384 against 16, and P-098 turns that into eight closed sessions.

**`MAX_EVENT_BODY` survives the split exactly, and the reason is worth writing down because it looks at first like it should not.** `Event 0x04`'s type is below `0x17`, so `RESPONSE_TYPE_EXTRA_BYTE` does not apply and its framing is `11 + 22 = 33`, not 34 — which appears to leave the constant one byte short. It does not, because `EVENT_FIXED_BYTES = 25` deliberately excludes the event record's own map header, and says so: *the map header is `ENVELOPE_BYTES`'*. The byte that `ENVELOPE_BYTES` and `WRAPPER_BYTES` double-count is precisely that map header. Two errors and an omission cancel to zero, and `1024 − 11 − 23 − 25 = 965` is exact rather than lucky.

That is the third instance of the same pattern in this one section, and it is the argument for splitting the constants rather than against it: every one of these cancellations is correct today and none of them is written down anywhere a person correcting one constant would look.

### Every widest response against `MAX_PAYLOAD`

```text
Readings   0x8E    34 + 42 + 880  =  956   ≤ 1024    68 spare
Inventory  0x8D    34 + 32 + 880  =  946   ≤ 1024    78 spare
Concerns   0x8F    34 + 33 + 832  =  899   ≤ 1024   125 spare
History    0x90    34 + 845       =  879   ≤ 1024   145 spare
Hello      0x81    34 + 270       =  304   ≤ 1024   720 spare
```

Each cap sits below its own derived ceiling with a stated margin, and each derivation belongs in `limits.rs` beside the others with an assertion that goes red when somebody raises a cap past what carries it. The way to watch them fail is to raise one and run `cargo test -p km43`.

**Forty-three constants**, not the twenty an earlier build step named, and the breakdown is printed so the count can be checked rather than believed:

```text
18  fixed on the wire   MAX_SERIES_LEN MAX_LABEL MAX_IDENT MAX_ADDR MAX_ROW_BYTES
                        MAX_SAMPLES MAX_SERIES MAX_READINGS_BYTES
                        MAX_INVENTORY_PAGE_ROWS MAX_INVENTORY_PAGE_BYTES
                        MAX_CONCERN_PAGE_ROWS MAX_CONCERN_PAGE_BYTES
                        MAX_HISTORY_POINTS MAX_COMPONENT_CMDS MAX_VALIDITY_SWEEP
                        MAX_PRESENCE_SWEEP MAX_CONCERN_EVENTS_PER_TICK
                        MIN_REV_INTERVAL_MS
10  reported            MAX_BUSES MAX_DEVICES MAX_COMPONENTS MAX_SIGNALS
                        MAX_SERIES_ELEMENTS MAX_PARAMS MAX_CONCERNS
                        MAX_SELECTORS MAX_HISTORY_SIGNALS MAX_TOPOLOGY_DEPTH
15  derived             ENVELOPE_BYTES WRAPPER_CONTENTS_BYTES
                        RESPONSE_TYPE_EXTRA_BYTE INNER_BODY_BYTES
                        READINGS_HEADER_BYTES INVENTORY_HEADER_BYTES
                        CONCERNS_HEADER_BYTES SAMPLE_CEILING SERIES_CEILING
                        CONCERN_CEILING POINT_CEILING SWEEP_CEILING
                        CLASS_A_TICK_CEILING INVENTORY_PAGE_ROWS_CEILING
                        MAX_CONCERNS_BELOW_FAULT
──
43
```

A step that says *twenty* against a table that holds forty-three is a step nobody can tell they have finished. Each name appears in exactly one of the three groups, which is the same rule that moved `MAX_BUSES` out of the fixed table.

### Controller RAM

Descriptor **labels live in the configuration image in FRAM**, not in the row structures, and each row holds a 2-byte offset — 32 bytes multiplied by 700 rows is 22 KB of UTF-8 that would otherwise sit in RAM for nobody. The controller **does** read them, at two moments: when it encodes a row into a page, and when it computes the topology digest, which is what makes a label edit visible to P-173. An earlier draft said the controller never reads them, and under that reading changing a label moves no byte the digest covers and build step 4's test cannot go red.

| | Rows | Bytes/row | |
|---|---:|---:|---:|
| buses | 8 | 16 | 128 |
| devices | 24 | 44 | 1,056 |
| components | 160 | 44 | 7,040 |
| signals — descriptor 35, live 21 | 384 | 56 | 21,504 |
| series element pool | 512 | 8 | 4,096 |
| parameters | 96 | 56 | 5,376 |
| concerns — including the persisted accumulated age | 48 | 68 | 3,264 |
| history open buckets | 24 | 24 | 576 |
| pending adoptions — including P-191's flap counter | 8 | 44 | 352 |
| announced-validity byte, one per signal — what P-182 coalesces against | 384 | 0 | 0 |
| page scratch — 880 staging + 184 row | — | — | 1,064 |
| inner-body encode buffer | — | — | 990 |
| | | | **45,446 B** |

**44.4 KB of 144 KB**, every one a fixed array sized at compile time, nothing allocated after init, no per-session subscription state, no resumption state. `MAX_SNAPSHOT_BODY` (888 B) retires with `Snapshot`, so the net is +43.5 KB.

**The element row was 6 bytes and is 8, which is this table's one unit confusion and worth naming.** Six is an element's *wire* width — an `i32` and a `q` byte, CBOR-packed. In RAM a `{ i32, quality }` cell has `i32` alignment, so five rounds to eight, and 512 of them are 4,096 bytes rather than 3,072. It was found by building it: `o89-core`'s store had a self-imposed 36 KB budget with 3,064 bytes free, the pool needed 3,072, and the `const` assertion holding that budget stopped the build **eight bytes short** — which is the arithmetic doing exactly what it was put there for. The packing that would buy the difference back stores values apart from the qualities that say whether to believe them, and that is the one trade this project does not make, so the budget moved instead.

*The lesson generalises to every other row here:* these widths were costed on the wire, and a row read in RAM pays alignment the wire does not. Nothing else in the table has been re-measured against a real struct, so treat the total as a floor rather than a figure.

The announced-validity byte is what makes P-182 bounded without a queue: the pending set is *derived* each tick by comparing a signal's current `q` against the last one announced, so a burst of 384 costs a byte per signal rather than 384 queue slots, and nothing can be dropped because nothing was ever enqueued.

**Its row is zero because it was measured, and the row above is why it can be.** The byte is a field on the live row rather than a table beside it, and a `Slot` was already 48 bytes with two spare in its own alignment — so `Store` is 41,168 bytes with the byte and 41,168 without it. That is the element row's lesson running the other way: a width costed on the wire is not a width in RAM, and the arithmetic goes in both directions. It stops being free the day a `Slot` grows past its padding, which the `SIZE` assertion is what catches.

Row widths are honest Rust with `Option`-wrapped optionals rather than sentinels — a `None` costs a discriminant and the alternative is a default that reads as a measurement, which is the thing this project does not ship.

### Controller flash, which is the budget nobody costed

Four message pairs on a ~256 KB dual-bank image, replacing `snapshot.rs`'s 1,415 lines. What keeps it affordable is that the five row kinds share **one** encoder driven by a static field table — `(key: u8, ty: u8, optional: bool)` — so adding a row kind is a table row rather than a function, and nothing monomorphises per kind. The table is exactly the keys in the five row definitions above: 4 + 13 + 9 + 18 + 17 = **61 entries at 3 bytes, 183 B**. Estimate: 2.5 KB of codec, that table, and the **29** new generated enums with `Display` against `generated.rs`'s current 1,091 lines — call it 14 to 20 KB of `.text`.

**The estimate is not the check.** `cargo size` on `o89-fw` before and after each of the four pairs lands, recorded in the commit message. An estimate nobody measured is exactly the class of number this repo has already caught twice.

## Requirements

**Twenty-two of these have been promoted and now live in [PROTOCOL.md](../PROTOCOL.md).**
A rule that is being implemented belongs in the settled document — that is what
`every_live_number_is_reachable`, `bodies_match_the_spec` and the traceability
ratchet each said in turn — so as each message lands, its requirements move
rather than being copied. What is left here is the reasoning; the rule is there.

| Here | There | What |
|---|---|---|
| P-190 | **P-145** | outcome other than 1 carries no rows, no cursor, no digest |
| P-153 | **P-146** | the controller does not pin a walk |
| — | **P-147** | an unallocated `what` is an outcome and not an error |
| P-173 | **P-148** | the digest preimage, byte for byte |
| P-151 | **P-149** | `rev` and digest are one identity; the trigger is the row write |
| P-157 | **P-196** | a value key exists exactly when there is a value |
| P-158 | **P-197** | a series' q bytes and its integers, and the counting between them |
| P-183 | **P-198** | the resolved selection: union, ascending `sig`, and a cursor that is an id |
| P-193 | **P-199** | outcomes are evaluated in ascending order, and what triggers `Readings`' |
| P-185 | **P-185** | every value position is an `i32`, and one out of range is refused, not clamped |
| P-174 | **P-200** | `cmp = 0` is device scope, and `sig`/`pid` reserve 0 |
| P-175 | **P-201** | an absent `cmds` is none, and `[]` is not a second way to write it |
| P-189 | **P-202** | `addr` is required on an addressed bus and unique within it |
| P-162 | **P-203** | a `rollup` is already counted, combines under nothing, and cannot cycle |
| P-160 | **P-204** | `unit` and `scale` ride a vendor kind and never a standard one |
| P-156 | **P-205** | `since` moves when the instrument or the meaning behind a row does |
| P-178 | **P-206** | `ebase` is the label of element 0, not its position |
| P-188 | **P-207** | the descriptor identity tuple, unique within a `rev` |
| P-171 | **P-208** | a page ends on whichever cap binds first, and a row is never split |
| P-183 | **P-209** | the concerns walk: `cid` ascending, and a `total` that counts what it returns |
| — | **P-210** | `seq` is the pin a concerns walk is held against, and what moves it |
| P-181 | **P-211** | a concern's accumulated age crosses a restart, or the row does not |

The numbers do not line up because PROTOCOL.md's space and this document's were
allocated independently, and renumbering a settled document to make a proposal
tidy is the wrong trade. The mapping is here so nobody reads the two as separate
rules that happen to agree. P-185 keeping its number is a coincidence of two
counters passing each other and not a convention.

**P-193 moved in part, and is now down to one message.** Its ascending-evaluation
clause is general and went whole; of its trigger table the `Readings 0x8E` rows
went with it and the `Concerns 0x8F` row followed when that message landed. Only
`History 0x90`'s four rows are still here, and they go over when it does. A
trigger promoted ahead of the message it triggers is a rule naming an outcome
nothing can produce, which is precisely what `every_live_number_is_reachable`
refuses.

*The concerns row was corrected on the way across.* It said outcome 3
`out_of_range` fires when `from` is past the largest **active** `cid`, and
*active* is the wrong word now that `total` counts a `cleared` row the walk still
returns — P-209 makes those rows part of the walk, so a `from` past the last
active one but not past the last cleared one has rows left to send. It is the
largest `cid` **the table holds**. The empty table was unstated and is now
outcome 1 with no rows rather than outcome 3: *nothing is wrong at this site* is
an answer, and a controller that refused it would put a client's screen into an
error state on the best day of the year.

**P-183 is the one rule that went across twice.** It stated two walks in one
paragraph — the `ReadSignals` selection and the `ReadConcerns` order — and the
two messages landed a long way apart, so it is **P-198** there for the first and
**P-209** for the second. Nothing is left here.

**P-156 moved in part, and P-178 is now whole.** P-205 carries P-156's two
`since` fields and the condition under which each must move; the clause stopping
a `History` bucket at either boundary, with its `stopped` value of
`1 device_replaced` or `2 component_reassigned`, stays here until the history
messages land — it is the half that names a message PROTOCOL.md does not
describe. P-178's remainder was the same shape and is gone: **P-206** now carries
the clause making `Concern` key 5 `elem` a 1-based position and the `ebase` +
`elem` − 1 a client renders from the two together, because the message that key
belongs to is described there now.

**P-188's two statements of the parameter tuple disagreed, and the requirement
block is the one that counts.** The prose at the head of this document wrote
`(dev, cmp, kind, domain, point, dir)` for a `ParamRow` while the requirement
wrote `(dev, cmp, kind, vtype, domain, point, dir)`. The requirement is right and
the prose has been corrected: a charger's enum-valued *battery type* and a gauge
sharing its `kind`, `domain`, `point` and `dir` on one component are two
parameters, and without `vtype` in the tuple a conforming controller refuses at
registration a pair this design explicitly wants. The tree could not settle it —
there is no parameter table in `o89-core` at all, so nothing was enforcing either
reading.



### Amended

**P-005** — the reported-keys list becomes **12, 14–29**. Key 13 is retired.

**P-014** — unchanged as a rule, and its scope is now stated: it governs a discriminant in a **request**, where a receiver can refuse and the sender can be told. On the response path it is displaced by P-165.

**P-019** — the vendor range `0xF000`–`0xFFFF` and the skip-unknown rule extend from the metric-kind and event-kind spaces to the **component-role, device-role, product, dialect, condition, measurement-point, vendor-namespace and enum-space** registries. Every other new space — `validity`, `provenance`, `shape`, `vtype`, `domain`, `direction`, `transport`, `severity`, `concern_state`, `presence`, `unit`, `bucket`, `history_source`, `topology_change_reason`, `history_stop_reason`, `inventory_kind`, and every new outcome — is closed and has no vendor range.

**Every name in both lists is the registry space's name, not the field's**, and the two differ in two places that matter to whoever writes `protocol.toml`: the space `direction` is carried in a field called `dir`, and the space `inventory_kind` is carried in a field called `what`. An earlier revision named those two by their field names here and by their space names in the registry section, which is one space under two spellings in the two lists build step 2 works from — the same defect that left `presence` allocated in neither.

**P-093** — the wall-clock rule stands. Its corollary is deleted: staleness no longer needs a date, because `age` is a duration on P-004's tick.

**P-003, P-096, P-097, P-098** — amended for an empty class B, in the same commit that retired `0x0101`. P-096's three causes for a `seq` hole become **one** — two of the three name class B in as many words, so only the failed-CRC skip survives. P-098's drop-oldest-first branch is unreachable from a session queue and says so. `0x0701 records dropped` stays allocated and is unreachable until a class B kind is allocated again.

*P-096's first cause was never implemented in the first place, which the retirement is how anybody found out.* `journal.rs` *writes a* `Class::Durable`/`Droppable` *byte into every record header so a scan can shed without parsing a payload — and every call site in the tree passes* `Durable`*, with nothing anywhere reading the byte to shed. So* dropped under pressure in the log *described a mechanism that has a field, a wire encoding and no code. It is not resurrected here: the log's write budget is entry 3's, and a cause with no producer is better named than quietly kept.*

### Retired

**P-089** (`Value` key 3 in `i32` range), **P-090** (no paging, at most `MAX_CHANNELS` values), **P-091** (absent omits key 3), **P-092** (`stale` carries a timestamp). Four describe a message that no longer exists. Their arguments survive as P-157, P-159 and P-185 — P-089's integer bound in particular is **replaced rather than dropped**, because five byte derivations in this document spend it and `cbor.rs` and `limits.rs` both cite it by number.

**This list said six, and two of them are not retired.** P-006 and P-125 were on it, the retirement commit ran into both, and 6c below records what it found.

*The ratchet does object, once, and the objection is easy to answer wrongly.* Deleting `**P-125**` from `PROTOCOL.md` fails the build with *`reading.rs` cites P-125, which no document allocates* — the citation check firing, because the allocation is read out of `PROTOCOL.md` and the citation out of a `#[test]` name. That message names the **test**, so the cheapest way back to green is to rename the test, and renaming it passes: the rule is then stated in no document, cited by nothing, and every check agrees. Watched, both halves: the deletion goes red, and the deletion plus the rename goes green with the sentence gone. The check is a tripwire on the *number*, not a guard on the *rule*, and it cannot tell a requirement that was replaced from one that was simply removed.

*P-006 outlived the message because it was never only about it.* It caps `Hello` key 13, and `handshake.rs` enforces it on **encode and on decode** — a controller that reports more than 32 is refused by the peer, and the controller is bound not to build one. What died is its *argument*: the snapshot it would build and then have refused with error 5. The rule goes when key 13 goes, which is the step that moves the `0x0002 channels` config section to `0x0004 topology`, and 6c's closing note already defers both. Until then its justification in `PROTOCOL.md` names a message that is gone and is rewritten in place, not deleted.

*P-125 outlived the message because its replacement is not here yet.* It is the only settled sentence that forbids rendering an unnamed enum value as the nearest one a build knows. P-165 replaces it and reaches much further, and P-165 is unpromoted — it lives in this document and nowhere a client implementer reads. P-125 is retired **in the commit that promotes P-165 into `PROTOCOL.md`**, and not before: deleting it first leaves the rule stated nowhere while `Meaning::Unrecognised` and the test named after it still stand behind it.

### New

**P-150** — `rev` MUST be monotonic in FRAM, MUST be incremented on any change to a bus, device, component, signal or parameter descriptor, and MUST NOT be decremented or reset — not on reboot, and not on factory reset, where `epoch` moves alongside it.

*A rev that can repeat is a cache that is silently wrong: a client rendering* pack 2 cell 9 *over bytes that are now* circuit 14. *Every other failure in this design is loud. This one is not, which is why the counter is in FRAM and why P-151 exists.*

**P-151** — `rev` and `topo_digest` are **one identity**. A client MUST treat a difference in either field as a different topology and MUST discard its cached descriptors. A client meeting a matching `rev` with a differing digest MUST refetch **and** MUST surface it as a controller fault. The digest a controller reports MUST equal P-173's hash of the descriptor rows **as they stand at the moment of the response**; a controller MAY cache the value, and MUST invalidate that cache on any write to any descriptor row.

*A digest that a client only compares when it fetches is a digest nobody ever compares, because a client whose rev matches never fetches. Putting it in `Hello 0x81` puts it in front of the one party that can catch a descriptor changed without the revision moving. The trigger is the row write and not the `rev` bump, because a controller that recomputes on the bump satisfies the letter of the rule, then edits a `ComponentRow` without bumping and reports a digest that still matches — the one mechanism the design claims for its own silent failure, not compelled to exist by the requirement that claims it.*

**P-152** — Every `Inventory`, `Readings`, `Concerns` and `History` response, **every event body that names a `dev`, `cmp`, `sig`, `elem` or `cid`, and every such `LogEntry`**, MUST carry `rev`. A receiver MUST NOT interpret any of them under a `rev` other than the one its cache holds; it discards and refetches instead.

*A stale cache renders the wrong component's name against the right number, which is worse than rendering nothing — and the replay path is where it bites hardest. A client subscribes from its last accepted seq, so a record written under rev 41 arrives before the `0x0901` that would qualify it, and P-153 has already made rev 41's descriptors unfetchable forever. `ReadLog` has the same hole months later. Six bytes on a class A path is cheap today and stops being cheap the moment the first event is in somebody's NOR ring.*

**P-153** — The controller MUST NOT pin a walk. It reports its current `rev` in every page, and MUST answer a request naming a `rev` that is neither 0 nor current with outcome **2 `superseded`**, the current `rev` in key 1, and an empty row array.

*Pinning is a resumption state machine holding a consistent view across round trips, on a device with no allocator — the reason [PROTOCOL-RATIONALE.md](../PROTOCOL-RATIONALE.md) rejected paging the snapshot. `rev` is the pin, it costs the controller nothing, and a torn walk is not prevented but is detectable in a field that is already on every page.*

**P-154** — `rev` MUST NOT change more often than `MIN_REV_INTERVAL_MS`. A sub-device discovered inside the window is staged and adopted at the next boundary. **A `SetConfig` write to `0x0004 topology` inside the window MUST be accepted and staged**, applied at the next boundary, and answered with `SetConfigAck` outcome **9 `staged`** carrying the seconds remaining.

*A modular product with a marginal bay contact — the ordinary failure of a connector at an unattended site — otherwise bumps faster than a seventeen-page walk completes, and the client never assembles an inventory. The config half is the commissioning laptop on the day the installer is writing topology in bursts: P-102 says apply on the pointer flip, P-150 says bump, P-154 said do not, and there was no outcome meaning* correct, but not for another eighteen seconds. *Entry 9 owns the outcome number.*

**P-155** — A device's `presence` MUST NOT bump `rev`. A device that stops answering keeps its rows; its signals report `validity 7 absent` with no value.

*A module pulled from bay 3 and pushed back in would otherwise discard every cached id at every client, twice, for a fact that changed nothing about what those ids mean. Liveness is cheap and hot; membership is rare and cold, and that split is the whole of fixture 6.*

**P-156** — `DeviceRow.since` MUST be set to the current `rev` whenever the physical instrument behind that row changes, and `ComponentRow.since` whenever that row's meaning changes. `History` MUST NOT return buckets spanning either boundary: it stops there and sets `stopped` to **1 `device_replaced`** or **2 `component_reassigned`** according to which seam it hit. The two are different values because *which* seam it is decides whether a technician is looking for a swapped instrument or a rewired configuration.

*Somebody swaps a dead charger for an identical one at the same terminals. Every id is unchanged, which is what you want for* what is the power in the pump house *and a trap for* is this the same instrument. *A series that runs straight through the seam is eight months of history plotted as one smooth line across two machines. The component half is the same failure one level down — a reassigned component plots two meanings as one line, and DEFERRED entry 1's own worked scenario has no device in it. This makes the seam visible where it matters; it does not settle [DEFERRED.md](DEFERRED.md) entry 1.*

**P-157** — `Sample` key 2 MUST be present exactly when validity is 1 `ok` or 2 `stale`, and absent otherwise. `provenance` MUST be 0 exactly when there is no value and in 1..6 exactly when there is.

*`0xFFFF` at a scale of −2 is 655.35 V, which is a plausible-looking number on an MPPT RS, and the vendor document says in as many words that fields not present in a given unit read that way. There is no slot for a number when there is no number — including for `sensor_fault`, where a rule demanding a value would force an encoder to invent one under a byte that says the sensor is broken. This rule constrains the encoding* after *a validity has been chosen; who chooses is P-176, and the two were one rule pretending to be a fix.*

**P-158** — `Series` key 2 MUST be exactly `n` bytes, where `n` is the descriptor's length. Key 3 MUST hold exactly as many integers as key 2 has bytes whose validity is 1 or 2, in ascending element order. A length disagreement is error 1.

*One open cell-sense wire must not blank fifteen good cells, and an absent element must not be a byte that decodes to a plausible voltage. Position is identity in a series, so an element cannot simply be omitted — but an element with no reading has no integer anywhere in the message, which is the only version of this a decoder cannot get wrong. There is no CBOR `null` on this wire; `cbor.rs` refuses simple value 22 on both sides and has a test named for it.*

**P-159** — `age` is a duration in **seconds** on P-004's monotonic tick, never a wall-clock instant, and is REQUIRED when validity is 2 `stale`. `Concern` key 9 `age` is always present.

*P-092 required a timestamp and P-093 forbade inventing one, so a controller whose clock had never been set could not report `stale` at all — the last known value simply disappeared until somebody wrote the time. A duration since boot is a claim a controller with no date can honestly make. Seconds and not milliseconds: a `u32` of milliseconds wraps at 49.7 days, and a controller seven weeks into an uninterrupted run is the normal state at this site rather than the exception.*

**P-160** — `unit` and `scale` MUST be absent from a `SignalRow` or `ParamRow` whose `kind` is below `0xF000`, and MUST be present when it is in the vendor range.

*A descriptor that can disagree with the registry is a second source of truth for the number on the screen. Two controllers could report the same standard quantity at different scales and both would verify, and a client could not tell a legitimate scale choice from a driver bug. Standard kinds keep fixed semantics; vendor kinds carry their own and are namespaced by `vns`.*

**P-161** — Instance identity MUST NOT appear in the metric-kind space. A repeated part is a component with a `role` and an `index`, or an element of a series.

*Tracker 2 is an instance of the same quantity, not a new quantity. `pv-power-1` through `pv-power-4` has no end — L1/L2/L3, bank 1/2, pack 1–16, cell 1–16, relay 1–6 and circuit 1–19 all reproduce it — and it spends the global registry on the shape of one product.*

**P-162** — A component whose `rollup` is set MUST have its values already accounted for in the named component's values, and a client MUST NOT combine the two under **any** aggregation — not a sum, not a maximum, not a mean. `rollup` MAY name a component of an ancestor device. It MUST NOT form a cycle; cycles are refused at config write and at runtime adoption.

*The charger's combined PV figure added to its four trackers is double the sun. A merged 240 V circuit added to its two legs is double the dryer. The earlier wording said* MUST NOT add*, which is false for most rows of its own flagship fixture — Victron's day record maxes power where it sums yield — so an implementer either dropped signals the vendor reports or shipped a descriptor carrying a false MUST. Stated as* do not combine*, the rule is true for every domain, and vacuous rather than false for an enum or a flags word, where there is nothing to combine. The ancestor-device permission is fixture 6: its modules must be devices — they have serials, firmware, presence and runtime adoption — so a same-device-only rule left the product's 4,200 W and its three modules' 1,400 W with no expressible relationship, and a client drawing 8,400 W of sun on a 4.2 kW system through the one topology the model was extended to express. Whether the aggregate was reported or summed by us is a different question, answered by `prov`.*

**P-163** — A repeated part that carries a label, a `rollup`, a command, or its own concern MUST be a component. A series element is anonymous and indexed.

*Nineteen circuits modelled as a series cannot say which one is the range and which two legs merge into it. Sixteen cells modelled as components cost sixteen rows and sixteen signals for a number nobody names. The rule is what makes both fixtures fit, and a driver that reaches for the wrong one has made a decision it cannot take back without a `rev` bump.*

**P-164** — A device reporting an operating state this controller has no normalized value for MUST report `validity 8 unnamed_state` with no value, and MUST raise a `Concern` carrying the source's own code in `raw` and its namespace in `vns`.

*The validity clause is built and promoted; the concern clause is blocked, and on something specific.* `Slot::quality` answers `unnamed_state` and `PROTOCOL.md` carries the rule. What cannot be written is `vns`: **nothing in `o89-core` knows which vendor a reading came from.** `driver::Device` is a Modbus slave with a register block and a list of signals, `dialects.rs` holds blocks and no dialect id, and the word `VendorNamespace` appears nowhere in the crate. The chain that would supply it — device → dialect → vendor — is `DeviceRow` keys, and **there is no device or component table in `o89-core` at all**, which is the same absence `traceability.toml` already records against P-201 to P-206.

*The fused type is what made that visible rather than shippable.* `VendorCode` carries `raw` and `vns` together or not at all, because key 12 is REQUIRED when key 11 is present. So the half-built version — a concern carrying a raw code from nobody — is not constructible, and the missing piece surfaced at the type rather than in a review. That is the third fused pair earning its place in a way the first two did not have to.

*So the order is:* the device and component tables, then a dialect that names its vendor, then this clause. It is not a small commit hiding behind a large one; it is a later build step that this rule turns out to sit on.

*The Magnum BMK's state of charge `255 = "Think'n"` means* still learning, not yet trustworthy *— present, not absent, and not to be acted on. Xantrex's `255 Data Not Available` and Victron's `255 Not available` are the same shape. Mapping any of them onto the nearest state we know is how a behaviour acts on a figure the device has said is not ready, and rendering it as an integer puts* state: 255 *on somebody's screen.*

**P-165** — An unrecognised value in **any closed space listed in P-019**, appearing in **any field or any value position, in any response body or any event body**, MUST surface **that one row** as unrecognised and MUST NOT invalidate the message. In the **value position** — `Sample` key 2, `Series` key 3 and `ParamRow` key 5 under `vtype = 3 enum`; `History` key 6 is not among them, because P-195 forbids an enum signal from carrying `hist` at all — the value MUST NOT be mapped onto a known member, MUST NOT be rendered as a number, and MUST NOT be replaced with a fallback. An unrecognised **validity** additionally means the value MUST NOT be rendered at all. An unrecognised **outcome** means *unknown, possibly executed*: it MUST NOT be rendered as either success or failure, and a client MUST NOT retry the request automatically.

*Stated as a list of nine field names — which is how it was written — the one position P-125 governed is not in it, and P-125's text is deleted in the same build step that scopes P-014 away from the response path. So a charger's firmware adds charge stage 9, the controller knows it so P-164 does not fire, `esp` is recognised so nothing else fires, and the client renders* stage: 9 *or picks the nearest one it knows and shows* float. *That is exactly what P-125 was written in full to forbid, arriving through its own replacement. Stated by category it also reaches `severity`, `concern_state`, `transport`, `unit`, `bucket`, `history_source`, `inventory_kind`, `presence` and every outcome space, none of which the enumeration covered, and the five event bodies, which the phrase* the response *excluded. The outcome clause is the sharpest of the three: REGISTRY.md still carries a row saying an unrecognised outcome is rejected outright, and* rejected *and* possibly executed *are different things to tell somebody about a command that may have started a generator.*

**Amended before promotion, because the tree says one clause cannot be met.** P-165's validity sentence — *an unrecognised validity additionally means the value MUST NOT be rendered at all* — reads at **element** granularity, and for a `Series` no receiver can deliver that.

`Series` key 3 is one array of integers holding exactly as many as key 2 has bytes whose validity carries a value, and an element's integer is found by counting the carriers **before** it — `Series::value_at` does precisely that, and P-197 requires an encoder and a decoder derive it the same way. So an unrecognised validity at element 3 does not cost element 3 alone. It makes the position of every integer after it unknowable: the receiver cannot tell whether the unknown validity consumed an integer, and being wrong by one shifts every remaining cell onto its neighbour's number. Sixteen cells, all plausible, all off by one, and the one that matters is the one somebody drives four hours to replace — which is the failure P-197 exists against, arriving through the rule written to prevent blanking.

*So the honest granularity for a series is the row.* P-165's own phrase — *surface that one row* — already permits it; the validity clause is what contradicts it, and the clause is what changes. **An unrecognised validity in `Series` key 2 makes that signal unreadable and MUST NOT invalidate the rest of the page.** A `Sample` keeps element granularity and needs none of this: its key 2 is an explicit optional key, so a receiver reads whether a value is present rather than deriving it.

*It is not promotable yet either, and that is a separate fact.* P-165 binds a **receiver**, and the only receiver-side decode in this tree is `Series::check`, a row-level primitive whose sole caller is the vectors test. There is no page decoder in Rust at all — the same reason P-125 could not be declared untestable. Promoting P-165 now would put a rule in the settled specification with nothing to point at, and would put it there in the element-level wording the paragraph above shows to be wrong. It goes in with the decoder, and the decoder is what proves the wording.

**P-166** — A `Command 0x08` MUST name `dev`, `cmp` and `rev`. The controller MUST refuse a `rev` that is not current with outcome **7 `stale_topology`** before the request reaches a handler, and MUST refuse a `kind` not in the target's `cmds` with outcome **8 `wrong_target`**. At `cmp = 0` the target's `cmds` is `DeviceRow` key 13. **Both checks run after PROTOCOL.md P-080's dedup lookup, not before it**: a command that already executed MUST be answered with the outcome P-120 recorded for it, because a byte-identical retry arriving after a `rev` bump is the ordinary shape of a lost `Ack`, and answering it `stale_topology` tells a client its command failed when it ran.

*A client cached* relay 3 = cmp 57*, somebody rewired and wrote configuration, cmp 57 is now the pump, and* turn on relay 3 *starts a pump from four hours away. Six bytes on a message that is sent by hand, against a mistake nobody can see happen.*

**P-167** — A parameter is writable only through the `Command` kind named in its own `via`. There is no register address, offset or raw value on this wire, in either direction.

*A compromised cloud with arbitrary write access to every attached instrument is worth more to an attacker than any single command. A vendor register nobody has normalized stays a read-only diagnostic row, and an engineer who genuinely needs to poke it uses the CLI on the bus.*

**P-168** — Acknowledging a concern moves `state` from **1 `active` to 2 `active_acked`** and never to 3, 4 or 5. Only the condition going away moves it further.

*A protection somebody has read is not a protection that has cleared. The two were one command called* clear alarm*, and a charger started on the strength of an acknowledged over-temperature is what that word buys you. The earlier wording named a `state 4 cleared` that the enum called `clearing_blocked`, which is the one shape of error this rule exists to forbid, committed inside the rule itself.*

**P-169** — The concern table MUST refuse rather than evict, MUST reserve `MAX_CONCERNS − MAX_CONCERNS_BELOW_FAULT` rows for `fault` and `protection`, and MUST report the refused count in `Concerns` key 6.

*Twenty-four cell-imbalance warnings arriving first otherwise hide the pack fault that arrives twenty-fifth. Refusing beats evicting when the members of a collection are interchangeable; per-cell warnings and a pack-level protection are not, and the ones that decide whether charging is safe are the ones that arrive late.*

**P-170** — Every collection in this section is bounded by a named constant, and the controller MUST report the values it enforces in `Hello 0x81` keys 18–29.

*P-005's argument one layer down. A parameter table with no cap cannot be compiled on a part with no allocator, and a `total` field wide enough to admit 65,535 rows is a client sizing an array against a page count nobody bounded.*

**P-171** — A page ends on its byte cap or its row cap, whichever binds first, and a row is never split. The row cap is what a decoder sizes a fixed array at; the byte cap is what decides how many arrive. A client MUST NOT assume both are reachable at once, and a page count MUST be computed as `min(row cap, byte cap ÷ row width)`.

*Reporting a number the controller does not enforce is worse than not reporting it, and three caps a client reads as simultaneous is exactly that: 40 samples and 7 full-width series are 1,577 bytes against a budget of 880. The division clause is here because this document stated the rule and then divided the row cap away in every page figure it printed.*

**P-172** — A series signal whose elements do not fit the remaining `MAX_SERIES_ELEMENTS` pool MUST be refused at registration, never shortened.

*A fourteen-pack bank silently reporting twelve cells per pack is a bank whose imbalance nobody can see. The device attaches, the signal does not, and a `Concern` names it.*

**P-173** — `topo_digest` is the **leftmost 8 bytes of SHA-256** over this preimage, and over nothing else:

```text
  "km43/v1/topo-digest"              19 bytes ASCII, no trailing NUL
‖ rev                                 4 bytes, big-endian
‖ for each descriptor row, in canonical order:
      the row's encoded CBOR map, byte for byte — exactly the bytes that
      appear inside the `rows` array of an Inventory 0x8D page

canonical order = `what` ascending  (1 buses, 2 devices, 3 components,
                                     4 signals, 5 parameters)
                  then the row's own id ascending within each kind
```

An absent optional key contributes nothing, because it is not in the bytes. A `label` contributes the bytes of its CBOR text item, because the row encoder emits it. Neither side re-encodes: the controller hashes what its row encoder produced, and a client hashes the row bytes exactly as they arrived, which `CborReader::raw` hands it whole.

*Key 7 fixed the order of rows and said nothing about the bytes of one — no domain label, no statement of which representation, nothing about absent optional keys, nothing about whether `label` is in the hash. Build step 4 calls this the only test that can see the one silent failure this design has, and under a preimage that hashes the rows the controller* holds *rather than the bytes it* sends*, changing a label moves no offset and the test cannot go red. The domain label is P-043's rule applied to a third kind of domain input, which that table gains a row and a sentence for. `rev` is in the preimage so a digest can never be lifted from one revision to another. The re-encoding question is P-017 and P-120's, and it is answered by construction rather than by exemption: both sides hash bytes that were produced once, by an encoder, and neither decodes and re-encodes to get them. And because `vectors/v1.json` is generated by a tool forbidden to depend on `km43`, the preimage has to be written precisely enough that a second implementation reproduces it — which is the whole reason to write it out.*

**P-174 is promoted as P-200**, and the numbers differ — a test named after this one is refused by the citation check, which is how the discrepancy was found. P-200 carried the rule for `cmp`, `sig` and `pid` and did **not** name `cid`, because the sentinel it is reserved against was `Concerns` key 4 and that key did not exist in the settled document. It does now, and P-200 names `cid` and `Concern` key 3 with the rest. Cite P-200.

**P-174** — `cmp = 0` is reserved in **every** message that names a component and means *the device as a whole*. A `ComponentRow` MUST NOT be allocated `cmp = 0`. `SignalRow` key 3, `ParamRow` key 3, `Concern` key 3 and `Command` key 4 all use it, and none of them expresses device scope by omitting the key.

**Every other id space starts at 1 for the same reason, and 0 is reserved in all of them**: `sig`, `pid` and `cid` MUST NOT be allocated 0, because 0 is already spent as the end-of-paging sentinel in `Inventory` key 4, `Readings` key 6 and `Concerns` key 4. A driver that allocates `sig = 0` makes `next = 0` unreadable — a client cannot tell *resume at signal 0* from *the selection is complete*, so it either stops a page early and renders a dashboard missing the well-pump circuit, or loops on page one forever.

*`BusRow` annotates 0 and `DeviceRow` annotates 0; `ComponentRow` key 1 was bare, and nothing forbade a driver allocating component 0. On fixture 2's inverter/charger that could be the AC transfer relay, and then* stop generator, this device *and* stop generator, the transfer relay *are the same bytes with no `Ack` field to separate them. Device scope was also encoded three ways across four messages — 0 in `Command`, absence in `Concern` and `ParamRow`, not at all in `SignalRow` — which is why `presence`, the signal the whole presence-versus-validity separation rests on, could not be described by a `SignalRow` at all and could not be selected by a `Sel`. One convention, four messages, and a client can ask whether a device is online.*

**P-175** — An absent `cmds` means the target accepts **no** commands. An empty array is not a legal encoding and is error 1. A `DeviceRow` carries `cmds` for its own `cmp = 0` scope, including `dev 0` for the controller's own commands.

*`ComponentRow` key 8 was the one optional key in the document with a MUST attached and no stated meaning for absence, so P-166 was either a no-op on every component a driver author left blank or* optional *was false for every commandable component. And `0x0203 acknowledge concern` takes a `cid` from the controller's own table, so it targets dev 0 / cmp 0 — which had no `cmds` list anywhere, making the design's own new command unsendable on every reading of its own rule.*

**P-176** — A dialect MUST declare, per register cell, the in-band pattern its vendor documents for *this unit does not have this*, or declare none. The pattern is matched on the raw register bits at the cell's own width, **before** sign extension, width conversion and scale. A driver meeting a declared pattern MUST publish `validity 4 unsupported` with no value and MUST NOT publish it as a reading. A reply that did not arrive intact is `validity 5 sensor_fault`, and a number that arrived but cannot be carried at the registry's scale is `validity 6 out_of_range` (P-185). None of the three is the other, and none of them carries a value.

*This is the wire half of a seam `map.rs` has already opened: `Absent::AllOnes` and `Absent::Raw(u32)` on a `Cell`, and `Reading::NotOnThisUnit` against `Reading::Unreadable` in `driver.rs`. Declared and never assumed, because most vendors use no sentinel and inventing one deletes the top reading of every register they really use. P-164 does the enum-shaped case and stopped there; the numeric one is what COVERAGE-RESEARCH calls the most dangerous translation on the whole path, and it had no rule, no place to declare a pattern, and no fixture. `0xFFFF` at scale −2 is well-formed, MAC-verified, P-157-compliant and P-165-compliant, and it raises an over-voltage concern against a healthy array, makes the shading comparison across trackers nonsense, and sits in the history bucket's maximum forever. Validity 6 `out_of_range` cannot catch it, because 655.35 V is a plausible number on a 450 V unit.*

**P-177** — A signal a given model or firmware does not implement MUST be published as a `SignalRow` at `validity 4 unsupported`, and MUST NOT be omitted from the inventory.

*Two conforming controllers on identical hardware otherwise give a client two different answers about what the site can measure, with different cap accounting and a different digest — one publishes 320 signals and the other 316. Publishing is also the cheaper of the two on the path that actually happens: the vendor confirms three times on one page that availability is a function of model* and firmware version*, so a downstream firmware update that adds* maximum allowed panel voltage *would, under the omit reading, be a topology change that bumps `rev` and discards every client's cache. Under this rule it is a validity transition from 4 to 1 — an `0x0102`, no bump, no walk. That is also why `topology_change_reason` has no* capability changed *value: the case exists, and it is not a topology change.*

**P-178** — `ebase` is the **label** of element 0; element k's label is `ebase` + k, and the default is 1. `Concern` key 5 `elem` is the element's **position**, 1-based, in `1..n`. A client renders the label as `ebase` + `elem` − 1.

*`SignalRow` key 10 — key 12 since the `shape`/`vtype` split — said* the index of element 0*, `Series` key 2 said* byte k is element k's*, and `Concern` key 5 said* 1-based element index*, so one word was taken from each vocabulary and no sentence joined them. The bounds table's own example is a 32-cell string as two 16-element signals with `ebase` 1 and 17, which is fixture 3. Pack 2's cell 23 goes over voltage: one encoder writes `elem = 7` meaning the seventh element, another writes 23 meaning the label, one client renders 7 and another renders 23. All parse, all MAC-verify, and somebody drives four hours and pulls the wrong cell. This document is origin-conscious everywhere else it cares —* 0-based *on `ReadSignals`,* 1-based instance… Never 0 *on `ComponentRow`,* in ascending bucket order *on `History` — so the omission read as an oversight rather than an implication. Position was chosen over label because it keeps `elem` inside `MAX_SERIES_LEN`, which keeps it a `u8` and costs two bytes rather than three; a concern above element 255 was inexpressible under the other reading anyway.*

**P-179** — `Series` key 4 `age` is the age of the **oldest** element at validity 2. An element at validity 1 has no age.

*Per-element validity was grafted in precisely so one open sense wire does not blank fifteen good cells, and the age then stayed per-series and REQUIRED when* any *element is stale, with no rule saying which one it described. Cell 3's sense wire is intermittent and its last good reading is two hours old; the other fifteen were read eight seconds ago. One controller sent 7200 and every client rendered the whole pack as unreadable, so the operator drove out; another sent 8 and a client rendered cell 3's two-hour-old 3.9 V as current, and a balancing decision was made on it. Both conformed. Naming the oldest costs no bytes and errs toward caution, which is the direction PROTOCOL.md's own re-basing rule takes.*

**P-180** — `state 5 cleared` is terminal. A concern row leaves the table only by an `0x0502` carrying state 5, and its `cid` MUST NOT be reallocated until that record is committed to the log.

*Without a state meaning* over*, all four legal values were forms of still-there and a protection that ended at dawn had no encoding. Without a removal rule, no sentence anywhere said a row ever leaves, so with refuse-not-evict a cold soak's thirty-two per-cell rows sat against `MAX_CONCERNS = 48` indefinitely and P-169's fail-safe test passed over a table permanently full of last spring. Without the `cid` rule, `0x0203 acknowledge concern` lands on a reused id. DEFERRED entry 13's own exit condition names `cleared` in as many words.*

**P-181** — A concern's accumulated `age` MUST be persisted with the row and carried across a restart. A controller that cannot recover the accumulated age MUST NOT report a fresh one.

*`age` runs on P-004's boot-relative tick against a RAM table, so a low-temperature protection that has blocked charge for six hours reports `age = 12` after a brown-out and the operator reads* this just started*. Key 10 `since` re-bases the same way, being first-observation too. PROTOCOL.md already answers this exact collision elsewhere with a MUST that re-bases in the over-retaining direction; this one re-based in the under-reporting one, with no rule at all. Four bytes a row in the store.*

**Its last sentence had no legal answer, and promotion is where that showed.** Key 9 is always present, so *MUST NOT report a fresh age* leaves a controller that cannot recover one with nothing to send: no third value, and no absence to encode. The two clauses could not both be met. **P-211** states the way out that was implied and never written — a controller that cannot recover a row's accumulated age does not restore the row at all, and the condition is raised again as a new concern under P-180 with a new `cid` and an age that honestly starts now. That is a smaller claim than an invented duration and a larger one than silence, and it is the same shape as P-194's answer to a gap it cannot measure.

*Nothing in the tree could have caught this at the time.* There was no `age` on a `Concern` in `o89-core` — the struct carried the id, what it is about, the condition, the severity, the state and the vendor code, and nothing that counted seconds — so the requirement had no implementation to contradict. It was found by writing the body out and asking what an encoder puts in key 9, which is the question a field list forces and a prose requirement does not. Step 7h has since built the field, and `Age`'s two constructors are P-211's two clauses.

**P-182** — The controller MUST NOT enqueue more than one `0x0102` and one `0x0902` per tick. Each carries an array of what fits its cap; entries that do not fit are carried to the next tick and MUST NOT be dropped. **`0x0501` and `0x0502` together** are bounded at `MAX_CONCERN_EVENTS_PER_TICK` per tick on the same terms. The class A events one tick can produce MUST sit below `MAX_EVENT_QUEUE` with a stated margin.

*One RS-485 pair going intermittent flips every signal behind it in one pass — up to 384 at the site cap — and class A cannot be dropped, so P-098 closes each of eight sessions, the reconnect replays the burst from the log and closes again, and L-022 puts the controller on the ladder at the third shed in an hour: every session dropped and the log saying* comms link lost *about a chip that answered every heartbeat. `MAX_EVENT_QUEUE` is the one existing bound this design multiplies by ten and it appeared in no bounds table, no `Hello` key and no build step.*

***The clears are counted with the raises, and an earlier revision of this rule bounded only the raises.*** *That gap is the same failure arriving through the fix for a different one: P-180 makes an `0x0502` mandatory as each row leaves the table, and a cold soak's thirty-two per-cell concerns all clear at dawn in one tick. Thirty-two class A events, a queue of sixteen, and the controller is back on the ladder — having been put there by the requirement that gave the lifecycle a state meaning* over*. Bounding raises and clears separately would have the same hole one level down, so the cap covers both kinds together.*

*The coalescing is bounded without a queue because the pending set is derived from a one-byte announced-validity value per signal, so nothing is ever enqueued and therefore nothing can be dropped.*

**P-183** — The resolved selection of a `ReadSignals` is the **set union** of its selectors, deduplicated by `sig`, ordered by **`sig` ascending**. A page is a prefix of that order and `from`/`next` are `sig` ids. A `cmp` selector matches that component and, transitively, every component whose `parent` chain reaches it; a `dev` selector matches that device and, transitively, every device whose `parent` chain reaches it. `cmp = 0` is not a legal selector — device scope is a `dev` selector — and a `Sel` carrying it is error 1.

**The same ordering rule governs a `ReadConcerns` walk**, by `cid` ascending. `rev` cannot pin that one, because concerns deliberately do not move it (P-155), so `Concerns` key 2 `seq` is the pin instead: a client MUST treat a page whose `seq` differs from the first page's as a torn walk and restart it. Without that, a `cid` released under P-180 and reallocated mid-walk is a row a client sees twice or never, in the table that decides whether a charger may start.

*P-153 makes the controller reproduce the set from scratch on every page, and only a normative order makes that reproducible. Order it by anything volatile inside one `rev` — poll-ring arrival, freshest first, selector order — and the indices shift between page 1 and page 2 at the same `rev` and the same `sel`: the client resumes at 40, gets a set that overlaps what it holds and omits signals it will never see, with `next` and `total` reconciling perfectly and the MAC verifying. With the push deleted the client keeps last poll's value with its `q` byte still reading `ok`, so validity 2 and `age` cannot fire on a sample that never arrived — a dashboard missing the well-pump circuit at 2 a.m. Union rather than concatenation because `total` differed between conforming controllers for one request otherwise, and `total` is the field P-170's own rationale exists to make sizable.*

**P-184** — In a `History 0x90`, key 5's own byte length is the number of buckets returned and keys 6, 7, 8 and 9 are sized from it, never from the request's `count`. **A bucket's validity MUST NOT be 2 `stale` or 3 `initialising`** — both say something about a live reading's relation to *now*, and a closed window is not a live reading; a bucket either holds a value or names why it does not. Key 6 therefore carries one integer per bucket at validity 1, and key 7 is REQUIRED whenever any bucket is at validity 1 and is at least 1 for each such bucket. Key 8 is REQUIRED iff the signal's `vtype` is `2 counter`, is exactly `ceil(len(key 5) / 8)` bytes, and the bucket at index k of the response is **bit `k mod 8` of byte `k div 8`, counting bit 0 as the least significant**. Bits past the last bucket MUST be zero. Any length disagreement is error 1. **The returned window is contiguous**: an **interior** gap — a bucket the store does not hold, with buckets it does hold on both sides — ends the response at that point with `stopped = 3 gap_in_record` and `next` naming the first bucket after it. A window running past `newest` is `4 end_of_record` and one starting before `oldest` is `5 older_than_store`; `stopped` is evaluated in ascending order like an outcome, so a response that hits a seam and then an edge names the seam. There is no encoding for *no bucket here* inside a window and there deliberately is not one — `absent` says the device is not present and `unsupported` says it does not implement the signal, so a client meeting either inside a chart plots fourteen hours of unavailability that never happened.

*"Exactly `count` bytes" and P-156's "it stops there" cannot both hold, and every other array is sized off the same number, so one wrong sentence mis-indexes the values, the sample counts and the reset bits together. One implementer returns 40 buckets and violates key 5; another pads 96 and must pick a validity for buckets that never existed —* absent *says the device is not present,* unsupported *says it does not implement it, neither means* no bucket here *— so a client plots fourteen hours of unavailability that never happened. `reset` is the only sub-byte-packed field in this document, and P-036 states its bit order in as many words* because it was previously drawn as `frag: u7, last: u1` with no byte layout, which two implementers pack differently. *A reset flag one bucket out puts the discontinuity in the wrong hour and sends a technician after a shunt that is fine.*

**P-185** — Every value position on this wire is a signed integer in the `i32` range: `Sample` key 2, `Series` key 3, `ParamRow` keys 5, 11 and 12, and `History` key 6. A receiver MUST reject a wider one with error 1. A source value outside the range MUST be published at `validity 6 out_of_range` with **no value** — never clamped, never wrapped, never widened. A `ParamRow` has no validity, so there the key is simply **omitted**, which is already what *never read* encodes.

*This is P-089 restated for the messages that replaced the one it named, and it is not optional bookkeeping: five byte derivations in this document spend it. Widen key 6 from an `i32`'s 5 bytes to a full-width integer's 9 and a documented-legal `count = 96` takes the `History` body from 845 to 1,229 and the frame to 1,263, against a `MAX_PAYLOAD` of 1024 — exactly the frame P-089 exists to stop the controller building and then refusing at a fully configured site. `cbor.rs` and `limits.rs` both cite P-089 by number and are corrected to cite this. Clamping was the tempting alternative and it is the same defect as the sentinel: a number at the rail is a number, and nothing downstream can tell it from a measurement.*

**P-186** — A `vtype = 4 flags` value is a bitmask in the value position. Enum-space member `m` occupies **bit `m − 1`**. Bits 0 to 30 are allocatable; **bit 31 MUST NOT be allocated**, because the value position is an `i32` and a set bit 31 is a negative number. A set bit with no allocated member MUST be surfaced as *unnamed bits set*, naming the bit numbers, and MUST NOT be dropped.

*The document never stated that a flags value is a bitmask, never mapped a member to a bit, and had no rule for an unallocated bit — where the silent default is fail-safe-inverted: a protection a newer firmware added renders as* no protection active. *Member 1 → bit 0 or bit 1 was a coin toss between the capability mask's `Bit 0` precedent and every enum space in this proposal starting at 1.*

**P-187** — Neither `parent` chain — `DeviceRow` key 7 or `ComponentRow` key 3 — may form a cycle, and neither may exceed `MAX_TOPOLOGY_DEPTH`. Both are refused at config write **and** at runtime adoption.

*`rollup` had an acyclicity rule and `parent` had none, while `parent` is what P-183's containment walk and every client's tree reconstruction traverse, on a part with no stack guard. Runtime adoption is not a config write, so the one check P-162 relied on did not cover the path fixture 6 exists to prove.*

**P-188** — `(dev, cmp, kind, shape, vtype, domain, point, dir)` MUST be unique within a `rev` across all `SignalRow`s, and `(dev, cmp, kind, vtype, domain, point, dir)` across all `ParamRow`s. A collision is refused at registration.

*A charger's absorption, float, equalize and maximum-regulation voltages are otherwise four rows all called* DC voltage *on one component, and the installer picks the wrong one to compare against. Nothing anywhere said the tuple was unique, which also means nothing said a client could key a cache on it.*

**P-189** — `DeviceRow.addr` MUST be present when the bus `transport` is an addressed one (`rs485`, `can`, `ip`), and MUST be unique within a `bus`. A receiver MUST refuse an inventory page that breaks either.

*Two devices on one RS-485 pair with no `addr` are indistinguishable to a client — it can see two chargers and cannot say which one is at which end of the wire, which is the first thing somebody walking up to the cabinet needs. Two devices with the* same *`addr` describe a bus that cannot work at all. The controller already refuses the second case at registration —* `Misconfigured::TwoDevicesAtOneAddress` *— so this is not a gap in the implementation but in what a **receiver** may rely on. This was recorded as a note against this document for one full revision, under a paragraph saying in as many words that the fix is a numbered requirement and not a note, because a note is read two ways.*

**P-190** — On any `Inventory 0x8D` outcome other than 1, `next` MUST be 0 and `digest` MUST be absent.

*`next = 0` is the natural encoding of* nothing follows*, which under key 7's original condition made the whole-topology digest mandatory on a response that answered nothing. On outcome 4 `out_of_range` the `rev` matches, so neither P-151 nor P-152 fires and a client can stamp a cache it never assembled.*

**P-191** — A walk MUST terminate. A staged sub-device that stages and un-stages more than three times inside one hour on P-004's tick MUST be **quarantined**: not adopted, `rev` does not move for it, and a `Concern` `bay_flapping` is raised against the enclosing device until it has been stable for the window.

*Losing the race against `MIN_REV_INTERVAL_MS` costs the client its whole walk — P-153 answers `superseded` with an empty array, P-152 forbids partial reuse, and nothing capped consecutive supersessions or raised anything a person could see. A marginal bay contact is the ordinary failure of a connector at an unattended site, and the visible symptom is a client that renders nothing while every individual rule is satisfied.*

**P-192** — `vendor_namespace` (`vns`) is a registry space allocated in `protocol.toml`, one namespace per vendor, with the vendor range and skip-unknown rule of P-019. A `vns` a receiver does not recognise renders the row with the namespace unnamed under P-165; it does not invalidate the row.

*`vns` was REQUIRED on three rows, P-160 rested on it, and it was in neither registry list, excluded by the build step's own count of nineteen spaces, and had no allocation authority. Two drivers both pick 7 and the namespacing evaporates, which is the failure REGISTRY.md's allocation rule exists to prevent.*

**P-193** — Every outcome this document allocates has exactly one trigger, and a responder MUST evaluate them **in ascending order and return the first that applies**. A malformed request is error 1 and is refused before any outcome is computed.

| Response | | Returned when |
|---|---:|---|
| all four | 1 `ok` | the request was answered, in whole or in part |
| all four | 2 `superseded` | `rev` is neither 0 nor the controller's current one (P-153) |
| `Inventory 0x8D` | 3 `unknown_kind` | `what` is not in 1..5 |
| | 4 `out_of_range` | `from` is greater than the largest id the request resolves to — of that kind, and of that `dev` when one was named |
| `Readings 0x8E` | 3 `unknown_selector` | a `Sel` names a `dev`, `cmp` or `sig` that does not exist at this `rev` |
| | 4 `out_of_range` | `from` is greater than the largest `sig` in the resolved selection |
| `Concerns 0x8F` | 3 `out_of_range` | `from` is greater than the largest active `cid` |
| `History 0x90` | 3 `unknown_signal` | `sig` does not exist at this `rev` |
| | 4 `series_not_historable` | the signal exists and its `shape` is 2 `series` |
| | 5 `no_history` | the signal exists, is a scalar, and carries no `hist` key |
| | 6 `out_of_range` | `first` is past `newest`, or `bucket` is finer than the signal's `hist` |

*Not one of these had a trigger. `Readings` outcome 3 was `selection_too_large`, whose only plausible cause is routed to error 1 elsewhere in the same document, and outcome 4 was attached to no condition at all — while a `sig` that does not exist at this `rev` had no answer anywhere, where `History` had `unknown_signal` for exactly that case.*

*The ordering clause is the half that is easy to miss, and it decided the numbering rather than merely describing it. A series signal never carries `hist`, so it satisfies both `series_not_historable` and `no_history` — and under ascending evaluation the lower number wins. Numbered the other way round, `series_not_historable` would be unreachable and `ReadHistory` key 2's own sentence,* MUST NOT be a series signal — outcome 4*, would name a value no controller could ever send: a client would branch on it forever while receiving* no history recorded *for a cell-voltage string that is structurally unchartable. Two conforming controllers answering 4 and 5 to one request is a client branching on a number that means different things depending on who it is talking to. This is the review's own named pattern — a fact the design clearly holds, written as a gloss in a field table instead of as a numbered requirement — and P-193 and P-194 are the last two places it was still true.*

**P-194** — A history bucket index is the number of whole `bucket` periods **elapsed** since this controller's first closed bucket — not a count of buckets closed — so a period in which nothing was recorded still consumes an index. The index is held in FRAM and survives a restart. Across a restart the controller MUST advance it by the whole periods the **wall clock** says passed — which is P-004's own last sentence being taken at its word, *the wall clock timestamps records and decides nothing else*, and a bucket index is a record's timestamp rather than anything on the control path. Where that gap cannot be established — the clock was never set, or was not set when the controller went down, or the RTC reports its backup domain invalid ([LINK.md](LINK.md) L-143) — the controller MUST NOT invent a width: it advances by one, marks the discontinuity, and `History` answers `stopped = 3 gap_in_record` with no claim about how wide the gap was. The buckets on the far side stay servable; a response never spans a gap, so each one carries its own `at` and no client is ever asked to date across a hole. `ReadHistory` key 4 and `History` keys 4, 10, 11 and 12 are all expressed in the units of the `bucket` the request named; the three bucket sizes nest exactly — 4 quarter-hours to an hour, 24 hours to a day — so the conversion is exact and has no rounding rule to get wrong.

*Two readings of one sentence, and both of them break something. As a count of closed buckets, a controller down for three days in January closes nothing: index n+1 sits three days after index n, and a client dating the window from key 15 — its only anchor — draws a seventy-two-hour outage as one quarter-hour and mis-dates every point after it. That is the failure key 7 and P-156's truncation are both written against, arriving one layer above where either can see it. As elapsed periods, the gap is on the axis and P-184 stops the response at it, which is a mechanism that already exists.*

*The clock clause is the part that cannot be waved at. **P-004's tick is monotonic since boot and restarts at zero**, so it cannot measure a gap that spans the boot — which is exactly the gap this requirement exists for. An earlier revision said "elapsed on P-004's tick" and was therefore unimplementable for its own worked example. The wall clock is the only source that can measure it, and P-093 already forbids inventing one, so a controller that does not have it says* there is a gap here *and refuses to say how wide, which is a smaller claim than the one it cannot support and a larger one than silence.*

*The units half is the one that produces two conforming controllers rather than one wrong chart. Keys 4 and 10 are positions in a response and keys 11 and 12 describe a store, and P-193's outcome 6 compares them — `first` is past `newest` — which is not a comparison unless they share a unit. A client asking for the last 96 days sends `first = newest − 95`; against a controller holding its axis in quarter-hours that is 24 hours, and it is either answered or refused with both sides conforming to every word written. Keeping the counter at the signal's finest `hist` and dividing down costs a division per request.*

**P-195** — When the requested `bucket` is coarser than the signal's `hist`, the coarse bucket is aggregated from its constituents by a rule fixed by `(vtype, domain)` and by nothing else:

| The signal is | Aggregated as |
|---|---|
| `vtype 2 counter`, any domain | the **last** constituent's value — a counter is a running total, not a rate, so summing four quarter-hours of *energy today* reports four days of it |
| `vtype 1 gauge`, `domain 8 max` | the **maximum** |
| `vtype 1 gauge`, `domain 9 min` | the **minimum** |
| `vtype 1 gauge`, `domain 6`/`7 limit` | the **last** — a limit is a state, not a quantity to average |
| `vtype 1 gauge`, every other domain | the **mean**, weighted by each constituent's key 7 sample count |
| `vtype 3 enum` or `4 flags` | **not aggregatable.** A signal of either MUST NOT carry `hist`; `ReadHistory` answers outcome 5 |

**The `q` byte aggregates too, and it is the one that sizes every other array.** A coarse bucket is `validity 1 ok` when **any** constituent is; otherwise it takes the validity of its earliest constituent, so the reason a window is empty survives instead of being averaged away. Its provenance is `3 derived` whenever more than one constituent went into it, because at that point the number is ours. Key 7 aggregates by sum — which is also what discloses that a coarse bucket rests on three readings of an expected ninety-two — key 8's bit is set when **any** constituent had a reset, and key 9 is `2 controller_derived` for **every** aggregated bucket, not only where the constituents disagree: the controller did the arithmetic, whatever the device supplied underneath, and key 9 exists to keep Victron's own day record distinguishable from what we integrated.

*`hist` says a coarser request is "aggregated from this" and said nothing about how, which is a whole chart's meaning left to whoever implemented it first. Mean and last differ by the entire value of a lifetime counter: aggregating four quarter-hours of* energy since reset *by mean reports a quarter of the total, and by sum reports four times a day's worth. Both render, neither warns, and the one that reads low is the one that makes a site look like it is producing less than it is. Weighting the mean by key 7 is the same rule key 7 exists for one layer down — an unweighted mean over a window where one constituent had three readings and another ninety-two is the smooth-line lie with extra steps. And enums are excluded rather than given a rule because there is no honest answer: the mean of two charge stages is not a charge stage, and* the last one in the window *is a fact about the sampling, not about the site.*


## What this replaces

### Messages

| | |
|---|---|
| `Snapshot 0x02` / `0x82` | **Retired.** Both numbers held forever, never reused. There are 83 free request opcodes, so scarcity is not a reason to reuse them; a bench build still sending the old body should meet error 2 rather than a body it misparses into readings that look fine |
| `0x0D` / `0x8D` | **New** — ReadInventory / Inventory |
| `0x0E` / `0x8E` | **New** — ReadSignals / Readings |
| `0x0F` / `0x8F` | **New** — ReadConcerns / Concerns |
| `0x10` / `0x90` | **New** — ReadHistory / History |
| `Subscribe 0x03` / `0x83` | **Unchanged.** It stays the event stream. There is no reading push |
| `Command 0x08` | Operation body gains keys 3 `dev`, 4 `cmp`, 5 `rev`; `args` moves from key 3 to key 6. `cmd_id` stays `u32` and `kind` stays key 2 |
| `Firmware 0x09` | Its target vocabulary becomes a `dev` from this inventory. That is entry 6's second device-id space deleted by construction; entry 6 still owns the bodies and the manifest |
| `Hello 0x81` | Key 13 retired; keys 18–29 added |

All four new request numbers are at or below `0x17`, so the request `type` stays one CBOR byte.

### Structures and enums

| | |
|---|---|
| `Value` | **Retired** in full — `channel`, `kind`, `value`, `quality`, `at` |
| `quality` (5 values) | **Retired.** The registry row keeps the reason: *it ran together whether a reading is trustworthy with where it came from, so a counted value could not also say it went stale* |
| `Hello 0x81` key 13 `max_channels` | **Retired** under P-012. The number is not reused |

### Limits

| | |
|---|---|
| `MAX_CHANNELS` | **Retired.** It was two things wearing one hat: the site's semantic capacity and a response cap. It is now `MAX_SIGNALS` (384, RAM) and `MAX_READINGS_BYTES` (880, wire) |
| `MAX_CHANNELS_CEILING`, `MAX_SNAPSHOT_BODY`, `VALUE_MAX_BYTES`, `SNAPSHOT_BODY_BYTES`, `SNAPSHOT_VALUES_HEADER_BYTES`, `SNAPSHOT_FIXED_BYTES` | **Retired** with the message they derive. Done, with P-089 — which left `MAX_CHANNELS` the one cap in `limits.rs` with no ceiling over it |
| `ENVELOPE_BYTES` / `WRAPPER_BYTES` | **Corrected.** They double-counted the body map header and omitted the second byte a `0x8x` response type costs; the two errors cancelled exactly. Split into `ENVELOPE_BYTES` 11, `WRAPPER_CONTENTS_BYTES` 22, `RESPONSE_TYPE_EXTRA_BYTE` 1. Every existing derivation keeps its answer, and `MAX_OPERATION_CEILING` is untouched |
| `MAX_EVENT_QUEUE` | **Unchanged at 16, and now load-bearing.** P-182 derives what one tick can produce against it, which nothing did before |

### Registry allocations

**Retired metric kinds**, each because it was a place smuggled into a quantity:

| | |
|---|---|
| `0x0130` start battery voltage | It is `0x0101` on a component whose `role` is `start-battery`. That row could only ever describe one second bank, and this is the fixture that proves the model **removes** registry rows |
| `0x0110` / `0x0111` / `0x0112` PV array V/I/P | The same three DC kinds at a `pv-array` or `mppt-tracker` component |
| `0x0120` / `0x0121` load current/power | The same kinds at a `load-output` component |
| `0x0105` battery temperature, `0x0301` ambient temperature | One `temperature` kind; *where* is the component |

**Renamed, not retired** — a widening, so every existing reading of them stays valid: `0x0101` battery voltage → **DC voltage**; `0x0102` → **DC current, signed, positive into the component**; `0x0103` → **DC power, signed**; `0x0302` probe temperature → **temperature**.

**Split:** `0x0205` AC energy becomes `ac energy imported` and `ac energy exported`, both counters, both at scale 1 so an `i32` spans 21.4 GWh. A counter cannot be signed — a monotonic total that reverses is a lie — and instantaneous AC power stays one signed kind with `dir` stating the convention. That is what fixture 5's *signed import/export power* actually needs.

**New metric kinds for stage durations:** `time in bulk`, `time in absorption`, `time in float`, counters at scale 0 in minutes. They were previously to be carried as one kind with a `point` naming the stage, which is a place smuggled into a quantity — the thing four rows above this one are retired for.

**Retired event kinds:** `0x0101 value changed` (class B). It was the only class B kind; its rate followed a sampling loop rather than anything happening at the site, and at nineteen circuits it overruns `MAX_EVENT_QUEUE` every tick. The number is held. Class B stays defined with no members.

**Redefined event kinds** (all currently *reserved*, so nothing has exchanged them): `0x0102` → **signal validity changed**, class A, coalesced array body. `0x0501 alarm raised` → **concern raised**, class A. `0x0502 alarm cleared` → **concern changed**, class A. **New:** `0x0901 topology changed` (A), `0x0902 device presence changed` (A, coalesced array body). Those five bodies are specified here, which discharges five of entry 10's rows.

**Retired command kind:** `0x0202 clear alarm`. The number is held and not reused; acknowledging is **new** `0x0203 acknowledge concern`, args `{1: cid u16}`, listed in `DeviceRow(dev 0).cmds`. Reusing `0x0202` for acknowledgement would put the two meanings on one number in the one place this design defines itself against them being the same word.

**New command outcomes:** 7 `stale_topology`, 8 `wrong_target`. Both are written into [PROTOCOL.md](../PROTOCOL.md) beside `Command 0x08`, with P-166's refusal rule, because `every_live_number_is_reachable` sweeps the settled documents and a number reachable only from a proposal is what it refuses.

**New SetConfig outcome:** 9 `staged`, for P-154's config-write case. Entry 9 owns the number.

**Retired config sections:** `0x0002 channels` and `0x0003 buses and devices`. Splitting a signal's owner from the signal is how the two disagree. **New:** `0x0004 topology`, one section, and it is what `rev` versions. Entry 9 still owns its body.

**New registry spaces**, all declared in `protocol.toml` and generated:

*Open, vendor range `0xF000`–`0xFFFF`, skip-unknown under P-019:* `component_role`, `device_role`, `product`, `dialect`, `condition`, `enum_space`, `measurement_point`, `vendor_namespace`.

*Closed, no vendor range, P-165 on every path:* `transport`, `shape`, `vtype`, `domain`, `direction`, `validity`, `provenance`, `severity`, `concern_state`, `presence`, `unit`, `bucket`, `history_source`, `history_stop_reason`, `topology_change_reason`, `inventory_kind`, plus one outcome space per new response.

`presence` is on that list **and** is reachable through `esp`, and both are true at once: it is the value of an ordinary signal at `(dev, cmp 0)`, and it is also the discriminant in `0x0902` key 2, where there is no `SignalRow` in reach to name a space. An earlier revision said it was *reachable through `esp`, not a discriminant field* and then used it as one, which left `0x0902` key 2 with no registry behind it for a decoder to resolve against. `control_owner` is only ever a signal value, so it is only ever reached through `esp`.

**Twenty-nine spaces**, not the nineteen an earlier build step counted, and the count is broken out because the two ways of undercounting it are both easy:

```text
 8  open registries      component_role device_role product dialect condition
                         enum_space measurement_point vendor_namespace
16  closed discriminants transport shape vtype domain direction validity
                         provenance severity concern_state presence unit
                         bucket history_source history_stop_reason
                         topology_change_reason inventory_kind
 4  response outcomes    one space each for Inventory Readings Concerns History
 1  reached only via esp control_owner
──
29
```

The nineteen missed `measurement_point` and `vendor_namespace` from the lists entirely, and counted neither the outcome spaces nor the two `esp` targets — while `topology_change_reason` and `history_stop_reason` were discriminants on the wire with no space behind them at all. A space that exists only as a column of names in a design document is a space two drivers allocate differently.

`unit` is new because the registry carries units today as display strings on metric rows, and a vendor kind needs a number. `topology_change_reason` has **no** *capability changed* value, and P-177 says why.

**Error codes:** none added. An unallocated `what` is outcome 3 in the response; an over-long selection, a `q` whose length disagrees with `n`, an empty `cmds` array and a `History` length disagreement are all error 1. Error 15 stays withdrawn — it refused an over-cap `Snapshot`, and there is no longer a `Snapshot` to build.

### Generated artefacts

`vectors/v1.json` is regenerated wholesale, the Rust and TypeScript bindings with it, and `snapshot.rs` is deleted rather than adapted. Anybody holding a bench build against the current draft regenerates. That is only defensible because no client exists, which is true today and stops being true at the first independent one.

## DEFERRED entry 13 — rows this closes

- **Attached-device inventory** — `ReadInventory`/`Inventory` with `BusRow` and `DeviceRow`: product, dialect, model role, serial, hardware and firmware revisions, bus address under P-189, `parent` for a sub-device, `presence` as a signal, and `since` for replacement. Bounded pages, stable ids, one `rev`, reported caps. Identity across replacement is *visible* here (P-156) and still *owned* by entry 1.
- **Repeated components** — `ComponentRow` with `parent`, `role`, `index`, `label` and `rollup`. A client with no site-specific code reconstructs the tree from `parent`, the instance number from `index`, the human name from `label` or from `role` + `index`, and the aggregate relationship from `rollup`. There is no `pv-power-2` anywhere, and P-161 forbids one.
- **Signal description** — `SignalRow` carries the owning device and component, quantity, `shape` and `vtype` on two axes, `domain`, `point`, `dir`, `n`/`erole`/`ebase` for series, `esp` for enum and flags spaces, and `hist` for what is chartable. P-160 keeps unit and scale in the registry for standard kinds and requires them on the row for vendor kinds, so a standard quantity cannot be redefined by a descriptor and a vendor quantity can still render.
- **Capacity and delivery** — `MAX_CHANNELS` retired. Inventory pages and selected reads, both bounded by two arms with derived ceilings and stated margins, and both costed against the six fixtures rather than asserted. 32 is gone as a whole-site cap; 880 bytes is the response cap and 384 signals is the site's semantic cap, and the two are different numbers because they were always two different things.
- **Value shape and validity** — `shape` names the container and `vtype` names what one value is, which is what lets fixture 3's per-cell balancing bitmap exist at all: a series of flags was not expressible while one `u8` carried both axes, and the closure list claimed it closed as *balancing as a flags series*. Validity (8 values) is separated from provenance (6), so `counted` **and** `stale` is `0x22`. Large lifetime counters are closed by the registry rather than the wire, the same way P-089 closed it: `ac energy imported`/`exported` at scale 1 gives an `i32` 21.4 GWh, which a 5 kW circuit reaches in 490 years. Text stays in descriptors and never on a reading.
- **Active concerns** — `ReadConcerns`/`Concerns` with a stable `cid`, `dev`/`cmp`/`sig`/`elem` source down to one cell, `sev`, a five-state lifecycle ending in a terminal `cleared`, a monotonic `age` that survives a restart, an optional wall-clock `since`, a normalized `cond`, and the vendor code preserved in `raw` with its namespace. Acknowledgement is separated from clearing by P-168 and removal is stated by P-180. Transitions stay entry 10's, and `0x0501`/`0x0502` now have bodies.
- **Operating state and control ownership** — `vtype = 3 enum` plus `esp` names the state domain in a field, which retires P-125. `control owner` is an allocated enum space — local panel, this controller, BMS, GX/ESS, remote client, device automation — carried as an ordinary signal with `prov = reported`, so *the BMS is driving the charge voltage and we are not* is a reading rather than an inference. P-164 gives the enum-shaped vendor fallback a home that cannot be mistaken for a normalized state and P-176 kills the numeric one before it becomes a reading at all.
- **Electrical topology and flow** — roles for `ac-input`, `ac-output`, `phase`, `line-pair`, `pv-array`, `mppt-tracker`, `dc-output`; `point` for the measurement point, now an open space so a function nobody has allocated is labelled rather than unrenderable; `dir` for the sign convention; signed instantaneous power with the convention stated on the row; two counters for import and export because a counter cannot be signed. Which AC input is live is a per-component enum, not a global index.
- **Battery/BMS safety surface** — `battery-bank`, `battery-pack`, `heater`, `contactor`, `fet` roles; cells and probes as series elements under P-163, which is the rule that puts thirty-two cells in two series signals and nineteen circuits in nineteen component rows rather than the reverse; balancing as a `shape 2` / `vtype 4` series of flags under P-186; CVL/CCL/DCL as `domain = limit_upper`/`limit_lower` with `prov = 5 reported`, so a behaviour reads the BMS's stated limit and never infers one; active protections as concerns addressed to `elem` under P-178's stated origin. Command authority never substitutes for observing the limit, because the limit is a signal and the command is a different message.
- **Device parameters and capabilities** — `ParamRow` with the current value, the device's permitted floor and ceiling, the `domain`/`point`/`dir` that tell four *DC voltage* rows apart, and `via` naming the one Command kind that writes it. Read-only on the wire (P-167), bounded by `MAX_PARAMS`, reported in `Hello` key 25, and entirely distinct from `GetConfig`. A client renders *40 A of 200* with no site-specific code.
- **Firmware targets** — `Firmware 0x09` targets a `dev` from this inventory. The second device-id space entry 6 was waiting on is deleted by construction; entry 6 keeps its bodies and its signing manifest.
- **Communication health** — `presence` is a signal at `(dev, cmp 0)` (online / degraded / offline / never_seen), reachable by a `Sel` because of P-174; `last_seen_age` is a counter, and bus CRC errors and timeouts are counters on the controller's own device row. All three are separate from a signal's `validity`. A healthy device behind a broken bus reads `presence = online` with `bus_timeouts` climbing and its signals `stale` with an age — three different sentences the old `quality` had one word for.
- **Evolution and limits** — `rev` plus `topo_digest` version the whole descriptor set, with P-173 giving the digest a preimage and P-151 giving it a defined consequent and a trigger that fires. Every new collection has a named bound, a documented behaviour when full, and a `Hello` key. P-019 extends the vendor range to eight open spaces; P-165 gives the closed ones a rule that reaches every field, every value position and every event body without blanking a page.

## DEFERRED entry 13 — rows deliberately left open

- **History and counters — half closed, and the half that is open is not this entry's.** `ReadHistory`/`History` closes the client-facing shape: bucket size, bucket identity as elapsed periods on a monotonic FRAM axis in the requested bucket's units (P-194) rather than the vendor's wrapping `un16` — a client treating that as monotonic mis-orders a year boundary, and a controller counting *closed* buckets instead of elapsed ones collapses a three-day outage to nothing — an authoritative response length with a cursor and both store bounds, sample count per bucket so a mean over 3 of 92 cannot render as a mean over 92, `reset` for counter wrap with its bit order written out, `dir` on the signal for direction, per-bucket `src` separating a device-supplied day record from one we integrated, and `stopped` naming why a response is short. What stays open is **DEFERRED entry 3's packed NOR record** — its field list and its partial-window rule. Nothing here forces entry 3's hand: the wire carries no positional record and a controller may serve `ReadHistory` from any store. `MAX_HISTORY_SIGNALS` is 24 and entry 3's ring is sketched at 20 channels, and those are two different numbers for two different things — what a client may chart against what the NOR record holds. They are not required to agree, but if entry 3 lands at 20 then four of the 24 are served from somewhere else or not at all, and that is entry 3's call to make rather than this one's to pre-empt. Two documents must not disagree about one record, so this one deliberately does not describe it.
- **Targeted control lifecycle — the common target is closed, the rest is not.** `Command` names `dev`, `cmp` and `rev`; `cmds` enumerates what a device and a component accept, with absence meaning *nothing*; outcomes 7 and 8 are the machine-readable refusals; desired against observed needs no new machinery because a `prov = 6 commanded` signal sits beside a `prov = 1 measured` one, which is how a welded relay reads *observed closed* against *commanded open*. **Left open:** the per-kind argument schemas (entry 8 owns them and is not touched), and lease/deadman, progress and cancellation. A lease is not a wire field on its own — it needs a renewal path and a revert rule, and a revert rule is a decision about what a controller does to an output when nobody is talking to it. That belongs with the first granted output, not here.
- **Config section bodies — entry 9, unchanged in scope and owed two numbers.** `0x0002 channels` and `0x0003 buses and devices` are retired and `0x0004 topology` replaces them, so the thing those sections configure finally has a wire shape to be configured against. The section body itself is still entry 9's, along with the `secret` rule, the `shadow` key number, and now `SetConfigAck` outcome 9 `staged`, which P-154 requires and this document does not allocate.
- **Event bodies — entry 10, mostly unchanged.** Five bodies are specified here because this entry owns their content: `0x0102`, `0x0501`, `0x0502`, `0x0901`, `0x0902`. Entry 10 keeps the other sixteen of its twenty and had to be edited in the same commit, because it says `alarm raised` needs a discriminator and this design answers that by retiring the kind that needed one.

  ***That edit did not happen, and "answers that" was too strong.*** Entry 10 now records what was actually left open. Renaming `0x0501` did not retire its four producers — P-079, P-085, P-115 and P-116 went on saying `alarm raised (0x0501)` in `PROTOCOL.md` for every commit in between — and giving the kind a `Concern` body settles the discriminator only as far as the condition registry reaches, which is not as far as *a durable write did not stick*, *the clock stepped* or *the floor was overridden at the panel*. P-115 and P-116 looked as though they additionally needed a magnitude, and `raw` travels only with a `vns` that names a third party. **They do not:** both raise their concern alongside the `time set` record P-111 requires, and that record already owes the old value and the new one, so the step is written once and the concern names only the condition. The controller-namespace trigger has not fired. Four condition values are allocated — `counter write failed`, `epoch write failed`, `clock stepped`, `floor overridden` — and `PROTOCOL.md` names them in the four requirements themselves.
- **Channel identity across reassignment — entry 1, not settled.** P-156 makes the seam visible at both the device and the component level and refuses to plot history across either. It does not answer entry 1's actual question, which is what identity costs in the durable aggregate record — and that cost is entry 3's byte budget, which this design deliberately does not spend. The interim advice stands and now reads as *do not reuse a component id; allocate a new one*, with the reserved runtime block sized so a hot-swapping site does not run out.
- **Security and conformance — entries 2, 4, 5, 7 and 11, untouched.** Confidentiality, rate limiting, the later Noise handshake, BLE and MQTT evidence, and spec-level checks remain exactly where they were. A complete data model still sits on all five, and this entry neither duplicates nor hides them. `req_id` admission, once entry 12, is settled in P-022 and binds the four new request types like every other: a request the window refuses is not answered and does not refresh the session under P-077.

## What the review changed

Sixty findings were raised on four lenses — a reading that is wrong and looks
right, two implementers working from the document alone, fidelity to the vendor
PDFs, and the bounds arithmetic recomputed against `cbor.rs`. Each was handed to
a separate reader whose job was to refute it. **Fifty-two survived**, sixteen of
them blocking. The verdict was *build with changes*.

**The shape survived and is not reopened.** Two planes joined by one `rev`;
`rollup` separating containment from accounting; `esp` naming the enum space in a
field; every instance number living on a component's `role` + `index`;
per-element validity; presence as a hot signal against membership as a cold
descriptor; refuse-not-evict with the refused count on the page; the
`(rev, digest)` pair in `Hello`. Every attack that reached those came back
refuted. Do not re-run the four-design comparison.

**What did not survive was the document**, and this revision is the answer. Each
blocker below leaves the list by naming where it is answered above, which is the
only form of *closed* this repo accepts.

| # | The blocker | Answered by |
|---|---|---|
| 1 | A loose terminal takes the radio off the air: `0x0102` is per-signal, class A, and class B is empty | P-182, coalesced `0x0102`/`0x0902` bodies, [the class A burst](#the-class-a-burst-one-tick-can-produce), P-003/096/097/098 amended, and build step 8's 384-in-one-tick test |
| 2 | The concern lifecycle has no state meaning *over*, and P-168 names a state the enum does not have | `state 5 cleared`, the five-row state table, P-168 corrected, P-180, and build step 7's clear-thirty-two test |
| 3 | Nothing kills a vendor's numeric absence sentinel | P-176, P-177, the validity 4/5/6 split, and build step 5's test that starts *before* a validity is chosen |
| 4 | `cmp = 0` is spent and never reserved; `0x0203` is unsendable | P-174, P-175, `DeviceRow.cmds`, `SignalRow.dev` |
| 5 | `elem` and `ebase` are two numberings with no sentence between them | P-178, `elem` recosted at 2 bytes, fixture 3 pinned to `ebase = 17` in build step 11 |
| 6 | One `age` for sixteen independently-valid elements | P-179 |
| 7 | Event bodies and `LogEntry` carry ids under no `rev` | P-152 extended, `rev` as key 1 on five bodies, the polled-versus-pushed sentence |
| 8 | `History` cannot say how many buckets came back | P-184, keys 5 and 10–14, outcome 4 for a series signal, and P-194/P-195 for what a bucket index and a bucket value mean |
| 9 | `n` and `reset` are optional with no condition, and `reset` states no bit order | P-184 |
| 10 | P-165 lists fields only; P-125's content is deleted; flags is unspecified | P-165 restated by category, P-186 |
| 11 | `topo_digest` has no preimage and its trigger is the bug it catches | P-173, P-151's trigger, the RAM section's label correction |
| 12 | Every page count divides the row cap away; no rule makes a walk terminate | P-171's division clause, the recomputed page table, `MAX_INVENTORY_PAGE_ROWS` 16 → 48, P-191 |
| 13 | `ReadSignals` resumes at an ordinal into an undefined order, and two outcomes have no trigger | P-183, `from`/`next` as `sig` ids, P-193's trigger table and its evaluation order |
| 14 | `shape` cannot be both series and flags, so fixture 3's bitmap has no encoding | the `shape`/`vtype` split, P-186 |
| 15 | Constants with no value, with no key, in two tables, and a check that cannot compile | `MAX_BUSES` 8, `MAX_CONCERNS_BELOW_FAULT` 24, `Hello` keys 20/24, byte caps unreported, the `#[test]` replacing the `const_assert!`, the fixture table, 43 constants |
| 16 | Four places this document and the settled ones disagree | `cmd_id` u32, P-185, P-192, `topology_change_reason` allocated |

Two of those changed a number rather than a sentence, and both are worth naming:
**`MAX_SIGNALS` moved from 320 to 384** because the fixture table said 276 does
not fit 256 writable, and **`MAX_INVENTORY_PAGE_ROWS` moved from 16 to 48**
because at 16 a typical row wasted two-thirds of a page and the walk was three
times the length `MIN_REV_INTERVAL_MS` had been justified against. Neither was
visible until the arithmetic was printed.

**Checked and refuted**, so they are not re-litigated: `MIN_REV_INTERVAL_MS`
derived against a worst-case walk driven by presence (forbidden by P-155 — the
walk arithmetic was wrong for the different reason blocker 12 names); `rev` in
the signed operation body making a legitimate retry undeliverable; P-019 and
P-165 giving opposite answers for a non-vendor unknown `role` or `cond`;
`rev = 0` as a wildcard; `MAX_HISTORY_SIGNALS = 24` against fixture 1; the
inner-body encode buffer frozen at today's cap; the open registries' flash cost;
`Series` key 3's ordering being pinned positionally by key 2; cross-implementation
paging divergence in `Readings` being harmless because every row carries its own
`sig`; `MAX_SAMPLES` and `MAX_SERIES` being correctly fixed rather than reported;
the `Command` key reassignment being legitimate because `Command` is reserved and
nothing has exchanged the body.

**What this revision does not claim.** The per-page BLE round trip that
`MIN_REV_INTERVAL_MS` is justified against is a projection, not a measurement, and
it is the first thing to check the first time a browser talks to real hardware.
The flash estimate is likewise an estimate; `cargo size` is the check and it is
in the build order twice. The fixture cardinalities are counted from
DEFERRED's prose and the committed catalogue rather than from six built
fixtures — step 11 is where they stop being arithmetic. And one code change is
named here rather than made: `Reading::Unreadable` in `map.rs` carries two
findings under one word, and step 5 splits it.

**On method.** Three passes were run against this document by fanning work out
across parallel authors, and two of them failed the same way: 137 edits that
could not be applied in any order because seven of them claimed one paragraph,
then eighteen problems of which eight were regions nobody had been assigned. The
design was never what failed — no round asked for a different shape. This
revision was written by one editor holding the whole document front to back, and
that is the finding worth keeping: a specification is a single artefact with
cross-references in every direction, and parallel authorship on one puts the
defects exactly where nobody is looking, which is the seams.

## Build order

Twelve commits, smallest first. Every one lands with tests, and the ones that produce a committed artefact land with the artefact and an empty diff on everything else.

> **This section had gone stale, and in the direction that costs the most.** It was audited against the tree after two of its claims turned out to be false — the *nine* metric-kind retirements were eight, and step 6c was written believing `Readings 0x8E` had no vector when `v1.json` has carried one, with three tests against it, all along. Both were asserted from this document rather than checked against the artefact. So the rest was checked, and three more steps were finished without their status being written down:
>
> - **Step 3's code is landed and its spec half was not, which this note got wrong twice.** `inventory.rs` has the table-driven encoder and the two-arm page cap, with tests naming each arm binding first, and `v1.json` carries `inventory_0x8D`. What this note then claimed — that the promotion *happened* and **the wall was routed around and then removed** — was false in both halves. Only the two wrapper bodies were promoted; the five row bodies were not, so 61 published row keys sat in `v1.json` with nothing in any settled document defining them. And the wall was never in the way: `bodies_match_the_spec` reads each vector entry's `body_readable`, the row blobs carry `row_cbor`/`row_len` instead, so it never looked at a row and could not have blocked one. A check that cannot fail is not a wall somebody climbed. The rows are promoted now, as P-200 through P-207, and `published_rows_match_the_spec` is the check that can see them — it reads the key numbers out of the published CBOR, with somebody else's decoder, because `vectors.rs` wrote those bytes and a check that decodes them with the encoder under test agrees with itself no matter what either says. It was watched going red three ways: a key renumbered in the document only, a required key marked optional, and a row body deleted. `bodies_match_the_spec` stayed green through all three, which is what it had been doing all along.
> - **Step 4 is landed.** `Hello 0x81` keys 18 through 29 are allocated and read, and key 19 is the topology digest.
> - **Step 5's `map.rs` split is landed.** `SensorFault` and `OutOfRange` are separate variants carrying separate validities, rather than the one `write_absent` the note describes.
>
> **This note first claimed that four rules — P-151, P-173, P-183 and P-188 — live only here and are invisible to the coverage gate. Three of the four were wrong,** and the way they were wrong is worth more than the claim was. They were checked by grepping `PROTOCOL.md` for `**P-151**` and finding nothing. But the two documents number independently, the promotion **renumbers**, and the mapping table two hundred lines above this one says so in full: P-173 is there as **P-148**, P-151 as **P-149**, P-183 as **P-198**. All three are promoted, implemented, and covered by tests named after their *promoted* numbers — `p_148_`, `p_149_` in `inventory.rs`. The gate has been watching them the whole time.
>
> *The lesson is the one this session kept paying for:* **search a document by what a rule says, not by what it is numbered.** A label is the one part of a requirement guaranteed not to survive being moved.
>
> **What survived was one instance, it was real, and it has now been promoted.** `P-188` — `(dev, cmp, kind, shape, vtype, domain, point, dir)` unique within a `rev` — was in neither the mapping table nor `PROTOCOL.md` under any number or any wording. It is **P-207** there now, and `Signal::same_identity` is cited by six tests named after it.
>
> **The promotion found more than it went looking for, and the pattern is worth more than any of it.** Promoting one rule was supposed to be a rename. It was not, because the rule named eight fields on two row types the settled document had never defined — so the row bodies had to go first, and with them seven more rules. Then `Signal::same_identity` turned out to be comparing seven fields of which **three — `vtype`, `domain` and `dir` — nothing was watching**: each could be replaced with `true` and all 453 tests stayed green. That is the same finding as the `shape`-versus-length leg one commit earlier, three more times in one function, and it says the method needs a test per leg rather than a test per story. The general shape: *a rule the gate cannot see accumulates unguarded implementation behind it,* because nothing is asking.
>
> *Genuinely not started:* steps **8** (class B; `0x0101 value changed` is still `reserved`, so nothing has exchanged it) and **9** (config sections; `0x0002` and `0x0003` are still `reserved` and `0x0004 topology` is not allocated). **Step 7 was on this list and no longer is** — it had no module, no spec section and no vector when that was written; it now has the table, the lifecycle, the pin, the page and the section, and what is left of it is the codec and the vector. The sub-steps below carry the detail.

**1. Correct the framing constants and add every new bound to `limits.rs`.** No wire change at all. Split `ENVELOPE_BYTES` / `WRAPPER_BYTES` into `ENVELOPE_BYTES` 11, `WRAPPER_CONTENTS_BYTES` 22, `RESPONSE_TYPE_EXTRA_BYTE` 1, and prove the existing derivations keep their answers. Add the **forty-three** constants of the Bounds section with their ceilings and an assertion each, including `CLASS_A_TICK_CEILING` against `MAX_EVENT_QUEUE`.
*Watch it fail:* raise `MAX_READINGS_BYTES` to 949 and see the assert go red; raise `MAX_SAMPLES` to 48 and see the other one; raise `MAX_VALIDITY_SWEEP` to 87 and see the event body exceed `MAX_EVENT_BODY`; set `MAX_CONCERN_EVENTS_PER_TICK` to 14 and see `CLASS_A_TICK_CEILING` cross `MAX_EVENT_QUEUE`. Then put them back. A ceiling nobody has watched go red is an assertion about the author's intent.

**2a. Give the registry somewhere to put an open `u16` space.** This is a prerequisite nobody costed, and step 2 cannot be written without it. The registry has exactly three shapes: `enums.*` is `u8` and closed, `codes.*` is `u16` and closed, and `metrics`/`events` are `u16` and open. **Open is not a property a space can declare** — `is_open` is called twice in `bindings.rs`, with the literal strings `"metric_kind"` and `"event_kind"`, and nothing else in the tree reads `meta.skip_unknown` at all. So the eight open registries this design allocates have no home: put them in `enums.*` and they are `u8` when they need `u16`; put them in `codes.*` and the generated binding is a **closed** enum for a space whose whole point is that a vendor value must skip rather than fail, which is P-019 inverted in the generated code.

Adding their names to `skip_unknown` would be worse than useless — it is a list checked against nothing, so the eight names would sit there being inert while the bindings stayed closed, and the file would read as though the job were done.
*The fix, and it is small:* let a space declare `open = true` on itself rather than be named in a list somewhere else, generalise `open_newtype` from two hardcoded calls to a loop over the open spaces, and make an open space refuse a `u8` width. A space that is open in one file and closed in another is the same defect class as a bound under two spellings, and the list form cannot go red when a name is misspelled.
*Watch it fail:* mark one space open, regenerate, and confirm its binding is a newtype rather than an enum; then misspell it and confirm the build refuses rather than silently emitting a closed enum.

**2b. Allocate the registry spaces in `protocol.toml` and regenerate.** **Twenty-nine** new spaces, the retirements, the renames, the metric split, the three stage-duration kinds. `vendor_namespace` and `topology_change_reason` are in this commit or P-192 and P-165 have nothing behind them. **Every new allocation lands with `status = "reserved"`, not `live`** — the rules that produce them are in this document, which `every_live_number_is_reachable` does not read, and `reserved` is what that sweep skips. The new spaces implement nothing yet, and the **renames are a widening** — a metric's generated constant is screaming-cased from its `name`, so `battery voltage` → `DC voltage` renames `MetricKind::BATTERY_VOLTAGE` at every call site, but the number and the meaning are untouched.

**The retirements are a different thing, and none of them lands here.** A retirement can only go in the commit that dismantles what depends on it, and three separate attempts to land them in this step were reverted by the tree:

- **The eight metric kinds cannot be retired until a behaviour selects on a component.** `0x0110 PV array voltage`, `0x0130 start battery voltage` and `0x0101 battery voltage` are published at the same unit and the same scale, so under this design what tells them apart is the *component* — and until then, **the kind is the only guard there is**. Collapsing them into `DC voltage` makes a generator start on the solar array's voltage at noon, and `the_solar_array_at_noon_is_not_the_bank_and_does_not_start_an_engine` goes red saying so. That step is **5b** below — and 5b has landed without unblocking them, which is worth writing down rather than discovering twice.

  *Why not.* 5b moved the **selection** into the seam: a season names a `Binding`, resolves it, and reads the `sig` it got. But the **guard** is still a kind check inside the behaviour — `Autostart::band` calls `number(stored, MetricKind::DC_VOLTAGE, …)` and refuses anything else, which is what `the_solar_array_at_noon_is_not_the_bank_and_does_not_start_an_engine` actually exercises. A behaviour is handed a bare `km43::Reading` carrying no evidence of which binding produced it, so the kind is the only thing it can check. Collapse the three and that check evaporates.

  *What unblocks it, now built and now plumbed:* `Observed` — a reading that **cannot be built except by reading through a `Watch`** — the seam's answer carrying the binding that produced it, so `band` trusts its provenance instead of re-deriving it from the kind. `Store::observe` is the only constructor outside a test, both seasons read through it, and `Autostart::band` and `Inputs` now take an `Observed` rather than a bare `Reading`. **The kind check inside `band` is redundant rather than load-bearing**, which was the whole precondition — it goes in the same commit as the kinds, and nothing else is holding them. Three things were settled getting here, and the first two did not go the way this document said they would:

  *How `band`'s own tests build one — the question dissolved rather than being answered, and this document had it wrong.* The prescription here was a `fixtures` feature the firmware never enables and the simulator does, on the reasoning that `o89-sim`'s band witness must build an `Observed` **without** asking the store and `o89-core` compiled as a dependency is not in test mode. The reasoning about test mode was right and the premise about the witness was wrong: a band is a number against two thresholds, so the witness never needed a reading at all and therefore never needed to build one. `Observed::built` is `#[cfg(test)]` and `pub(crate)`, **there is no `fixtures` feature**, and `Store::observe` is the only constructor in any build the firmware can produce. That is a stronger guarantee than a feature flag staying off — it is not a thing `cargo tree` has to be asked about — and it deleted a feature rather than adding one. The general lesson is worth more than the specific fix: a witness that needs the same fixtures as the thing it witnesses is usually witnessing at the wrong level.

  *And it is `Inputs`, not just `band` — done.* `Inputs` carries the four readings, so it carries `Observed`, and `Inputs::number` reads the binding's kind too. The thirty-odd fixtures across `machine.rs` and `reading.rs` went through **one `seen(kind, reading)` helper written once**, which is what kept it a mechanical change; the alternative was a substitution run across multi-line call sites, and this repo has already paid for that lesson three times.

  *What is actually lost.* Today `band` refuses a foreign reading **at runtime**: hand it the array's voltage and it answers `None`, which is what `the_solar_array_at_noon_is_not_the_bank_and_does_not_start_an_engine` asserts. Afterwards a wrong binding is refused **at resolution**, at commissioning, by `Signals::resolve`. That is a better guard — a component tells an array from a bank and a kind soon will not — but it is a *different* one, and the defence-in-depth of having both goes away. The test asserting the runtime refusal has to become a test asserting the resolution refusal, and somebody should say out loud that a behaviour handed the wrong signal by a correct-looking config now has nothing left to catch it.
- **`Snapshot 0x02`/`0x82` cannot be retired until `snapshot.rs` is deleted**, which is step 6. Retiring the message removes `MessageType::Snapshot`, and the file that implements it is still in the tree.
- **Event `0x0101 value changed` cannot be retired until class B is dealt with**, which is step 8. It is the only class B kind, so retiring it leaves `outbound.rs`'s drop-oldest-first tests with nothing to test the mechanism with.

*What this step does land:* the twenty-nine spaces, the four renames, the AC energy split as two **new** numbers beside a still-live `0x0205`, the three stage-duration kinds, `0x0203 acknowledge concern`, the two command outcomes, `SetConfig` outcome 9, and the four new message pairs. Every one of them is additive.

Two smaller things the tree decided rather than the plan. The four new message types make `empty.rs`, `signed.rs` and `wrapper.rs` non-exhaustive, which is the compiler asking whether each is signed, wrapper-authenticated and empty-bodied — it is the exhaustive-matching rule doing review, and the answers go in this commit. And the space carrying `SignalRow.domain` is allocated as `signal_domain`, because `Domain` is already P-043's MAC label; the field keeps its short name the way `dir` does over `direction`.
*The acceptance test is an empty diff:* the generated Markdown and bindings for every space that did **not** change must be byte-identical. `cargo xtask registry && git diff --stat` names exactly the tables that moved or it does not go in. REGISTRY.md's hand-written prose — the class A/B paragraph and the unrecognised-outcome row — moves in this same commit, because `cargo xtask check` gates on the generated tables beside it and a document nobody edited by hand must not be the thing that fails.
*What the gate will not tell you:* it does not sweep metric or event kinds, so every new kind here is unreachable-by-construction and silently green. Count them by hand against the table above, because nothing else will.

**3. `Inventory 0x0D` / `0x8D` — the cold plane.** All five row kinds behind one table-driven encoder, the scratch-and-`raw()` page builder, the two-arm page cap with `min(row cap, byte cap ÷ width)`. Vectors: one page of each kind with every row at its widest, and one with every optional key absent.
~~**The vectors are blocked, and on the thing this document has been deferring.**~~ **Resolved — see the audit note at the head of this section.** What follows is why it was blocked and what unblocked it, kept because the reasoning is the general one and it applies again to `Concerns 0x0F`/`0x8F`. `bodies_match_the_spec` refuses a published body whose message `PROTOCOL.md` does not define, so `vectors/v1.json` cannot carry an `Inventory 0x8D` while `Inventory 0x8D` exists only here. That is the second gate to say it: `every_live_number_is_reachable` said the same at step 2, and both were treated as walls to route around — reserved rather than live, vectors held back — when they were saying something simpler. **A message being implemented belongs in the settled document.** The proposal status was true when nothing was built against it and stopped being true at step 1. Promoting `ReadInventory 0x0D` / `Inventory 0x8D` into `PROTOCOL.md` — its two bodies, and the requirements that produce its numbers — is what unblocks the vectors, and it is a decision about this design's status rather than a step in building it.

*Watch it fail:* add one byte to a `DeviceRow`'s worst case in the row-width table and see the `#[test]` that encodes a worst-case row through the public encoder go red. It is a `#[test]` and not a `const_assert!` because `CborWriter` is not `const fn` — the earlier draft prescribed a check that cannot compile. This is the check that stops the row-width table becoming a second copy of the encoder, which is what happened to COBS in this crate already.

**4. `Hello 0x81` keys 18–29, and the digest.** Key 13 and `MAX_CHANNELS` stay for now — `Snapshot` still uses them. Implement P-173's preimage exactly, and ship its vector in `vectors/v1.json` **before** any controller computes one, generated by the tool that may not depend on `km43`.
*Watch it fail:* change one `label` in a `ComponentRow` **without** bumping `rev`, and see the digest go red. Then edit a `ComponentRow` without bumping and confirm the controller's cached digest was invalidated by the row write rather than by the bump — a controller that recomputes only on the bump passes the first half of this test and is exactly the defect P-151 exists to catch. If either stays green, P-151 is prose.

**5. `Readings 0x0E` / `0x8E`.** *The message landed in `km43` some time ago; the **store-to-wire path** landed with `Store::readings`, which walks in ascending `sig` order and pages on `next`. What is still owed here is the `map.rs` split below and the two vectors.* Scalars first, then series. The `q`-byte packing, P-157's present-iff invariant, P-183's ordering, and the `sig` cursor. Split `Reading::Unreadable` in `map.rs` in this commit: a short reply and a value that will not fit the scale are `5 sensor_fault` and `6 out_of_range`, and they collapse into one `write_absent` today.
*Watch it fail:* two tests, and the first one is the one that was missing. Feed `0xFFFF` through a dialect cell that declares `Absent::AllOnes`, **starting before any validity has been chosen**, and grep the encoded bytes for any integer that could be read as that signal at its scale — the earlier draft's version started from an already-chosen `sensor_fault`, which is precisely why it could not see the failure. Then a vector with elements 3 and 9 at `sensor_fault`: flip one `q` byte to `ok` without adding an integer and see P-158's length check refuse it with error 1.

**5b. The store on the signal plane, and a behaviour that names what it watches.** This is the step this document has been referring to as missing, in three separate places, and it is one step rather than three. Step 6 waits on it because `snapshot.rs` holds the store's value model. The **eight metric-kind retirements** wait on it because a behaviour cannot select on a component until the store holds one. And the capability audit in [CONTROLLER-V1.md](https://github.com/origin89hq/origin89/blob/main/docs/CONTROLLER-V1.md) cannot be generated until a behaviour's needs are a thing the compiler can read.

*The failure it prevents, stated once:* `0x0110 PV array voltage`, `0x0130 start battery voltage` and `0x0101 battery voltage` are one unit at one scale. Today the **kind** is the only thing keeping them apart, and it is doing a job it was not designed for — which is why the design wants to collapse all three into `DC voltage`. Do that first and a generator starts on the solar array at noon. So the component has to become the discriminator *before* the kind stops being one, and never the other way round.

**A behaviour names a binding, and never a `sig`.** A `sig` is allocated by config or by runtime adoption and is only meaningful within a `rev`. A behaviour holding one across a revision bump reads whatever now occupies that id — which is P-152's failure exactly, arriving inside the controller where no `rev` check is watching for it. The frost behaviour that was heating a cabin would be reading the battery pack's probe, with a perfectly current `q` byte on it.

*What a binding is:* the tuple **P-188 already declares unique** — `(cmp, kind, domain, point, dir)`, with `dev` implied by `cmp` and `shape`/`vtype` implied by what the behaviour can consume. Not `(cmp, kind)` on its own: a charger's absorption, float and equalize voltages are one kind on one component and differ only in `point`, which is the four-identical-rows failure keys 7 to 9 exist against. A binding that omits the discriminators resolves to whichever row the table happens to hold first.

**A binding resolves once per `rev`, not once per tick.** Not for speed — 384 rows at 1 Hz on an M0+ is nothing — but because a resolution that fails must be *visible*. Resolved per tick, a binding naming a component nobody configured is an absent reading forever, which is the same shape a dead probe has, and the one thing this store has just learned to tell apart. Resolved at the bump, it is a **commissioning error with a name**: config says *the cabin's air temperature* and the topology has no such signal, raised as a concern and surfaced, once.

**The quality floor is a set and not a threshold, and origin89's [CONTROLLER-V1.md](https://github.com/origin89hq/origin89/blob/main/docs/CONTROLLER-V1.md) said otherwise when this was written.** Its audit reads `quality ≥ counted`, which was defensible when `quality` had five values in a rough order of trust. It has stopped being true: `provenance` allocates `1 measured`, `2 counted`, `3 derived`, `4 estimated`, `5 reported`, `6 commanded`, and those numbers are an allocation order rather than a trust order. `5 reported` is not worse than `4 estimated` — a BMS stating its own charge-current limit is the most authoritative number on the bus, and a behaviour comparing `>=` would refuse it and accept an inference instead. A behaviour declares the **set** of provenances it will act on. That line is the controller's to fix, in origin89, because a `>=` written from it compiles and is silently wrong.

*Bounds:* one binding table, `MAX_WATCHES` entries, refused rather than evicted. Every binding carries the `sig` it resolved to at the current `rev` and the reason it did not, and both are readable — the second is what a commissioning laptop needs.

*This document called that constant `MAX_BINDINGS` and the tree calls it `MAX_WATCHES`,* because `session::Binding` is already a different sense of the word in the same crate — a session bound to a transport — and `session.rs`'s own prose says *one of eight bindings* about a table that is not this one. Two eight-entry caps called bindings, meaning different things, is the kind of collision somebody reads past. The table holds `Watch`es, so the cap is named after what it counts, the way `Signals` holds `Signal`s.

*What lands with it:* the store keyed by `sig`, `Freshness` moving from a channel to a signal, series signals holding `n` elements against `MAX_SERIES_ELEMENTS`, `frost::Reading::celsius`'s unit-and-scale filter becoming a binding on the cabin's component, and the metric-kind retirements this unblocks.

*Landed so far:* `Signal`, `Signals`, `Binding` and `Watch`; then the store keyed by `sig`, with the metric kind and `Freshness` read off the `Signal` rather than copied into the slot — `Store` is `[Option<Slot>; MAX_SIGNALS]`, 384 slots of 48 bytes, 18 KB against the 15 KB the signal table costs, and `Device` names sigs rather than channels. **Scalars only:** `Store::register` refuses a `Shape::Series` row, because a slot holds one number and publishing the first element of a cell-voltage series as the pack is worse than refusing to hold it at all. Both seasons hold `Watch`es now rather than `Sig` constants. Frost names *the cabin's air temperature on the probe's component*; the generator names four, three of which share a component and are separated by `kind` alone — which is the first time that discriminator carries weight outside a unit test, and 15 season tests go red if two of the bindings are made to name one signal. Then `Observed`, and `Autostart::band` and `Inputs` taking one rather than a bare `Reading`, which is what makes the kind check in `band` redundant and discharges the last precondition the retirements were waiting on.

*Still ahead.* Three things, in this order, and the second is no longer a guess:

1. ~~**The element pool against `MAX_SERIES_ELEMENTS`.**~~ **Landed.** A series declares its length through `Extent { Scalar, Series(SeriesLen) }` — `SignalRow` keys 5 and 10 fused, so the wire's *`n` is required iff `shape` is series* cannot be violated by construction rather than by an encoder remembering. `Store` holds one shared `[Element; 512]` run, `register` allocates from it by bump and refuses a series that will not fit whole (P-172), and the refusal names the shortfall because *this pack wants sixteen and four are left* is what somebody at the cabinet can act on. Elements are read and written one at a time, each carrying its own three-state validity, so one dead cell does not blank a pack.

   *Three things the tree decided rather than the plan.* The store's budget went 36 KB → 42 KB, for the reason recorded in the bounds table above plus 3 KB that `Extent` cost by pushing `Signal` over an alignment boundary. `Held`'s two ticks became a `Run`, because a series ages as one thing under P-179 and there was no value to hang the question on — the alternative was a fake `Held` carrying a zero, which is the invented default this project does not ship. And **P-188's identity compares the shape and not the length**: `Extent` fuses them, so a derived `PartialEq` would call a fourteen-cell and a sixteen-cell row on one component two signals and register both. That last one was written as a comment first, and the comment was wrong — changing the comparison on purpose left all 443 tests green. The test that now catches it was written afterwards, which is the fourth time in this repo a guard has turned out to be prose.

2. ~~**The binding table and `MAX_BINDINGS`.**~~ **Landed, as `MAX_WATCHES = 8`.** The demand was counted rather than estimated: two behaviours naming five watches between them — frost one, the generator four. Eight is that plus room for one more frost-sized behaviour, and it is deliberately not the 16 or 32 earlier proposals floated, because neither number appeared anywhere in the repo and both were room-to-grow with nothing under them. **The cap is small on purpose:** the table refuses rather than evicts, so it has to be a number a real site can reach and a person can then be told about — a cap nobody can hit is a cap nobody has tested. `the_behaviours_in_the_tree_fit_the_watch_table` goes red when a third behaviour is added and nobody thought about the number, which is what makes the derivation a live check rather than a paragraph.

   *What the table was actually for, and it was not the cap.* `Watch::resolve` **threw the reason away**: a binding that failed to resolve went back to holding no id, so a behaviour with no reading looked exactly like a behaviour whose probe had died. One sends somebody to the config file and the other sends somebody to the cabin, and nothing told them apart. `Resolution` is three states now — never resolved, resolved at a revision, *refused at a revision and here is why* — and `Store::unwatched` walks every binding the controller holds and names the ones that answer nothing. That is the commissioning read this bound was written for, and it did not exist.

   *The store owns the table*, for the same reason it owns `Signals`: a binding resolves **at a revision**, and handing `observe` a watch table per query would let it answer against whichever one it was given. That is the hole that closed when the topology moved inside. A behaviour holds a `WatchId` and never a `Watch`, so there is no second table to hand over.

3. ~~**The nine kind retirements.**~~ **Landed, and there were eight.** `0x0105`, `0x0110`–`0x0112`, `0x0120`, `0x0121`, `0x0130` and `0x0301`, marked `retired` in `protocol.toml`, which stops a constant being generated and made the compiler name every remaining use — five, all in tests, because `Observed` had already done the plumbing. **This document said nine in four places and its own table lists eight;** the likely miscount is the temperature row, whose two retirements collapse into `0x0302`, a *rename* that got counted as a third retirement.

   *`frost::Reading::celsius` landed in the same commit,* as predicted, and it takes an `Observed` now. It still filters on unit-and-scale, and that turned out to be the right call for a reason the plan had wrong: the filter is not doing *selection*, it is guarding the **scale** `DeciCelsius` claims. Selection is the binding's job and always was. What changed is the kind it reads — the binding's, not the reading's.

   **The argument, made out loud, and the plan was too kind to itself.** This document said the guard moves from runtime to commissioning: caught by `band` answering `None` before, caught by `Signals::resolve` after. That is true only for a binding naming something that **does not exist**. A binding naming the *wrong but real* component — the array's, at the bank's kind — resolves cleanly, bands cleanly, and nothing in the tree refuses it. The defence-in-depth is not relocated, **it is gone.** What replaces it is weaker in kind: the binding is explicit, held in one table, and readable at commissioning by `Store::unwatched`. A person, not a check. That is a defensible trade — a component tells an array from a bank and a kind soon will not — but it is a trade, and `the_solar_array_at_noon_is_told_from_the_bank_by_its_component_alone` now pins the hole open with a comment saying so, rather than the design claiming a guard it does not have.

   *One more guard was found to be prose.* `celsius` was changed to read the reading's kind instead of the binding's, on purpose, and all 447 tests stayed green — the tank test used the same kind for both, so it could not tell them apart. That is the fifth time in this repo. `frost_reads_the_kind_its_binding_named_and_not_the_one_that_arrived` closes it, and the generator's equivalent was checked the same way and already had two tests that fire.

*The store belongs to a revision.* It holds the `rev` its slots were registered against and refuses every read and every write against a table carrying a different one. Without that it answers whatever table it is handed: a cabin probe registered at one revision and read against the next, where the same id is now the pack's voltage, publishes −5.0 °C as −0.050 V under a `q` byte reading `measured` and `ok`. Both halves are plausible alone, which is what makes it undetectable downstream — and it is the failure `Watch` was built to stop for behaviours, arriving one level below it, because nothing outside `signals.rs` holds a `Watch` yet.

*Two answers to one question, on purpose.* A `sig` the store holds and a **same-revision** topology does not describe — two pieces of configuration that disagree — reads as **no reading at all**, because there is no kind to publish it under and no window to age it against, and a behaviour handed nothing already fails safe — the store says *which* of the three it was, so a season does not have to guess. The same slot **refuses the whole `Snapshot`**, because a client watching a signal quietly vanish from the picture has nothing to point at, and that is not a fail-safe. `MAX_SIGNALS` is twelve times `MAX_CHANNELS`, so a full store cannot be published in one frame either way, and the refusal is now a path with a test on it rather than a comment saying it cannot happen.

*Watch it fail:* bind a frost behaviour to the cabin's air temperature, bump `rev` with a topology where the battery pack's probe now holds the old `sig`, and see the behaviour refuse to decide rather than heat on the pack's temperature. Then delete the re-resolution and watch it heat. Second: give a charger an absorption **and** a float voltage on one component, bind on `(cmp, kind)` alone, and see the binding refuse as ambiguous rather than take the first row.

**5c. The value model on the signal plane, and the enum space that is missing from it.** *This is the step 6c says does not exist.* Its own words: `snapshot.rs` "defines `Meaning`, `Reading` and `SnapshotError`, which are the state store's value model … and the thing that replaces it is the signal plane arriving in `o89-core`, **which no step here describes**." Everything still owed by step 6 is owed to this, so it is written down before somebody else rediscovers the hole.

*The failure it prevents.* `Meaning` decides whether a number is a measurement or an enumerated state by matching `MetricKind` against a **hardcoded list of three** — `GENERATOR_STATE`, `GENERATOR_SELECTOR_POSITION`, `LAST_BOOT_REASON`. That is precisely the hardcoded map the opening of this document says `esp` exists to delete, and it is sitting inside the controller rather than inside a client. A charger's firmware adds charge stage 9 and `Meaning` has no way to know the signal was ever an enum, because the only thing that told it was a kind somebody wrote out by hand.

*What is missing, measured rather than assumed.* `EnumSpace(u16)` is generated into `km43`, and `esp` appears as an optional key in the `SignalRow` and `ParamRow` shape tables — key 13 and key 10. **Nothing produces it and nothing consumes it**, and `o89-core` names neither `esp` nor `EnumSpace` anywhere. So `Signal` carries `vtype` and knows a value is an enum, and cannot say *which space it is drawn from* — which is the exact state this document's second paragraph calls "straight back on the hardcoded map", arriving one layer lower than the client it was written about.

*The order, and each step is blocked by the one above it:*

1. ~~**`Signal` gains the enum space.**~~ **Landed, as `Nature`.** Not `Option<EnumSpace>` beside `Vtype` — the wire's rule is *required iff `vtype` is 3 or 4*, and two independent fields can express the pair the rule forbids. Fused the way `Extent` fused shape and length: `Gauge`, `Counter`, `Enum(EnumSpace)`, `Flags(EnumSpace)`, so the illegal combination is not constructible rather than merely rejected, and `space()` answers `None` for a number rather than `EnumSpace(0)`.

   *The blast radius was six lines, and the identity was the whole job.* Every construction site in the tree was `Vtype::Gauge`, so the field rename cost nothing. What it did cost is a second leg of P-207's identity: `same_identity` compares `nature.vtype()` and **not** the whole `Nature`, exactly as it compares `extent.shape()` and not the length. Compare `Nature` whole and two enum rows of one kind on one component — one drawn from `generator_state`, one from `charge_stage` — both register, and a binding resolves to whichever the table held first. A behaviour reading *generator state* is then handed a charge stage whose 3 means `absorption` where it means `running`: both numbers small, both legal, nothing downstream able to tell them apart. **Watched:** replacing the leg with `self.nature == other.nature` turns `p_207_two_enum_signals_drawn_from_different_spaces_are_one_signal_declared_twice` red and nothing else, which is what says the test guards that leg and not the neighbourhood.

   *Fusing a pair of wire keys into one type is now the second time a derived comparison would have been quietly wrong.* That is worth stating as a rule rather than as two incidents: **a fused type needs its identity leg written by hand, and the leg needs a test that goes red when it is deleted.**
2. **`Meaning` reads the signal, not the kind.** The discrimination becomes a function of `(Sample, Signal)`, and the three hardcoded kinds stop being special. This is where P-165's rule actually lands in code, and it is what makes P-125 retirable rather than merely stale.

   *Where it actually goes, which is not where this step first said.* The answer is already allocated: **`validity 8 unnamed_state`**, and **P-164** already states the rule — a source reporting an operating state the controller has no normalized value for reports that validity with no value, and raises a concern carrying the source's own code. So the discrimination belongs in `Slot::quality`, at the moment the `q` byte is built, and not in an enum a behaviour matches on afterwards. That answers the *unsure* recorded at the foot of this step: `Meaning` does not need to move onto the signal, because a behaviour that reads validity never needed it. `Validity::UnnamedState` is allocated on the wire and **nothing in the tree produces it** — the same shape `esp` was in before step 1.

   *Landed, and P-164 is promoted into `PROTOCOL.md` with it* — `EnumSpace::members`/`names` generated from the registry join, `Slot::quality` answering `unnamed_state` for a value the space does not name, and `Signals::register` refusing a signal drawn from a space that names nothing at all. The refusal is at registration rather than per poll for the reason 5b gives about resolution: reading `unnamed_state` forever is true and useless, and it sends somebody to a cabinet when the fault is a word in a config file.

   **Only half of P-164 is built, and the requirement states both.** The validity clause is done and tested. The **concern clause** — carrying the source's own code in `raw` and its namespace in `vns` — is not: there is no general concern table in `o89-core` at all, only the two behaviour-local `Concern` enums in `frost.rs` and `machine.rs`. So `p_164_a_state_this_build_cannot_name_is_never_published_as_its_number` covers the clause it is named for and the matrix cannot tell that the other one is unwritten. Said here because the traceability count will read as covered either way. **It can tell now** — `[[clauses]]` in `traceability.toml` names the sentences a rule states and requires a test for each, and this paragraph is the reason that table exists.

   *One thing the tree decided.* The check is asked **before** staleness, not after. A number this build cannot name is not publishable at any age — `stale` would carry the integer, and the whole point is that nothing downstream may render it. And only `Nature::Enum` is asked, never `Flags`: a flags value is a bitmap over members rather than one of them, so putting it through `names()` would call every real bitmap unnameable. `balancing`, the one flags space, has no members yet anyway.

   *What it needs first, and this is measured.* `Slot::quality` has to ask whether an integer is a member of the signal's space, which is a question only the registry can answer. The join is by name — `enum_space` "generator state" against `[[enums.generator_state]]` — and **two of the seven allocated spaces have no member table at all**: `charge stage` and `balancing`. That is deliberate rather than broken; both are `status = "reserved"` because the design has not settled what is in them, and `balancing` is a flags space whose members are per-cell bits. But `EnumSpace::CHARGE_STAGE` is generated as a usable constant regardless of status, so a signal can be declared against a space that can never name anything. `every_live_enum_space_names_its_members` is what makes promoting one to `live` require settling it first, and the failure it prevents is a cabinet that reads as a rack of failed instruments because a registry entry was half written.
3. ~~**Behaviours read a `Sample`.**~~ **Landed, in two commits.** `Observed` carries a `Sample` and the signal's `Nature`; `Slot::reading` and `Store::reading` are gone, so there is one path from a slot to a number; the store tests naming P-091 and P-092 repoint to **P-196**. **6b's owed half went with it** — the wall-clock fallback that reported `absent` for an aged-out value on a clockless controller is unnecessary now that the age is a duration on P-004's tick, and the test asserting the old behaviour asserts the new one and says why it changed.

   *The nature had to travel beside the sample, and that was not in the plan.* A `Sample` carries no kind and no space, so a behaviour reading a **state** had nothing to check it got the set it meant. `Inputs::position` had been leaning on a comment saying only `0x0601` ever resolved to a position; it reads `Nature::Enum(GENERATOR_SELECTOR)` now. The alternative was trusting that `Slot::quality` had already refused everything else — a guarantee held across a module boundary with nothing asserting it, which is the shape this repo has found to be prose five times and was not going to make a sixth.

   *`admitted` became a set over provenance*, which the quality-floor paragraph above said it should always have been. Frost admits every source and gates on validity alone, because CONTROLLER-V1.md puts the provenance gate on autostart and inventing one for frost would be a parameter no document asks for.

   *Two things the tests caught rather than the author.* `Sample::new` refused four fixtures with `StaleWithoutAge` — P-196 requires an age on a stale reading and the helper passed `None` throughout, so the constructor would not build the shape the wire forbids. And eight season tests went red because the simulated selector was still declared `Nature::Gauge`: it is a switch position, the topology is now the only thing that says so, and a season where the generator never starts is what a wrong declaration costs. That is the migration working — the fact moved out of a convention and into a field.

   *Settled by asking when the deferral would end.* `Reading` and the old `Meaning` had no users left, and the module still could not be deleted: **P-019 and P-125 were covered only by tests inside it**. The tempting move was to declare P-125 untestable and delete the file. The question that killed that idea is *when would it be implemented* — and the answer is that P-125 is a **client** rule, `packages/km43` holds one generated file and nothing else, and `cargo xtask check` reads `.rs` only. So the trigger would have fired the moment a browser rendered a reading and the entry would have sat in the untestable bucket forever, outliving the thing it was waiting for. That is the graveyard `traceability.toml` was written against.

   *What it actually wanted was the other half of step 2.* P-164 put the refusal in the controller's `q` byte and that was the **sending** half; P-125 has always been the **receiving** one, and neither substitutes for the other — a controller can only refuse what *it* cannot name, and a client two versions older has a shorter list than the controller that answered it. So `Meaning` survives, rekeyed from three hardcoded metric kinds onto `Option<EnumSpace>`: `Measurement`, `Named`, `Unrecognised`, `Nothing`. `Option` rather than a `Nature`, because for this question a gauge and a counter are the same thing — a number — and `Nature::space()` hands the argument over already shaped.

   *Both rules are now covered by code a client will actually call*, in `km43` where one can reach it, and each test fires on the realistic wrong implementation rather than on a contrived one: calling anything from a known space `Named` reddens P-125 alone, and reading an unknown space as a plain number reddens P-019 alone. `Reading`, `WrongConstructor` and the channel-and-kind value model are gone — 239 lines out, 131 in.
4. **Then step 6 finishes**: P-091 and P-092 retire, `reading.rs` goes, and the `### Snapshot` section leaves `PROTOCOL.md`.

*What this is not.* It is not a mechanical substitution. `Quality` and `Reading` are named about 250 times across eleven files in `o89-core` and `o89-sim`, and the lesson this document has already paid for three times is that a scripted edit across a region being restructured costs more than writing the region. Step 3 above is the one that touches every file, and it is the one that wants a single `seen(...)`-shaped helper written once — the same thing that kept `Inputs` mechanical in 5b.

*Unsure, and recorded rather than decided:* whether `Meaning` survives at all after step 2, or whether a behaviour asking *is this a number* wants a method on the signal instead. The smaller option is to keep the enum and change what feeds it, and that is what is written above — but it is written by somebody who has not yet tried the other one.

**Answered, by reading rather than by trying.** `Meaning` does not survive and does not need to: `validity 8 unnamed_state` and P-164 already say what an unnameable state is, so the discrimination belongs in the `q` byte and a behaviour reads validity. Step 2 above carries the detail. The question was worth writing down and was worth about twenty minutes to answer, and the answer was in the requirement list the whole time — which is the argument for reading the allocations before designing a type to replace them.

**6. Retire `Snapshot`, and everything that hangs off it.** `0x02`/`0x82`, `Value`, `quality`, `MAX_CHANNELS` and its five derived constants, `Hello` key 13, P-089 through P-092. Delete `snapshot.rs`. Regenerate `vectors/v1.json` wholesale. The tree never carries two ways to read state, because a shim for a client that does not exist is the thing this project state forbids. **Blocked on 5c**, which is where its remaining half actually lives.

*This step named P-006 and P-125 too, and both are live rules that survive the message* — the Retired section above says which condition each one waits on. **P-093 was never on this list and must not be added to it.** It is amended above, and it is the only sentence in the settled spec forbidding a zero that means *unknown* — but its text was about `Snapshot` key 2 and `Value` key 5, so it read like part of the message and would have gone out with the section.

*It has been moved.* P-093 is now stated by category — every field carrying a wall-clock time — in the `## State and events` preamble, above the subsection that dies. **Measured rather than assumed:** delete the `### Snapshot` section from `PROTOCOL.md`, run `cargo xtask check`, and the citation check names P-125 once and P-091/P-092 seven times, and does not name P-093. That list is the actual remaining cost of the section, and it is the two requirements whose blockers are recorded above — not five.

**It is not one commit, and the reason is the fourth instance of this document's recurring mistake.** `snapshot.rs` does not only define the wire message. It defines `Meaning`, `Reading` and `SnapshotError`, which are the **state store's value model** — `o89-core` and `o89-sim` name them in seventy-two places — and `MAX_CHANNELS` is the store's array length. Deleting the file deletes what the controller holds, not merely what it publishes, and the thing that replaces it is the signal plane arriving in `o89-core`. A retirement can only land in the commit that dismantles what depends on it, and this one depended on a step that did not exist. **It does now — 5c above**, written once the hole had been walked into a second time from the other end: chasing what still blocked P-091 and P-092 arrives at the same missing piece as chasing what `snapshot.rs` left behind.

*That step is **5b**:* the store keyed by `sig` rather than by channel, with behaviours naming a binding rather than an id. It is **the same step the eight metric-kind retirements are waiting on** — a behaviour cannot select on a component until the store holds one — so the two are one piece of work and not two.

**6a. Give the store the reasons it was throwing away.** Landed. `write_absent(channel)` took no argument at all and set the slot to `None`, so `driver.rs`'s three findings — a register the model lacks, a reply that did not arrive, a number that will not fit — arrived as one fact. Worse, a channel **registered and never polled** was the same `None` as a dead probe, so the first poll cycle after a boot read as a cabinet of broken instruments. `Last` is three states now, `write_absent` carries a `Validity`, and `Store::quality` produces the `q` byte a `Readings` will publish.

*The five-value `quality` split with nothing left over, and the store had already done the splitting.* The three a driver may claim — `measured`, `counted`, `estimated` — are **provenances**. The two `Sample::read` refuses — `stale`, `absent` — are **validities**. That is why `Sample::read`'s constructor rule reads as arbitrary and is not: it was separating validity from provenance a year before there were two words for it. So `counted` **and** `stale` — `0x22`, the case one word could not express — needs no new information from anywhere.

*Still owed by 5b, and found by reviewing its own commits.* The topology and the store are **one thing** and the tree says so three times without saying it once: `store.rs`, `driver.rs` and `bus/season.rs` each invent a private struct holding a `Signals` beside a `Store`, two of them near-identical down to the comment. Meanwhile `Bus::poll` and `Bus::file` take the pair loose and are six-parameter functions, which is the lint naming its own fix.

*And it does not want a new type at all.* The obvious answer is a third struct owning both, which needs a name — `Site` already means three different things here, one of them public in `o89-sim`. The better answer is that **`Store` owns its `Signals`**. A store is built for one revision and can only ever be read against the topology it was registered under, so handing it a table per query is what created the hole in the first place. Owning it deletes the argument from five signatures, collapses the three fixtures, and makes the guard structural: there is no second table to hand over.

*Landed.* `WrongRevision` is gone — there is no second table to hand over, so the check it performed has nothing to check. `NotInTopology` and `TooManySignals` survive as answers the compiler cannot prove unreachable, each documented as such rather than unwrapped. `StoreError::AlreadyRegistered` is deleted: asked second, it could only ever agree with the topology's refusal above it. The two tests that built a store disagreeing with its table by swapping a field cannot be written any more, which is the guarantee. `Bus::poll` and `Bus::file` are back to five parameters and every `{ signals, store }` fixture is gone.

*What 6a did not do:* the store still publishes a `Snapshot` and still holds `Reading`. The array length was `MAX_CHANNELS` and is `MAX_SIGNALS` since 5b. `Store::quality` is the second reader of the same state rather than the only one, which is the shape this document forbids for a wire and tolerates for one commit inside a crate — on the condition that the next commit removes the first.

**6b. A stale reading no longer needs the clock.** *Half landed.* `Store::readings` ages a stale sample in whole seconds on the monotonic tick, so the new plane never asks for a date — which was the precondition. The **fallback in `Slot::reading` is still there**, because `Snapshot` is still the other output and producing `stale` without a timestamp would only build a body its encoder throws away. It goes with the file, in 6c. It is a behaviour change rather than a deletion, so it does not ride along with one. `Snapshot`'s `stale` carries a **wall-clock timestamp** (P-092), so `Slot::reading` reports `absent` for an aged-out value when the clock has never been set — P-093 forbids inventing the date. `Readings` key 4 `age` is a **duration on P-004's tick**, which is monotonic since boot and which a controller always has. Under the new plane the fallback is unnecessary: a controller that has never been told the date still knows the value is two hours old, which is the part a behaviour needs. Delete the fallback in the commit that publishes `Sample` from the store, and not before — while `Snapshot` is the output, producing `stale` without a timestamp only builds a body the encoder throws away.

**6c. The retirement itself.** *Landed in two commits.* The first split the value model out of `snapshot.rs` — `Meaning`, `Reading` and its constructors into `reading.rs` — which is what turned this from a rewrite into a deletion. The second retired `Snapshot 0x02`/`0x82` in `protocol.toml`, deleted `snapshot.rs`, `Store::snapshot` and `StoreError::Snapshot`, took the snapshot entries out of the vectors generator, and regenerated `v1.json`.

*The compiler named the blast radius,* which is what retiring a message type is for: `empty.rs`, `signed.rs` and `wrapper.rs` each carry an exhaustive list of every `MessageType`, so removing one made all three fail to compile rather than silently leaving `Snapshot` classified.

*What the deletion cost in coverage, and what was done about it.* Removing the snapshot tests took three requirements from covered to uncovered — **P-019**, **P-090** and **P-125** — and `cargo xtask check`'s traceability ratchet refused the build, which is exactly the job it was built for. Only one of them was actually retired. P-090 bounded `values` at `MAX_CHANNELS` and said there was no paging: both are facts about a message that carried a whole site in one frame, and `Readings` pages, so it is retired and its number held. **P-019 and P-125 outlived the message** — a vendor kind is still surfaced rather than rejected, and an unnamed state is still never rendered as the nearest one this build knows, both in `Meaning`, which is now in `reading.rs`. They had been covered *only* by the `Snapshot` decoder's tests. They have their own now, named after them, in the module the behaviour lives in. The ratchet's number did not move.

*Still owed, and deliberately not in these commits:* `MAX_CHANNELS` and `Hello` key 13. `config.rs` still sizes its channel array on `MAX_CHANNELS`, and that array belongs to the `0x0002 channels` config section — which entry 9 replaces with `0x0004 topology`. Retiring the constant before that section moves would leave the config plane with no cap at all. Key 13 rides with it, because it is what the controller reports the constant as. Repoint the `Value`-specific P-089 citations in `limits.rs` in whichever commit takes those; the four general ones in `cbor.rs` and `handshake.rs` have already moved to P-185, because they were never about a snapshot.

*The gap this opened, and it was smaller than the commit that opened it said.* `p_092_a_store_encodes_the_snapshot_the_published_vectors_carry` drove the store and compared its bytes to `v1.json` — the one check that an *independent* generator and this crate agreed about what the store publishes. It died with the message, and that commit claimed `Readings 0x8E` had no vector to replace it because the vectors were blocked on promotion into `PROTOCOL.md`. **Both halves of that were wrong.** `Readings 0x0E`/`0x8E` has been a settled section of `PROTOCOL.md` for some time — step 3's blocker is `Inventory 0x0D`/`0x8D` and only that — and `v1.json` has carried a `readings_0x8E` body, with three tests in `km43` against it, all along.

*What was actually missing was one test, and it is written now.* Nothing drove the **store** into those published bytes; `km43`'s tests check the encoder against the vector, not the plane that fills it. `a_store_encodes_the_readings_the_published_vectors_carry` registers the two signals the vector describes, writes what each instrument said, pages the store, encodes the body and compares. It reads the hex out of the artefact rather than transcribing it into a `const`, which is the discipline this repo has had to relearn in four modules. Watched fail twice: once by moving the generator's number and regenerating, and once by making the store emit a zero for the faulted cell instead of omitting it — the counting rule that turns three cells into three shifted ones and sixteen into sixteen.

**6d. The driver reads the topology instead of guessing at it.** *Landed.* Step 2 recorded that `driver.rs`'s `Device` and this plane's `DeviceRow` are one instrument modelled twice and that the driver's copy should eventually read this one. It does now: the driver's type is `Instrument`, it carries a `Dev`, and `Bus` carries the `BusId` it is.

*What that was covering up, and it was not cosmetic.* The two halves were joined by nothing — the driver knew a slave address, the store knew a `Scope`, and the only bridge was **each fixture building a `Cmp` out of a slave address**, in `driver.rs` and in `o89-sim`'s season alike. The topology registers slave 1 on one pair and slave 1 on the next as two devices deliberately, and an address-derived component id collapses them into one. Every reading that produces is in range, `measured`, and the other cabinet's.

*So `Bus::agrees_with` compares the two pictures* — the row exists, it is on this pair, it answers at this address, and every signal the instrument writes resolves through `Topology::device_of` back to that same device. Six answers rather than one, because *polled down the wrong pair* and *scoped to the neighbour's component* send somebody to different files. The season runs it before the first exchange.

*Watched fail, and the last one is the argument for the whole check.* Silencing the ownership comparison reddens the misattribution test alone; silencing the bus comparison reddens the wrong-pair test alone. Then move the shed meter's row to a second pair in the simulator's own fixture and **silence the check**: all forty tests pass, `misfiled` is 0 and `blank` is 0. A season cannot see this, because there is nothing wrong with any individual exchange.

**6e. The topology carries its own revision, and its rows carry when they last changed.** *Landed with P-205.* `Topology::new` takes a `rev`, every row it takes is stamped with the revision current when it arrived, and the two operations that move a row — a device replaced, a component that means something else — bump the revision and re-stamp in **one call**. Apart, there is a window where the row describes the new instrument under the old `rev`, and a client that fetched inside it caches a row nothing will ever tell it to discard (P-150).

***`since` is stamped and is not a field of the row***, which is the whole of why it is worth anything: a config write declares what a device *is* and the controller says when it last became that. A caller-supplied `since` is a number a driver can get wrong, and the field exists so a client can refuse to plot across the seam — a wrong one draws the old shunt and the new one as one continuous meter, with a step in the middle that reads as consumption nobody had.

*It also closed a hole the presence sweep had worked around.* `Presences::same_revision` could check the event's revision and the store's and **not** the topology's, because a `Topology` did not have one. It checks all three now, so a device replaced under a running sweep is refused rather than announced.

*Still owed here:* the staging `MIN_REV_INTERVAL_MS` requires — a sub-device discovered inside the window is held and adopted at the next boundary — which is a separate rule about *when* a bump may happen rather than about what a bump does.

**7. `Concerns 0x0F` / `0x8F`,** including the severity-band admission, the refused counter, the five-state lifecycle and P-181's persisted age.

*The table has landed, and so has the wire.* `o89-core`'s `Concerns` holds the severity band — `info` and `warning` share `MAX_CONCERNS_BELOW_FAULT` rows and `fault`/`protection` may use the table, so thirty-two cell-imbalance warnings on a cold morning cannot leave the pack fault behind them with nowhere to go — the refused count, and the five-state lifecycle with `acknowledge`, `condition_gone`, `condition_returned` and `release`. **P-168 and P-180 went into `PROTOCOL.md`** first, with the state table, in the `## State and events` preamble rather than a section of their own: at that point `0x0F`/`0x8F` was `reserved` with its body deferred, and a normative section for a message nobody can send is the mirror of the defect `no_retired_message_keeps_a_normative_section` was added to catch.

*That is what 7f changed, and it changed both halves together for that reason.* The section and the status are one decision: a section under a `reserved` status is the defect above, and a `live` status with no section is what `every_live_number_is_reachable` refuses. So `ReadConcerns 0x0F` / `Concerns 0x8F` has a section, its three bodies, four rules of its own as **P-208** to **P-211**, and a `live` row in the registry — all in one commit, because either half alone is a state this repo has a check against.

*One rule was added that this document implies and never stated:* **an acknowledgement does not survive the condition returning.** Somebody read that the pack was over temperature at four in the morning; the pack going over temperature again at noon is a thing nobody has read, and a row that stayed `active_acked` through it is a screen claiming otherwise.

*Still owed here:* **the wiring, and only that.** Nothing calls the codec, because there is no request dispatcher and `Concerns::page` is not connected to `ConcernsPage`. The message is built, specified, published and dated.

**7d. The pin a walk is held against.** *Landed.* `Concerns` had a table, a lifecycle and a refused count, and **no `seq`** — so key 2 had nothing behind it and a walk over concerns had nothing to hold it still. `rev` cannot do it, because concerns deliberately do not move `rev` (P-155). Without the pin a `cid` released under P-180 and handed to a different condition between two pages is a row the client sees twice or never, with every field of both pages well formed, in the table that decides whether a charger may start.

*It moves when a row arrives or leaves and not when one changes state*, and that half is what the second test is for. The tempting version moves it on any change, passes the arriving-and-leaving test, and makes a walk unfinishable exactly when the site is at its worst: a pack whose rows change state every tick would tear every page a client asked for, forever, for a change that reorders nothing. Thirty-two per-cell rows clearing on a cold morning is the case this table was sized around.

*And the walk is by `cid` ascending, not table order* — table order is an accident of which slot was free, and two pages ordered that way can hold one row twice or miss another, which is the same failure the pin exists against arriving through the ordering instead of through reuse.

*Watched fail three times:* never move the pin and the arriving-and-leaving test reddens; move it inside `row_mut` so every state change counts and the storm test reddens; walk in table order and the ordering test reddens.

**7e. The page the encoder will serialise, built where the cap lives.** *Landed.* `Concerns::page` stops at `MAX_CONCERN_PAGE_ROWS` and carries `next`, `total` and the pin. In the controller and not in the encoder, because a page built past the cap is a frame the controller assembles and then refuses, and the client is told nothing about the rows it will never be sent.

*`total` is every row the walk returns, and not only the ones still going wrong.* A `cleared` row stays in the table until it is released and a walk has to return it — a client that never receives it never learns the condition ended. A `total` that left those out would be smaller than the number of rows the same walk delivers, which is a client unable to tell a short page from a torn one.

*One test was standing over a distinction that does not exist, and breaking it is what said so.* It asserted that `next` names the row that did not fit rather than counting one past the last one sent. Under an at-or-after cursor those are the same answer, and the deliberate break passed. What survives is the property that is real: a row released between two pages neither repeats nor loses one, and the pin is what tells a client the table moved underneath it. The `cid` cursor is kept for the reason `ReadSignals` gives for a `sig` cursor over an ordinal — a client can watch the ids ascend and check it.

*And the citation check caught its own author:* the test was first named `p_171_…`, and P-171 lives in this document rather than in the settled specification, so it was a test standing behind a number no document allocates. It is `p_208_…` now, which is where P-171 landed.

**7f. The section, and the status that goes with it.** *Landed.* `PROTOCOL.md` describes `ReadConcerns 0x0F`, `Concerns 0x8F` and the `Concern` row, and the registry calls the message and its three outcomes `live`. Four rules came across: **P-208** the two page-cap arms, **P-209** the walk order and what `total` counts, **P-210** the pin, **P-211** the age. Three arrived covered by tests that were already asserting them under other names; P-211 did not, and could not.

*Writing the body out is what found the hole in P-181,* which is recorded against that entry above. A field list asks what an encoder puts in a key. A prose requirement does not, and this one had said *do not report a fresh age* about a key that is always present.

*One more number was corrected on the way past.* Four `[[outcomes]]` rows in `protocol.toml` cited **P-153** for `superseded`, and P-153 is this document's number for a rule that went across as **P-146** — the same defect the P-174 note above records, in a file nobody thought to search. Two of the four were on `live` spaces. The citation check does not read `protocol.toml`, so nothing was ever going to say so.

***This entry claimed the `Concern` row's thirteen keys were checked by nothing, and the second half of that was wrong.*** The first half stands: `bodies_match_the_spec` reads a fenced block's field list and **drops the keys of an embedded type**, deliberately, because `Sample` and `Series` restart at key 1 and would otherwise append to `Readings 0x8E` as a body with `1` twice. So the two wrapper bodies are watched there and the row inside `c` is not.

*What that note then said about the other check was asserted from its doc comment rather than from its code.* `published_rows_match_the_spec` was described here as reading the five descriptor kinds and therefore unable to see a `Concern`. It reads **every nested type `PROTOCOL.md` defines inside a message** — `rows.rs` parses the fences and matches a published entry to a type by name — so a `concern_widest` row is compared key for key the moment it is published, which 7g did. Watched both ways it was said it should be: renumber key 13 in this document only, and mark key 9 optional in this document only. Each goes red, and the second names only the row it should.

*The lesson is the one this document keeps paying for:* **a check's doc comment is what somebody wrote about it, and its code is what it does.** The same shape as searching a document by a rule's number rather than by what it says.

**7g. The vector, which is the first outside opinion about these bytes.** *Landed.* `vectors/v1.json` carries a `concerns_0x8F`: a request, a three-row page, and the two ends of the row budget. The rows are chosen for the rules that are easy to get wrong — cid 9 is pack 2's cell 23 at `elem = 7` against an `ebase` of 17, cid 11 is the charger as a whole at `cmp = 0` with a vendor code and the namespace that reads it, and cid 12 is a protection that ended at dawn and has not been released, so `total` is 3 with a `cleared` row counted in it.

*Watched by moving the generator, which is the test this document says to apply.* Change one `cid` and regenerate: `the_published_concerns_body_is_the_one_this_crate_writes` goes red. Widen `age` to a `u64` and regenerate: the row-budget test goes red instead. Neither is a round trip inside the crate, which is the whole reason the generator may not depend on it.

***The generator and the crate disagreed once, and the generator was right.*** The crate-side fixture built its narrowest row with `Part::device`, which is `cmp = 0` and two bytes shorter, and would have pinned 35 where this document derives **37**. Narrowest here means **fewest keys**, not smallest numbers — every required key stays at its widest, because 37 is the divisor behind *the byte cap would admit 22 rows where the row cap admits 12*, and a figure taken from small ids claims more room than a real page has. `published_rows_match_the_spec` also refuses the word: a published row must end in `_widest` or `_required_keys_only`, which is the vocabulary this confusion had already cost somebody once.

**7h. The age, which is two numbers and not one.** *Landed.* `Concern` carries an `Age`: what the row accumulated before this boot, and the tick this boot first saw it at. Two, because P-004's tick is zero at boot and a concern outlives one — a protection that has held the charger off since midnight reads twelve seconds after a brown-out at dawn, and *this just started* is what an operator then reads about the six hours that are the reason to look.

***The FRAM path turned out not to be the blocker, and this entry said it was.*** Twice: the build-order note above and `traceability.toml` both had P-211 waiting on storage. What P-211 actually says is that a restored row carries what it accumulated, and that a controller which cannot recover that number does not restore the row — and `Age`'s two constructors are those two sentences. `starting` is the only route to a zero; `carried` will not be built without the seconds. Where the seconds are read back from is a storage question the rule has no opinion about, and treating it as a precondition kept a testable rule sitting on the uncovered list.

*Watched twice, and they fail differently.* Make `carried` discard its seconds and the restart test reddens alone. Stop counting this boot's elapsed at all and both redden, which is what says they are not one test wearing two names. Ratchet 48 → 47, and P-211 takes a `[[clauses]]` entry with both halves.

**7a. P-164's concern clause, which is the table's first caller.** *Landed.* Only the validity half was built: `Slot::quality` refused to publish a state the signal's space cannot name, and nothing anywhere said so. A charger whose firmware added a stage this build has never heard of read `unnamed_state` at every poll for the season, and the only trace was an absent value on a page — no device named, no vendor code, nothing to act on.

*It is a sweep and not a hook at the write, and that is the decision worth arguing with.* The obvious place is the driver, at the moment the value arrives. It cannot do the other half: the condition **ends** when a value the space does name arrives, and an absence stopping is not an event anything can hook. `Concerns::track_unnamed_states` does both directions against `Store::unnameable`, so the same charger reporting the same unknown state for a week is one row, and a build that later names the value clears it.

*The chain the clause needs runs signal → `Scope` → `Topology::device_of` → `DeviceRow.dialect` → `vendor_of_dialect`,* and step 6d is what completed it. A dialect this build has no namespace for raises the concern with **no code**: inventing a namespace is the fallback P-125 forbids, and dropping the concern would lose the one sentence that is true either way.

*`warning`, and the band is the argument.* The number was never published, so no behaviour decided on it and nobody drives out. It also matters that this is the one thing in the design that raises in bulk — a revision renaming an enum space makes every signal drawn from it unnameable at once — so it is the likeliest way to fill the table, and `MAX_CONCERNS_BELOW_FAULT` is exactly what stops that spending the pack fault's rows.

*`cid` allocation is lowest-free, not a counter.* A counter on a controller that runs for years wraps back through ids still in the table, and `0x0203 acknowledge concern` then lands on the wrong row. Reuse after `release` is what P-180 permits and only that. The allocator answers over a wider space than the table holds, so a full table still has ids and admission is what refuses — *no room* and *no id* stay two sentences.

*Watched fail, four times:* delete the clearing half and the nameable-again test reddens alone; drop the dedup and both the one-row test and the returning-condition test redden; raise as `fault` and the band test reddens with the P-164 test; drop the vendor lookup and the P-164 test reddens alone. P-164 leaves `cargo xtask check`'s *one test* list in the same commit.

*Still unsure, and recorded rather than decided:* the sweep is O(signals × concerns) per call, which is nothing at 1 Hz over 384 signals and 48 rows and is worth measuring on the part before the poll loop calls it at a higher rate.

**7b. The season that closes it end to end.** *Landed.* The unit tests drive the sweep directly; nothing drove it through a real behaviour over months. The generator simulator already publishes the one enum-valued signal in the tree — `GENERATOR_SELECTOR_POSITION`, drawn from `EnumSpace::GENERATOR_SELECTOR` — so the case is a site rather than a contrivance: somebody fits a four-position selector, or a panel is swapped for one that numbers its positions differently.

*What used to happen is the reason this is worth a season.* The controller reads a 4 from a set that names three, P-164 refuses to publish it — correctly, since the nearest position it knows is `auto` and guessing that starts an engine on a switch somebody deliberately moved — the behaviour reports `CannotSeeTheSelector` and declines for the rest of the winter, and **the panel shows a selector with nothing wrong with it**. The only way to find out was to drive out and look. The site's table now carries the position verbatim with whose number it is.

*Both directions, over ten days:* eight days of an unreadable position is **one** row and not one per poll, and a switch turned back to a position this build knows ends it. `Site::selector_position` takes the later of the two events for that reason — a fixture that cannot express the condition stopping cannot test the half of the sweep that clears.

*Watched fail twice:* delete the sweep call and the reporting test reddens; publish `site.selector()` instead of the raw position and it reddens again, because the fixture is then no longer producing an unnameable value at all — which is the failure mode of a test that looks like it is exercising something and is not.

**The fixture was wrong first, and correcting it found something.** It declared the selector on an EPEVER-dialect panel, which made the season assert `VendorNamespace::EPEVER` for a switch no site reads that way. origin89's `CONTROLLER-V1` says *one three-position selector **at the controller***: it is a switch on local I/O, on `Dev::CONTROLLER`, speaking `no_protocol`. The topology now carries two devices for that reason, and whose device a signal hangs off is what decides whose number an unreadable value is.

***And for this one the answer is nobody's.*** P-164 carries `raw` only with the `vns` that reads it — rightly, since a code from nobody is unreadable — and `VendorNamespace` names third parties, with no entry for this controller. So a switch on our own panel reporting position 4 raises a concern that **does not say 4**, and the one place a person most wants the number is the one place the wire cannot put it. The season asserts that shape (`UnnamedSelector::Uncoded`) rather than smoothing it over, and moving the switch onto the meter reddens it with `Coded { raw: 4, vns: PZEM }` — so both halves are live and the test pins which one this site is.

*Not fixed here, and the condition rather than a plan:* this wants a namespace for the controller's own codes **the first time a controller has to report a value of its own that this build cannot name** — a local input, a derived figure, an internal state. Until then it is one fixture asserting a gap, which is cheaper than an allocation on the wire that nothing yet needs. Allocating one is not retrofittable politely once a client is reading concerns, so it belongs in the same decision as the `Concerns 0x0F`/`0x8F` body rather than before it.

**7c. P-164 was only ever asked of one value at a time.** *Fixed.* `Slot::quality` asked the enum space and `Store::element` **never asked at all**, so a pack publishing a per-cell state read the cell nobody could name straight out as a number and answered `ok`. `Store::readings` pages through that same call, so it went on the wire as a state — which is precisely what the requirement exists to forbid, on the plane where it is hardest to see: fifteen cells are fine, nothing about the pack looks wrong, and the one rendered as *the nearest state we know* is the cell somebody would have driven out for.

*The two paths had two answers because the question was written twice.* It is `Signal::names` now and both call sites ask it. `Flags` is deliberately not asked — a bitmap is a combination of members and almost never a member — and a gauge is not asked because a bank at 52.1 V is not a member of anything.

*And the element path no longer hands back a number it has just called unpublishable:* the value is read off the `q` byte rather than off the cell, so a validity saying *there is none* and a number surviving beside it cannot both be true.

**This is what gave `About::Element` its first producer.** The variant has been in the design since P-178 and nothing in the crate had ever built one. A cell is `About::Element(scope, sig, at)` and a scalar is `About::Signal(scope, sig)`, because *the pack's state is unreadable* and *cell 7 reports something we cannot read* send somebody to different places. The clearing matches on the **position** as well as the signal — fifteen cells recovering must not close the row about the sixteenth, and matching on the signal alone does exactly that and looks right.

*Watched fail three times:* clear by signal alone, raise `About::Signal` for a cell, or undo the store's check — the first two redden the cell test, and the third reddens it together with the store test that is the bug report.

**The ownership question 6a invites is answered, and by measurement.** *Should `Store` own its `Topology` the way it owns its `Signals`?* The argument reads identically — a store is registered against one topology and can only be read against it — and it would delete `Disagreement::SignalScopeNotInTopology` by making it unconstructible. **The budget refuses.** Bisecting a `const` assertion rather than estimating: `Store` is between 40 and 41 KB against the 42 KB its own `SIZE` holds it to, and `Topology` is another 3 to 3.5 KB. The two together are past the line. So the topology sits beside the store and the callers that need both take both, which is why `Bus::agrees_with` and `Concerns::track_unnamed_states` each take two tables rather than one. Recorded here and at `SIZE`, because the argument is good enough that somebody will try it again.
*Watch it fail:* three, and the second is the one an earlier draft was missing. Raise thirty `info` concerns and then one `protection`, and assert the protection is admitted and the twenty-fifth `info` is not; delete the band check and see the protection get refused. Then **raise thirty-two per-cell concerns, clear every condition, and assert the table is empty and thirty-two `0x0502`s carrying state 5 are in the log** — delete P-180's removal rule and watch the table stay full and the next `protection` get refused, which is the failure the first test cannot see because it runs against a freshly built table. Then raise a protection, restart the controller, and assert the reported `age` is the accumulated one and not twelve seconds.

**8. The five event bodies — `0x0102`, `0x0501`, `0x0502`, `0x0901`, `0x0902` — and P-182's coalescing.** ***Done: all five bodies, all three of P-182's sweeps, the rule itself promoted into `PROTOCOL.md` with a four-clause entry, and class B empty.*** `0x0501` and `0x0502` went first — they need no coalescing, the `Concern` codec already encodes the thirteen keys a raise carries, and P-180 had been promising an `0x0502` that nothing could write. `0x0102`, `0x0901` and `0x0902` followed. All five are specified in `PROTOCOL.md`, `live`, coded, and published in `vectors/v1.json`, and two rules came with them: **P-212** on the arrays and on `prev` being the last value *announced*, **P-213** on why a revision moved.

*The bodies did not need the coalescing and the coalescing needs them,* which is why they went in this order. What P-182 decides is how many entries go in a tick and what happens to the rest; what the bodies decide is that there is an array to put them in. Building the second first would have been a rule with nothing to bound. `rev` as key 1 on every one of them, the two array bodies, the announced-validity byte per signal, and the carry-to-next-tick rule. P-003, P-096, P-097, P-098 and REGISTRY.md's class A/B prose were amended for an empty class B in the commit that retired `0x0101`.
*Watch it fail:* flip all 384 signals in one tick and assert **eight** ticks of one `0x0102` each, that every one of the 384 changes appears exactly once across them, and that the queue never exceeds `CLASS_A_TICK_CEILING`. Then delete the carry-over clause so an over-cap burst is dropped rather than deferred, and see the count come back 48 instead of 384 — a `const_assert!` over four constants cannot see that difference, which is why this step exists and why step 1's assertion is not enough on its own. Then clear thirty-two concerns in one tick and assert `0x0501` and `0x0502` are bounded **together**: bound only the raises and the clears take the radio off the air by the path P-182's rationale describes.

***The validity sweep is built and its watch-it-fail has been run: 48 instead of 384, exactly as predicted.*** The announced byte is a field on the live row rather than a table beside it, for the reason `Store` owns its `Signals` — a parallel table goes on describing signals a revision bump replaced, and announces that the cabin probe moved while naming an id that now belongs to the pack. Marking is split from sweeping: the sweep builds the record and marks nothing, and the store is told what was announced once that record is committed, which is P-180's rule about a `cid` arriving at the same place for the same reason. Mark at build time and a record that never reaches the log takes 48 changes with it — the difference against the announced byte is the only thing that remembers them.

***The concern sweep is built and watched fail twice.*** Bound only the raises and the mixed tick sends two records where four were owed; give each kind a cap of its own and one tick sends five against a bound of four. The announced state is a field on the row for the same reason the `q` byte is, and the same split applies — a clear marked away on a record nobody wrote is lost on the row that is about to be released, where nothing can recover it. **Deriving rather than queueing buys one thing worth naming:** a protection that trips and releases between two ticks, with the client still holding `active`, owes *nothing*. The difference cancels, where a queue would carry two records saying it ended and returned on a link that is metered.

**Building it found a hole in P-212.** The rule named `VChange` key 3 only, because `0x0502` carries no array and read as a different kind of record — but the cap sends **one** record for a row that goes `active` → `acked` → `latched_cleared` inside a tick, and a `prev` taken from the last state held names `acked`, which is a state no client was ever sent. P-212 and both field lists say *last announced* now.

***The presence sweep is built, and the blocker it was parked on turned out to be the wrong question.*** It was recorded here as *there is no `presence` metric kind, so no such signal can be registered and there is nothing to compare an announced byte against*. True, and beside the point: **P-182 binds the event, not the reading.** The sweep needs a device's presence and a way to notice it moved, and neither of those requires presence to be a stored signal. Publishing it at `(dev, cmp 0)` so a client can `Sel` it is a different piece — it needs the metric kind, and it needs the store to accept a `derived` provenance, which `Sample::read` refuses today.

**Presence is derived from the store rather than timed, and that is what makes it impossible to contradict.** A device is `online` when at least one signal behind it is current, `never_seen` when nothing behind it has ever been written, and `offline` otherwise. *Current* is already `Freshness`, per signal, set by whoever commissioned the site — so there is no second threshold to defend and no second clock to disagree with the signals. A device reading `online` while every signal behind it is stale would be a well-formed, MAC'd contradiction, and deriving one from the other is the only way to be sure it cannot happen.

**`degraded` is not produced, and it is not a rate.** It means the device answered *badly* — an exception response, a short frame, a bad CRC — which is a fact about an answer that only the driver sees. Making it a rate would fold bus flakiness back into presence, which is the conflation the *Communication health* row exists to prevent, and it would say in a coarser way what the signals already say with an age. The producer lands with the driver work.

*One limitation is worth writing down because it is the store's shape rather than this derivation's:* **an absence does not age.** A probe written once as `sensor_fault` reads `sensor_fault` in April, so a device whose every signal is an absence reads `offline` even while it is answering. `ok` is the only validity carrying recency, so it is the only one presence can ask. That errs toward *you cannot get a current reading from this*, which is the true half, and the signals carry the rest.

**9. `ReadHistory 0x10` / `0x90`,** with the bucket counter in FRAM, the per-bucket sample count and `src`, the cursor, and P-156's truncation at both `since` boundaries.
*Watch it fail:* four. Ask for a day of a signal stored at quarter-hours and assert the aggregate matches P-195's rule for its `(vtype, domain)` — then change a lifetime counter's rule from *last* to *mean* and watch a day's energy come back at a quarter of itself, which is the one wrong number on this path that renders cleanly and makes a site look like it is producing less than it is. Take the controller off for three days across the window and assert the response stops at the gap with `stopped = 3`, that `next` names the far side, and that `at` + k × bucket dates every returned point correctly — under a *closed-bucket* index it will not, and nothing else in the suite can see that. Then set `DeviceRow.since` mid-window and assert the response stops there with `stopped = 1` and a `next` that resumes past the seam; then set `ComponentRow.since` mid-window on a different signal and assert `stopped = 2`, because one stop reason covering both seams was what an earlier draft had and it cannot tell a swapped charger from a rewired circuit — an assertion that could not be written while key 5 pinned the length to the request's `count`. Then delete the truncation and watch a series run straight across two instruments. Add a vector with a reset in bucket 3 of 20, which is asymmetric under a reversed bit order and is the only kind of bucket that catches P-184 being read backwards.

**10. `Command 0x08` target, `cmds` enforcement, outcomes 7 and 8.** Nothing actuates — commands are still reserved — but the refusal path is real and testable. PROTOCOL.md gains the two outcomes and P-166 in this commit, which is what keeps `every_live_number_is_reachable` green.
*Watch it fail:* compose a command under `rev = N`, bump `rev`, send it, and assert outcome 7 before any handler runs. Aim a `start generator` at a tank component and assert outcome 8. Send `0x0203 acknowledge concern` at dev 0 / cmp 0 and assert it is **accepted** — under the earlier rules it was refused on every reading, which is the shape of a design refusing its own new command.

**11. The six fixtures as integration tests.** Each one `include_str!`s `vectors/v1.json` and drives the public API — never a hex string retyped into the module it is meant to check. Fixture 1 asserts the aggregate is not double-counted; 2 that L-N and L-L are distinguishable and `control owner` is read rather than inferred; 3 that **pack 2's half-string is pinned to `ebase = 17`**, that the concern on its cell 23 carries `elem = 7` and renders as 23, and that one bad cell does not blank the other fifteen; 4 that the start battery is a typed role and not a label string; 5 that the merged circuit's two legs roll up exactly once; 6 that a module going offline does not move `rev` and a module arriving does.
*Watch it fail:* move `vectors/v1.json`. Every one of these must go red. Fixture 3's `ebase` is the load-bearing detail — at the default `ebase = 1` the two readings of P-178 both return 7 and the committed vector cannot diverge, so the fix would be untested and would look tested.

**Fixture 3's `ebase` half has landed**, and what it needed first was a **reader**: nothing in `km43` took a descriptor row apart, so P-206 could be encoded and published and still have nothing to drive it. `RowSlots::decode` walks the same field table the encoder walks, in the other direction, and `p_206_the_published_element_position_reads_as_the_cell_the_published_row_labels` reads the concern page and the `signal_series` row out of `v1.json` and joins them.

The row is new to the vectors, and its absence was the gap: `concerns_0x8F` published *element 7 of signal 204* and nothing published said what signal 204's elements are called, so the two numbers met only in a sentence in `rows_readable`. Prose is what P-206 exists because somebody implemented from. What is left of fixture 3 is the other clause — one bad cell not blanking the other fifteen — which is a `Readings 0x8E` question and waits on the reading plane.

**Between step 3 and step 4, and again after step 10: `cargo size` on `o89-fw`, recorded in the commit message.** Flash is the budget on this part, three of four candidate designs reported RAM and called it the budget, and an estimate nobody measured is exactly the class of number this repo has caught twice.
