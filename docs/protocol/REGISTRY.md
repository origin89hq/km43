---
title: Protocol number registry
description: The authoritative allocation of every KM43 code space, message type, outcome, and capability.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

# KM43 — number registry

<p class="o89-doc-kicker">KM43 / numeric authority</p>

<p class="o89-doc-deck">Every message type, field, outcome, capability, metric, and event gets one permanent number here before an implementation is allowed to use it.</p>

<dl class="o89-doc-facts">
  <div>
    <dt>Source</dt>
    <dd><code>protocol.toml</code> and generated tables</dd>
  </div>
  <div>
    <dt>Allocation rule</dt>
    <dd>Reserve the number before writing code</dd>
  </div>
  <div>
    <dt>Lifecycle</dt>
    <dd>Live, reserved, withdrawn, or retired</dd>
  </div>
  <div>
    <dt>Vendor range</dt>
    <dd><code>0xF000–0xFFFF</code> for metric and event kinds</dd>
  </div>
</dl>

<nav class="o89-doc-links" aria-label="Related KM43 documents">
  <a href="/km43/specification/">Specification <span aria-hidden="true">→</span></a>
  <a href="/km43/protocol-map/">Visual map <span aria-hidden="true">→</span></a>
  <a href="/km43/deferred/">Deferred schemas <span aria-hidden="true">→</span></a>
</nav>

<p class="o89-doc-section-label">Allocation rules</p>

A number is allocated here before it appears in any implementation. Two people
picking `0x0503` independently produce two firmwares that disagree about what a
generator is doing, and the disagreement is invisible until one of them is at a
site. The collision must surface in the pull request that allocates the number,
not on the wire.

**Retired numbers stay in the table**, marked retired, with the date and the
reason. Deleting the row is how a number gets reused by somebody who never knew.

**Reserved ranges.** `0xF000`–`0xFFFF` is reserved for vendor and experimental
use in the **metric-kind and event-kind** spaces, and will never be allocated
here. A device may emit one, and a client shows that channel or that record as
*unrecognised* and keeps the rest of the message.

**Skip what you cannot name; reject what you cannot act on.** Those two spaces
are labels on data — not knowing a metric kind costs one row on a screen. Every
other number in this file is a value something decides on, and there the rule is
P-014 in [PROTOCOL.md](../PROTOCOL.md): an unrecognised discriminant is error 1,
with no vendor range and no `0 = unknown` to fall back to. P-019 is the carve-out
by *space* and it names these two and no others; P-125 is the carve-out by
*position*, and it is the one place a discriminant is not in a discriminant
field — the three metric kinds below whose key 3 is an answer rather than a
measurement.

| Space | An unrecognised value is |
|---|---|
| Metric kinds, event kinds | **skipped** — that one `Value` or `Event` is surfaced as unrecognised, the rest of the message stands |
| Quality | **rejected** — a reading whose trustworthiness cannot be named is not a reading |
| Generator state, generator selector, boot reason | **skipped for that one channel** — P-125, and it is the second carve-out: an answer nobody can name is not rendered, and the `Snapshot` around it stands |
| Command, SetConfig, Pair, Firmware and Time outcomes | **rejected** — a client that cannot tell *accepted* from *inhibited* has learned nothing |
| Client kinds, time sources, config sections, error codes | **rejected** |

What separates the first row from the rest is the difference between the label on
a quantity and the answer to a question. *Generator state* is the label, and a
client that does not hold metric `0x0501` can say *there is a channel here I
cannot name* and be honest.
*The generator is in state 6* is the answer, and a client that renders an answer
it cannot read is the room card showing 0.0 °C all over again.

Status column, and the four are genuinely different things:

| Status | The number is | May it be emitted? |
|---|---|---|
| **live** | allocated and fully specified | Yes |
| **reserved** | allocated; its **body or argument schema** is deferred, see [DEFERRED.md](DEFERRED.md) | **Yes, where a normative rule requires it** — but a receiver must not depend on the body's contents, because the body is what is deferred |
| **withdrawn** | allocated; the condition it named is answered somewhere else now | No. Nothing emits it, and the number is not free |
| **retired** | was used, and is gone forever | No |

**`reserved` is not `withdrawn`, and conflating them was a real bug.** An earlier
revision defined `reserved` as "nothing may emit it", which quietly forbade three
things the specification requires: the `records dropped` event that explains a
hole in `seq`, the `time set` event that records which source moved the clock,
and the comms-processor lifecycle events LINK.md leans on. All three have
allocated kinds whose *bodies* are deferred — the number is emittable, the schema
is not yet written. A status that forbids a MUST is a status that is wrong.

---

## BLE GATT identifiers

Private UUIDs in canonical text form. Discover handles by UUID on each connection;
see PROTOCOL.md's BLE GATT section for properties and byte order. The table
also carries the shared envelope budget and BLE transport limits.

| Name | Value |
|---|---|
| `BLE_SERVICE_UUID` | `ab43e89a-7c21-4a5d-9b62-19e430000001` |
| `BLE_RX_UUID` | `ab43e89a-7c21-4a5d-9b62-19e430000002` |
| `BLE_TX_UUID` | `ab43e89a-7c21-4a5d-9b62-19e430000003` |
| `BLE_LAST_FLAG` | `0x80` |
| `BLE_INDEX_MASK` | `0x7f` |
| `MAX_PAYLOAD` | `1024` |
| `BLE_MIN_MTU` | `23` |
| `BLE_MAX_MTU` | `517` |
| `BLE_MAX_VALUE` | `512` |
| `BLE_TIMEOUT_MS` | `5000` |
| `BLE_TX_CAPACITY` | `1` |

## WebSocket discovery

Where a client reaches the WebSocket transport on the site network; see
PROTOCOL.md's WebSocket section, P-223 to P-225. The service type is declared
in the iOS app's `NSBonjourServices`, so renaming it strands every installed app.

| Name | Value |
|---|---|
| `WS_PORT` | `80` |
| `WS_PATH` | `/km43` |
| `DNSSD_SERVICE` | `_km43._tcp` |
| `DNSSD_TXT_DEVICE_ID` | `id` |

## Message types — `u8`

The high bit means *response to a request*. `Event` is the only unsolicited
message.

`0x60`–`0x7E` is the link-local range from [LINK.md](LINK.md), whose responses
are `0xE0`–`0xFE` — the same high-bit rule, so nothing special has to be
remembered. `0x7F` is deliberately left out of the range, because `0x7F` with
the high bit set is `0xFF`, which is Error: 31 requests against 31 responses is
a rule that stays true, and a 32nd request whose response is somebody else's
opcode is a trap for whoever allocates last. A link-local type arriving on a
client-facing transport is error `257`, not error `2`: it is a routing bug in the
comms processor, not a client sending nonsense, and the two want different
investigations.

**The two auth columns are one column in disguise, and splitting them is the
point.** A request and its response are not always authenticated the same way:
a `Time` request is `signed` and its response is `sealed`, and `Enrol` goes out
as the last handshake message and comes back `pair_sealed`, under keys that are
not a session's. A single column covered both while agreeing with the spec only
by luck. The values are `none` (P-054), `handshake` (P-057), `pair_reply`
(P-241), `pair_sealed` (P-064), `sealed` (P-231), `signed` (P-053), `link` and
`sealed_or_bare` (P-142), and `protocol.toml` refuses to parse any other.

| Request | Response | Name | Auth (request) | Auth (response) | Since | Status |
|---|---|---|---|---|---|---|
| `0x00` | `0x80` | Discover | `none` | `none` | 1.0 | live |
| `0x01` | `0x81` | Hello | `handshake` | `handshake` | 1.0 | live |
| `0x02` | `0x82` | Snapshot | `sealed` | `sealed` | 1.0 | retired |
| `0x03` | `0x83` | Subscribe | `sealed` | `sealed` | 1.0 | live |
| — | `0x04` | Event | — | `sealed` | 1.0 | live |
| `0x05` | `0x85` | ReadLog | `sealed` | `sealed` | 1.0 | live |
| `0x06` | `0x86` | GetConfig | `sealed` | `sealed` | 1.0 | live |
| `0x07` | `0x87` | SetConfig | `signed` | `sealed` | 1.0 | live |
| `0x08` | `0x88` | Command | `signed` | `sealed` | 1.0 | reserved |
| `0x09` | `0x89` | Firmware | `signed` | `sealed` | 1.0 | reserved |
| `0x0A` | `0x8A` | Time | `signed` | `sealed` | 1.0 | live |
| `0x0B` | `0x8B` | Pair | `handshake` | `pair_reply` | 1.0 | live |
| `0x0C` | `0x8C` | Goodbye | `sealed` | `sealed` | 1.0 | live |
| `0x0D` | `0x8D` | Inventory | `sealed` | `sealed` | 1.0 | live |
| `0x0E` | `0x8E` | Readings | `sealed` | `sealed` | 1.0 | live |
| `0x0F` | `0x8F` | Concerns | `sealed` | `sealed` | 1.0 | live |
| `0x10` | `0x90` | History | `sealed` | `sealed` | 1.0 | reserved |
| `0x11` | `0x91` | WifiScan | `sealed` | `sealed` | 1.0 | live |
| `0x12` | `0x92` | WifiStatus | `sealed` | `sealed` | 1.0 | live |
| `0x13` | `0x93` | Enrol | `handshake` | `pair_sealed` | 1.0 | live |
| `0x14` | `0x94` | Vouch | `sealed` | `sealed` | 1.0 | live |
| `0x15` | `0x95` | Invite | `signed` | `sealed` | 1.0 | live |
| `0x16` | `0x96` | Approve | `signed` | `sealed` | 1.0 | live |
| `0x17` | `0x97` | Remove | `signed` | `sealed` | 1.0 | live |
| `0x18` | `0x98` | Clients | `sealed` | `sealed` | 1.0 | live |
| `0x60`–`0x7E` | `0xE0`–`0xFE` | *link-local, see [LINK.md](LINK.md)* | — | — | 1.0 | live |
| — | `0xFF` | Error | — | `sealed_or_bare` | 1.0 | live |

`GetConfig` and `SetConfig` are **live**: the four messages are settled, and so
are the bodies of the two sections marked live under **Config sections** below.
A section still marked reserved there has a number and no field list, and a
client must not depend on the contents of one — see
[DEFERRED.md](DEFERRED.md) entry 9.

`Pair` and `Enrol` carry the pairing handshake, `Noise_XXpsk0`, under the
pre-shared key P-088 derives from `printed_secret`; `Hello` carries the session
handshake, `Noise_IK`, against the controller key the client pinned (P-226).
Everything after a handshake is sealed (P-231). The printed secret derives two
pairing keys and nothing else, so a photographed label is a way to ask for a
slot while somebody holds the window open, never a way into one that exists.

`Goodbye` exists because a session table with no way to empty it locks every
client out after eight reconnections inside the expiry window. It is not
politeness; it is the difference between a browser refresh working and not.
---

## Error codes — `u16`

What `Error 0xFF` carries, for a request that never reached its handler. A
handler's own refusal is an outcome in its response instead (P-141).

| Code | Meaning | Sealed? | Status |
|---|---|---|---|
| 1 | Malformed frame | no | live |
| 2 | Unknown message type | no | live |
| 3 | Protocol major mismatch | no | live |
| 4 | Hello required first | no | live |
| 5 | Payload too large | no | live |
| 6 | Unknown section | yes | live |
| 7 | Busy — retry | yes | live |
| 8 | Session table full | no | live |
| 9 | Session expired | no | live |
| 10 | Authentication failed | no | live |
| 11 | Counter not fresh | yes | retired |
| 12 | Unknown client | no | live |
| 13 | Pairing window closed | no | withdrawn |
| 14 | Stale challenge — reconnect and retry | no | live |
| 15 | Snapshot exceeds channel cap | yes | withdrawn |
| 16 | Not permitted on this transport | no | withdrawn |
| 17 | Clock not set | yes | withdrawn |
| 18 | Challenge unavailable | no | live |
| 19 | Unsupported suite | no | live |
| 20 | Role not permitted | yes | live |
| 256–511 | *link-local, see [LINK.md](LINK.md)* | no | live |

**13, 15, 16 and 17 are withdrawn, not live**, because nothing produces them.

**13** because P-241 answers a `Pair` arriving with no window open with `Pair
0x8B` outcome 2 `window_closed`, tagged under a key the label derives. That is
P-141 doing its job: a refusal the comms processor can forge is a refusal that
sends somebody back to the panel to press a button that was never needed.

**15** because P-090 refuses an over-cap configuration at write time with
`SetConfigAck` outcome 5 `exceeds_cap`. Nothing builds an over-cap `Snapshot` to
refuse — the failure lands on the person editing config rather than on a client
at 2 a.m.

**16** because there is no per-transport permission policy yet — that is
[DEFERRED.md](DEFERRED.md) entry 4 — and the only signal a controller has about
which transport a client arrived on is a field the comms processor writes, which
is the one party the boundary exists to distrust.

**17** because no rule in [PROTOCOL.md](../PROTOCOL.md) or [LINK.md](LINK.md)
raises it. A controller whose clock has never been set does not refuse anything:
P-093 omits `at`, and P-092's `stale` simply stops being expressible until the
first `Time` write. There is nothing left for a refusal to say.

All four numbers are held so nobody else takes them. They are retired-adjacent
rather than free — each one had a rule pointing at it once, and reusing a number
somebody's early implementation may already have emitted is the collision this
file exists to stop. Each stays unemitted until a rule says what refuses what.

This table allocates a *meaning*. The rule that produces a code lives in
[PROTOCOL.md](../PROTOCOL.md) or [LINK.md](LINK.md), and a condition those
documents describe without naming a code here is a bug in them: two
implementations will pick different numbers for the same refusal and neither is
wrong.

**The sealed column is the receiver's rule, not the sender's.** It says which
codes a receiver refuses to read out of a bare `Error` body — a bare error 6 or
11 is discarded, not acted on. What shape a sender emits is P-142's question and
is answered by whether that sender holds a session, never by looking a code up
here. One column, one meaning, or the two tests disagree in exactly the case that
matters: a session the controller has already dropped.

Link-local codes start at **256** so a client can tell *the link failed* from
*your request failed*. Three of them reach a client on purpose: **257** (it sent
a link-local type), **258** (it connected before the two firmwares had exchanged
`LinkUp`) and **259** (its handle is gone, which is what a controller reboot
looks like from the outside). All three mean *reconnect*, and none is sealed, so
the rule below applies to them like any other unauthenticated error. The rest —
**256** and **260**–**264** — never leave the UART, and one of those in a
client-facing frame is wrong on sight.

**An unauthenticated error is a hint, never a fact.** The comms processor can
forge every `no` row above. A client may retry or reconnect on one; it must never
render one as a statement about the site, and it must never conclude from error
`9` that its own writes did not land — that is what the log is for.

---

## Metric kinds — `u16`

Every metric carries a **unit** and a **scale**, and the value on the wire is an
integer. There is no FPU on the target, and a scaled integer cannot disagree
with itself the way a float rounded by two languages can.

`value = wire_integer × 10^scale`, in the stated unit.

**A metric kind and an event kind can be the same number, and fourteen of the
twenty event kinds are.** `0x0604` is *log ring utilisation* here and *time set*
in the event table; `0x0301` is *ambient temperature* here and *behaviour
decision* there. Nothing on the wire is ambiguous — a metric kind appears only in
`Value.kind`, an event kind only in `Event.kind` and `LogEntry.kind`, and no field
takes both — so this is a trap for a person rather than for a decoder: somebody
greps `0x0604`, finds one row, and writes it into the wrong table. That is the
exact mistake this file exists to catch, sitting inside the file itself.

The two spaces are **not** renumbered onto disjoint prefixes. It would buy a
decoder nothing, cost half of both spaces, and retire twenty numbers that four
documents and the vector file already name in prose — and a renumber applied here
and not in [LINK.md](LINK.md) is precisely the collision the allocation rule
exists to stop. What is required instead is a habit with teeth: **prose naming one
of these numbers says which space it is in** — *metric `0x0604`*, *event
`0x0604`* — and a bare number in a sentence about kinds is a bug in that sentence.

P-019's vendor range `0xF000`–`0xFFFF` spans both spaces on purpose. It is the
same rule in each — surface that one carrier as unrecognised, keep the rest of the
message — so it needs one range and not two.

### `0x01xx` — DC electrical

| Kind | Name | Unit | Scale | Status |
|---|---|---|---|---|
| `0x0101` | DC voltage | V | −3 | live |
| `0x0102` | DC current (+ into the component) | A | −3 | live |
| `0x0103` | DC power (signed) | W | −1 | live |
| `0x0104` | state of charge | % | −1 | live |
| `0x0105` | battery temperature | °C | −1 | retired |
| `0x0110` | PV array voltage | V | −3 | retired |
| `0x0111` | PV array current | A | −3 | retired |
| `0x0112` | PV array power | W | −1 | retired |
| `0x0120` | load current | A | −3 | retired |
| `0x0121` | load power | W | −1 | retired |
| `0x0130` | start battery voltage | V | −3 | retired |

**Battery current is signed**, and that is the whole point of it. A PZEM-017
reports current as unsigned and therefore cannot fill this slot at all — it
cannot tell 40 A into the bank from 40 A out of it. A source that cannot
distinguish direction does not implement this measurement, even if it exposes an
ampere value.

### `0x02xx` — AC electrical

| Kind | Name | Unit | Scale | Status |
|---|---|---|---|---|
| `0x0201` | AC voltage | V | −1 | live |
| `0x0202` | AC current | A | −3 | live |
| `0x0203` | AC power | W | −1 | live |
| `0x0204` | AC frequency | Hz | −2 | live |
| `0x0205` | AC energy | Wh | 0 | live |
| `0x0206` | AC energy imported | Wh | 0 | reserved |
| `0x0207` | AC energy exported | Wh | 0 | reserved |

**AC frequency** is the discriminator that proves an engine caught. Current into
the bank is also what the sun does; 120 V at 60 Hz is not.

### `0x03xx` — temperature

| Kind | Name | Unit | Scale | Status |
|---|---|---|---|---|
| `0x0301` | ambient temperature | °C | −1 | retired |
| `0x0302` | temperature | °C | −1 | live |

### `0x04xx` — level

| Kind | Name | Unit | Scale | Status |
|---|---|---|---|---|
| `0x0401` | tank level | % | −1 | live |
| `0x0402` | tank sender current | A | −6 | live |

### `0x05xx` — generator

| Kind | Name | Unit | Scale | Status |
|---|---|---|---|---|
| `0x0501` | generator state (enum, see below) | — | 0 | live |
| `0x0502` | generator run hours | h | −2 | live |
| `0x0503` | generator starts since commissioning | count | 0 | live |
| `0x0504` | run contact commanded (bool) | — | 0 | live |

### `0x06xx` — controller

| Kind | Name | Unit | Scale | Status |
|---|---|---|---|---|
| `0x0601` | generator selector position (enum, see below) | — | 0 | live |
| `0x0602` | uptime since boot | s | 0 | live |
| `0x0603` | last boot reason (enum) | — | 0 | live |
| `0x0604` | log ring utilisation | % | −1 | live |

---

## The three spaces inside a metric

`0x0501`, `0x0601` and `0x0603` carry an **answer** in a `Value`'s key 3 where
every other metric carries a measurement. P-125 is the rule that follows from
that, and it is the one place in the protocol where a discriminant is not in a
discriminant field: a value here that a client cannot name is surfaced as
unrecognised **for that one channel** and never rendered as a state, while the
`Snapshot` around it stands.

They were three sentences of prose under the tables above until a client had to
decide what an unrecognised one means. A number a reader has to parse out of a
sentence is a number the bindings cannot be generated from, which is the whole
argument for this file.

## Generator states — `u8`

The value of metric `0x0501`: what the generator is doing.

| Value | Name | Meaning |
|---|---|---|
| 1 | stopped | No AC and our contact open. Autostart may fire |
| 2 | starting | Our contact closed, no AC yet. Gives up after the start window |
| 3 | running | AC present with our contact closed. Ours, and ours to stop |
| 4 | running, not ours | AC present with our contact **open** — somebody started it with the fob. Not a fault, and never rendered as one |
| 5 | stop not honoured | Our command was withdrawn and the AC persists. Notify; never retry |
| 6 | gave up | Commanded to run and it did not, as many times as the starter is worth. The contact stays open and nothing here will try again until a person clears it — out of fuel, an oil-alert shutdown and a flat start battery are indistinguishable from the controller, and hammering a start line into any of them is wrong |

The state model is two facts: is there AC, and is our contact closed. `4` is the
row that matters: somebody started it with the fob, and closing our contact on
top of that converts *the fob owns it* into *both own it*, after which the
human's stop button does not work.

## Generator selector — `u8`

The value of metric `0x0601`: where the auto / off / manual selector is.

| Value | Name | Meaning |
|---|---|---|
| 1 | auto | Behaviours may command the generator |
| 2 | off | Never command it, for any reason. A behaviour that needs it reports itself `inhibited` |
| 3 | manual | The operator is driving. The controller monitors and logs only |

Named for what it selects, because `SelectorPosition` on its own is a client
rendering three positions of something without knowing what they govern. It is
also a different thing from the lockout switch at the genset: that one is a
service lockout — nothing cranks while somebody's hands are in there — and this
one is an operator override, at the controller.

## Boot reasons — `u8`

The value of metric `0x0603`: why the controller last started.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | power | Power-on, power-down or brown-out. The controller reports all three with one flag and cannot tell them apart | live |
| 2 | watchdog | The independent watchdog fired | live |
| 3 | brown-out | Folded into 1: the flag that reports a brown-out also reports a power-on | retired |
| 4 | software reset | A reset the image asked for, with no panic before it | live |
| 5 | panic | The image panicked and reset itself | live |
| 6 | pin reset | The reset pin, with no power flag beside it | live |
| 7 | option-byte reload | The option bytes reloaded, which is how the controller swaps its image banks | live |
| 8 | window watchdog | The window watchdog fired | live |
| 9 | low-power entry | An illegal entry into a low-power mode | live |

Eight situations the controller can tell apart. `1 power` is power-on,
power-down and brown-out together, because one flag reports all three; `3` was
brown-out and is retired rather than reused. A generator that was running through
one of them is another situation again — the log record carries that, not this
metric. The boot record `0x0601` carries this value in its key 1.

---

## Quality — `u8`

How far a reading can be trusted, in one word.

| Value | Name | Meaning |
|---|---|---|
| 1 | measured | Read directly from an instrument |
| 2 | counted | Integrated or accumulated, and trustworthy as a total |
| 3 | estimated | Derived from something else, e.g. SoC from terminal voltage |
| 4 | stale | Was measured, is no longer current: older than its channel's maximum age, or the same reading for so long that the instrument is presumed hung |
| 5 | absent | No reading. **The value key is omitted entirely** |

A behaviour that needs a *counted* figure refuses an *estimated* one. This is
the founding rule of the project and the reason `5` exists rather than a zero.

---

### `0x07xx` — charger stage durations

How long a charger has spent in each stage. Quantities, not a `point` on one kind.

| Kind | Name | Unit | Scale | Status |
|---|---|---|---|---|
| `0x0701` | time in bulk | min | 0 | reserved |
| `0x0702` | time in absorption | min | 0 | reserved |
| `0x0703` | time in float | min | 0 | reserved |

## Event kinds — `u16`

What an `Event` or a `LogEntry` records, in its `kind` key.

**This is a different space from the metric kinds above, and fourteen of the
twenty numbers below are also a live metric kind.** `0x0201` is *generator state
changed* here and *AC voltage* there. Nothing decodes ambiguously — the two never
meet in one field — but a sentence that says `0x0201` without saying which space
it means is a sentence somebody implements backwards. Say *event `0x0201`*. The
argument for leaving the numbers overlapping is at the head of the metric table.

| Kind | Name | Class | Status |
|---|---|---|---|
| `0x0101` | value changed | B | retired |
| `0x0102` | signal validity changed | A | live |
| `0x0201` | generator state changed | A | reserved |
| `0x0202` | generator command withdrawn | A | reserved |
| `0x0203` | generator stop not honoured | A | reserved |
| `0x0301` | behaviour decision (shadow or applied) | A | reserved |
| `0x0302` | behaviour inhibited | A | reserved |
| `0x0401` | output changed | A | reserved |
| `0x0501` | concern raised | A | live |
| `0x0502` | concern changed | A | live |
| `0x0601` | boot | A | live |
| `0x0602` | config changed | A | reserved |
| `0x0603` | client enrolled | A | live |
| `0x0604` | time set | A | live |
| `0x0605` | client removed | A | live |
| `0x0606` | invite proposed | A | live |
| `0x0701` | records dropped | A | reserved |
| `0x0702` | record failed CRC | A | live |
| `0x0801` | comms link lost | A | live |
| `0x0802` | comms power cycled | A | live |
| `0x0803` | comms unrecoverable | A | live |
| `0x0804` | sessions shed for backpressure | A | live |
| `0x0805` | comms boot noise | A | live |
| `0x0806` | wifi status changed | A | live |
| `0x0901` | topology changed | A | live |
| `0x0902` | device presence changed | A | live |

Every row is **reserved**, and the reason is the `body` map. The kind numbers
and the classes are settled; not one kind says what is inside its body, so two
implementations can agree on framing, on the cipher and on the sequence number and
still disagree about every event they exchange. The numbers are allocated; the
body schemas are deferred — see [DEFERRED.md](DEFERRED.md).

### Class A and class B

The `Class` column decides which records survive a controller under pressure,
and the two words are defined **here**, normatively, rather than left to a design
document. A column with no definition beside it is a column every implementation
fills in for itself, and the two answers it picks between are *keep this alarm*
and *drop it*. A controller that ranks *alarm raised* below *value changed* loses
the alarm on the busiest day, which is the day it mattered.

**Class A is never dropped — not from the log, and not from a queue.** When the
implementation's bounded global write budget is exceeded on class A alone, the
controller raises a diagnostic instead of shedding: a site
producing that many state changes has something genuinely wrong with it, and the
record of what went wrong is the last thing to throw away. When a session's
`MAX_EVENT_QUEUE` cannot take a class A event, P-098 in
[PROTOCOL.md](../PROTOCOL.md) closes that session and the client reconnects and
catches up with `ReadLog`. That is worse than a delivered event and far better
than a client sitting on a socket it believes is current while an alarm never
reached it.

**Class B is dropped first, under pressure, and every drop is counted.** In the
log it is what the write budget sheds; in a session's outbound queue it goes
oldest first, and the count reaches *that* session in its own *records dropped*
(`0x0701`) record — a log-ring count cannot explain a hole one queue made.
Counted is half the definition and not a detail: a hole in `seq` with no number
attached is the mystery P-097 forbids a client to render as a complete stream.

**Today class B has no members, and the split is a column waiting for one.**
*Value changed* was the only kind whose rate followed a sampling loop rather than
something happening at the site, and it is retired: at nineteen circuits it
overran `MAX_EVENT_QUEUE` every tick, so the hint a client was meant to lean on
was the first thing shed. A value moving is what polling is for. Everything left
in the table is a state change, a command outcome, an alarm, a boot, or a record
about the log itself, and every one of those is a sentence somebody has to be
able to find in April.

The column stays because the next kind that is genuinely sheddable should not
have to reintroduce the idea — but until one is allocated, a conforming
controller sheds nothing anywhere, and the paragraph above describes a path no
input can reach. `o89-core` retired its shedding code with the kind rather than
carry sixty lines no test could turn red.

**A new event kind is allocated with its class, or it is not allocated.** A row
added with the class left blank is a number on the wire before anybody has
decided whether it may go missing.

*Behaviour decision* carries whether the decision was **applied or shadowed**.
While every site runs in shadow, a client that cannot tell a shadowed decision
from an applied one cannot audit the thing the shadow deployment exists to prove.

`0x08xx` is the link to the comms processor. [LINK.md](LINK.md) L-023 and
L-110 through L-112 require the controller to log every one of these — the heartbeat ladder ends in a rail
that stops being cycled — and had no numbers to log them under, which is how a number gets
invented at a bench by whoever hit it first. *Comms power cycled* carries the
cycle count, because *three power cycles in an hour, cycling stopped* is a sentence
somebody has to be able to read at a client: a link that goes quiet leaving no
record behind looks exactly like a site that is fine.

*Sessions shed for backpressure* is the newest of them, and it is allocated
because LINK.md's L-023 requires a class A record for the **first** session shed in an
hour and had no kind to log it under. A comms processor that answers every
heartbeat and drains the UART slowly closes all eight sessions without forging a
byte or dropping a frame, and the shed record is the only trace it leaves — *the
link is up and carrying nothing* is otherwise a state the untrusted peer can
drive at will with nobody able to name it afterwards. It is class A for the same
reason: it is the evidence, so it is the one record that must not be shed by the
pressure it describes. *Comms link lost* (`0x0801`) stays the escalation at three
in an hour; `0x0804` is the first occurrence.

**A clock that jumps is not a fourth kind.** LINK.md's L-160 logs a step of more than
five seconds in `0x0604` `time set`, carrying the old value alongside the new and
the source that set it. One clock change is one record. Splitting it into a
routine kind and a jumped kind gives a client two things to reconcile and gives
whoever is asking *did the schedule fire twice on Tuesday* two places to look.

---

## Config sections — `u16`

Which part of the configuration a `GetConfig` or `SetConfig` names in its
`section` key.

| Section | Name | Status |
|---|---|---|
| `0x0001` | identity and site | live |
| `0x0002` | channels | reserved |
| `0x0003` | buses and devices | reserved |
| `0x0010` | generator behaviour | reserved |
| `0x0011` | frost behaviour | reserved |
| `0x0012` | schedule behaviour | reserved |
| `0x0013` | load-shed behaviour | reserved |
| `0x0020` | network | live |
| `0x0021` | cloud | reserved |

The two **live** rows have bodies, defined in [PROTOCOL.md](../PROTOCOL.md)
under *Section bodies*: identity and site, and the network. The **reserved** rows
have a number and no field list — a client can ask for `0x0011` and be told it
exists — and their bodies are open in [DEFERRED.md](DEFERRED.md) entry 9. The
behaviour sections among them already share one settled key, `shadow`, in the
table below.

The **network** and **cloud** sections hold credentials — the site's Wi-Fi
passphrase among them, because the controller holds the master copy and
[LINK.md](LINK.md) says why. **A field marked `secret` is never returned in a
`Config` body** (P-106), which every enrolled client can ask for, the cloud client
included; the body says whether the field is set under a key of its own. Anybody
drafting the cloud section from this table alone would write the leak straight
back in.

---

## Behaviour section keys — `u16`

The keys all four behaviour sections, `0x0010` to `0x0013`, carry under one
number (P-103). A key only one behaviour reads belongs to that section's body,
not here.

| Key | Name | Status |
|---|---|---|
| 1 | shadow | live |

`shadow` is readable by a client so that "nothing is actuating" is a thing a
person can confirm rather than believe, and it is one number because a `shadow`
that meant key 9 for frost and key 4 for the generator is a flag somebody reads
wrong exactly once. It is not capability bit 7: that bit says *some* behaviour is
in shadow, site-wide, and cannot say which.

---

## Command kinds — `u16`

**Reserved, not specified.** No actuation until a controller is granted authority
over an output — see [DEFERRED.md](DEFERRED.md). The space is allocated now so
that nothing squats on it in the meantime.

| Kind | Name | Status |
|---|---|---|
| `0x0101` | start generator | reserved |
| `0x0102` | stop generator | reserved |
| `0x0103` | run exercise cycle now | reserved |
| `0x0201` | set output | reserved |
| `0x0202` | clear alarm | retired |
| `0x0203` | acknowledge concern | reserved |
| `0x0301` | clear override | reserved |

Those six names are allocations, not specifications: none has an argument schema
and none may be sent by a client yet. `0x8000`–`0xFFFF` is where bench and
experimental kinds go instead — permanently non-normative, never allocated in
this file, and free to abandon. That is the whole of the squatting rule, and
[DEFERRED.md](DEFERRED.md) entry 8 says when a low number becomes sendable.

There is deliberately **no factory-reset command and no unpair command.** A
compromised cloud that can unpair a controller which starts engines is worth
more to an attacker than any single command. Both require the physical button,
and that is the only way a full client table is emptied.

---

## Command outcomes — `u8`

How a `Command 0x88` answered.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | accepted | Acted on | live |
| 2 | rejected | Refused, `detail` says why | live |
| 3 | duplicate | Already seen this `cmd_id`; not acted on twice | live |
| 4 | inhibited | The selector is at Off, or the generator is not ours | live |
| 5 | unauthorised | This client may not do this | live |
| 6 | shadowed | Would have been accepted; nothing was actuated | live |
| 7 | stale_topology | The `rev` the command was composed under is not current, so `dev` and `cmp` may name something else now (P-166) | reserved |
| 8 | wrong_target | The target does not list this `kind` in its `cmds` (P-166) | reserved |

`4` and `6` are not failures. `inhibited` is the controller declining with a
reason a person can read; `shadowed` is every decision a site makes while it runs
in shadow.

`5` is what the **client capability mask** below produces. A client whose mask
does not carry *send commands* is refused here, inside a sealed response, rather
than with an error the comms processor could have forged — P-141, applied.

## SetConfig outcomes — `u8`

How a `SetConfig 0x87` answered.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | accepted |  | live |
| 2 | stale_version |  | live |
| 3 | invalid |  | live |
| 4 | unauthorised |  | live |
| 5 | exceeds_cap |  | live |
| 9 | staged | Correct, and applied at the next `MIN_REV_INTERVAL_MS` boundary rather than now (P-154) | reserved |

`4` is the capability mask refusing one of two different things: a client that may
not write configuration at all, or a client that may not write **this section** —
a cloud client editing `0x0020 network`. One outcome for both, because from the
client's side there is one thing to do about either, and the section it named is
already echoed back in key 1.

## Pair outcomes — `u8`

How a `Pair 0x8B` answered.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | enrolled | The client's key is in a slot that was free, and `client_id` names it (P-064, P-240) | live |
| 2 | window_closed | No pairing window was open. Answered under the refusal tag after message 1, or in `Enrol 0x93` when the window closed before message 3; never counted as an authentication failure (P-241) | live |
| 3 | bad_proof | A wrong label cannot be answered under a key the client holds, so it is bare error 10 now (P-066) | withdrawn |
| 4 | table_full | No free slot and no slot with this label. Nothing is evicted (P-067, P-240) | live |
| 5 | reclaimed | No free slot, and the lowest slot with a byte-identical label was re-keyed: the old install's key is erased and the generation moves on (P-240) | live |
| 6 | proceed | Message 1 opened, the window is open and there is a slot to allocate; `Pair 0x8B` carries message 2 (P-064) | live |
| 7 | not_stored | The slot could not be written durably, so nothing was enrolled and a class A concern was raised (P-064) | live |

**`5` is what stops the client table being a consumable, and the rules that
produce it are P-078 and P-240 in [PROTOCOL.md](../PROTOCOL.md), not this file.**
Which pairing re-keys an occupied slot, that the `label` comparison is over the
exact UTF-8 bytes `PairOffer` carried, that a free slot is always preferred so a
reclaim never takes a live phone's slot while there is room, that a reclaim now
revokes the old install's key, and why re-keying a slot does not re-open
replay — all of it is there. What this file allocates is the number.

**`6` and `2`, `4` travel in `Pair 0x8B`; the others in `Enrol 0x93`.** `6` is
the only outcome that carries message 2. A refusal after message 1 carries the
tag of P-241 instead, and one decided at message 3 is sealed under the keys the
handshake just split into. `3` is withdrawn: a wrong label is answered with bare
error 10, because the controller cannot tag a refusal under a key the client
holds when it cannot know which label the client used.

**Outcome 5 rather than outcome 1** is the part that belongs here, because it is
the allocation decision: a reclaim silently reported as an enrolment is a row
overwritten with nobody told. The person at the panel needs to read *this
replaced the row called `kitchen phone`*, and the log record needs to say the
same — see [DEFERRED.md](DEFERRED.md) entry 10.

## Time outcomes — `u8`

How a `Time 0x8A` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | accepted | The clock moved, and the `time set` record names who moved it (P-111) |
| 2 | rejected | `at` is past the plausibility window's upper edge. The clock did not move (P-113) |
| 3 | unauthorised | This client's capability mask does not let it set the clock (P-105) |
| 4 | needs_button | `at` is below the monotonic floor. A person at the panel can override it and the client can send it again (P-114, P-116) |

`3` exists because the capability mask can refuse a `Time` write, and *rejected*
would have told a client its clock was implausible when the real answer is that it
is not allowed to set one. Moving the clock moves `schedule`, `exercise` and
`quiet_hours` with it, so *who may* and *is this a sane time* are two questions and
a client that cannot tell them apart retries forever against the wrong one.

`4` splits the same hair one more time. A backward set refused for P-114's floor
is refused for a reason a person can act on — hold the button at the panel and
send it again — and under `2` it was indistinguishable from a time nobody could
believe. A client that cannot tell those apart puts *the controller says that
time is implausible* on the screen while the correction somebody drove four hours
to make sits one gesture away.

## Vouch outcomes — `u8`

How a `Vouch 0x94` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | vouched | The answer carries the epoch, slot, generation and tag of P-244 |
| 2 | bad_verifier | The verifier key is a low-order point, so no tag under it could vouch for anything (P-245) |

`2` is the only refusal because it is the only thing a controller can find wrong
with a vouch request. Whether the nonce is fresh, the binding belongs to the
caller and the generation is the one being linked is the verifier's to check
(P-247), and the controller holds none of the records that would answer it.

## Time sources — `u8`

Who set the clock, recorded as `source` in the `time set` event (P-111).

| Value | Name | Meaning |
|---|---|---|
| 1 | client | A signed `Time` write from an enrolled client |
| 2 | ntp-via-comms | A `TimeOffer` the controller accepted from the comms processor |

**One space for what gets recorded.** P-111's `time set` event records a value
from this table, chosen by which message moved the clock, and there is no second
space it may draw from. A signed `Time` write is `1`; nothing in its body says
so, because key 2 of the `Time` operation, which once carried a value from this
table, is **retired** and never reused (P-012). An accepted `TimeOffer` from
[LINK.md](LINK.md) is recorded as `2` (L-162). That offer carries a `source` field of its
own — a link-local enum with one value in it — and **its number is never copied
through**: `1` there means *NTP*, `1` here means *a client set the clock*, which
is the opposite. The point of recording a source at all is to tell a drifted RTC
from a lying uplink, so a number copied straight across inverts the one thing the
field exists to say.

## Scan states — `u8`

`WifiScan 0x91` key 1: what became of the most recent scan. `complete` always
has a list beside it and `none` never does (P-217).

| Value | Name | Meaning |
|---|---|---|
| 1 | none | No scan has completed since the controller booted, and none is running |
| 2 | running | The controller has asked the comms processor for a scan and holds no answer yet |
| 3 | complete | The most recent scan completed; its list is the one held |
| 4 | failed | The most recent scan was refused, failed or timed out. A list held from before it stays |

`failed` does not clear the list. A person who has just picked a network and
presses refresh again should still see it, with the age saying how old it is.

## Scan refusals — `u8`

`WifiScan 0x91` key 2: why a refresh started nothing. P-218 checks them as
`unauthorised`, `radio_off`, `link_down`, `too_soon`, which is not the order of
the values.

| Value | Name | Meaning |
|---|---|---|
| 1 | too_soon | A scan started less than `SCAN_INTERVAL_MS` ago (P-218) |
| 2 | radio_off | The network section has never been written, so the radio has no country and may not scan |
| 3 | link_down | The comms link is not up |
| 4 | unauthorised | This client's capability mask lacks bit 1 (P-105) |

`radio_off` has a remedy a client can offer: write the network section's
`country` and `hostname` first. `too_soon` has none but waiting, and the list
it answers with is at most ten seconds old.

## Wi-Fi security — `u8`

`Ap` key 3, as the comms processor classified the access point's beacon.

| Value | Name | Meaning |
|---|---|---|
| 1 | open | No passphrase. The network section cannot join it |
| 2 | wpa2_personal | WPA2 with a passphrase, including WPA/WPA2 mixed mode |
| 3 | wpa3_personal | WPA3 SAE with a passphrase, including WPA2/WPA3 transition mode |
| 4 | other | Anything a WPA passphrase does not join: WEP, WPA alone, enterprise, OWE |

The four are what a client does with a row, not every mode a beacon can
advertise: `2` and `3` take a passphrase and the network section can join
them, `1` and `4` it cannot. A closed space refuses an unknown value (P-014),
so `other` is where a mode nobody listed goes rather than a reason to reject
the whole list.

## Wi-Fi bands — `u8`

`Ap` key 4. The channel in key 5 is numbered within the band, and 2.4 GHz and
6 GHz both have a channel 1.

| Value | Name | Meaning |
|---|---|---|
| 1 | ghz_2_4 | 2.4 GHz |
| 2 | ghz_5 | 5 GHz |
| 3 | ghz_6 | 6 GHz |

## Wi-Fi states — `u8`

`WifiStatus 0x92` key 3, `0x0806` key 3 and LINK.md's `WifiState` key 2. One
space for all three, because the controller relays the comms processor's value
and a second numbering would be a translation somebody gets wrong.

| Value | Name | Meaning |
|---|---|---|
| 1 | off | The radio holds no network or no radio metadata and is not trying |
| 2 | joining | Trying, with no outcome yet for this version since the comms processor booted |
| 3 | joined | Associated and holding an IPv4 address |
| 4 | failed | Not joined; `reason` is the most recent failure, and the radio is still trying |

## Wi-Fi failures — `u8`

The reason beside `failed`, in the same three places.

| Value | Name | Meaning |
|---|---|---|
| 1 | auth_failed | The access point refused the passphrase, or the handshake did not complete |
| 2 | not_found | No access point with this SSID was heard on a channel the radio may use |
| 3 | no_ip | Associated, and no address was assigned |
| 4 | lost | Was joined, and the association dropped |
| 5 | other | A failure the radio could not place in the four above |

`auth_failed` is almost always the passphrase, and `not_found` is a mistyped
SSID, an access point out of range, or a 5 GHz-only network the ESP32-C6
cannot hear. Those are the three a person setting up a unit can fix from where
they stand, which is why they are named rather than folded into `other`.

## Firmware outcomes — `u8`

How a `Firmware 0x89` answered. **Reserved** — see [DEFERRED.md](DEFERRED.md).

| Value | Name | Status |
|---|---|---|
| 1 | accepted | reserved |
| 2 | bad_offset | reserved |
| 3 | bad_signature | reserved |
| 4 | wrong_target | reserved |
| 5 | too_large | reserved |
| 6 | no_transfer_in_progress | reserved |
| 7 | not_owner | reserved |
| 8 | unauthorised | reserved |

`7` and `8` are different refusals and were one word covering both. **`7`
`not_owner` is about a transfer**: a `Firmware` operation naming a transfer that
another client began. One image lands at a time, and a second client feeding
chunks into somebody else's transfer is how a half-and-half image gets written and
then fails its signature after the reboot. **`8` `unauthorised` is about the
client**: its capability mask does not carry *push firmware*, and no transfer of
its own would have been accepted either. A client told `not_owner` retries when
the other transfer finishes, which is right for one and a loop for the other.

**Nothing produces `7` yet, and that is a gap in the message bodies rather than
in this table.** No document says how a transfer records which client owns it, so
there is nothing an implementation could compare a second client against. It is
owed by [DEFERRED.md](DEFERRED.md) entry 6 along with the rest of the `Firmware`
field list, and it is named there so the number does not sit here looking
implemented.

## Invite outcomes — `u8`

How an `Invite 0x95` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | proposed | The invite is pending, and `nonce` names it until an owner approves or declines it or it expires (P-252) |
| 2 | unauthorised | This client's role may not propose this role (P-251) |
| 3 | invites_full | The pending-invite table has no row this inviter may take. Nothing is evicted (P-253) |
| 4 | known_key | An occupied slot already holds this key (P-252) |
| 5 | table_full | No row could be allocated to this role now, so an approval would fail (P-258) |
| 6 | no_budget | This admin slot has proposed its limit of invites without an owner approving one (P-254) |

`6` is an admin that has spent its proposals without an owner approving one
(P-254). It is durable and a reboot does not restore it, because it is what
stops a compromised admin phone trying a million controller nonces until one
gives the digits the invitee is reading out.

## Approve outcomes — `u8`

How an `Approve 0x96` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | enrolled | The invitee's key is in a slot, and `confirm` proves the controller wrote it (P-255) |
| 2 | declined | The invite is withdrawn and nothing was enrolled (P-255) |
| 3 | unauthorised | Only an owner approves, and only an owner or the invite's own inviter declines (P-255) |
| 4 | unknown_invite | No live invite has this nonce: it was consumed, it expired, or the controller rebooted (P-253) |
| 5 | inviter_gone | The slot that proposed it no longer holds that enrolment, or its role may no longer propose this role (P-255) |
| 6 | refused | The reveal does not match the commitment, or the proof does not verify. The invite is consumed (P-255) |
| 7 | known_key | An occupied slot already holds this key. The invite is consumed (P-255) |
| 8 | table_full | No row can be allocated to this role. The invite stays pending (P-258) |
| 9 | not_stored | The slot could not be written durably. The invite stays pending and a class A concern was raised (P-255) |

`3` leaves the invite pending, because a sender that may not decide has not
decided anything. `8` and `9` leave it pending because nothing about the invite
was wrong and the owner can free a row or retry. Every other refusal after the
nonce was found consumes it: an invite is good for one decision (P-255).

## Remove outcomes — `u8`

How a `Remove 0x97` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | removed | The enrolment is gone: its sessions are unbound and its generation has moved on (P-256) |
| 2 | gone | That enrolment no longer holds the slot. Nothing changed (P-256) |
| 3 | protected | An owner slot, or a viewer slot for a sender that is not an owner. Nothing changed (P-256) |
| 4 | unauthorised | This client's role may not remove anybody (P-251) |
| 5 | not_stored | The slot could not be written durably and a class A concern was raised (P-256) |

`2` is not a failure. A removal names an enrolment by `client_id` and
generation, and one that finds the slot free or re-keyed has nothing left to
remove; the enrolment it named is already over (P-256).

---

## Client kinds — `u8`

What a client says it is when it enrols: inside `PairOffer` for a label
pairing, and in the `Invite` operation for an invited one. It is shown in the
client list and decides nothing; the role does (P-105).

| Value | Name |
|---|---|
| 1 | app |
| 2 | browser |
| 3 | cloud |
| 4 | cli |

## Suites — `u8`

The key agreement and cipher a pairing or a session runs (P-226). A slot records
the suite it enrolled under and a `Hello` must present exactly that one; an
unknown suite is error 19 before anything else is read.

| Value | Name | Meaning |
|---|---|---|
| 1 | x25519_chachapoly_sha256 | Noise_XXpsk0_25519_ChaChaPoly_SHA256 to pair, Noise_IK_25519_ChaChaPoly_SHA256 for a session |

## Roles — `u8`

What a slot may do, fixed when the slot is written and stored in its key record
(P-239, P-250). The capability mask below is the role's.

| Value | Name | Meaning |
|---|---|---|
| 1 | owner | Paired first in the physical window, or approved as an owner by an owner. Never removed by a message |
| 2 | admin | Everyone else a person enrols. May propose admins and remove admins |
| 3 | viewer | Reads the site and writes nothing. The cloud's identity; only an owner adds or removes one |

## Invite decisions — `u8`

`Approve 0x16` key 2.

| Value | Name | Meaning |
|---|---|---|
| 1 | approve | Enrol the invitee's key |
| 2 | decline | Withdraw the invite |

## Client capability mask — `u16`

A per-client bitfield, the one the slot's role is handed. **P-105 in
[PROTOCOL.md](../PROTOCOL.md) is the rule** — why the role decides and
`client_kind` and `transport` do not, that no message raises or lowers a mask,
and what each refusal is answered with. This file allocates the bits and the
row each role is handed.

It is not a wire discriminant — P-014 does not reach it, and an unallocated bit
is a capability nobody has defined yet, not a value to reject. It is allocated
here because two firmwares that disagree about what bit 4 means disagree about
whether an admin can write the network, which is the same collision as two people
picking `0x0503` and worse in its consequences.

| Bit | The client may | owner | admin | viewer |
|---|---|---|---|---|
| 0 | write configuration at all | yes | yes | **no** |
| 1 | write the **network** (`0x0020`) and **cloud** (`0x0021`) sections, and refresh a `WifiScan` | yes | **no** | **no** |
| 2 | send `Command 0x08` | yes | yes | **no** |
| 3 | set the clock with `Time 0x0A` | yes | yes | **no** |
| 4 | push firmware with `Firmware 0x09` | yes | yes | **no** |
| 5 | read the **network** (`0x0020`) and **cloud** (`0x0021`) sections with `GetConfig`, the scan list with `WifiScan`, and the client table with `Clients 0x18` | yes | yes | **no** |
| 6 | propose an admin with `Invite 0x15`, and remove an admin with `Remove 0x17` | yes | yes | **no** |
| 7 | approve or decline any invite with `Approve 0x16`, propose an owner or a viewer, and remove a viewer | yes | **no** | **no** |
| 8–15 | unallocated | — | — | — |

## Link-local error codes

Errors on the link between the controller and its comms processor, numbered
from 256 so a client can tell *the link failed* from *your request failed*.

Allocated in [LINK.md](LINK.md), which is where the rule for each one lives; L-180 is the rule for the third column.
They are listed here because this file is where a number is handed out, and a
space allocated somewhere else is a space two people can allocate from.

Three of them reach a client on purpose and six never do. That distinction is
the reason they are a separate space from the client error codes rather than a
continuation of them: a client that cannot tell *the link failed* from *your
request failed* retries against the wrong thing.

| Code | Meaning | Reaches a client? |
|---|---|---|
| 256 | Unknown link-local opcode, or one sent from the wrong side | no |
| 257 | Link-local type on a client transport | **yes** |
| 258 | Client frame before LinkUp completed | **yes** |
| 259 | Unknown connection handle | **yes** |
| 260 | Connection table full | no |
| 261 | Link protocol major mismatch | no |
| 262 | Too many outstanding link-local requests | no |
| 263 | Link-local type with a non-zero session | no |
| 264 | No authorisation matches this image | no |

Bit 1 is only consulted when bit 0 is set: a client that may not write
configuration cannot write two particular sections of it either.

Which response answers which denial, because those are outcome numbers and
outcome numbers live here. P-105 is what requires every one of them to ride
inside the sealed response rather than inside an `Error` the comms processor could
have forged:

| Refused | Answer |
|---|---|
| `SetConfig`, bit 0 clear — or bit 1 clear on `0x0020`/`0x0021` | `SetConfigAck 0x87` outcome 4 `unauthorised` |
| `Command`, bit 2 clear | `Ack 0x88` outcome 5 `unauthorised` |
| `Time`, bit 3 clear | `TimeAck 0x8A` outcome 3 `unauthorised` |
| `Firmware`, bit 4 clear | `Firmware 0x89` outcome 8 `unauthorised` |

**A client kind added to the table above arrives with its row here in the same
commit** — P-105 refuses enrolment of a kind with no row, and this is the
allocation half of the same rule. A kind with no mask row is a client whose
permissions are whatever the implementer's zero value happens to be, and a
default that opens is the one direction this project never defaults.

**A cloud client keeps bit 2, and that is deliberate.** Telling a generator to
stop from somewhere that is not the site is the whole point of having a cloud at
all, and every command is sealed end to end regardless — a compromised relay cannot
forge one, it can only refuse to carry it. What it does not need is the ability to
re-flash the controller, move the clock under a schedule, or read back the
credentials it forwards. Command authority is separately gated in any case: no
`kind` below `0x8000` is sendable by anybody yet ([DEFERRED.md](DEFERRED.md)
entry 8).

**The failure the `cloud` column closes** is that `Command` 5 `unauthorised`,
`SetConfig` 4 `unauthorised` and `Firmware` 8 were a vocabulary of refusals with
nothing behind them — allocated in this file, produced by nothing, and reading as
implemented to everybody who grepped for them. P-105 says what that left the most
exposed client in the product able to do; this table is where it stops.

The mask granted at enrolment belongs in the `client enrolled` record (event
`0x0603`) when that body schema is written — [DEFERRED.md](DEFERRED.md) entry 10.
*Somebody was enrolled* and *somebody was enrolled and may push firmware* are
different sentences, and only one of them is an audit record.

## Capability bits — `u32`

Returned in the Hello response. A bit set means the controller can do the thing;
a client must not assume an unset bit is a failure, only an absence.

| Bit | Meaning | Status |
|---|---|---|
| 0 | event log readable | live |
| 1 | configuration writable | live |
| 2 | commands accepted | reserved |
| 3 | firmware update accepted | reserved |
| 4 | clock settable by client | live |
| 5 | counted state of charge available | live |
| 6 | AC metering on the generator | live |
| 7 | any behaviour is in shadow mode | live |
| 8 | wifi scan and join status | live |
| 9 | vouch answered | live |
| 10–31 | unallocated | — |

Bit 8 says the controller answers `WifiScan 0x11` and `WifiStatus 0x12`
(P-216). A client that does not see it offers manual SSID entry and nothing
else.

Bit 9 says the controller answers `Vouch 0x14` (P-246). A client that does not
see it cannot link the generation to a site until the controller's firmware is
updated.

Bit 7 is deliberately coarse. A client that wants to know *which* behaviour is
shadowed reads the config sections; the bit exists so an app can put a banner up
without four round trips.

**Bits 1, 2, 3 and 4 are answered per calling session, not per device**: the
controller reports its own capability **and** the calling client's mask. A cloud
client sees *firmware update accepted* and *clock settable by client* clear, and
does not draw a button that can only ever be refused. No new field carries this,
because the Hello response is bound to exactly one `client_id` by construction —
the field that can say it is already in the right place.

Bit 1 is coarser than the mask and stays that way. A cloud client may write
configuration and may not write two sections of it, so it reads bit 1 set and is
still refused with outcome 4 on the network section. A bit here is a claim about
a message type, not about every section that message can name.

---

The topology design's spaces follow. Everything here is `reserved` until the rule that
produces it is written into a document `every_live_number_is_reachable` sweeps.

## Bus transports

What a port physically is. `rs485`, `can` and `ip` are the addressed ones, which is what makes `DeviceRow.addr` required on them and meaningless on the rest.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | rs485 | A two-wire multidrop serial bus; `addr` is required on it (P-189) | reserved |
| 2 | can | CAN, where a device is addressed by node id | reserved |
| 3 | ve_direct | Victron's point-to-point serial; one device per port, so no address | reserved |
| 4 | local_io | The controller's own inputs and outputs | reserved |
| 5 | ip | Ethernet or Wi-Fi, addressed by host | reserved |
| 6 | onewire | 1-Wire, addressed by ROM id | reserved |
| 7 | internal | Inside the controller; nothing physical to unplug | reserved |

## Inventory row kinds

Which of the five descriptor tables a page is paging through.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | buses | `BusRow` | reserved |
| 2 | devices | `DeviceRow` | reserved |
| 3 | components | `ComponentRow` | reserved |
| 4 | signals | `SignalRow` | reserved |
| 5 | parameters | `ParamRow` | reserved |

## Signal shapes

Whether a signal carries one value or `n` of them. The container only — what one value *is* is the value type below.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | scalar | One value | reserved |
| 2 | series | `n` values in one signal, addressed by position | reserved |

## Value types

What a single value is, independent of how many there are. Splitting this from the shape is what lets a series of flags exist: sixteen per-cell balancing bits are one signal, not sixteen.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | gauge | A quantity that moves in both directions | reserved |
| 2 | counter | A running total. It never reverses, which is why a coarse history bucket takes the last constituent and not their sum (P-195) | reserved |
| 3 | enum | One member of the space named by `esp` | reserved |
| 4 | flags | A bitmask over the space named by `esp`; member m is bit m − 1 (P-186) | reserved |

## Signal domains

Which window a value describes. The same quantity at `live` and at `max` are two signals, not one signal read twice.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | live | What it is now | reserved |
| 2 | lifetime | Since the device was made | reserved |
| 3 | since_reset | Since somebody last cleared it | reserved |
| 4 | today | Since local midnight | reserved |
| 5 | yesterday | The previous whole day | reserved |
| 6 | limit_upper | A ceiling the source states it is honouring | reserved |
| 7 | limit_lower | A floor the source states it is honouring | reserved |
| 8 | max | The largest seen over the domain's window | reserved |
| 9 | min | The smallest seen over the domain's window | reserved |

## Sign conventions

Which way is positive, stated on the row rather than assumed from the quantity.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | positive_is_in | Positive flows into the component | reserved |
| 2 | positive_is_out | Positive flows out of it | reserved |
| 3 | magnitude_only | Unsigned; the sign carries no meaning | reserved |

## Measurement points

Where a quantity is measured. Never a charge stage — a stage duration is a quantity and lives in the metric table.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | line to neutral | reserved |
| `0x0002` | line to line | reserved |
| `0x0003` | terminal | reserved |
| `0x0004` | cell | reserved |
| `0x0005` | internal | reserved |
| `0x0006` | ambient | reserved |
| `0x0007` | heatsink | reserved |
| `0x0008` | case | reserved |
| `0x0009` | inlet | reserved |
| `0x000A` | outlet | reserved |
| `0x000B` | transformer | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## Units

What a vendor kind is measured in. Standard kinds carry their unit in the metric table; a vendor kind carries it on the row, and needs a number to carry.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | volt | V | reserved |
| 2 | ampere | A | reserved |
| 3 | watt | W | reserved |
| 4 | watt hour | Wh | reserved |
| 5 | ampere hour | Ah | reserved |
| 6 | degree celsius | °C | reserved |
| 7 | percent | % | reserved |
| 8 | hertz | Hz | reserved |
| 9 | second | s | reserved |
| 10 | minute | min | reserved |
| 11 | hour | h | reserved |
| 12 | count | a plain tally | reserved |
| 13 | ohm | Ω | reserved |
| 14 | pascal | Pa | reserved |
| 15 | litre | L | reserved |
| 16 | none | a number with no unit — an enum or a flags word | reserved |

## Validity

Whether a number is usable now. Separated from provenance because `counted` **and** `stale` is a real state and one word could not say it.

| Value | Name | Meaning |
|---|---|---|
| 1 | ok | Current |
| 2 | stale | Was good; the value is the last known and `age` says how old |
| 3 | initialising | The source is up and has not produced a first reading |
| 4 | unsupported | This device does not implement it, including a vendor's in-band absence pattern (P-176) |
| 5 | sensor_fault | The source reports it bad, or the reply did not arrive intact |
| 6 | out_of_range | A number arrived and was refused: impossible here, or outside `i32` at the registry's scale (P-185) |
| 7 | absent | The component or device is not present |
| 8 | unnamed_state | The source reported an operating state we have no value for (P-164) |

## Provenance

Where a number came from. `0` exactly when there is no number at all.

| Value | Name | Meaning |
|---|---|---|
| 0 | none | There is no number |
| 1 | measured | Read directly from an instrument |
| 2 | counted | Integrated or accumulated by the source, and trustworthy as a total |
| 3 | derived | This controller computed it from other signals |
| 4 | estimated | Inferred from a proxy — state of charge from terminal voltage |
| 5 | reported | The device states it: a limit, or a setpoint it says it is honouring |
| 6 | commanded | What was asked for, never what was observed |

## Device presence

Whether a device is answering. Separate from any of its signals' validity, and it never moves `rev`.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | online | Answering | reserved |
| 2 | degraded | Answering, with errors or omissions | reserved |
| 3 | offline | Was seen and has stopped answering | reserved |
| 4 | never_seen | Configured and has never answered | reserved |

## Concern severities

How much a concern matters. The table reserves rows above `warning` so per-cell noise cannot hide a pack fault.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | info | Worth recording | reserved |
| 2 | warning | Worth looking at | reserved |
| 3 | fault | Something is broken | reserved |
| 4 | protection | A source is refusing to operate to protect itself | reserved |

## Concern states

Where a concern is in its life. Acknowledging is not clearing, and only the condition going away clears it.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | active | The condition is present | reserved |
| 2 | active_acked | Somebody has read it. The condition is still present | reserved |
| 3 | latched_cleared | The condition is gone; the source's latch is not, and will clear on the source's own terms | reserved |
| 4 | clearing_blocked | The condition is gone and the source states it cannot reset the latch yet — the difference between *wait* and *drive out* | reserved |
| 5 | cleared | Over. Terminal, and the only state a row carries as it leaves the table (P-180) | reserved |

## Conditions

A normalized thing that has gone wrong. Open, so a condition nobody has allocated still renders as a sentence somebody can act on.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | over voltage | reserved |
| `0x0002` | under voltage | reserved |
| `0x0003` | over temperature | reserved |
| `0x0004` | under temperature | reserved |
| `0x0005` | charge over current | reserved |
| `0x0006` | discharge over current | reserved |
| `0x0007` | short circuit | reserved |
| `0x0008` | overload | reserved |
| `0x0009` | cell imbalance | reserved |
| `0x000A` | low state of charge | reserved |
| `0x000B` | charge inhibited | reserved |
| `0x000C` | discharge inhibited | reserved |
| `0x000D` | unnamed state | reserved |
| `0x000E` | registration refused | reserved |
| `0x000F` | series too long | reserved |
| `0x0010` | inventory full | reserved |
| `0x0011` | bay flapping | reserved |
| `0x0012` | counter write failed | retired |
| `0x0013` | epoch write failed | reserved |
| `0x0014` | clock stepped | reserved |
| `0x0015` | floor overridden | reserved |
| `0x0016` | entropy unavailable | reserved |
| `0x0017` | client table write failed | reserved |
| `0x0018` | dedup write failed | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## History buckets

The three window sizes. They nest exactly — four quarter-hours to an hour, twenty-four hours to a day — so converting between them has no rounding rule.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | day | Coarsest | reserved |
| 2 | hour | Four quarter-hours | reserved |
| 3 | quarter_hour | Finest. The three nest exactly, which is why P-194's conversion has no rounding rule | reserved |

## History sources

Whether a bucket is the device's own record or one this controller integrated. Per bucket, because a window can span the day the device stopped supplying one.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | device_reported | The device's own record, on its own axis | reserved |
| 2 | controller_derived | This controller integrated it, including any bucket it aggregated (P-195) | reserved |

## History stop reasons

Why a history response is shorter than asked for. Evaluated in order, so a response that hits a seam and then an edge names the seam.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | device_replaced | A `DeviceRow.since` boundary: a different instrument | reserved |
| 2 | component_reassigned | A `ComponentRow.since` boundary: the same instrument, a different meaning | reserved |
| 3 | gap_in_record | The store holds nothing here and does not claim how wide the hole is | reserved |
| 4 | end_of_record | Past the newest closed bucket | reserved |
| 5 | older_than_store | Before the oldest bucket held | reserved |
| 6 | page_full | The response reached its byte or point cap | reserved |

## Topology change reasons

Why `rev` moved. There is deliberately no *capability changed* value: a signal a unit does not implement is published at validity 4, so it becoming available is a validity change and not a topology change.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | boot | First inventory after a restart | reserved |
| 2 | config_write | An operator wrote topology | reserved |
| 3 | sub_device_adopted | A module answered and was taken into the tables | reserved |
| 4 | sub_device_removed | A module was taken out of them | reserved |
| 5 | device_replaced | The instrument behind a row changed (P-156) | reserved |

## Component roles

What a component is. Open: a role nobody has allocated renders under its number rather than blanking the row around it.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | pv array | reserved |
| `0x0002` | mppt tracker | reserved |
| `0x0003` | battery bank | reserved |
| `0x0004` | battery pack | reserved |
| `0x0005` | heater | reserved |
| `0x0006` | contactor | reserved |
| `0x0007` | fet | reserved |
| `0x0008` | ac input | reserved |
| `0x0009` | ac output | reserved |
| `0x000A` | phase | reserved |
| `0x000B` | line pair | reserved |
| `0x000C` | dc output | reserved |
| `0x000D` | load output | reserved |
| `0x000E` | start battery | reserved |
| `0x000F` | meter | reserved |
| `0x0010` | circuit | reserved |
| `0x0011` | merged circuit | reserved |
| `0x0012` | transfer relay | reserved |
| `0x0013` | inverter | reserved |
| `0x0014` | charger | reserved |
| `0x0015` | probe | reserved |
| `0x0016` | tank | reserved |
| `0x0017` | cell | reserved |
| `0x0018` | relay | reserved |
| `0x0019` | generator | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## Device roles

What a whole enclosure is. Open, on the same terms.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | solar charger | reserved |
| `0x0002` | inverter | reserved |
| `0x0003` | inverter charger | reserved |
| `0x0004` | bms | reserved |
| `0x0005` | energy meter | reserved |
| `0x0006` | shunt | reserved |
| `0x0007` | sensor | reserved |
| `0x0008` | power module | reserved |
| `0x0009` | controller | reserved |
| `0x000A` | battery monitor | reserved |
| `0x000B` | temperature sensor | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## Products

A product this controller has a driver for. Open, and a vendor range is expected to carry most of it.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | origin 89 controller | reserved |
| `0x0002` | pzem 003 | reserved |
| `0x0003` | pzem 017 | reserved |
| `0x0004` | epever tracer b | reserved |
| `0x0005` | victron mppt rs | reserved |
| `0x0006` | victron multiplus | reserved |
| `0x0007` | eg4 lifepower4 | reserved |
| `0x0008` | morningstar sunsaver duo | reserved |
| `0x0009` | emporia vue 3 | reserved |
| `0x000A` | ecoflow power kit | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## Driver dialects

A protocol dialect the controller can speak. A dialect is distinct when its framing or register model differs, not when a vendor ships a second model.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | no protocol | reserved |
| `0x0002` | pzem dc | reserved |
| `0x0003` | epever b | reserved |
| `0x0004` | victron mppt rs hex | reserved |
| `0x0005` | victron gx modbus vebus | reserved |
| `0x0006` | eg4 lifepower4 serial | reserved |
| `0x0007` | morningstar sunsaver duo | reserved |
| `0x0008` | emporia vue3 esphome i2c | reserved |
| `0x0009` | ecoflow power kits | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## Enum spaces

The spaces a `SignalRow` can point `esp` at. This is the registry of registries, and it is what lets a client learn a value is a charge stage from the descriptor.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | presence | reserved |
| `0x0002` | control owner | reserved |
| `0x0003` | generator state | reserved |
| `0x0004` | generator selector | reserved |
| `0x0005` | boot reason | reserved |
| `0x0006` | charge stage | reserved |
| `0x0007` | balancing | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## Control owners

Who is deciding, carried as an ordinary signal so *the BMS is driving the charge voltage and we are not* is a reading rather than an inference.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | local_panel | The buttons on the device itself | reserved |
| 2 | this_controller | Origin 89 | reserved |
| 3 | bms | The battery is deciding | reserved |
| 4 | gx_ess | A Victron GX or ESS assistant | reserved |
| 5 | remote_client | A person, through this protocol | reserved |
| 6 | device_automation | The device's own schedule or logic | reserved |

## Vendor namespaces

One namespace per vendor, so two drivers cannot both pick 7 for a vendor kind or a raw condition code.

| Kind | Name | Status |
|---|---|---|
| `0x0001` | victron | reserved |
| `0x0002` | epever | reserved |
| `0x0003` | pzem | reserved |
| `0x0004` | eg4 | reserved |
| `0x0005` | morningstar | reserved |
| `0x0006` | emporia | reserved |
| `0x0007` | ecoflow | reserved |
| `0x0008` | magnum | reserved |
| `0x0009` | xantrex | reserved |
| `0xF000`–`0xFFFF` | vendor range, skip-unknown under P-019 | — |

## Dataset metrics

The public equipment dataset ([offgrid-equipment](https://github.com/origin89hq/offgrid-equipment)) names a reading with one flat word, `pv-voltage`; this registry names it as a quantity at a place, DC voltage at an mppt tracker. This table is the one translation between the two, generated from `[[dataset_metrics]]` in `protocol.toml`, so a support list, a client and an assistant setting a live reading against a rated limit all agree on it. A place left as *any* matches every component; a more specific row wins over a less specific one, and a row naming the role outranks one naming only the point, so a bank's cell temperature takes the bank's word. The signal domain is never open: a row that names none carries `live`, the reading as it is now, so a moving limit of the same kind has no word. A counter's word depends on its window: the lifetime AC energy is `ac-energy-total`, today's is `ac-energy-today`, and yesterday's has no word. A word the protocol cannot carry is listed with why, so *not translatable* reads differently from *forgotten*. The dataset's own vocabulary is pinned beside the registry by hash, and `cargo xtask check` refuses a row naming a word outside it, a word no row accounts for, and a live metric kind that neither reaches a word nor is declared the controller's own.

| Dataset word | Kind | Role | Point | Domain |
|---|---|---|---|---|
| `pv-voltage` | `0x0101` DC voltage | pv array | any | live |
| `pv-voltage` | `0x0101` DC voltage | mppt tracker | any | live |
| `battery-voltage` | `0x0101` DC voltage | battery bank | any | live |
| `battery-voltage` | `0x0101` DC voltage | battery pack | any | live |
| `load-voltage` | `0x0101` DC voltage | load output | any | live |
| `pv-current` | `0x0102` DC current (+ into the component) | pv array | any | live |
| `pv-current` | `0x0102` DC current (+ into the component) | mppt tracker | any | live |
| `battery-current` | `0x0102` DC current (+ into the component) | battery bank | any | live |
| `battery-current` | `0x0102` DC current (+ into the component) | battery pack | any | live |
| `load-current` | `0x0102` DC current (+ into the component) | load output | any | live |
| `pv-power` | `0x0103` DC power (signed) | pv array | any | live |
| `pv-power` | `0x0103` DC power (signed) | mppt tracker | any | live |
| `battery-power` | `0x0103` DC power (signed) | battery bank | any | live |
| `battery-power` | `0x0103` DC power (signed) | battery pack | any | live |
| `load-power` | `0x0103` DC power (signed) | load output | any | live |
| `battery-temperature` | `0x0302` temperature | battery bank | any | live |
| `battery-temperature` | `0x0302` temperature | battery pack | any | live |
| `battery-temperature` | `0x0302` temperature | cell | any | live |
| `state-of-charge` | `0x0104` state of charge | any | any | live |
| `ac-voltage` | `0x0201` AC voltage | any | any | live |
| `ac-current` | `0x0202` AC current | any | any | live |
| `ac-power` | `0x0203` AC power | any | any | live |
| `ac-frequency` | `0x0204` AC frequency | any | any | live |
| `ac-energy-total` | `0x0205` AC energy | any | any | lifetime |
| `ac-energy-today` | `0x0205` AC energy | any | any | today |
| `temperature` | `0x0302` temperature | any | any | live |
| `tank-level` | `0x0401` tank level | any | any | live |
| `generator-run-state` | `0x0501` generator state (enum, see below) | any | any | live |
| `generator-run-hours` | `0x0502` generator run hours | any | any | lifetime |
| `uptime` | `0x0602` uptime since boot | any | any | since_reset |
| `ac-apparent-power` | *not carried: no metric kind* | — | — | — |
| `ac-power-factor` | *not carried: no metric kind* | — | — | — |
| `charge-stage` | *not carried: the charge stage enum space has no members yet (#3)* | — | — | — |
| `consumed-amp-hours` | *not carried: no DC charge counter kind (#2)* | — | — | — |
| `cycle-count` | *not carried: no metric kind* | — | — | — |
| `humidity` | *not carried: no metric kind* | — | — | — |
| `link-downlink` | *not carried: no metric kind* | — | — | — |
| `link-latency` | *not carried: no metric kind* | — | — | — |
| `link-online` | *not carried: link state is presence and the comms link events, not a metric* | — | — | — |
| `link-signal-quality` | *not carried: no metric kind; the comms processor's radio is not a reading the controller carries* | — | — | — |
| `link-uplink` | *not carried: no metric kind* | — | — | — |
| `pressure` | *not carried: no metric kind* | — | — | — |
| `pv-energy-today` | *not carried: no DC energy kind (#2)* | — | — | — |
| `pv-energy-total` | *not carried: no DC energy kind (#2)* | — | — | — |
| `pv-irradiance` | *not carried: no metric kind* | — | — | — |
| `state-of-health` | *not carried: no metric kind* | — | — | — |
| `switch-state` | *not carried: the only switch metric is the generator run contact command, an echo of a command rather than a measured state* | — | — | — |
| `tank-volume` | *not carried: the protocol carries a tank level in percent, never a volume* | — | — | — |
| `time-to-go` | *not carried: no metric kind* | — | — | — |

## Inventory outcomes

How an `Inventory 0x8D` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | ok | The request was answered, in whole or in part |
| 2 | superseded | `rev` is neither 0 nor the controller's current one (P-146) |
| 3 | unknown_kind | `what` is not in 1..5 |
| 4 | out_of_range | `from` is past the last row the request resolves to |

## Readings outcomes

How a `Readings 0x8E` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | ok | The request was answered, in whole or in part |
| 2 | superseded | `rev` is neither 0 nor the controller's current one (P-146) |
| 3 | unknown_selector | A `Sel` names a `dev`, `cmp` or `sig` that does not exist at this `rev` |
| 4 | out_of_range | `from` is past the last row the request resolves to |

## Concerns outcomes

How a `Concerns 0x8F` answered.

| Value | Name | Meaning |
|---|---|---|
| 1 | ok | The request was answered, in whole or in part; an empty table is this and not outcome 3 |
| 2 | superseded | `rev` is neither 0 nor the controller's current one (P-146) |
| 3 | out_of_range | `from` is greater than the largest `cid` the table holds |

## History outcomes

How a `History 0x90` answered.

| Value | Name | Meaning | Status |
|---|---|---|---|
| 1 | ok | The request was answered, in whole or in part | reserved |
| 2 | superseded | `rev` is neither 0 nor the controller's current one (P-146) | reserved |
| 3 | unknown_signal | `sig` does not exist at this `rev` | reserved |
| 4 | series_not_historable | The signal exists and its `shape` is 2 `series` | reserved |
| 5 | no_history | The signal exists, is a scalar, and carries no `hist` key | reserved |
| 6 | out_of_range | `from` is past the last row the request resolves to | reserved |

## Retired numbers

None yet. When the first one lands it stays here forever, with the date and the
reason, because the alternative is somebody reusing it in three years.
