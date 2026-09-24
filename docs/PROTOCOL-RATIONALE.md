---
title: Design rationale
description: Why KM43 uses CBOR, trusts the controller instead of the relay, authenticates readings, and puts a hard ceiling on every resource.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

# KM43 — design rationale

<p class="o89-rationale-kicker">KM43 / engineering rationale</p>

<p class="o89-rationale-deck">KM43 assumes the awkward version of the job: the controller is unattended, the radio path is unreliable, the internet-facing processor may be compromised, and the person debugging it may not have the matching firmware source. Those are not edge cases. They are the environment.</p>

<dl class="o89-rationale-ledger">
  <div>
    <dt>Trust boundary</dt>
    <dd>The STM32 decides. The internet-facing processor only carries frames.</dd>
  </div>
  <div>
    <dt>Field diagnosis</dt>
    <dd>A captured frame stays readable without the exact firmware build or schema.</dd>
  </div>
  <div>
    <dt>Bounded state</dt>
    <dd>Every table, queue, payload, and parser depth has a hard ceiling.</dd>
  </div>
  <div>
    <dt>Safe repetition</dt>
    <dd>Sessions, counters, request IDs, and command IDs each answer a different retry failure.</dd>
  </div>
</dl>

This page explains those choices. [KM43 v1.0](PROTOCOL.md) remains the normative
specification; if the two disagree, use the specification and fix this page.
The [known-good vectors](protocol/vectors/v1.json) make its byte-level claims
checkable. The trust boundary below explains why the controller owns the site
while every other component is a client.

---

## CBOR: readable when the tooling is gone

The deciding case is not a benchmark. It is a winter night, four hours from the
site, with a laptop, a serial adapter, and a frame from firmware whose source is
not on that laptop. **A frame nobody recognises must still be dumpable by a
generic tool at 2 a.m.**

Postcard wins on bytes and is the natural Rust answer, but it is a schema format.
Without the exact matching schema, its frame is opaque. With a *slightly wrong*
schema, it can decode into plausible garbage instead of failing. That is worse
than an obvious refusal when the frame is the only evidence available.

CBOR is self-describing enough that the same frame pastes into any generic
decoder and comes out as a shape a person can read. Browser and phone clients
also have mature decoders without a generated schema artefact that must ship in
lockstep with the controller. That is worth the bytes.

The bytes are not free and are not pretended away: integer keys claw most of them
back, and the limits table exists so the cost is bounded rather than argued
about. The controller parses the subset itself rather than taking a codec — see
*A CBOR library in the firmware* below, which is the argument, not the shrug it
would be without one.

### Integer keys

String keys cost bytes on every single frame, forever, and they invite the class
of typo that type-checks: `"channel"` against `"chanel"` is two valid maps.

Integer keys with the skip-unknown rule are what buys schema evolution without a
code-generation toolchain on either side. A v1 controller survives a v2 client's
extra fields by ignoring them, and a v2 client survives a v1 controller by
finding an optional field missing. Neither side needs to know the other's
version to parse.

### Why a retired number is retired forever

There is no recall. A controller in a cabin in February is running whatever
firmware it was flashed with, and it will meet clients that shipped years later.

If key `4` meant `mac` in v1 and gets reused for `label` in v2, then a v1
controller reads a v2 client's label as a MAC. The good case is that it rejects
the frame and somebody spends a week on it. The bad case is that some length
happens to line up and it does not reject anything. There is no version field
that saves this, because the whole point of the skip-unknown rule is that fields
are interpreted without consulting one.

So a retired number stays retired, and
[`protocol/REGISTRY.md`](protocol/REGISTRY.md) is the enforcement rather than the
good intention: a number is allocated there before it appears in any
implementation, retired numbers stay in the table marked retired, and the
collision gets caught in a pull request instead of in a cabin. "Never reuse a
number" is unenforceable without a list of the numbers already used.

The corollary, which is a rule and not a style note: **if a field's absence has no
sane default, it is a new message type, not a new field.** A new optional field
whose absence means "assume the old behaviour" is fine. A new optional field
whose absence means "assume something that could be wrong about a site" is the
same bug as a missing probe reading 0.0 °C.

---

## Trust the controller, not the relay

### The comms processor is the part that will have a CVE

The ESP32-C6 terminates TLS, holds the Wi-Fi association, advertises over BLE,
serves the web UI's static assets and talks to the cloud. It is a Wi-Fi and BLE
stack with an HTTP server on the internet, and it will be patched for years. That
is not a criticism of the part; it is the job description. Anything holding that
job is the thing an attacker reaches first.

So the protocol is designed on the assumption that the comms processor is
compromised, and the interesting question is what that buys an attacker.

**What a compromised comms processor can do, and we accept:**

- **Drop, delay and reorder frames.** It is the wire, and a wire can be cut.
  Nothing in the protocol pretends to prevent this, because the answer is
  architectural rather than cryptographic: the controller runs the site with no
  client connected at all, for a week, as an acceptance test. Denial of service
  against the *link* is not denial of service against the *site*.
- **Hold the controller's transmit line down.** The UART is RTS/CTS and P-033
  makes both signals a requirement at 921600, so the comms processor decides how
  fast the controller may transmit — and *slowly* is the interesting setting, not
  *never*. Refuse everything and the link looks dead, which the heartbeat ladder
  already answers. Drain it slowly instead and the link stays nominally up while
  the eight per-session outbound queues fill, and P-098 then does exactly what it
  says: a class A event that cannot be queued closes the session. Eight sessions
  closed, every client sent back to reconnect and catch up by `ReadLog`,
  repeatably, without forging a byte or dropping a frame.

  This is a different failure from the first bullet. A dropped frame loses a message; a
  deasserted CTS drives a controller state transition, on demand, from outside.
  The outcome is still acceptable — nobody is left believing they are live and
  current, which is the property P-098 exists for — but the other five are on
  this list because naming a capability is what lets it be bounded, and an
  unnamed one is bounded by nothing. So it is bounded: the controller counts
  sessions shed this way per hour, records the first one rather than the tenth,
  and treats a persisting pattern as a link that answers heartbeats and carries
  no traffic, which enters the heartbeat ladder that already exists. The bounds
  are in [`protocol/LINK.md`](protocol/LINK.md).
- **Read everything it forwards.** See below; this is a stated V1 line.
- **Exhaust tables.** Every table has a cap and refuses rather than evicting, so
  the cost of trying is bounded and visible.
- **Lie about connections.** Connection identity crosses the UART as link-local
  messages, from the untrusted party. A comms processor that invents connections
  gets a bounded challenge table full of challenges nobody can answer, because
  the *only* thing it is trusted to say is "a connection appeared". Every claim
  about *who* is behind that connection is checked against a key it does not
  have.
- **Offer a time.** `TimeOffer` carries no MAC, because no key on that link
  would help. It cannot move the clock below the newest log record the
  controller holds — a floor that is a fact about this unit rather than a build
  timestamp frozen at compile time, and the difference is a unit whose RTC backup
  cell has died and whose clock is therefore unknown at *every* boot. Nor can it
  step a known clock by more than five seconds, offer more than once a quarter of
  an hour, or suppress the record of which source set it —
  and a clock change never replays a schedule, so it cannot start a generator by
  moving time under one. The bounds are in
  [`protocol/LINK.md`](protocol/LINK.md); what makes them load-bearing is that
  time is an input to `schedule`, `exercise` and `quiet_hours`.

**What it must not be able to do, and cannot:**

- Start the generator, change a setpoint, or accept a firmware image. Every write
  carries a MAC the controller checks itself.
- Lie about the site. Every response and every event carries a MAC too, which is
  the largest change in this revision and has its own section below.
- Learn a key that would let it do either of those later. No key is ever
  transmitted.

**Out of scope, said plainly:** somebody with the controller board in their hands
and a debug probe. Physical possession of the STM32 is physical possession of the
site, and there is a lockout switch at the genset for exactly the case where a
person is standing there.

### Which is why the security boundary is the STM32

Terminate TLS on the ESP32 — it has to happen there, that is what the part is
for. But if trust *ends* there, then a command from a compromised comms chip is
byte-for-byte indistinguishable at the controller from a command from a paired
phone, and the controller has no way to tell and no way to log the difference.
The whole authentication story would be protecting the internet-facing hop and
nothing else.

So the device key lives in STM32 storage, is never exposed to the ESP32, and the
controller authenticates end to end. The comms processor routes.

---

## Keys are derived, never transported

### The history, because it is the best argument for the rule

An earlier draft returned `client_key bytes(32)` in the pairing response. Over
the UART. Through the very component the rest of the document insists must never
hold one.

A compromised comms chip would only have had to wait — somebody pairs a phone
once, in person, and from that moment the chip can forge commands for the life of
the device. Four sections of careful reasoning about keeping the key away from
the ESP32, undone by one field in one message that nobody read against the
argument.

That is the reason this file exists and the reason the vectors file exists. The
failure was not a weak primitive. It was prose and format disagreeing, in a
document long enough that nobody noticed.

### So both sides derive it

```text
client_key = HKDF(salt=device_id, ikm=printed_secret,
                  info="km43/v1/client-key" | epoch:u32be | client_id:u32be,
                  L=32)
```

`epoch` is P-085's `u32` counter in FRAM, incremented on every factory reset and
never decremented. It is in that `info` because it is the **only input to the
formula that anybody can ever change**: `device_id` is etched, and the printed
secret is on a label that cannot be reprinted into a unit already on a wall.
Without it, a factory reset invalidates nothing — press the button, reset, pair a
new phone, it is issued `client_id 1`, and the phone that was stolen last week is
already holding `client_id 1`'s key. `epoch` is what makes a reset a revocation
rather than a gesture, and it is why the documented remedy for a compromised
client is a remedy.

That field was missing from this page for a revision, which is worth recording
rather than quietly correcting. [PROTOCOL.md](PROTOCOL.md) had it and so did
`v1.json`; the formula printed here derived a different key for every client, in
the one file whose job is to explain the formula. P-001 would have caught it — on
a bench, on a phone that scanned the right label and got `bad_proof` — which is
P-001 earning its place and also the most expensive way in the world to find a
missing field in a document. Nothing generated this block from the vectors, so
nothing compared them.

The printed secret reaches the phone through its camera, off a QR code. It never
crosses the link. What crosses is a proof of knowledge, and an observer — which
here means the comms processor, sitting on both the challenge and the proof —
learns nothing it can replay.

Two conditions make that sound, and both are requirements rather than
recommendations:

- **The printed secret is exactly 32 bytes — 256 bits.** P-044 fixes it there,
  printed as 64 lowercase hex characters and fed to the KDF as the decoded bytes.
  Not *at least* something: the vectors are computed against a 32-byte IKM, so an
  implementer who takes a floor from this paragraph and prints 16 bytes derives a
  different `client_key` for every client and fails every vector, which is the
  one disagreement this file exists to stop. A six-digit PIN is brute-forceable
  offline from a single observed proof, and the observer is not hypothetical: it
  is the chip in the same enclosure.
- **A physical act still gates enrolment.** Knowing the secret is not by
  itself sufficient. P-066 opens a 120-second window with the pushbutton or
  selector gesture, with a temporary power-on exception for first enrolment
  on a board without a pushbutton.

The first-enrolment exception is deliberate for controller board A revision A,
which has no pushbutton. Power-on opens one 120-second window only when boot
reads a valid empty client table. A boot that repairs a lost or corrupt table
opens nothing; a later boot that reads the valid empty table is eligible.
Exposure is bounded to an unpaired unit and ends at its first successful
enrolment; an attacker still needs the printed secret to
produce the Pair proof. The selector gesture remains available on revision A,
including after the boot window expires and for later enrolments.

The cost is that power-on does not prove somebody is at the panel. A power cut
at an unattended, unpaired site opens the window with nobody present. Someone
who has photographed the QR and is in Bluetooth range at that moment can enrol
first. After a factory reset the unit is exposed again at every boot until it
is re-paired. Losing the client table to corruption locks out every enrolled
client anyway. Power-on eligibility returning from the next boot after recovery
is how the owner re-pairs until the button exists; an attacker still needs the
printed secret and presence in Bluetooth range during that window. This is a
temporary acceptance of that risk, not a weaker Pair proof. Retire the exception
when the board gains its pushbutton, as tracked in
[firmware#60](https://github.com/origin89hq/firmware/issues/60); a board with a
pushbutton must never use it. The controller firmware owns boot eligibility,
window timing and closure. KM43 carries the window report and checks the proof;
its codecs cannot establish that a physical act occurred.

**The limitation, stated rather than left to be discovered:** anyone who
photographs the label can derive keys, permanently, and there is no forward
secrecy — a recorded session stays recoverable if the label leaks later. The
upgrade is an authenticated key agreement: X25519 with ChaCha20-Poly1305,
Noise-style, which is what Matter does for exactly this problem under exactly
this constraint. Roughly 10–15 KB of flash against a ~256 KB budget, and tens of
milliseconds per session on an M0+. Worth doing. Not worth doing before there is
a bench, and the trigger is the first unit that leaves our hands.

---

## Readings need authentication too

Earlier drafts authenticated requests only. That left a compromised comms
processor free to **lie about the site**: report a bank at 80 % when it is at
30 %, answer `accepted` to a stop command it dropped on the floor, fabricate log
entries, or say the generator stopped while it is still running.

The asymmetry is the whole argument:

> **A forged command has a physical consequence somebody eventually notices; a
> forged reading is simply believed.**

A generator that starts at 3 a.m. is heard by somebody, or shows up in the run
hours, or empties a tank that somebody measures. A bank reported at 80 % that is
actually at 30 % is a phone screen that looks fine right up until February, and
the consequence of believing it is that nobody drove out.

For a product whose proposition is *you can trust what it tells you about a place
you are not at*, the read direction is not the lesser problem. It is the product.

So every response and every event carries a MAC over its type, its routing fields
and its payload, under the session key. Sixteen bytes and one HMAC-SHA256 per
message, on a device budgeted at roughly two thousand log records a day and a
1 Hz control loop. It is not a number anybody has to think about again.

### The shape, and why it is that shape

The MAC lives in a body wrapper — `{1: payload bstr, 2: mac bstr16}` — mirroring
the byte-string `operation` pattern that signed requests already use. One rule
for both directions instead of two.

**The verifier authenticates exactly the bytes that arrived, never a
re-encoding.** This is the COSE_Mac0 pattern and it exists to delete a whole
class of bug: no canonicalisation rule can be got wrong by one encoder in one
language, because no canonicalisation rule is load-bearing. The deterministic
encoding house rule is for debuggability and byte-stability. "Both encoders sort
map keys identically" is not a property anybody can check at 2 a.m. across two
languages, so nothing depends on it.

**Every preimage is domain-separated and carries `type`.** The labels
(`km43/v1/req`, `/rsp`, `/evt`) mean a preimage from one direction can never
collide with one from another, and `type` inside the preimage means a signed
`SetConfig` cannot be replayed as a signed `Command`.

**`req_id` is inside both directions.** `(session_id, req_id)` is exactly what the
untrusted router correlates on. With `req_id` in the response MAC and absent from
the request MAC, the router can take a genuinely authenticated answer and attach
it to the wrong outstanding request — which is the failure the response MAC was
added to prevent, arriving through the one field it forgot to cover.

**The client contributes entropy.** `Hello` carries a `client_nonce` and the
session key binds it. Without it, every input to the session key is either
long-term or chosen by the controller, so a comms processor holding a recording
can replay an entire session at a client that has no way to tell fresh from
stale — and the read direction of this whole section would hold only for writes.

The anti-rollback check that goes with it — a client noticing that
`log_newest_seq` or `state_seq` went backwards — is a SHOULD and not a MUST on
purpose. A legitimate board swap or a NOR erase regresses those numbers, and a
hard MUST turns a repair into a lockout at a site four hours from a road. Surface
it loudly, keep the session.

### Why the first units paired in cabins freeze the handshake

Once the first units are paired in cabins, their `client_key` and their stored
counters are derived from these formulas. Changing an input afterwards is not a
protocol revision, it is a re-pair of every enrolled client, in person, at every
site. That puts the handshake in the same category as per-device keys and the
other choices that cannot be retrofitted to a fielded unit, and it is why the two
weeks were spent now, while nothing implements this yet, rather than reserved
for later.

---

## Events are copied for each session

Once events are authenticated under a session key, one event to eight subscribed
sessions is eight MACs and eight frames. That sounded expensive, so it was
costed instead of argued about:

| | |
|---|---|
| Eight copies of the event stream, at 921600 8N1 | **0.026 %** of the UART |
| Eight HMAC-SHA256 per event, on the 64 MHz M0+ | **0.014 %** CPU duty |

Both are costed against a deliberately conservative operating budget: roughly
two thousand log records a day — one every 43 seconds — and an event frame of
128 bytes, which is more than twice the framed size of the example in `v1.json`
and so generous rather than flattering. The arithmetic is written out because a
number nobody can reproduce is a number that gets quoted for years and was wrong
the whole time:

- **UART.** 8 copies × 128 bytes × 10 bits on 8N1 = 10,240 bits per event. One
  event every 43.2 s is 237 bit/s against 921,600. That is 0.026 %.
- **CPU.** An HMAC-SHA256 over a 128-byte preimage is six SHA-256 compression
  blocks — one for the ipad block, three for the padded preimage, one for the
  opad block, one for the padded digest. 384 bytes at roughly 125 cycles a byte,
  which is what SHA-256 costs on a core with no hardware hash, is 48,000 cycles,
  or 0.75 ms at 64 MHz. Eight of them is 6 ms every 43.2 s. That is 0.014 %.

A day ten times noisier than the budget still costs a quarter of a percent of the
UART and a seventh of a percent of the CPU. Two numbers that end the discussion.
The rest of the argument is about the alternative.

**A subscription key shared across subscribed sessions** would give one frame and
real fan-out on the comms processor. It fails on revocation, and it fails
structurally rather than at the margin: a shared key must be rotated the moment
any holder loses the right to hold it, and **revocation here is physical only**.
So either a rekey needs a person to drive to the site, or the shared key outlives
the revocation and a revoked client keeps reading the site's telemetry from
wherever it now is. Neither is acceptable, and the second is the one that would
actually happen.

The precedent is worth naming, because this shape is solved elsewhere and the
split always lands in the same place. **Matter** uses group keys for one-to-many
and per-peer CASE sessions for anything that matters, precisely because group
keys carry a rekey-on-membership-change problem. **Victron's BLE Instant Readout**
does use a shared per-device key — but only ever for read-only advertisement,
never for control. Neither precedent is doing what a shared subscription key
would have been doing here.

The deliberate consequence: **"fan out events to subscribed sessions" is deleted
from the comms processor's permitted-role list.** It frames, routes, rate-limits
and holds transports. That is a smaller job description than it had before, which
is the direction that list should always move.

Per-session outbound queues get a named capacity and a documented behaviour when
full, like every other table: `MAX_EVENT_QUEUE`, in
[PROTOCOL.md](PROTOCOL.md)'s limits, which is the one place its value is written. Telemetry drops, oldest first, and the drop
is counted into a `records dropped` record delivered to *that* session, because a
hole nobody can put a number on is a mystery. A safety event does not drop at
all: a session that cannot take one is closed, so a client is never left
believing it is live and current while a state change never reached it.

---

## Counters and command IDs solve different problems

### Counters are per client

A single device-wide counter livelocks the moment two clients are active. Both
read 100, both send 101, one is rejected and re-reads, and so does the other, and
neither of them is wrong. A phone and a browser open at the same time is the
normal case at commissioning, not an edge case.

So the controller stores `client_id → highest accepted counter` in FRAM, updated
before the operation executes.

### They are not two spellings of the same idea

- **`counter` prevents replay.** A frame captured off the wire and sent again
  carries a counter that no longer exceeds the stored one.
- **`cmd_id` suppresses duplicates.** A retry after a lost acknowledgement
  carries the same `cmd_id`, and the controller answers `duplicate` instead of
  starting a generator a second time.

**A retried command has the same `cmd_id` and a *new* `counter`.** It is a
genuinely new frame — it has to pass the replay check and it has to fail the
dedup check. Collapse the two mechanisms into one and you lose one of those: a
single counter-only scheme has no way to tell a retry from a new command, and a
single id-only scheme has no freshness at all. Losing safe retries matters
concretely, because MQTT delivery is QoS 1 and a duplicate on a maintained
contact is a second start.

The dedup table is keyed `(client_id, cmd_id, operation-hash)`. Keyed on `cmd_id`
alone, client B's command answers `duplicate` because client A happened to pick
the same number, and the failure looks like the controller ignoring a stop
request.

The hash is there because `(client_id, cmd_id)` still cannot tell a **retry**
from a **reused id**. A genuine retry carries byte-identical operation bytes —
same kind, same arguments, only the counter is new — so it hashes the same and
dedups, which is what the table is for. A client that reuses an id inside the
window for a *different* command hashes differently, and that case is a client
bug the protocol should name rather than swallow.

**The lookup is on `(client_id, cmd_id)` and the hash decides which answer the
match gets** — `duplicate` when it agrees, `rejected` when it does not. Hashing
all three into one opaque key reads as the same design and is not: a reused id
simply *misses*, and the controller executes a second command under an id it has
already answered for. That is the failure the table exists to prevent, arriving
through the fix for a different one.

It lives in FRAM, not RAM. A reset inside the dedup window would otherwise turn a
client's retry into a second start, and a brown-out on a weak bank in February is
exactly when both a command and a reset are likely. One small record per command,
on a part rated for far more than that.

---

## An unreadable section must be repairable

On a bench board on 2026-09-24, a damaged network section was refused on read.
The paired phone could not learn the version it needed for `SetConfig`, so the
unit could not be set up at all. P-108 answers an unreadable section just like
one that has never been written: version 0 and no body. The client cannot tell
the two apart and does not need to. It uses the ordinary read-then-write flow
with `expected_version` 0 (P-100), and an accepted write replaces the damaged
record. The controller in `origin89hq/firmware` owns detecting the unreadable
record and replacing it; the protocol codec only enforces the answer's shape.

## Physical presence grants three different powers

On a board with a pushbutton, that button gates three decisions: it opens a 120-second
enrolment window, it arms a single-use override of the clock's monotonic floor,
and — held long enough — it factory-resets the device. For a long time the
documents described these as one thing, and one sentence in particular said the
floor override was gated by "deliberately the *same* evidence" as enrolment.

That sentence was wrong in a way that mattered. If a press that opens a pairing
window also lifts the clock floor, then `pairing_open` — a flag any client can
read out of an unauthenticated `Discover` — becomes a published announcement of
when the floor is down. A holder of a captured signed frame does not have to
guess when somebody is at the panel; it can poll for it. And the press people
are most often asked to make is the enrolment press, so the moment a technician
adds a phone is the moment a banked *set the clock back eleven months* lands.

Except for P-066's first-enrolment power-on window, they are the same **class**
of evidence — a person at the site, making a
decision that cannot be undone from four hours away — and that is the argument
for gating any of them on a button at all. They are not the same gesture, and
the protocol now says so: the override has its own press pattern, is consumed by
one write, and clears on release.

The rejected fix is worth recording because it is the obvious one. Reporting
`button_held` in `Discover` would let a client put *hold the button and send* on
the screen, which is genuinely better UX than learning it from a refusal. It is
also an unauthenticated, pollable answer to *is somebody standing at the
controller right now*, reachable by anybody who can open the port rather than
only by an enrolled client — a strictly better oracle than the one being closed.
The refusal outcome carries the same instruction one round trip later.

---

## Order does not make data current

`counter` orders a client's writes and `cmd_id` suppresses duplicates. Neither
is a clock, and for a long time nothing else was either. A signed write captured
at nine in the morning satisfied every rule it met at midnight: the MAC still
verified, the counter still exceeded the stored one because it did when the
frame was made, and the dedup entry had aged out ten minutes after it was
written. *Start the generator*, delivered fifteen hours late, with every check
passing.

DNP3 Secure Authentication answers this with a per-operation challenge — the
outstation issues a nonce and the master signs it — which is airtight and costs
a round trip on every write, over a link that is sometimes a cellular modem at
the bottom of a valley.

The cheaper answer was already written down and was being enforced by nobody.
`req_id` was specified as strictly increasing per session, as a statement about
what a client does. Making the controller check it costs a `u32` and a small
bitmask per session, and bounds the delay to whichever comes first: the client's
next accepted request, or the fifteen-minute session expiry that destroys the
key the frame was MAC'd under. The tolerance for reordering is not a weakening —
four requests may be in flight and may arrive in any order, so a strict
must-exceed rule would refuse honest traffic on a bad radio.

What the controller says when it refuses was left open for a while, and the
answer is nothing. The obvious move is an `Error`, and under the session key it
is the one thing this rule must never produce: the response MAC covers
`(type, session_id, req_id)` and nothing that moves, so an answer to a replayed
`req_id` is a second genuine response to a pair that was already answered, and
the relay now holds two to choose between. A bare code avoids that and buys
nothing. It would need an allocation argued for out loud, and the only peers
that would ever read it are a relay replaying frames and a client with a bug,
because an honest client never reuses a `req_id` and never has more than
`MAX_INFLIGHT` in flight. The broken client times out and retries under a new
`req_id`, which it does after any lost frame anyway.

The refusal also has to undo what the frame did on its way in. It carries a
valid MAC, so under the old wording of the session timer it counted as traffic,
and a relay replaying one captured request every fourteen minutes held a
session open forever while staying clear of the failure limit. So a refused
request refreshes nothing, and it is not counted as a failure either, since
that would let the relay close an honest client's connection with the client's
own frames.

The general lesson is the one worth keeping: a rule written as client behaviour
is not a rule. If it protects the controller, the controller has to check it.

---

## Silence is a state, not proof

Every mechanism for detecting a dropped event is built on a **hole** — a gap
between two `seq` values that arrived. The class-A guarantee, the `records
dropped` accounting, the per-session MAC: all of them assume something got
through.

`type` is in the clear, because a receiver has to route a frame before it can
authenticate one. So the comms processor can drop every unsolicited event
without decoding a single body, and dropping *all* of them produces no hole at
all. Every detection mechanism in the protocol runs on evidence that total
suppression is careful never to create, and a suppressed site looks exactly like
a quiet one — which is what this site looks like for eleven months of the year.

A keepalive would fix it and would cost traffic on a metered link forever. It
was not needed: the controller's newest `seq` already rides inside `Snapshot`,
`SubscribeAck` and `Hello`, under a MAC the comms processor cannot forge. The
client compares a number it is already being handed against the highest it has
accepted. *Nothing has happened* and *you have been told nothing has happened*
become two comparable numbers, for no bytes at all.

---

## What v1 deliberately does not provide

**Confidentiality against our own comms processor.** Stated here so nobody
discovers it in a review.

The ESP32 can read everything it forwards: every reading, every command, every
configuration value, in the clear, on the internal UART. What a compromised comms
processor learns is occupancy patterns, generator activity, energy use and
network settings. What it cannot do is change any of them, or forge a report
about them, or hold a key that would let it do so later.

Integrity is the property that must hold in V1. Secrecy from our own hardware
needs the AEAD upgrade described under pairing, and it arrives with Noise or it
does not arrive. That is a line, drawn on purpose — not an oversight, and not
something to be quietly fixed by adding encryption to one message.

The same line runs out to the cloud. TLS terminates at the relay, so the relay
can read telemetry, which is what makes server-side alerting and fleet dashboards
possible at all. Commands are MAC'd end to end regardless, so a compromised relay
can never forge one. End-to-end encryption to the phone is a product decision,
deliberately deferred.

---

## Rejected alternatives

### Our own SHA-256

The generator uses `sha2` and `hmac` deliberately — [its manifest](../Cargo.toml)
says audited third-party primitives rather than our own — and the firmware now
uses the same two crates. That means the published vectors no longer prove our
HMAC *independently*: a bug in `sha2` would be invisible to them, because both
sides would have it.

Writing our own SHA-256 to restore that independence was considered and
rejected, and the reasoning is the mirror of the CBOR decision one section down.
There, hand-writing won because almost everything the protocol needs is a
*restriction* a general codec will not enforce, so the validation layer gets
written either way. Here there is no restriction to enforce. SHA-256 is a fixed
function with a published answer, we would implement it exactly as specified,
and the only thing our own version could add is a bug.

What the vectors are actually for is the **preimage** — which field, in which
order, at which width, under which label — and that stays independent, because
the generator composes it from the specification and the firmware composes it
from the code. That is also where this corpus has already been wrong: a preimage
gained a label in the spec and not in the generator, and the check meant to catch
it compared descriptions rather than composition. Agreement with RFC 4231 covers
the primitive; nothing but two independent compositions covers the preimage.

### A CBOR library in the firmware

`minicbor` is `no_std`, has no allocator requirement, and is maintained. Writing
a decoder for a hostile input format by hand is normally the wrong instinct, and
it was seriously considered.

What decided it is how little of a general codec this protocol can actually use.
Definite lengths only, integer map keys only, no tags, no floats, no simple
values beyond `true`/`false`, a depth cap of 8, a string cap of 64, unknown keys
skipped but unknown *discriminants* refused, and RFC 8949 §4.2 deterministic
encoding on the way out. Almost every one of those is a **restriction**, and a
general codec by definition does not enforce them — so the validation layer gets
written either way, and the bug surface moves to our code either way. What the
dependency would buy is the part that is easy to test against published vectors,
and what it would leave is the part that is not.

Against that: a proc-macro dependency and a codec in an image with a ~256 KB
budget, for the fraction of it we would reach.

The honest risk is that a hand-written parser of attacker-controlled bytes is
where memory-safety bugs live. Two things answer it here, and neither is
confidence. The crate is `#![deny(unsafe_code)]` with no `alloc`, so the failure
modes available are a panic or a wrong answer rather than a corrupted heap. And
the reader is required to be *total* — every byte sequence yields a value or a
named refusal — which is a property a fuzzer can attack directly, and it is on
the list to prove rather than sample.

### A shared subscription key

One event frame instead of eight, fanned out by the comms processor. Rejected
because it needs rekey-on-revoke and revocation is physical only, so the rekey
either requires a drive or does not happen. Costed against the alternative at
0.026 % of the UART and 0.014 % CPU, derived above, which is not a price worth a
permanent structural weakness. Full argument above.

### A remote `Revoke` message

A signed `Revoke` means a stolen phone is dealt with from anywhere, which is a
real benefit and the reason this was in an earlier draft.

It also means a compromised client key can revoke every *other* client —
including the one somebody would have used to notice. And it does not survive its
own trust argument: adding a client to a non-empty table requires P-066's
physical gesture at the device, and de-enrolment is the stronger power. Granting the stronger
power on weaker evidence is backwards.

So revocation is physical: the button, and factory reset. The cost is written
down rather than discovered — a lost phone is a four-hour drive, and once the
client table is full the ninth client is refused until somebody visits. That is
accepted, because the failure on the other side is a compromised client quietly
removing the site's ability to be told to stop. Factory reset already requires
the button for the same reason, and **the client table is emptied by a physical
factory reset and by nothing else.**

"And a revoke" is gone from the pairing prose. There is no `Revoke` message.

### Paging the snapshot

A cursor over the snapshot would support the largest sites, which are the ones
worth the most. It also means pages have to be pinned to a single `seq` or the
client assembles a torn view — half the channels from before a change and half
from after, with nothing in the frame to say so. Pinning is a resumption state
machine holding a consistent view across round trips, on a device with no
allocator.

So the snapshot is capped at 32 channels, and a configuration that exceeds the
cap is **refused at write time**. The failure lands on the person editing the
configuration, at a keyboard, with the reason in front of them — instead of on a
client at 2 a.m. quietly assembling a view that is half an hour old in places.
The controller is currently budgeted for twenty channels, so a cap of thirty-two
leaves room; a site that genuinely needs more will produce a paging design
informed by a real site rather than an imagined one.

That evidence now exists in the equipment catalogue: a four-tracker MPPT, a
multi-phase inverter, a sixteen-cell BMS, a dual-bank charger, and a
nineteen-circuit meter all require repeated components with stable meaning. They
do not by themselves settle whether the answer is paging, selected reads, compact
vectors, or a replacement `Snapshot`. No client exists yet, so
[DEFERRED.md](protocol/DEFERRED.md) entry 13 may replace this draft design rather
than preserve it as a legacy path. The concrete fixtures now choose the bytes.

### Reserving the response MAC rather than shipping it

The cheap path was to reserve the wrapper key numbers now, ship the field
definitions, and implement verification when a controller is first granted
authority over an output. It costs nothing while nothing implements this yet and
it keeps every response body unchanged.

It was rejected because it *is* the defect this revision exists to fix, chosen
deliberately. Three review rounds have now found the same thing — a property
described in prose that the wire format did not deliver — and reserving a field
for a MAC nobody computes is that exact artefact, produced on purpose and
labelled as a plan.

The deadline is also not really the first granted output. Once the first units
are paired in cabins their keys and counters depend on these preimages, so a
reserved field that changes shape when it is finally implemented is a re-pair of
every enrolled client at every site. The two weeks are cheaper now than they will
ever be again.

### A `u16` `req_id`, with a rule to reconnect before it wraps

Two bytes smaller on every frame, and a rule — *end the session and re-establish
it rather than wrap* — that is trivially correct on paper.

It was rejected on what the rule actually asks for. A browser polling a snapshot
every two seconds exhausts 65,536 request ids in **a day and a half**, so the
reconnect that reads as a formality is a reconnect every second afternoon, on the
one client that is open all the time. That alone would only be annoying. The
reason it is not acceptable is what happens when somebody skips it: an
implementation that simply wraps looks completely normal, and the property
`req_id` carries quietly stops holding. A response MAC covers
`(type, session_id, req_id)` and nothing that changes over time, so a recurring
`req_id` inside a live session is a genuine, correctly-MAC'd answer from an hour
ago that verifies against the request being asked now — the comms processor
answering *is the generator running* with a real *no* it recorded earlier. A rule
whose violation looks exactly like normal operation, and whose consequence is an
hour-old answer that verifies, is a rule that will be violated.

A `u32` deletes the rule instead of documenting it: at one request every two
seconds it lasts two hundred and seventy years, which is longer than the copper.

The timing is the other half. The envelope is fixed forever — that is P-010, and
everything that may change belongs in a body — so the width of `req_id` was a
decision available exactly once. It is also inside three MAC preimages, which
freeze with the client keys the first time units are paired in cabins. This was
the last moment two bytes were free, and after it they would have cost a drive to
every site.

### Baking the session, channel and queue limits into the wire

One limits table, all of it normative, every implementation agreeing on every
number. Rejected because the numbers are two different kinds of thing wearing one
hat.

`MAX_PAYLOAD`, `MAX_STRING` and `MAX_DEPTH` **cannot** be negotiable. A decoder
needs all three before it decodes anything, and a receiver that has to ask its
peer how deep a map may nest has already parsed the peer's answer with no depth
bound in place. A limit that arrives after the parse is not a limit; it is a stack
overflow with a handshake in front of it. Those three are wire rules and they are
fixed here.

Sessions, channels and event-queue depth are the other kind: they are facts about
*this box* — how much RAM it has, how many transports terminate on it. Freezing
them in the protocol makes a bigger V2 controller a **protocol revision for no
reason**: a unit that can bind sixteen sessions would need a new version number
to say so, and every fielded v1 client would have to be taught that number before
it believed the answer. So they are reported in `Hello`, and a client reads what
the controller in front of it can do rather than what this document could imagine
in advance.

The line, in one sentence: **a limit a decoder must know before it decodes is
fixed on the wire; a limit that is a fact about one box is reported by that box.**

With one thing that does not move: a reported limit still has to fit inside a
wire-fixed one. A controller that reports more channels than a `Snapshot` at its
widest can carry inside `MAX_PAYLOAD` is reporting a number it cannot honour, and
the symptom is the frame it builds and then refuses with error 5 — which is
exactly the arithmetic that turned `MAX_CHANNELS` from a round number into a wire
rule. Reported does not mean unchecked.

### A reserved flags byte in the envelope

Standard practice, one byte, always zero, room to grow. Rejected for two reasons
and the second is the one that decided it.

The information is already there. The envelope is a CBOR array, so an envelope
that grows a field is an array of five where a v1 reader expected four, and the
reader can see that without being told — self-describingly, which is the whole
reason CBOR is on this wire. A flags byte is a second way to say the same thing,
and the first way costs nothing.

The second reason is what a reserved byte becomes. It is always zero, so nothing
reads it, so nothing tests it, so no implementation is ever exercised against a
non-zero value — and then the first thing that ever sets a bit in it meets a
fleet of receivers that have spent years learning it means nothing. That is
P-012's argument about a retired number, one field over. A byte nobody reads is
not neutral; it is a trap with a delay on it.

### Refreshing the session timeout on outbound traffic

A session expires after fifteen minutes without traffic, and counting the
controller's own frames as traffic sounds like symmetry. It is exactly backwards.

A subscribed session receives an event every time the site does anything, so
outbound refresh makes a subscribed session **immortal** — and subscribed sessions
are precisely the ones most likely to be stale. The whole reason the expiry exists
is the transport that looks alive and is not: the tab on a laptop that was closed
and put in a bag still has a socket the comms processor believes in, and TCP can
take a long time to disagree. That session is the one being timed out, and it is
also the one the controller would be keeping alive by talking to it. Eight of them
and every binding is spent on clients that stopped listening, while the person
standing at the panel is refused.

So only inbound frames refresh it. What proves a client is still there is that it
is still asking something, which is a fact about the client. The controller
talking to itself is not evidence of anything.

### An outbound queue of encoded frames

The obvious implementation of a per-session queue is a ring of frames ready to
go: encode once, MAC once, hand it to the UART when there is room.

The arithmetic kills it. Sixty-four deep across eight sessions is 512 frames, and
at the 128-byte event frame everything else on this page is costed with, that is
**64 KiB of a 144 KiB part** — nearly half the RAM on the controller, holding
copies of records the log already holds. The same queues as `u64` references into
the log are **4 KiB**.

So a queue holds `seq` references and the frame is rendered when it is sent. The
content is in the log by construction — an event is a record first — and the MAC
is the same MAC either way, computed later rather than earlier: P-098 gives every
session its own copy under its own key, so there was never a frame two sessions
could have shared. The 0.75 ms derived above is paid once per session per event
whichever end of the queue it happens at.

What that buys is not the RAM, it is what the RAM was deciding. With frames in
the queue, every proposal to make a queue deeper is an argument about memory
against everything else that lives there, settled by whoever is holding the map
file. With references, depth is 8 bytes a slot — 64 bytes across all eight
sessions for every step deeper — so it is a knob somebody turns when a bad radio
proves it needs turning, rather than a number that had to be right the first
time.

---

## What three review rounds taught us

Three rounds of review. Each one found the same class of defect, and it is worth
recording that it was the same class rather than tidying it into a changelog:
**prose describing a property the wire format did not deliver.**

**Round one.** `Hello` carried a proof "over the challenge from `Discover`", and
`Discover` returned no challenge. There was no challenge anywhere on the wire.
The handshake was described accurately and could not be built.

**Round two** (thanks to jprovost) found three holes, all of this shape. The
largest was the pairing response returning `client_key` over the UART — a
document with four sections on keeping keys away from the comms processor,
handing it the key.

**Round three** found that the section titled *"Responses and events are
authenticated too"* described a MAC with no wire slot, no field number, an
undefined `kind`, and a `seq` that most responses do not have. **No response body
had a `mac` field at all.** The prose was right about why it mattered and the
format contained none of it.

And in the same round: **the pairing response was authenticated by nothing.** Not
weakly authenticated — the specification named no key, and the general rule
provably could not apply, because there is no session yet and `client_key`
requires the `client_id` that this very message carries. That is the one message
that fixes a client's identity and its anti-replay baseline, fully controlled by
exactly the adversary the document spends four sections defending against.
Rewrite `counter` to 2⁶⁴−1: the client's first signed write carries it, the
controller accepts it because it exceeds the stored baseline, persists it to
FRAM, and every subsequent write from that client fails forever. The recovery
path is a re-pair gated by a physical button. One forged field in one
unauthenticated message, and the site permanently loses the ability to be told to
stop — which is the failure the enrolled-client cap is written to prevent.

### The vectors do not stop a fourth round

This spot used to say they did: every preimage is written out byte by byte in
[`protocol/vectors/v1.json`](protocol/vectors/v1.json), so a property that exists
only in prose has no entry there, so the fourth round cannot be the third.

That was wrong, and it was wrong in the same shape as everything else on this
page — a property described in prose that the artefact does not deliver. It is
corrected here rather than quietly softened, because a document that is wrong
about its own safeguard is worse than one that never claimed to have a safeguard:
the second makes somebody look, and the first tells them not to bother.

**A vector tests a computation. All three defects above were omissions**, and an
omission has nothing to compute:

- `Hello` proved "over the challenge from `Discover`", and `Discover` returned no
  challenge. There is no vector for a field that is not in the message. Nothing
  fails — there is one fewer entry in a file whose entries nobody counts.
- The draft that returned `client_key` in the pairing response would have had a
  vector, and it would have passed. Perfectly reproducible and perfectly wrong:
  two implementations agreeing byte for byte on the frame that hands the comms
  processor the key. A vector proves both sides compute the same thing. It has no
  opinion about whether that thing belongs on the wire.
- No response body had a `mac` field, so there was no response-MAC vector — and
  the absence of one is indistinguishable from a message that is legitimately
  unauthenticated. `Discover 0x80` has no MAC vector either, and that is correct.

The proof is in this repository, not in the argument. **Four error codes are
allocated that no rule produces** — 13, 15, 16 and 17, now marked `withdrawn` in
[`protocol/REGISTRY.md`](protocol/REGISTRY.md). Every vector passes. They were
found by a person reading the registry against the rules, which is the method
that has now been wrong three times in a row.

What the vectors do cover is the other half, and it is a real half: **two
implementations that both compute a value and disagree about its bytes.** A key
derivation, a preimage, a truncation, a CRC check value, a COBS block boundary.
That disagreement is invisible on the wire — it surfaces as a `bad_proof` on a
phone that scanned the right label — and it costs a bench day to find by
inspection. P-001 earns its place. It is simply not the thing that has gone wrong
here yet.

What catches an omission is a check over the *specification*. Three, and each one
would have caught one of the three rounds:

1. **An authentication coverage matrix, generated from the registry.** Every
   allocated message type resolves to exactly one authentication rule — a P-052
   row, P-053, or P-054 — and a type resolving to none, or to two, fails.
   Generated rather than written, so an opcode allocated tomorrow appears in it
   the moment its row lands and somebody has to answer for it. A response body
   with no `mac` field cannot survive this.
2. **A reachability check: every live code is cited by some rule.** Error codes,
   outcomes, event kinds, capability bits. A number nothing produces is either a
   rule that was never written or a number that should be `withdrawn`, and both
   are worth being told about. The four codes above are what this finds the day
   each one goes dead, rather than a review round later. A challenge that no
   message carries is the same defect one space over.
3. **A non-disclosure check: no response carries a field derived from key
   material.** A short list of names — `printed_secret`, `pair_key`,
   `client_key`, `session_key`, the device key — and a rule that none of them may
   appear as a field in any message definition in this repository. It is a crude
   check, and it would have caught the worst defect this protocol has had, in a
   pull request, months before there was a vector to be wrong about.

None of the three tests an implementation. They test this specification, against
the registry and the message definitions, and they belong in the same commit gate
the vectors do. **The vectors say two implementations agree. These say the
document asked them to agree about the right things.**

### The authentication rule is written twice and nothing compares them

One place that risk is live right now.

[`protocol/REGISTRY.md`](protocol/REGISTRY.md)'s message table carries an **Auth**
column — `none`, `proof`, `session`, `signed`, `printed secret`, `link`. The same
rule is in [PROTOCOL.md](PROTOCOL.md) in finer vocabulary and in normative form:
P-052 says which messages are wrapper-authenticated and under which label, P-053
sends the signed requests elsewhere because they carry a counter, P-054 names the
two exceptions.

They agree today — somebody checked, line by line. That is the whole problem.
Nothing *makes* them agree, and the registry is the file people edit first,
because a number is allocated there before it appears anywhere else. So the next
opcode gets a row with an Auth cell filled in from memory, in a pull request that
never opens the document holding the rule a receiver actually enforces. Then two
files say different things about one message type, and which one an implementer
believes is decided by which one they opened.

Stated rather than left to be discovered: **P-052, P-053 and P-054 in
[PROTOCOL.md](PROTOCOL.md) are normative. The registry's Auth column is an index
into them and settles nothing.** Where the two disagree, the registry is the bug.

That decides who wins an argument nobody is having yet, and it does nothing to
raise the argument. The thing that raises it is check 1 above, which is why check
1 is generated from the registry rather than written beside it.
