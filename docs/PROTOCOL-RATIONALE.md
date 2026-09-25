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
    <dd>Sessions, request IDs, and command IDs each answer a different retry failure.</dd>
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
- **See who talks, and how much.** Every body after a handshake is sealed, but
  the envelope is not: `type`, `session_id` and `req_id` are what it routes on,
  so it sees which kind of message goes where, how often and how large. It also
  reads `Discover`, which is unauthenticated because no key exists yet: the
  `device_id`, the model, the epoch and whether the pairing window is open.
- **Exhaust tables.** Every table has a cap and refuses rather than evicting, so
  the cost of trying is bounded and visible.
- **Lie about connections.** Connection identity crosses the UART as link-local
  messages, from the untrusted party. A comms processor that invents connections
  gets a bounded challenge table full of challenges nobody can answer, because
  the *only* thing it is trusted to say is "a connection appeared". Every claim
  about *who* is behind that connection is checked against a key it does not
  have.
- **Offer a time.** `TimeOffer` carries no tag, because no key on that link
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
  is sealed under a session key it does not hold, and the controller checks the
  tag itself.
- Lie about the site. Every response and every event is sealed too, and has its
  own section below.
- Read the site. The readings, the configuration, the Wi-Fi passphrase in a
  `SetConfig` and every command cross it as ciphertext.
- Learn a key that would let it do any of those later. No private key or shared
  secret is ever transmitted (P-045), and the keys a session runs under come
  from ephemeral keys drawn for that handshake, so a recording it holds today
  does not open with anything it could steal tomorrow.
- Put itself between a phone and the controller. The owner's phone checks the
  controller's key against the fingerprint printed on the label (P-236), and
  every phone after that runs its sessions against the key it pinned.

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

So the controller key, the random bit generator's state and every enrolled
client's key live in STM32 storage and are never exposed to the ESP32, and the
controller authenticates and encrypts end to end. The comms processor routes.

---

## Keys are agreed, never transported

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

### v1 derived every key from the label, which was the next thing wrong

v1's answer to that draft was to have both sides derive the key instead of
sending it:

```text
client_key = HKDF(salt=device_id, ikm=printed_secret,
                  info="km43/v1/client-key" | epoch:u32be | client_id:u32be,
                  L=32)
```

Nothing crossed the link but a proof of knowledge, and `epoch`, bumped on every
factory reset, was meant to make a reset a revocation: without it, the phone
stolen last week already held the key for `client_id 1` that a new phone would be
issued after the reset.

That field was missing from this page for a revision, which is worth recording
rather than quietly correcting. [PROTOCOL.md](PROTOCOL.md) had it and so did
`v1.json`; the formula printed here derived a different key for every client, in
the one file whose job is to explain the formula. P-001 would have caught it — on
a bench, on a phone that scanned the right label and got v1's `bad_proof` — which
is P-001 earning its place and also the most expensive way in the world to find a
missing field in a document. Nothing generated this block from the vectors, so
nothing compared them.

The deeper problem was in the formula, not the page. Every input to it except the
label is public: `device_id` is in `Discover`, so is `epoch`, and `client_id`
counts from 1. So whoever photographed the label once held every slot's key at
every epoch, factory resets included, for the life of the unit, and every session
anybody had recorded opened on the day the label leaked. v1 wrote that down as a
limitation with a trigger, the first unit to leave our hands. What fired it first
was the product: several people per controller, some invited without visiting it.
An invitee's key would have had to come from the label, which neither the owner's
phone nor the cloud should hold, and freeing a slot retires nothing when the label
derives the same key again.

### So each client makes its own key, and the controller has one

A client generates its static key pair from its own CSPRNG when it enrols, and
keeps it. The controller has one key pair of its own, generated at manufacture.
Neither private half ever crosses the link (P-045). The two sides agree the keys a
session runs under by Noise (P-226): X25519, ChaCha20-Poly1305 and SHA-256, the
same shape Matter uses for the same problem under the same constraint.

The label now derives exactly two things, `pair_psk` and `refusal_key` (P-088),
and both are used only while somebody at the panel has opened the pairing window.
No client key, session key, controller key or random value comes from it. It
authenticates one thing: a pairing attempt made in person.

**Why `XXpsk0` to enrol, then `IK` for every session.** The pattern follows from
who knows what beforehand. At enrolment the phone has the label and no key the
controller knows, so both static keys have to travel inside the handshake, which
is `XX`, and the label's pre-shared key is mixed in before anything else, which
is `psk0`. A peer without the label then fails at message 1 for the price of an
HKDF chain and one tag check, with no key agreement spent on it. After enrolment
each side holds the other's static key, so `IK` does it in one round trip: the
phone's key travels encrypted, message 1 is readable only by the controller that
holds the pinned key, and message 2 opens only for it.

**Why the fingerprint is on the label.** Without it, `XXpsk0` authenticates the
controller by the pre-shared key alone, and the pre-shared key is the label.
Anybody who has photographed the label and holds a network position — a
compromised comms processor, a host on the site's Wi-Fi answering mDNS, a phone
in Bluetooth range — answers the owner's `Discover` with a key of its own,
completes the handshake with the owner's phone, and pairs itself into the real
controller in the same window. The owner's phone pins the attacker's key, and
every session it opens for the life of that enrolment runs through a relay that
reads and rewrites it. Printing a 16-byte hash of the controller key (P-236) and
refusing a message 2 that does not match closes that for 33 more characters in
the QR code (P-049). The fingerprint is public and grants nothing.

**Why the controller key is made at manufacture and never changes.** The
STM32G0B1 has no hardware random number generator, and a key minted at first
boot from whatever a Cortex-M0+ can scrape together at power-on is a key nobody
can vouch for. The fingerprint also has to exist before the label is printed, so
the key has to exist before it too. It stays the same across factory resets
(P-235) because rotating it would revoke nothing — what ends a stolen phone's
access is its slot — and would break the one thing the label can still vouch for
once it is on a wall, along with every invited phone's pin. The manufacturing
station keeps the fingerprint and nothing else.

**Why the controller's randomness is a ratchet.** Every ephemeral key and every
challenge the controller uses comes from a deterministic random bit generator
seeded at manufacture (P-237). v1 minted challenges from the printed secret,
which was harmless while the printed secret was every key anyway; carried over,
it would have made every controller ephemeral something a photographed label
computes. The state advances and is persisted before each draw is used, because a
power cut between a draw and its successor being durable draws the same value
again after the reset: the same challenge, the same ephemeral, and a recorded
`Hello` accepted a second time under the same session keys. It is never
re-initialised, or every unit returns to the sequence it started with. Advancing
first also means a state read out with a probe yields every later draw and none
of the earlier ones, so sessions recorded before a capture stay sealed.

**What it costs, measured rather than estimated.** One X25519 operation is about
12.0 million instructions on this core: measured under QEMU's micro:bit Cortex-M0
machine with `-icount shift=0`, `x25519-dalek` 3 on its `u32` backend, built at
`opt-level = "s"`. At 64 MHz that is roughly 190 to 280 ms, depending on how many
cycles an instruction really takes, which QEMU does not model. v1's deferred
entry estimated tens of milliseconds per session, and was wrong by more than an
order of magnitude: a `Hello` costs the controller four DH operations and a key
generation, one to one and a half seconds, and a pairing costs three at message
2 and two at message 3. That is why three rules exist (P-243, P-238, P-241). Key agreement
never runs inside the control loop and one handshake runs at a time; a `Hello`
names its slot with an HMAC before any DH, so a stranger's garbage costs the
controller a few milliseconds rather than a quarter of a second; and a pairing
refused because the window is closed is answered under an HMAC rather than a
message 2.

The same measurement run over `km43`'s own code for the controller's side, under
QEMU's MPS2 AN385 model running the same `thumbv6m` build:

| Step | Instructions |
|---|---|
| `Hello` admission tag, one slot | 48 thousand |
| `Hello` `es`, `ss` and the offer | 24.2 million |
| `Hello` key generation, `ee`, `se` and the report | 35.2 million |
| `Pair` message 1 opened | 242 thousand |
| `Pair` refusal, message 1 opened and tagged | 270 thousand |
| `Pair` message 2 | 35.2 million |
| `Enrol` message 3, the admission key and `Enrol 0x93` | 24.2 million |
| One 900-byte response sealed | 150 thousand |

What pairing does not hide, said out loud: `PairOffer` is sealed under a key the
label derives and nothing else, so somebody who records a pairing and later
photographs the label reads the `label` and `client_kind` it carried. Nothing
after message 1 has that weakness; every session key comes from ephemeral keys.

The handshake's stack peaks at 3.4 KB. A pairing held between messages 2 and 3
is 176 bytes of state, and a session's keys, nonce and window are 104. Flash for
the new primitives is about 11 KB, X25519 7.8 KB and ChaCha20-Poly1305 2.9 KB,
inside the 10–15 KB that entry guessed; SHA-256 and HMAC were already there for
v1.

Two conditions make the label sound, and both are requirements rather than
recommendations:

- **The printed secret is exactly 32 bytes — 256 bits.** P-044 fixes it there,
  printed as 64 lowercase hex characters and fed to the KDF as the decoded bytes.
  Not *at least* something: the vectors are computed against a 32-byte IKM, so an
  implementer who takes a floor from this paragraph and prints 16 bytes derives a
  different `pair_psk` and fails every pairing vector, which is the one
  disagreement this file exists to stop. A six-digit PIN is brute-forceable
  offline from a single recorded pairing message 1, and the recorder is not
  hypothetical: it is the chip in the same enclosure.
- **A physical act still gates enrolment.** Knowing the secret is not by
  itself sufficient. P-066 opens a 120-second window with the pushbutton or
  selector gesture, with a temporary power-on exception for first enrolment
  on a board without a pushbutton.

The first-enrolment exception is deliberate for controller board A revision A,
which has no pushbutton. Power-on opens one 120-second window only when boot
reads a valid empty client table. A boot that repairs a lost or corrupt table
opens nothing; a later boot that reads the valid empty table is eligible.
Exposure is bounded to an unpaired unit and ends at its first successful
enrolment; an attacker still needs the printed secret to open pairing message 1.
The selector gesture remains available on revision A, including after the boot
window expires and for later enrolments.

The cost is that power-on does not prove somebody is at the panel. A power cut
at an unattended, unpaired site opens the window with nobody present. Someone
who has photographed the QR and is in Bluetooth range at that moment can enrol
first. After a factory reset the unit is exposed again at every boot until it
is re-paired. Losing the client table to corruption locks out every enrolled
client anyway. Power-on eligibility returning from the next boot after recovery
is how the owner re-pairs until the button exists; an attacker still needs the
printed secret and presence in Bluetooth range during that window. This is a
temporary acceptance of that risk, not a weaker pairing check. Retire the
exception when the board gains its pushbutton, as tracked in
[firmware#60](https://github.com/origin89hq/firmware/issues/60); a board with a
pushbutton must never use it. The controller firmware owns boot eligibility,
window timing and closure. KM43 carries the window report and checks the
handshake; its codecs cannot establish that a physical act occurred.

**What is left, stated rather than left to be discovered.** The label plus an
open window is still the whole of the authority to enrol, and after a factory
reset whoever pairs first becomes the owner. That is the ownership root, accepted
as it stands. `Discover` still gives `device_id` and the epoch, and mDNS the
`device_id`, to anybody on the network, because a client has to learn them
before any key exists. And a
reclaim now does what v1's only pretended to: the old install's key is erased with
the slot (P-240), where v1's label derived the same key again and the old install
kept working.

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

So every response and every event is sealed: encrypted with ChaCha20-Poly1305
under the session's key for that direction, with a 16-byte tag over the
ciphertext and the envelope fields the comms processor routes on. v1 did the
authenticating half with an HMAC-SHA256 body wrapper and left the payload
readable; why it stopped there is under *What v1 deliberately did not provide*.
Sixteen bytes and one AEAD per message, on a device budgeted at roughly two
thousand log records a day and a 1 Hz control loop.

### The shape, and why it is that shape

The sealed body is `{1: sealed}` on a request and `{1: sealed, 2: nonce}` on a
response or an event (P-231): the ciphertext with its tag, and the controller's
nonce where the nonce is not already on the envelope. Nothing outside `sealed`
is interpreted before the tag verifies, and the skip-unknown rule is switched off
for this one map, because a key added beside the ciphertext would be meaningful
and outside the tag, which is the classic shape of the bug.

**The receiver authenticates exactly the bytes that arrived, never a
re-encoding.** v1's wrapper got this from the COSE_Mac0 pattern; the AEAD gets it
for free, because the tag is over the ciphertext as it came off the wire and the
inner body is decoded only after it opens (P-048). No canonicalisation rule can
be got wrong by one encoder in one language, because none is load-bearing. The
deterministic encoding house rule is for debuggability and byte-stability. "Both
encoders sort map keys identically" is not a property anybody can check at 2 a.m.
across two languages, so nothing depends on it.

**The associated data is `type | session_id | req_id`, and each of the three is
there for a failure** (P-234). The two directions already have different keys,
because Noise's `Split()` gives one to each; v1 had to separate them with
`km43/v1/req`, `/rsp` and `/evt` labels instead. `type` is what separates two
messages in one direction, so a sealed `SetConfig` cannot be replayed as a
sealed `Command` (P-046). And `req_id` is inside both directions:
`(session_id, req_id)` is exactly what the untrusted router correlates on, and
without it in a response's associated data the router can take a genuinely
authenticated answer and attach it to the wrong outstanding request (P-047).

**A nonce is used once per key, and the sealing side picks it** (P-232). A
request's nonce is its `req_id`, issued by the client's sealing state itself; the
controller's nonce counts from 0 across every response and event it seals. A
nonce used twice under one key gives away the XOR of two plaintexts and the
one-time Poly1305 key, and with that key anybody on the path forges every later
message of the session. So the nonce lives where a caller cannot supply one,
and there is one of it: an application picking a `req_id` and a cipher picking a
nonce is two sources for one number, which is the version of this that goes
wrong. Neither key nor nonce is ever persisted (P-230), so a reboot or a restart
ends the session and the next `Hello` starts from fresh ephemeral keys; nothing
has to remember a nonce across a power cut, which is the one thing FRAM would
otherwise have had to get right on every message. There is no rekey either: a
session long enough to want one is replaced by a new `Hello`, which recovers
from a key compromise where Noise's `Rekey()` would not. A session ends before a
`req_id` would pass `2^32 − 1`, which at one request every two seconds is more
than two centuries.

**A replay is dropped before its tag is checked, and moves nothing.** The
controller's check for requests is P-022's window on `req_id`; the client keeps
the same kind of window over the controller's nonce (P-233). The window moves
only once a tag has verified, because a forged nonce that moved it would push the
honest messages behind it out of range without the attacker ever needing a valid
tag. And a replay is not counted as an authentication failure, because that
would let a relay shed a client's connection using the client's own frames.

**Both ends contribute entropy.** v1's `Hello` carried a `client_nonce` for
this; now each side's ephemeral key does it (P-071). Without fresh input from the
client, every input to the session keys is either long-term or chosen by the
controller, so a comms processor holding a recording can replay an entire
session at a client that has no way to tell fresh from stale — and the read
direction of this whole section would hold only for writes.

The anti-rollback check that goes with it — a client noticing that
`log_newest_seq` or `state_seq` went backwards — is a SHOULD and not a MUST on
purpose. A legitimate board swap or a NOR erase regresses those numbers, and a
hard MUST turns a repair into a lockout at a site four hours from a road. Surface
it loudly, keep the session.

### Why the first units paired in cabins freeze the handshake

Once the first units are paired in cabins, each slot holds a client's static key,
the suite it enrolled under and its admission key, and each phone holds the
controller key it pinned. Changing a pattern, the prologue, a label or the
admission tag's formula afterwards is not a protocol revision, it is a re-pair of
every enrolled client, in person, at every site. Some of it is fixed earlier
still: the controller key, its fingerprint and the QR payload are fixed when the
label is printed, and a label cannot be reprinted into a unit already on a wall.

That puts the handshake in the same category as per-device keys and the other
choices that cannot be retrofitted to a fielded unit, and it is why v1's
label-derived handshake was replaced outright rather than kept alongside. The
plan it had written down assumed fielded v1 units, and offered a second handshake
at `Discover` with v1 supported for their service life. No unit had left our
hands, so there was nothing to support. What the next change gets instead is the
suite byte (P-226): a slot pins the suite it enrolled under and a `Hello` must
present exactly that one (P-239), and the day a controller offers two, the offer
enters the prologue, so an offer stripped in flight is a handshake that fails
rather than a quiet downgrade.

---

## Events are copied for each session

Once events are sealed under a session key, one event to eight subscribed
sessions is eight seals and eight frames. That sounded expensive, so it was
costed instead of argued about. v1 costed it with an HMAC per copy, and the
cipher that replaced it has not yet been timed on the part, so the CPU line is
now a bound rather than a figure:

| | |
|---|---|
| Eight copies of the event stream, at 921600 8N1 | **0.026 %** of the UART |
| Eight HMAC-SHA256 per event, on the 64 MHz M0+ (v1) | **0.014 %** CPU duty |
| Eight ChaCha20-Poly1305 seals per event, on the same part | under **1 %** unless a seal costs more than 27,000 cycles a byte |

All three are costed against a deliberately conservative operating budget:
roughly two thousand log records a day — one every 43 seconds — and an event
frame of 128 bytes, which is more than twice the framed size of the example in
`v1.json` and so generous rather than flattering. The arithmetic is written out
because a number nobody can reproduce is a number that gets quoted for years and
was wrong the whole time:

- **UART.** 8 copies × 128 bytes × 10 bits on 8N1 = 10,240 bits per event. One
  event every 43.2 s is 237 bit/s against 921,600. That is 0.026 %.
- **CPU, v1.** An HMAC-SHA256 over a 128-byte preimage is six SHA-256
  compression blocks — one for the ipad block, three for the padded preimage,
  one for the opad block, one for the padded digest. 384 bytes at roughly 125
  cycles a byte, which is what SHA-256 costs on a core with no hardware hash, is
  48,000 cycles, or 0.75 ms at 64 MHz. Eight of them is 6 ms every 43.2 s. That
  is 0.014 %.
- **CPU, sealed.** One percent of 43.2 s is 432 ms, which is 54 ms for each of
  eight copies, which is 3.46 million cycles at 64 MHz, which is 27,000 cycles
  for each of 128 bytes, over two hundred times what SHA-256 costs a byte on
  the same core. That is a high bar and it is still a bound, not a measurement:
  the per-message cost on this part is owed, and it belongs beside the X25519
  figure when it is taken.

A day ten times noisier than the budget still costs a quarter of a percent of the
UART. The CPU is the number to re-check once the seal is measured; the argument
below does not depend on it, because it is about the alternative.

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

## Request IDs and command IDs solve different problems

### A write carries no counter

Every write used to carry a per-client counter, and the controller refused one
that did not exceed the last it had accepted. That was the replay defence of v1's
symmetric scheme, in which every key came from the label, and it was the one
defence that did not depend on a key being fresh.

The Noise sessions of origin89hq/km43#128 took that job over. Each session draws
fresh ephemeral keys at both ends, so a frame from one session does not open in
another, and inside a session P-022's window refuses a `req_id` it has already
accepted. There is nowhere left for a captured write to replay that the counter
could see.

The review of that change found one role left for it: a backstop if the
controller's random bit generator ever repeated a draw. A repeat gives the same
challenge and the same ephemeral, a recorded `Hello` replayed against it derives
the recorded session's keys, and every write of that session opens again under a
window that starts empty. The counter would have refused those writes.

It was retired anyway (origin89hq/km43#131), for three reasons.

- **It covers that failure only in part.** The replayed session makes the
  controller seal new responses under the recorded session's keys at the same
  nonces, which gives away the XOR of old and new plaintexts and the one-time
  Poly1305 keys of that direction. A repeated draw breaks P-237 whatever the
  counter does; the counter turned back one consequence of it.
- **The failure it backstops is already a type.** `Drbg::draw` takes the store
  and releases nothing until the advanced state has been written and read back,
  so a draw that skips the persist does not compile. What no type can check is
  that the store is durable, and a counter kept in another record does not check
  that either; an attacker who can roll FRAM back rolls a counter back with it.
  The test for durability is on the real part: reset between draws and confirm
  the next one differs.
- **Its cost fell on every write, from every client.** A FRAM write before each
  one executed, a failure path with its own class A concern (P-079), an error
  code (11), a `HelloReport` key a client had to read to recover from it
  (P-081), a rule forbidding the obvious local recovery, and 21 bytes of signed
  body. It carried hazards of its own as well: a counter the network could set
  to 2⁶⁴−1 pinned a client's writes forever, which P-065 existed only to stop,
  and two sessions of one client raced each other for the next value.

Ordering was not a reason to keep it. Inside a session the counter refused a
write that arrived behind a later one, but P-081 then told the client to take a
fresh counter and send it again, so the late write landed anyway. Configuration
carries `expected_version` (P-100), and that is the ordering that holds.

With the counter gone, the signed body's other two keys had no job. `client_id`
restated the session's binding, and P-084 existed only to catch the two
disagreeing; `operation` wrapped the one field left. A write's inner body is now
its operation body.

### They are not two spellings of the same idea

- **`req_id` refuses a replay.** A frame sent again inside its session carries a
  `req_id` the controller has already accepted (P-022), and a frame from any
  other session does not open.
- **`cmd_id` suppresses duplicates.** A retry after a lost acknowledgement
  carries the same `cmd_id`, and the controller answers `duplicate` instead of
  starting a generator a second time.

**A retried command has the same `cmd_id` and a *new* `req_id`.** It is a
genuinely new frame — it has to pass the replay check and it has to fail the
dedup check. Collapse the two mechanisms into one and you lose one of those: a
`req_id`-only scheme has no way to tell a retry from a new command, and an
id-only scheme has no freshness at all. Losing safe retries matters concretely,
because MQTT delivery is QoS 1 and a duplicate on a maintained contact is a
second start.

The dedup table is keyed `(client_id, cmd_id, operation-hash)`. Keyed on `cmd_id`
alone, client B's command answers `duplicate` because client A happened to pick
the same number, and the failure looks like the controller ignoring a stop
request.

The hash is there because `(client_id, cmd_id)` still cannot tell a **retry**
from a **reused id**. A genuine retry carries byte-identical operation bytes —
same kind, same arguments, only the `req_id` is new — so it hashes the same and
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

## A site links a generation on the controller's word

The cloud keeps a site's history by ownership generation, and a person links a
generation to a site from the phone they paired. Before `Vouch` the link route
took `device_id`, epoch and a name, and all three are public: the label, the mDNS
TXT record and every `Discover` carry the first two. Anybody signed in to any
account could link a generation before its owner did. The owner's link then
failed as already taken, and once readings are delivered (origin89hq/km43#129)
the squatter's site would receive them. The only recovery was a factory reset,
which starts a new generation.

The phone cannot be the witness. It says whatever its user wants, and the cloud
has no way to ask the controller directly. What the phone can do is carry a
statement the controller made and the cloud can check, and that is P-244.

**Why a MAC under a DH, and not a signature.** The controller already holds an
X25519 key, and the cloud can hold one too. `X25519(cs, VS)` is a key only the two
of them can compute, so an HMAC under it is a statement from this controller that
this verifier alone can check. A signature would let anybody check it, which
nothing here needs, and would cost a second key made at manufacture and a second
curve's code on a Cortex-M0+ with an image budget of about 256 KB. The DH costs a
quarter of a second, once per link, and takes its turn with the handshakes.

**Why the fingerprint.** The verifier needs `CS`, and the only party offering it
is the caller. A `CS` the caller chose is a key whose private half the caller
may hold, and the caller can then tag any statement it likes. The manufacturing
station keeps each unit's `controller_fp` and nothing else (P-235), and 16 bytes
are enough: the verifier hashes the offered `CS` and compares it with the record
before it spends a DH. The record is only as good as its path to the verifier,
so P-249 says it comes from the station over an authenticated channel, is never
rewritten once held, and that a unit with no record is refused. How the station
delivers it, whether an operator import or a feed signed by a station key, is
the station's to choose (origin89hq/firmware#171); what the verifier may accept
is fixed here. The vector set publishes the forgery this refuses with a
tag that really verifies under the impostor's key, so a test cannot pass by
refusing it for the wrong reason.

**Why the verifier builds the statement.** The caller hands over four things: the
controller key, the slot, the generation and the tag. Everything else in the
preimage comes from the verifier's own records: the generation being linked, and
the nonce and binding it issued together. A vouch for another account, or from
an earlier epoch, therefore fails at the tag, not at a comparison somebody has to
remember to write. A replay passes the tag, because it is the same bytes, and
the spent nonce is the one check that refuses it. That is why P-247 records the
nonce before anything else runs.

**Why both a nonce and a binding.** The nonce makes a vouch good once. The
binding names the account it was issued for, inside the tagged bytes. A verifier
that looked the nonce up and forgot to check who presented it would still find
another account's vouch failing at the tag.

**Why not the cloud's own enrolment.** origin89hq/km43#135 offered a
second route: the owner enrols the cloud's view-only client, and the cloud reads
`device_id` and epoch over its own session. That needs owner-approved enrolment,
which origin89hq/km43#129 has not specified yet, and it still needs a way to bind
that enrolment to one account's site. A vouch works with the phone the owner
already paired.

**What a vouch does not say.** It says a slot in this generation asked, and which
slot. It does not say the slot is the owner's, because roles do not exist yet.
Any enrolled client may ask, and the verifier learns `client_id` and generation,
so the owner and admin roles origin89hq/km43#129 adds can narrow who may link
without changing what the controller tags.

---

## Order does not make data current

A write's counter ordered a client's writes and `cmd_id` suppresses duplicates.
Neither is a clock, and for a long time nothing else was either. A signed write
captured at nine in the morning satisfied every rule it met at midnight: the tag
still verified, the counter still exceeded the stored one because it did when the
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
key the frame was sealed under. The tolerance for reordering is not a weakening —
four requests may be in flight and may arrive in any order, so a strict
must-exceed rule would refuse honest traffic on a bad radio. Since requests are
sealed, the `req_id` is also the request's nonce (P-232), so the same window is
what stops the controller opening one nonce twice.

What the controller says when it refuses was left open for a while, and the
answer is nothing. The obvious move is an `Error`, and under the session key it
is the one thing this rule must never produce: a response's associated data
binds it to `(type, session_id, req_id)` and nothing else, so an answer to a replayed
`req_id` is a second genuine response to a pair that was already answered, and
the relay now holds two to choose between. A bare code avoids that and buys
nothing. It would need an allocation argued for out loud, and the only peers
that would ever read it are a relay replaying frames and a client with a bug,
because an honest client never reuses a `req_id` and never has more than
`MAX_INFLIGHT` in flight. The broken client times out and retries under a new
`req_id`, which it does after any lost frame anyway.

The refusal also has to undo what the frame did on its way in. Its tag
verifies, so under the old wording of the session timer it counted as traffic,
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
dropped` accounting, the per-session tag: all of them assume something got
through.

`type` is in the clear, because a receiver has to route a frame before it can
authenticate one. So the comms processor can drop every unsolicited event
without decoding a single body, and dropping *all* of them produces no hole at
all. Every detection mechanism in the protocol runs on evidence that total
suppression is careful never to create, and a suppressed site looks exactly like
a quiet one — which is what this site looks like for eleven months of the year.

A keepalive would fix it and would cost traffic on a metered link forever. It
was not needed: the controller's newest `seq` already rides inside `Snapshot`,
`SubscribeAck` and `Hello`, sealed under keys the comms processor does not hold. The
client compares a number it is already being handed against the highest it has
accepted. *Nothing has happened* and *you have been told nothing has happened*
become two comparable numbers, for no bytes at all.

---

## What v1 deliberately did not provide, and what it provides now

**Confidentiality against our own comms processor was the line v1 drew.** v1
authenticated every message and encrypted none, so the ESP32 could read everything
it forwarded: every reading, every command, every configuration value, the Wi-Fi
passphrase in a `SetConfig`, in the clear on the internal UART. What it learned
was occupancy patterns, generator activity, energy use and network settings. What
it could not do was change any of them, forge a report about them, or hold a key
that would let it do so later. v1 said secrecy needed the AEAD upgrade and would
arrive with Noise or not at all, rather than be patched onto one message.

It arrived with Noise. Every body after a handshake is sealed (P-231), so the
comms processor now carries ciphertext on every transport, the LAN included. Key
agreement and encryption landed together on purpose: key agreement alone would
still have handed the passphrase in `SetConfig`, and every reading, to the chip
this page assumes is compromised.

**The cloud reads plaintext, by the owner's decision.** TLS terminates at the
relay, and a cloud service is an enrolled client with its own session like any
other, so it opens what it is sent. That is what makes server-side alerting,
summaries and a history people can read while the controller is offline possible
at all. The alternative was encrypting readings end to end to the site's members,
with the cloud storing ciphertext it cannot read; it moves alert generation onto
a phone that is asleep with the app closed in exactly the case nobody is looking,
and makes every invitation carry a data key as well as an enrolment. The product
is an alerting service, so the cloud reads. What it cannot do is write on anybody
else's behalf: every write is sealed under the session of the client that sent
it, and what a cloud client may write itself is fixed by the capability mask it
was enrolled with (P-105).

**What is still readable, said plainly.** The envelope is in the clear because it
is what the comms processor routes on, and `Discover` is unauthenticated because
no key exists yet. So the relay still sees which kind of message goes where, when,
and how large, and anybody on the network sees a controller's `device_id`, epoch
and whether its pairing window is open.

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

One premise under this has moved. In v1 no removal could have worked at all,
remote or physical short of a reset, because the label derived a freed slot's key
again for whoever held it. With per-client keys, freeing a slot erases the key and
moves its generation on (P-239), so a removed key stays removed. That is what
lets `Remove 0x17` (P-256) exist, and the argument above is what shapes it: an
admin removes admins, only an owner removes the cloud's viewer, and no message
removes an owner. A compromised admin can still remove the other admins, and an
owner who is told so by a `client removed` record re-invites them. It cannot
remove anybody who could remove it back. A lost owner phone is still a factory
reset, which is the ownership root this document already accepts.

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

This was argued in v1, when a response was authenticated by an HMAC wrapper
rather than sealed, and the argument is kept because it applies to any tag. The
cheap path was to reserve the wrapper key numbers now, ship the field
definitions, and implement verification when a controller is first granted
authority over an output. It costs nothing while nothing implements this yet and
it keeps every response body unchanged.

It was rejected because it *is* the defect this revision exists to fix, chosen
deliberately. Three review rounds have now found the same thing — a property
described in prose that the wire format did not deliver — and reserving a field
for a MAC nobody computes is that exact artefact, produced on purpose and
labelled as a plan.

The deadline is also not really the first granted output. Once the first units
are paired in cabins their keys depend on these preimages, so a
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
`req_id` carries quietly stops holding. In v1 a response MAC covered
`(type, session_id, req_id)` and nothing that changes over time, so a recurring
`req_id` inside a live session was a genuine, correctly-MAC'd answer from an hour
ago that verified against the request being asked now — the comms processor
answering *is the generator running* with a real *no* it recorded earlier.
Sealing made the same wrap worse: a request's `req_id` is its nonce (P-232), so
a wrapped `req_id` is a ChaCha20-Poly1305 nonce used twice under one key, which
gives away the Poly1305 key and with it every later message of the session. A
rule whose violation looks exactly like normal operation, and whose consequence
is a forgery that verifies, is a rule that will be violated.

A `u32` deletes the rule instead of documenting it: at one request every two
seconds it lasts two hundred and seventy years, which is longer than the copper.

The timing is the other half. The envelope is fixed forever — that is P-010, and
everything that may change belongs in a body — so the width of `req_id` was a
decision available exactly once. It is also the request's nonce and inside
every associated data string, which freeze with the handshake the first time
units are paired in cabins. This was
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
go: encode once, seal once, hand it to the UART when there is room.

The arithmetic kills it. Sixty-four deep across eight sessions is 512 frames, and
at the 128-byte event frame everything else on this page is costed with, that is
**64 KiB of a 144 KiB part** — nearly half the RAM on the controller, holding
copies of records the log already holds. The same queues as `u64` references into
the log are **4 KiB**.

So a queue holds `seq` references and the frame is rendered when it is sent. The
content is in the log by construction — an event is a record first — and the seal
costs the same either way, paid later rather than earlier: P-098 gives every
session its own copy under its own key, so there was never a frame two sessions
could have shared. The cost derived above is paid once per session per event whichever end
of the queue it happens at.

What that buys is not the RAM, it is what the RAM was deciding. With frames in
the queue, every proposal to make a queue deeper is an argument about memory
against everything else that lives there, settled by whoever is holding the map
file. With references, depth is 8 bytes a slot — 64 bytes across all eight
sessions for every step deeper — so it is a knob somebody turns when a bad radio
proves it needs turning, rather than a number that had to be right the first
time.

---

## What three review rounds taught us

Three rounds of review, all of them of v1's drafts. Each one found the same
class of defect, and it is worth recording that it was the same class rather
than tidying it into a changelog:
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
That disagreement is invisible on the wire — it surfaces as a pairing refused
with error 10 on a phone that scanned the right label, as v1's `bad_proof` did
before it — and it costs a bench day to find by inspection. P-001 earns its place. It is simply not the thing that has gone wrong
here yet.

What catches an omission is a check over the *specification*. Three, and each one
would have caught one of the three rounds:

1. **An authentication coverage matrix, generated from the registry.** Every
   allocated message type resolves to exactly one authentication rule — a P-052
   row, P-053, or P-054 — and a type resolving to none, or to two, fails.
   Generated rather than written, so an opcode allocated tomorrow appears in it
   the moment its row lands and somebody has to answer for it. A response body
   that nothing seals cannot survive this, as v1's with no `mac` field could not.
2. **A reachability check: every live code is cited by some rule.** Error codes,
   outcomes, event kinds, capability bits. A number nothing produces is either a
   rule that was never written or a number that should be `withdrawn`, and both
   are worth being told about. The four codes above are what this finds the day
   each one goes dead, rather than a review round later. A challenge that no
   message carries is the same defect one space over.
3. **A non-disclosure check: no response carries a field derived from key
   material.** A short list of names — `printed_secret`, `pair_psk`,
   `refusal_key`, `admit_key`, the controller's private key, the random bit
   generator's state, a transport key; in v1 it was `pair_key`, `client_key`,
   `session_key` and the device key — and a rule that none of them may
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
column — `none`, `handshake`, `pair_reply`, `sealed`, `signed`,
`sealed_or_bare`, `link`. The same rule is in [PROTOCOL.md](PROTOCOL.md) in
finer vocabulary and in normative form: P-052 says which messages are sealed and
by which side, P-053 names the signed requests and says their inner body is the
operation, and P-054 names what is not sealed: `Discover`, and the
handshake messages that carry their own authentication.

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
