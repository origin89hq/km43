---
title: KM43 v1.0
description: The normative wire protocol for authenticated, bounded message passing between an Origin 89 controller and its clients.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

# KM43 v1.0

<p class="o89-doc-kicker">KM43 / normative specification</p>

<p class="o89-doc-deck">The wire contract between a controller and every client that talks to it: bounded for fixed memory, authenticated across an untrusted relay, and unchanged by the transport underneath.</p>

<dl class="o89-doc-facts">
  <div>
    <dt>Status</dt>
    <dd>Normative draft</dd>
  </div>
  <div>
    <dt>Message model</dt>
    <dd>Requests, responses, and an event stream</dd>
  </div>
  <div>
    <dt>Trust boundary</dt>
    <dd>Messages are proven at the controller</dd>
  </div>
  <div>
    <dt>Transports</dt>
    <dd>UART, WebSocket, USB, BLE, and MQTT</dd>
  </div>
</dl>

<nav class="o89-doc-links" aria-label="Related KM43 documents">
  <a href="/km43/rationale/">Design rationale <span aria-hidden="true">→</span></a>
  <a href="/km43/registry/">Number registry <span aria-hidden="true">→</span></a>
  <a href="/km43/test-vectors/">Test vectors <span aria-hidden="true">→</span></a>
</nav>

This document says **what** an implementation must do. Every mandatory rule has
a stable `P-nnn` identifier; the [design rationale](PROTOCOL-RATIONALE.md)
explains why the rule exists. Link-local controller↔comms messages have their own
[specification](protocol/LINK.md), and unresolved body schemas and equipment-model
coverage are named in
[deferred decisions](protocol/DEFERRED.md) instead of being guessed here.

---

## How to read this

**MUST**, **MUST NOT**, **SHOULD** and **MAY** carry their RFC 2119 meanings.
Every mandatory requirement is numbered `P-nnn` so that a test can cite the line
it proves.

Two independent implementations — one `no_std` Rust on the controller, one
TypeScript in a browser — must interoperate having read only this document and
the files it links. Anywhere you have to guess, this document has a bug; say so.

**P-001** — An implementation MUST reproduce every vector in
`protocol/vectors/v1.json` applicable to its transports exactly before it is
connected to another implementation. Core vectors apply to every transport;
the `ble` traces additionally apply to BLE implementations. Reproducing those
traces is necessary but does not establish BLE interoperability or extend the
conformance claim. A key-derivation disagreement is invisible on the wire and
costs a bench day to find by inspection.

---

## Limits

Every one of these is a fixed array with a named capacity. Nothing on the
controller allocates after init, so a limit is refused rather than grown.

They are not all the same kind of thing, and one table was hiding that.

### Fixed on the wire

**A decoder needs these before it decodes.** `MAX_PAYLOAD` decides whether there
is a buffer to read the frame into at all; `MAX_FRAME` is what a receiver sized
that buffer at before a byte arrived; `MAX_STRING` and `MAX_DEPTH` are what stop
a hostile body from walking off the stack while it is being parsed. Not one of
them can be learned from inside the message it bounds, so not one of them can be
negotiated. They are the same on every device, forever.

| Name | Value | Behaviour when reached |
|---|---|---|
| `MAX_PAYLOAD` | 1024 bytes | Error 5, frame dropped |
| `MAX_FRAME` | 1032 bytes | Frame dropped, resynchronise |
| `MAX_OPERATION` | 960 bytes | Error 5 |
| `MAX_LOG_PAGE_ENTRIES` | 64 entries | Page truncated, `complete = false` |
| `MAX_LOG_PAGE_BYTES` | 896 bytes | Page truncated, `complete = false` |
| `MAX_SCAN_APS` | 16 access points | The strongest are listed, the rest counted in `unlisted` |
| `MAX_STRING` | 64 bytes, UTF-8 | Error 1 |
| `MAX_DEPTH` | 8 | Error 1 |

### Reported by the controller

The rest are **device capability, not wire format**. A controller with more RAM
holds more sessions; a smaller one holds fewer. A client carrying these
compiled in is a client that has to be reissued to meet a controller it was not
built against, and the failure is quiet rather than loud: it keeps four requests
in flight at a controller that allows two, collects error 7 for the afternoon,
and tells somebody the site is busy.

So the controller reports them in `Hello 0x81`, and the figures below are what
*this* controller enforces rather than what the protocol permits.

| Name | This controller | `Hello 0x81` key | Behaviour when reached |
|---|---|---|---|
| `MAX_SESSIONS` | 8 | 12 | Error 8, oldest is **not** evicted |
| `MAX_CHANNELS` | 32 | 13 | Config write refused, `SetConfigAck` outcome 5 `exceeds_cap` |
| `MAX_CLIENTS` | 8 | 14 | Pair outcome 4 `table_full` |
| `MAX_EVENT_QUEUE` | 16 events per session | 15 | Class B dropped, oldest first, and counted; a class A event that cannot be queued closes the connection (P-098) |
| `MAX_INFLIGHT` | 4 requests per session | 16 | Error 7 `busy` |
| `MAX_CMD_DEDUP` | 32 entries, 10 minutes, no client above 16 | 17 | Error 7 `busy` |

Key 17 reports the **entry count**. The 10 minutes is not reported and is not
negotiable: it is how long a retry stays safe, which is a property of a client on
a bad radio rather than of the controller's memory. Neither is the per-client
half (P-122): a client that never exceeds 16 live entries never observes it, and
one that does is being told to slow down rather than being told the site is
full.

**P-005** — The controller MUST report keys 12 to 17 with the values it actually
enforces, and a client MUST use the reported value in place of any it was built
with. A client MUST NOT exceed one it has been told.

Reporting a number the controller does not enforce is worse than not reporting
it. A client that is told it may keep eight requests in flight, and is then
refused the third with error 7, has been handed a field that made it behave
worse than the compiled-in guess it replaced.

**P-006** — `max_channels` (key 13) MUST only ever be reported **downward from
32**. A controller MUST NOT report more, and a client MUST reject a `Hello 0x81`
that does, with error 1.

Thirty-two is `MAX_CHANNELS`, the length of the array a config's channel list is
held in. Downward costs nothing: a device that holds twelve channels reports
twelve, and a client that writes twelve gets them all. Upward is a controller
advertising room it does not have, and the client finds out at write time —
`SetConfigAck` outcome 5 `exceeds_cap` — after it has already built a
configuration around the number it was told.

**The 32 no longer has a derivation, and that is worth saying out loud.** It was
chosen under a ceiling of 35 that came from fitting a worst-case `Snapshot` into
`MAX_PAYLOAD`: 966 bytes of headroom divided by a 27-byte `Value` is 35.7, so 35
fit and 36 did not, and the three spare entries absorbed a `Value` gaining an
optional key. That message is retired. The ceiling, the widths it was computed
from and the assertion that held the cap under it are all gone from `limits.rs`,
and nothing has replaced them: what bounds a channel list now is the `0x0002
channels` config section, whose width is derived nowhere in this document. The
number is unchanged and is a round number again rather than a wire rule, which
is the state it was in before somebody checked it the first time.

### Neither fixed nor reported

| Name | Value | Behaviour when reached |
|---|---|---|
| `MAX_CHALLENGES` | 8 | Error 18 `challenge unavailable`; nothing is evicted |
| `MAX_AUTH_FAILURES` | 8 per connection in 60 seconds | Connection closed, `CloseConnection` reason 3 `authentication_failures`; a fresh `Hello` does not clear the count |

Both bound what the controller will spend on a peer that has proved nothing, and
there is nothing a client does differently for knowing either. A limit is
reported so a client can **stay inside** it; these two are reached only by a
client doing something it was not supposed to be doing — holding challenges it
never answers, or presenting proofs it cannot pass.

`MAX_SESSIONS` is the cap on **bindings**, not on transports. Every client
transport terminates on the comms processor today, and it refuses a ninth
connection at `ClientConnected` before any `Hello` can be sent
([LINK.md](protocol/LINK.md) L-061); error 8 is what refuses a session on a transport
the comms processor does not own.

`MAX_PAYLOAD` bounds the **encoded envelope** — the whole message as it is
framed. A receiver refuses a larger one with **error 5** and drops the frame, and
so does a sender that finds it has built one: an inner body that will not fit its
wrapper, a signed operation past `MAX_OPERATION`, a log page past
`MAX_LOG_PAGE_BYTES`. The word `payload` on its own means key 1 of the wrapper in
P-050, which is bounded by what fits inside the envelope that carries it.

That sentence used to live only inside the snapshot's derivation, which is how
the reachability sweep found it: retiring the message took the last rule in this
document that said *error 5* out loud, and a code nothing produces is a code an
implementer has no reason to handle. The cap it belongs to was three blocks up
the whole time.

`MAX_FRAME` is derived, not asserted:

```
envelope 1024 + crc16 2                      = 1026 bytes into COBS
COBS worst case  1026 + ceil(1026 / 254) = 1026 + 5 = 1031
delimiter                                    + 1    = 1032
```

So is `MAX_LOG_PAGE_BYTES`, and the arithmetic is why it is not 1024. A page is not a
frame — it travels inside one, under an envelope, a wrapper and a MAC:

```
MAX_PAYLOAD                                          1024
  less envelope [type, session_id, req_id, body]      -11
  less wrapper map + bstr header + mac(16)            -23
  less LogPage keys 2, 3 and 4                        -26
                                                     ────
  headroom for entries                                 964  ->  896 with margin
```

The envelope is 11 rather than 9 because `req_id` is a `u32` (P-022): a CBOR
integer at the top of the `u16` range is three bytes and at the top of the `u32`
range it is five. Two bytes on every frame, and every derivation on this page
carries them.

A limit that cannot fit inside the thing that carries it is not a limit, it is a
frame that gets built and then refused. `MAX_LOG_PAGE_BYTES` was derived that way from
the start, and every cap the reading and inventory planes add sits under a
ceiling `limits.rs` computes from the encoder's own widths rather than from a
count somebody did by hand.

`MAX_CHANNELS` was derived here too, against the worst-case `Snapshot` that
carried a whole site in one frame. **P-089 is retired** along with that
derivation: it bounded a `Value`'s key 3 to `i32` for one reason, which was
making 32 of them fit inside `MAX_PAYLOAD`, and there is no `Value` and no
snapshot to fit. The bound itself was not wrong and is not lost — P-185 states
it for every value position on the wire that replaced it, over `Sample` key 2,
`Series` key 3 and every value position of a descriptor row, and states the part
P-089 never did: a source value outside the range is published at `validity 6
out_of_range` with no value rather than clamped. The number is held and not
reused.

**P-002** — A receiver MUST size its frame buffer at `MAX_FRAME` and MUST
discard, without allocating, any frame that would exceed it.

**P-003** — Refusing MUST be preferred to evicting. Silently dropping a client's
enrolment is how a cabin loses its ability to be told to stop.

`MAX_EVENT_QUEUE` was the one deliberate exception, on the grounds that refusing
there means one slow client on a bad radio stalls the other seven — telemetry
drops and is counted, a safety event does not. **It is not an exception today,
because there is no telemetry kind left to drop.** `0x0101 value changed` was the
only class B kind and it is retired, so every record a queue can hold is one that
may not be dropped and a session that cannot take one is closed rather than lied
to. The class stays defined for a kind that may want it, and this exception comes
back with that kind. What it costs and how a client sees it are in P-096 to
P-098.

**P-169** — The concern table MUST refuse rather than evict, MUST reserve
`MAX_CONCERNS − MAX_CONCERNS_BELOW_FAULT` rows for `fault` and `protection`, and
MUST report the count it has refused in `Concerns` key 6.

Refusing is P-003; the **reservation** is the part that is not. A site with two
packs of sixteen cells can raise a cell-imbalance warning for every cell on a
cold morning, and a table that admits them in arrival order is full before the
BMS opens a contactor. The condition somebody has to drive four hours to attend
to is then the one condition with nowhere to go — so the rows above the band are
held for it, and thirty-two warnings cannot spend them.

The reservation does not work in reverse. Faults occupying rows do not consume
the band below them: a site holding twenty-five faults still admits a warning,
because a screen that stops reporting anything minor exactly when the site is at
its worst is the failure inverted rather than avoided.

The refused count is a count and not a flag. *The table filled once during a
storm* and *it has been refusing every tick for a week* are different sites, and
only one of them needs a bigger table.

**P-004** — Every duration in this document MUST be measured on a **monotonic
tick since boot**, never on the wall clock: the 15-minute session expiry, the
120-second challenge and pairing windows, `MAX_CMD_DEDUP`'s 10 minutes, the
60-second `MAX_AUTH_FAILURES` window, the 5-second BLE reassembly timeout, the
50 ms incomplete-frame timeout, and every other one below. The tick is
**milliseconds in a `u64`**, it never runs backwards, and a clock write — a
client `Time 0x0A`, or a `TimeOffer` the controller accepts — MUST NOT move it.
The wall clock timestamps records and decides nothing else.

The clock is settable by any enrolled client and movable by the comms processor,
so a duration measured on it is a duration somebody else sets. Deduplication is
where that ends up on a maintained contact: client A sends a command and the ack
is lost; a compromised client advances the clock eleven minutes; the dedup entry
ages out; A retries with the same `cmd_id` and — correctly, under P-082 — a
**new** counter. The counter check passes because the counter really is new, the
dedup table has nothing left to match, and the generator starts a second time.
That is exactly what P-121 puts the table in FRAM for and what P-122 refuses to
evict for, defeated without forging anything.

The width is stated because the tempting one is wrong. A `u32` of milliseconds
wraps at 49.7 days, and a controller seven weeks into an uninterrupted run is the
normal state at this site rather than the exception; after the wrap every
duration above measures backwards — a session that never expires next to a dedup
window that expired the moment it was written. A `u64` does not wrap inside any
service life, and an implementation whose hardware counter is narrower MUST widen
it in software before anything here reads it.

---

## Encoding

**CBOR** (RFC 8949), definite length everywhere.

**P-010** — Envelopes MUST be CBOR arrays. The envelope is fixed forever;
anything that needs to change belongs in a body. What "fixed" means element by
element, and what a decoder does with an envelope longer than the one it knows,
is P-028.

**P-011** — Bodies MUST be CBOR maps with **integer keys only**. Never strings.

**P-012** — A retired field number MUST NOT be reused. Retired numbers stay
recorded in [REGISTRY.md](protocol/REGISTRY.md).

**P-013** — A decoder MUST skip map keys it does not recognise, and MUST NOT
reject a message for containing them. A v1 controller has to survive a v2
client's extra fields and the reverse.

**A later field added to `Pair 0x0B`, `Pair 0x8B` or the signed body MUST enter
that message's preimage.** Those three are the only bodies whose MAC covers
*fields* rather than an encoding, so a key added outside the preimage is one the
comms processor can write, alter or remove with every tag still verifying.
P-013 still applies to them — a v1 controller skips a key it does not know,
because refusing means a v2 client cannot enrol at, or write to, a v1
controller, and enrolment is the one exchange that needs somebody at the panel.
What makes skipping safe is the rule above and the corollary in
[PROTOCOL-RATIONALE.md](PROTOCOL-RATIONALE.md): a field whose absence has no
sane default is a new message type rather than a new key.

The signed body was missing from that list for as long as the list existed. Its
`km43/v1/req` preimage covers `client_id` and `counter` as fields and the
operation as a blob — never an encoding of the map around them — so a key 5
added in a later version lands outside the MAC in exactly the way this paragraph
was written to forbid, on the four messages that carry every **write**.

**P-014** — A decoder MUST reject an **enum discriminant** it does not
recognise, with error 1. This is the opposite of P-013 and deliberately so: an
unknown extra field is a newer peer being chatty, but an unknown *value* in a
field that decides behaviour is a message whose meaning is not knowable. There is
no `0 = unknown` fallback anywhere in this protocol.

**P-019** — P-014 has exactly one exception: the vendor and experimental range
`0xF000`–`0xFFFF`, reserved by [REGISTRY.md](protocol/REGISTRY.md) in the
**metric-kind and event-kind spaces only** and never allocated by this document.
A decoder MUST NOT reject a message for carrying one. It MUST surface that one
carrier as *unrecognised* and keep the rest of the message: a `Value` whose
`kind` is in the range is shown as a configured channel with no reading rendered,
and an `Event` or `LogEntry` whose `kind` is in the range is surfaced with its
body unread, its `seq` still advancing the highest the client has accepted
(P-056). Blanking a snapshot because somebody hung a vendor meter next to the
frost probe is the worse failure by a distance. Every other discriminant space —
`quality`, `section`, `source`, `client_kind`, every outcome, every error code —
has no vendor range and no exception.

**P-015** — Every key listed in a body definition below is REQUIRED unless
marked *optional*. A missing required key is error 1.

A map carrying the same integer key **twice** is error 1 as well, refused before
anything in that map is interpreted. P-013 is about a key a decoder does not
recognise, not one it recognises twice: RFC 8949 §5.6 leaves the resolution to
the decoder, and two libraries that pick differently read different bytes out of
one authenticated message. This is a check on the frame as received rather than a
re-encoding, so it does not lean on P-016 and does not disturb P-017.

It binds every map in the message, including a key skipped under P-013 and a map
inside a value whose schema is deferred, such as `Event 0x04` key 4 or `Command`
`args`. Those are exactly the keys no body decoder looks at, and the decoder that
one day reads them would inherit whichever copy the receiver kept.

**P-016** — Encoders MUST emit RFC 8949 §4.2 deterministic encoding: shortest
form integers, sorted map keys, definite lengths, no indefinite strings.

**P-017** — Authentication MUST NOT depend on P-016. Every MAC in this document
is computed over a byte string that is carried on the wire and verified exactly
as received, never over a re-encoding. P-016 exists for debuggability and
byte-stability; if it and a MAC ever disagree, the MAC wins.

**P-018** — Floating point MUST NOT appear on the wire. Every measurement is an
integer with a **unit and a scale** from the metric registry. There is no FPU on
the target, and two languages rounding the same float differently is a defect
nobody can see in a hex dump.

---

## Envelope

```text
[ type: u8, session_id: u16, req_id: u32, body: map ]
```

**P-028** — The **array length is the extension point**. A v1 decoder MUST
reject an envelope whose array length is not exactly 4, with error 1, before it
reads any element. Anything a later version adds is a fifth element **appended
at the end**; no existing element ever changes meaning, order or width, which is
what P-010 means by fixed forever.

P-010 said the envelope is fixed and left the interesting half unwritten: what a
decoder does when it meets a five-element one. Undefined meant one implementation
reads the first four and carries on — acting on a message whose fifth element it
cannot see and which may be the one that changes what the other four mean — and
another rejects it, and both were obeying every rule on the page. Refusing is the
answer for the same reason P-014 refuses an unknown discriminant: an unknown
extra *field* is a newer peer being chatty, but an envelope of a shape this
version has never been told about is a message whose meaning is not knowable.

**There is no reserved flags byte, and that is a decision rather than an
oversight.** A byte that is always zero and that nothing reads is dead weight on
every frame for the life of the product, and it does not stay unread: the first
person who needs a bit puts one in it, in a field no decoder was ever taught to
check, so nothing rejects the frame and the two sides disagree in silence. The
array header already carries the same information and carries it
self-describingly — a four-element envelope and a five-element envelope are
different bytes, a generic CBOR dump shows the difference to somebody at 2 a.m.
without being told what version it is looking at, and the check costs one
comparison a decoder is already making to read the array at all.

**P-029** — Every `seq` bound in this document names the **first position
included**. `from_seq`, `accepted_from_seq`, `oldest_seq` and the `from_seq` of a
`ReadLog` all mean *start here*, and the record at that position is delivered.

Four requirements were each correct under the opposite reading and no two of
them had to agree. P-099 clamps a `ReadLog` to `oldest_seq` so the client "can
then see it lost data", which only works if the record at `oldest_seq` arrives.
P-104 sets `accepted_from_seq` and P-056 makes a client reject anything not
*greater* than that mark, which under an inclusive reading drops the first
replayed event on the floor. Getting it wrong loses exactly one record per
subscription, which is invisible on a busy stream and is a class A alarm on a
quiet one — and a quiet stream is what this site has for eleven months of the
year.

**P-020** — `type` with the high bit set means *response to a request*. `0x04` is
the only unsolicited message. `0x60`–`0x7E` and their `0xE0`–`0xFE` responses are
link-local ([LINK.md](protocol/LINK.md) L-002) and MUST NOT appear on a client-facing
transport; one that does is error 257. The range stops at `0x7E` because `0x7F`
with the high bit set is `0xFF`, which is Error — a request whose response opcode
is already spoken for is a trap for whoever allocates last.

**P-021** — A client that has no session yet MUST send `session_id = 0`, and MUST
NOT rely on that value surviving. **The comms processor overwrites `session_id`
with the connection handle on every inbound client frame**, and the handle is
what the controller sees. Handles are never 0, so a client frame reaching the
controller still carrying 0 is a comms-processor bug.

**P-026** — The controller MUST answer a pre-session request — `Discover 0x80`,
`Pair 0x8B`, and any bare `Error` answering one — with the connection handle in
`session_id`, so the response routes back to the connection that asked. That is
not a session; a session exists only after `Hello`.

Without this stamping rule the only demux field on the wire is one the client is
told to zero, so the controller cannot tell which of eight connections a
`Discover` arrived on — and P-060's fresh-challenge-per-connection is
unimplementable, falling back to a single device-wide challenge and the
two-client livelock it exists to prevent.

**P-022** — `req_id` is a **`u32`**, MUST be **strictly increasing within a
session**, and MUST NOT be reused or restarted. A client MUST NOT have more than
`MAX_INFLIGHT` outstanding.

**The controller MUST enforce this rather than trust it.** It MUST hold, per
session, the highest `req_id` it has accepted and a record of which of the last
`MAX_INFLIGHT` it has already accepted, and MUST refuse — without acting, and
before the counter is read — any request whose `req_id` it has already accepted,
or whose `req_id` is below `highest_accepted − MAX_INFLIGHT`.

**A request this rule refuses MUST NOT be answered** — not with its response,
not with an `Error` under the session key, and not with a bare one. It MUST NOT
refresh the session (P-077) and MUST NOT count toward `MAX_AUTH_FAILURES`
(P-051). The window is consulted only once the request's MAC has verified: a
request whose MAC fails is P-051's, whatever its `req_id`, and takes nothing
from the window. A client that hears nothing treats it as any lost exchange: it
times out and, if it still wants the answer, sends the request again under a new
`req_id`.

Silence is the only answer that does no harm. Anything MAC'd under the session
key covers `(type, session_id, req_id)`, and that pair has already been
answered, so the controller would be minting a second genuine response to it,
which is the substitution the freshness paragraph below exists to prevent. A
bare code would need a number for a condition an honest client never meets: it
never reuses a `req_id` and never has more than `MAX_INFLIGHT` outstanding, so
only a relay replaying frames or a broken client ever reaches the window, and
neither is owed an explanation. The other two exclusions stop the replay doing
anything on its way past. The frame verifies, so if it refreshed the session, a
relay replaying one captured request every fourteen minutes would hold the
session open indefinitely; and if it counted as a failure, the relay could shed
an honest client's connection using that client's own frames.

The tolerance is not slack, it is the reorder window this protocol already
permits: a client may hold four requests in flight and they may arrive in any
order, so a strict *must exceed* rule would refuse honest traffic on a bad
radio.

This is what bounds how *old* a signed write may be when it lands, which
nothing else does. `counter` orders a client's writes and `cmd_id` suppresses
duplicates — P-082 says exactly that — and neither is a clock. A frame captured
and withheld replays whenever the holder chooses, and every rule it meets is
satisfied: the MAC is valid, the counter is above the stored one because it was
above it when the frame was made, and the dedup entry aged out ten minutes
later. *Start the generator*, sent at nine in the morning and delivered at
midnight.

With the receiver rule, the window closes at whichever comes first: the client's
next accepted request, which moves `highest_accepted` past the banked frame, or
P-077's fifteen-minute session expiry, which destroys the `session_key` the
frame was MAC'd under. Both are already in this document; what was missing was
the requirement that makes the controller notice.

This is what gives a response its freshness. The response MAC covers
`(type, session_id, req_id)` and nothing that changes over time, so if a
`req_id` could recur, a response recorded earlier in the same session would
verify against a later request — the comms processor answering a *"is the
generator running"* with a genuine, correctly-MAC'd *"no"* from an hour ago.
Strictly increasing and never reused makes that impossible without a second
counter on every message.

**The width is `u32` because a `u16` ran out.** It was two bytes, with a rule
saying a session that would exhaust the space had to be ended and
re-established. A browser polling `Readings` every two seconds issues 43,200
requests a day and exhausts 65,536 of them in a day and a half — so the rule
came due on the client that polls hardest, on a session that was working
perfectly, and what it demanded was a reconnect nothing was wrong with. Every
client would have had to implement a wrap-out path that only ever fired in
normal use, and the one that got it wrong would have wrapped instead, which is
the failure the paragraph above describes.

Four bytes reach 4.29 billion, which at two seconds a request is more than two
centuries: the counter outlasts the hardware, so there is nothing to write down
about what happens when it runs out. Two bytes on every frame is the price, and
the limits arithmetic above pays it with 102 to spare on the worst frame this
protocol can build.

**P-023** — For an unsolicited `Event` the sender MUST set `req_id = 0`, and it
enters the MAC preimage as `0x00000000` — four zero bytes, the same width every
other `req_id` occupies in a preimage, because a field that changes width between
messages is a field two implementations pad differently.

**A receiver MUST refuse an `Event` whose envelope carries a non-zero `req_id`,
before verifying it.** That half was missing, and it is the half that matters:
because the preimage carries a literal zero rather than the field, `req_id` is
the one envelope value on an event that the MAC does *not* cover. Left
unchecked, the comms processor stamps any number it likes onto an event and the
tag still verifies — the frame is authentic and one of its fields is not. That
is P-084's shape exactly, one message over: a preimage that *covers* a field
without *constraining* it, which P-047 spends four bytes on every other message
to prevent. It surfaced while the wrapper was being written, which is the
cheapest place for it to surface.

**P-024** — A client MUST drop a response whose `(session_id, req_id)` matches no
outstanding request. It MUST NOT re-match a response by inspecting its body.

**Before a session exists, a client matches on `req_id` alone**, and MUST take
the `session_id` the response carries as its **connection handle** — the value it
puts on every frame from then until `Hello` gives it a session. This covers
`Discover 0x80`, `Pair 0x8B` and `Hello 0x81`, and any bare `Error` answering one.

The pair rule cannot be satisfied on message one and never could. A client with
no session sends `session_id = 0` (P-021); the comms processor overwrites it with
the connection handle on the way in (P-021 again); and the controller answers
with that handle so the response routes back (P-026). So the response's
`session_id` is provably **not** the one the client sent, by three requirements
working exactly as written — and a client obeying the pair rule literally drops
the first message of every session it will ever open, including the `Hello 0x81`
that would have given it the session. Matching on `req_id` is sufficient there
because `req_id` is already unique among that client's outstanding requests
(P-022) and there is only one connection to confuse it with.

It is also where the handle comes from. Nothing else told a client what to put in
`session_id` between `Discover` and `Hello`; it sends 0, has it rewritten, and
never learns the value — which is fine while the comms processor rewrites every
frame, and stops being fine on any transport that does not.

An `Error` carrying `session_id = 0, req_id = 0` is the carve-out, and it is
carved out because it is not a response to anything: it answers no request by
construction (P-027), so there is nothing for it to match and dropping it on that
ground drops it always. A client MUST surface it as a **link diagnostic** — *the
link between here and the controller is mangling frames* — and MUST NOT match it
to any outstanding request, MUST NOT let it complete one, and MUST NOT read it as
a statement about the site (P-055). It is unauthenticated, so what it licenses is
retrying or reconnecting and nothing else.

**P-025** — A frame too malformed to parse its envelope MUST be answered with
`session_id = 0, req_id = 0`, and the comms processor MUST route that answer back
on the connection the bad frame arrived on. It cannot route by `session_id` here
— there is no usable one, which is the entire reason the frame is being refused —
so it routes by the connection it just read the bytes from, which it knows
because it read them.

The earlier rule had the comms processor swallow this as a link-level diagnostic
and route nothing, and that is the wrong end. A client whose frame was
unparseable then hears nothing at all: it waits out its own timeout with an empty
screen and the person holding it says *it just stops working*, which is the one
bug report nobody can act on. The `0, 0` error is the only thing on the wire that
says *your frames are arriving corrupted* — the comms processor keeping it to
itself makes a link fault look like a dead controller.

**P-027** — An `Error` answering a frame whose envelope parsed MUST echo that
frame's `session_id` and `req_id`, and those echoed values are what enter the
`rsp` MAC preimage. An `Error` about a frame whose envelope did not parse
(P-025), or about the link rather than about any request, carries
`session_id = 0, req_id = 0`.

Echoing was only ever implied, and implied is what this document says it must
never be. Two sides that disagree about which `req_id` went into the preimage
compute different MACs for codes 6, 7 and 11 — every code the registry still
marks MAC'd and live — so a refusal somebody needed to read arrives as a
verification failure instead. P-024's carve-out is the other half of it: an error
about the link answers no request, and a rule that drops everything unmatched
drops 259 after a controller reboot — which is the signal to reconnect, and a
signal nobody receives is not one.

---

## Framing

### UART — controller ↔ comms processor

```text
COBS( envelope | crc16 ) 0x00
```

| | |
|---|---|
| Baud | 921600, 8N1, **RTS/CTS hardware flow control** |
| CRC | CRC-16/CCITT-FALSE — poly `0x1021`, init `0xFFFF`, no reflection, xorout `0x0000`, check `0x29B1` |
| CRC covers | the **CBOR-encoded envelope** bytes exactly, first to last — computed **before** COBS, and covering neither the delimiter nor the CRC itself |
| CRC on the wire | **little-endian**, immediately after the envelope, and the two are COBS-encoded together |
| Delimiter | `0x00` |
| Incomplete frame timeout | 50 ms since the last byte → discard and resynchronise |
| RX buffer | 2 × `MAX_FRAME`, DMA circular |

**"Encoded" means CBOR here, not COBS**, and the two orders are not
interchangeable. The sender encodes the envelope as CBOR, computes the CRC over
those bytes, appends it little-endian, and COBS-encodes the pair. A receiver
undoes COBS first and checks the CRC second. Computing the CRC over the
*COBS-encoded* bytes instead is a frame that verifies on both sides of a bench
and fails against anybody else's implementation, and the word "encoded" sitting
in a table headed by `COBS(...)` is exactly how somebody arrives at it. This was
raised while the framing layer was being written, which is the moment it was
cheapest to answer.

**There is no length field.** COBS plus the delimiter already frames the message,
and a second length source is a second thing to disagree with the first. The
earlier draft carried one and never said what to do when they disagreed.

**P-030** — A receiver MUST resynchronise by reading to the next `0x00`.

**P-031** — A frame failing its CRC MUST be dropped silently. There is no NAK at
this layer: the request layer retries, and a link-level retransmit would
duplicate a command.

**P-032** — A COBS code byte of `0x00` inside a frame, or a block running past
the end of a frame, MUST be treated as corruption: drop and resynchronise. A
resynchronising receiver is handed arbitrary bytes by definition and MUST NOT
panic, allocate, or loop unboundedly on any input.

**P-033** — RTS/CTS is REQUIRED at this rate and the production connector MUST
carry both signals. A board that omits them because bring-up worked at 115200
drops bytes in the field and it looks like a protocol bug.

### WebSocket

**P-034** — One protocol message per binary WebSocket frame. Already framed,
already ordered: no COBS, no CRC. Text frames MUST be rejected.

### USB CDC

**P-035** — As UART, including COBS and the CRC, without the flow-control
requirement.

### BLE GATT

**Host-tested transport contract; radio interoperability unverified.** BLE is
not conformance surface; see [DEFERRED.md](protocol/DEFERRED.md) entry 7.

One primary service, two characteristics. UUIDs are allocated in
`crates/km43/protocol.toml` and published in
[REGISTRY.md](protocol/REGISTRY.md#ble-gatt-identifiers) and both bindings:
`BLE_SERVICE_UUID`, `BLE_RX_UUID` (client → controller, Write Without Response),
`BLE_TX_UUID` (controller → client, Notify, with a Client Characteristic
Configuration Descriptor). Use canonical UUID text with platform APIs; raw
Bluetooth UUID fields use least-significant octet first, not ASCII UUID text.

Advertising or its scan response MUST include the service UUID. Neither the
local name nor the Bluetooth address identifies the controller for KM43 trust.
On every connection the client discovers the service and characteristic handles
by UUID, checks the required properties, enables notifications and waits for
subscription success before sending Discover. Refuse the connection if the
service, characteristics or properties are missing or ambiguous. Do not require
Bluetooth bonding, site Wi-Fi or internet to discover or use this transport.
Advertising, connecting and bonding grant no KM43 permission: the STM32 alone
checks the physical pairing window and Pair proof (P-066, P-068).

The assembled bytes are exactly one CBOR-encoded KM43 envelope, including its
body/wrapper and proof or MAC where required. No COBS, CRC, delimiter, length
prefix or BLE-specific opcode is added. `MAX_PAYLOAD` includes the entire
encoded envelope. Reassembly does not validate CBOR or authenticate a message;
those checks remain on the ordinary controller/client message path. Link-local
messages remain forbidden on BLE (L-002). The comms processor uses the shared
connection table and session stamping rules, not a BLE authentication path.

Each Write Without Response or notification carries one fragment value:

```text
[ msg_id: u8 ][ flags: u8 ][ fragment data ]
```

**P-036** — `flags` bit 7 (`BLE_LAST_FLAG`, `0x80`) is `last`; bits 6–0
(`BLE_INDEX_MASK`) are the fragment index, starting at zero and increasing by
one through at most 127. Fragment data MUST be nonempty. Index 127 without
`last` is invalid. Senders fill each nonfinal fragment to the selected value
limit; receivers accept shorter nonempty fragments.

**P-037** — Fragment data MUST be at most `min(ATT_MTU − 3, 512) − 2` bytes:
three ATT bytes, then two KM43 bytes, with the GATT attribute limit also applied.
Use ATT MTU 23 until an exchange completes; supported MTUs are 23 through 517.
An adapter whose API reports maximum write/notify *value length* uses that limit
directly, capped at 512, and subtracts only the two KM43 bytes. It may choose a
smaller value limit (at least 20 bytes). Freeze the sender's selected limit for
each message; if it can no longer be sent, close the connection and purge queues.
A full 1024-byte envelope needs 57 fragments at MTU 23, or five at MTU 247.
The ATT bounds come from the
[Bluetooth ATT specification](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/attribute-protocol--att-.html).

**P-039** — `msg_id` identifies the protocol message a fragment belongs to.
Each direction starts at zero on a new connection. A sender MUST use one value
for every fragment and increment it modulo 256 only after the final fragment
has entered the ordered transmit path. Busy/refused admission does not advance
it. IDs are mismatch detectors, not acknowledgements, replay protection or
permission to combine concurrent messages.

A receiver maintains one assembly per connection and receiving direction.
Process each value in this order:

1. Expire any assembly at **at least 5000 ms** since its last accepted fragment,
   using monotonic time; a backwards clock also discards it. Run expiry even
   when no more fragments arrive.
2. Reject a value shorter than three bytes or larger than the negotiated value
   bound, clearing the assembly.
3. If the ID changed, discard the old assembly. An index-zero fragment with the
   new ID starts immediately, including a single-fragment final message. A
   nonzero fragment cannot start an assembly and is discarded.
4. For the same active ID, require the next consecutive index. Duplicate index
   zero also discards the assembly; do not reuse that offending fragment to
   start another. The next index zero may start a message. Missing/out-of-order
   fragments therefore cannot produce a partial message.
5. Reject an append beyond `MAX_PAYLOAD`, or a nonfinal append that reaches
   `MAX_PAYLOAD` or index 127, clearing the assembly. Otherwise append and
   refresh the timer. Only `last` delivers bytes, exactly once for that assembly.

Once idle, any ID at index zero is allowed. A repeated complete message can be
delivered again; KM43's request, counter and deduplication rules still apply.

The transmit queue has **one complete message slot per connection and direction**
(`BLE_TX_CAPACITY`). It owns at most `MAX_PAYLOAD` bytes and refuses a second
message without evicting or modifying the first. Stack queues also need named,
fixed capacities in the adapter. Use one ordered ATT bearer; no interleaving
fragments or EATT scheduling across bearers. Advance a fragment only after the
stack accepts it into its FIFO. While busy, retain the exact bytes and retry
when capacity is reported; never enqueue a duplicate after successful admission.
FIFO order must extend through the radio stack, including across ID wrap. A
wrap from 255 to zero cannot overtake an older fragment. If the stack cannot
provide that guarantee, this transport cannot use it.

A stalled send expires after 5000 ms without successful stack admission (measured
from enqueue or the last admission), closing the connection and purging both
queues. This timer is the adapter's responsibility. A full application queue is
reported to its producer for bounded retry; if a controller response cannot be
retained or backpressured, close that client connection instead of silently
losing a response. Stack admission is not remote receipt: Write Without Response
and Notify have no KM43 acknowledgement. Request deadlines and signed-write
reconciliation remain unchanged.

Disconnect, notification disable, controller loss, or link restart discards both
partial assemblies and queued sends. Cancel callbacks from the old connection;
none may feed a new connection or a reused handle. A reconnect rediscovers and
subscribes again, starts IDs at zero and follows the normal challenge/session
lifecycle. Opposite directions are independent, so uploading does not block
reassembly of notifications.

`vectors/v1.json`'s `ble` action trace supplies `action`, `mtu`, `now_ms`, hex
`input`, expected outcome and hex `output`. An optional `value_limit` selects
a smaller transmit value length without changing the negotiated receive MTU;
when absent, the sender uses the MTU-derived maximum. `reset` labels a new test case;
`disconnect` resets both directions; `fragment` offers bytes without advancing;
`accepted` models successful FIFO admission; `small_buffer` offers a two-byte
output buffer; `expire` drives the receive timer. Payload stress cases use opaque
bytes to isolate transport bounds; envelope cases carry the published authenticated
response. Rust and TypeScript tests execute the trace against their public transport APIs.
These traces do not simulate a Bluetooth stack or establish native-app pairing.

### MQTT

**Specified, unimplemented, unverified.** Not conformance surface — see
[DEFERRED.md](protocol/DEFERRED.md) entry 7.

| Topic | Direction |
|---|---|
| `km43/<device_id>/rx` | to the controller |
| `km43/<device_id>/tx` | from the controller |

**P-038** — `<device_id>` MUST be the 16 bytes rendered as 32 **lowercase**
hexadecimal characters, no separators. A client learns it from the QR code it
already scans to pair, because it needs the topic before it can send a Discover.

QoS 1. The `counter` rule below is what makes at-least-once delivery safe.

---

## Cryptographic conventions

Everything in this section is fixed by
[protocol/vectors/v1.json](protocol/vectors/v1.json). If your implementation
disagrees with a vector, your implementation is wrong.

**P-040** — Every integer entering a MAC or a KDF MUST be encoded **big-endian,
fixed width, with no padding and no length prefix**. The `|` operator below joins
fixed-width fields with no separator.

**P-041** — `HMAC` means **HMAC-SHA256**. Where 16 bytes are specified it is the
**leftmost 16 bytes** of the 32-byte output.

**Sixteen bytes is a 128-bit authentication tag, and 128 bits is the security
target.** It is not a number arrived at by trimming until things fit, and the
truncation is not a weakening anybody should have to infer from the word
*truncated*: what it buys is frame size on a link where every byte is budgeted —
`MAX_PAYLOAD` is 1024, a full `Readings` page spends 880 of it, and the full
32-byte tag rides on every response, every signed request and every one of eight
separately-MAC'd copies of each event. Truncating an HMAC to
its leftmost bytes is the standard construction (RFC 2104 §5, NIST SP 800-107),
and 128 bits is where this document stops. Anybody tempted to trim further to win
a few more bytes in a frame is trading the property the whole protocol rests on
for something the limits arithmetic can be made to give up instead.

**P-042** — `HKDF` means **HKDF-SHA256** (RFC 5869) with `salt`, `IKM` and `info`
as **named arguments**. It MUST NOT be implemented as a hash over a
concatenation; the earlier draft wrote `HKDF(a | b | c)`, which assigns none of
the three.

**P-043** — Every **domain input** MUST begin with its label, so a value computed
for one purpose can never verify for another. There are two kinds of domain input
and the distinction is load-bearing: a **MAC preimage prefix**, and an **HKDF
`info` argument**. An implementer who reads the table below as nine MAC preimages
derives keys that are wrong on both sides and identical to nobody — the defect
P-001 exists to catch, because it is invisible on the wire.

| Label | Kind | Used for |
|---|---|---|
| `km43/v1/pair-key` | HKDF `info` | deriving the pairing key from the printed secret |
| `km43/v1/client-key` | HKDF `info` | deriving a client's long-term key |
| `km43/v1/session-key` | HKDF `info` | deriving a session key |
| `km43/v1/pair-proof` | MAC preimage | the client's proof during pairing |
| `km43/v1/pair-ack` | MAC preimage | the controller's pairing response |
| `km43/v1/hello-proof` | MAC preimage | the client's proof during Hello |
| `km43/v1/req` | MAC preimage | a signed request — one that carries a counter |
| `km43/v1/wrq` | MAC preimage | a wrapper-authenticated request — read-only, no counter |
| `km43/v1/rsp` | MAC preimage | a response |
| `km43/v1/evt` | MAC preimage | an event |

Labels are ASCII, no trailing NUL.

### Key derivation

```text
pair_key    = HKDF(salt = device_id,                   16 bytes
                   ikm  = printed_secret,              32 bytes
                   info = "km43/v1/pair-key",
                   L    = 32)

client_key  = HKDF(salt = device_id,                   16 bytes
                   ikm  = printed_secret,              32 bytes
                   info = "km43/v1/client-key" | epoch:u32be | client_id:u32be,
                   L    = 32)

session_key = HKDF(salt = challenge | client_nonce,    16 + 16 bytes
                   ikm  = client_key,                  32 bytes
                   info = "km43/v1/session-key" | session_id:u16be,
                   L    = 32)
```

**P-085** — `epoch` is a `u32` monotonic counter in FRAM. It starts at 1, MUST be
incremented on every factory reset, and MUST never be decremented. Every
`client_key` derived under epoch *n* is unusable at epoch *n+1*.

**A factory reset MUST increment `epoch`, persist it, read it back and verify it
before clearing anything else** — the client table, the counters and the dedup
table in that order, and only after the read-back agrees. On a failed write or a
failed read-back the reset MUST NOT proceed, the controller MUST raise a class A
`concern raised` (`0x0501`) at condition `epoch write failed`, and it MUST refuse
every `Pair` until the write succeeds.

The order is the load-bearing half. A power cut between the two steps must leave
an epoch that is too high, which only over-invalidates — the worst case is a
phone that has to be paired again. The reverse order leaves a cleared table at a
stale epoch, and then the next enrolment mints `client_id 1` under the same epoch
the stolen phone holds a key for. That is the exact failure P-085 exists to
prevent, arriving through the write that implements it.

Refusing `Pair` until it succeeds is the same argument as P-079's, one level up:
a controller that cannot invalidate key material must not mint new material into
the slots it could not invalidate. This requirement got the treatment P-079 gave
the counter write because the epoch write is the one FRAM write the entire
revocation story rests on, and it was the one with nothing said about it failing.

**This is the only thing on this design that can invalidate key material, and
without it a factory reset invalidates nothing.** `device_id` is etched and
`printed_secret` is on a label that cannot be reprinted into a unit already on a
wall — so before this counter existed, all three KDF inputs were immutable for the
life of the product. Press the button, reset, re-pair a new phone, it is issued
`client_id 1`, and **the phone that was stolen last week already holds
`client_id 1`'s key.** The documented remedy for a compromised client removed no
access at all, and a resold unit left its previous owner with a working key for
somebody else's site. LINK.md's L-135 already clears the Wi-Fi passphrase on a factory
reset for exactly that scenario; the reasoning simply had not been applied to key
material.

**P-086** — `client_id` MUST be allocated as the **lowest free slot index in the
client table, counting from 1**. This is a KDF input, so it is frozen as hard as
the formula around it, and leaving it to the implementer means two firmwares mint
different keys from the same label. Slot reuse within an epoch is what P-085
exists to make safe.

**P-087** — `Discover 0x80` MUST carry the current `epoch` (key 8), so a client
whose key no longer derives is told why. Without it the symptom is an
unexplainable `bad_proof` on a phone that worked yesterday.

**P-088** — `printed_secret` MUST NOT be used directly as an HMAC key. Both
pairing proofs are computed under `pair_key`.

It is a master secret that can never be rotated, and the comms processor observes
every pairing exchange — using it raw would hand the one component this document
declares hostile an HMAC oracle under the one secret the whole device depends on.
RFC 5869 §3.1 and NIST SP 800-108 both say the same thing: derive a
purpose-specific key, do not MAC under the master. One extra HKDF at enrolment
buys it, and it is free only until the first unit is paired.

**P-222** — A client that keeps its enrolment across a restart MUST keep only
its `client_key` with the `device_id`, `epoch` and `client_id` it was derived
under, and MUST NOT keep `printed_secret` once `Pair` succeeds. Before sending
`Hello` under a kept key it MUST compare the kept `device_id` and `epoch` with
the `Discover 0x80` it has just received, and on either differing it MUST pair
again rather than send `Hello`.

Without somewhere to keep the key, a relaunched app can only pair again, and
that needs a person at the controller (P-066). The shortcut is to keep the
label's secret and re-derive, and that is the failure this rule names: the
printed secret derives a key for every slot at every epoch, so a phone holding it
survives the factory reset P-085 relies on to lock it out. The kept key dies with
its epoch. `Discover` carries no MAC (P-054), so the comparison guards against
the wrong controller and a reset, not against a relay; the `Hello` proof is what
the controller checks.

**P-044** — `printed_secret` MUST be exactly **32 bytes of entropy**, carried in
the QR code as 64 lowercase hexadecimal characters. The KDF consumes the
**decoded 32 bytes**, never the printed text. A six-digit PIN is brute-forceable
offline from a single observed proof and MUST NOT be used.

**P-045** — No key is ever transmitted. What crosses the link is a proof of
knowledge, which an observer learns nothing from.

**P-049** — The QR code payload MUST be exactly

```text
km43:1:<device_id>:<printed_secret>
```

— the literal ASCII `km43`, a colon, the payload version `1`, a colon, the
`device_id` as the 32 lowercase hexadecimal characters of P-038, a colon, and the
`printed_secret` as the 64 lowercase hexadecimal characters of P-044. That is
`4 + 1 + 1 + 1 + 32 + 1 + 64` = **104** characters: no whitespace, no URI escaping, no trailing newline, nothing else.

A scanner MUST refuse a payload that does not match that shape exactly, and MUST
NOT pair from a partially parsed one — no uppercase hex, no tolerance for
surrounding whitespace, and never a bare hex string for either field. The secret
is meaningless without the `device_id` that salts its KDF, and a scanner that
will take a fragment is a scanner that can be fed one.

It is a bare string rather than a `km43://` URI because a scheme is an
app-link registration and a claim on the operating system, and this is the one
artefact in the whole protocol that is fixed at print time: a label cannot be
reprinted into a unit already on a wall. Two fields were already specified
character by character with nothing saying what carried them, which reads as
settled and is not.

### Message authentication

```text
req mac = HMAC(session_key, "km43/v1/req" | type:u8 | session_id:u16be
                          | req_id:u32be | client_id:u32be | counter:u64be
                          | operation)[0..16]

wrq mac = HMAC(session_key, "km43/v1/wrq" | type:u8 | session_id:u16be
                          | req_id:u32be | payload)[0..16]

rsp mac = HMAC(session_key, "km43/v1/rsp" | type:u8 | session_id:u16be
                          | req_id:u32be | payload)[0..16]

evt mac = HMAC(session_key, "km43/v1/evt" | type:u8 | session_id:u16be
                          | 0x00000000 | payload)[0..16]
```

**P-046** — `type` MUST be inside every preimage, so a signed `SetConfig` cannot
be replayed as a signed `Command`.

**P-047** — `req_id` MUST be inside both the request and the response preimage.
`(session_id, req_id)` is exactly what the untrusted comms processor correlates
on; without it in the request MAC, it can move a validly-MAC'd answer onto the
wrong outstanding request.

**P-048** — `operation` and `payload` are **byte strings carried on the wire**,
and the MAC covers those literal bytes. A verifier MUST NOT re-encode before
verifying.

---

## Authenticated bodies

**P-050** — Every message listed in P-052 has a body that is exactly this
wrapper:

```text
1: payload   bstr    the CBOR-encoded inner body
2: mac       bstr16
```

The wrapper MUST contain **exactly** keys 1 and 2. Any other key in it is error 1,
and **P-013 does not apply to the wrapper** — the one structure in this document
where skip-unknown-keys is switched off. P-051 switches it off for key 2 of this
same wrapper, which is the other half of the same rule rather than a second
place.

That is a rule about the future rather than about today. The MAC covers `payload`
and nothing else, so a key 3 added to the wrapper in v2 would be semantically
meaningful and structurally **outside the authentication**, and P-013 would have
every v1 decoder skip it politely on the way past. It is the classic shape of the
bug: the field added later lands on the wrong side of the MAC, and nobody notices
because skip-unknown-keys is correct everywhere else. Everything that needs to
grow, grows inside `payload`, which is authenticated.

`Hello 0x01` and `Pair 0x0B`/`0x8B` are authenticated by the proof formulas in
their own sections and are deliberately **not** this wrapper: what verifies them
comes from inside the body, so the wrapper's verify-then-decode ordering is not
available. P-057 says what they do instead.

**P-051** — For every message in P-052 a receiver MUST verify the MAC **before**
decoding `payload`, and MUST discard the message on failure. P-013's
skip-unknown-keys rule MUST NOT be applied to key 2: a body arriving without a
MAC where one is required is discarded, never accepted as a message with an
unknown key missing.

Discarding is about not acting, not about staying silent. A receiver MAY answer a
bare `Error` code 10 carrying the `session_id` and `req_id` from the envelope it
received, at most once per offending frame; a client treats that under P-055 and
concludes nothing about the site from it. The controller counts MAC failures
**per connection** and sheds with `CloseConnection` reason 3
([LINK.md](protocol/LINK.md)) at `MAX_AUTH_FAILURES` — 8 inside 60 seconds,
measured on P-004's tick. The count belongs to the connection row rather than to
the session, so a `Goodbye` and a fresh `Hello` does not clear it: a threshold
the peer resets by handshaking again is not a threshold. The same applies to a
signed request whose MAC fails under P-080 and to a `Hello` proof that fails
under P-057 — one condition, one code, rather than each implementer picking a
number. A request P-022 refuses is not a MAC failure and is neither counted nor
answered: its MAC verified, and counting it would let a relay shed a client's
connection with frames that client sent.

The number is named for the reason every other cap here is named. It is not what
makes a forgery hard — 128 bits of truncated HMAC-SHA256 is what makes a forgery
hard — it is what bounds the CPU a peer can spend on MACs it cannot pass, and it
is what turns *the controller sheds a client that keeps failing* into something
conformance item 7 can prove rather than something each firmware picks at a
bench: 3 on one, 1000 on the other, and the site that got the second one never
sheds anybody.

**`Pair` is the exception, and P-141 is why.** A `Pair 0x0B` whose proof fails
MUST be answered with `Pair 0x8B` outcome 3 `bad_proof`, `client_id = 0`,
carrying the P-064 MAC — never with a bare error 10. Outcome 3 exists for exactly
this condition, and P-141 settles which of the two is sent wherever both could
answer: the outcome. P-066's argument applies here unchanged and is the reason —
a refusal the comms processor can forge is a refusal that sends somebody back to
the panel. A forged error 10 tells a person standing at the device that they
mis-scanned a label they scanned correctly, and the only cure they can think of
is pressing the button again.

**The exception is about which message answers, not about the count.** A `Pair
0x0B` answered outcome 3 `bad_proof` MUST count against `MAX_AUTH_FAILURES` for
that connection: it is the only path on which an unproven peer makes the
controller compute an HMAC, which is precisely the CPU the counter bounds.
Outcome 2 `window_closed` and outcome 4 `table_full` MUST NOT count, and for two
different reasons. `window_closed` is reached **without verifying anything** —
the window MUST be checked before the proof, so refusing costs the controller
nothing, and counting it would let anybody close a technician's connection by
sending `Pair` at a controller with no window open. `table_full` is reached only
after a proof that **passed**: P-078 puts the reclaim match behind the proof, so
there is no earlier point at which a full table is knowable, and a peer that
gets there has proved it is entitled to ask.

Both halves matter and only one is obvious. Without the first, `Pair` is an
unmetered HMAC oracle sitting behind the one message type that has to work while
somebody is standing at the panel with a phone. Without the second, the shed
threshold fires on refusals the controller reached without doing any work.

**P-052** — The following are authenticated by the wrapper above under
`session_key`, each with the label its direction requires:

| Messages | Label |
|---|---|
| Requests `0x03`, `0x05`, `0x06`, `0x0C`, `0x0D`, `0x0E`, `0x0F`, `0x10`, `0x11`, `0x12` | `km43/v1/wrq` |
| Responses `0x81`, `0x83`, `0x85`, `0x86`, `0x87`, `0x88`, `0x89`, `0x8A`, `0x8C`, `0x8D`, `0x8E`, `0x8F`, `0x90`, `0x91`, `0x92`, and `0xFF` in its wrapped form (P-142) | `km43/v1/rsp` |
| Event `0x04` | `km43/v1/evt` |

The read-only requests need their own label because they carry no counter and so
cannot use the signed-request preimage. Without one they would have no preimage
at all, and every request type in the first row could not be authenticated.

**P-053** — Signed requests (`0x07`, `0x08`, `0x09`, `0x0A`) use the signed body
in the next section instead, because they carry a counter the wrapper has no room
for.

**P-054** — `0x00`/`0x80` (Discover) are **unauthenticated**: no key exists yet.
`0x0B`/`0x8B` (Pair) are authenticated under **`pair_key`**, which P-088 derives
from `printed_secret` with the label `km43/v1/pair-key`, rather than under a
session key — there is none yet either.

This used to say the printed secret was keyed directly, with no derived pairing
key in between, which is the exact thing P-088 forbids and says why: the comms
processor watches every pairing exchange, and MACing under the master secret
hands the one component this document declares hostile an HMAC oracle under the
one secret the whole device depends on. Two requirements one page apart said
opposite things about which key signs the same message, and an implementer would
have picked whichever they read second.

**P-055** — A client MUST NOT render an unauthenticated message as a statement
about the site. From an unauthenticated `Error` a client may retry or reconnect,
and may conclude nothing else.

**P-056** — A client MUST hold a mark meaning **the lowest `seq` it will still
accept**, and MUST reject an unsolicited `Event` (`0x04`) whose `seq` is below
it. On accepting a `SubscribeAck` the mark is set to `accepted_from_seq`; on
accepting an event it is set to that event's `seq + 1`. That is what stops a
replay inside a session.

Written as *not greater than the highest accepted*, with the mark reset to
`accepted_from_seq`, the rule discarded the first replayed event of every
subscription: `accepted_from_seq` names a position that is delivered (P-029), and
the record at exactly that position is not greater than the mark. One record per
subscription, always the oldest one the client asked for, and on a stream that is
quiet for eleven months of the year that record is as likely as not the alarm
somebody subscribed to find. Phrasing the mark as a floor rather than as a
high-water line makes both cases the same sentence.

Without the reset on `SubscribeAck`, a second `Subscribe` from an earlier
`from_seq` delivers events the client is then obliged to reject one by one, and
the catch-up P-094 exists to guarantee does nothing at all.

`LogEntry` values inside a `LogPage` are outside this rule entirely. They are
records the client asked for, by `req_id`, under a response MAC bound to that
request — going backwards is the whole point of `ReadLog`, and a rule written for
the live stream must not reach the catch-up path it exists alongside.

**P-057** — `Hello 0x01` and `Pair 0x0B` cannot be checked before their bodies
are read: `Hello`'s key comes from a `client_id` inside the body, and `Pair`'s
preimage covers `client_kind` and `label`, which are inside it too. So the order
is fixed here rather than left to P-051: decode the body under `MAX_PAYLOAD`,
`MAX_STRING`, `MAX_DEPTH` and P-015; take the fields the proof needs; verify the
proof; and only then act on anything that was decoded. A decode failure is error
1 and an unknown `client_id` is error 12, and neither does any further work. With
P-072 this is the second place a value is used before it is authenticated, and
conformance items 4 and 5 are what stand behind it.

---

## Sessions

### Discover — `0x00` / `0x80`

The only thing an unauthenticated peer gets: enough to know what it is talking to
and whether it can be paired with.

```text
Discover  0x00
  (empty map)

Discover  0x80          unauthenticated
  1: protocol_major   u8
  2: protocol_minor   u8
  3: device_id        bstr16
  4: model            text
  5: provisioned      bool     true once at least one client is enrolled
  6: pairing_open     bool     true while a physical act at the controller has
                              opened a window (P-066)
  7: challenge        bstr16   fresh per connection, from the controller
  8: epoch            u32      provisioning epoch; keys derived under an older
                              one no longer verify (P-085)
```

Everything else — snapshot, log, configuration, firmware state, diagnostics —
requires an authenticated session. Configuration alone would otherwise leak
occupancy, generator activity, energy use and network settings to anyone within
BLE range.

**P-060** — The controller MUST attempt to mint a **fresh challenge per connection**,
using the connection handle from [LINK.md](protocol/LINK.md) L-060, and MUST hold
at most `MAX_CHALLENGES`. A single device-wide challenge livelocks two clients against
each other exactly the way a device-wide counter would.

A `Discover` MUST be answered with that connection's **current** challenge
when one is available. If the connection holds none — the one it had was
consumed, it expired at 120 seconds, or initial minting failed under L-070 —
the controller MUST discard any expired challenge and attempt to mint another
for that handle. If minting fails, the connection holds no challenge and the
controller MUST send the refusal below. At most one challenge exists per
connection at any moment; only a live challenge may be returned. Handing back a challenge that is already dead
sends a client off to compute a proof that cannot verify, and error 14 is the
only way it finds out.

If the controller cannot supply a valid challenge, it MUST refuse `Discover`
with error 18 `challenge unavailable`, using the error shape P-142 requires
and echoing the request under P-027. This includes exhausted challenge storage,
a failed challenge generator, and missing provisioning material needed to
produce a valid response. It MUST NOT send a placeholder or expired challenge,
or evict another connection's challenge. Error 18 is readable bare; under
P-055 and P-140 it permits retrying or reconnecting, never a conclusion about
the site or a guarantee that the next attempt will succeed. Error 7 remains
MAC-required and MUST NOT be used for this refusal.

A bare `busy` is discarded by a conforming client, leaving it to time out.
Giving this refusal its own code lets the client read it before a session exists
without allowing a forged bare `busy` to stand in for an authenticated refusal
of an in-session request.

**P-061** — A challenge MUST be **single-use**: consumed by the first `Hello` or
`Pair` that presents it. A second use is error 14.

Consuming one leaves the connection holding none, and something has to replace
it or a browser would have to drop its socket in the middle of enrolment. Two
things do: P-058 hands the replacement back inside the `Pair` response, which is
what makes the flow with somebody standing at the panel `Discover`, `Pair`,
`Hello` on one transport; and P-060 mints one on the next `Discover` for every
other case, a `Hello` that consumed one, a challenge that expired, a client that
ignored key 4.

**P-062** — A challenge MUST expire 120 seconds after it is minted, and MUST be
discarded when its connection drops. Error 14 tells the client to reconnect and
retry. Exactly two conditions produce it and no others: a challenge presented
after it expired or after its connection dropped, and a challenge presented a
second time (P-061). A client cannot tell them apart and does not need to — both
mean *the thing you proved against is gone, go back to `Discover` for a live
one*, which is why they share a code rather than costing the registry two.

**P-063** — A challenge MUST come from a CSPRNG. A predictable challenge makes
the session key predictable.

### Pair — `0x0B` / `0x8B`

A client is enrolled once, in person, and derives a key it is never sent.

```text
Pair  0x0B
  1: client_kind      u8       see REGISTRY
  2: label            text     ≤ MAX_LABEL; what a person sees in the client list
  3: proof            bstr16
  4: client_nonce     bstr16   fresh per attempt, from the client's CSPRNG

proof = HMAC(pair_key, "km43/v1/pair-proof" | device_id | challenge
                     | client_nonce | client_kind:u8 | label)[0..16]

Pair  0x8B
  1: outcome          u8       see REGISTRY
  2: client_id        u32      0 when outcome is neither 1 enrolled nor 5 reclaimed
  3: mac              bstr16
  4: next_challenge   bstr16   the challenge this connection holds now that the
                               one just presented has been consumed

mac = HMAC(pair_key, "km43/v1/pair-ack" | device_id | challenge
                   | client_nonce | outcome:u8 | client_id:u32be | epoch:u32be
                   | next_challenge)[0..16]
```

**P-069** — `client_nonce` MUST be fresh per pairing attempt and MUST be in both
preimages. Without it every input to the pair-ack MAC is chosen by the controller
or fixed by the device, so an ack recorded from an earlier enrolment verifies
again on a later attempt — and the ack is the message that fixes a client's
identity. The controller would be telling one phone it is `client_id 3` while a
replayed ack tells the next phone the same thing.

`label` enters the preimage as its **UTF-8 bytes**, without the CBOR text-string
header, and it is last and carries no length prefix — it is the one
variable-width field in any preimage in this document, everything ahead of it is
fixed width, and that is the same convention P-048 uses for `operation` and
`payload`. `MAX_STRING` bounds it at 64 bytes.

It is in the preimage because it is the field a person reads when deciding which
enrolments belong at this site. Left outside, the comms processor rewrites it in
flight at no cost and the controller stores the rewritten value and authenticates
it onward — an audit record naming a device that was never there. P-070 already
states the same principle one message over.

**P-058** — `Pair 0x8B` MUST carry `next_challenge`: the challenge the
controller mints for that connection as the presented one is consumed, minted
under P-060 and P-063 like any other. It MUST be inside the pair-ack preimage,
and it is present on **every** outcome.

The enrolment flow was `Discover`, `Pair`, `Discover`, `Hello` — four messages,
of which the third exists only to collect a replacement challenge, because P-061
makes a challenge single-use. That is a whole round trip on a link somebody is
standing in front of with a phone, spent asking for a value the controller had
already decided to mint. Issuing it in the ack makes the flow `Discover`,
`Pair`, `Hello`.

**It is inside the MAC because the next `Hello` proof is computed against it.**
Left outside, the comms processor substitutes a challenge of its own choosing and
the `Hello` that follows proves against a value the untrusted party picked, which
is the one input to `session_key` the controller is supposed to own. That is
P-069's argument for `client_nonce`, one field over and in the other direction.

Every outcome carries it because P-061 consumes a challenge on **presentation,
not on success**: a `Pair` that failed its proof has still spent it. A client
told `bad_proof` needs a live challenge to retry the thing it just got wrong, and
without key 4 in that response the answer would be another `Discover` — which is
the round trip this requirement deleted, put back on the path where somebody is
already frustrated. A client MAY ignore key 4 and `Discover` again anyway; P-060
mints a fresh one and discards this one, exactly as it does for a challenge that
expired.

**P-064** — An enrolment that succeeds MUST be answered with `Pair 0x8B` outcome
1 `enrolled`, carrying the allocated `client_id`. Every refusal names its outcome
somewhere below; the one that succeeds did not, and an implementer reaching it by
elimination is the guessing this document says it must never require.

The pairing response MUST carry the MAC above, and a client MUST
discard a response that fails it rather than enrolling. Nothing else in this
protocol can authenticate this message: no session exists, and `client_key`
cannot be derived until `client_id` has been read out of this very message. The
earlier draft left it authenticated by nothing, which let the comms processor
choose a client's identity and its replay baseline.

**A wrong printed secret earns a refusal its client cannot check.** The
controller MACs outcome 3 under the real `pair_key` (P-051), and a client that
scanned the wrong label derives a different one, so the `bad_proof` it earned
fails the MAC exactly as a forged reply does. It cannot tell the two apart.
The client MUST treat a pairing response that fails the MAC as a failed attempt
that may mean a wrong code: it MUST NOT enrol, MUST NOT prove a retry against
that response's `next_challenge`, and starts any retry from `Discover` (P-060).
It MAY tell the person the code may be wrong and offer to rescan. It MUST NOT
say the code *is* wrong or that the controller refused: the response is
unauthenticated, and P-055 applies. A retry whose proof the controller checks
and rejects counts against `MAX_AUTH_FAILURES` (P-051), so a phone still holding
the wrong code sheds its own connection after eight tries.

The converse is a statement the client can make. A `bad_proof` that **verifies**
was MAC'd under the `pair_key` the client holds, so the code was right and the
controller received fields that do not match the proof: a `label` or
`client_kind` rewritten in flight (P-069), or a client computing its own proof
wrong. Telling that person to rescan sends them back to a label that was
never the problem.

**P-065** — A newly enrolled client's counter MUST start at **0**, and the
response MUST NOT carry a starting counter. A counter supplied by the network is
a counter an attacker can set to `2^64 − 1`, after which every write that client
ever makes fails as stale and recovery is a four-hour drive.

**P-066** — A physical act at the controller MUST gate enrolment: the pushbutton
on a board that has one, otherwise the selector gesture the controller's design
defines under *Auto / off / manual* ([CONTROLLER-V1](https://github.com/origin89hq/origin89/blob/main/docs/CONTROLLER-V1.md)),
with the first-enrolment power-on exception below. No message opens the window.
Knowing the printed secret is not by itself sufficient. The window is 120 seconds.

On a controller board without a pushbutton, power-on MUST open the window once
per boot, at boot, **only when it reads a valid empty client table**, whether
empty after factory reset or after recovery of a lost or corrupt table. A boot
that finds the table absent or unreadable and repairs it to a durable empty
table MUST NOT open a power-on window; a later boot that reads that valid empty
table is eligible. This window lasts the same 120 seconds
and MUST close on the first successful `Pair`, as any window closes on successful
enrolment under L-195; one opening admits one enrolment. While the client table
is non-empty, power-on MUST NOT open a window: only the design's selector gesture,
or the pushbutton on a board that has one, opens it. A board **with a pushbutton
MUST NOT use this exception**. `Pair` still requires the printed-secret proof
(P-064, P-068); the window is an additional gate, never a replacement for that
proof. This temporary rule serves controller board A revision A and MUST be
retired when the pushbutton is present ([firmware#60](https://github.com/origin89hq/firmware/issues/60)).

The controller reports every window's open and closed state, including a
power-on window, to the comms processor using
[PairingWindow](protocol/LINK.md#pairing-reachability) (L-193 through L-195)
so a phone can reach it without the house network; that report grants no
enrolment permission. The deadline starts at boot for a power-on window, not
when the link becomes ready. A `Pair` arriving with no window open MUST be
answered with `Pair 0x8B` outcome 2 `window_closed` and `client_id = 0`, carrying
the MAC above — not with an unauthenticated error. A refusal the comms processor
can forge is a refusal that sends somebody back to the panel to perform an act
that was never needed.

**P-067** — A full client table MUST refuse with outcome 4, **unless P-078's
reclaim matched first**. It MUST NOT evict. `table_full` therefore means eight
distinct labels rather than eight pairings.

**P-068** — Counter recovery is a **re-pair, not a reset**. A reinstalled app
pairs again, in person, and is given the **same** `client_id` when its `label`
matches an occupied row byte for byte (P-078, outcome 5 `reclaimed`), and a new
one otherwise. What must never happen is handing a client a fresh counter for an
existing id **on request** — that is a replay hole with a friendly name. What
makes a reclaim different from a request is the evidence behind it: the button,
the 120-second window and a proof under `pair_key` that needs the printed
secret, which is the same evidence as a first enrolment and not a message
anybody can send.

**P-078** — Inside an open pairing window, a `Pair` whose proof verifies and
whose `label` is **byte-identical** to an occupied row's label MUST reuse that
row: same `client_id`, counter back to 0, `client_kind` and capability mask
re-fixed from this proof exactly as at first enrolment, answered with outcome 5
`reclaimed`. Matching MUST run **before** allocation — reclaim, then P-086's
lowest free slot, then P-067's outcome 4 — and it MUST compare the exact UTF-8
bytes that entered the pair-proof preimage: no case folding, no trimming, no
Unicode normalisation.

**Every session bound to that `client_id` MUST be unbound before the row is
rewritten**, and the counter MUST NOT be reset while any binding on the row
survives.

Without that the reset is a replay hole. The three rules below hold for a frame
captured under an *old* session; they say nothing about a session that is still
bound when the reclaim happens, and nothing else unbinds one. The counter row is
per `client_id` (P-081) and is selected by the session rather than the body
(P-084), so a session that survives the reclaim reads a row that was just set to
0 under a `session_key` nothing touched — and every signed frame captured from
that session carries a counter above 0. Ten minutes later the dedup entry ages
out and a captured `Command` is executable again.

Unbinding is enough on its own, and the transport does not need closing: the
client discovers it through error 9 and reconnects, which is the signal P-143
already documents for a session that no longer exists.

**Without this the client table is a consumable.** `MAX_CLIENTS` is 8 and those
eight are shared by every phone, every browser, the cloud and the CLI, while
P-068 makes spending one *routine*: app reinstalled, phone replaced, browser data
cleared. The break point is eight cumulative re-pairings, not eight people, which
one phone reaches in a season — and after it, the answer to *the site cannot be
told to stop* is a four-hour drive. The cost of physical-only revocation was
priced against a lost phone, which is rare. Nobody priced the reinstall.

Nothing new is granted by it. Whoever can reclaim a row can already enrol into a
free one and can already factory-reset the whole table.

**Matching on `label` is sound only because `label` is inside the pair-proof
preimage** (P-069). Outside it, the comms processor rewrites it in flight — to
point a reclaim at somebody else's row, or to stop a legitimate match and burn a
slot. The byte-exact comparison is the same argument one layer down: two
implementations that normalise differently hand one client another client's row.
The cost is that renaming a phone spends a slot, which is the right way round,
because that is visible to the person standing at the panel and the other error
is not.

**A reclaim is not a revocation, and reaching for it as one is the wrong tool.**
Same epoch and same `client_id` means a byte-identical `client_key`, so the old
install still holds a working key. This is for the honest case. A stolen phone is
still the button and a factory reset, which bumps the epoch and invalidates every
key at once (P-085).

**Setting the counter back to 0 does not re-open replay**, and that is worth
writing down because it is not obvious. A signed request is MAC'd under
`session_key`, never under `client_key`, and `session_key` binds a single-use
CSPRNG challenge (P-061, P-063) and the client's own nonce (P-071). A frame
captured under an old session cannot verify under a new one at any counter value.
And P-078 unbinds every session on the row **before** the counter moves, so
there is no session left that a captured frame could verify under. The counter
orders a client's writes within a session and across a reboot; it is not what
stands between a recorded frame and a replay. Weaken any one of those four rules
and this reset becomes a hole — which is the sentence to check against before
weakening one. The fourth was missing until a reviewer checked the other three
against it and found the case they do not cover.

**P-105** — Every enrolled client MUST carry a **capability mask**, fixed at
enrolment from the attested `client_kind`, stored in FRAM beside that client's
counter, and never changed by any message. The bit allocation and the per-kind
rows are in [REGISTRY.md](protocol/REGISTRY.md). A `client_kind` with no row
there MUST be refused at enrolment. A refused capability MUST be answered inside
the MAC'd response for that message — `SetConfigAck` outcome 4 `unauthorised`,
`Ack` outcome 5 `unauthorised`, `TimeAck` outcome 3 `unauthorised`, `Firmware`
outcome 8 — and never with an `Error`, which is P-141 applied.

Three outcomes spelled out an authorisation model that no normative document
defined a single permission for, which left all eight enrolled clients strictly
equipotent: **the cloud client could push firmware, write the site's Wi-Fi
passphrase and move the clock.** That client is reachable from the internet by
definition. A vocabulary of refusals with nothing behind it is worse than an
outright gap, because it reads as implemented to everybody who greps for it.

`client_kind` is a sound input and LINK.md's `transport` (L-072) is not, and the
difference is provenance: `client_kind` is inside the pair-proof preimage — its
last two fields are `client_kind:u8 | label` — so it is attested under `pair_key`
by a holder of the printed secret inside the 120-second window P-066 opens, while
`transport` is written by the comms processor, which lifts any rule keyed on it
for free.

**No message raises a mask and no message lowers one.** Either is a re-pair,
which means the button. This is the rejected-`Revoke` argument one field over: a
mask any client can edit is a mask the most exposed client edits first, and the
party that most wants firmware authority is exactly the party that must not be
able to grant itself firmware authority. A reclaimed row re-fixes its mask from
the proof P-078 just verified, so a row's permissions never outlive the enrolment
that set them.

**The mask is only as good as the enrolment, said out loud.** Whoever holds the
printed secret inside an open P-066 window chooses `client_kind`, and can therefore
enrol a cloud relay as `1 app`. That person already has the label and an open window,
which is the whole of the authority in this design. The mask defends against a
client that turns hostile later, not against the person who enrolled it.

**The limitation, stated rather than left to be discovered:** anyone who
photographs the label can derive keys, and there is no forward secrecy. The
upgrade is an authenticated key agreement — see
[DEFERRED.md](protocol/DEFERRED.md).

### Hello — `0x01` / `0x81`

```text
Hello  0x01
  inner body:
    1: protocol_major   u8
    2: protocol_minor   u8
    3: client_id        u32
    4: client_version   text
    5: client_nonce     bstr16
  body:
    1: payload          bstr     the inner body above, encoded
    2: proof            bstr16

proof = HMAC(client_key, "km43/v1/hello-proof" | challenge | client_nonce
                       | client_id:u32be | payload)[0..16]

Hello  0x81             wrapper under session_key
  1: protocol_major   u8
  2: protocol_minor   u8
  3: session_id       u16      also in the envelope; MUST match
  4: fw_controller    text
  5: fw_comms         text     what the comms processor says about itself.
                               Diagnostic only — a client MUST NOT decide on it
                               and MUST NOT read it as confirmation that a
                               comms image is installed
  6: capabilities     u32      bitfield, see REGISTRY
  7: log_oldest_seq   u64
  8: log_newest_seq   u64
  9: state_seq        u64
 10: time_known       bool
 11: counter          u64      this client's last accepted counter
 12: max_sessions     u8       the reported limits, P-005. What this controller
 13: max_channels     u8       enforces, not what the protocol permits.
 14: max_clients      u8       Key 13 is capped at 32 and only ever reported
 15: max_event_queue  u16      downward from it (P-006)
 16: max_inflight     u8
 17: max_cmd_dedup    u16      entries; the 10-minute window is not negotiable
 18: rev              u32      the topology revision
 19: topo_digest      bstr8    P-148's hash; with key 18 it is one identity (P-149)
 20: max_buses        u8       the topology caps: P-005, one message over
 21: max_devices      u16
 22: max_components   u16
 23: max_signals      u16
 24: max_series_elements  u16  a shared pool; it implies nothing about key 23
 25: max_params       u16
 26: max_concerns     u16
 27: max_selectors    u8       per ReadSignals
 28: max_history_signals  u16
 29: max_topology_depth   u8   how deep either parent chain may run
```

**P-070** — The Hello proof MUST cover the whole inner body, so that
`protocol_major`, `protocol_minor` and `client_version` cannot be rewritten in
flight. Version negotiation running on attacker-controlled values is a downgrade
with extra steps.

**P-071** — `client_nonce` MUST come from a CSPRNG and MUST be fresh per
handshake. Without it every input to the session key is either long-term or
chosen by the untrusted side, and a recorded session replays cleanly at a client
that cannot tell.

**P-072** — The client derives `session_key` using the `session_id` from the
**envelope** of the Hello response, then verifies the body MAC. This is the one
place a value is used before it is authenticated, and it is safe because
`session_id` is inside the preimage: a rewritten `session_id` yields a different
key and the MAC fails.

**P-073** — A major version mismatch MUST refuse the session with error 3. A
minor mismatch MUST proceed at the lower of the two. A newer client degrades; it
never assumes.

**P-074** — `state_seq` is the state store's own counter. `log_oldest_seq`,
`log_newest_seq` and every `seq` elsewhere in this document are positions in the
**log** sequence space. They are two spaces and MUST NOT be compared.

**P-075** — A client SHOULD refuse, and MUST surface, a session whose
`log_newest_seq` or `state_seq` has regressed below the highest it previously
accepted from that `device_id`. This is SHOULD rather than MUST because a board
swap or a NOR erase regresses it legitimately, and a hard rule would turn a
repair into a lockout at a site four hours from a road.

### Goodbye — `0x0C` / `0x8C`

```text
Goodbye  0x0C          wrapper, empty inner body
Goodbye  0x8C          wrapper, empty inner body
```

**P-076** — A connection row has two independent states: **allocated**, meaning a
transport exists, and **bound**, meaning a session is running on it. `Goodbye`
clears the binding only. The row stays allocated to the transport that is still
open, its handle is not reusable, and the controller MUST free the row itself on
`ClientDisconnected` from [LINK.md](protocol/LINK.md) and on a new comms
`boot_id` (L-041). Without the binding being freed, a browser refreshed eight times
inside the expiry window locks every client out for fifteen minutes; without the
distinction, one polite `Goodbye` makes the controller's connection count
disagree with the comms processor's and the heartbeat resync costs the other
seven clients a reconnect.

A client that has sent `Goodbye` MAY `Hello` again on the same transport: the row
is still allocated, and the next `Discover` on it returns a live challenge under
P-060.

**A `Hello` whose proof verifies on a row that is already bound MUST replace the
binding**, deriving the new `session_key` from the challenge and `client_nonce`
that `Hello` presented. The previous `session_key` MUST be destroyed and that
session's outstanding requests abandoned. It MUST NOT be answered with error 8.

The state is reached routinely and not by anybody misbehaving: the controller
binds the row, the response is lost on the way back, and the client — holding no
`session_id` and no key — has nothing to do except `Hello` again. Refused, it is
stuck until P-077's fifteen minutes expire the session it never learned it had,
on a transport it believes is healthy. Error 8 is the worst of the available
refusals, because it means *session table full* and a client reading it waits
rather than reconnecting; a binding held by the client that is asking is not a
full table.

Replacement rather than refusal is safe because the proof is the whole check. A
peer that can verify a `Hello` on this row can already open a fresh row, and the
row is not a permission — it is a place to put a key. Note that the replacing
`Hello` may carry a *different* `client_id`: the session binds whichever one
proved, and counters are per client in FRAM (P-081), so nothing about the
previous client's counter row moves.

**P-077** — Sessions expire after 15 minutes without traffic, and the controller
sends `CloseConnection` with reason `session_expired` so the row and the
transport go at the same moment rather than leaving a socket the client believes
is healthy.

**Only an authenticated inbound frame refreshes that timer** — a request whose
wrapper MAC or signed-body MAC verified on that session and that P-022 did not
refuse. A replayed request verifies, which is why the second condition is
needed: without it, one captured frame replayed before each expiry is a
keep-alive the relay holds. Outbound MUST NOT
refresh it: not a response, not an event, not a `records dropped` record the
controller generated by itself. A frame that fails its MAC does not count as
traffic either; it counts against `MAX_AUTH_FAILURES`.

*Traffic* was never defined, and the reading that costs nothing to arrive at is
the wrong one. If an outbound event refreshed the timer, a **subscribed session
would never expire at all** — the controller is publishing to it every time
anything on the site moves, so the session stays alive on the strength of the
controller talking to itself. And the sessions most likely to be stale are
exactly the subscribed ones: the browser tab somebody closed the lid on still
holds one of eight bindings, cheerfully fed events nobody is reading, until
somebody at the panel is refused with error 8 for a session that stopped existing
in any useful sense hours ago. Expiry has to measure the client still being
there, and only something the client sent measures that.

`MAX_SESSIONS` is 8, and a `Hello` that finds no binding free is
refused with error 8. Today that only fires on a transport the comms processor
does not own, because it refuses a ninth connection at `ClientConnected` before
any `Hello` can be sent. A session table that grows with reconnections is an
unbounded allocation wearing a different hat.

---

## Signed requests

Every **write** is signed: configuration, firmware, time and commands. Not just
commands — authenticating one write and not another is a locked door next to an
open one.

```text
body of any signed request
  1: client_id    u32
  2: counter      u64      MUST exceed this client's last accepted value
  3: operation    bstr     the CBOR-encoded operation body
  4: mac          bstr16
```

**P-080** — The controller MUST take these steps in this order:

1. Verify the MAC. A MAC that fails is P-051's error 10.
2. Check the counter. A counter that does not exceed the stored value MUST be
   refused with error 11.
3. For a `Command 0x08`, look up `(client_id, cmd_id)` in the dedup table and
   answer per P-120 and P-124 on a match, **without executing**.
4. For a `Command 0x08`, reserve a dedup entry marked **in flight**, and persist
   it together with the new counter **in one FRAM transaction**. A failure here
   is P-079's error 7 and P-122's error 7.
5. Execute.
6. For a `Command 0x08`, mark the reserved entry **complete**, carrying the
   outcome it produced.

Persisting before executing is deliberately fail-closed: a brown-out between the
two loses the operation, and the client's retry carries a new counter and
succeeds. The reverse order leaves a replayable counter after a power cut, which
is the worse failure at this site. One number each for the two refusals, named
here rather than picked at a bench.

The dedup entry is written in the same transaction as the counter for the same
reason the counter is written before the handler runs. Written after `execute`,
it is exactly the record that a reset between the two destroys — which is the
window P-121 puts the table in FRAM to close, reopened three lines below the
requirement that closes it. Written before, a crash leaves an entry saying an
operation may have run, which is a question the controller can answer.

**What a retry meets against an entry left *in flight* by a reset is the case
this ordering exists for, and ordering alone does not answer it.** The controller
cannot know from the entry whether the operation ran: the reset could have landed
on either side of `execute`. It MUST NOT assume either. It MUST answer from the
**state store**, which is authoritative for what the hardware is doing — if the
contact the command asked for is already in the asked-for state, the entry
completes as `accepted` and the retry is answered outcome 3 `duplicate`; if it
is not, the entry is discarded and the retry executes normally. That is the one
reading under which a `start` interrupted by a brown-out neither starts twice
nor silently fails to start, and it is available because the state store is read
from the hardware at boot rather than remembered.

**P-079** — If persisting the counter fails, the operation MUST NOT execute. The
controller MUST answer error 7 `busy` and MUST raise a class A `concern raised`
(`0x0501`) at condition `counter write failed`. It MUST NOT execute anyway and
leave a counter store that does not know it happened.

Fail-closed is the whole of P-080's ordering, and it had no exit. FRAM is where
the per-client counters live, and the client keys, the dedup table, the A/B
configuration pointer and the panic reason with them; a write that fails there is
the controller losing its record of what it has already accepted. Execute anyway
and the frame that just ran replays the moment somebody sends it again — the hole
P-080 orders its steps to close, opened by the one step that did not work.
[LINK.md](protocol/LINK.md) L-137 gives the comms processor `nvs_write_failed` for
exactly this on its own side, where what is at stake is a Wi-Fi passphrase; the
controller side, where it is a counter, said nothing at all.

Error 7 because there is one instruction to give and it is *the controller did
not do this, send it again*: a retry carries a new counter under P-082 and lands
if the next write succeeds. P-141 is not in tension with that — the persist sits
ahead of `execute` in P-080's order, so nothing has reached a handler yet, which
is the condition P-141 keeps `Error` for. And what tells somebody the part is
wearing out is the class A record, which lands in the log in NOR — a different
device from the one that just failed — rather than the error code, which the
comms processor can drop.

**P-081** — Counters are **per client**, stored `client_id → highest accepted` in
FRAM. A single device-wide counter livelocks the moment two clients are active:
both read 100, both send 101, one is rejected forever.

**A client that receives error 11 MUST take its next counter from `Hello 0x81`
key 11**, re-`Hello`ing if it no longer holds a live value, and MUST NOT retry by
incrementing the value it just had refused.

A local increment from a value that is already behind the stored one never
catches up: the client sends 101, is refused because the row holds 340, sends
102, is refused, and spends the afternoon walking towards a number it cannot
see. That is P-081's livelock reached by one client on its own, and it is
reachable in the honest case — two installs of the same app on one `client_id`,
or a client whose local counter did not survive a crash. Key 11 is the way out,
and until this rule existed the field list described it as *this client's last
accepted counter* and nothing told anybody to read it.

**P-084** — Key 1 `client_id` MUST equal the `client_id` the session was bound to
at `Hello`. A mismatch MUST be refused with error 12 **before** the counter is
read or written. Key 1 is on the wire only because it is inside the MAC preimage;
it is never the lookup key, and the counter row is selected by **the session**,
not by the body.

Without this the counter store is keyed by a field the sender chooses, and the
MAC does not save it: the sender computes it under its own `session_key`, so the
preimage *covers* the field without *constraining* it. Any enrolled client could
write `2^64 − 1` into another client's row, and that client's every later write
would fail as stale until somebody drove out — which is exactly the lockout P-065
exists to prevent, reached through a different message. This document already
sets the precedent it nearly omitted: `Hello 0x81` key 3 carries `session_id`
with *MUST match*, and the framing section refuses a second length field on the
grounds that a second source of the same fact is a second thing to disagree with
the first.

**P-082** — `counter` prevents replay. `cmd_id` suppresses duplicates. They solve
different problems and both are required: a retried command carries the same
`cmd_id` and a **new** `counter`.

**P-083** — `operation` MUST NOT exceed `MAX_OPERATION` (960 bytes). The
worst-case CBOR overhead of the signed body and the envelope around it is 49
bytes, so a payload holds an operation of **975** — and 960 is a cap with
margin, not that ceiling, the same way every page cap in the reading and
inventory planes sits under one.

The fifteen bytes are what absorbs a later key. The signed body is one of the
three whose MAC covers *fields* rather than an encoding, so a key added to it
enters the preimage and these bytes both; without the margin, adding one turns
an operation that was legal yesterday into a frame the controller builds and
then has to refuse. This paragraph said 960 *was* `MAX_PAYLOAD` less the
overhead, which is an equality that never held: the overhead is 49 and the
subtraction gives 975.

---

## State and events

**P-093** — Every field carrying a **wall-clock time** MUST be omitted when the
clock has never been set, and a zero MUST NOT be sent to mean *unknown*. 1970 is
a plausible wrong measurement, and this project does not ship a default that can
be mistaken for one.

Stated by category rather than as a list of keys, because the list was the
defect: this rule was written about two keys of one message, and it has to reach
`Readings 0x8E` key 3, `Event 0x04` key 2 and every `at` a later body adds. A
**duration** is a different thing and is not covered here. Anything on P-004's
monotonic tick — `age` above all — is a claim a controller with no date can
honestly make, which is why the reading plane measures staleness that way and
asks for no timestamp at all.

**Retired with `Snapshot 0x02`/`0x82`.** The message carried a whole site in one
frame, keyed by channel; `Readings 0x0E`/`0x8E` pages by `sig` and is what
replaced it. Five numbers are held and not reused, and each one's argument is
stated where it now lives:

- **The `i32` bound on a value** (P-089) held key 3 down so that a full `MAX_CHANNELS`
  snapshot fitted `MAX_PAYLOAD`. **P-185** carries the bound to every value
  position on the wire and adds what P-089 left unsaid: an out-of-range source
  value is published with no value at all rather than clamped.
- **The site-wide cap** (P-090) bounded `values` at `MAX_CHANNELS`, with no paging.
  Both were facts about one frame carrying the whole site. `Readings` pages, so
  the cap it needs is a *page* cap: 880 bytes is what one response holds and 384
  signals is what a site can mean.
- **Absence omitting the value** (P-091) dropped key 3 when `quality` was `absent`, so a client could tell
  *configured but unreadable* from *not configured at all*. **P-196** makes the
  value key present exactly when the `q` byte says so, and the distinction is
  sharper than P-091 could express: `initialising`, `sensor_fault`,
  `unsupported` and `absent` are four answers where `quality` had one.
- **Stale carrying a timestamp** (P-092) required the last value **and a date**. The
  first clause survives in **P-196**; the second was a cost rather than a rule.
  A wall-clock date is what made `stale` inexpressible on a controller whose
  clock had never been set — P-093 forbids inventing one — so the last known
  value disappeared exactly when somebody wanted it. `age` is a duration on
  P-004's tick, which a controller always has.
- **The channel cap** (P-006) caps `Hello` key 13 at 32 and is **not** retired: it binds both
  directions and `max_channels` is still reported. Only its derivation died with
  the message, which the limits section says out loud.

**The concern lifecycle.** A concern is a condition a source is reporting, and
it has five states because two of them are the difference between *wait* and
*drive out*. `Concerns 0x0F`/`0x8F` is the message that publishes them and its
body is deferred; the lifecycle is settled here because the controller holds it
whether or not anything has asked.

| | | |
|---|---|---|
| 1 | `active` | the condition is present |
| 2 | `active_acked` | somebody has read it. The condition is still present |
| 3 | `latched_cleared` | the condition is gone; the source's latch is not, and will clear on the source's own terms |
| 4 | `clearing_blocked` | the condition is gone and the source states it *cannot* reset the latch yet — a BMS protection needing a completed charge cycle |
| 5 | `cleared` | over. Terminal |

**P-168** — Acknowledging a concern moves `state` from **1 `active` to 2
`active_acked`** and never to 3, 4 or 5. Only the condition going away moves it
further.

A protection somebody has read is not a protection that has cleared. On the
equipment this replaces the two were one command called *clear alarm*, and a
charger started on the strength of an acknowledged over-temperature is what that
word buys. A person is not the condition going away, and no number of reads ends
one.

**P-180** — `5 cleared` is terminal, and a concern row leaves the table only
carrying it. A `cid` MUST NOT be reallocated until the record announcing the
clear is committed.

A row removed at `latched_cleared` disappears from a screen with the latch still
holding, and disappearance is not something a client can detect here: concerns
deliberately do not move `rev`, so P-152 never fires a refetch and the client
simply stops being told. Terminal also means a condition that returns is a **new**
concern with a new `cid` — an id freed before its clear is durable can be handed
to a different condition while a client still believes the old one is open, and
nothing on the wire distinguishes that from an update.

**P-208** — A page ends at its **row cap** or its **byte cap**, whichever binds
first, and a row is never split across two pages. A client MUST NOT assume both
caps are reachable at once, and MUST size a page as
`min(row cap, byte cap ÷ row width)`.

Reporting a number the controller does not enforce is worse than not reporting
it, and two caps read as simultaneous is exactly that: 40 samples and 7
full-width series are 1,577 bytes against a `Readings 0x8E` budget of 880.
Which arm binds is a property of the message and of the rows in it, and the
answer differs per message — the row cap always binds for `Concerns 0x8F`,
where twelve rows at their widest are 756 bytes against 832. So a client that
sizes its array off the row cap and its buffer off the byte cap is right about
each and wrong about the product.

A row is never split because there is no continuation encoding, and deliberately
not one. Half a row on one page and half on the next is a row a decoder can only
reassemble by holding state across two requests, which is the resumption machine
P-146 exists to refuse.

### Inventory — `0x0D` / `0x8D`

The cold plane: what a client needs to *interpret* a number, fetched once and
paged. Five row kinds travel in one message because they are all descriptors and
they all move together under one `rev`.

The reasoning, the bounds and the rest of the model are in
[TOPOLOGY-DESIGN.md](protocol/TOPOLOGY-DESIGN.md). What is here is the wire.

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
  7: digest       bstr8    optional; the topology digest, present iff outcome is 1
                           and key 4 is 0
```

A page carries rows of exactly one kind, the `what` it echoes. `cmp`, `sig` and
`pid` start at 1 and reserve 0 (P-200); `bus 0` and `dev 0` are not reserved and
name the controller's own local I/O and the controller itself. The bounds named
here are in [TOPOLOGY-DESIGN.md](protocol/TOPOLOGY-DESIGN.md)'s bounds table.

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
                           unique within a bus (P-202)
  4: product      u16      product registry; 0xF000–0xFFFF vendor, skip-unknown
  5: dialect      u16      driver dialect registry; vendor range, skip-unknown
  6: role         u16      device role registry; vendor range, skip-unknown
  7: parent       u16      optional; the device this is a sub-device of.
                           Absent = attached directly to its bus
  8: serial       text     optional; ≤ MAX_IDENT
  9: hw           text     optional; ≤ MAX_IDENT
 10: fw           text     optional; ≤ MAX_IDENT
 11: label        text     optional; ≤ MAX_LABEL
 12: since        u32      the rev at which this row's physical identity last
                           changed (P-205)
 13: cmds         [ u16 ]  optional; ≤ MAX_COMPONENT_CMDS command kinds legal at
                           this device's own scope, cmp = 0. Absent = none (P-201)

ComponentRow
  1: cmp          u16      1..; 0 is reserved and MUST NOT be allocated —
                           it names the device as a whole (P-200)
  2: dev          u16
  3: parent       u16      optional; owning component. Absent = the device is the parent
  4: role         u16      component role registry; vendor range, skip-unknown
  5: index        u16      optional; 1-based instance within (dev, parent, role).
                           Absent = the only one of its role there. Never 0
  6: rollup       u16      optional; the component whose signals already account
                           for mine. May name a component of an ancestor device (P-203)
  7: label        text     optional; ≤ MAX_LABEL
  8: cmds         [ u16 ]  optional; ≤ MAX_COMPONENT_CMDS command kinds legal here.
                           Absent = this component accepts none (P-201)
  9: since        u32      the rev at which this row's meaning last changed (P-205)

SignalRow
  1: sig          u16      1..; 0 is reserved (P-200)
  2: dev          u16      REQUIRED
  3: cmp          u16      REQUIRED; 0 = the device as a whole (P-200)
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
                           Element k's label is `ebase` + k. Default 1 (P-206)
 13: esp          u16      optional; enum space registry.
                           REQUIRED iff vtype is 3 or 4, absent otherwise
 14: unit         u8       optional; unit registry. REQUIRED iff key 4 is in the
                           vendor range, absent otherwise (P-204)
 15: scale        i8       optional; same condition as key 14 (P-204)
 16: vns          u16      optional; vendor namespace. REQUIRED iff key 4 is in
                           the vendor range, absent otherwise
 17: hist         u8       optional; present iff this signal is stored for history
                           — the finest bucket it is kept at, coarse to fine
                           (1 day · 2 hour · 3 quarter_hour). MUST be absent when
                           vtype is 3 or 4. Absent = no history
 18: label        text     optional; ≤ MAX_LABEL

ParamRow
  1: pid          u16      1..; 0 is reserved (P-200)
  2: dev          u16
  3: cmp          u16      REQUIRED; 0 = the device as a whole (P-200)
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
 13: via          u16      optional; the command kind that writes it.
                           Absent = read-only
 14: unit         u8       optional; REQUIRED iff key 4 is in the vendor range,
                           absent otherwise (P-204)
 15: scale        i8       optional; same condition as key 14 (P-204)
 16: vns          u16      optional; same condition as key 14
 17: label        text     optional; ≤ MAX_LABEL
```

A **parameter** is what a downstream device says about itself and does not change
with the weather — a nameplate rating, an input current limit, a permitted floor
and ceiling. A *derated* limit, a BMS's present charge-current limit or a charger
backing off in heat, is an ordinary signal with `domain = 6 limit_upper`, because
it moves. That is the whole of the separation: a parameter changes when the
hardware changes, so it belongs to a descriptor under `rev`. Origin 89's own
configuration stays in `GetConfig`/`SetConfig` and is not a parameter.

A `ParamRow` carries no validity. Key 5 is present when the controller has read
the value and absent when it has not, and a change to it *is* a topology change.
Marking a pulled module's parameters absent without bumping `rev` would make the
digest diverge under a fixed revision and fire P-149's controller-fault MUST
against a controller that is behaving correctly. Whether the instrument is
reachable at all is a signal, on the hot plane, where it belongs.

**P-145** — An `Inventory 0x8D` whose `outcome` is not 1 MUST carry `next = 0`,
MUST carry no rows, and MUST NOT carry key 7.

`next = 0` is the natural encoding of *nothing follows*, so without this a
response that answered nothing is shaped exactly like one that answered
everything. On outcome 4 the `rev` matches, so nothing else fires: a client sees
a current revision, a finished walk and a whole-topology digest, and stamps a
cache it never assembled. A receiver MUST refuse the combination as well as a
sender refusing to write it — the receiving side is where the cache gets
stamped, and a rule enforced on one side is the side that is not enforced.

**P-146** — The controller MUST NOT pin a walk. It reports its current `rev` in
every page, and MUST answer a request naming a `rev` that is neither 0 nor
current with outcome **2 `superseded`**, the current `rev` in key 1, and an
empty row array.

Pinning is a resumption state machine holding a consistent view across round
trips on a part with no allocator, which is what
[PROTOCOL-RATIONALE.md](PROTOCOL-RATIONALE.md) rejected paging the snapshot for.
`rev` is the pin, it costs the controller nothing, and a torn walk is not
prevented but is detectable in a field that is already on every page.

**P-147** — A request that was answered, in whole or in part, is **outcome 1
`ok`**. A `what` outside 1..5 is **outcome 3 `unknown_kind`** and not an error:
the request parsed, and it named a table that does not exist. A `from` past the
last row the request resolves to is **outcome 4 `out_of_range`**.

An unallocated `what` refused as error 1 tells a client its message was
malformed, which sends somebody to check their encoder instead of their table
number.

**P-148** — `topo_digest` is the **leftmost 8 bytes of SHA-256** over this
preimage, and over nothing else:

```text
  "km43/v1/topo-digest"              19 bytes ASCII, no trailing NUL
‖ rev                                 4 bytes, big-endian
‖ for each descriptor row, in canonical order:
      the row's encoded CBOR map, byte for byte — exactly the bytes that
      appear inside the `rows` array of an Inventory 0x8D page

canonical order = `what` ascending, then the row's own id ascending in a kind
```

An absent optional key contributes nothing, because it is not in the bytes. A
`label` contributes the bytes of its CBOR text item, because the row encoder
emits it. Neither side re-encodes: the controller hashes what its row encoder
produced, and a client hashes the row bytes exactly as they arrived, which
`CborReader::raw` hands over whole. That is P-017 and P-048 surviving a hash
computed at both ends, which is the only way two implementations agree on one.

The label is a third kind of domain input beside P-043's two — not a MAC
preimage prefix and not an HKDF `info`, but a hash-domain prefix. It carries
`v1` so a later encoding cannot make every deployed client surface *controller
faulty* forever on a healthy site. `rev` is inside it so a digest can never be
lifted from one revision to another.

**P-149** — `rev` and `topo_digest` are **one identity**. A client MUST treat a
difference in either as a different topology and MUST discard its cached
descriptors. A client meeting a matching `rev` with a differing digest MUST
refetch **and** MUST surface it as a controller fault. The digest a controller
reports MUST equal P-148's hash of the descriptor rows **as they stand at the
moment of the response**; a controller MAY cache the value and MUST invalidate
that cache on any write to any descriptor row.

A digest a client only compares when it fetches is a digest nobody ever
compares, because a client whose `rev` matches never fetches. Putting it in
`Hello 0x81` puts it in front of the one party that can catch a descriptor
changed without the revision moving.

**The trigger is the row write and not the `rev` bump**, and that is the whole
requirement. A controller that recomputes on the bump satisfies any looser
wording, then edits a `ComponentRow` without bumping and reports a digest that
still matches — so the one mechanism this protocol has for its own silent
failure is not compelled to exist by the rule that claims it.

**P-200** — `cmp = 0` is reserved in **every** message that names a component
scope, and it means *the device as a whole*. A `ComponentRow` MUST NOT be
allocated `cmp = 0`, and `SignalRow` key 3, `ParamRow` key 3 and `Concern` key 3
carry 0 for device scope rather than expressing it by leaving the key out.
`sig`, `pid` and `cid` MUST NOT be allocated 0 either, because 0 is already
spent as the end-of-paging sentinel in `Inventory` key 4, `Readings` key 6 and
`Concerns` key 4, and as *from the beginning* in the requests that feed them. A
`Sel` is the one place `cmp = 0` is refused rather than honoured, and P-198
gives the reason.

Without the reservation a driver hands component 0 to an inverter/charger's AC
transfer relay, and that relay's `SignalRow`s sit at the same `cmp` as the
device's own. *The instrument answered* and *the transfer relay is closed* then
differ in nothing a client can read.

Device scope is a value and not an absence because absence is what an encoder
produces by forgetting. If a missing key 3 meant *the whole device*, a driver
that never filled it in would publish the array's current, the load's current
and the battery's current as three device-scope currents told apart by nothing —
`point` is optional, and `cmp` was what separated them. An instrument that has
gone quiet is reported as a signal about the whole box and about no part of it,
so it needs a `cmp` to sit at, and 0 is the one it gets.

A driver that allocates `sig = 0` makes `next = 0` unreadable: *resume at signal
0* and *this page ends the selection* become the same number in the same key.
One client stops the walk a page early and the well-pump circuit is not on the
dashboard at all — not stale, not faulted, absent; another reads it as a cursor
and fetches page one forever. `bus 0` and `dev 0` are not counter-examples: both
name the controller, both sort first in their kind, and a page resumes at an id
above the last one it sent, so `next` there is 0 only as the sentinel.

**P-201** — An absent `cmds`, on a `ComponentRow` or a `DeviceRow`, means that
scope accepts **no** commands. An empty array is not a legal encoding and is
error 1. A `DeviceRow` carries `cmds` for its own `cmp = 0` scope, and the
controller's own row at `dev 0` carries its list the same way.

Absence is what a driver author gets for not thinking about the key, so it has
to be the narrow reading. The other way round, every row nobody filled in says
*anything is allowed here*, and the widest list on the site is the one that
ships by default.

An empty array says exactly what an absent key says, and one meaning with two
encodings is where two controllers differ quietly: one omits the key, the other
writes `[]`, and a client that special-cases one renders the other as *not
known* rather than *none*. Refusing `[]` leaves one way to write *none*, and it
costs no bytes.

The controller is a `DeviceRow` at `dev 0` like any instrument on any bus, and
it carries a list for the same reason they do. Without it, the one device
present at every site is the only one whose commands nothing on the wire can
name.

**P-187** — Neither `parent` chain — `DeviceRow` key 7 or `ComponentRow` key 3 —
may form a cycle, and neither may exceed `MAX_TOPOLOGY_DEPTH`. Both are refused
at config write **and** at runtime adoption.

A chain that returns to where it started makes every walk over the topology
non-terminating, and one deeper than the cap makes a walk unbounded on a
controller with no allocator to bound it with. Adoption is named alongside the
config write because adoption is not a config write: a sub-device arriving on a
bus at three in the morning goes through a different door, and a rule enforced at
only one of them is enforced at neither.

**P-202** — `DeviceRow` key 3 `addr` MUST be present when the row's `bus` has an
addressed `transport` — `rs485`, `can` or `ip` — and MUST be **unique within a
`bus`**. A receiver MUST refuse an `Inventory 0x8D` page that breaks either.

Two devices on one RS-485 pair with no `addr` are two rows a client cannot tell
apart. It can say there are two chargers and not which one is at which end of
the wire, so *the second charger has stopped answering* names nothing anybody
can walk up to, and the person who drove four hours to swap it is reading labels
in the cabinet with a torch.

Two devices carrying the same `addr` describe a bus that cannot work at all. One
of them is answering for both, and one instrument's numbers arrive on the screen
under two serial numbers.

The half that is easy to leave out is the receiver's. A controller already
refuses the duplicate when a device registers, so the gap is not in what a
sender writes but in what a client may assume about what it received. A client
caches descriptor rows and refetches only when P-149's identity moves, so a page
it accepted once is a page it renders for hours.

**P-203** — A component whose `rollup` is set MUST have its values **already
accounted for** in the named component's values, and a client MUST NOT combine
the two under **any** aggregation — not a sum, not a maximum, not a mean.
`rollup` MAY name a component of an ancestor device. It MUST NOT form a cycle;
cycles are refused at config write **and** when a device is adopted at run time.

The charger's combined PV figure added to its four trackers is double the sun. A
merged 240 V circuit added to its two legs is double the dryer. All three
operators are named because a rule that forbids only addition is one a client
satisfies by reaching for the next operator to hand; on a `vtype 3 enum` or
`4 flags` there is nothing to combine and the rule costs those rows nothing.

The ancestor-device permission is the modular all-in-one. Its modules carry
their own `serial` and their own `fw`, and one can go missing while the other
two keep charging, which makes them devices and not components. A same-device
rule would leave the product's 4,200 W and its three modules' 1,400 W apiece
with no relationship anything can express: a client that adds them draws 8,400 W
of sun on a 4.2 kW system, one that averages them draws 2,100 W on an afternoon
the array made 4,200, and neither figure is out of range for anything downstream
to catch.

Cycles are checked at adoption and not only at config write, because a module
that turns up in a chassis bay brings rows nobody typed, and a `rollup` loop is
a client following the chain until the tab stops responding. Whether an
aggregate is the device's own figure or arithmetic this controller did is a
different question, and `provenance` already answers it.

**P-204** — `unit` and `scale` MUST be **absent** from a `SignalRow` or a
`ParamRow` whose `kind` is below `0xF000`, and MUST be **present** when that
`kind` is in the vendor range `0xF000`–`0xFFFF`.

P-018 already names where the unit and the scale of a standard quantity come
from, and it is the registry. A row that carries them again is a second source
of truth for the number on the screen. `0x0101 DC voltage` is volts at a scale
of −3, so a 25.6 V bank is 25600; a driver that writes `scale = −2` into its own
rows publishes 2560 for the same bank, and that row parses, MAC-verifies and
renders as 2.56 V. Two controllers can then disagree by a factor of ten about a
standard quantity, and no client can tell which one is the driver bug, because
each is telling the truth about itself.

A vendor kind has no registry row to read a unit off, so above `0xF000` the
descriptor is the only place one can live, and `vns` is what stops one vendor's
`0xF001` from being read as another's. Below the range the registry owns the
pair, above it the row does, and never both — offered both, a client will trust
the row because it is the more specific of the two, and the registry stops being
the thing that decides what a standard kind means.

**P-205** — `DeviceRow` key 12 `since` MUST be set to the current `rev` whenever
the **physical instrument** behind that row changes, and `ComponentRow` key 9
`since` MUST be set to the current `rev` whenever **that row's meaning** changes.
A row that has been through neither carries the `rev` at which it first appeared;
there is no value meaning *never changed*, because a row appearing is the thing
behind it arriving.

Somebody swaps a dead charger for an identical one at the same terminals. The
`dev`, every `cmp` under it and every `sig` are unchanged, which is exactly what
you want for *what is the power in the pump house* and a trap for *is this the
same instrument*. Eight months of stored readings then draw as one smooth line
across two machines, and the kilowatt-hours somebody totals off that line credit
a charger that is in a bin.

The component half is the same failure one level down. `cmp 57` was relay 3 and
is now the well pump: the id did not move, the number under it means something
else, and readings a client kept from before the rewire join readings from after
it into a line that was never measured anywhere. `since` is the field that says
*the thing behind this id is not the thing it was*, and it is what a client
checks before joining what it holds under one `rev` to what it holds under a
later one.

Two fields rather than one marker because the two send a technician to different
places — one is looking for a box that was changed, the other for wiring that
was, and a single seam cannot say which. And the seam is a `rev` rather than a
date, so a controller that has never been told the time can still set it: P-093
forbids inventing the date, and `rev` is already on every page a client fetches.

**P-206** — `ebase` is the **label of element 0**, not its position: element `k`
of a `Series` carries the label `ebase` + `k`, and a `SignalRow` that omits
`ebase` is read as `ebase = 1`. A client that puts an element in front of a
person MUST identify it by that label, and never by `k`. `Concern` key 5 `elem`
is the element's **position**, 1-based and in `1..n`, and a client MUST render
its label as `ebase` + `elem` − 1. `ebase` + `n` − 1 MUST fit a `u16`: a row
whose top element has no label is refused rather than published.

A label that wraps is not a missing label, it is a **different cell**. A row
declaring sixteen elements based at `0xFFFF` renders its second as cell 0, which
is a number somebody can find on some other rack, and the wrap is invisible in
every byte of the row and the reading. Refusing at the descriptor puts it in
front of whoever configured the site, which is the one moment anybody can act on
it.

A 32-cell string is longer than one series may be, so it is published as two
16-element signals on two half-string components, with `ebase` 1 and 17. Element
6 of the second signal is cell 23 — the number painted on the cell in the rack.
A client counting off the front of the signal calls that same element the
seventh and renders cell 7, which is in the other pack. Both readings parse,
both MAC-verify, and somebody drives four hours and pulls the wrong cell.

The default is what hides it. On a single pack `ebase` is absent and therefore
1, so counting from the front and adding `ebase` give the same number for every
element: two implementations that disagree about what the word means draw
identical screens, and every bench test passes on both. The first site to split
a string across two signals is the first place the disagreement is visible, and
by then it is visible as a cell number somebody is standing in front of.

`elem` is a position and not a label so that one arithmetic is stated once and
performed by the client. One word was taken from each vocabulary before this
rule existed — `SignalRow` said *the index of element 0*, `Series` said *byte k
is element k's*, and the concern said *1-based element index* — and no sentence
joined the three. A position also keeps `elem` inside `1..n`, which is what
makes it a byte; carrying the label instead costs a third byte on every row and
puts a number above 255 out of reach on a rack that has one.

**P-207** — `(dev, cmp, kind, shape, vtype, domain, point, dir)` MUST be
**unique within a `rev`** across all `SignalRow`s, and
`(dev, cmp, kind, vtype, domain, point, dir)` across all `ParamRow`s, which
carry no `shape`. The identity compares `shape` and **not** the series length
`n`. A collision MUST be refused at registration: the colliding row does not
enter the inventory.

A charger's absorption, float, equalize and maximum-regulation voltages are one
`kind` on one component, and `domain`, `point` and `dir` are the only things
separating them. Leave one of the three out of the identity and rows differing
only in it collide, so a conforming controller refuses three of the four: the
installer with a meter on the bank goes looking for the absorption setpoint and
finds one row that says *DC voltage*. The controller at the next site, whose
author kept the tuple as written, publishes all four.

Uniqueness is also what lets the tuple be a name. A `sig` is an id inside one
`rev` — P-149 makes a client discard its descriptors the moment the revision
moves — so a saved chart, or an alert somebody set, has to find its signal again
by what it measures rather than by the number it held yesterday. That works only
when exactly one row answers to the tuple; with two, the lookup returns
whichever the client indexed first, which is a coin toss made once and then
trusted.

Put `n` in the identity, instead of `shape` or alongside it, and a fourteen-cell
row and a sixteen-cell row on one component become two different signals — one
pack described twice. A client then plots the string beside itself, or plots the
fourteen and drops two cells with nothing on the wire saying they are missing,
which is the failure P-197's per-element `q` byte exists to prevent.

### Readings — `0x0E` / `0x8E`

The hot plane: what the numbers *are*, polled. A `Readings` parses with no
descriptor at all — scalars and series travel as two arrays, so no key's CBOR
type depends on a `shape` that lives in a different message under a different
`rev`. Only its *meaning* needs the cold plane.

The reasoning and the bounds are in
[TOPOLOGY-DESIGN.md](protocol/TOPOLOGY-DESIGN.md). What is here is the wire.

```text
ReadSignals  0x0E            wrapper
  1: rev          u32      the revision the client's cache holds
  2: sel          [ Sel ]  optional; at most MAX_SELECTORS. Absent means every signal
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
                           is 2, and it is the age of the oldest such element
```

**P-198** — The resolved selection of a `ReadSignals` is the **set union** of its
selectors, deduplicated by `sig`, ordered by **`sig` ascending**. A page is a
prefix of that order, and `from` and `next` are `sig` ids and never ordinals. A
`cmp` selector matches that component and, transitively, every component whose
`parent` chain reaches it; a `dev` selector matches that device and, transitively,
every device whose `parent` chain reaches it. A `Sel` MUST carry exactly one of
keys 1, 2 and 3 — none, two, or `cmp = 0` is error 1.

P-146 makes the controller hold no resumption state, so it rebuilds the set from
scratch on every page, and only a normative order makes that reproducible. Order
it by anything volatile inside one `rev` — poll-ring arrival, freshest first,
selector order — and the second page is a prefix of a different sequence: the
client resumes at the cursor, receives a set that overlaps what it holds and
omits signals it will never see, with `next` and `total` reconciling perfectly
and the MAC verifying. The missing ones keep last poll's value with its `q` byte
still reading `ok`, so nothing ever goes stale on a dashboard that is quietly
missing the well-pump circuit.

An ordinal cursor cannot be checked by the side that receives it. A `sig` cursor
can: a client watches the ids ascend.

Union rather than concatenation because two conforming controllers otherwise
disagree about `total` for one request, when a client names a device and one of
its components.

**P-199** — A responder MUST evaluate a response's outcomes in **ascending order**
and return the first that applies. A malformed request is error 1 and is refused
before any outcome is computed. On any outcome other than 1 a `Readings 0x8E`
MUST carry `next = 0`, no samples and no series, and a `Concerns 0x8F` MUST
carry `next = 0` and no rows, for the reason P-145 gives.

For `Readings 0x8E`: outcome 1 `ok` when the request was answered, in whole or
in part; outcome 3 `unknown_selector` when a `Sel` names a `dev`, `cmp` or `sig`
that does not exist at this `rev`; outcome 4 `out_of_range` when `from` is
greater than the largest `sig` in the resolved selection.

For `Concerns 0x8F`: outcome 1 `ok` when the request was answered, in whole or
in part; outcome 3 `out_of_range` when `from` is greater than the largest `cid`
the table holds. There is no `unknown_selector` on this one, because a
`ReadConcerns` names nothing that can fail to exist — it carries a cursor and no
selection at all. **An empty table is outcome 1** with no rows and `next = 0`,
and never `out_of_range`: *nothing is wrong at this site* is an answer, and a
client that reads it as a refusal shows a screen with no state on it.

Outcome 2 `superseded` is P-146's and needs no restating, but it is worth saying
why it reaches a message whose rows do not move `rev`. A `Concern` names a
`dev`, a `cmp` and usually a `sig`, and those are ids inside one revision. A
page answered under a revision the client no longer holds is a row about a
component whose meaning has changed underneath it.

Ascending evaluation is the half that is easy to leave out, and it is what stops
two conforming controllers answering different numbers to one request — a client
branching on a value that means one thing here and another thing at the next
site.

**P-185** — Every value position on this wire is a signed integer in the `i32`
range: `Sample` key 2, `Series` key 3, and every value position of a descriptor
row. A receiver MUST reject a wider one with error 1. A source value outside the
range MUST be published at `validity 6 out_of_range` with **no value** — never
clamped, never wrapped, never widened. A descriptor row has no validity, so
there the key is simply omitted, which is already what *never read* encodes.

A clamped number is a lie a client cannot detect: a shunt reporting a
five-million-amp fault surfaces as 2 147 483 647 and every rule downstream reads
a real, enormous current. Refusing it says the same thing the wire already has a
word for.

`i32` and not something wider because every derivation of a body's width in this
protocol spends the bound, and because nothing a controller of this size measures
needs more: the range at a scale of −3 is ±2 147 483 A, and at −2 it is ±21 million
volts.

**P-196** — A reading's value key MUST be present exactly when its `q` byte's
validity is `1 ok` or `2 stale`, and absent otherwise. `provenance` MUST be `0`
exactly when there is no value and in `1..6` exactly when there is. A `stale`
reading MUST carry an `age`, and one that is not stale MUST NOT.

There is no slot for a number when there is no number. `0xFFFF` at a scale of
−2 is 655.35 V, which is a plausible reading on a 450 V unit, and the vendor
documents say in as many words that fields a unit does not have report that way.
A value beside a validity that says the sensor is broken forces an encoder to
invent one; a zero beside `absent` is the room card showing 0.0 °C for a probe
that is not there.

The two halves have to agree and not merely each be legal on its own: `ok` with
provenance `0` says there is a number and names no source for it, and `absent`
with `measured` says an instrument read something that is not present. A
receiver MUST refuse both.

`stale` means *this is old*, and how old is the only thing that makes it usable.
Without the age a client renders a two-hour-old cell voltage as current and a
balancing decision is made on it.

**P-164** — A source reporting an operating state this controller has no
normalized value for MUST be published at **`validity 8 unnamed_state` with no
value**, and MUST raise a `Concern` carrying the source's own code in `raw` and
its namespace in `vns`. Which set a value is drawn from is the signal's `esp`,
and the question is asked of the registry — never of a list of metric kinds
written into an implementation.

A charger ships firmware with a sixth generator state and this controller knows
five. Publish the integer under `ok` and a client draws *state: 6*, or picks the
nearest one it holds and draws *running* over an engine that is doing something
else. Neither is a state anybody has; the second is worse than the first,
because it is confident.

The refusal is in the `q` byte and not beside the value, because `q` is the one
field every reader already consults before it renders anything, and
`unnamed_state` carries **no value at all** — so there is no number left for
something downstream to render by accident. The raw code is not lost: it goes to
the concern, where it is a thing to investigate rather than a thing to draw.

**This is the sending half.** P-125 below is the receiving one, and the two are
not the same rule stated twice: a controller can only refuse a state *it* cannot
name, and the client reading its answer may be older still. Both are needed, and
both stay until P-165 states them by category.

**P-125** — A **receiver** meeting a value drawn from an enum space it does not
recognise MUST surface **that one reading** as unrecognised: never mapped onto a
member it does know, never rendered as a bare number, and never replaced with a
fallback. It MUST NOT invalidate the response around it, and the `q` byte stays
authoritative for whether the reading is any good at all.

Which set a value comes from is the signal's `esp`. A space a receiver has no
members for — one in the vendor range under P-019, or one allocated in a registry
newer than the build reading it — names nothing, so every value in it is
unrecognised. That is the same answer for the same reason, and pretending to tell
those two cases apart would be a claim with no basis.

**This is P-164 from the other end, and neither substitutes for the other.**
P-164 binds the controller, which refuses to publish a state *it* cannot name.
P-125 binds whoever receives that response, and a client two versions older than
the controller that answered it has the shorter list. A protocol that stated only
the sending half would be correct on the day every part was built together and
wrong from the first update after it.

Rejecting instead is not available on this path. A client cannot refuse part of a
MAC'd response it has already verified, and refusing all of it throws away every
other signal on the page because one enum was new — which is the failure P-014
would cause here, and why P-014 is scoped to requests.

**P-197** — A series reading's key 2 MUST be exactly `n` bytes, where `n` is the
signal's declared length, and byte `k` is element `k`'s `q`. Key 3 MUST hold
exactly as many integers as key 2 has bytes whose validity carries a value, in
ascending element order. A length disagreement is error 1.

Position is identity in a series, so an element with no reading cannot simply be
left out — the byte at its position is what says why it has none. An element
with no reading has no integer anywhere in the message, which is the only
version of this a decoder cannot get wrong: there is no null on this wire, and a
placeholder would be a number.

**Off by one and every element after the gap reads the next one's value.**
Sixteen cells, all plausible, all shifted by one position — and the one that
matters is the one somebody drives four hours to replace. That is why the count
is a rule and not a convention, and why an encoder and a decoder derive it the
same way from the same bytes.

One open cell-sense wire blanks one cell. It does not blank the other fifteen,
and it does not put a plausible voltage where the missing one was.

### Concerns — `0x0F` / `0x8F`

What is wrong at the site, as **state**. `concern raised` (`0x0501`) and
`concern changed` (`0x0502`) announce the transitions; this is the table they act
on, and it is what a client reads when it has just connected instead of replaying
a season of events to find out whether the pack is still in protection.

The lifecycle, the severity band and the refusal rule are in the preamble above
— P-168, P-169 and P-180 — because the controller holds them whether or not
anything has asked. The reasoning and the bounds are in
[TOPOLOGY-DESIGN.md](protocol/TOPOLOGY-DESIGN.md). What is here is the wire.

```text
ReadConcerns  0x0F           wrapper
  1: rev          u32      the revision the client's cache holds
  2: from         u16      the `cid` to resume at, inclusive;
                           0 means from the beginning

Concerns  0x8F               wrapper under session_key
  1: rev          u32      the controller's current revision
  2: seq          u64      log position this page reflects, and the pin a
                           walk is held against
  3: c            [ Concern ]  optional; at most MAX_CONCERN_PAGE_ROWS
  4: next         u16      the `cid` to pass as `from` for the next page;
                           0 when this page ends the walk
  5: total        u16      rows the walk returns, the cleared ones included
  6: refused      u16      concerns the table has refused since boot
  7: outcome      u8       1 ok · 2 superseded · 3 out_of_range

Concern
  1: cid          u16      never 0, and stable for as long as the row lives
  2: dev          u16
  3: cmp          u16      0 is the device as a whole (P-200)
  4: sig          u16      optional; the signal it is about
  5: elem         u8       optional; the element's 1-based position in a
                           series signal, which is not its label (P-206)
  6: cond         u16      condition registry; vendor range, skip-unknown
  7: sev          u8       1 info · 2 warning · 3 fault · 4 protection
  8: state        u8       1 active · 2 active_acked · 3 latched_cleared
                           · 4 clearing_blocked · 5 cleared
  9: age          u32      seconds on P-004's tick since first observed,
                           always present
 10: since        u64      optional; wall-clock time first observed, omitted
                           when the clock has never been set (P-093)
 11: raw          u32      optional; the source's own code, verbatim
 12: vns          u16      optional; whose code that is. REQUIRED with key 11
                           and absent without it
 13: seq          u64      the log position of the record that opened the row
```

Key 9 is always present and key 10 is not, for the reason `age` beats a
timestamp everywhere else on this wire: a controller whose clock has never been
set can still say how long something has been wrong. Key 5 is what makes *cell
23 of pack 2 is over voltage* sayable at all — a cell costs no descriptor row
and is still addressable.

Keys 11 and 12 travel together or not at all. A raw code with no namespace is a
number from nobody, and a namespace with no code names a vendor and says nothing
about them. Two vendors both use `0x0021` for different things, which is the
whole reason key 12 exists.

`cond` is skip-unknown under P-019, so a condition nobody has allocated still
renders as *protection, pack 2, cell 23, code 0x4A12* — a sentence somebody can
act on, rather than a row a client drops because it did not recognise a number.

**P-209** — A `ReadConcerns` walk is ordered by **`cid` ascending**; `from` and
`next` are `cid` ids and never ordinals, and a page is a prefix of that order.
`total` MUST be the number of rows the walk returns, which **includes rows at
state 5 `cleared` that have not yet been released**.

P-146 makes the controller hold no resumption state, so it rebuilds the walk
from scratch on every page, and only a normative order makes that reproducible.
Order it by where a row happened to land in the table and the second page is a
prefix of a different sequence: the client resumes at the cursor, is handed a
row it already holds and never sees another, with `next` and `total` reconciling
perfectly and the MAC verifying.

An ordinal cursor cannot be checked by the side that receives it. A `cid` cursor
can — the client watches the ids ascend — which is the argument P-198 makes for
a `sig` cursor over a position, and it applies here for the same reason.

`total` counts the cleared rows because the walk returns them. A row stays in
the table until it is released, and a client that never receives it never learns
the condition ended. Leave those out and `total` is smaller than the number of
rows the same walk delivers, which is a client with no way to tell a short page
from a torn one.

**P-210** — `Concerns` key 2 `seq` is the pin a walk is held against. A client
MUST treat a page whose `seq` differs from the first page's as a **torn walk**
and MUST restart it. The controller MUST move `seq` when a row enters or leaves
the table, and MUST NOT move it when a row only changes state.

`rev` cannot do this job. Concerns deliberately do not move it — a pack going
out of balance is not a topology change, and a client that discarded its
descriptors every time one did would refetch a seventeen-page inventory on a
cold morning — so a walk over concerns has nothing else to hold it still.
Without the pin, a `cid` released under P-180 and handed to a different
condition between two pages is a row the client sees twice or never, in the
table that decides whether a charger may start, with every field of both pages
well formed and the MAC verifying.

The second half is what keeps the fix from being worse than the fault. Move
`seq` on any change at all and thirty-two per-cell rows clearing at dawn tear
every walk in progress, for a change that reorders nothing — a client that can
never finish reading the table exactly when the site is at its worst.

**P-211** — `Concern` key 9 `age` is a duration in **seconds** on P-004's tick
and is always present. A row that survives a restart MUST carry its accumulated
age across it. A controller that cannot recover a row's accumulated age MUST NOT
restore that row wearing a fresh one: the condition is raised again as a **new**
concern under P-180, with a new `cid` and an age that honestly starts now.

`age` runs on a tick that is zero at boot, against a table in RAM. A
low-temperature protection that has held the charger off since midnight reports
`age = 12` after a brown-out, and the operator reads *this just started* about
the six hours that are the whole reason to look. Key 10 `since` re-bases the
same way, and on a controller whose clock has never been set it is not there at
all — so key 9 is the only field that can carry the answer.

The last clause is the one that had no legal answer before. Key 9 is always
present, so *do not report a fresh age* is not something a controller can do
while still restoring the row: it has no third value to send and no absence to
encode. Dropping the row and raising the condition again is the honest version
— the age really is new, the `cid` is new, and a client is told it is looking at
a new concern rather than handed an old one wearing a new number.

### Subscribe — `0x03` / `0x83`

```text
Subscribe  0x03         wrapper
  1: from_seq     u64      0 means live only, no replay

SubscribeAck  0x83      wrapper
  1: accepted_from_seq  u64
  2: oldest_seq         u64
  3: current_seq        u64
  4: gap                bool
```

**P-094** — The transition from replay to live MUST be atomic: the controller
replays retained events from `accepted_from_seq` and continues into live delivery
with no window between. An event created between "subscription registered" and
"replay finished" would otherwise be lost, and lost silently.

**P-104** — `accepted_from_seq` MUST be `current_seq + 1` when `from_seq` is 0,
and `max(from_seq, oldest_seq)` otherwise, where `current_seq` is the newest
`seq` the log holds at the moment the `Subscribe` is answered.

`current_seq + 1` rather than `current_seq`, because under P-029 the mark names
the first position that will be delivered and *live only, no replay* means the
first position after everything that already exists. Answering `current_seq`
promises the client the newest record it explicitly asked not to receive.

It is the position replay starts from under P-094 and the mark a client resets
its `seq` filter to under P-056, and nothing said what the controller puts in it.
A controller that echoed the client's 0 replays the entire retained ring at a
client that asked for **no** replay; one that answered `current_seq` for every
value replays nothing at all, ever. Both obeyed every rule written down, which is
two implementations disagreeing about the one field that decides how much history
arrives — the disagreement this document exists to make impossible.

`max(from_seq, oldest_seq)` is P-099's `ReadLog` clamp word for word. The same
fall off the same ring answered two ways in two messages is a difference somebody
would have to discover.

**P-144** — **`seq` 0 is not a position.** The first record a log ever writes is
`seq = 1`, and 0 in `oldest_seq` or `current_seq` means *this log holds no
record*. A receiver MUST NOT treat 0 as a record it can ask for.

P-095 already says this about `from_seq` — *it is not a position* — and the rest
of this protocol already spends 0 the same way: `client_id = 0` is no client
(P-086) and `session_id = 0` is no session (P-021). Saying it once about the
`seq` space closes two questions that would otherwise be settled per
implementation.

The first is the empty log. P-104 reads `current_seq` as "the newest `seq` the
log holds", and a log holding nothing has no such value; an implementation that
puts a real position there answers `accepted_from_seq` one past a record that
does not exist. With 0 meaning *none*, `current_seq + 1` is 1 — the position the
first record will take — and P-104 needs no exception.

The second is `Subscribe` itself. `from_seq = 0` is the sentinel, so a client
could not ask for position 0 even if one existed. A log whose first record sat
at 0 would hold exactly one record no client could ever subscribe from, and
`ReadLog` — which has no sentinel — could ask for it. One space, two messages,
two answers.

**P-095** — `gap` MUST be true when `from_seq` is not 0 and
`from_seq < oldest_seq`. The client fell off the ring and knows precisely that it
did.

`from_seq = 0` is exempt because it is not a position — it means *live only, no
replay*, and on any ring that has wrapped `0 < oldest_seq` is unconditionally
true. Without the exemption a client that deliberately asked for nothing behind
it is told, every single time, that it lost data it never asked for.

A session MAY `Subscribe` more than once. The later `SubscribeAck` replaces the
earlier subscription and re-opens a replay window from its own
`accepted_from_seq`, which is what P-056 resets against.

### Event — `0x04`

```text
Event  0x04             wrapper under session_key, req_id = 0
  1: seq          u64
  2: at           u64      optional, omitted when the clock was never set
  3: kind         u16      see REGISTRY
  4: body         map      kind-specific. Six kinds are defined below; the rest
                           are deferred — see REGISTRY and DEFERRED.md
```

**Six kinds are defined here and the rest are not.** The two concern records
come first. They are here rather than in [DEFERRED.md](protocol/DEFERRED.md) entry 10 because the
concern table is built and P-180 already says a row leaves it only by an
`0x0502` carrying state 5 — a rule about a record nobody could write.

```text
ConcernRaised  0x0501       class A, carried in Event 0x04 key 4
  1: rev          u32
  2: c            Concern   the row as it was admitted, keys 1 to 13

ConcernChanged  0x0502      class A, carried in Event 0x04 key 4
  1: rev          u32
  2: cid          u16
  3: dev          u16
  4: cond         u16
  5: state        u8      the state it moved to; 5 cleared is the row leaving
  6: prev         u8      the state last **announced**, not the last it held
```

`0x0501` carries the whole row and `0x0502` carries five fields, because the two
answer different questions. A raise is the first a client hears of a condition,
so it needs everything a page would have given it — which is why key 2 is the
same `Concern` the `Concerns 0x8F` section defines, encoded the same way, rather
than a second shape meaning nearly the same thing. A change is about a row the
client already holds, and `cid` is what it holds it by.

**Key 6 `prev` is what makes a hole in `seq` legible.** P-096 says the sequence
is not contiguous, so a client can miss a transition — and without the state it
moved from, a row that went `active` → `active_acked` → `latched_cleared` while
one record went missing arrives as a jump the client cannot tell from a
controller that skipped a state. With `prev` it can see that what it holds is not
what the controller moved from, and reconcile under P-097 rather than render a
lifecycle that never happened.

`dev` and `cond` ride on `0x0502` for the client that missed the raise
altogether. *Concern 12 is over* is unrenderable on its own; *the pack's
under-temperature protection is over* is a sentence, and it costs six bytes.

**Three more bodies this document defines** are `signal validity changed`
(`0x0102`), `topology changed` (`0x0901`) and `device presence changed`
(`0x0902`). Two of them carry an array, which is the whole of why they are
shaped the way they are: one RS-485 pair going intermittent flips every signal
behind it in a single pass — up to 384 at the site cap — and class A events are
never dropped, so one event per signal is 384 of them into a queue of sixteen
across eight sessions. Every session gets closed, every reconnect replays the
burst from the log, and the ladder takes the radio off the air writing
`comms link lost` against a chip that answered every heartbeat. An array makes
that eight ticks of one event.

```text
ValidityChanged  0x0102     class A, carried in Event 0x04 key 4
  1: rev          u32
  2: e            [ VChange ]   1 to MAX_VALIDITY_SWEEP, coalesced

VChange
  1: sig          u16
  2: q            u8      the validity and provenance it moved to
  3: prev         u8      the last one **announced**, not the last observed

TopologyChanged  0x0901     class A, carried in Event 0x04 key 4
  1: rev          u32      the new revision
  2: reason       u8      1 boot · 2 config_write · 3 sub_device_adopted
                          · 4 sub_device_removed · 5 device_replaced
  3: added        u16
  4: removed      u16

PresenceChanged  0x0902     class A, carried in Event 0x04 key 4
  1: rev          u32
  2: e            [ PChange ]   1 to MAX_PRESENCE_SWEEP, coalesced

PChange
  1: dev          u16
  2: presence     u8      the presence it moved to
  3: prev         u8      the presence it moved from
```

**P-212** — `0x0102` and `0x0902` each carry an **array**, and a controller MUST
NOT send one that is empty. `VChange` key 3 and `ConcernChanged` key 6 are the
value this controller last **announced** for that signal or row, which is not
necessarily the last one it held.

An empty array is a record saying nothing happened, which is a byte cost on a
metered link and a wake-up on a phone. That it cannot happen by construction is
not the point — a coalescing rule that produced one would be a bug this says out
loud.

The announced-versus-observed half is the one that bites. A signal may move twice
between two events, because one event carries what accumulated since the last —
so a `prev` set from the last thing the driver saw describes a transition the
client was never told about, and the client compares it against a value it does
not hold. What it holds is what was last sent to it, and that is what `prev` has
to be.

**`0x0502` was outside this sentence and had the identical hole**, which is what
building P-182's concern half found. It carries no array, so it read as a
different kind of record — but the coalescing bounds `0x0501` and `0x0502`
together, and a row that goes `active` → `acked` → `latched_cleared` inside one
tick's four sends **one** record. Taken from the last state held, its `prev` names
`acked`, which is a state no client was ever sent.

**P-213** — A `0x0901` MUST carry the reason the revision moved. `added` and
`removed` count **descriptor rows**, of every kind, and a reason of
`1 boot` MUST carry the counts as of that boot rather than zero.

A client's whole decision on meeting a new `rev` is whether to refetch, and it
has already discarded its cache under P-149 by the time it reads this. What the
reason buys is what it tells a person: *somebody wrote configuration* and *a
module was pulled out of bay 3* are the same two numbers and completely different
sentences, and only one of them is worth driving out for.

Zero counts at boot would be a controller reporting that it came up with no
topology, on the one event where the client has the least other evidence — so the
first `0x0901` after a restart carries what the tables hold, not the delta from
nothing.

**The boot record is the sixth body**, and it is the one a controller writes
before any other: the reset reason and the RTC's state are read out of registers
the next reset overwrites, so the log is the only place they outlive the boot.
A board powered up after a night unplugged is the boot nobody had a probe on.

```text
Boot  0x0601                class A, carried in Event 0x04 key 4
  1: reason       u8      boot_reason, see REGISTRY
  2: backup       bool    false when the RTC reported its backup domain invalid
  3: rtc_crystal  bool    true when the RTC runs from its crystal, ready and selected
  4: rail_cycled  bool    true when this reset power-cycled the comms processor
  5: task         u8      reason 2 only: the task that stopped checking in
  6: overdue      u32     reason 2 only: ms past its window when the feed stopped
  7: file         u32     reason 5 only: a hash of the panicking source file's path
  8: line         u32     reason 5 only: the line
```

Keys 5 to 8 are the previous run's last words. `task` and `file` are numbered by
the image that was running, which a reader resolves against that image; the
record names the reason and the place, and the build says what the place was.

**P-214** — A boot body MUST carry keys 5 and 6 together or not at all and only
with reason 2, and keys 7 and 8 together with reason 5 and no other; a receiver
MUST refuse one that breaks either.

A panic is a software reset that left words behind, so reason 5 without a site
is a software reset reported as something it cannot show. Words beside any other
reason are worse: a power cut carrying a panic site is a record that contradicts
itself, and whoever reads it in April cannot tell which half happened. A watchdog
may arrive without a task, because the run that starved it did not always get
as far as saying who.

The controller's clock, recovery ladder and log reader write these class A
bodies in `Event 0x04` key 4: time set, record failed CRC, comms link lost,
comms power cycled, comms unrecoverable, sessions shed for backpressure and
comms boot noise. Their integer keys are local to each kind.

```text
TimeSet  0x0604
  1: old          u64     optional; ms since epoch before the change
  2: new          u64     ms since epoch after the change
  3: source       u8      time_source, see REGISTRY

RecordFailedCRC  0x0702
  1: count        u32     stored records skipped in this scan because their CRC failed

CommsLinkLost  0x0801
                           empty map; the first rung, from L-110 or L-022

CommsPowerCycled  0x0802
  1: count        u32     cycles inside the preceding hour, including this cycle

CommsUnrecoverable  0x0803
  1: rail_on      bool    true: left on and uncycled; false: left off (L-112)

SessionsShedForBackpressure  0x0804
  1: count        u32     sessions shed inside the preceding hour, including this shed

CommsBootNoise  0x0805
  1: count        u32     bytes refused as non-frames during this comms boot attempt
```

**P-215** — These bodies MUST carry every listed key except `Time set.old`,
which MUST be omitted when the previous clock was unknown (P-093). A receiver
MUST refuse a missing required key, a duplicate known key, an unallocated time
source, or a zero count in `0x0702`, `0x0802` or `0x0804`. Unknown keys are
skipped under P-013. Counts saturate at `u32::MAX`; that value means at least
that many, never a wrapped total.

`Time set.source` uses the same space as P-111: a signed client write is
`client`, an accepted offer is `ntp-via-comms`, never the link-local source
number (L-162). An old value of zero is a known epoch, not absence. The outer
record's `at`, when present, uses the clock after the change. The body records
both forward and backward steps without an unsigned delta.

The power-cycle and session-shed counts use the same rolling hour as L-111 and
L-022. They count actions, not emitted records; L-023 can require only the first
shed to be logged. `rail_on` records the branch actually taken for the recovery
pause, not a request to change the rail. `Comms link lost` carries no diagnosis:
both an unanswered heartbeat and backpressure escalation reach that rung.

`Record failed CRC` counts failed stored records, not UART frames (P-031).
A scan emits one summary after it finishes, if any records failed. It does not
copy `seq`, kind or time from damaged bytes: the failed CRC makes those values
untrusted. Re-reading the same damaged record in another scan can count it
again; this is not a lifetime count of distinct losses.

`Comms boot noise` preserves the ROM and bootloader text count that would
otherwise exist only in a probe log. The interval starts when the controller
starts a comms boot attempt and ends at the first valid `LinkUp`, or when the
controller abandons that attempt before starting another. It counts bytes
classified as non-frames, not malformed frames or refusal messages, and is
recorded once per attempt, including zero. It saturates by the same rule as the
other counts. A client compares the count against the expected boot output for
the comms image; the body does not encode a firmware-specific fault threshold.

**P-182** — The controller MUST NOT enqueue more than one `0x0102` and one
`0x0902` per tick. Each carries an array of what fits its cap; entries that do
not fit are carried to the next tick and MUST NOT be dropped. **`0x0501` and
`0x0502` together** are bounded at `MAX_CONCERN_EVENTS_PER_TICK` per tick on the
same terms. The class A events one tick can produce MUST sit below
`MAX_EVENT_QUEUE` with a stated margin.

One RS-485 pair going intermittent flips every signal behind it in a single pass
— up to 384 at the site cap — and class A cannot be dropped, so P-098 closes each
of eight sessions, the reconnect replays the burst from the log and closes again,
and [LINK.md](protocol/LINK.md) L-022 puts the controller on the ladder at the
third shed in an hour: every session dropped, and the log saying `comms link lost`
about a chip that answered every heartbeat.

**The clears are counted with the raises**, because P-180 makes an `0x0502`
mandatory as each row leaves the table and a cold soak's thirty-two per-cell
concerns all clear at dawn in one tick. Bounding raises alone leaves the clears
unbounded and reproduces the same burst, arriving through the requirement that
gave the lifecycle a state meaning *over*.

**The coalescing is bounded without a queue.** The set of things owing an event
is *derived* each tick, by comparing what a signal, a device or a concern row is
doing now against the last value announced for it — so a burst of 384 costs a
byte per signal of state rather than 384 queue slots, and nothing can be dropped
because nothing was ever enqueued. It also means a thing that moves and moves
back between two ticks owes nothing at all: the difference cancels, where a queue
would carry both records.

**P-096** — `seq` is strictly increasing but **NOT contiguous**. A hole means a
stored record failed its CRC and was skipped. Class A records — state changes,
command outcomes, alarms, config changes, boot records — are never dropped from
the log and never dropped from a queue (P-098), so no hole the controller creates
hides one. The wire is a different matter: the comms processor can drop a frame,
and a hole is therefore evidence rather than proof.

**This rule named three causes and two of them were class B**, which has no
members since `0x0101 value changed` was retired: nothing sheds in the log and
nothing sheds in a queue, so the failed-CRC skip is the only one a controller can
still produce. Both come back with the class, and a client that treats a hole as
possibly-shed is not wrong — it is reading a rule written for the day something
is allocated into class B again.

**P-097** — A client MUST NOT re-read the log on every hole. An unconditional
catch-up per hole is a `ReadLog` storm that anybody able to drop a frame can
trigger. A hole accounted for by a `records dropped` event (`0x0701`) is
explained and needs nothing further: that record carries the count, which is what
turns a hole from a mystery into a number.

`0x0701` stays allocated and **nothing produces one today**: it counted class B
records shed from a session's queue, and class B has no members. A client keeps
the rule rather than dropping it, because the alternative is a client that has to
be changed on the day a kind is allocated into class B — and the failure that
would arrive in the meantime is a stream rendered as complete through a hole with
a number sitting in a record the client stopped reading.

A hole that no `0x0701` accounts for is the other case, and a client MUST NOT
render the stream as complete through one. It MUST surface it, and MAY reconcile
it with a single bounded `ReadLog` from the last `seq` it accepted. That is the
only in-band signal that a frame went missing between the controller and the
screen.

**P-119** — A subscribed client MUST compare the highest `Event` `seq` it has
accepted against the newest `seq` reported inside the MAC'd responses it is
already receiving — `Readings 0x8E` key 1, `SubscribeAck 0x83` key 3
`current_seq`, and `Hello 0x81` key 8 `log_newest_seq` — and MUST treat a
divergence that persists across a bounded number of such responses as a broken
stream: surface it, reconnect, and reconcile with a single bounded `ReadLog`,
exactly as P-097 permits for an unexplained hole.

**A hole is evidence that frames are being dropped; it is not evidence that they
are not.** `type` is in the clear (P-018), so the comms processor can drop every
`0x04` without decoding a body and without knowing what any of them said. Total
suppression produces no hole, because a hole is a gap between two records that
arrived and none arrive. Every rule above — P-096's three causes, P-097's
`0x0701` accounting, P-098's separate MAC per session — runs on evidence that
suppression is careful never to create. A relay that drops one event in ten is
caught immediately; one that drops all of them looks exactly like a quiet site,
which is what this site looks like for most of the year.

What makes the check cheap is that the answer is already on the wire and already
authenticated. The controller's newest `seq` rides inside three responses a
client asks for anyway, under a MAC the comms processor cannot forge — so
"nothing has happened" and "you have been told nothing has happened" become two
different, comparable numbers, with no keepalive, no new field and no traffic on
a link that is metered.

**P-098** — The controller MUST send one separately-MAC'd copy of an event to
each subscribed session. The comms processor holds no key and therefore cannot
fan out; it routes. At eight sessions this is 0.026 % of the UART and 0.014 % CPU
duty on the target, which is what makes the honest option affordable.

Each session's outbound queue holds `MAX_EVENT_QUEUE` events. When it is full,
class B events MUST be dropped oldest first and counted, and the controller MUST
deliver a `records dropped` (`0x0701`) event **to that session** carrying the
count dropped for it — a log-ring count cannot explain a hole one session's queue
made, and P-097 is only honest if every hole arrives with a number attached.

A class A event MUST NOT be dropped on this path. A session that cannot take one
MUST be closed with `CloseConnection`, reason `shedding`
([LINK.md](protocol/LINK.md) L-022, L-023), so the client reconnects and catches up from its
last `seq`. The record is in the log either way. What must never happen is a
client sitting on a socket it believes is live and current while an alarm never
reached it.

**Both paragraphs stand and only the second one runs.** Class B has no members
since `0x0101` was retired, so a full queue has nothing it may drop and every
arrival takes the closing path — which is why a controller conforming to this
today implements no shedding at all. The first paragraph is not aspirational and
not dead: it is the rule the day a kind is allocated into class B, and it is
written here rather than rediscovered then.

### ReadLog — `0x05` / `0x85`

```text
ReadLog  0x05           wrapper
  1: from_seq     u64
  2: max_entries  u16      clamped to 64

LogPage  0x85           wrapper
  1: entries      [ LogEntry ]
  2: next_seq     u64      pass back to continue
  3: oldest_seq   u64      what the controller still holds
  4: complete     bool     true when caught up to newest
```

A `LogEntry` has the same keys as an `Event` body — `seq`, `at`, `kind`, `body` —
and is never a message. The name differs because the two were the same word, and
a rule written about one was being read onto the other: P-056 rejects an `Event`
that goes backwards, which is exactly what a page of log entries does by
construction.

**P-099** — If `from_seq < oldest_seq` the controller MUST answer from
`oldest_seq`. The client can then see it lost data. Silent loss is the failure
this rule exists to prevent.

**There is no outbox.** The cloud is a client with a cursor, exactly like a
phone. Nothing queues on the comms processor, nothing tracks "sent" state, and
there is one catch-up mechanism rather than one per transport.

---

## Configuration

```text
GetConfig  0x06         wrapper
  1: section      u16      see REGISTRY

Config  0x86            wrapper
  1: section      u16
  2: version      u32      increments on every accepted write
  3: body         map      optional; the section's body as Config carries it,
                           below, and absent exactly when version is 0

operation body of SetConfig  0x07
  1: section      u16
  2: expected_version  u32
  3: body         map      the section's body as SetConfig carries it, below

SetConfigAck  0x87      wrapper
  1: section      u16
  2: version      u32      the new one
  3: outcome      u8       see REGISTRY
```

**P-100** — `expected_version` MUST be checked and a mismatch refused with
`stale_version`. For a section that has never been written or that the
controller cannot read, the version checked MUST be 0 (P-108). A client writes
against `expected_version` 0 in either case, and an accepted write replaces
what the controller holds. A phone and a browser editing the same setpoints
is not hypothetical.

**P-108** — A section that has never been written or that the controller holds
but cannot read MUST be answered with `version` 0 and no key 3, and a readable
written section MUST carry a nonzero `version` and key 3, so a client MUST
refuse a `Config` in which the two disagree. The client cannot distinguish
*never written* from *unreadable* and does not need to: in both cases it writes
against `expected_version` 0 (P-100), and an accepted write replaces what the
controller holds. A damaged record can therefore be repaired through the
ordinary read-then-write flow. Neither case is answered with a body of defaults,
which would read exactly like a configuration somebody chose.

**P-101** — Validation happens on the controller and rejection is loud. A
configuration naming a channel that does not exist is refused, not stored, with
`SetConfigAck` outcome 3 `invalid`; a `GetConfig` or `SetConfig` naming a section
that is not allocated is error 6, because that one never reaches a handler at
all. A behaviour that silently never runs is worse than a write that failed.
A section body whose values break its schema below MUST be refused with outcome
3 and MUST NOT be stored: text outside its byte bounds, a `country` that is not
two capital letters, a `hostname` that is not a host name, a `psk` with no
`ssid` to join, and a key a section carries only in `Config` sent in a
`SetConfig`. A body whose CBOR breaks P-015 — a required key missing, a key
twice, a value of the wrong type — is error 1 like any other body. Nothing in a
section is truncated, trimmed or case-folded to make it fit: `ca` is not `CA`
to a radio, and a controller that fixed it quietly would store a value nobody
wrote.

**P-102** — Writes MUST land in the inactive **A/B slot** with a sequence number
and CRC and take effect by an atomic pointer flip. A power cut mid-write leaves
the previous configuration intact and running.

**P-103** — Every behaviour section MUST carry a `shadow` flag readable by a
client, under one key number that is the same in all four behaviour sections.
While every site runs in shadow nothing actuates, and a deployment whose whole
purpose is to be audited must let a person confirm that rather than believe it.
The key is `1`, allocated once as **Behaviour section keys** in
[REGISTRY.md](protocol/REGISTRY.md), and it is a required `bool`: a behaviour
body without it is error 1, never a behaviour presumed live or presumed shadowed.

The earlier draft carried a `crc` in the Config response. It is removed: it
described the FRAM slot's own CRC, which a client cannot compute or check, so it
was a field that could only ever be ignored or wrongly trusted.

### Section bodies

A section has one key space, and `Config` and `SetConfig` both use it. Where the
two differ it is because one field is `secret`, and the network section is the
only place that happens. The sections not listed here are allocated in
[REGISTRY.md](protocol/REGISTRY.md) with their bodies still open in
[DEFERRED.md](protocol/DEFERRED.md) entry 9.

```text
Identity  0x0001        identity and site, in Config and SetConfig
  1: site_name    text     1 to MAX_LABEL bytes; what a person calls the site

Behaviour  0x0010       every behaviour section, 0x0010 to 0x0013
  1: shadow       bool     true while the behaviour decides and actuates nothing

NetworkWrite  0x0020    network, as SetConfig carries it
  1: ssid         text     optional; 1 to 32 bytes; absent when no network is set
  2: psk          text     optional; 8 to 63 bytes; secret
  4: country      text     exactly 2 bytes, ISO 3166-1 alpha-2, A to Z
  5: hostname     text     1 to 32 bytes: letters, digits and hyphens, with
                           no hyphen first or last

NetworkRead  0x0020     network, as Config carries it
  1: ssid         text     optional; as above
  3: psk_set      bool     present exactly when key 1 is: whether a passphrase
                           is held for that network
  4: country      text     as above
  5: hostname     text     as above
```

The **network** section is the master copy L-130 puts on the controller, and
each field is the one `NetConfig 0x65` pushes under the same name: an `ssid`
and a `psk` become an `op = set`, no `ssid` becomes an `op = clear`, and
`country` and `hostname` travel in both. The bounds are `NetConfig`'s, so a
section the controller accepted is one the comms processor cannot refuse as
`rejected_invalid` for its shape. A network with no passphrase is not supported:
a WPA passphrase is what L-131 carries, and an open network is a different
section body, not an empty `psk`.

**P-106** — A field marked `secret` MUST NOT be returned in a `Config` body, and
a client MUST refuse a `Config` body that carries one. The body carries the
field's presence under a key of its own instead — `psk_set` for `psk` — and
never the field's key holding a placeholder. `GetConfig` is answered to every
enrolled client, the cloud client included, so a readable passphrase is a
customer's Wi-Fi credential sitting in our own relay's logs. A `psk` returned
as `"********"` is worse than none: a client reads the section, edits the
hostname, writes the body back, and sets the site's passphrase to eight
asterisks from four hours away. The client refuses as well as the controller
omitting, so that a controller which leaks is a failure somebody sees rather
than a value somebody stores. The same log is why an implementation never prints
a secret field, or a body that may carry one, in its own diagnostics: a
`SetConfig` that is logged on its way in leaks what the `Config` withheld on its
way out.

**P-107** — A `SetConfig` of the network section that carries an `ssid` and no
`psk` MUST keep the passphrase the controller already holds only when that
`ssid` is byte-for-byte the one it is held for, and MUST be refused with outcome
3 `invalid` otherwise, including when no passphrase is held at all. This is
what lets a person change the hostname without retyping a passphrase nobody can
show them. It is never a passphrase following a network it was not given for:
the controller would join the neighbour's access point with the cabin's
credential, and the site would drop off the air with nothing to point at.

---

## Wi-Fi

A person setting up a controller has to choose the network it joins and then
find out whether it joined. The phone in their hand cannot help with either:
iOS gives an app no list of nearby networks, and a `SetConfigAck` says the
section was stored, not that anything came of it. A wrong passphrase, a
mistyped SSID and a network the radio cannot hear all read as success until
somebody notices the unit is not online. These two messages answer both
questions from the radio that has to do the joining. The comms processor scans
and reports; the controller holds the latest of each and answers from it
([LINK.md](protocol/LINK.md) *Wi-Fi scan and join state*).

```text
WifiScan  0x11          wrapper
  1: refresh      bool     true asks for a new scan

WifiScan  0x91          wrapper
  1: scan         u8       scan_state, the most recent scan:
                           1 none · 2 running · 3 complete · 4 failed
  2: refused      u8       optional; scan_refusal, why this request's refresh
                           started nothing: 1 too_soon · 2 radio_off
                           · 3 link_down · 4 unauthorised
  3: age_ms       u32      optional; since the list below arrived, on P-004's
                           tick, saturating
  4: aps          [ Ap ]   present exactly when key 3 is; 0 to MAX_SCAN_APS
                           rows, strongest first
  5: unlisted     u16      present exactly when key 3 is; access points heard
                           and not listed, saturating

Ap
  1: ssid         text     1 to 32 bytes
  2: rssi         i8       dBm, as the radio measured it
  3: security     u8       wifi_security: 1 open · 2 wpa2_personal
                           · 3 wpa3_personal · 4 other
  4: band         u8       wifi_band: 1 ghz_2_4 · 2 ghz_5 · 3 ghz_6
  5: channel      u8       1 to 233, within that band

WifiStatus  0x12        wrapper
  (an empty map)

WifiStatus  0x92        wrapper
  1: section      u32      the network section's version on the controller;
                           0 when never written or unreadable (P-108)
  2: version      u32      optional; the section version the radio is acting on
  3: state        u8       present exactly when key 2 is; wifi_state:
                           1 off · 2 joining · 3 joined · 4 failed
  4: reason       u8       present exactly when key 3 is failed; wifi_failure:
                           1 auth_failed · 2 not_found · 3 no_ip · 4 lost · 5 other
  5: ipv4         bstr4    present exactly when key 3 is joined

WifiStatusChanged  0x0806   wifi status changed, class A, in Event 0x04 key 4
  1: section      u32      as in WifiStatus 0x92
  2: version      u32      required here
  3: state        u8       required here
  4: reason       u8       present exactly when key 3 is failed
  5: ipv4         bstr4    present exactly when key 3 is joined
```

**P-216** — A controller MUST set capability bit 8 in `Hello 0x81` exactly
when it answers both `WifiScan` and `WifiStatus`, and a client MUST NOT send
either to a controller that does not set it. A controller without the bit is
set up by typing the SSID, which is what every client did before these
messages existed.

The bit is how a client learns this before it asks. The alternative is sending
`WifiScan` and reading error 2 as *not supported*, and P-055 forbids concluding
anything from an unauthenticated error: the comms processor can forge that one
and hide scanning from every client it relays for.

**P-217** — The controller MUST hold at most one list, the one from the most
recent scan that completed, and MUST answer every `WifiScan` from it. Keys 3, 4
and 5 MUST be present together exactly when a list is held, `scan` MUST NOT be
`3 complete` without them or `1 none` with them, and a client MUST refuse a
response that breaks either. A failed scan MUST NOT replace or
clear the list held before it; `scan` says it failed and `age_ms` says how old
the list still on offer is.

A list that disappeared when a refresh failed would leave a person who had just
picked a network looking at an empty screen, and an empty list is a real answer:
the radio heard nothing. So *no list*, *the radio heard nothing* and *the
refresh failed* are three different bodies.

**P-218** — A `WifiScan` with `refresh` true that meets a running scan joins
it and carries no key 2. Otherwise it MUST start a scan, unless one of these
holds, and then it MUST carry key 2 naming the first that does:
`4 unauthorised` when the client's mask lacks bit 1 (P-105); `2 radio_off` when
the network section has never been written; `3 link_down` when the comms link
is not up; `1 too_soon` when the controller started a scan less than
`SCAN_INTERVAL_MS` (10 000 ms) before, on P-004's tick. Key 2 MUST be absent
when `refresh` is false. A scan the comms processor refuses, fails or never
answers MUST end as `4 failed`.

**A scan takes the radio off the channel it is working on.** The ESP32-C6 has
one 2.4 GHz radio for Wi-Fi and BLE, and a scan dwells on each channel in turn,
so a phone connected over BLE loses throughput for the second or two it takes.
The interval is what makes that a cost the controller chooses rather than one
any client can impose: eight clients asking every second get one scan every ten
seconds between them, and each reads the same list.

*Radio off* is the unwritten section. A comms processor that holds no country
may not transmit (L-133), and a scan transmits. The setup order follows: write
the network section with `country` and `hostname` and no `ssid`, which pushes
radio metadata and no network, then scan, then write the `ssid` and `psk`. A
client needs the country for the second write anyway.

*Unauthorised* borrows bit 1 rather than allocating a bit of its own, because
the scan exists to choose a network to write. The cloud client cannot write
one, and a client reachable from the internet has no business moving the site's
radio off channel on demand. It still reads the list that is held.

`WifiScan` is not a signed request, although a refresh starts something. It
changes nothing a later request reads except the list itself, the interval
bounds it, and signing it would spend a FRAM counter write on every scan.
Nothing it does reaches the site.

**P-219** — `WifiStatus 0x92` MUST carry key 1, and MUST carry keys 2 and 3
exactly when the controller holds a report from the comms processor's current
boot. It MUST drop the report when the link goes down and when the comms
processor's `boot_id` changes (L-041). Key 4 MUST be present exactly when
`state` is `4 failed` and key 5 exactly when it is `3 joined`. A client MUST
refuse a body or a `0x0806` record that breaks any of these.

Key 1 and key 2 are two versions on purpose. A client that wrote the section
holds the version its `SetConfigAck` returned; when key 2 equals it, the state
is about that write, and when it differs the comms processor has not taken it
yet or failed to store it (L-137). Without the pair, `failed auth_failed` from
the previous network reads as the verdict on the passphrase just typed.

A report from a comms boot that has ended is not a report. The radio that joined
is gone, and the one that replaced it has not said anything yet, so absence is
the honest answer and the client waits for the next one.

**P-220** — The controller MUST write a `0x0806` record when the version, state
and reason it holds differ from those it last announced, and MUST NOT write one
for `2 joining`. A record whose version differs from the last announced MUST be
written at once. Any other MUST wait until `WIFI_RECORD_INTERVAL_MS` (600 000 ms)
after the previous `0x0806`, on P-004's tick, and then carry the state held at
that moment, or nothing if it no longer differs.

The first answer after every write arrives at once, which is the one a person
at the panel is waiting for. A marginal access point is the case the interval
exists for: it drops and rejoins every few seconds, every transition is class A,
and one record each would push a month of history out of the log in a day. Ten
minutes bounds that at six an hour, and a client that wants the state now reads
`WifiStatus`. Losing Wi-Fi also takes the cloud client's route to the log with
it, so a delayed record costs the clients still able to read it very little.
`Joining` is left out because it is what every write starts with. The write
already told the client that much, and announcing it would spend the immediate
record on the one state nobody needed to hear.

**P-221** — A client MUST present the list and the status as the comms
processor's report, and no decision on the controller or a client that grants
anything MAY rest on them. The controller's MAC says it relayed them, not that
they are true: a hostile comms processor can list a network that is not there
and report `joined` from a board that is not. This is `fw_comms`'s rule
(L-032) for the same reason. None of it gains that processor anything: the
passphrase a person types for the network it listed reaches it through
`NetConfig` regardless.

---

## Time

```text
operation body of Time  0x0A
  1: at           u64      ms since epoch

TimeAck  0x8A           wrapper
  1: outcome      u8       see REGISTRY
  2: at           u64      optional; the controller's time after the write,
                           omitted when the clock has never been set
```

`TimeAck` outcome 1 `accepted` always carries key 2, because the write it
answers has just set the clock. A receiver refuses one without it: an answer
that says the clock moved and not where leaves the client unable to tell
whether the time that landed was its own.

**P-110** — Setting the clock is a **signed write**. It changes what every later
log record claims about when it happened.

**P-111** — The controller MUST record `source` in the resulting `time set` event
(`0x0604`). NTP arrives via the comms processor, which this document otherwise
tells you not to believe; recording which one set the clock is what lets a
post-mortem tell a drifted RTC from a lying uplink.

The value recorded comes from the **Time sources** table in
[REGISTRY.md](protocol/REGISTRY.md), which is the one space for it. A clock moved
by a `TimeOffer` the controller accepted ([LINK.md](protocol/LINK.md) L-162) is
recorded as `2` `ntp-via-comms`; `1` `client` is only ever a signed client write.
The value is fixed by which message moved the clock and is never read out of
either one. `TimeOffer` carries a `source` of its own about which NTP path it
used, and that value is never copied through — copying it inverts exactly the
distinction this requirement exists to preserve.

Key 2 of the `Time 0x0A` operation body is **retired**. It carried a `source`
from the same space, and a signed write is always `client`, so the field could
only repeat that or contradict it: a controller that recorded it would log a
client write as NTP from the comms processor. A receiver skips key 2 under P-013
and records the write as `client` whatever it said.

**P-112** — Events already written with no timestamp MUST NOT be retroactively
stamped. Their ordering is exact through `seq`, and a client MAY place them once
time is known. Rewriting history in an audit log is worse than a gap in it.

**P-113** — A `Time 0x0A` whose `at` falls outside the **plausibility window**
MUST be refused with `TimeAck` outcome 2 `rejected`, and the clock MUST NOT move.
The window opens at **the timestamp of the newest log record carrying one** —
P-114's floor, the same value — and closes ten years after it. On a controller
holding no timestamped record at all it opens at the firmware build timestamp
instead.

**Below the lower edge is P-114's case and is answered outcome 4
`needs_button`; outcome 2 is for the upper edge.** The two requirements share
that edge, so without this sentence a set below it matches both and an
implementer picks. They are not the same refusal: below the floor there is
something a person at the panel can do about it (P-116), and ten years ahead
there is not.

That is the same window [LINK.md](protocol/LINK.md) L-140 applies to a first
`TimeOffer`, and it has to be, because it is the same question asked at the other
door. It used to say *from the firmware build timestamp*, which was the rule
LINK.md had before it moved its own floor, so the two documents had drifted into
describing different windows in the same words. The newest log record is the
better floor on every count: it is in NOR, it survives the boot, and it is
correct by construction — the controller was demonstrably running when it wrote
that record, so no honest clock is earlier. A build timestamp is a fact about a
compiler and gets weaker every day the firmware runs; a unit two years in the
field is defending a window that opened two years ago. It is right for exactly
one case, the unit that holds no timestamped record at all, and that is the case
it is kept for.

The ten years are unchanged and are the same ten years for the same reason: the
window has to reach every day of the week and every time of day, or a clock set
by somebody who was simply wrong about the date gets refused for being unusual.

**P-114** — A `Time 0x0A` whose `at` is earlier than the timestamp of the newest
log record carrying one MUST be refused with `TimeAck` outcome 4 `needs_button`.
That timestamp is the **monotonic floor**: the controller already holds it, and
it is the best evidence on site of a moment that has certainly passed. When no
record carries a timestamp — the clock has never been set — there is no floor,
and P-113's window is the whole of the check.

Outcome 4 rather than outcome 2, because the refusal has an answer and outcome 2
does not carry it. P-116 says a person at the panel can override the floor; a
client told only *rejected* cannot tell a time nobody could believe from a
correction that is one gesture away from landing, and has no reason to put *hold
the button and send it again* on the screen. That sentence is the whole point of
P-116, and until this outcome existed there was no way for a client to learn it
was the right one.

**One floor, both doors.** The floor is not a rule about which message moved the
clock. [LINK.md](protocol/LINK.md) L-140 applies it to the first `TimeOffer` after
boot and this requirement applies it to a signed client `Time 0x0A`, so a client
cannot be talked into what an offer was refused — which is the sentence LINK.md
already uses for it, and the earlier wording here said the opposite: *the floor
is on `Time 0x0A` and not on a `TimeOffer`*. Two documents disagreeing about
which door a floor stands in is a floor with a way round it.

**What it binds is the first set, and what it does not bind is the drift
correction, on either door.** An accepted `TimeOffer` inside LINK.md's
5-second cap (L-150) is a correction and not a jump: a clock running a few seconds fast has to be
walked back, that is what correcting drift *is*, and a floor that refused it
would leave the controller unable to make the one correction it is allowed to
make — on a path that is also rate-limited to one offer a quarter hour and
recorded either way. `Time 0x0A` carries no such cap, which is why every one of
them meets the floor. What P-114 refuses is the jump, not the correction.

**P-115** — When the clock was **already known** and an accepted set moves it by
more than `TIME_STEP_ALARM`, **one hour**, in either direction, the controller
MUST raise a class A `concern raised` (`0x0501`) at condition `clock stepped`,
alongside the `time set` record P-111 requires, whichever message moved it. The
concern names the condition and **not the size of the step**: the `time set`
record carries the old value and the new one, so the step is already written, and
one number recorded twice is two numbers that can disagree. A first set after
boot is not a step:
there is nothing to subtract it from, and a difference computed against a clock
that was never known is a measurement nobody made.

Outcome 2 `rejected` is produced by P-113 and by nothing else, and outcome 4
`needs_button` by P-114 and by nothing else — before them neither had a producer
at all, which made them values in the registry no controller could send and no
client would ever see. On either the clock does not move and key 2 carries the
time the controller kept, omitted under P-093's rule when it has never had one: a
rejected first set would otherwise have to answer with a zero, and a zero is
1970.

None of this existed, and `Time 0x0A` is the one message that moves the clock
with nothing bounding it. LINK.md is careful about a `TimeOffer` — ten-year
window on the first set, five seconds a step afterwards, one offer a quarter hour
(L-140, L-150, L-151) — and not one of those bounds reached a signed client
write. Any compromised
client key wrote any time it liked.

The **backward** jump is the worse half and nothing addressed it at all. LINK's
cap is about the forward jump, where a schedule fires early and somebody hears an
engine. Move the clock back ten years and every schedule, exercise and
quiet-hours deadline lands in the future: nothing fires, nothing alarms, and the
weekly exercise run never comes round again. That is not a benign delay: *a
generator that only starts in an emergency is a generator that does not start in
an emergency*, and the symptom arrives four months later, in February, as an
engine that will not catch.

LINK.md's L-161, that **a clock change never replays a schedule**, is written about
a `TimeOffer` and applies here word for word. It is a rule about what a behaviour
may treat as elapsed, not about which message moved the clock, so the forward
jump P-113 still permits — anywhere inside a ten-year window — starts nothing.

**P-116** — A `Time 0x0A` that the floor would refuse MUST be accepted **while a
floor override is armed**, and the controller MUST raise a class A
`concern raised` (`0x0501`) at condition `floor overridden`, alongside the
`time set` record P-111 requires. How far back the clock went is that record's
old value against its new one, for the reason P-115 gives. With no override armed
it is refused under P-114 exactly as before, as `TimeAck 0x8A` outcome 4
`needs_button`.

**P-117** — The floor override:

1. Is armed **only** by a press pattern at the panel distinguishable from
   P-066's enrolment gesture and from the factory-reset hold. An enrolment
   gesture MUST NOT arm an override; P-066's first-enrolment power-on window
   MUST NOT arm one either.
2. Is **single-use**: it authorises exactly one accepted floor-crossing
   `Time 0x0A`, and MUST be cleared on use, on release of the button, and on a
   bounded timeout no longer than P-066's 120 seconds.
3. Is evaluated at the **instant the controller processes the operation**. It is
   not a window a client can be told about in advance and it is not P-066's
   120-second window.
4. Does not lift P-118's rate limit. A `Time 0x0A` refused for the rate limit is
   refused with an override armed exactly as without one.

**P-118** — The controller MUST accept at most one `Time 0x0A` per **15 minutes**
on P-004's tick, matching the `TimeOffer` bound in
[LINK.md](protocol/LINK.md) L-151. Beyond that it MUST refuse with error 7 `busy`,
before the operation executes.

The armed state is what makes "somebody is at the panel" an authorisation rather
than a coincidence. Without rules 1 and 2, holding the button is a *condition* a
client can wait for: an attacker banks a floor-crossing frame with a valid MAC
and a fresh counter, retries it in a loop, and it lands the moment a technician
holds the button down for an unrelated reason — enrolling a new phone, most
likely, since that is the press this document already asks people to make. The
person who authorised nothing sees an engine that will not start in February. Not
arming on the enrolment press is what breaks that, and it is also what stops
`pairing_open` in `Discover 0x80` from being a published signal for when to fire.

Rule 4 and P-118 close the retry loop itself. A client that may send `Time 0x0A`
as fast as it likes costs nothing to park in a loop, and every rule above is a
rule about *when* the write lands rather than *whether* it can keep asking. One
write a quarter hour makes waiting for a press expensive and matches L-151, the bound
LINK.md already places on the comms processor's own offers — the same door should
not have two widths depending on which side knocks.

**There is deliberately no field reporting the button's state.** A
`button_held` flag in `Discover 0x80` would let a client prompt *hold the button
and send*, which is the one thing outcome 4 does not do as well. It would also be
an unauthenticated, pollable answer to *is somebody standing at the controller
right now* — strictly better for the attacker above than the `pairing_open`
oracle rule 1 exists to close, and available to anybody who can reach the port
rather than only to an enrolled client. Outcome 4 tells a client the same thing
one refusal later, on a MAC'd response, at a rate P-118 bounds.

**The enrolment window and the floor override are separate states and either may
be true without the other.** The enrolment window is 120 seconds long, opened by
P-066's physical act (including its first-enrolment power-on exception),
and reported as `pairing_open` in `Discover 0x80` key 6. The override is
armed by a different gesture, consumed by one write, and reported nowhere. An
open pairing window is **not** the P-116 gate and MUST NOT be read as one. The
factory-reset hold is a product-local behaviour outside KM43 because it changes
no message, but it is a third distinct gesture rather than "the button" a third
time.

The override is of the **floor**, which means P-114 and the lower edge of
P-113's window, because they are the same value and lifting one without the
other lifts nothing. The ten-year upper edge still binds and is not overridable
by anything: the button is evidence about a clock that ran ahead, not a licence
to write any number at all.

This closes a gap P-114 used to concede in place of fixing. A clock set wrong
*forward*, inside P-113's window and so a date somebody could believe, stayed
wrong forever: every correction downward is below the floor and refused, so the
one thing a person could do about it was the one thing the controller would not
accept. Every record written from then on carries a date that is years out, and
the log stops being something anybody can reason about — which is the thing the
floor exists to protect.

**The floor is evidence, not authority.** It says a moment has certainly passed,
inferred from a record this controller wrote. A person standing at the panel is
better evidence about the same question, and it is deliberately the same *class*
of evidence that gates enrolment (P-066) and factory reset — not the same
gesture, which P-117 rule 1 exists to keep apart — because it is the same class
of decision: something that cannot be undone from four hours away, made by
somebody who is not four hours away. The attack the floor refuses — a
compromised client walking the clock backwards until no schedule ever fires again
— needs nobody at the site by construction, so requiring somebody at the site
costs it nothing and costs the attacker everything.

The alarm is what keeps it honest. An override that left no record would be a
floor with a quiet door in it, and *the clock was moved back eleven months, by a
person at the panel, on this date* is a sentence somebody reading the log in
February has to be able to find.

---

## Commands

**Reserved until a controller is granted authority over an output.** No actuation
before then — see [DEFERRED.md](protocol/DEFERRED.md). The shape is fixed now so
the code space and the dedup rule cannot be invented differently later.

```text
operation body of Command  0x08
  1: cmd_id       u32      client-generated, unique per command
  2: kind         u16      see REGISTRY
  3: args         map

Ack  0x88               wrapper
  1: cmd_id       u32
  2: outcome      u8       see REGISTRY
  3: detail       text     operator-facing, <= 64 bytes
```

**P-120** — The dedup table MUST be keyed
`(client_id, cmd_id, operation-hash)`, where **operation-hash is the leftmost 8
bytes of SHA-256 over the `operation` byte string exactly as it arrived on the
wire** (P-048, and never over a re-encoding).

`client_id` is in the key because two clients numbering their commands from zero
is the normal case, and a `cmd_id`-only key answers `duplicate` to a command
nobody sent twice — the failure looks like the controller ignoring a stop
request.

The hash is in the key because `(client_id, cmd_id)` alone cannot tell a **retry**
from a **reused id**. A genuine retry carries byte-identical operation bytes —
same `cmd_id`, same `kind`, same `args`, only the counter is new under P-082 — so
it hashes the same and dedups, which is the whole point of the table. A client
that reuses a `cmd_id` inside the window for a *different* command carries
different bytes and hashes differently.

**The lookup is on `(client_id, cmd_id)` and the hash decides which answer the
match gets** — `duplicate` when it agrees, P-124's `rejected` when it does not.
An implementation that hashes all three fields into one opaque key cannot tell
the two apart: a reused id simply misses, and the controller executes a second
command under an id it has already answered for, which is the failure the table
exists to prevent arriving through the fix for a different one.

**An entry is created only for a command that executed or committed to
executing** — outcome 1 `accepted` or outcome 6 `shadowed`. Outcome 2 `rejected`
(P-124's and the handler's alike), outcome 4 `inhibited` and outcome 5
`unauthorised` MUST NOT create one.

Each of those three names a condition the client is expected to retry past. The
selector was at Off and somebody has since turned it; a capability was missing
and has been granted; a refusal was transient. Leave an entry behind and the
retry that should finally run is answered `duplicate` instead — the same silent
no-op wearing the word for success that P-124 exists to prevent, reached from the
other side.

**A live match with an agreeing hash MUST be answered with the outcome that was
recorded**, not unconditionally with `duplicate`: `duplicate` where the recorded
outcome was `accepted`, and `shadowed` where it was `shadowed`. A retried command
in shadow mode that comes back `duplicate` tells the client an action was taken
at a site where, by definition, nothing was actuated — and shadow mode exists so
that nobody has to guess which of those two happened.

An entry is 25 bytes — `client_id:u32`, `cmd_id:u32`, hash 8, `inserted:u64`,
`status:u8` — so `MAX_CMD_DEDUP`'s 32 entries cost 800 bytes of FRAM, on a part
that already holds the client keys, the counters and the A/B configuration
pointer. `status` is the in-flight/complete distinction P-080 step 4 needs and
the recorded outcome together; two states and two outcomes fit a byte with room
left. Eight bytes of hash is 64 bits against an attacker who does not choose the
key and gains nothing from a collision anyway: the worst a collision does is
answer `duplicate` to a command that was not one, which is the same failure the
`client_id` in the key already exists to prevent and is bounded to one client's
own ten-minute window.

**P-121** — The dedup table MUST live in **FRAM** and survive a reset. A reboot
inside the dedup window would otherwise turn a client's retry into a second
start, on a maintained contact, at a site with nobody in the room.

**On boot, every surviving entry's `inserted` MUST be set to the new boot's tick
zero**, so it lives a further ten minutes from that moment and never longer.

`inserted` is P-004's monotonic tick, and P-004's tick is zero at the boot P-121
requires the entry to survive — so a surviving entry has no clock to be measured
against, and until this rule existed there was none to write. Four requirements
could not all hold at once: the window is measured on the tick (P-004), the entry
outlives the reset (P-121), it never evicts (P-122), and the entry had no field
to hold a time at all. Both branches an implementer could pick were bad. Never
draining fills the table at 32 and P-122 then answers error 7 to every command,
which is a site that cannot be told to stop. Expiring at boot restores exactly
the double-start hole P-121 exists to close.

**Re-basing at boot over-retains rather than under-retains, and that is the
direction chosen deliberately.** Over-retaining answers `duplicate` to a command
that was not one, bounded to ten minutes after a reset. Under-retaining starts a
generator twice on a maintained contact. The first is a client that has to send
its command again; the second is why the table is in FRAM.

Do **not** reach for a persisted tick base or a tick counted from first boot.
Either makes the tick's monotonicity depend on a FRAM write surviving the
brown-out that caused the reset — and P-079 already says that write is a thing
that can fail.

**P-122** — The table holds `MAX_CMD_DEDUP` entries for 10 minutes. When full the
controller MUST refuse with error 7 rather than evict. Evicting the oldest entry
is what makes a duplicate executable again.

**No single `client_id` may hold more than half of `MAX_CMD_DEDUP` live
entries.** A client at its own ceiling is refused error 7; every other client is
unaffected.

Without that bound the table is one pool and `MAX_CLIENTS` is 8, so a single
enrolled client — a commissioning laptop in a retry loop, a cloud relay with a
stuck queue — fills all 32 entries in ten minutes and every other client's next
command is refused error 7. That is one misbehaving client denying a stop
request to all seven others, and P-081 already rejects the same shape for
counters: shared per-device state livelocks the moment two clients are active.

Half rather than `MAX_CMD_DEDUP / MAX_CLIENTS`: a hard eighth is 4 entries, too
thin for a commissioning session, and it strands 28 entries whenever one client
is the only one on the site — which is most of the time. Half means the table can
only be globally full when at least two clients are jointly filling it, and it
costs nothing when only one is present. Refusing still beats evicting; it just
refuses the client that filled its own share first.

**P-124** — A `Command` whose `(client_id, cmd_id)` matches a live dedup entry
but whose operation-hash does not MUST be answered `Ack 0x88` outcome 2
`rejected`, with `detail` saying the `cmd_id` was reused for a different command.
It MUST NOT be answered `duplicate`, and it MUST NOT execute.

That case is a client bug and the protocol should say so out loud rather than
swallow it. Keyed on `(client_id, cmd_id)` alone the controller answers
`duplicate`, which reads at the client as *you already sent this, it was already
acted on* — so the client stops, satisfied, and the command it actually asked for
was never executed and never refused. A silent no-op wearing the word for
success is the worst answer available on a message type that starts engines.
`rejected` with a `detail` a person can read sends the same client back to look
at how it numbers its commands, which is where the fault is.

Executing it instead is not the alternative. The whole point of the window is
that the controller cannot tell a reused id from a retry it half-heard, and the
one thing it must not do is start a generator twice on a guess.

**P-123** — `inhibited` and `shadowed` are outcomes, not errors. The selector is
at Off, or the generator is running and not ours, or the behaviour is in shadow
mode. Each is the controller declining with a reason a person can read.

---

## Firmware

**Reserved.** The message bodies are deferred — no OTA until a bootloader exists
and an image has been verified on a bench — but the signing manifest, signature
algorithm and key location are **not** deferred that far, because a bootloader
cannot be retrofitted to a unit already in a cabin. See
[DEFERRED.md](protocol/DEFERRED.md) for the trigger.

What is settled and MUST NOT be relitigated when the bodies land:

**P-130** — The comms processor delivers the controller image; the **controller's
own bootloader** verifies the signature. Letting the untrusted chip be the
gatekeeper would undo every other authentication argument in this document.

**P-131** — A comms image is verified twice: the controller authorises the
release, and the **comms processor's own secure boot** verifies the image
signature before executing it. Step two is not redundant — a comms processor that
is already compromised must still refuse an invalid image at its own boot,
without help.

---

## Errors

```text
Error  0xFF             bare — no session to key a MAC with
  1: code         u16      see REGISTRY
  2: detail       text     <= 64 bytes

Error  0xFF             wrapper under session_key, the bare body above inside
  1: payload      bstr
  2: mac          bstr16
```

Which of the two a sender uses is decided by **P-142 and nothing else**: wrapped
when the sender holds a session for that `session_id`, bare when it does not.

The registry's MAC'd column is not a second test for the same question. It is the
**receiver's** check — the list of codes a receiver refuses to read out of a bare
body — so a bare `Error` carrying a code marked MAC'd is discarded under P-051
rather than acted on. Read as an instruction to the sender it becomes a rule that
cannot be obeyed: the conditions where there is genuinely no session are exactly
the ones where the sender has no key to honour it with. One column, one meaning,
and the meaning is *what a receiver will accept*.

**P-140** — See P-055. An unauthenticated error is a hint, never a fact.

**P-141** — A request that reaches its handler MUST be answered by its own
response type, carrying an outcome. `Error 0xFF` is for conditions that stop a
request reaching a handler at all, plus P-060's challenge-unavailable refusal:
`Discover` has no refusal outcome. Where a registry lists both an outcome and an
error code for the same condition, **the outcome is what is sent**.

Two answers to one refusal is one implementer emitting an error while another
implements the outcome as dead code, and the split is not cosmetic: an outcome
rides inside a MAC'd response and most of these error codes do not, so the
duplicate is also the forgeable one. An over-cap config write is `SetConfigAck`
outcome 5 (P-090), a closed pairing window is `Pair 0x8B` outcome 2 (P-066), a
failed pairing proof is `Pair 0x8B` outcome 3 (P-051), and a version mismatch is
outcome 2 `stale_version` (P-100). Codes 13 and 15 are the error codes the first
two replaced, and both are now `withdrawn` in
[REGISTRY.md](protocol/REGISTRY.md) — which is what this requirement looks like
once it has been applied rather than only stated. Code 10 stays live because it
still answers a wrapper MAC and a signed request; what it must not answer is a
`Pair`.

**P-142** — Which of the two shapes an `Error` takes is decided by whether the
**sender** holds a session for that `session_id` — wrapped under `session_key`
when it does, bare when it does not. A receiver MUST NOT decide by inspecting the
body: it applies its own session state, and P-051 stands, so a bare body carrying
a code the registry marks MAC'd is discarded rather than read. Letting the body
choose is letting the comms processor strip the MAC off a refusal to hide it.

The two sides can disagree, and one code exists for exactly that: a client whose
session the controller has already dropped gets a bare error 9 where it expected
a wrapper. So a client that receives an `Error` on a session it believes is live,
and that is not the wrapper or does not verify, MUST NOT act on its code and MUST
NOT conclude anything about the site from it (P-055). It reconnects and sends a
new `Hello`. It MUST NOT conclude that its earlier writes did not land — the log
is what says that.

**P-143** — A request whose type requires a session, arriving before any `Hello`
has succeeded on that connection, MUST be refused with error 4. One arriving on a
`session_id` the controller does not hold, or on one that has expired, MUST be
refused with error 9. Both are bare under P-142, because in both the controller
has no key to sign with. Two conditions the whole protocol turns on had a number
in the registry and no rule pointing at it, which is two implementers picking
differently for the same refusal.

**A frame carrying a `type` this document does not allocate MUST be refused with
error 2, bare.** That is the third such condition and it was the last live code
in the registry that no rule produced. Without a rule, one implementation answers
error 1 and calls it malformed — it parsed perfectly, it simply says nothing —
another drops the frame and answers nothing at all, and a client that hears
nothing waits out its own timeout with an empty screen. Bare like error 1 beside
it and for the same reason: the refusal happens before any session lookup,
because `type` is what selects the handler that would have found the session, and
there is no handler.

A link-local type on a client-facing transport is **not** this code. That is
error 257 under P-020 — a routing bug in the comms processor rather than a client
sending nonsense, and the two want different investigations.

---

## The comms processor boundary

**May:** frame and unframe, fragment and reassemble, route by `session_id`,
**route a `session_id = 0, req_id = 0` error back on the connection the offending
frame arrived on** (P-025), **stamp the connection handle into `session_id` on
every inbound client frame, overwriting whatever the client sent** (P-021),
rate-limit, validate frame sizes, terminate TLS, hold a Wi-Fi association,
advertise over BLE, serve the web UI's static assets.

Stamping is the one envelope field it rewrites, and it is in this list rather
than assumed: rewriting an envelope field is exactly the sort of thing the
"shall not" list would otherwise forbid, and LINK.md depends on it in three
places (L-003, L-012, L-062).

**Shall not:** decode a body, cache controller state, answer a request on the
controller's behalf, hold automation configuration, interpret command semantics,
or **fan out an event** — it holds no key, so it cannot produce a valid copy.

| | Where | Why |
|---|---|---|
| Wi-Fi credentials | Cached on the comms processor, encrypted in its own NVS; controller holds the master copy | It must associate at boot without waiting for the controller |
| TLS certificates, cloud endpoint | Comms processor | Transport concerns |
| Connection routing table | Comms processor, 8 rows ([LINK.md](protocol/LINK.md) L-060, L-061) — it owns the transports, not the bindings | Transport concern by definition |
| Device key, client keys, counters | **Controller only, never transmitted** | The whole basis of authentication |
| Everything about the site | Controller | It is the thing that decides |

---

## Conformance

An implementation is conforming when all of these pass. Controller pairing
checks MUST include P-066's first-enrolment exception: a valid empty client table
read at boot on a board without a pushbutton opens one 120-second window; expiry does
not reopen it in that boot; a first successful `Pair` closes it; an enrolled
unit's reboot opens nothing while its table remains non-empty; factory reset
restores eligibility on subsequent boots; a boot that finds an absent or
unreadable table and repairs it opens nothing, but a later boot that reads the
valid empty table is eligible; and a board with a pushbutton never opens a
window at power-on. A wrong printed-secret proof still fails inside the boot window. PairingWindow reports
MUST follow L-193 through L-195, including the remaining time after a delayed
link and closure after enrolment. The selector gesture remains available on a
board without a pushbutton, including after the boot window expires.

An implementation claiming conformance is claiming it for **UART, USB CDC and
WebSocket**. BLE has host transport vectors but no phone/board qualification;
MQTT has no transport vectors. Neither is conformance surface — see [DEFERRED.md](protocol/DEFERRED.md) entry 7.

1. Every core vector in `protocol/vectors/v1.json` reproduces exactly. BLE
   qualification additionally requires the `ble` traces and the phone/board
   evidence in DEFERRED entry 7.
2. COBS round-trips every length from 0 to `MAX_PAYLOAD`, including 254 and 255,
   and matches the Cheshire & Baker examples — including the one a round trip
   cannot catch on its own, 254 bytes followed by a zero, where an encoder and a
   decoder that are wrong the same way agree with each other and with nobody
   else.
3. Every single-bit flip in a framed message is caught by the CRC or the MAC.
4. A truncation at every byte offset of every message decodes to an error, never
   a panic and never a partial accept.
5. Random bytes fed to the resynchroniser for a million frames produce no panic,
   no allocation and no unbounded loop.
6. A message with an unknown map key is accepted; a message with an unknown enum
   discriminant is rejected; a message carrying the same map key twice is
   rejected with error 1; and a `Readings` page carrying one reading drawn from
   an enum space in the vendor range alongside a known one is accepted, with that
   one reading surfaced as unrecognised (P-019, P-125).
7. Every table reaches its cap under load and refuses, and none evicts — except
   `MAX_EVENT_QUEUE`, which drops class B and closes the connection rather than
   dropping class A. `MAX_AUTH_FAILURES` is in that sweep too, and it is a
   counter rather than a table: the connection is closed at the cap, and a
   `Goodbye` and a fresh `Hello` part-way through the run does not reset the
   count.
8. A replayed request is dropped unanswered by the `req_id` window, refreshes
   nothing and counts nothing (P-022), and a signed write re-sent under a fresh
   `req_id` with its old counter is refused by the counter; a replayed event is
   rejected by `seq`; a `LogPage` whose entries go backwards is accepted; a
   response moved to another `req_id` fails its MAC.
9. Removing any single MAC check causes at least one test to fail loudly.
10. An `Error` answering a request is matched to that request by its echoed
    `req_id`; an `Error` carrying `session_id = 0, req_id = 0` is surfaced as a
    link diagnostic rather than dropped, and never completes a request.
11. Every reported cap is checked against a ceiling derived from the encoder's
    own widths, and the worst case is what gets built — not a typical one. This
    is the cap the document got wrong once, by counting 32 as "the largest that
    fits" when 35 did, and it was a worst-case test that caught it. The message
    that finding was made against is retired; the discipline it produced is what
    `limits.rs` asserts for `MAX_SAMPLES`, `MAX_SERIES`, `MAX_INVENTORY_PAGE_ROWS`
    and the rest.
12. A five-element envelope is rejected with error 1 and nothing inside it is
    read (P-028), and a `Hello 0x81` reporting `max_channels` above 32 is
    refused rather than clamped (P-006).
13. A `Command` retried with identical operation bytes answers `duplicate`; the
    same `cmd_id` with different operation bytes inside the window answers
    `rejected` and does not execute (P-120, P-124). One test per direction, and
    the second one fails loudly if the operation-hash is dropped from the key.
14. A session with an active subscription, fed events and answering nothing,
    expires on schedule (P-077). This is the test that fails if outbound traffic
    is allowed to refresh the timer, and it fails nowhere else.
15. A section that has never been written and a damaged section the controller
    cannot read both answer `GetConfig` with `version` 0 and no key 3 (P-108).
    In each case, an otherwise valid `SetConfig` with `expected_version` 0
    replaces what the controller holds; a subsequent read returns the written
    body and its nonzero version (P-100). A mismatched expected version is
    refused, and clients reject a `Config` whose version and body disagree.
