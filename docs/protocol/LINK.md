---
title: Controller–comms link
description: Normative link-local messages, limits, and recovery rules between the STM32 controller and ESP32-C6 communications processor.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

# Link-local messages — controller ↔ comms processor

<p class="o89-doc-kicker">KM43 / link-local specification</p>

<p class="o89-doc-deck">The private transport contract between the STM32 controller and the ESP32-C6 communications processor: connection lifecycle, flow control, credentials, time, and firmware release.</p>

<dl class="o89-doc-facts">
  <div>
    <dt>Status</dt>
    <dd>Normative draft</dd>
  </div>
  <div>
    <dt>Security boundary</dt>
    <dd>The STM32 decides; the ESP32 routes</dd>
  </div>
  <div>
    <dt>Opcode range</dt>
    <dd><code>0x60–0x7E</code> / <code>0xE0–0xFE</code></dd>
  </div>
  <div>
    <dt>Forwarded to clients</dt>
    <dd>Never</dd>
  </div>
</dl>

<nav class="o89-doc-links" aria-label="Related KM43 documents">
  <a href="/km43/specification/">Client protocol <span aria-hidden="true">→</span></a>
  <a href="/km43/registry/">Allocated numbers <span aria-hidden="true">→</span></a>
  <a href="/km43/verification/">Verification plan <span aria-hidden="true">→</span></a>
</nav>

None of these messages is forwarded to a client or carries a tag. Their outcomes,
reasons, and operation values share the authoritative allocation in
[`protocol.toml`](../../crates/km43/protocol.toml); `cargo xtask check`
refuses an allocated value that this document never names.

---

## Why this document exists

The design already requires all of these exchanges. `Hello` promises the client a
`fw_comms` string and nothing in the client protocol supplies it. The handshake
requires a challenge that is fresh *per connection*, and nothing told the
controller a connection had happened. The comms processor caches Wi-Fi
credentials whose master copy lives on the controller, and no message moved them.
The controller authorises a comms firmware release, over a message that did not
exist.

Every one of those would have been invented at bring-up, on a bench, by whoever
hit it first — and would then have been outside the versioning scheme, with no
opcode allocation, no capacity, and no answer for what happens when one side
reboots. That is the defect this file closes.

---

## Reserved range

| | Requests | Responses |
|---|---|---|
| Client messages | `0x00`–`0x5F` | `0x80`–`0xDF` |
| **Link-local** | **`0x60`–`0x7E`** | **`0xE0`–`0xFE`** |
| Error | — | `0xFF` (shared) |

The high-bit rule is unchanged: `type` with the high bit set is a response.
`0x60`–`0x7E` is carved out of the request space and `0xE0`–`0xFE` out of the
response space, so a reader who knows only the client protocol sees an opcode it
has never heard of rather than one it might guess at.

`0x7F` is deliberately left out of the range, because `0x7F | 0x80` is `0xFF`,
which is Error. Thirty-one request codes against thirty-one response codes is a
range that cannot be got wrong; thirty-two against thirty-one is a trap laid for
whoever allocates last, in a range whose stated virtue is that nothing special
has to be remembered.

| | Request | Response | Direction |
|---|---|---|---|
| LinkUp | `0x60` | `0xE0` | either side |
| Heartbeat | `0x61` | `0xE1` | either side |
| ClientConnected | `0x62` | `0xE2` | comms → controller |
| ClientDisconnected | `0x63` | `0xE3` | comms → controller |
| CloseConnection | `0x64` | `0xE4` | controller → comms |
| NetConfig | `0x65` | `0xE5` | controller → comms |
| TimeOffer | `0x66` | `0xE6` | comms → controller |
| CommsRelease | `0x67` | `0xE7` | controller → comms |
| EnterDownload | `0x68` | `0xE8` | controller → comms |
| PairingWindow | `0x69` | `0xE9` | controller → comms |
| WifiScan | `0x6A` | `0xEA` | controller → comms |
| WifiScanResult | `0x6B` | `0xEB` | comms → controller |
| WifiState | `0x6C` | `0xEC` | comms → controller |
| *reserved* | `0x6D`–`0x7E` | `0xED`–`0xFE` | — |

**L-001** — A receiver MUST refuse a link-local message arriving from the side
the direction column does not permit, with code 256 — the same code as an opcode
it does not know. The comms processor answering `ClientConnected` at the
controller is a bug in the comms processor, and a controller that accepts a
`CommsRelease` from its own peer has lost the plot about who authorises
firmware. From the receiver's side those are the same mistake — a frame it has
no business acting on — so one code covers both and neither firmware has to
decide which kind of wrong it is looking at.

### A link-local opcode on a client transport is a protocol error

**L-002** — The comms processor MUST NOT emit a frame in this range on BLE,
WebSocket, MQTT or USB, and MUST NOT accept one from them. A client frame
carrying a link-local `type` MUST be dropped at the comms processor — not
forwarded, not translated, not answered on the controller's behalf — and the
client MUST be answered `Error 0xFF` with code 257.

Without that rule the whole boundary is decorative. Anything a browser can put on
the wire could tell the controller that a connection exists, offer it a time, or
name a firmware digest. Refusing at the comms processor is what keeps this range
meaning *the two firmwares talking to each other* rather than *a message type any
client can send*.

**L-003** — In the other direction: the comms processor MUST drop a frame the
controller emits with a link-local `type` and a non-zero `session_id`, and MUST
answer code 263 rather than routing it to a client. That frame is a controller
bug, and the only thing routing it achieves is delivering a message about the
link to whichever unlucky client happens to own that session number. 263 goes
back to the side whose bug it is, where somebody can act on it.

---

## Envelope, framing and correlation

Identical to the client protocol, deliberately — one decoder, one framer, one set
of size limits on each side:

```text
[ type: u8, session_id: u16, req_id: u32, body: map ]

COBS( envelope | crc16 ) 0x00
```

**L-010** — A link-local frame MUST use the client protocol's envelope, framing
and size limits unchanged: CBOR with integer keys (P-011), definite lengths,
unknown keys skipped (P-013), unknown enum discriminants rejected (P-014), every
listed key required unless it is marked *optional* (P-015), RFC 8949 §4.2
deterministic encoding (P-016), and the 1024-byte payload cap. The rules are
named rather than summarised because a link-local body that is missing a required
key has to fail the same way a client body does, and the reader should not have to
work out which of the client rules followed the envelope across. The UART is
921600 8N1 with RTS/CTS, as everything else on this link.

**L-011** — Every duration in this document MUST be measured on P-004's
monotonic tick since boot, never on the wall clock.

One bound in particular is why. The 500 ms response timeout, the 2-second
heartbeat and the 6-second ladder would survive being measured on anything, since
nothing here moves the clock by seconds on purpose. **The 15-minute rate limit on
accepted time offers would not.** Its entire job is to stop a clock walk, and the
wall clock is the thing the walk moves — an offer accepted as a first set lands
anywhere inside a ten-year window, and any enrolled client can push the clock an
hour with a signed `Time 0x0A`, either of which hands the comms processor a fresh
offer slot on demand. Backwards is no better: a clock moved back leaves *last
accepted* in the future and refuses every honest offer until real time catches
up. A bound measured on the quantity it is bounding is not a bound. It is
measured on the tick, which nothing on this link can move.

**L-012** — Every link-local frame MUST carry `session_id = 0`. Session 0 means
*the link itself, not a client*, and a handle is never 0 (L-060), so the two uses
cannot collide. It is also what makes L-003 decidable: a link-local frame
carrying a non-zero session is a controller bug the comms processor can see
without knowing anything else about the frame.

**L-013** — The sender MUST allocate `req_id` from its own counter, independent
of the peer's, and both counters wrap. A `req_id` is only meaningful until its
response arrives, and it MAY recur on this link: P-022's strictly-increasing,
never-reused rule does not apply here.

Wrapping is allowed here and forbidden one document over, and the difference is
not an oversight. A client's `req_id` is the nonce its request is sealed under
and is inside every response's associated data, so a value that recurs inside a
session is a nonce used twice under one key. Nothing in this range is sealed or
carries a tag, and at most four requests are
outstanding per side, so there is nothing here for a recurring number to unlock.
Saying so is what stops somebody carrying P-022's wrap-out path onto a link that
does not need it.

**Integer widths** in the bodies below are the range a field is allowed to take,
not its encoding — CBOR emits shortest-form integers. Where a link-local integer
ever enters a hash, a MAC or an associated data string it is big-endian, fixed width, no padding, no
length prefix, exactly as in the client protocol. Today no link-local field does,
which is the subject of the next section.

| Limit | Value | Rule |
|---|---|---|
| Outstanding link-local requests, per side | **4** | L-014 |
| Response timeout | 500 ms | L-015 |
| Attempts before a request is given up | 3 | L-015 |
| `EnterDownload` repeat period, exempt from L-015 | 100 ms | L-192 |
| `EnterDownload` given up after | 3 000 ms | L-192 |

**L-014** — A side MUST NOT have more than 4 link-local requests outstanding,
and a receiver MUST answer a peer's fifth with code 262. It is a fixed table on
both sides with nothing behind it to grow into, and refusing beats evicting here
as everywhere: a fifth request that displaced an outstanding one would lose
whichever answer somebody was already waiting on, and the sender would never
learn which.

**L-015** — A sender MUST treat a request unanswered after 500 ms as failed and
MUST retry it with the same `req_id`, up to 3 attempts; after the third it MUST
give the request up and report it failed to whatever asked. Whether the link is
down is not this rule's to decide: that is L-100's timer alone, which a peer
that answers nothing reaches six seconds after its last answer whatever was
outstanding. A `Heartbeat` is not retried either, because the next beat two
seconds later is its retry and a missed one is what L-100 measures. Reusing the
`req_id` is what lets the peer recognise a retry instead of answering a request
it has already answered, and it is only safe because nothing in this range
is sealed. Retrying forever is the alternative, and it hides a
link that has stopped carrying traffic behind a sender that looks busy.

Nothing in this range is cryptographic, so its vectors in
[vectors/v1.json](vectors/v1.json) are wire bytes only, and they are a subset
of the allocated opcodes: `LinkUp`, `ClientConnected` and its acknowledgement,
`TimeOffer` and its refusal, `NetConfigAck`, and `EnterDownload` and its
refusal, plus `PairingWindow` open, closed and acknowledgement, and the Wi-Fi
scan request, its refusal, a complete and a failed result, its acknowledgement,
and a joined and a failed state report, chosen for the bodies with the most keys
and, for `TimeOffer`, `EnterDownload` and `WifiScan`, the refusal rather than
the acceptance. They exist because the
two ends of this link are two codebases, and bytes two implementations agree on
with nothing else checking them are how a format drifts.

---

## Unauthenticated by design, and where that stops

**L-020** — **While the two chips are on one board**, a link-local message MUST
NOT carry a MAC, and the two chips MUST NOT share a key for this purpose. Two
reasons, and the second is the one that matters — and the scope is in the
requirement rather than in the heading above it, because L-024 is the exception
and an unconditional MUST NOT here would make that exception unimplementable.

The link is two chips on one board, in a sealed enclosure, in a locked electrical
room, four hours from a road. Somebody with probes on that UART already has the
FRAM, the controller key and a screwdriver, so authentication would be protecting a
door that is already off its hinges.

More to the point: **there is no key that would help.** A link key would have to
live in the ESP32's flash — the part this entire architecture assumes will
eventually have a CVE. Authenticating link-local messages with a key the
untrusted peer holds authenticates nothing at all. It would make this document
look safer and change no property.

So the acceptance is explicit, and so are its edges. A hostile comms processor is
assumed throughout; here is exactly what this range lets it do and what it does
not:

1. **No link-local message carries a site action, and the one indirect lever is
   `TimeOffer`.** None of them starts a generator, moves a setpoint, writes
   configuration or enrols a client. But time is an input to `schedule`,
   `exercise` and `quiet_hours`, so moving the clock moves every scheduled run
   with it. That is why the step is capped below rather than merely bounded and
   logged, and why a clock change never replays a schedule.
2. **A connection is not a session.** `ClientConnected` creates a row in a table
   and attempts to mint a challenge (L-070). Turning that into a session still requires a `Hello`
   that only the holders of an enrolled client's private key and the
   controller's can complete — neither of which the comms processor holds, and
   neither of which is ever sent. A comms processor that invents eight
   connections has filled the connection table and nothing else. It could already deny
   connectivity by simply not forwarding; it is the radio.
3. **A time offer is floored, capped, rate-limited and logged.** The first set
   after boot cannot go below the timestamp of the newest log record the
   controller holds; once the clock is known an accepted offer moves it by at
   most 5 seconds, and anything larger has to arrive as a signed client
   `Time 0x0A`. The source is recorded in the record either way, so a hostile NTP
   path shows up in the log instead of silently rewriting history.
4. **The credential push is one-way and gains it nothing.** There is no read-back
   message. The most a comms processor achieves by reporting a stale version is
   to be handed the credentials it already had.
5. **L-021** — Power authority runs one way only. The controller MAY cut the
   ESP32's rail; the comms processor MUST NOT be able to reset the
   controller, and the board MUST NOT carry a line in that direction. A wedged or
   hostile comms processor must never be able to reset the thing holding the
   keys.
6. **Backpressure is a lever, and it is not the same as dropping frames.** RTS/CTS
   is mandatory at this rate (P-033), so the comms processor decides how fast the
   controller may transmit. Refusing everything looks like a dead link and the
   ladder below already answers it. *Draining slowly* is the interesting setting:
   the link stays nominally up, heartbeats still cross, and the eight per-session
   outbound queues fill anyway — at which point P-098 closes any session that
   cannot take a class A event. Those queues hold `seq` references and render the
   frame on the way out, never encoded frames waiting in RAM, so eight full ones
   cost a few KiB rather than tens of a 144 KiB part: what fills is a list of
   numbers, and the depth is a knob rather than a memory decision. Filling one is
   still a bound being reached and not a part running out — the event is in the
   log either way, which is what the reconnecting client reads it back from.
   Eight sessions closed and every client sent back to reconnect and catch up by
   `ReadLog`, repeatably, with no byte forged and no frame dropped. The outcome
   is the one P-098 was written for, so it is accepted; what is not acceptable is
   leaving a state transition the untrusted peer can drive at will uncounted.

   **L-022** — The controller MUST count the sessions it sheds under
   backpressure, per hour, and on the third inside an hour it MUST enter the
   ladder below at its first rung: every connection and session dropped, comms
   link lost (`0x0801`) logged, control unaffected. If it keeps happening the
   ladder does the rest. Calling that record *link lost* is the honest name for
   it: from the controller's side the link stopped carrying traffic, and which
   pin it stopped on is a detail for whoever reads the log.

   **L-023** — The first session shed for backpressure inside an hour MUST be
   logged as class A **sessions shed for backpressure** (`0x0804`), allocated in
   [REGISTRY.md](REGISTRY.md), and not as `0x0801`. `0x0801` is the escalation,
   not the first occurrence. A controller that logged only the escalation would
   leave a comms processor that answers every heartbeat and drains slowly with no
   trace at all until the third shed, and the first two are the ones that would
   have explained it. It is class A for the same reason the record it describes
   must survive the pressure that produced it.

**L-024** — If this link ever leaves the board, every link-local message MUST be
authenticated under a link key held in the controller's storage and provisioned
at manufacture. A two-box product, or an RS-485 run to a remote radio, voids every
sentence above: L-020 holds only because the two chips are one board in a sealed
enclosure, and a remote radio is the same protocol wearing a different threat
model. Written here so that change is a decision somebody makes rather than a
property somebody loses — it arrives as a mechanical decision, and nobody
re-reads this file for one.

---

## LinkUp

The ESP32 and the STM32 do not update together. A fielded unit will meet a newer
peer — after a comms OTA, after a board swap, after somebody flashes one of them
on the bench — and the version each side is running has to be a fact on the wire,
not an assumption.

```text
LinkUp  0x60  ·  LinkUp  0xE0
  1: protocol_major   u8
  2: protocol_minor   u8
  3: role             u8      1 controller · 2 comms
  4: fw               text    ≤ 32 bytes, the sender's own firmware version (L-034)
  5: boot_id          u32     redrawn randomly on every boot
  6: hw               text    ≤ 32 bytes, board name and revision (L-034)
  7: net_version      u32     *optional*, comms only: the version of the last
                              `NetConfig` it stored, a clear included; 0 if it
                              has no written master (L-132)
  8: device_id        bstr16  controller only: the `device_id` of `Discover`
                              key 3 (L-035)
```

Request and response carry the same fields, except field 7, which only the comms
processor sends, and field 8, which only the controller sends. This is a mutual statement, not a query — whoever comes up first
says who it is, and the answer says who the other one is.

**L-030** — Both sides MUST send `LinkUp` at boot, and either side MAY send it
again at any time. Repeating it is harmless: what tears everything down is a
*changed* `boot_id` (L-041, L-042), not
the arrival of the message. Read the other way round, a diagnostic resend costs
every client a reconnect. A controller with no `device_id` sends none (L-115).

**L-031** — The controller MUST store field 4 of the last successful `LinkUp`
and MUST report it as `fw_comms` in the client `Hello` response. That is the
whole supply chain for a field the client protocol has been promising with
nothing behind it.

**L-032** — A client MAY display `fw_comms`, MUST NOT read it as confirmation
that a comms image is installed, and no authorisation on either side MAY rest on
it.
It is the untrusted chip's own account of what it is running, so it is diagnostic
in exactly the sense `peer` is. The answer to *whose bytes are those* comes from
the comms processor's own secure boot, and nothing on this link carries that
measurement.

**L-033** — A side is linked once its own `LinkUp` has been answered: the
answer carries the peer's statement, and answering proves the peer holds this
side's. A `LinkUp` from the peer is answered with this side's statement and
recorded, and a side that is not linked sends its own at once; the peer's
`LinkUp` does not link the side that receives it. A `LinkUp` whose `boot_id`
differs from the one this side last saw unlinks it before anything else, because
the new boot has answered nothing of this side's: the side sends its own at
once and is linked again only when the new boot answers. Until linked, the comms
processor MUST NOT forward a client frame and the controller MUST NOT accept
one; a client frame arriving before that MUST be answered with code 258. A comms
processor that starts routing before it knows the controller's protocol version
is a comms processor that will forward a v2 body to a v1 controller and blame
the client. A controller with no `device_id` neither sends nor answers a
`LinkUp` (L-115).

A statement received is not a link. A peer that can talk but cannot hear sends
its `LinkUp` for ever and answers nothing, and a side that counted the statement
as the link would route to a peer that never hears the reply. Only an answer
proves both directions, which is also the property the heartbeat ladder below
is measured on.

**L-034** — `fw` in `LinkUp`, and `version` in `CommsRelease` and
`CommsReleaseAck`, MUST be a semantic version whose build metadata names the
commit it was built from: `MAJOR.MINOR.PATCH[-PRE]+gXXXXXXXX`, with the first
eight lowercase hex digits of the commit id after the `g`. Each of `MAJOR`,
`MINOR` and `PATCH` MUST be at most three decimal digits, and `PRE`, without
its hyphen, at most eight bytes. `hw` MUST be the board name and revision as
origin89hq/hardware writes them, such as `controller-a rev B`. The controller
MUST send the same `fw` text as `fw_controller` in the client `Hello`. A
receiver MUST NOT refuse a `LinkUp` whose text has another shape.

Without a format, two firmwares that never met could disagree: one sending
`0.1.0`, the other `0.1.0+g1a2b3c4d`. A client comparing them learns nothing,
and a bench log cannot match a running unit to a commit. The commit id is what
does that matching, and eight digits of it is what fits. A semantic version
alone has no ceiling, so the limits are what make the field hold every legal
text: three-digit components, an eight-byte pre-release and the commit come to
30 bytes, under the 32 the field allows. A full 40-character hash or a build
date does not fit, which is why the format names neither. The receiver half
exists because these texts are diagnostic (L-032): a link taken down over a
version string is an outage caused by a label.

**L-035** — The controller MUST send field 8 in every `LinkUp`, carrying the
same 16 bytes `Discover 0x80` key 3 carries, and the comms processor MUST NOT
send it. A receiver MUST refuse a controller `LinkUp` without field 8, and a
comms `LinkUp` with one, as it refuses any body missing a required key. The
comms processor MUST use it only as the TXT `id` of PROTOCOL.md P-224, taken
from the latest controller `LinkUp` it accepted.

The comms processor advertises the controller on the site network and has no
other way to learn which controller it is: the only other place the bytes
travel is inside a relayed `Discover` answer, and a relay that reads the bodies
it carries is one step from rewriting them. The `device_id` is not a secret
(P-038), so it comes over the link the way the hostname already does, from the
controller. Required rather than optional, because a comms processor that
linked without it would advertise a service no client can pick out, and nothing
would say why.

The same requirement is what keeps a controller with no `device_id` off the
link. It has one only once it is provisioned at manufacture, so a unit fresh
off the bench has none, and neither does one that could not read its
provisioning at boot. Such a controller cannot state itself, and L-115 says
what it does instead.

### boot_id is what makes a reboot visible

**L-040** — Each side MUST redraw `boot_id` randomly on every boot. Both rules
below rest on the value changing, and a `boot_id` derived from a serial number,
or a counter that starts at 1 in RAM, is the same number after the reboot it
exists to make visible. Neither rule would ever fire.

A `boot_id` different from the one last seen means the peer restarted, which is
what L-041 and L-042 act on.

**L-041** — On a `LinkUp` whose comms `boot_id` differs from the one last seen,
the controller MUST immediately drop every connection that comms processor
announced and every session bound to them. They went with the reboot. Without
this, eight connections evaporate in a reboot the controller never noticed, eight
rows sit in the table until their 15-minute expiry, and the next client to
connect is told the table is full.

**L-042** — On a `LinkUp` whose controller `boot_id` differs from the one last
seen, the comms processor MUST close every live client connection. The clients'
session keys went with the controller's RAM (P-230), so their next requests
would fail one at a time with increasingly confusing errors. A closed
socket is the honest signal, and every client already handles one.

### Version mismatch does not take the link down

**L-050** — On a link protocol major mismatch the controller MUST accept only
`LinkUp`, `Heartbeat` and a `CommsReleaseAck` `0xE7` answering a release it sent
itself; the comms processor MUST accept only `LinkUp`, `Heartbeat` and
`CommsRelease`; everything else MUST be refused with code 261; a `CommsRelease`
*request* arriving at the controller MUST be refused with code 256 exactly as it
always is; and client frames MUST NOT be forwarded in either direction. A major
mismatch means link-local traffic only, and it does not relax the direction rule:
a version mismatch is not a reason to let the untrusted peer authorise firmware.

Refusing the link outright would be tidier and wrong: the way out of a version
mismatch is to push firmware, and pushing firmware needs the link. A mismatched
pair that cannot be updated is a drive.

**L-051** — On a minor version mismatch both sides MUST proceed at the lower of
the two minor versions, exactly as with a client.

---

## Connections

### Who allocates what

**L-060** — The comms processor MUST allocate every connection handle itself,
from an incrementing counter in the range 1 to 0xFFFF, skipping handles currently
in use, and MUST NOT ever allocate 0. It is the thing that accepts and drops
transports, so it is the thing that knows when one exists. Every client transport
— BLE, local Wi-Fi, cloud, USB — terminates on it, so there is exactly one
allocator and the question of two allocators colliding does not arise.

Never 0, because session 0 already means *the link itself, not a client* and a
handle of 0 would collide with every link-local frame — P-021 leans on handles
never being 0 to tell a comms-processor bug from an honest client that has no
session yet. Skipping handles in use is what stops the counter, on its way round,
from handing a live connection's number to a new transport and delivering
somebody else's responses to it.

**The controller allocates the session** — not the number, the right to use it.
The `session_id` in the client `Hello` response is the handle the controller was
given, echoed back. One number on the wire, and one row that has two independent
states:

| | | Rule |
|---|---|---|
| Handle range | 1 – 0xFFFF. Never 0 | L-060 |
| Allocation | An incrementing counter, skipping handles in use | L-060 |
| Reuse | Only after the controller has acknowledged the release | L-080 |
| Connection rows | **8**. Allocated on `ClientConnected`, freed on `ClientDisconnected` | L-062 |
| Row states | **allocated** — a transport exists · **bound** — a session is running on it | L-062 |
| When full | `ClientConnected` answers `refused_table_full`, transport closed | L-061 |

**L-061** — When all eight connection rows are allocated the controller MUST
answer `ClientConnected` with `refused_table_full`, and the comms processor MUST
then close that transport with a reason a client can show. The close is half the
requirement: a transport left open with no row behind it is a browser waiting on
an answer nobody is going to send, and the person holding it has nothing to read
but a spinner.

**Allocated is not bound, and the connection table is not the session table.** A
row is allocated the moment a transport exists, before any client has proved
anything — that is what holds the connection's challenge and what a `Discover`
is answered on. It becomes bound when a `Hello` on it succeeds, and the binding
is the session: a separate table with its own cap, `MAX_SESSIONS` in
[PROTOCOL.md](../PROTOCOL.md), and its own refusal. `Goodbye` clears the binding
and leaves the row allocated to a transport that is still open.
`ClientDisconnected` frees the row and any binding on it.

Two words rather than one, because the difference between them settles three
questions that are otherwise each a separate bug: what `conns` counts in a
heartbeat, when a handle may be reused, and whether one polite browser costs the
other seven clients a reconnect.

`MAX_SESSIONS` is also 8, so a connection that exists here can always be bound
and error 8 never fires over this link — a nine-client site is refused earlier,
at `ClientConnected`, with code 260. Error 8 is not dead: it refuses a *session*
where 260 refuses a *connection*, and it is what a transport the comms processor
does not own would use. See open item 1.

Two numbers for one connection would mean a mapping table on both sides, and the
first time they disagreed the symptom would be a response delivered to the wrong
client. The comms processor has to route responses back to a transport anyway.
Making the transport's own identifier the session number deletes the mapping and
the class of bug that comes with it.

**L-062** — The controller MUST answer a frame carrying a connection handle it
was never told about with code 259, and MUST drop the frame. That is what a
controller reboot looks like from the client's side, and it is the signal to
reconnect. Answering with silence instead turns a reboot into a socket that hangs
until it dies on its own, which is the one bug report nobody can act on.

### ClientConnected

```text
ClientConnected  0x62
  1: conn         u16     the handle
  2: transport    u8      1 ble · 2 wifi_local · 3 cloud · 4 usb
  3: peer         text    ≤ 64 bytes — a BLE address, an IP, a cloud account.
                          Diagnostic only

ClientConnectedAck  0xE2
  1: outcome      u8      1 accepted · 2 refused_table_full
                          · 3 refused_handle_in_use · 4 refused_link_not_up
```

**L-070** — On answering `ClientConnected` with `accepted` the controller MUST
attempt to mint a fresh challenge for that connection and hold it against the
handle if successful. If it cannot mint one, it MUST still accept the connection
when the connection admission checks pass, retaining the allocated row with no
challenge. It MUST NOT substitute a placeholder or another connection's
challenge, or refuse the connection as though its table were full.

A `Discover` on that handle is answered with the connection's *current*
challenge. If none was minted at connect, or the one held has expired at 120
seconds or has already been consumed, the controller attempts to mint another
under P-060. If it still cannot supply a valid challenge, it answers error 18
`challenge unavailable`. The row remains allocated so a later `Discover` can
retry on the same transport. At most one challenge exists per connection at any
moment, and the `Hello` that consumes it binds its session to it through the
prologue (P-227).

Accepting the connection records where the client can be answered; it does not
promise that challenge generation succeeded. Requiring a challenge before
`accepted` would prevent a client from reaching `Discover` to receive P-060's
refusal when the first attempt fails.

Re-minting is what lets a client that has sent `Goodbye` open a second session on
the same transport, and what lets a client that has just paired go on to `Hello`
without dropping its socket: either one re-reads `Discover`, gets a live
challenge, and proves against that. Without it the row is allocated, the socket
is open, and every `Hello` on it is answered with error 14 — a browser that
closed one screen and opened another would have to reconnect to be let back in,
for no reason anybody could give the person watching it.

**L-071** — `ClientConnectedAck` MUST NOT carry the challenge. It is not secret
— it goes out in a `Discover`
response in the clear — so the reason is not confidentiality; it is that the
second copy would sit on the chip this document assumes is hostile. A comms
processor holding a cached challenge serves it after a controller reboot, and the
client goes off to build a handshake that cannot succeed and learns why only
from error 14.

**L-072** — `peer` and `transport` are both assertions from the untrusted peer.
Nothing MAY decide on `peer`, and no authorisation on either side MAY rest on
`transport`; `transport` MAY be logged and shown. An IP
address reported by the chip we do not trust is not an identity, and a comms
processor that wants a message permitted writes `transport = 4`, so any rule
keyed on that field is a rule it lifts for free. The moment a behaviour reads
either one, the untrusted chip is making the decision.

### ClientDisconnected

```text
ClientDisconnected  0x63
  1: conn         u16
  2: reason       u8      1 closed_by_client · 2 transport_error
                          · 3 idle_timeout · 4 closed_by_comms

ClientDisconnectedAck  0xE3
  1: outcome      u8      1 released · 2 unknown_handle
```

**This is what frees the connection row — and the session bound to it — in the
second it becomes free.** Sessions expire after 15 minutes without traffic, and
expiry is a backstop, not a mechanism. Without this message, a browser that
reloads eight times in a quarter of an hour has consumed all eight rows, and the
ninth attempt — from anybody, including the person standing at the panel — is
refused for fourteen minutes. Nothing about that is visible from either end: the
table is full of connections that closed.

**L-080** — The comms processor MUST NOT reuse a handle until the controller has
answered its `ClientDisconnected` with `ClientDisconnectedAck`. A comms processor
that recycled a handle the moment the socket closed would hand a brand-new
connection the previous one's challenge, and — if that row was still bound — the
previous client's session. Waiting for one small message is the whole fix.

### CloseConnection

```text
CloseConnection  0x64
  1: conn         u16     0 means every connection
  2: reason       u8      1 session_expired · 2 shedding
                          · 3 authentication_failures · 4 resync

CloseConnectionAck  0xE4
  1: outcome      u8      1 closed · 2 unknown_handle
  2: closed       u8      how many were actually closed
```

The controller needs a way to say *this one is finished*. A session that expires
at 15 minutes otherwise leaves a socket the client believes is healthy, and the
client discovers otherwise one failed request at a time. Closing the transport is
unambiguous and frees the row on both sides at the same moment.

It is also how the controller sheds a client that keeps failing authentication,
without the comms processor needing to know what a tag is.

**L-090** — The comms processor MUST treat `CloseConnection` with `conn = 0` as
every connection, and MUST report in the ack's `closed` how many it actually
closed. `conn = 0` is what the heartbeat resync below sends, and the count is the
only way the controller learns whether the table it believed in matched the
transports that really existed. A resync that closed nothing and said nothing
leaves behind exactly the leak it was sent to heal, and six seconds later it is
sent again.

---

## Heartbeat

```text
Heartbeat  0x61  ·  Heartbeat  0xE1
  1: uptime_s     u32     since this side's boot, saturating
  2: conns        u8      allocated connection rows this side believes are live,
                          bound or not
```

**L-100** — Each side MUST send a `Heartbeat` every 2 seconds and MUST answer the
peer's immediately rather than on its own next tick. A link is alive while the
peer answers: 6 seconds since the peer last answered any request of this
side's, three heartbeat periods, MUST be treated as a dead link. The timer is
the whole of the condition, and any answer restarts it, a heartbeat's or
another request's. It runs only on a linked side: a side that has not been
answered since it booted is unlinked, which is already the state a dead link
leads to (L-110, L-120), and the controller counts its sixty seconds to a cut
from the rail's last coming up until the first answer arrives (L-111), except
while L-113 or L-115 suspends it. The peer's own heartbeats do not count toward
it: a heartbeat received proves the peer can talk, not that it can hear, and a
peer whose receiver has hung keeps talking. Only an answer proves both directions.

Every rung of the ladder below is measured from that one number, so the 2 seconds
is not a comfort setting. Answering immediately rather than folding the answer
into the next scheduled beat is what keeps a healthy link off the first rung: a
side that batches its reply can be a full period late through nothing but
scheduling, and two of those in a row look exactly like a comms processor that
has stopped answering.

**`conns` catches the leak nothing else would.** A `ClientDisconnected` lost to a
CRC failure leaks a row, and a leaked row is invisible: the controller thinks a
connection exists, the comms processor knows it does not, and nobody compares.
Two counts in a message that was going to be sent anyway make the disagreement
loud in six seconds.

**L-101** — `conns` MUST count allocated connection rows, bound or not, and MUST
NOT count bound sessions. That is the whole reason the two words exist. The comms
processor has no idea which connections carry a session — it does not see `Hello`
succeed. Counting sessions on the controller's side would make every connection
look like a leak for as long as it sits between `ClientConnected` and its first
`Hello`, and would make one client's `Goodbye` read as a leak forever after. Six
seconds later the resync below fires and all eight clients reconnect because one
of them was polite.

**L-102** — When the two counts differ for three consecutive heartbeats the
comms processor's count MUST be taken as the correct one, the controller MUST
send `CloseConnection(conn = 0, reason = resync)`, and the comms processor MUST
re-announce every live connection. It owns the transports, so it is the one that
is right. That costs the clients a reconnect and buys a leak that heals itself
without a drive. Three consecutive rather than one, because a heartbeat that
crosses a `ClientConnected` in flight shows a difference that is not a leak, and
healing that would cost eight clients a reconnect for a message that arrived a
moment later.

### When the controller stops hearing the comms processor

| Since the comms processor last answered | What the controller does |
|---|---|
| 6 s | Link down. Drop every connection and session, log comms link lost (`0x0801`). Control is unaffected (L-110) |
| 60 s | Cut the ESP32 power rail for 5 s, restore it, log comms power cycled (`0x0802`) with the count (L-111) |
| 3 power cycles inside an hour | Stop cycling for 15 minutes with the rail **off**, or **on** on a board that cannot switch it back on after that long; raise comms unrecoverable (`0x0803`) (L-112) |
| A comms firmware install is in flight | The ladder is suspended until the install finishes or its window lapses (L-113) |
| The controller keeps the link down on purpose | No rail cuts and no comms unrecoverable (`0x0803`) while it does (L-115) |

**L-110** — Six seconds after the comms processor last answered one of the
controller's requests the controller MUST treat the link as down, drop every connection and every session
bound to one, and log comms link lost (`0x0801`). **Control MUST be unaffected.**

That second sentence is the one to write the test around. It is the
week-with-no-client acceptance test running for real, and deleting it means a
site four hours from a road stops running its generator because a browser went
away.

**L-111** — Sixty seconds after the comms processor last answered one of the
controller's requests, or after the rail last came up if it has not answered
since, the controller MUST cut the ESP32 power rail for 5 seconds, restore it, and log comms power cycled (`0x0802`)
carrying the count. A wedged Wi-Fi stack has no other recovery. The count is in
the record because the rung below is counted on it, and a power cycle nobody
counts is a boot loop nobody can name afterwards from the log. L-113 and L-115
name the times it does not.

**L-112** — After 3 power cycles inside an hour the controller MUST stop
cycling the rail for 15 minutes, MUST raise comms unrecoverable (`0x0803`), and
MUST leave the rail off for those 15 minutes, unless its board cannot switch the
rail back on after that long. Such a board MUST leave the rail on and uncycled
for the 15 minutes instead. The `0x0803` record MUST say which of the two the
controller did. A comms processor in a boot loop draws power continuously on the
weakest bank in February and delivers nothing, and hammering a load switch every
minute is how somebody finds out about its thermal limit in a place nobody can
reach.

The exception is a property of the board, written in the board's own document,
never a firmware preference. It exists because one board has it: on controller
board A revision A, switching `V3V3_ESP` on after minutes off corrupts the
STM32's control flow within milliseconds, every time it has been tried, while
switch-ons seconds apart pass by the hundreds (origin89hq/hardware#5). Off for
15 minutes is the one pattern that board cannot survive, and a controller that
crashes itself to rest the radio has broken L-110 to keep L-112. Leaving the
rail on costs the power a boot loop draws; it keeps control running, and it
stops the cycling that was wearing the switch. A board whose switch passes
long off-times, as revision B's slew-limited switch is built to
(origin89hq/hardware#48), takes the rail-off branch. Which branch a unit took
is in the record, so a log never has to be read against a guess about which
board it came from. That field lands with the `0x0803` body, which
[DEFERRED.md](DEFERRED.md) entry 10 still owns.

**L-113** — While a comms firmware install is in flight the controller MUST
suspend the ladder, and MUST resume it only when the install finishes or its
10-minute window lapses. A 60-second timer that power-cycles the board mid-write
turns an update into a brick.

**L-115** — While the controller keeps the link down on purpose, because it
had no `device_id` at boot or because L-195's revisions are spent, L-111 and
L-112 MUST NOT apply: it MUST NOT cut the rail on their account and MUST NOT
raise comms unrecoverable (`0x0803`). Either condition holds until the
controller reboots. A controller with no `device_id` MUST NOT send `LinkUp` and
MUST NOT answer the comms processor's, whatever L-030 and L-033 ask, and stays
unlinked for the boot. The download window is unaffected: `EnterDownload` does
not depend on `LinkUp`, and the reset L-192 asks for is that rule's own, not a
rung of the ladder.

The answer is withheld too because an answer to `LinkUp` is a statement, and a
controller statement without field 8 is refused (L-035). The only way to send
one would be to fill field 8 with something that is not this controller's
`device_id`, which the comms processor would then advertise. The ladder exists
to recover a comms processor that has stopped answering. Here the comms
processor has done nothing wrong; the controller is the side declining to link.
Applied as written, L-111 would cut the rail every minute from boot and L-112
would raise `0x0803` after the third cut, a power cycle loop and an alarm on a
unit whose only fault is missing provisioning, which cycling the module cannot
supply. The same holds after L-195's revisions run out. A controller that had a
`device_id` at boot and has not reached L-195's limit is not keeping the link
down on purpose, and the ladder applies to it in full.

**L-114** — The rail's declared fail state MUST be on, so that a controller
reset is not also a comms reset. Every time the rail goes off, it is because
running firmware decided so and logged it (L-111, L-112), never as a side effect
of the controller restarting.

The cost of the other choice is counted in rail cycles. With a fail state of
off, the rail is off whenever the STM32 is not driving it on, and that includes
every reset: on controller board A revision A, `PC5` is high-impedance through
reset and `R19` holds `Q2` off. Each controller reset then reboots the ESP32,
costs a Wi-Fi association, and is a rail switch-on of the kind
origin89hq/hardware#5 is open on. A crash loop at the 8-second watchdog is 450
of those an hour, against the three deliberate ones L-112 allows. A fail state
of on removes all of them, and removes a separate inrush event at cold boot as
well (origin89hq/hardware#48, its rule A-23). Revision B is built this way.

The rule used to rest on reachability: a controller that comes up with its
radio off is one nobody can reach to ask why. That reason does not hold on its
own. L-120 and L-121 make a comms processor that has lost its controller close
every client and answer nothing, so a powered radio with no controller behind it
cannot be asked anything. What it does buy is that the box still shows up on
the access point. That is a real benefit, and a minor one.

One case argues the other way. After a brown-out on a weak bank, the module's
first Wi-Fi burst comes before the controller's policy runs, and that burst
could pull the bank back under. It lasts under a second, and it is being
measured on the revision A rework (origin89hq/hardware#48, item 9). If that
measurement shows the burst tipping a recovering bank back into brown-out, the
fail state is the thing to revisit.

### When the comms processor stops hearing the controller

**L-120** — Six seconds after the controller last answered one of the comms
processor's requests, and from its boot until the controller first answers,
the comms processor MUST close every client connection, stop advertising over BLE, refuse
new connections, and retry `LinkUp` every 2 seconds until the controller answers.

Refusing and un-advertising is what makes the outage visible at the phone instead
of at the end of a timeout: a client that can still associate with a comms
processor holding nothing gets a socket that opens and then never answers. The
retry is what makes the recovery automatic — the controller coming back is the
only event either side is waiting for, and nobody is there to press anything.

**L-121** — A comms processor that has lost the controller MUST NOT serve a
cached snapshot, MUST NOT answer a `Discover` from memory, and MUST NOT hold a
client connection open while it waits. "The app shows the last known values with
no way to tell they are stale" is the failure that made the comms processor a
pipe in the first place, and a controller that is down is exactly when that
failure would matter most.

And it does not reset the controller. There is no line.

---

## Wi-Fi credentials

**L-130** — The controller MUST hold the master copy of the Wi-Fi credentials,
and the comms processor MUST hold a cache of them in its own NVS.
Both halves of that are load-bearing.

The cache exists because the two chips boot independently and their boots are not
ordered. A comms processor that had to wait for the UART and a `LinkUp` before it
could associate turns a slow controller boot into a site with no connectivity, and
it puts the passphrase on the internal link on every power cycle rather than once.

The master copy is on the controller because **the ESP32 is the part that gets
replaced.** It has the radio, the antenna connector and the CVEs. If the
credentials lived only there, swapping the board means somebody drives out with a
laptop and a serial cable. With the master copy on the controller a replacement
board reports `net_version = 0`, gets pushed the current credentials within a
second of link-up, and associates — no re-pairing, no provisioning step, no
second place to factory-reset.

The master copy is the `0x0020 network` config section, whose body
[PROTOCOL.md](../PROTOCOL.md) defines under *Section bodies*. Each field below
is the section's field of the same name, key 2 is that section's `version`, and
the section's bounds are these, so a network a client wrote and the controller
accepted is never one this link refuses for its shape.

```text
NetConfig  0x65
  1: op           u8      1 set · 2 clear
  2: version      u32     the controller's config version for this section
  3: ssid         text    ≤ 32 bytes, omitted when op = clear
  4: psk          text    8–63 bytes, omitted when op = clear
  5: country      text    exactly 2 bytes, ISO 3166-1 alpha-2; omitted for unwritten clear
  6: hostname     text    ≤ 32 bytes; omitted for unwritten clear

NetConfigAck  0xE5
  1: outcome      u8      1 stored · 2 rejected_invalid · 3 nvs_write_failed
  2: version      u32     the version of what it now holds, a clear included;
                          0 for an unwritten master or a stored unwritten clear
```

**L-131** — A `NetConfig` with `op = clear` MUST omit both `psk` and `ssid`, and
a `psk` sent with `op = set` MUST be 8 to 63 bytes. A `clear` that still carried
the passphrase would put it on the internal link one more time to accomplish its
own deletion. It omits the `ssid` for a duller reason: the controller sending a
clear may hold no network to name — a board out of another unit reaching a
controller nobody has provisioned gets a clear, and there is no SSID anywhere in
that exchange. An empty string in field 3 would be a value meaning *no network*,
which is the kind of default this project does not permit. Eight to sixty-three is the range a WPA passphrase can take, so
anything outside it is a credential no radio can use — refused here with
`rejected_invalid` rather than at association, where the only symptom is a board
that never comes on the air.

**L-132** — `NetConfigAck` and `LinkUp.net_version` MUST report the version
persisted in NVS, including a stored clear. A successful unwritten clear MUST
persist the absence of the network section and report 0, even if the module
previously held another unit's network. A successful ordinary clear MUST store
and report its nonzero version. An empty NVS also reports 0. Zero describes the
current unwritten master state, not the module's provisioning history.

Reporting the version actually stored lets the controller retry a failed write.
Reporting 0 after an ordinary clear would instead repeat that clear forever:
the controller holds version *n* and the cache reports 0.

**L-133** — The controller MUST push `NetConfig` after every `LinkUp` whose
`net_version` does not equal its own version, and MUST NOT withhold the push
because the version reported is higher. The rule is *different*, not *newer*. A
fresh board reports 0 and gets provisioned. A board that came out of another unit
reports some larger number and gets overwritten anyway, because those credentials
belong to somebody else's site and a version comparison is not a claim about who
is right. Comparing for newer is what turns a board swap into a drive.

When the versions differ and the master section has never been written or is
unreadable (P-108), the controller MUST send `op = clear`, `version = 0`, with
keys 3 through 6 omitted. This unwritten
clear MUST erase cached credentials, country, and hostname, stop Wi-Fi station
association and any Wi-Fi access point, and keep Wi-Fi transmission disabled
until a subsequent valid nonzero `NetConfig` supplies radio metadata. It MUST
NOT reuse the foreign cache's country or invent one. BLE and USB remain
available under their existing authorization rules. Applying the clear again
MUST be safe. `stored` MUST be sent only after erasure is durable; subsequent
`LinkUp` reports 0, ending the version mismatch.

A receiver MUST reject a version-zero `set`, an unwritten clear carrying any
of keys 3 through 6, or a nonzero clear missing country or hostname with
`rejected_invalid`, without changing its cache or radio state. Unknown extension
keys retain the ordinary unknown-key behavior. Zero is reserved for the unwritten
clear; ordinary sets and factory clears use the written section's nonzero version.

**L-134** — A nonzero-version `NetConfig` MUST carry `country` as exactly two bytes of ISO 3166-1
alpha-2. It is on the wire rather than in a firmware build because a radio in the wrong
regulatory domain is an illegal transmitter, and the domain is a property of
where the box is installed, not of the image somebody flashed — built into
firmware, a board that is legal in one country is contraband in the next and
nobody finds out from the device.

**L-135** — On a factory reset of a written network section, the controller
MUST send `NetConfig` with `op = clear` at the incremented, nonzero section
version, retaining the section's country and hostname, so a passphrase does not
survive on a board that is about to be pulled and
shipped somewhere. The controller is the only side that knows a reset happened,
so if it does not say so the credential stays where nobody will think to look for
it. If the master section is unwritten, the controller MUST instead send the
unwritten clear defined by L-133 without creating a network section.

**L-136** — The comms processor MUST cache at most one network, and a `NetConfig`
with `op = set` MUST replace what it holds rather than adding to it. This is a
value, not a table. A cabin has one AP; a list is a roaming feature and a place
for a stale credential to keep a board off the air, and the answer to "the AP is
dead" is BLE or USB, which need no AP at all.

**L-137** — A comms processor whose NVS write fails MUST answer
`nvs_write_failed` and MUST keep running on the credentials it was given in RAM,
and the controller MUST push again at the next `LinkUp` and log the failure. A
board with worn-out NVS otherwise associates fine until its next reboot and then
goes dark for no visible reason. Staying on the air with the RAM copy keeps the
site reachable now; the ack and the log entry are what tell somebody the flash is
finished, before the trip rather than after it.

For an unwritten clear, an erase failure MUST still clear the RAM copy and stop
Wi-Fi transmission. It MUST NOT resume the foreign network. The acknowledgement
MUST be `nvs_write_failed` with the previously persisted version, and `LinkUp`
MUST continue to report that version until erasure succeeds. The controller
retries the unwritten clear at the next `LinkUp`. After a reboot, the existing
cached-boot rules apply until the controller resends the clear; an unsuccessful
erase cannot promise durable removal.

---

## Wi-Fi scan and join state

`NetConfigAck` says the credentials were stored, and nothing on this link said
what the radio did with them or what it could hear. The client protocol's
`WifiScan` and `WifiStatus` ([PROTOCOL.md](../PROTOCOL.md) P-216 to P-221) are
answered from what these three messages carry. `Ap` is PROTOCOL.md's row, key
for key, so the controller relays a list without translating it.

```text
WifiScan  0x6A
  1: scan         u32     non-zero; numbered by the controller from 1 in each boot

WifiScanAck  0xEA
  1: outcome      u8      1 started · 2 refused_busy · 3 refused_radio_off

WifiScanResult  0x6B
  1: scan         u32     the WifiScan this answers
  2: outcome      u8      1 complete · 2 failed
  3: aps          [ Ap ]  present exactly when outcome = complete;
                          0 to MAX_SCAN_APS rows, strongest first
  4: unlisted     u16     present exactly when outcome = complete; saturating

WifiScanResultAck  0xEB
  1: scan         u32     echoes the result's

WifiState  0x6C
  1: version      u32     the NetConfig version the radio is acting on
  2: state        u8      wifi_state: 1 off · 2 joining · 3 joined · 4 failed
  3: reason       u8      present exactly when state = failed; wifi_failure:
                          1 auth_failed · 2 not_found · 3 no_ip · 4 lost · 5 other
  4: ipv4         bstr4   present exactly when state = joined

WifiStateAck  0xEC
  (an empty map)
```

**L-200** — The controller MUST have at most one `WifiScan` outstanding, and
MUST number them from 1 within each boot, never 0. The comms processor MUST
answer `started` and scan, or `refused_busy` while a scan it started has no
acknowledged or given-up result, or `refused_radio_off` while it holds no radio
metadata. It MUST NOT scan in that last state, passively included: L-133 keeps
Wi-Fi transmission off until a `NetConfig` supplies a country, and a scan on no
regulatory domain is the illegal transmitter L-134 exists to prevent.

The number is what ties a result to its request. `req_id` ends with the
acknowledgement (L-013), and the result arrives seconds later as the comms
processor's own request, so without it a late result from a scan the controller
gave up on would be read as the answer to the next.

**L-201** — For each `WifiScan` answered `started`, the comms processor MUST
send exactly one `WifiScanResult` carrying its number, retried under L-015. A
`complete` result MUST carry keys 3 and 4 and a `failed` one neither, and a
receiver MUST refuse one that breaks this under L-010. `failed` is a radio that
could not scan. A scan that heard nothing is `complete` with no rows, and the
difference is whether a person should try again or move the unit.

**L-202** — The list MUST hold one row per SSID, for the strongest access point
heard with it, ordered strongest first, at most `MAX_SCAN_APS`. An access point
with an empty SSID, or one whose SSID is not UTF-8, MUST NOT be listed.
`unlisted` MUST count the access points heard and left out for those reasons
or for want of room, and MUST NOT count those merged into a row for their SSID.

One row per SSID because a network is chosen by name: the section holds one
(L-136), and the radio picks the access point when it joins. A mesh with six
nodes would otherwise spend six rows on one choice and push the neighbour's
network off the list. A hidden network has no name to pick, and the person types
it, which is the fallback anyway. A name that is not UTF-8 cannot be written
into the section, whose `ssid` is text, and a lossy conversion would list a
name that matches no network on the air. Counting them keeps *the radio heard
three networks you cannot pick* different from *the radio heard nothing*.

**L-203** — The controller MUST treat a scan as failed when its `WifiScanAck`
is not `started`, when the request is given up under L-015, when no result
arrives within `SCAN_TIMEOUT_MS` (15 000 ms) of the `started`, and when the link
goes down or the comms `boot_id` changes first. It MUST acknowledge and discard
a result carrying any other number.

An active scan of the thirteen 2.4 GHz channels takes under two seconds on
the ESP32-C6, and channels a country allows only passively take longer. Fifteen
seconds covers both with room, and without a timeout a comms processor that
answered `started` and never finished would leave every client reading
`running` for as long as the link stays up.

**L-204** — The comms processor MUST send `WifiState` once its own `LinkUp` has
been answered (L-033) and again whenever what it would report changes. `off`
means it holds no network or no radio metadata and is not trying. `joining`
means it is trying and the credentials installed in RAM have had no outcome
since they were installed. `joined` means it is associated and holds an IPv4
address. `failed` means it is not joined, `reason` is the most recent failure,
and it is still trying; once the installed credentials have had an outcome, a
dropped association, a failed retry or a restarted radio session is `failed`
and never `joining` again.

`joining` is a state the comms processor passes through once per installation.
Credentials are installed at boot and whenever an accepted `NetConfig` puts a
different version in RAM, lower as well as higher: L-133 pushes whatever
differs, so a resynchronised controller can send a version below the one the
radio holds, or one it already held earlier in the same boot. Every change of
installed version starts again at no outcome. The outcome belongs to the
installed credentials alone, so the comms processor keeps no history of
earlier versions and one returning to a number it has seen is `joining` like
any other. A `NetConfig` that leaves the version unchanged does not reinstall.

A radio that retries every few seconds and reported `joining` between
failures would put a report on the link each time, and P-220's records would
count retries rather than changes. A retry that fails the same way changes
nothing and is not reported.

**L-205** — `version` MUST be the version of the credentials the radio is
using. After an NVS write fails (L-137) that is the version it was given, not
the one it persisted; after an unwritten clear, or from an empty NVS, it is 0.
The question a client asks is whether the radio is acting on its write, and the
radio acts on what is in RAM.

**L-206** — The comms processor MUST NOT have more than one `WifiState`
outstanding. A change while one is outstanding replaces whatever is waiting to
be sent, retries of the outstanding one carry its own body (L-015), and the
newest state goes once that one is answered or given up. Two outstanding would
let a retry of the older arrive after the newer, and the controller would hold
a state the radio has already left. One at a time makes the order on the cable
the order of the states.

**L-207** — The controller MUST NOT act on a `WifiScanResult` or a `WifiState`
beyond holding, answering and recording it. In particular it MUST NOT push
`NetConfig` because of a reported state: L-133 decides a push on `LinkUp`'s
`net_version` alone. A comms processor that reported `failed` for ever would
otherwise have the controller put the passphrase on the link at its own pace,
and the report is the untrusted chip's account of itself, diagnostic in exactly
the sense `fw_comms` is (L-032).

---

## Time offers

The clock is settable by a client and by NTP through the comms processor, and the
source is recorded in the record either way.

```text
TimeOffer  0x66
  1: unix_ms      u64
  2: source       u8      1 ntp
  3: accuracy_ms  u32     the comms processor's own estimate
  4: server       text    ≤ 64 bytes, diagnostic

TimeOfferAck  0xE6
  1: outcome      u8      1 accepted · 2 refused_implausible
                          · 4 refused_step_too_large · 5 refused_rate_limited
                          — 3 is withdrawn and the number stays held
```

**It is an offer, the controller decides, and what it decides is different before
and after the clock is known.**

**L-140** — The controller MUST refuse the first set after boot with
`refused_implausible` unless `unix_ms` falls between the **monotonic floor** —
the timestamp of the newest log record it holds — and ten years after that floor.
An NTP server that answers 1970 — or an unauthenticated NTP path somebody else
owns — would otherwise set the clock to 1970 and make every record written
afterwards sort before every record written before it. Ordering survives through
`seq`; readable time does not, and readable time is what somebody has to reason
with in April about an engine that ran in February.

**The floor is that record and not the firmware build timestamp**, and the unit
that makes the difference is one whose RTC backup cell has died. That is an
ordinary, silent failure at −25 °C: the part still runs, it simply comes up with
nothing in it. On that unit the clock is unknown at *every* boot, so the 5-second
cap below never applies to the offer that matters — and brown-outs are guaranteed
on a weak bank in February, while the comms processor's offer arrives within a
second of LinkUp. It beats any authenticated client `Time` to the first set
systematically, not occasionally. With a build timestamp as the floor, the
untrusted component picks a moment inside a ten-year window every time the power
blinks, on a unit nobody knows is faulty.

The newest log record is a better floor on every count. It is in NOR, it survives
the boot, and it is correct **by construction**: the controller was demonstrably
running when it wrote that record, so no honest clock can be earlier. A build
timestamp is a fact about a compiler and gets weaker every day the firmware runs
— a unit two years in the field is defending a window that opened two years ago.
P-114 in [PROTOCOL.md](../PROTOCOL.md) holds a signed client `Time 0x0A` to the
same **monotonic floor**: one floor, both doors, so a client cannot be talked into
what an offer was refused. The two rules are written in two files and they are the
same rule; grep the phrase and you should find both.

**L-141** — The controller MUST NOT apply the floor to an offer that moves an
already-known clock inside the 5-second cap, including one that moves it
backwards. The floor binds the first set on both doors and the correction on
neither: a clock running a few seconds fast has to be walked back — that is what
drift correction *is* — and a floor applied to the correction would leave a
controller unable to make the one correction it is allowed to make, refusing
every honest offer until real time caught up with the record it wrote while it
was fast.

A signed client `Time 0x0A` meets the floor on every set, not only the first:
it carries no 5-second cap, so there is no correction-sized set to exempt. When
it is refused for the floor the answer is `TimeAck` outcome 4 `needs_button`,
because P-116 lets a person at the panel override the floor and a client has to
be able to say so. This paragraph used to claim a client `Time 0x0A` was
"alarmed by P-115 rather than floored", which is the opposite of what P-114
says — two documents describing different rules for the same door is a floor
with a way round it, which is the failure the sentence above about one floor and
both doors exists to prevent.

What the floor refuses is the **jump** — the one set that has no cap on it,
which is also the one set the comms processor systematically wins.

**L-142** — A controller that holds no log record carrying a timestamp MUST use
the firmware build timestamp as the floor, and MUST NOT use it as the floor in
any other case. A unit out of the box, or one whose ring was written entirely
before any clock was ever set — P-093 omits `at` in that window — has no log
record to take a floor from. That is the virgin RTC the build timestamp was
always right for, and it is the only case it is right for.

**L-143** — A boot at which the RTC reports its backup domain invalid MUST be
recorded in the class A boot record (`0x0601`). A dead backup cell should be an observation
somebody can read, not something inferred months later from a controller that
keeps asking what time it is. It is key 2 of the boot body, defined under
`Event 0x04` in [PROTOCOL.md](../PROTOCOL.md).

**L-150** — Once the clock is known the controller MUST refuse an offer that
would move it by more than 5 seconds, in either direction, with
`refused_step_too_large`. The correction has to arrive as a signed client
`Time 0x0A` instead.

Five seconds is drift; an hour is a different Tuesday. The first-set window above
is ten years wide, so it reaches every day of the week and every time of day —
and time is an input to `schedule`, `exercise` and `quiet_hours`. Without this cap
the comms processor chooses when the generator exercises, having authorised
nothing, forged no tag and touched no setpoint. It is the one lever in this range
that reaches the site, and this is where it stops.

**L-151** — The controller MUST accept at most one offer per 15 minutes,
measured on P-004's monotonic tick, and MUST refuse and count every offer
arriving inside that window with `refused_rate_limited`.

The bound is a security one, not a politeness one: 5 seconds every 15 minutes is
eight minutes a day, which is drift correction, whereas 5 seconds every second is
the same ten-year walk taken in steps small enough that each one passes. The tick
is what makes it a bound at all rather than a number the walk moves along with the
clock — the argument is under L-011 above. Rate-limiting the *client* transports
is still an open question — see [DEFERRED.md](DEFERRED.md) — and this bound does
not wait on it.

**L-152** — The controller MUST NOT emit `TimeOfferAck` outcome 3.
3 `refused_have_better` is
withdrawn because no rule produces it and no sound rule can.

It was allocated for an offer less accurate than whatever set the clock last, and
the only accuracy figure anywhere on this link is `accuracy_ms`, which the comms
processor writes about itself. That is the same provenance as `peer` and
`transport`, and it gets the same answer: a refusal keyed on a field the untrusted
peer fills in is a refusal it lifts by writing a smaller number, and it would lift
it in the one direction that matters — always winning, never being refused. The
controller holds no accuracy estimate of its own to compare against,
and the other door onto the clock, a signed client `Time 0x0A`, carries no
accuracy at all. There is not even a second opinion to be had.

An outcome a receiver may see and no rule can send is worse than a gap, because
two implementers will invent a rule for it and they will invent different ones —
and the one that guesses *refuse an offer no better than the last* ships a
controller that stops accepting time and never says why. So the number stays in
the table unemitted rather than being handed to whoever allocates next, exactly as
[REGISTRY.md](REGISTRY.md) holds its four withdrawn error codes. `accuracy_ms`
stays in the offer alongside `server`: worth reading in a log, and deciding
nothing.

**L-160** — The controller MUST record any accepted clock change of more than
5 seconds, whatever moved it, in the `time set` event (`0x0604`), carrying the
old value alongside the new one and the source that set it. With the cap above,
that is the first set after boot and every signed client `Time 0x0A` — which is
exactly the set of clock changes big enough to move a schedule. A schedule that
fired twice on a Tuesday is otherwise unexplainable in April, and one record for
one clock change is easier to read than two.

**L-161** — A behaviour whose decision actuates MUST NOT treat time the
controller never had as time that has passed, and a clock change MUST NOT cause a
run the new clock says was missed. A controller that boots with no clock, learns
that it is a Tuesday in April, and finds that a weekly exercise run has "missed"
ten years of Tuesdays fires none of them — not ten years of them, and not one.
The next run is the next one that comes round on the new clock. Without this the
cap above is worth nothing: a step the controller accepted as plausible would
start a generator at an unattended site, and the record would say a schedule did
it.

**L-162** — The link-local `source` value MUST NOT be copied into the `0x0604`
record; the record MUST name the clock as having been set by an offer through the
comms processor, distinctly from a client `Time` operation. `source` here is a
link-local space with one value in it and is not the time-source space the
record uses. What the record has to answer is which door the clock came
through, because that is what tells a drifted RTC from a lying uplink — copying a
number across from a space that means something else makes two spaces look like
one to whoever reads the log.

---

## Comms firmware release

**The controller authorises. The comms processor's own secure boot verifies.**
Two checks, and the second one is not the first one repeated.

```text
CommsRelease  0x67
  1: op           u8      1 authorise · 2 activate · 3 revoke
                          · 4 confirm_healthy
  2: version      text    ≤ 32 bytes (L-034)
  3: image_len    u32
  4: digest       bytes(32)   SHA-256 over the whole image

CommsReleaseAck  0xE7
  1: outcome      u8      1 authorised · 2 installed · 3 activated
                          · 4 refused_digest_mismatch · 5 refused_signature
                          · 6 refused_no_space · 7 rolled_back
  2: version      text    what it will boot next (L-034)
  3: bytes_have   u32     resume point after an interruption
```

1. A client sends a signed `Firmware` with `target = comms`. **That message's
   body is not specified yet** — [REGISTRY.md](REGISTRY.md) marks `0x09`/`0x89`
   reserved and [DEFERRED.md](DEFERRED.md) still owns the field list, `target`
   included. Everything below this step is settled; the step that starts it is
   not, and a reader should not have to discover that by grepping for a field
   name. The controller opens the sealed request and applies policy.

   **L-169** — Policy MUST NOT permit an arbitrary downgrade.
   Rollback-to-known-good is step 6 below — an image that never confirms healthy
   is put back by the ESP32 on its own, with no client, no wire and no drive — so
   the four-hour distance is already answered by the inactive partition and does
   not need an OTA that reinstalls an older, still validly signed image. Anti-
   rollback for the comms image is [DEFERRED.md](DEFERRED.md) entry 6's, and
   permitting the downgrade here would have quietly settled it the wrong way in
   the one document nobody re-reads when that entry lands.
2. **L-170** — The controller MUST send `authorise` carrying the version, the
   image length and the digest, and MUST record the authorised digest in FRAM.
   FRAM rather than RAM because the controller can reboot in the middle of an
   install — a brown-out on a weak bank in February is the ordinary case, not the
   exotic one — and an authorisation that lived only in RAM comes back empty. The
   comms processor is then holding bytes nothing authorised, and the only way out
   is a drive.
3. The image arrives — chunked over this link, or downloaded by the comms
   processor from the release URL, whichever the transport makes cheaper. Which
   one is used does not matter, because the digest decides.
4. **L-171** — The comms processor MUST hash the image it received, MUST answer
   `refused_digest_mismatch` and install nothing when that hash does not equal the
   authorised digest, and MUST refuse with code 264 an image that matches no
   authorisation at all. The digest is what decides, which is the whole reason
   step 3 does not care how the bytes arrived. Without the hash the controller has
   authorised a version *string*, and a version string is whatever the untrusted
   chip says it downloaded.
5. **L-172** — The comms processor MUST write the image to the inactive
   partition, and its own secure boot MUST verify the image signature before
   executing it. Authorisation says *which bytes*; secure boot says *whose*.
6. **L-173** — `activate` MUST reboot the comms processor onto the new image,
   the slot MUST be marked good only on `confirm_healthy` sent after the link
   comes back on the new version, and without that confirmation the comms
   processor's own rollback MUST put the old image back. The thing that proves a
   new image healthy is the new image talking. An image that boots and never
   speaks is the one case nobody can answer from a laptop, and rollback answers it
   with no client, no wire and nobody driving out.

**L-174** — The controller MUST hold at most one authorised release at a time, a
new `authorise` MUST replace the previous one with both logged, and an
authorisation MUST lapse when its 10-minute install window expires. Two live
digests is a question about which
one the arriving bytes were meant to match, and nobody wants to be answering it
during an update. The window is there because L-113 suspends the ladder while an
install is in flight: a suspension with no end is a wedged comms processor that
never gets power-cycled because it said it was updating.

### Why the second verifier is not redundant

The controller cannot verify an ESP32 image signature, and should not be able to:
a controller holding the comms signing key is a controller whose compromise is
also a comms compromise. It authorises a **digest**, which is a statement about
*which bytes*, not about *whose bytes*.

The two checks answer different questions and fail at different times:

- **Authorisation answers "is this the release the owner asked for."** It binds
  the update to an authenticated client command and to policy the controller
  holds. It says nothing about whether those bytes are genuine firmware.
- **Secure boot answers "is this signed by whoever may write firmware for this
  chip."** It runs on the chip, with no link and no peer, so it still works when
  the controller is the thing that is wrong — a corrupted FRAM, a service tool
  that once had the button, a pair of clips on the UART.
- **Authorisation happens once. Secure boot happens on every boot, forever.** An
  image that was authorised and then damaged — a flipped bit in flash, a partial
  write from a brown-out mid-install at −25 °C — is still the authorised image by
  digest at the moment it was written and is not genuine firmware by the time it
  runs. Only the check that runs at every boot catches that.

Delete L-172 and the failure is not "an attacker gets in". It is a comms board
executing garbage after a power cut, and no drive short enough to fix it.

---

## Pairing reachability

A cached network can be unreachable from the phone at the panel. The provisioning
access point therefore runs while no network is cached **or** while the controller
reports an open pairing window, provided valid radio metadata is available.
The unwritten-clear Wi-Fi shutdown rule (L-133) takes precedence, including
across reboot after successful erasure; a pairing report supplies no regulatory
country. This message changes reachability only: P-066's
physical act and the controller's handshake checks still decide whether enrolment is
allowed. It carries no credentials and cannot open the controller's window.

```text
PairingWindow  0x69
  1: revision       u64     increases for each new report, from 1
  2: remaining_ms   u32     0 closed; 1..120000 remaining duration

PairingWindowAck  0xE9
  1: revision       u64     echoes the request, including an ignored old revision
```

**L-193** — A `PairingWindow` body MUST carry a non-zero `revision` and
`remaining_ms` in 0..120000; its acknowledgement MUST carry a non-zero revision.
Missing, duplicate or out-of-range fields are malformed under L-010. Zero duration
means closed, not unknown; no message received means unknown and grants no
pairing-based access-point lifetime.

**L-194** — The comms processor MUST act on `PairingWindow` only from the
controller UART, with session zero, after its own `LinkUp` has been validly
answered under L-033. It MUST NOT act on bytes in a relayed client stream,
including a nested or text representation of this message. L-002's code 257
still answers a link-local opcode on a client transport. A request received
before linking is discarded without acknowledgement or access-point changes.

**L-195** — The controller MUST send its current window state after linking,
on the physical opening, and on every closure, including successful enrolment
or reclaim and expiry. For successful enrolment or reclaim it MUST queue
the client response before the closed report. It MUST compute `remaining_ms` from
its monotonic deadline when first sending, never from the original duration after
a delay. Each new report, including a resynchronisation of unchanged state, has a
strictly increasing revision within the controller boot; retries
retain the same revision and body. Revisions MUST NOT wrap: at exhaustion the
controller takes the link down, keeps it down without running the ladder
(L-115), and only a controller reboot permits another opening. A closed state
supersedes pending open retries; an unsent expired opening is replaced by the
closed state.

**L-196** — The comms processor MUST retain only the greatest accepted revision
and one local monotonic deadline. On a newer open revision it sets that deadline
to the first receipt time plus `remaining_ms`, using checked arithmetic and
refusing an unrepresentable deadline. A duplicate or older revision is acknowledged
but MUST NOT change the deadline or reopen a closed window. A newer closed state,
local deadline expiry, link loss, or either processor reboot MUST clear the
pairing-based access-point lifetime. A repeated `LinkUp` for the same boot MUST
NOT clear revision history; a changed controller boot clears it. A controller
resynchronising after link loss MUST issue a fresh revision. An acknowledgement
confirms processing, not successful enrolment or that an access point is usable.

The clocks are not synchronised: the local deadline bounds radio availability
from receipt, so UART delivery delay can leave the access point up briefly after
the controller's deadline. It never extends enrolment, which the controller checks
on its own clock. An early close is applied on receipt; a lost close is bounded by
the local deadline and link-loss detection. No wall-clock time enters this rule.
When a closed report would take the access point down, the comms processor
MUST first transmit client responses already queued ahead of that report, allowing
at most 500 ms to drain them and accepting no new access-point connections during
that drain. This lets the phone receive the successful `Pair` response before its
transport disappears; it does not delay the controller closing enrolment.
After the drain, the access point stays up only if no network is cached and valid
radio metadata is available; cached credentials are neither cleared nor replaced by this message.
The firmware implements the radio and window lifecycle in
[firmware#11](https://github.com/origin89hq/firmware/issues/11).

---

## The download window

On controller board A revision A the module's `IO8` is unconnected, so the
ROM's strapping route into serial download does not work, and the one route
that does is the register one: firmware running on the module sets the ROM's
force-download flag and resets itself. That route exists only while firmware on
the module runs and still honours the request, so on that board the ability to
reprogram the module is a property of the image on it, and an image that
crashes before it listens, or one that drops the request, takes the last
programming path with it. The earlier bench image scanned the relayed client
stream for a text line, which is the failure this section exists against: a
pattern in that stream which reboots the module into download mode hands any
client able to reach the link a way to take the product off the air.

```text
EnterDownload  0x68
  1: reason     u8      1 bench · 2 recovery — diagnostic: the controller
                        records it with the request, and nothing either side
                        branches on it

EnterDownloadAck  0xE8
  1: outcome    u8      1 entering · 2 refused_outside_window
```

**L-190** — Before it forwards any client frame, the comms processor MUST
listen on the controller UART for `EnterDownload` for 1 500 ms from its own
start, the half-open interval from the start to the start plus 1 500 ms, and
MUST honour one arriving inside it: answer `entering`, set the ROM's
force-download flag, and reset into the ROM within 100 ms of the answer,
forwarding and answering nothing else meanwhile. One received at or after the
close is outside the window (L-191). The start, the moment it listens, MUST come
within 1 000 ms of its reset being released, the boot chain before it included,
ROM and bootloader and any image verification they do: the window then closes
at most 2 500 ms after the release, inside the controller's 3 000 ms of repeats
(L-192). Board A's bench measured 270 ms. The window runs before any code that
can crash for a reason of ours, which is what keeps an application in a crash
loop offering it on every cycle, and the 1.5 s it costs every boot is spent
while the link is coming up anyway.

**L-191** — Outside that window the comms processor MUST answer
`refused_outside_window` and MUST NOT set the flag; and whatever the window,
it MUST NOT act on an `EnterDownload` that arrived on a client transport.
L-002 already refuses the frame there with code 257; this says the action is
never taken, so that the refusal being lost to a bug in the routing does not
become a reboot. The refusal outside the window is an answer rather than
silence because L-015 gives an unanswered request up, and a controller that
asked too late must learn it asked too late, not that the module is gone.

**L-192** — The controller MUST send `EnterDownload` only after it has itself
reset the module, by cycling `EN` or the rail, MUST send the first within
200 ms of releasing `EN`, and MUST repeat it every 100 ms with the same
`req_id` until it is answered or 3 000 ms have passed. It MUST log the reason it
sent with the verdict, or with the absence of one: the module keeps nothing across
the reset it is asked for, so the controller's log is the only account of why a
module entered its ROM. L-015 does not apply to
`EnterDownload`: not its 500 ms, not its three attempts, and not its taking
the link down, because the window is measured from the module's start, which
the controller cannot see, and three attempts half a second apart could all
fall before the module's UART is up or all after the window closed; giving up
at 3 000 ms is this rule's, and it takes nothing down. Tying the
request to a reset the controller performed is what correlates the two clocks,
and it is also what makes the request unforgeable from the module's side: a
comms processor cannot be talked into the ROM by anything that did not first
hold its `EN` low.

Nothing here is cryptographic; the two frames are published in
[vectors/v1.json](vectors/v1.json) beside the other link frames, because the
two ends of this link are two codebases and the request that recovers one of
them is the last frame that may drift. Revision B restores the strapping route
with a pull-up on `IO8` (hardware#48), and there this message is defence in
depth; on revision A it carries the whole recovery story, and the acceptance
test is an image that crashes at once, delivered as an update, recovered
through the controller with no wire on the module.

---

## Error codes

Link-local codes start at **256** so that a client can tell *the link failed*
from *your request failed*. They travel in the shared `Error 0xFF`, which is why
they are numbered out of reach of the client codes rather than kept off the wire
by hoping.

**L-180** — Codes 257, 258 and 259 MUST reach the client whose frame raised
them; the other six MUST NOT appear in a client-facing frame. A client that sent
a link-local type, or connected before the comms processor was linked (L-033),
or is holding a handle the controller has never heard of, has to be told
something: a client answered with silence waits until its socket dies, and the
person holding the phone says *it just stops working*, which is the one bug
report nobody can act on. The other six describe the two firmwares to each other
and mean nothing to a browser, so one of them in a client-facing frame is wrong
on sight rather than merely unhelpful.

| Code | Meaning | Reaches a client? |
|---|---|---|
| 256 | Unknown link-local opcode, or one sent from the wrong side | no |
| 257 | Link-local type on a client transport | **yes** |
| 258 | Client frame before `LinkUp` completed | **yes** |
| 259 | Unknown connection handle | **yes** |
| 260 | Connection table full | no — the transport is closed with a reason instead |
| 261 | Link protocol major mismatch | no |
| 262 | Too many outstanding link-local requests | no |
| 263 | Link-local type with a non-zero session | no — it goes back to the controller, whose bug it is |
| 264 | No authorisation matches this image | no |

**L-181** — An error raised about a link-local frame MUST carry
`session_id = 0, req_id = 0` and MUST NOT be routed to a client. It stays on the
UART. There is no client behind it — the frame came from the other firmware, not
from a socket — so routing it anyway hands some arbitrary client a diagnostic
about a conversation it is not part of, with nothing to match it against.

**L-182** — An error raised about a client's frame MUST be routed to that
client, and MUST echo that frame's `session_id` and `req_id` when its envelope
parsed, carrying `0, 0` only when it did not. Both are routed: P-025 makes the
comms processor send a `0, 0` error back on the connection the bad frame arrived
on, and it can, because that connection is the one it just read the bytes from.

The echo is not a nicety, though. A client matches a response to a request by
`(session_id, req_id)` and has nothing else to match on, so an error stamped
`0, 0` about a request that parsed fine reaches the client as an unmatchable link
diagnostic (P-024) while the request it was meant to answer sits outstanding
until it times out. 259 is what a controller reboot looks like from the outside,
and it needs to arrive as an answer to the request that hit it, not as a puzzle
alongside one.

All three are unauthenticated, so the client protocol's rule holds unchanged: an
unauthenticated error is a hint, never a fact. All three mean *reconnect*.

---

## Capacities

Every one of these has a documented behaviour when it is reached, and none of
them evicts:

| Table | Capacity | When full |
|---|---|---|
| Connection rows | 8 | `ClientConnected` answers `refused_table_full`; the comms processor closes the transport with a reason (L-061) |
| Challenges held, one per connection row | 8 (`MAX_CHALLENGES`) | Error 18 `challenge unavailable` (P-060); nothing is evicted |
| Sessions bound onto those rows | 8 (`MAX_SESSIONS`) | Error 8. Unreachable while every transport terminates here, because a row exists before the `Hello` that would bind it |
| Accepted time offers | 1 per 15 minutes | `refused_rate_limited`, counted (L-151) |
| Sessions shed for backpressure | 3 per hour | The first one is recorded; the third means the link carries no traffic whatever the heartbeats say, and the ladder runs from its first rung (L-022, L-023) |
| Outstanding link-local requests, per side | 4 | The sender does not issue a fifth; a peer that does gets code 262 (L-014) |
| Cached Wi-Fi network | 1 | A `set` replaces — a value, not a table (L-136) |
| Wi-Fi scans outstanding | 1 | The controller does not send a second; the comms processor answers `refused_busy` (L-200) |
| Access points in a scan result | `MAX_SCAN_APS`, 16 | The strongest are listed, the rest counted in `unlisted` (L-202) |
| Wi-Fi state reports outstanding | 1 | A newer state replaces the one waiting to be sent (L-206) |
| Authorised comms release | 1 | A new `authorise` replaces the previous one; both are logged (L-174) |
| ESP32 power cycles | 3 per hour | No cycling for 15 minutes, rail off, or on where the board cannot switch it back on after that long; comms unrecoverable (`0x0803`) raised (L-112). Not counted while L-113 or L-115 suspends the ladder |

---

## Open items

1. **A direct service transport to the controller.** Today every client transport
   terminates on the comms processor, which is what makes one handle allocator
   correct. If a service port is ever fitted on the controller, it becomes its own
   comms processor for that port and must allocate handles from a range the comms
   processor never uses — decided then, not improvised at the bench.
2. **Whether `CommsRelease` should carry the release notes or a URL.** Chunking
   an image over a 921600 UART works and downloading it does not depend on the
   controller having seen the bytes. Both are supported above; which one the field
   actually uses is a bench question.
