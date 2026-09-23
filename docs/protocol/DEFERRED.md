---
title: Deferred protocol decisions
description: Questions KM43 deliberately leaves unanswered, with the evidence and trigger required to settle each one.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

# Deferred

<p class="o89-doc-kicker">KM43 / open decisions</p>

<p class="o89-doc-deck">Questions the protocol refuses to answer before evidence exists. Each one names what is missing, what would make the choice honest, and the event that forces a decision.</p>

<dl class="o89-doc-facts">
  <div>
    <dt>Open entries</dt>
    <dd>Twelve</dd>
  </div>
  <div>
    <dt>Normative</dt>
    <dd>No—these are explicit gaps</dd>
  </div>
  <div>
    <dt>Required shape</dt>
    <dd>Question, evidence, and trigger</dd>
  </div>
  <div>
    <dt>Decision rule</dt>
    <dd>Field evidence ends the deferral</dd>
  </div>
</dl>

<nav class="o89-doc-links" aria-label="Related KM43 documents">
  <a href="/km43/specification/">Settled requirements <span aria-hidden="true">→</span></a>
  <a href="/km43/rationale/">Design rationale <span aria-hidden="true">→</span></a>
  <a href="/km43/registry/">Allocated numbers <span aria-hidden="true">→</span></a>
</nav>

## How deferral works

Twelve things this corpus deliberately does not answer — ten of them questions
about the wire, entry 11 about how these documents get checked for the
questions nobody thought to ask, and entry 13 the equipment model the first ten
quietly assumed was flat. Entry 12 was answered and moved into P-022; its number
is not reused, so a reference to entry 13 still means the same thing. They live
here rather than inline because an open question sitting in a normative
document reads as a specification to somebody who skimmed to their section and
stopped. A paragraph saying "most
likely we retire the number" is indistinguishable, at implementation time, from a
paragraph saying "the number is retired" — and the person who implemented the
wrong one is four hours from a road when it matters.

Every entry states the question, why it is not being guessed, what has to be true
before anybody can answer it, and the **trigger** — an observable condition that
forces the answer whether or not somebody feels ready. An entry without a trigger
is not deferred, it is forgotten.

| | Question | Trigger |
|---|---|---|
| 1 | Channel identity across reassignment | First channel repointed at a deployed site, or the first site running a configuration that is not ours |
| 2 | Cloud confidentiality | First cloud client enrolled at a site we do not own |
| 3 | Aggregate record shape | Decidable a month after the first shadow deployment; **hard deadline: before the ring starts filling for a winter** |
| 4 | Rate limiting policy | Measurements the first time a browser talks to real hardware; before any off-site transport |
| 5 | Noise handshake | The first unit that leaves our hands |
| 6 | Firmware bodies and the signing manifest | **Manifest before the first unit ships with a locked bootloader** |
| 7 | BLE and MQTT conformance | The first byte over either link |
| 8 | Command argument schemas | The first output granted authority — it needs exactly one kind |
| 9 | Config section body schemas | The first configuration written over the API rather than flashed |
| 10 | Event body schemas per kind | The first event on the wire |
| 11 | Checks that test the specification rather than an implementation | Before the next audit round |
| 13 | Multi-device topology and complete equipment coverage | Before the `channels` or `buses and devices` config body becomes live, or the first repeated component is exposed over KM43 |

---

## 1. Channel identity across reassignment

**The question.** A channel is a `u16` from configuration, stable by contract.
Somebody moves the pump-house probe onto the tank sender's terminals and edits
the config to match. Channel 7 now means something different, and eight months of
logged history says nothing about the seam. A client plots one series that
changes meaning in the middle.

**Why it is not guessed.** The obvious answer — retire the number forever, like a
CBOR field number — is probably right and is not free. The snapshot is capped at
32 channels, so a site rewired three times over three winters runs out of channel
space with nothing actually wrong. The alternative, a generation counter making
identity `(channel, generation)`, widens every `Value` and every aggregate record
by two bytes for the life of the product, and aggregates are ~1,920 records a day.
Choosing between "you run out eventually" and "everything is two bytes fatter
forever" needs to know how often a channel is actually repointed, and the answer
today is a guess about our own habits at one site.

**What must be true first.** A real config-edit history — how many channels get
repointed in a season, and whether the repointing is *same quantity, new hardware*
(the probe died, here is its replacement) or *this slot is something else now*.
Those two want different answers and today they look identical. Entry 3 also has
to land first: whatever carries identity into history has to fit inside the
aggregate record.

**Trigger.** The first channel repointed at a deployed site, or the first site
that comes up running a configuration that is not ours — whichever is first.
Until then the interim rule is operator advice and not a wire rule: **do not
reuse a channel number, allocate a new one.** It costs nothing to follow now and
it does not bind the decision.

---

## 2. Cloud confidentiality

**The question.** TLS terminates on the comms processor and again at the relay,
so the cloud can read every reading it forwards. Should telemetry be encrypted
end to end between the controller and the phone, leaving the relay a blind pipe?

**Why it is not guessed.** Because "encrypt it, obviously" deletes the feature.
A relay that can read telemetry is a relay that can notice a bank at 30 % at
3 a.m. and wake a phone that is asleep with the app closed. Move the telemetry
behind a key the relay does not hold and notification generation moves to the
phone — which then has to be running and connected to notice anything, in exactly
the case where nobody is looking. Push notification already requires the cloud;
this decides whether it also requires the cloud to be trusted with readings.

Commands are MAC'd end to end either way. A compromised relay can never forge a
start, a setpoint change or a firmware acceptance, in any version of this. What
is at stake is only who may **read**, and that is a product question in a crypto
costume.

**What must be true first.** Somebody has to say what is being sold: an alerting
service, or a private one. That answer does not exist while every site is ours and
every alert goes to our own phone.

**Trigger.** The first `client_kind = 3` enrolment at a site we do not own.
Nothing before the first shadow deployment needs it — that deployment has no
cloud at all.

---

## 3. Aggregate record shape

**The question.** Downsampled history shares the NOR ring with events and is most
of what is written: 15-minute aggregates over 20 channels are ~1,920 records a day
against ~100 class A events. The size of one is what chose the flash part. The
fields in it are undecided.

**How much of the ring that is has two answers, and both are written here because
an earlier revision rounded them into one "about 96 %".** Aggregates are **95.0 %
of the records** — 1,920 of the 2,020 written a day — and **93.4 % of the bytes**
— 80,640 framed of 86,340, at the packed size this entry settles on below. The
two come apart because a class A record is 57 bytes framed against an aggregate's
42. A budget set against the record count and then checked against the byte count
is four points out before anybody has made a mistake, which is the same class of
error as comparing a payload figure to a framed one.

**Every byte figure in this entry is labelled *payload* or *framed*, and the two
are never compared.** That sounds like bookkeeping and it is the whole of the
arithmetic problem here. The ring's record is

```text
[ magic u16 | len u16 | seq u64 | class u8 | payload | crc32 ]
    2          2         8         1                     4     = 17 bytes
```

so **framed = payload + 17**, per record. An earlier controller budget priced an
aggregate at ~24 bytes *encoded + framing*, and an earlier revision of this entry
compared payload-only field costs against that number as though the two were the
same kind of thing. They are not, and the mistake is not small: **24 framed leaves 7 bytes
of payload**, which does not hold `channel` and `kind` — 4 bytes packed — let
alone a mean, a min, a max, a sample count and a window start. That line priced a
record nobody can build, and it is corrected there in the same round as here.

**Why it is not guessed.** This is the one record whose size multiplies by
700,000 a year. On the arithmetic below, **one byte added on a hunch costs about
four days of ring, permanently.** And the interesting part is not the field list,
it is what a window reports when 3 of its 92 samples were readable and the probe
was absent for the rest. A mean over three samples that looks identical to a mean
over ninety-two is a lie that renders as a smooth line — the same failure as a
room card showing 0.0 °C for a probe that is not there, one aggregation layer up.

**Why it is safe to defer at all.** The ring's record header already carries a
`class` byte. A later aggregate shape is a new class, not a migration: old
records stay readable, the boot scan already skips what it does not recognise,
and nothing has to be rewritten in place.

**What is already decided, because the arithmetic decided it: this record is not
CBOR.** A seven-field aggregate — channel, kind, mean, min, max, sample count,
window start — costs **39 bytes of payload** as a CBOR map with integer keys,
against **25 packed positionally**. Counted framed, one record per channel per
window, alongside a working budget of ~100 class-A records a day at ~40 bytes of
payload and therefore 57 framed:

```text
                        payload   framed   bytes/day   days of a 14.5 MB ring
CBOR map, integer keys      39       56      113,220          134
packed positional           25       42       86,340          176

bytes/day = 1,920 × framed + 100 × 57
14.5 MB   = 15,204,352 bytes
```

Everything is in bytes. These were KB/day figures before, and a rate in KB against
a ring in MB is two conversions where somebody eventually takes 1000 for one and
1024 for the other; nothing on this page is rounded to a KB.

**Packed still beats CBOR by roughly forty days, so the conclusion this entry
rests on survives.** Written in CBOR the ring hands somebody 134 days rather than
176, and the encoding argument below stands unchanged.

**What does not survive is the absolute figure. ~290 days does not close under
either encoding with the record shaped one-per-channel-per-window** — 176 days is
not a Quebec winter handed over in April, which is the sentence the 128 Mbit part
was bought to make true.

**The record shape is what has to absorb that, and absorbing it is what this entry
is for.** The corrected controller budget uses the same arithmetic and states the
target as a number: at 20 channels
and 15-minute windows, a 200-day ring needs the packed aggregate **under 20 bytes
of payload**, against the 25 the seven-field sketch costs. Two of the levers are
this entry's, and the rest — fewer channels in history, longer windows — are that
section's:

- **Fewer or narrower fields.** Twenty bytes of payload is roughly channel, kind,
  mean, count and one more thing. Min and max are the two to justify, and the
  honest question is whether anything ever reads them.
- **One record per window instead of one per channel.** The 17 bytes of framing
  are per *record*, not per aggregate, so a record carrying all 20 channels of one
  15-minute window pays them once: 96 × (17 + 20 × 25) = 49,632 bytes a day, plus
  class A, is 55,332 — **275 days**, without cutting a single field. It costs the
  ability to write one channel's window on its own, and it makes one CRC failure
  lose twenty aggregates instead of one. Both are real and neither has been
  weighed against a month of shadow, which is exactly why this is deferred rather
  than decided here.

Whichever is picked, that table moves with it. A capacity figure in one document
that the record shape in another cannot reach is two documents disagreeing — and
this is the pair that gets discovered by a ring that filled in six months, by
somebody who connected in April expecting a winter.

**A positional encoding is right here and wrong on the wire**, and the reason is
the same one that put CBOR on the wire in the first place. [SCALE][scale], the
codec Polkadot uses, is the reference worth reading: fixed-width little-endian
integers, compact varints for lengths, no field tags, and exactly one valid
encoding per value. Its documentation is blunt that it *"is not self-describing,
meaning the decoding context must fully know the encoded data types"* — Polkadot
supplies that context out of band, as runtime metadata clients fetch.

That is disqualifying on the wire, where a fielded controller meets a newer app
and neither can be updated first. It costs nothing on flash, where the conditions
are reversed: both ends are the same firmware, the `class` byte already versions
the record, and nobody debugs a NOR record by pasting it into a generic decoder.
Being canonical by construction is a bonus — the ring needs no equivalent of
P-016 and no P-017 disclaimer.

What is still open is the field list and the partial-window rule, not the
encoding family.

[scale]: https://docs.polkadot.com/reference/parachains/data-encoding/

**What must be true first.** A month of real sampling from site A: how often a
window is partial, whether min and max are ever read by anything or whether mean
plus count is the whole of it, and what the actual per-channel event rate is
against the assumed one-per-minute cap.

**Trigger.** Decidable once site A has a month of shadow behind it. **Hard
deadline: before the ring starts filling for a winter** — the ring that has to
hand somebody a Quebec winter in April is the one that started filling before the
cold did. Until it is decided, a site in shadow writes class A only and no
aggregates. Losing a month of 15-minute history is recoverable; a winter written
in a shape we then abandon is not.

---

## 4. Rate limiting policy

**The question.** What is a misbehaving client allowed to cost the controller,
and does the answer differ by transport?

**Why it is not guessed.** The comms processor is the cheap place to enforce a
limit — it already sees every frame — and it is the component this protocol
insists must not interpret anything. A limit enforced only there is a limit that
an attacker who owns that chip simply lifts. So the limit that matters has to
also exist at the controller, where the budget is thin and known: fanning events
out as N authenticated copies already costs 0.026 % of the UART and 0.014 % CPU
duty at 8 sessions. That is a calculation, not a measurement, and it covers the
cheap path. Nobody has measured the expensive ones.

The transports genuinely differ, which is why one number will not do. A BLE
client at BLE throughput cannot flood anything. A WebSocket client on the LAN can
ask for `ReadLog` from `oldest_seq` in a loop, and each answer is a NOR read plus
a page of up to `MAX_LOG_PAGE_BYTES` — 896 bytes, roughly 30 records — encoded
and MAC'd. `MAX_LOG_PAGE_ENTRIES` never binds: a `LogEntry` with a real `seq`
and a timestamp is 27 bytes before its body carries anything, so the byte arm
runs out first every time. A `Snapshot` at the 32-channel cap is the other
expensive one. Neither of those has a millisecond figure attached to it.

**What must be true first.** Three measured numbers on real hardware: what one
`ReadLog` page costs, what a full `Snapshot` costs, and what the UART actually
sustains with 8 sessions subscribed and events going out N times.

**Trigger.** The first time a browser talks to real hardware, those three
requests get timed and the numbers get written down. The policy follows the
numbers. **Hard deadline: before any transport reachable from off-site is
enabled.** Until then every client is somebody standing inside the building, and
the cost of a flood is that they have to stop and go home.

---

## 5. When to move to a Noise handshake

**The question.** When does the symmetric scheme get replaced by an
authenticated key agreement — X25519 with ChaCha20-Poly1305, Noise-style, which
is what Matter does for this exact problem under this exact constraint?

**Why it is not guessed.** The symmetric scheme is not a placeholder. It
transmits no key, so a comms processor that watches every pairing for the life of
the device learns nothing it can use. What it does not have is forward secrecy,
and it cannot survive a camera. A label photographed once yields every client key
that device will ever mint, permanently, and the label cannot be reprinted into a
unit already on a wall. That is a real limitation with a known price —
10–15 KB of flash against ~256 KB, tens of milliseconds per session on an M0+ —
and it is not urgent while every label is in our building.

**What must be true first.** This cannot be an edit. The handshake is final the
first time units are paired in cabins: their `client_key` and stored counters are
derived from those exact formulas, and changing a label or a field width
un-pairs them from four hours away. So the upgrade is a **second** handshake
offered alongside the first, chosen at `Discover`, with v1 supported for the
service life of every unit already fielded. Which means version negotiation has
to have been exercised in the field at least once before it is trusted to carry
something this load-bearing.

**Trigger.** The first unit that leaves our hands — a site we do not own, or a
unit shipped to somebody else. Not a date: the day a label we cannot reprint is
in a building we cannot walk into.

---

## 6. Firmware message bodies and the signing manifest

**The question.** Two questions with two different deadlines, which is the whole
reason this entry exists.

The **message bodies**: what a `Firmware` `begin` actually carries, what `commit`
presents, which target a transfer names, how a resumed transfer proves it is
resuming the same image. The shape in the draft is a sketch. `target` is on that
list for a reason — [LINK.md](LINK.md) already writes `target = comms` in prose
and builds the comms release flow on top of it, so the field somebody else is
depending on is a field with no definition. Everything downstream of that step in
LINK.md is settled; the message that starts it is not.

**On that list too, because nothing else can put it there: which client owns a
transfer in flight.** [REGISTRY.md](REGISTRY.md) allocates `Firmware` outcome 7
`not_owner` for a client feeding chunks into a transfer another client began, and
no document says how a transfer records who began it — so there is nothing for a
second client's `Firmware` to be compared against, and no rule anywhere produces
the outcome. One image lands at a time; two clients interleaving chunks into one
is how a half-and-half image gets written, passes every per-chunk check it is
given, and fails its signature after the reboot. That is a drive. The number is
allocated and unraisable until these bodies name the owner, and it is written
down here so that it is owed rather than assumed.

The **manifest**: what the bootloader verifies. Its layout, the signature
algorithm, where the public key lives, and what the manifest binds beyond the
image bytes — version, target, board revision, and the monotonic index the next
section settles.

**Why they are not guessed.** There is no OTA until a bootloader exists and an
image has been verified on a bench, and nothing on the path to the first shadow
deployment transfers firmware at all. Writing message bodies for a feature nobody
is building is how a spec acquires fields that no implementation ever exercises
and no vector ever covers.

**And why the deadline is not the feature's.** The bootloader holds the verifying
key and the verification code, and a bootloader cannot be replaced on a unit
already in a cabin — that is the entire point of it, and it is one of the four
things that must exist from unit #1 for exactly this reason. A unit shipped
with a bootloader that checks the wrong structure, or checks it against a key with
nowhere to rotate to, is a unit that must be physically retrieved to ever accept
an update again. So **the manifest layout, the signature algorithm and the key
location must be fixed before the first unit ships with a locked bootloader —
which is weeks earlier than the messages that use them, and months earlier than
OTA.** Getting that ordering backwards is how the deadline gets missed by a team
that thought it had until the feature.

**What is settled now, because A/B already bought it: anti-rollback is a
monotonic index, and OTA downgrade is not the rollback path.**

[LINK.md](LINK.md) permits an arbitrary downgrade on the grounds that the site is
four hours away and rollback-to-known-good has to stay possible. The premise is
right and the conclusion does not follow from it. **A/B with health confirmation
already provides rollback-to-known-good**: the inactive partition still holds the
image that was running an hour ago, an update that never confirms healthy is put
back by the bootloader on its own, and none of that involves a client, a wire, or
a decision somebody has to make correctly from a phone. That is the recovery the
four-hour drive argument is about, and it is already there without a wire rule.

What permitting arbitrary OTA downgrade adds on top is a *different* capability:
**reinstalling an old, still validly signed, known-vulnerable image, chosen
remotely by any of the eight enrolled clients.** The signature check cannot refuse
it — the image is genuine, that is the point — so a patch shipped for a disclosed
hole can be un-shipped from the internet by whichever client is compromised. There
is no failure that capability prevents which the inactive partition does not
already cover.

So:

- **The manifest carries a monotonic index — `u32`**, bumped whenever an image
  ships that must not be reverted past. It is a manifest field, which is why it
  lands with the manifest and not with the message bodies: it cannot be
  retrofitted into a bootloader already in a cabin.
- **The bootloader refuses an image whose index is below the highest ever
  confirmed healthy on that unit.** Confirmed healthy, not merely installed — an
  image that never confirmed is one the unit has already decided against, and
  raising the bar on it would strand a unit behind its own failed update.
- **Reverting to the inactive partition is always available and is not an OTA.**
  It transfers nothing, needs no client and is not gated by the index. That is
  what a bad update actually costs, and it costs no drive.
- **A downgrade below the index requires the physical button** — the same class
  of evidence that gates enrolment and factory reset, though a distinct gesture
  from either, as P-117 now requires of every use of that button. It is the same
  class of decision: re-opening a hole that was closed, on a unit somebody is
  standing at.

The comms image gets the same treatment, enforced where its signature is enforced
— by the ESP32's own secure boot at every boot, not by the controller's
authorisation step. **[LINK.md](LINK.md) step 1 of the comms release flow used
to say a downgrade was permitted and logged, and no longer does** — it now says
policy does not include one, and points here. That was the half of this entry
that could be paid immediately: the sentence cost nothing to strike, needed
nothing that does not already exist, and left the wire document quietly settling
this entry the wrong way in the place nobody re-reads.

What stays open here is narrow: **what earns a bump.** Every release is one
answer, a security fix is another, and the difference decides whether somebody who
skipped three releases can still be talked back one over the wire.

**What must be true first.** For the manifest: a decision on Ed25519 against
ECDSA P-256 costed in flash and verify-time on an M0+ with no accelerator;
whether the key sits in a write-protected flash page, in option bytes, or in OTP;
and **where the highest-confirmed-healthy index is stored**, since a value the
running image can lower is not an anti-rollback at all; and whether there is one
key or a key plus a rotation slot. Whether the manifest binds a board revision can
wait for there to be more than one board. For the message bodies: a bootloader
that exists and an image that has been verified once on a bench.

**Trigger.** Manifest, algorithm, key location and the monotonic index: **before
any unit is flashed with read-out protection enabled**, which comes with the first
unit that ships with a locked bootloader. The index is on that list rather than
with the message bodies because a bootloader that does not check one cannot be
taught to later. Message bodies and their vectors: before the first OTA is
attempted over any link — which is a long way off, because no unit has a
bootloader yet.

---

## 7. BLE and MQTT — interoperability unverified

BLE has an allocated service and characteristic contract, envelope byte format,
bounded fragmentation/reassembly and ordered transmit admission in PROTOCOL.md.
The `ble` traces in [`vectors/v1.json`](vectors/v1.json) exercise minimum and
negotiated MTUs, full payloads, malformed/missing/duplicate/out-of-order fragments,
changed IDs, wrap with blocked sends, timeout and disconnect cleanup against the
Rust and TypeScript transport APIs. This is host evidence, not a radio or native-client result.

Still required: the firmware and supported native phone implementations must run
the same traces, then demonstrate discovery/subscription, platform value limits,
FIFO queue order through wrap, bounded stack memory and send-stall cleanup,
concurrent upload/notifications, reconnect/callback isolation, BLE/Wi-Fi coexistence
and controller-loss shutdown on the board. Pair must fail outside/after the
STM32 physical window and with a wrong proof, including on a bonded connection.
Record supported phone OS versions, negotiated MTUs and implementation revisions
with that evidence. [km43#81](https://github.com/origin89hq/km43/issues/81) owns
protocol qualification; [firmware#96](https://github.com/origin89hq/firmware/issues/96)
owns stack integration and phone/board acceptance. Neither is complete on host
vectors alone.

MQTT remains specified, unimplemented and unverified: broker behavior, QoS 1
redelivery and whether topics need a session dimension still need evidence.

Conformance remains **UART, USB CDC and WebSocket**. Extend the BLE claim only
after shared-vector consumption and the supported phone/board evidence exist.
MQTT requires its own implementation and verification before a claim. Initial
native-app pairing depends on BLE qualification; Bluetooth connection or bonding
never replaces KM43 authorization.

---

## 8. Command argument schemas

**The question.** `Command` carries `kind: u16` and `args: map`.
[REGISTRY](REGISTRY.md#command-kinds--u16) has six numbers with names on them —
start generator, stop generator, run exercise cycle now, set output, clear alarm,
clear override. Not one of them says what its `args` map contains, or what it may
refuse and why.

**Why it is not guessed.** There is no actuation until a controller is granted
authority over an output, and the first grant is *one non-critical output*. Any
kind written today is written against a behaviour that has never left shadow
mode, and a command's argument schema is a promise about what a behaviour will
accept — which is precisely what a month of shadow exists to correct. The `inhibited` outcome makes this sharper: a kind whose rejection
reasons are unknown is a kind whose arguments are unknown, because half of what
an argument does is give the controller something to refuse.

**Why the numbers are allocated now regardless.** `kind` is a `u16` inside a
MAC'd operation. A number squatted by somebody's bench experiment is a number that
cannot be reclaimed once a client has shipped using it, and routing around a
squatted low number is a permanent ugly seam in a registry that will outlive all
of us. Allocating in REGISTRY is what stops that; it is the opposite of squatting,
and it is why the six rows are there and marked **reserved** — allocated, not
specified. So the settled part of this entry is a rule about *use*, not about
allocation: **no `kind` below `0x8000` may be sent by any client until the
behaviour it commands has an argument schema in the registry, and bench and
experimental code uses `0x8000`–`0xFFFF`, which is permanently non-normative,
never allocated in REGISTRY, and may never appear in a shipped client.** Bench
code gets a place to live that costs nothing to abandon, and the low numbers stay
under the one process that can keep them straight.

**What must be true first.** The behaviour being commanded has run a month in
shadow, and there is a list of things somebody actually wanted to do to it rather
than a list of things it could plausibly accept.

**Trigger.** The first output granted authority — it needs exactly one kind, and
that kind gets its argument schema then. The rest keep their numbers and gain
their schemas when a second output is granted, not before. Standing rule: **no
`kind` becomes sendable before the behaviour it commands has run a month in
shadow.**

---

## 9. Config section body schemas

**The question.** `GetConfig` answers with `3: body map` and `SetConfig` sends
one, and no section says what is in it. What integer key is the frost setpoint?
What unit is it in, and at what scale? What key is `shadow`, which P-103 says
every behaviour section must carry?

**Why it is not guessed.** The candidate parameters have names already —
`autostart_source (voltage | soc) · threshold · duration` — and names are the
easy half. P-011 wants an integer
key for each, P-018 wants a unit and a scale on every measurement that crosses
the wire, and `threshold` supplies neither: it is millivolts under one
`autostart_source` and tenths of a percent of charge under the other, and a
schema written today has to guess which one a generator behaviour that has never
left shadow mode will actually read. That is the same mistake entry 8 refuses to
make for command arguments, one message over. A setpoint written in the wrong
unit does not fail loudly — it starts an engine at the wrong voltage.

**Why the numbers are allocated anyway.** The section numbers are settled and
stay in [REGISTRY](REGISTRY.md#config-sections--u16): nothing squats on `0x0011`,
and a client asking for a section it may not read still gets a straight answer
about whether it exists. Only the contents are open, which is why every section
row is marked **reserved** rather than live.

**What is settled now, while the schemas are still open: a field marked `secret`
is never returned by `GetConfig`.**

`0x0020 network` holds the site's Wi-Fi passphrase. It holds it for a good reason
— the controller keeps the master copy because the ESP32 is the part that gets
replaced, and credentials living only on the radio board turn a board swap into a
drive with a laptop and a serial cable ([LINK.md](LINK.md)). What follows from
that and was never written down is the other half: `GetConfig` answers with a
section body, nothing marks a field unreadable, and so **all eight enrolled
clients can read the passphrase — the cloud client included.** That is the only
leak in this corpus that crosses the product boundary: a customer's Wi-Fi
passphrase, readable by our own relay, through a message written for reading
setpoints. `0x0021 cloud` is the same shape with a different credential inside it.

The rule: **a field marked `secret` in a section schema is never returned by
`GetConfig`. The response carries the field's presence and the section's
`version`, never its value.** *Set* or *not set* is what a person needs on a
screen, and the section's `version` already says when it last changed. `SetConfig`
still writes it — the field is write-only, not unwritable — and the passphrase
reaches the radio exactly as it did, pushed one way over `NetConfig` with no
read-back message. **The link already refuses to hand a passphrase back; it is
`GetConfig` that would hand it to anybody holding a session.**

**Presence is its own key, and never the value's key carrying a placeholder.** A
`psk` returned as `"********"` is a default that can be mistaken for a
measurement, and the thing that eventually happens to it is that a client reads
the section, edits one unrelated field, and writes the whole body back — setting
the site's passphrase to eight asterisks from four hours away.

The marking belongs to the schema, not to the client. A client deciding for itself
which fields are sensitive is a client the comms processor can talk out of it.

This is a different mechanism from the per-client capability mask in
[REGISTRY](REGISTRY.md#client-capability-mask--u16), and both are needed. The mask
stops a cloud client **writing** `0x0020` and `0x0021`; `secret` stops **every**
client reading a value out of them. A client that may legitimately edit the
network section still has no business reading the passphrase back, and no editing
flow needs it — nobody re-types a passphrase they have just been shown.

**It is written now because it becomes an observable behaviour change the moment
the schemas land.** A section body drafted without it produces a `GetConfig` that
returns a passphrase, and by the time anybody notices, a relay has been logging
them.

**What must be true first.** A behaviour has run in shadow long enough that the
parameters it reads have stopped moving, and somebody has wanted to change one
from a phone rather than from a build. Half of a config schema is what an
operator tried to adjust and could not; a schema written before anybody tried is
a list of everything the code happens to hold, which is a different list.

**Trigger.** The first configuration written over the API rather than flashed. A
controller configured by flashing a struct needs no wire schema at all — the
compiler is the schema. The first `SetConfig` that has to land on a controller
nobody is holding needs all of it, including the `shadow` key, because a shadow
flag a client cannot read is a shadow deployment nobody can confirm.

---

## 10. Event body schemas per kind

**The question.** Every `Event` carries `4: body map`, described as
kind-specific, and no kind specifies it. Twenty kinds, twenty blanks. Six
of them already have a sentence promising a field: `0x0701` records dropped
"carries the count", `0x0301` behaviour decision "carries whether the decision
was applied or shadowed", `0x0604` time set carries the old value, the new value
and the source, and `0x0802` comms power cycled "carries the cycle count". A
promise with no key number is a promise no implementer can keep, and all four are
load-bearing — the first turns a hole in `seq` into a number, the second is the
whole audit trail of shadow mode, the third is how somebody works out whether a
schedule fired twice, and the fourth is the one [LINK.md](LINK.md) leans on: the
ladder stops cycling after three in an hour, and without the count nobody reading
the log can tell the first cycle from the one that gave up.

**A fifth promise is made in [REGISTRY](REGISTRY.md#client-capability-mask--u16)
rather than in a normative document, and it lands here too.** `0x0603` `client
enrolled` has to carry the capability mask that was granted, and whether the row
was newly allocated or **reclaimed** from an identical label. *Somebody was
enrolled* and *somebody was enrolled, may push firmware, and took over the row
called `kitchen phone`* are different sentences, and only the second one is an
audit record.

**`0x0803` comms unrecoverable owes one more, and [LINK.md](LINK.md) L-112 is
where it is promised.** The third rung of the heartbeat ladder has two branches:
the rail left off for fifteen minutes, or left on and uncycled on a board that
cannot switch it back on after that long. The record has to say which, or a log
from a site reads the same whichever board wrote it, and *the rail was off for
fifteen minutes* is a claim about power draw somebody will act on.

**The sixth is `0x0501`, and it needs a discriminator before it needs anything
else.** Four requirements raise it and none of them is distinguishable from the
others in the record: P-079 when persisting a counter fails, P-085 when the epoch
write fails, P-115 when an accepted set moves the clock by more than an hour, and
P-116 when somebody at the panel overrides the monotonic floor. A kind with four
unrelated producers and no field saying which one fired is a record nobody can
read in April — *an alarm was raised* is not a sentence anybody can act on, and
the four want four different responses, one of which is a drive out to replace a
failing FRAM. So: a field naming the condition, first; then the signed size of
the step for P-115 and P-116, in the same units as the clock, because *the clock
was moved back eleven months, by a person at the panel* is the sentence P-116
exists to make findable; then the failed-write reason for P-079 and P-085.

***And `0x0501` stopped being the kind those four were written against, which is
what took this entry so long to answer.*** [TOPOLOGY-DESIGN.md](TOPOLOGY-DESIGN.md)
renamed it from `alarm raised` to **`concern raised`** and gave it a body: `rev`,
and the thirteen keys of a `Concern`. `protocol.toml` took the new name and
`PROTOCOL.md` did not — **four MUSTs went on saying `alarm raised` (`0x0501`)**
— and this paragraph went on saying the discriminator was owed by a kind that had
already been redefined. Three documents, three answers, about a number an
implementer is told to send. They agree now, and what follows is what they agree
on.

*The design's own note says this entry had to be edited in the same commit as the
redefinition, and it was not.* What that commit would have had to settle is not a
rename, and calling it one is how it stayed open:

- **A `Concern` is about a `dev` and a `cmp`.** A failed FRAM write is
  expressible — the controller is a device, and `cmp = 0` is the device as a
  whole — so the four producers *can* raise concerns. What they cannot do yet is
  say **which** condition: the registry allocates `over voltage` through
  `bay flapping` and nothing for a durable write that did not stick, a clock
  step, or a floor override at the panel.
- **P-115 and P-116 also need a magnitude, and the wire has nowhere to put one.**
  A `Concern` carries `raw` only with the `vns` that reads it, and
  `vendor_namespace` names third parties with no entry for this controller — the
  same gap the generator-selector season records, arriving from the other side.
  *The clock was moved back eleven months* is a number, and the body can carry it
  only under a namespace nobody has allocated.

**Decided, and the controller namespace is not needed after all.** All four
producers raise `concern raised`, `cond` is the discriminator, and the registry
allocates the four values they need — `counter write failed`, `epoch write
failed`, `clock stepped`, `floor overridden`. `PROTOCOL.md` names them in the
requirements themselves, so there is no kind an implementer can send under a name
the registry does not use.

*The magnitude is what made this look like a namespace question, and it is not
one.* A `Concern` has no numeric payload — `raw` is a `u32` holding *the source's
own code, preserved verbatim*, and a clock step is signed and in milliseconds, so
`raw` was never a slot it could occupy. It did not need to be: P-115 and P-116
both raise their concern **alongside the `time set` record P-111 requires**, and
that record already owes the old value and the new one on the row above. The step
is `new − old`, written once. Recording it on the concern as well would be one
number in two places, which is the thing that eventually disagrees.

So the controller-namespace trigger has **not** fired here. It fires the first
time something has to report a value of its own that no other record already
carries, and that is still ahead.

***Both bodies have landed, and this entry is down to eighteen kinds.***
`PROTOCOL.md` defines `ConcernRaised 0x0501` and `ConcernChanged 0x0502` under
the `Event 0x04` section, both are `live`, both have a codec beside the
`Concern` row `0x0501` carries, and `vectors/v1.json` publishes both. They went
first because the concern table is built and P-180 already said a row leaves it
only by an `0x0502` carrying state 5 — a rule about a record nobody could write.

*The raise carries the page's row and not a second shape of it,* which is the
decision worth recording: key 2 is the same `Concern`, the same thirteen keys,
the same encoder. Two shapes meaning nearly the same thing are two decoders to
keep in step, and the raise path is exercised more rarely than the page path by
exactly the margin that hides a bug until a pack goes out of balance in
February.

***All five bodies TOPOLOGY-DESIGN specifies have landed*** — `0x0102`,
`0x0501`, `0x0502`, `0x0901` and `0x0902` — so this entry is down to **fifteen**
kinds of its twenty. The three that followed the concern records did not wait for
P-182: what the coalescing decides is how many entries go in a tick, and what the
body decides is that there is an array to put them in.

***The boot record has landed, and this entry is down to fourteen.***
`Boot 0x0601` is defined under `Event 0x04` with P-214, has a codec and a vector,
and carries the reset reason, the backup-domain flag L-143 promises, and the
previous run's last words. It went next because the controller was already
writing it with an empty body: a record on a unit's ring that said *a boot
happened* and nothing about why, which is the evidence a bench session after a
night unplugged went looking for and could not find. The `boot reason` space
moved with it: the controller reports power-on, power-down and brown-out with
one flag, so `1` became `power` and `3 brown-out` is retired; pin reset,
option-byte reload, the window watchdog and low-power entry were added, because
the part tells them apart and a bank swap is not a power cut.

**The controller's first producers are settled under P-215.** `0x0604` carries
old (absent when unknown), new and time source; `0x0702` counts failed stored
records without trusting their contents; `0x0801` is an empty map; `0x0802`
counts cycles in the rolling hour; `0x0803` names the rail branch; and `0x0804`
counts sessions shed. `0x0805` preserves the non-frame byte count per comms boot
attempt. Each has a codec and a published vector.

*What stays owed:* the other reserved event bodies, including the dropped count,
the applied-or-shadowed decision and the client-enrolment capability mask.

If the space keeps gaining producers, the honest answer is to allocate distinct
event kinds rather than to keep widening a discriminator inside one — but that is
a decision to take when the fifth producer appears, and the discriminator is owed
either way.

**Why it is not guessed.** An event body is not only a wire shape. The same
records go into the NOR ring and come back out of `ReadLog` months later, so a
body guessed today is a body a client has to keep decoding for as long as the
ring holds — the same argument as entry 3, and the reason entry 3 is careful
about a field added on a hunch. The bodies that matter most are also the ones
nothing has emitted yet: what a `behaviour inhibited` record has to carry is
whatever a person needs to answer *why did it not start*, and that question has
never been asked at a real site.

**A warning about the vectors.** The event vector in
[`vectors/v1.json`](vectors/v1.json) encodes kind `0x0201` with a body of
`{1: 3, 2: 1}`. Those two keys are allocated nowhere and are not a schema — the
vector exists to pin framing, the wrapper and the MAC, and the body inside it is
filler that had to be some bytes. Reading it as an allocation is exactly the
failure this file exists to prevent. Pinning it, or replacing it, is the first
thing this entry does when it lands.

**What must be true first.** A controller that emits events, and a client that
tries to render them, so the field list is what somebody needed rather than what
somebody could imagine. The six already promised — the dropped count, the
applied-or-shadowed flag, the clock's old value, new value and source, the comms
power-cycle count, the granted capability mask, the alarm's condition, and which
rail branch `0x0803` took — are the floor and not the schema.

**Trigger.** The first event on the wire. Until then nothing sends a body and
nothing decodes one; the moment one is sent the shape is public, it is in
somebody's log ring, and it stops being cheap to move.

---

## 11. Checks that test the specification, not an implementation

**The question.** The conformance list in [PROTOCOL.md](../PROTOCOL.md) and every
vector in [`vectors/v1.json`](vectors/v1.json) test an *implementation*: given
these bytes, do you compute what we compute. Three checks would test the
documents instead. **All three are now built**, they run in
[`xtask/src/check.rs`](../../crates/xtask/src/check.rs), they fail the build, and CI
runs them — which is what this entry asked for. Each is narrower than the entry
described, and the remainder is what keeps it open.

- **The authentication coverage matrix** became a parse-time property rather
  than a check. `Auth` in [`registry.rs`](../../crates/xtask/src/registry.rs) has nine
  variants and no tenth, so a registry naming a rule that does not exist fails
  to load at the line that names it, and `every_message_declares_its_auth`
  catches a direction with no label at all. **What it does not do** is compare a
  label against the rule it claims: nothing checks that the `signed` in the
  table agrees with P-052, P-053 or P-054. The `Error` row — *session or none*,
  which is P-142's answer about the sender rather than a lookup — is still
  settled by whoever reads it, and it is the row this entry named as the one
  showing why a generated matrix beats reading a column.

- **The reachability check** exists as `Registry::unreachable`, and it sweeps
  message types, error codes, outcome spaces and the link-local error codes
  against the protocol corpus. **What it does
  not sweep is `enums.*` and `codes.*`** — quality, client kinds, time sources, config
  sections, command kinds, capability bits — so no discriminant space is
  reachability-checked. Both ways were tried and neither is honest yet. Sweeping
  by member reports all eighteen, because a member of one of those spaces is a
  label: `quality = estimated` decides nothing on the wire, no rule quotes it,
  and requiring one means writing eighteen sentences that repeat the table.
  Sweeping by space name reported four spaces that *are* reached, under their
  field name rather than their space name — `source` for `time_source`,
  `section` for `config_section`. A check that cries wolf gets switched off,
  which is worse than an honest gap, so the gap is written down here instead.

- **The non-disclosure check** exists as `no_response_carries_key_material`, and
  it is the narrowest of the three. It compares the derived-key bytes against
  the encoded bodies in `vectors/v1.json`, so it catches a secret that reached a
  vector. **It does not read the message definitions**, so a field that would
  leak key material in an implementation but was never put in a vector passes.
  The check it stands in for — no *definition* names a field derived from
  `device_key`, `pair_key`, `client_key`, `session_key` or the printed secret —
  needs the body schemas that entry 10 defers, and cannot be finished before
  them.

**Why they matter more than another vector, which is the whole point of this
entry.** A test vector catches two implementations disagreeing about a value both
of them knew to compute. It cannot catch a value nobody listed. **Every defect
the first three audit rounds found was an omission**: error codes with no rule
that produces them, a `GetConfig` that hands the site's Wi-Fi passphrase to the
cloud because nothing marked a field unreadable, three `unauthorised` outcomes
with no permission model behind them, a `Class` column with the classes defined
nowhere normative, a session shed with no event kind to log it under. Not one was
arithmetic. A corpus checked only by vectors is checked for the one kind of
defect it has not been making.

**What was true first.** The condition this entry set was that the tables be
emitted from a data file rather than hand-kept, and they are:
[`protocol.toml`](../../crates/km43/protocol.toml) is where a number is
allocated, REGISTRY.md's tables are spliced from it, and `Codegen::write`
refuses when the document holds a table no section generates — which is what
stopped the client capability mask being hand-kept outside the registry.

**What remains.** Three things, and the entry closes when they are done: a
matrix that checks an auth *label against its rule* rather than its presence;
reachability for the discriminant spaces, which needs a convention for how a
rule names one; and a non-disclosure check that reads definitions rather than
vector bytes, which waits on entry 10.

**Trigger.** The first two before the next audit round, on the same reasoning as
before — a round is only worth running on what the checks cannot find. The third
follows entry 10's trigger, because there is nothing to read until a body has a
field list.

---

## 13. Multi-device topology and complete equipment coverage

**The question.** What is the smallest bounded model that lets a controller
describe several physical devices, and several repeated components inside one
device, without turning an instance number into a new metric kind? The current
`Value` says only `channel`, `kind`, one signed integer, `quality`, and an optional
sample time. The `channel` is stable by promise and anonymous by schema: the
`channels` and `buses and devices` config bodies that would say what owns it are
both deferred in entry 9.

That is enough for one PV voltage, one PV current, and one PV power. It is not a
complete equipment model. A Victron MPPT RS reports two or four independent
trackers, each with voltage, current, power, tracker mode, and daily history. A
VE.Bus system reports distinct AC inputs and output phases. A battery reports a
pack, modules, cells, temperature probes, contactors, FETs, and balancing state.
A dual-bank charger reports two batteries through one enclosure. A circuit meter
reports nineteen current transformers. The committed catalogue records all five
shapes in origin89's `docs/catalog/`: `ve-direct.md`, `can-bms.md`,
`modbus-rs485.md` and `lan-http.md`; they are no longer hypothetical future sites.

**The correction to one catalogue sentence matters.** Distinct configured
channels can carry four values with the same `MetricKind`, so the current bytes do
not literally force a four-tracker charger to publish only a sum. What they do
not carry is a normative, authenticated statement that channel 12 is *device 3,
tracker 2, east array*, that channel 16 is the aggregate of trackers 1–4, or that
the mapping changed. A private build can assign those numbers by convention. Two
independent clients cannot discover their meaning from the settled protocol.

**Why adding `pv-power-1` through `pv-power-4` is not the answer.** Tracker 2 is
an instance of the same quantity, not a new quantity. The same suffix scheme has
no end: phase L1/L2/L3, battery bank 1/2, pack 1–16, cell 1–16, relay 1–6, and
circuit 1–19 all reproduce it. It also makes an all-in-one power station pretend
to be several unrelated devices and spends the global number registry on the
shape of one product. The candidate hierarchy to prove is:

```text
controller -> bus -> physical device -> component -> signal
```

`component` is where tracker, PV string, AC input, AC output, phase, battery bank,
pack, module, cell, relay, probe, tank, and circuit belong. `signal` is where
voltage, current, power, mode, temperature, state, limit, and counter belong. This
is a candidate invariant, not a wire schema; the identifiers, field numbers, and
message types remain open until the fixtures below fit.

**The coverage ledger.** The equipment catalogue contains many vendor fields,
but they collapse into these protocol gaps. A row leaves this ledger only when
its owner has a normative body, bounds, generated bindings, and a conformance
fixture. A vendor register name by itself never becomes a KM43 allocation.
The source sweep, counts, inspected pages, confirmed findings, and open design
questions are preserved in [Equipment coverage research](COVERAGE-RESEARCH.md).

| Gap | Failure today | Owner and exit condition |
|---|---|---|
| Attached-device inventory | `Discover` identifies the Origin 89 controller, not the instruments behind it; product id, model, serial, hardware revision, firmware, bus address, dialect, presence, and replacement have no authenticated inventory | This entry: bounded inventory with stable device/component ids and a topology revision; entry 1 settles identity across replacement and reassignment |
| Repeated components | Trackers, phases, banks, cells, relays, probes, and circuits are anonymous channel-number conventions | This entry: parent, role, index, label, and aggregate/member relationships reconstructable by a client with no site-specific code |
| Signal description | A standard `kind` fixes a quantity, but no settled schema names the owning component, measurement point, direction, source, reset domain, or whether a value is observed, derived, or merely commanded | This entry: authenticated signal descriptors; standard kinds keep fixed semantics, vendor kinds remain namespaced |
| Capacity and delivery | `Snapshot` returns all values, stops at 32, and has no filter or paging; high-cardinality cells or circuits exhaust it before ordinary site telemetry is added | This entry: bounded inventory pages and bounded selected/filtered telemetry reads or subscriptions; 32 may remain a response cap but cannot remain the whole-site semantic cap |
| Value shape and validity | One `i32` cannot efficiently carry indexed cells, large lifetime counters, flags, or vendor state; `measured`, `counted`, `estimated`, `stale`, and `absent` mix origin with validity, so a counted value cannot also say it became stale | This entry: explicitly bounded scalar, counter, enum/flags, and repeated-sample shapes, with validity separated from provenance; text stays in bounded descriptors rather than high-rate samples |
| Active concerns | **Closed.** `Concerns 0x0F`/`0x8F` is live, with a section, a codec and a vector, and it publishes the stable concern id, the source component, the severity, the five-state lifecycle, the age, the normalized condition and the preserved vendor code. The transition events `0x0501` and `0x0502` are still reserved with deferred bodies, and entry 10 owns them | This entry owned the snapshotable concern state; entry 10 owns the transition-event bodies and now records what `0x0501` being redefined left open |
| Operating state and control ownership | Charger stage cannot describe inverter bypass, eco search, BMS charging/discharging, MPPT clipping, external control, or which AC input is active | This entry: typed state domains plus the source of authority — local panel, controller, BMS, GX/ESS, remote client, or device automation — with a raw vendor fallback that cannot be mistaken for a normalized state |
| Electrical topology and flow | AC input and output, grid/generator/shore, L1/L2/L3, line-to-neutral/line-to-line, bypass, AC- versus DC-coupled PV, charger output, and import/export collapse onto single scalar kinds | This entry: ports, phase/leg roles, measurement points, sign conventions, and directional flow/counter semantics. Metric names alone do not carry topology |
| Battery/BMS safety surface | Per-cell voltage and temperature, imbalance, heater, balancing, contactor/FET state, allow-charge/discharge, and CVL/CCL/DCL are absent even though they decide whether starting a charger is safe | This entry: battery-bank/pack/module/cell profile, active protections, and reported operational limits; command authority never substitutes for observing the BMS limit |
| History and counters | Events are readable, but daily/yesterday records, extrema, stage durations, arbitrary windows, per-tracker history, and lifetime versus user-resettable counters have no common query shape | Entry 3 owns the controller's packed aggregate record; this entry owns client-facing history, bucket, reset, wrap, direction, sample-count, and source semantics |
| Device parameters and capabilities | Downstream devices report ratings, supported features, current setpoints, effective derated limits, relay meaning, and read/write constraints; hub config and live metrics are both the wrong home | This entry owns read-only capability and parameter descriptors; entry 9 owns Origin 89 configuration bodies and secret handling |
| Targeted control lifecycle | `Command` has no common device/component target, its arguments are deferred, and it cannot express desired versus observed state, a temporary lease/deadman, progress, cancellation, or a machine-readable refusal | Entry 8 owns kind-specific arguments; this entry owns the common target and lifecycle. Raw vendor writes are not a cloud command surface |
| Firmware targets | Controller and comms images are discussed, while attached-device and component firmware identity, compatibility, progress, and ownership are not modelled | Entry 6 owns firmware bodies and manifest; its target vocabulary depends on this entry's inventory rather than inventing a second device-id space |
| Communication health | Value staleness cannot distinguish an absent instrument, unsupported signal, bad CRC, open/short/reversed sensor, changing module list, or a healthy device behind a broken bus | This entry: device/component presence and health separate from signal validity, with last-seen and bounded diagnostic counters where a source provides them |
| Evolution and limits | There is no topology generation, descriptor/schema identity, per-device capability negotiation, or reported cap for devices, components, signals, vector length, and descriptor pages | This entry: every new collection is bounded, capability-discovered, and versioned; unknown normalized and vendor extensions remain skippable under P-019 |
| Security and conformance | A complete data model would still sit on known open security and verification work | Entries 2, 4, 5, 7, and 11 remain the owners of confidentiality, rate limiting, the later Noise handshake, BLE/MQTT evidence, and spec checks. This entry does not duplicate or hide them. `req_id` admission, once entry 12, is settled in P-022 |

**The minimum proof before choosing bytes.** Build six source-backed fixtures:

1. One physical charger with four MPPT trackers, aggregate PV values, and
   per-tracker daily history.
2. One inverter/charger with two AC inputs, split-phase or three-phase output,
   bypass, and an external controller/BMS ownership state.
3. One battery bank with at least two packs, sixteen cells, four temperature
   probes, balancing, heater, contactor/FET state, active protections, and
   charge/discharge limits.
4. One dual-bank solar charger with an independently identified start battery.
5. One nineteen-circuit meter with parent/merged circuit identity and signed
   import/export power.
6. One modular all-in-one power system whose online sub-device list changes at
   runtime without changing the physical product identity.

For each fixture, a `no_std` controller must encode the inventory and the widest
permitted response without allocation or exceeding `MAX_PAYLOAD`; a TypeScript
client that knows no site-specific channel numbers must reconstruct every label,
parent, unit, role, aggregate, and control target. Bounds must be costed for the
controller actually being built.

**There is no compatibility constraint yet.** As of 2026-08-08 no KM43 client
exists and no deployed unit depends on these bytes. This entry may therefore
replace the draft `Snapshot`, renumber provisional allocations, and regenerate
bindings and vectors if that produces the smaller honest v1. A new message type
may still be the cleanest design under P-012, but it is not required as a legacy
escape hatch. Compatibility begins when the first independent client exists, not
when the first draft acquired a number.

**What this entry does not require.** KM43 does not have to standardize every
air-quality index, GPS field, grid-support curve, or vendor diagnostic before the
first controller ships. It does have to provide the finite shapes above so a
profile or namespaced extension can carry one without corrupting another. Core
profiles should cover PV/charger, inverter/AC, battery/BMS, generator, tank and
I/O, environmental sensors, and link health; specialist DER, GPS, air-quality,
and raw diagnostics may remain optional profiles.

**Trigger.** Before entry 9 makes either `0x0002 channels` or `0x0003 buses and
devices` writable, or before any KM43 driver exposes a second tracker, phase,
bank, cell, relay, probe, or circuit — whichever comes first. **Hard deadline:
before KM43 is described as a complete equipment protocol.** Until this entry
lands, v1 is accurately a bounded, authenticated scalar telemetry and control
kernel, not a complete model of the devices the catalogue says Cabin Hub may
meet.

---

## How an entry leaves this file

Two ways, and only two.

**It moves into the normative spec.** With a test vector in
[`vectors/v1.json`](vectors/v1.json) wherever the entry has anything to compute,
and with its section deleted from this file **in the same commit**. A question
answered in one document and still open in another is two documents disagreeing,
which is the thing this project does not permit between a doc and the code and
does not permit here either.

**Or it is abandoned, in writing.** Moved to an `Abandoned` section at the bottom
of this file with the date and the reason, not deleted. "We are not doing
end-to-end encryption" is a sentence somebody re-litigates in a year. "We decided
on 2026-11-04 not to, because it moves alerting onto a phone that is asleep" is a
sentence that survives the argument, and it is also the sentence that tells the
person re-opening it what new fact would justify re-opening it.

**What may not happen is an entry quietly disappearing.** A question that
vanishes during a tidy-up has been decided by nobody, and the decision surfaces
later as a unit in a cabin that does not do what somebody assumed. If a commit
removes an entry, its message says which of the two things happened.

**A trigger that has fired is a bug in this file, not a missed deadline.** This
file gets read again every time one of the conditions above comes true. An entry
whose condition came true two weeks ago and still sits here unanswered is the
file failing at its only job.
