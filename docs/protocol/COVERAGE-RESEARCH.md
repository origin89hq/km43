---
title: Equipment coverage research
description: Evidence behind KM43's multi-device topology and semantic coverage backlog.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 3
---

# Equipment coverage research

<p class="o89-doc-kicker">KM43 / research record</p>

<p class="o89-doc-deck">What the committed equipment protocols can express, what KM43 v1 can preserve today, and which reusable data-model shapes are still missing.</p>

<dl class="o89-doc-facts">
  <div>
    <dt>Reviewed</dt>
    <dd>2026-08-08</dd>
  </div>
  <div>
    <dt>Scope</dt>
    <dd>KM43 state model against the committed equipment catalogue</dd>
  </div>
  <div>
    <dt>Evidence</dt>
    <dd>Repository sources and four vendor protocol PDFs</dd>
  </div>
  <div>
    <dt>Status</dt>
    <dd>Research, not normative wire allocation</dd>
  </div>
</dl>

<nav class="o89-doc-links" aria-label="Related KM43 documents">
  <a href="/km43/deferred/">Tracked gaps <span aria-hidden="true">→</span></a>
  <a href="/km43/specification/">Settled protocol <span aria-hidden="true">→</span></a>
  <a href="/km43/registry/">Live registry <span aria-hidden="true">→</span></a>
</nav>

This page preserves the evidence behind
[DEFERRED entry 13](DEFERRED.md#13-multi-device-topology-and-complete-equipment-coverage).
It exists so the eventual topology design starts from the devices already found,
not from memory or from the shape of the first driver implemented. Catalogue
field names are evidence of required shapes; they are **not** automatic KM43
metric, command, or field allocations.

## Question and conclusion

The question was whether KM43's current `channel + MetricKind + scalar value`
model is complete enough to normalize the equipment in `docs/catalog/`, including
devices with multiple MPPT trackers.

It is not. KM43 v1 is a strong bounded and authenticated message kernel around a
small scalar telemetry model. The missing piece is not CBOR and it is not one
forgotten `MetricKind`. It is a reusable identity and topology layer for repeated
components, followed by bounded ways to describe, read, stream, and retain their
signals.

**There are no KM43 clients or deployed wire dependencies as of 2026-08-08.**
The current v1 text, bindings, and vectors are therefore a draft to correct, not
a compatibility surface to preserve. The topology work may replace message
bodies, allocations, and generated types directly before v1 is frozen. Keeping a
legacy flat path would spend implementation and conformance effort on a client
that does not exist.

One correction is important: the current bytes **can** carry four readings of the
same metric kind under four different configured channel ids. They do not force a
multi-tracker charger to publish only an aggregate. What is missing is the
normative authenticated description that tells an independent client which
device and tracker owns each channel, which reading is the aggregate, and whether
that mapping changed.

## Sources and method

### KM43 sources inspected

The `crates/o89-core/` paths below are the controller's, in origin89; so are the
vendor documents under `docs/vendor/`, which are not ours to redistribute and are
not in this repository.

- `docs/PROTOCOL.md`: limits, `Snapshot`, `Value`, subscriptions, events,
  configuration, commands, firmware, and conformance.
- `docs/PROTOCOL-RATIONALE.md`: CBOR rationale, the rejected paged snapshot, and
  the fixed-versus-reported limit boundary.
- `docs/protocol/REGISTRY.md`: 28 live metric kinds, five quality values, reserved
  config sections, reserved command kinds, events, and capabilities.
- `docs/protocol/DEFERRED.md`: existing owners for channel identity, aggregates,
  rate limiting, firmware, command/config/event bodies, and request admission.
- `crates/o89-core/src/store.rs`: one store slot is `channel`, `kind`, freshness,
  and one held scalar.
- `crates/o89-core/src/driver.rs`: a device maps a block's fields onto a flat list
  of channel ids, and two devices may not write one channel.

### Equipment catalogue sweep

The seven connected-device catalogue files contain **134** explicit
`Reports with no MetricKind` blocks. Each block may name many fields, so 134 is a
count of evidence groups rather than missing protocol allocations.

| Catalogue family | Gap blocks |
|---|---:|
| VE.Direct / Victron serial and BLE | 27 |
| Modbus RTU / RS-485 | 44 |
| Modbus TCP | 13 |
| CAN and battery protocols | 19 |
| LAN, HTTP, MQTT, and gRPC | 20 |
| Local I/O | 9 |
| Other serial | 2 |
| **Connected total** | **134** |

`docs/catalog/no-comms.md` contains 35 more blocks, kept separate because a
device with no readable interface cannot become a KM43 driver merely by adding a
data-model shape.

The catalogue's already-mappable `reports` lines use 42 unique metric names. The
KM43 registry currently has 28 live metric rows. Those vocabularies come from
different layers and cannot be subtracted mechanically; the comparison only
shows that KM43's present state profile is smaller than the common telemetry set
the catalogue already assumes, before the explicit gaps are considered.

The counts can be reproduced with:

```sh
rg -c 'Reports with no `MetricKind`' docs/catalog/*.md
rg '^`reports` ' docs/catalog/*.md \
  | sed 's/^.*`reports` //' \
  | tr ',' '\n' \
  | sed 's/^ *//; s/ *$//' \
  | sort -u
```

### Vendor documents visually checked

Four committed primary sources were selected because together they prove the
repeated-component shapes rather than merely naming more metrics:

| Source | Pages checked | Shape confirmed |
|---|---:|---|
| `docs/vendor/victron-mppt-ve-direct-hex-protocol-rev18.pdf` | 14, 20 | Tracker count; combined PV values; trackers 1–4 voltage, current, power, mode; combined and per-tracker daily history |
| `docs/vendor/victron-mk2-protocol-3.14.pdf` | 10–13 | AC L1–L4 requests; phase identity and phase count; AC input versus inverter output; inverter modes; input-current limits; Battery Operational Limits and its timeout |
| `docs/vendor/eg4-lifepower4-battery-communication-protocol.pdf` | 11–13, 17–21 | Sixteen cell voltages, four cell temperatures, pack/environment/MOSFET values, capacity and energy counters, per-cell alarms, protections, FET/heater state, and balancing bitmap |
| `docs/vendor/morningstar-sunsaver-duo-modbus-specification.pdf` | 4–5 | Battery 1 and battery 2 measurements, state, limits, and configuration inside one physical charger |

The equipment catalogue remains the broader evidence ledger. The four PDFs are
the compact source set that independently confirms the structural conclusion.

## Confirmed structural findings

### Multiple MPPTs are components, not metric kinds

Victron exposes runtime tracker count and repeats the same voltage, current,
power, mode, and history shape for trackers 1–4. The correct semantic model is
one physical charger containing repeated tracker components, not global metric
kinds named `pv-power-1` through `pv-power-4`.

A complete client must also distinguish the charger's combined PV figures from
the per-tracker figures. Otherwise it will either hide shading on one string or
double-count the aggregate and its children.

### AC needs ports and phases

The MK2 and GX evidence distinguishes mains/shore/generator input from inverter
output, identifies phases, and reports states such as bypass and PowerAssist. A
single `ac-voltage`, `ac-current`, or `ac-power` kind cannot carry input/output,
source, phase, line-to-neutral versus line-to-line, and import/export meaning by
itself.

### Batteries are hierarchies

A useful BMS surface is bank → pack/module → cell, plus repeated temperature
probes and controllable or protective components. Pack voltage and state of
charge alone omit the fields that explain whether charging is safe: cell spread,
low-temperature protection, charge/discharge permission, contactor and FET state,
heater, balancing, and the BMS's reported charge/discharge limits.

### One enclosure may contain several banks or subsystems

The SunSaver Duo proves two battery banks inside one charger. Portable power
stations and modular power kits go further: one serial-numbered product may
contain a battery, inverter, AC charger, several solar chargers, distribution
circuits, relays, and a modem. Registering fake unrelated devices loses the
physical identity and makes lifecycle, firmware, and aggregate power ambiguous.

### The aggregate is reported by the device, not summed by the controller

**Confirmed**, `victron-mppt-ve-direct-hex-protocol-rev18.pdf` page 14: register
`0xEDBC` "Panel power" is documented as *the combined power for the entire unit*,
and sits beside per-tracker power at `0xECCC`, `0xECDC`, `0xECEC`, `0xECFC`. Page
20 repeats the split for history: the regular day record `0x1050..0x106E` is the
combined unit, and `0x10A0..0x10BD` is the per-tracker record.

So a design that treats the aggregate as a controller-computed sum of its members
publishes a different number from the one the charger reports, and neither the
controller nor a client can say which it is looking at. Provenance has to
distinguish **device-reported aggregate** from **controller-derived sum**. That is
narrower than the research's general observed/derived/commanded axis, and it is
the case that actually occurs.

### Signal availability is a function of model *and* firmware version

**Confirmed**, same page 14: "The panel current is not available in the
10A/15A/20A chargers"; "The maximum allowed panel voltage is added in firmware
version 1.16"; "Tracker mode ... Added in firmware version 1.42"; and four
registers marked *MPPT RS models only*.

A signal can therefore be unsupported on this unit today and supported after the
downstream device's own firmware update. A descriptor set that is static per
model is wrong; it is per device instance and it can change without the device
being replaced. *Inference*: this is the same revision problem as a changing
sub-device inventory, so both should move one mechanism rather than two.

### The vendor encodes absence in-band, with a sentinel that reads as a measurement

**Confirmed**, page 20: "Fields that are not present in the given unit report as
`0xFFFF`", and "Consumed is not available on models without load output (reads as
`0xFFFFFFFF`)."

This is the most dangerous translation on the whole path. A driver that passes the
sentinel through publishes 65 535 as a reading, and every rule downstream — a
frost behaviour, an alarm threshold, an aggregate — acts on it. `0xFFFF` at a
scale of 0.01 V is 655.35 V, which is a plausible-looking number on an MPPT RS.
It is not one vendor. The committed catalogue records the same shape in four
families: Victron `0xFFFF` and `0xFFFFFFFF` above; Xantrex Freedom SW device
state `255 = Data Not Available` (`docs/catalog/modbus-tcp.md`); Victron Inverter
RS MPP operation mode `255 Not available` (same file); and the Magnum BMK's state
of charge `255 = "Think'n"`, meaning *still learning, not yet trustworthy*
(`docs/catalog/other-serial.md`). The last one is a third state again — neither
present nor absent, but not to be acted on.

**The seam did not exist when this was written, and now it does.** At the time,
`crates/o89-core/src/driver.rs` reached `write_absent` down exactly one path —
the registry's scale could not carry the number — and wrote `Quality::Measured`
for everything else, so the first driver written for any of those four families
would have published the sentinel as a reading. *Confirmed by reading the file;
the shipped EPEver and PZEM dialects use no sentinels, so it was a trap set for
the next driver rather than a defect in the current two.*

`map.rs` now carries `Absent::{AllOnes, Raw(u32)}` on a `Cell`, declared per
register and never assumed, matched on the raw bits at the cell's own width
before the sign, the width conversion and the scale — because it is a bit
pattern the vendor documents and not a quantity. `driver.rs` answers
`Reading::NotOnThisUnit` when it matches, against `Reading::Unreadable` when the
reply was short or the scale could not carry it, because *the device says it does
not have this* and *the reply did not arrive intact* are different findings and
collapsing them hides a broken bus behind a field that was always going to be
missing.

That closes the driver half. **The wire half is
[TOPOLOGY-DESIGN.md](TOPOLOGY-DESIGN.md)'s P-176**, which says which validity
each of the two publishes — `4 unsupported` and `5 sensor_fault` — and forbids
either from being published as a reading. The finding stands as written: the
model must make *absent* unrepresentable as a value rather than merely
discouraged, and the driver layer is where the sentinel dies.

### A history bucket is not a time series of the live signals

**Confirmed**, page 20. The per-tracker history record carries energy, peak power
and Voc max per tracker. The live per-tracker registers carry power, voltage,
current and tracker mode. **They are different signal sets.** The combined day
record adds extrema (battery voltage max and min, power max, battery current max,
panel voltage max) and durations (time in bulk, absorption, float, in minutes).

A design that models history as "the same signals, bucketed" cannot carry any of
it. Buckets have their own signals, their own extrema, and their own durations.

The bucket identity is also a wrapping counter: "The sequence number can be used
to uniquely identify a day ... stays the same while data traverses through the
30 day backlog buffer. For each new day added the sequence number will be
increased by 1, at the count of 365 it will be wrapped to 0." So a bucket id is
a wrapping `un16` over a 30-record backlog, and a client that treats it as
monotonic will mis-order a year boundary.

### High-cardinality telemetry exceeds the current whole-site cap

Four MPPT trackers are manageable as individual scalar signals. Sixteen cells,
multiple probes, protections, and a nineteen-circuit meter are not. The current
`Snapshot` returns every configured value, permits at most 32, and has no filter
or paging. Raising `MAX_CHANNELS` alone does not provide topology, consistent
identity, compact repeated samples, or bounded delivery.

## Normalized protocol gaps

The 134 catalogue evidence groups reduce to these reusable protocol-level needs:

1. Authenticated inventory for attached physical devices and changing sub-device
   lists.
2. Stable component hierarchy with parent, role, instance index, label, and
   aggregate/member relationships.
3. Signal descriptors carrying owner, quantity, unit, scale, measurement point,
   direction, source, reset domain, and observed/derived/commanded provenance.
4. Bounded inventory pages and selected or filtered telemetry delivery beyond a
   32-value whole-site snapshot.
5. Explicit scalar, large-counter, enum/flags, and compact repeated-sample shapes.
6. Validity separated from provenance, so a measured or counted value may also
   be stale, initializing, invalid, unsupported, or absent for a stated reason.
7. Snapshotable active concerns with severity, lifecycle, source, timestamps,
   normalized condition, and preserved vendor code; events remain transitions.
8. Typed operating state and control ownership for charger, inverter, BMS,
   tracker, generator, link, and autonomous device logic.
9. Electrical ports, phases, measurement points, sign conventions, and
   directional power/energy flow.
10. BMS safety profiles including cells, probes, protections, contactors/FETs,
    heater/balancing, permissions, and CVL/CCL/DCL.
11. History query semantics for buckets, extrema, sample coverage, reset/wrap,
    direction, and device-supplied versus controller-derived records.
12. Read-only capability and parameter descriptors distinct from Origin 89 hub
    configuration and from high-rate telemetry.
13. A common command target and lifecycle distinct from kind-specific arguments:
    desired versus observed state, refusal code, lease/deadman, progress, and
    cancellation where applicable.
14. Firmware targets tied to the same inventory identity rather than a second
    target-id space.
15. Device and bus health distinct from signal staleness.
16. Topology/schema revision and reported caps for every new collection.

The ownership and exit condition for each row are maintained in
[DEFERRED entry 13](DEFERRED.md#13-multi-device-topology-and-complete-equipment-coverage),
which also points to the existing entries that own security, firmware, config,
commands, events, history storage, and request admission.

## Candidate model, not a settled schema

The smallest hierarchy that covers every confirmed case is:

```text
controller -> bus -> physical device -> component -> signal
```

For a four-tracker charger, that might describe:

```text
device: SmartSolar MPPT RS 450/200
  component: charger aggregate
    signals: PV voltage, current, power, charge state
  component: MPPT tracker 1
    signals: PV voltage, current, power, tracker mode
  component: MPPT tracker 2
    signals: PV voltage, current, power, tracker mode
  component: MPPT tracker 3
    signals: PV voltage, current, power, tracker mode
  component: MPPT tracker 4
    signals: PV voltage, current, power, tracker mode
```

The high-rate sample may still carry only a compact `signal_id`; the authenticated
descriptor cached by the client gives that id its meaning. A topology revision in
state and history is the candidate way to make a mapping change visible. Neither
choice is normative until its size, lifecycle, and compatibility behavior pass
the source-backed fixtures in DEFERRED entry 13.

## Decisions this research supports

- **Keep CBOR.** Integer-keyed CBOR can encode the required inventory, descriptor,
  concern, history, and selected-read messages. The gap is semantic structure,
  not serializer capability. CBOR also preserves the existing inspectability and
  forward-compatible skipping rules.
- **Do not allocate numbered metric variants for instances.** Instance identity
  belongs in topology.
- **Do not overload one flat `DeviceKind` for all-in-one products.** Physical
  identity and logical components are separate axes.
- **Do not silently reinterpret `channel`.** There is no deployed compatibility
  obligation, so the draft channel model may be replaced or deliberately promoted
  into a signal-id model. Either way, ownership and topology generation must be
  explicit before v1 is frozen.
- **Do not solve capacity only by raising 32.** Keep every response bounded and
  add selection, filtering, paging, or a new message type as the costed fixtures
  require.
- **Do not build a legacy path for hypothetical clients.** Regenerate the v1
  bindings and vectors after the corrected model lands; compatibility starts at
  the first real independent client, not at the first draft.
- **Do not turn vendor registers into remote raw-write commands.** Normalize safe
  operator intent and preserve raw diagnostics as bounded, namespaced evidence.

## Open design questions

The research settles the need, not these bytes:

- Whether components are encoded as one flat parent-linked table or nested maps.
- Width and lifecycle of device, component, and signal ids.
- Whether channel identity becomes `(id, generation)`, references a topology
  revision, or is retired on semantic reassignment.
- Whether large live sets use client-selected `ReadValues`, stateless pages,
  filtered subscriptions, compact vectors, or more than one of those.
- Which repeated samples deserve vectors and how per-element absence/quality is
  represented without an unbounded bitmap.
- Whether standard signal kinds retain fixed unit/scale while installer-defined
  and vendor kinds obtain bounded descriptors.
- Exact separation of validity, provenance, confidence, and device-reported
  sensor status.
- Which operating states are normalized across vendors and which remain raw
  namespaced codes beside a smaller common state.
- How active concerns are acknowledged without confusing acknowledgement with
  clearing the underlying protection.
- Which profiles are core at v1 completion and which are optional extensions.

Those questions are deliberately left in DEFERRED rather than answered here.
This page is the evidence record against which their eventual answers are tested.
