// The crosswalk as a client reads it: a kind over a domain at a place in, a
// dataset word or nothing out. The Rust side has the same cases; these keep a
// TypeScript-only slip in the predicate from shipping while the types still pass.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  ComponentRole,
  Direction,
  datasetAbsent,
  datasetMetrics,
  datasetName,
  MeasurementPoint,
  MetricKind,
  metricUnits,
  SignalDomain,
} from "../src/generated.ts";

test("a bank's live DC voltage is battery-voltage, and a tracker's is pv-voltage", () => {
  assert.equal(
    datasetName(
      MetricKind.DC_VOLTAGE,
      SignalDomain.Live,
      ComponentRole.BATTERY_BANK,
    ),
    "battery-voltage",
  );
  assert.equal(
    datasetName(
      MetricKind.DC_VOLTAGE,
      SignalDomain.Live,
      ComponentRole.MPPT_TRACKER,
    ),
    "pv-voltage",
  );
});

test("the specific row wins: a cell's temperature is the battery's, a heater's is plain", () => {
  assert.equal(
    datasetName(
      MetricKind.TEMPERATURE,
      SignalDomain.Live,
      ComponentRole.CELL,
      MeasurementPoint.CELL,
    ),
    "battery-temperature",
  );
  assert.equal(
    datasetName(
      MetricKind.TEMPERATURE,
      SignalDomain.Live,
      ComponentRole.HEATER,
    ),
    "temperature",
  );
});

test("the domain is never open: a limit and a day's counter are not the live reading", () => {
  assert.equal(
    datasetName(
      MetricKind.DC_CURRENT,
      SignalDomain.LimitUpper,
      ComponentRole.BATTERY_BANK,
    ),
    undefined,
  );
  assert.equal(
    datasetName(MetricKind.AC_ENERGY, SignalDomain.Lifetime),
    "ac-energy-total",
  );
  assert.equal(
    datasetName(MetricKind.AC_ENERGY, SignalDomain.Today),
    "ac-energy-today",
  );
  assert.equal(
    datasetName(MetricKind.AC_ENERGY, SignalDomain.Yesterday),
    undefined,
  );
  assert.equal(datasetName(MetricKind.AC_ENERGY, SignalDomain.Live), undefined);
});

test("a kind with no word, and a place no row names, both answer nothing", () => {
  assert.equal(
    datasetName(MetricKind.LOG_RING_UTILISATION, SignalDomain.Live),
    undefined,
  );
  assert.equal(
    datasetName(MetricKind.DC_VOLTAGE, SignalDomain.Live, ComponentRole.HEATER),
    undefined,
  );
});

test("rows lead with the most specific, and an absent word is never also carried", () => {
  const specificity = (m: (typeof datasetMetrics)[number]) =>
    (m.role === undefined ? 0 : 4) +
    (m.point === undefined ? 0 : 2) +
    (m.dir === undefined ? 0 : 1);
  const order = datasetMetrics.map(specificity);
  assert.deepEqual(
    order,
    [...order].sort((a, b) => b - a),
  );
  for (const word of Object.keys(datasetAbsent))
    assert.ok(
      datasetMetrics.every((m) => m.name !== word),
      `${word} is absent and carried`,
    );
  assert.ok(datasetAbsent["cycle-count"]?.length, "an absent word says why");
});

test("a live charge stage is the dataset's charge-stage, and no other domain is", () => {
  assert.equal(
    datasetName(MetricKind.CHARGE_STAGE, SignalDomain.Live),
    "charge-stage",
  );
  assert.equal(datasetAbsent["charge-stage"], undefined);
  for (const domain of [
    SignalDomain.Lifetime,
    SignalDomain.SinceReset,
    SignalDomain.Today,
    SignalDomain.Yesterday,
  ])
    assert.equal(datasetName(MetricKind.CHARGE_STAGE, domain), undefined);
});

test("a tracker's yield is pv-energy over its window, and only counting out", () => {
  const out = Direction.PositiveIsOut;
  const tracker = ComponentRole.MPPT_TRACKER;
  assert.equal(
    datasetName(
      MetricKind.DC_ENERGY,
      SignalDomain.Lifetime,
      tracker,
      undefined,
      out,
    ),
    "pv-energy-total",
  );
  assert.equal(
    datasetName(
      MetricKind.DC_ENERGY,
      SignalDomain.Today,
      tracker,
      undefined,
      out,
    ),
    "pv-energy-today",
  );
  assert.equal(
    datasetName(
      MetricKind.DC_ENERGY,
      SignalDomain.Yesterday,
      tracker,
      undefined,
      out,
    ),
    undefined,
  );
  assert.equal(
    datasetName(MetricKind.DC_ENERGY, SignalDomain.Lifetime, tracker),
    undefined,
    "a DC counter that names no direction has no word",
  );
});

test("only the charge leaving the bank is consumed-amp-hours", () => {
  const bank = ComponentRole.BATTERY_BANK;
  assert.equal(
    datasetName(
      MetricKind.DC_CHARGE,
      SignalDomain.SinceReset,
      bank,
      undefined,
      Direction.PositiveIsOut,
    ),
    "consumed-amp-hours",
  );
  assert.equal(
    datasetName(
      MetricKind.DC_CHARGE,
      SignalDomain.SinceReset,
      bank,
      undefined,
      Direction.PositiveIsIn,
    ),
    undefined,
    "charged amp-hours are not consumed ones",
  );
  assert.equal(
    datasetName(
      MetricKind.DC_CHARGE,
      SignalDomain.Lifetime,
      bank,
      undefined,
      Direction.PositiveIsOut,
    ),
    undefined,
  );
});

// Read from the registry itself, so a unit or decade that moved there and not
// here goes red rather than agreeing with a copy.
test("the DC counters carry the registry's unit and decade", () => {
  const registry = readFileSync("../../crates/km43/protocol.toml", "utf8");
  const metric = (name: string): [number, string, number] => {
    const block = registry
      .split("[[metrics]]")
      .find((b) => b.includes(`name = "${name}"`));
    assert.ok(block, `the registry allocates ${name}`);
    const field = (key: string) => {
      const found = new RegExp(`^${key} = "?([^"\\n]*)"?$`, "m").exec(block);
      assert.ok(found?.[1] !== undefined, `${name} has a ${key}`);
      return found[1];
    };
    return [Number(field("kind")), field("unit"), Number(field("scale"))];
  };
  for (const [kind, name] of [
    [MetricKind.DC_ENERGY, "DC energy"],
    [MetricKind.DC_CHARGE, "DC charge"],
  ] as const) {
    const [number, unit, scale] = metric(name);
    assert.equal(kind, number, `${name} is kind ${number}`);
    assert.deepEqual(metricUnits[kind], [unit, scale], name);
  }
});
