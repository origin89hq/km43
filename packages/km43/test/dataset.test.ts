// The crosswalk as a client reads it: a kind over a domain at a place in, a
// dataset word or nothing out. The Rust side has the same cases; these keep a
// TypeScript-only slip in the predicate from shipping while the types still pass.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ComponentRole,
  datasetAbsent,
  datasetMetrics,
  datasetName,
  MeasurementPoint,
  MetricKind,
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
    (m.role === undefined ? 0 : 2) + (m.point === undefined ? 0 : 1);
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
  assert.ok(datasetAbsent["charge-stage"]?.length, "an absent word says why");
});
