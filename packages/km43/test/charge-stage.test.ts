// The charge stages as a TypeScript client holds them, against the registry
// they were generated from. A client that names stage 3 `float` where the
// controller means `absorption` draws a confident wrong stage over a bank, so
// the names and numbers are read out of protocol.toml rather than retyped.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ChargeStage } from "../src/generated.ts";

/** Every `[[enums.charge_stage]]` block in the registry, as value and name. */
function registryStages(): Map<number, string> {
  const registry = readFileSync("../../crates/km43/protocol.toml", "utf8");
  const stages = new Map<number, string>();
  for (const block of registry.split("[[enums.charge_stage]]").slice(1)) {
    const value = /^value = (\d+)$/m.exec(block)?.[1];
    const name = /^name = "([^"]+)"$/m.exec(block)?.[1];
    assert.ok(value !== undefined && name !== undefined, block);
    stages.set(Number(value), name);
  }
  return stages;
}

test("every registered charge stage has its number and its name in the TypeScript enum", () => {
  const stages = registryStages();
  assert.equal(
    stages.size,
    7,
    "the registry's charge stages were not all read",
  );
  for (const [value, name] of stages) {
    const variant = name.charAt(0).toUpperCase() + name.slice(1);
    assert.equal(
      (ChargeStage as Record<string, unknown>)[variant],
      value,
      `${name} is ${value} in the registry`,
    );
  }
});

test("the TypeScript enum names no charge stage the registry did not allocate", () => {
  const stages = registryStages();
  const emitted = Object.values(ChargeStage).filter(
    (v): v is number => typeof v === "number",
  );
  assert.deepEqual(
    [...emitted].sort((a, b) => a - b),
    [...stages.keys()].sort((a, b) => a - b),
  );
  // Victron's `CS` 245 is *starting up*: a vendor state with no member here.
  // A lookup must come back empty, never with the nearest stage.
  assert.equal(
    (ChargeStage as Record<number, string | undefined>)[245],
    undefined,
  );
  assert.equal(
    (ChargeStage as Record<number, string | undefined>)[0],
    undefined,
  );
});
