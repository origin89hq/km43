// The package has no `Concern` codec, so the rule a client can act on is the
// predicate: a row carrying `vendor fault` without keys 11 and 12 is one the
// Rust decoder refuses, and a client building its own must refuse it too.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Condition, conditionNeedsVendorCode } from "../src/generated.ts";

test("a vendor fault is refused without its vendor code", () => {
  assert.equal(conditionNeedsVendorCode(Condition.VENDOR_FAULT), true);
});

test("every other allocated condition is accepted with no vendor code", () => {
  const others = Object.entries(Condition).filter(
    ([name]) => name !== "VENDOR_FAULT",
  );
  assert.ok(others.length > 0, "no other condition was checked");
  for (const [name, cond] of others) {
    assert.equal(conditionNeedsVendorCode(cond), false, name);
  }
});

test("a condition this build has never heard of is carried, not refused", () => {
  for (const cond of [0, 0x0100, 0xf000, 0xffff]) {
    assert.equal(conditionNeedsVendorCode(cond), false, cond.toString(16));
  }
});
