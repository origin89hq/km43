import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { BleReceiver, BleSender, bleValueLength } from "../src/ble.ts";
import { BLE_LAST_FLAG } from "../src/generated.ts";

function record(value: unknown): Record<string, unknown> {
  assert.ok(
    value !== null && typeof value === "object" && !Array.isArray(value),
  );
  return value as Record<string, unknown>;
}

function text(value: unknown): string {
  assert.equal(typeof value, "string");
  return value as string;
}

function number(value: unknown): number {
  assert.equal(typeof value, "number");
  return value as number;
}

function bytes(value: unknown): Uint8Array {
  const hex = text(value);
  assert.match(hex, /^(?:[0-9a-f]{2})*$/);
  return new Uint8Array(Buffer.from(hex, "hex"));
}

test("the published BLE traces agree on bytes, failures and state in both languages", () => {
  const document: unknown = JSON.parse(
    readFileSync("../../docs/protocol/vectors/v1.json", "utf8"),
  );
  const trace = record(document).ble;
  assert.ok(Array.isArray(trace));
  const rx = new BleReceiver();
  const tx = new BleSender();
  let cases = 0;
  for (const [index, raw] of trace.entries()) {
    const step = record(raw);
    const action = text(step.action);
    const input = bytes(step.input);
    const output = bytes(step.output);
    const mtu = number(step.mtu);
    const now = number(step.now_ms);
    let status: string;
    switch (action) {
      case "reset":
        rx.reset();
        tx.reset();
        cases += 1;
        continue;
      case "disconnect":
        rx.reset();
        tx.reset();
        status = "ok";
        break;
      case "expire":
        rx.expire(now);
        status = "ok";
        break;
      case "enqueue":
        status = tx.enqueue(input, mtu);
        break;
      case "accepted":
        status = tx.accepted();
        break;
      case "fragment":
      case "small_buffer": {
        const destination = new Uint8Array(action === "small_buffer" ? 2 : 512);
        const result = tx.fragment(destination);
        status = result.status;
        if (result.status === "ok")
          assert.deepEqual(
            destination.slice(0, result.length),
            output,
            `step ${index}`,
          );
        break;
      }
      case "receive": {
        const result = rx.receive(input, mtu, now);
        status = result.status;
        if (result.status === "message")
          assert.deepEqual(result.bytes, output, `step ${index}`);
        break;
      }
      default:
        assert.fail(`unhandled action ${action}`);
    }
    assert.equal(status, step.expected, `step ${index}: ${action}`);
  }
  assert.equal(cases, 18);
  assert.ok(trace.length > 1500);
});

test("MTU and clock boundaries refuse nonfinite and fractional platform input", () => {
  for (const value of [NaN, Infinity, -1, 22, 23.5, 518]) {
    assert.equal(bleValueLength(value), undefined);
    assert.equal(new BleSender().enqueue(new Uint8Array([1]), value), "mtu");
  }
  assert.equal(bleValueLength(23), 20);
  assert.equal(bleValueLength(247), 244);
  assert.equal(bleValueLength(517), 512);
  for (const now of [NaN, Infinity, -1, 1.5]) {
    assert.deepEqual(
      new BleReceiver().receive(new Uint8Array([0, BLE_LAST_FLAG, 1]), 23, now),
      { status: "length" },
    );
  }
});
