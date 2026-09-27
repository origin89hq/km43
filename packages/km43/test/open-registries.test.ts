// The open tables as a driver author reads them: a constant, and the number it
// puts on the wire. Nothing decodes these, so a constant on the wrong number
// is only caught by asking the registry what the number should be.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Dialect, Product } from "../src/generated.ts";

const registry = readFileSync("../../crates/km43/protocol.toml", "utf8");

// Every numbered, not-gone row under one heading, keyed by the identifier the
// generator gives its name. A range row has no number and is left out.
const rows = (table: string): [string, number][] => {
  const found = registry
    .split(`[[open_registries.${table}]]`)
    .slice(1)
    .map((b) => b.split("\n[[")[0] ?? "")
    .flatMap((block): [string, number][] => {
      const field = (key: string) =>
        new RegExp(`^${key} = "?([^"\\n]*)"?$`, "m").exec(block)?.[1];
      const number = field("number");
      const name = field("name");
      const status = field("status");
      if (number === undefined || name === undefined) return [];
      if (status === "withdrawn" || status === "retired") return [];
      return [[name.toUpperCase().replace(/[^A-Z0-9]+/g, "_"), Number(number)]];
    });
  assert.ok(found.length > 0, `no ${table} row was read out of protocol.toml`);
  return found.sort();
};

const constants = (set: Record<string, number>): [string, number][] =>
  Object.entries(set).sort();

test("every Dialect constant carries its registry number, and none is missing", () => {
  assert.deepEqual(constants(Dialect), rows("dialect"));
});

test("every Product constant carries its registry number, and none is missing", () => {
  assert.deepEqual(constants(Product), rows("product"));
});

// An inventory row keys a device by product and dialect together, so the AC
// pair must share the one and not the other.
test("the PZEM-014 and PZEM-016 are two products, and pzem ac is not pzem dc", () => {
  const product = new Map(rows("product"));
  const dialect = new Map(rows("dialect"));
  assert.equal(Dialect.PZEM_AC, dialect.get("PZEM_AC"));
  assert.equal(Product.PZEM_014, product.get("PZEM_014"));
  assert.equal(Product.PZEM_016, product.get("PZEM_016"));
  assert.notEqual(Product.PZEM_014, Product.PZEM_016);
  assert.notEqual(Dialect.PZEM_AC, Dialect.PZEM_DC);
});

// A DS18B20 probe is a device of its own, so it has a product; VE.Direct text
// and Pylontech CAN are framings whose devices wait for their own product rows.
// Text mode is not the HEX mode on the same port, and a probe does not speak
// the `no protocol` the controller's own analogue inputs sit under.
test("the three new dialects are their own numbers, and only the DS18B20 has a product", () => {
  const dialect = new Map(rows("dialect"));
  const product = new Map(rows("product"));
  assert.equal(Dialect.VE_DIRECT_TEXT, dialect.get("VE_DIRECT_TEXT"));
  assert.equal(Dialect.PYLONTECH_CAN, dialect.get("PYLONTECH_CAN"));
  assert.equal(Dialect.DS18B20, dialect.get("DS18B20"));
  assert.equal(Product.DS18B20, product.get("DS18B20"));
  assert.notEqual(Dialect.VE_DIRECT_TEXT, Dialect.VICTRON_MPPT_RS_HEX);
  assert.notEqual(Dialect.DS18B20, Dialect.NO_PROTOCOL);
  assert.equal(product.has("VE_DIRECT_TEXT"), false);
  assert.equal(product.has("PYLONTECH_CAN"), false);
});
