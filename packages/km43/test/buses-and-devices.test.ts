// `0x0003 buses and devices` against the published vectors and each refusal
// the section's rules name. The Rust crate has the same cases; these keep a
// TypeScript-only slip in the codec or the checks from shipping.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  type BoardBus,
  type BusesAndDevicesRead,
  type BusesAndDevicesRefusal,
  type BusesAndDevicesWrite,
  checkBusesAndDevices,
  type Decoded,
  type DeviceEntry,
  type DialectRule,
  decodeBusesAndDevicesRead,
  decodeBusesAndDevicesWrite,
  encodeBusesAndDevices,
  type SiteRules,
  sectionAnswer,
} from "../src/buses-and-devices.ts";
import {
  DeviceOption,
  DeviceRole,
  Dialect,
  Direction,
  ErrorCode,
  MAX_CONFIG_DEVICES,
  Parity,
  Product,
  PylontechVersion,
  SetConfig,
  Transport,
} from "../src/generated.ts";

const bodies = (() => {
  const file: unknown = JSON.parse(
    readFileSync("../../docs/protocol/vectors/v1.json", "utf8"),
  );
  assert.ok(file !== null && typeof file === "object" && "bodies" in file);
  return file.bodies as Record<string, { body_cbor: string }>;
})();

function published(name: string): Uint8Array {
  const entry = bodies[name];
  assert.ok(entry, `the vector file has no ${name}`);
  return Uint8Array.from(Buffer.from(entry.body_cbor, "hex"));
}

/** Pylontech CAN has no dialect number yet, so a vendor-range one stands in. */
const PYLONTECH_STAND_IN = 0xf0a0;

const BOARD: BoardBus[] = [
  { bus: 0, transport: Transport.LocalIo },
  { bus: 1, transport: Transport.Rs485 },
  { bus: 2, transport: Transport.Can },
  { bus: 3, transport: Transport.VeDirect },
  { bus: 4, transport: Transport.Ip },
];

const DIALECTS: DialectRule[] = [
  {
    dialect: Dialect.PZEM_DC,
    transports: [Transport.Rs485],
    options: [DeviceOption.PollPeriod],
    minPollMs: 500,
  },
  {
    dialect: Dialect.EPEVER_B,
    transports: [Transport.Rs485],
    options: [DeviceOption.CurrentDirection, DeviceOption.PollPeriod],
    minPollMs: 1000,
  },
  {
    dialect: Dialect.VICTRON_MPPT_RS_HEX,
    transports: [Transport.VeDirect],
    options: [DeviceOption.VeDirect3v3, DeviceOption.CurrentDirection],
    minPollMs: 1000,
  },
  {
    dialect: Dialect.EG4_LIFEPOWER4_SERIAL,
    transports: [Transport.Rs485],
    options: [DeviceOption.CurrentDirection],
    minPollMs: 1000,
  },
  {
    dialect: PYLONTECH_STAND_IN,
    transports: [Transport.Can],
    options: [
      DeviceOption.CurrentDirection,
      DeviceOption.PylontechVersion,
      DeviceOption.PollPeriod,
    ],
    minPollMs: 1000,
  },
];

const RULES: SiteRules = {
  buses: BOARD,
  dialects: DIALECTS,
  maxDevices: 24,
  maxTopologyDepth: 4,
};

function meter(
  dev: number | undefined,
  addr: number,
): DeviceEntry<number | undefined> {
  return {
    dev,
    bus: 1,
    addr: Uint8Array.of(addr),
    product: Product.PZEM_017,
    dialect: Dialect.PZEM_DC,
    role: DeviceRole.ENERGY_METER,
    options: { pollPeriodMs: 1000 },
  };
}

function pack(
  dev: number | undefined,
  addr: number,
  parent?: number,
): DeviceEntry<number | undefined> {
  const entry: DeviceEntry<number | undefined> = {
    dev,
    bus: 1,
    addr: Uint8Array.of(addr),
    product: Product.EG4_LIFEPOWER4,
    dialect: Dialect.EG4_LIFEPOWER4_SERIAL,
    role: DeviceRole.BMS,
  };
  if (parent !== undefined) {
    entry.parent = parent;
  }
  return entry;
}

function write(
  ...devices: DeviceEntry<number | undefined>[]
): BusesAndDevicesWrite {
  return {
    buses: [
      { bus: 1, rate: 9600, dataBits: 8, parity: Parity.None, stopBits: 2 },
    ],
    devices,
  };
}

function refused<T>(decoded: Decoded<T>): BusesAndDevicesRefusal {
  assert.ok(!decoded.ok, "the body is refused");
  return decoded.refusal;
}

function assertInvalid(refusal: BusesAndDevicesRefusal | undefined): void {
  assert.ok(refusal, "the body is refused");
  assert.deepEqual(sectionAnswer(refusal), {
    kind: "outcome",
    outcome: SetConfig.Invalid,
  });
}

function assertMalformed(refusal: BusesAndDevicesRefusal): void {
  assert.deepEqual(sectionAnswer(refusal), {
    kind: "error",
    code: ErrorCode.MalformedFrame,
  });
}

/** A hand-written body, for shapes the encoder will not produce. */
function hex(text: string): Uint8Array {
  return Uint8Array.from(Buffer.from(text.replaceAll(" ", ""), "hex"));
}

test("the published answers and writes decode and re-encode byte for byte", () => {
  for (const name of [
    "busesanddevices_0x0003",
    "buses_and_devices_empty_0x0003",
    "buses_and_devices_widest_0x0003",
  ]) {
    const bytes = published(name);
    const read = decodeBusesAndDevicesRead(bytes);
    assert.ok(read.ok, name);
    assert.deepEqual(encodeBusesAndDevices(read.value), bytes, name);
  }
  for (const name of [
    "buses_and_devices_write_0x0003",
    "buses_and_devices_empty_0x0003",
  ]) {
    const bytes = published(name);
    const written = decodeBusesAndDevicesWrite(bytes);
    assert.ok(written.ok, name);
    assert.deepEqual(encodeBusesAndDevices(written.value), bytes, name);
  }
});

test("the published site reads back to the fields its description names", () => {
  const read = decodeBusesAndDevicesRead(published("busesanddevices_0x0003"));
  assert.ok(read.ok);
  const site: BusesAndDevicesRead = read.value;
  assert.equal(checkBusesAndDevices(site, RULES), undefined);
  assert.deepEqual(
    site.buses.map((bus) => [bus.bus, bus.rate]),
    [
      [1, 9600],
      [2, 500_000],
    ],
  );
  assert.deepEqual(
    site.devices.map((device) => [device.dev, device.product, device.dialect]),
    [
      [1, Product.PZEM_017, Dialect.PZEM_DC],
      [2, Product.EPEVER_TRACER_B, Dialect.EPEVER_B],
      [4, Product.VICTRON_MPPT_RS, Dialect.VICTRON_MPPT_RS_HEX],
    ],
  );
  assert.equal(
    site.devices[1]?.options?.currentDirection,
    Direction.PositiveIsIn,
  );
  assert.equal(site.devices[2]?.addr, undefined);
  assert.equal(site.devices[2]?.options?.veDirect3v3, true);
});

test("the published write adds a device with no dev and moves dev 1", () => {
  const written = decodeBusesAndDevicesWrite(
    published("buses_and_devices_write_0x0003"),
  );
  assert.ok(written.ok);
  assert.deepEqual(
    written.value.devices.map((device) => [device.dev, device.addr?.[0]]),
    [
      [1, 5],
      [2, 2],
      [undefined, 6],
    ],
  );
  assert.equal(checkBusesAndDevices(written.value, RULES), undefined);
});

test("the widest published body is 901 bytes and refused as a closed parent chain", () => {
  const bytes = published("buses_and_devices_widest_0x0003");
  assert.equal(bytes.length, 901);
  const read = decodeBusesAndDevicesRead(bytes);
  assert.ok(read.ok);
  assert.equal(read.value.devices.length, MAX_CONFIG_DEVICES);
  const refusal = checkBusesAndDevices(read.value, {
    buses: Array.from({ length: 8 }, (_, i) => ({
      bus: 24 + i,
      transport: Transport.Rs485,
    })),
    dialects: [
      {
        dialect: 0xf002,
        transports: [Transport.Rs485],
        options: [
          DeviceOption.CurrentDirection,
          DeviceOption.PylontechVersion,
          DeviceOption.VeDirect3v3,
          DeviceOption.PollPeriod,
        ],
        minPollMs: 1000,
      },
    ],
    maxDevices: 24,
    maxTopologyDepth: 4,
  });
  assert.equal(refusal?.reason, "parent_loop");
  assertInvalid(refusal);
});

test("every combination of bus settings and options round-trips", () => {
  for (let mask = 1; mask < 16; mask += 1) {
    const bit = (n: number) => (mask & (1 << n)) !== 0;
    const section: BusesAndDevicesWrite = {
      buses: [
        {
          bus: 1,
          ...(bit(0) ? { rate: 0xffff_ffff } : {}),
          ...(bit(1) ? { dataBits: 7 as const } : {}),
          ...(bit(2) ? { parity: Parity.Odd } : {}),
          ...(bit(3) ? { stopBits: 1 as const } : {}),
        },
      ],
      devices: [
        {
          ...meter(0xffff, 0xff),
          options: {
            ...(bit(0) ? { currentDirection: Direction.PositiveIsOut } : {}),
            ...(bit(1) ? { pylontechVersion: PylontechVersion.V13 } : {}),
            ...(bit(2) ? { veDirect3v3: false } : {}),
            ...(bit(3) ? { pollPeriodMs: 0xffff_ffff } : {}),
          },
        },
      ],
    };
    const decoded = decodeBusesAndDevicesWrite(encodeBusesAndDevices(section));
    assert.ok(decoded.ok, `mask ${mask}`);
    assert.deepEqual(decoded.value, section, `mask ${mask}`);
  }
});

test("every truncation of a body is refused", () => {
  const bytes = published("busesanddevices_0x0003");
  for (let length = 0; length < bytes.length; length += 1) {
    assert.ok(
      !decodeBusesAndDevicesRead(bytes.subarray(0, length)).ok,
      `a ${length}-byte prefix decoded`,
    );
  }
});

test("a flipped bit anywhere is answered, never thrown", () => {
  const bytes = published("busesanddevices_0x0003");
  for (let at = 0; at < bytes.length; at += 1) {
    for (let bit = 0; bit < 8; bit += 1) {
      const flipped = bytes.slice();
      flipped[at] = (flipped[at] ?? 0) ^ (1 << bit);
      decodeBusesAndDevicesRead(flipped);
      decodeBusesAndDevicesWrite(flipped);
    }
  }
});

test("a body of the wrong shape is error 1", () => {
  // {1: []} with no device list.
  assert.deepEqual(refused(decodeBusesAndDevicesWrite(hex("a1 01 80"))), {
    reason: "missing",
    key: "buses and devices devices",
  });
  // A device entry carrying `bus` twice.
  const twice = refused(
    decodeBusesAndDevicesWrite(
      hex("a2 01 80 02 81 a5 02 01 04 03 05 02 06 05 02 01"),
    ),
  );
  assertMalformed(twice);
  // A bus entry that sets nothing, and an options map with no key.
  assert.deepEqual(
    refused(decodeBusesAndDevicesWrite(hex("a2 01 81 a1 01 01 02 80"))),
    { reason: "nothing_set", key: "bus entry bus" },
  );
  assert.deepEqual(
    refused(
      decodeBusesAndDevicesWrite(
        hex("a2 01 80 02 81 a6 02 01 03 41 01 04 03 05 02 06 05 08 a0"),
      ),
    ),
    { reason: "nothing_set", key: "device entry options" },
  );
  // Parity 9 and protocol revision 3 are not allocated (P-014).
  const parity = refused(
    decodeBusesAndDevicesWrite(hex("a2 01 81 a2 01 01 04 09 02 80")),
  );
  assert.deepEqual(parity, {
    reason: "unknown_value",
    key: "bus entry parity",
  });
  assertMalformed(parity);
  const version = refused(
    decodeBusesAndDevicesWrite(
      hex("a2 01 80 02 81 a5 02 02 04 01 05 19 f0 a0 06 04 08 a1 02 03"),
    ),
  );
  assertMalformed(version);
});

test("P-101: structure is judged before values", () => {
  // A rate of 0, then a device missing its product: malformed, not invalid.
  const both = refused(
    decodeBusesAndDevicesWrite(
      hex("a2 01 81 a2 01 01 02 00 02 81 a3 02 03 05 04 06 01"),
    ),
  );
  assert.deepEqual(both, { reason: "missing", key: "device entry product" });
  assertMalformed(both);
});

test("P-261: a bus the board lacks, a bus twice, or a setting its transport lacks is invalid", () => {
  const unknown: BusesAndDevicesWrite = {
    buses: [{ bus: 7, rate: 9600 }],
    devices: [],
  };
  assert.deepEqual(checkBusesAndDevices(unknown, RULES), {
    reason: "unknown_bus",
    bus: 7,
  });
  assertInvalid(checkBusesAndDevices(unknown, RULES));
  const twice: BusesAndDevicesWrite = {
    buses: [
      { bus: 1, rate: 9600 },
      { bus: 1, stopBits: 2 },
    ],
    devices: [],
  };
  assert.equal(checkBusesAndDevices(twice, RULES)?.reason, "bus_twice");
  const rateOnIp: BusesAndDevicesWrite = {
    buses: [{ bus: 4, rate: 9600 }],
    devices: [],
  };
  assert.deepEqual(checkBusesAndDevices(rateOnIp, RULES), {
    reason: "not_on_transport",
    bus: 4,
    key: "bus entry rate",
  });
  const framingOnCan: BusesAndDevicesWrite = {
    buses: [{ bus: 2, rate: 500_000, dataBits: 8 }],
    devices: [],
  };
  assert.equal(
    checkBusesAndDevices(framingOnCan, RULES)?.reason,
    "not_on_transport",
  );
  // A rate of 0 and nine data bits are refused where they are read.
  assertInvalid(
    refused(decodeBusesAndDevicesWrite(hex("a2 01 81 a2 01 01 02 00 02 80"))),
  );
  assertInvalid(
    refused(decodeBusesAndDevicesWrite(hex("a2 01 81 a2 01 01 03 09 02 80"))),
  );
});

test("P-262: an answer lists every dev, ascending, and a client refuses one that does not", () => {
  const noDev = refused(
    decodeBusesAndDevicesRead(
      encodeBusesAndDevices(write(meter(undefined, 1))),
    ),
  );
  assert.deepEqual(noDev, { reason: "missing", key: "device entry dev" });
  assertMalformed(noDev);
  const backwards = refused(
    decodeBusesAndDevicesRead(
      encodeBusesAndDevices(write(meter(2, 2), meter(1, 1))),
    ),
  );
  assert.deepEqual(backwards, {
    reason: "out_of_order",
    key: "device entry dev",
  });
  assertMalformed(backwards);
  assert.equal(
    checkBusesAndDevices(write(meter(1, 1), meter(1, 3)), RULES)?.reason,
    "dev_twice",
  );
});

test("P-264: an undeclared option, one the dialect lacks, a short poll and a sign with no direction are invalid", () => {
  const undeclared = refused(
    decodeBusesAndDevicesWrite(
      hex("a2 01 80 02 81 a6 02 01 03 41 01 04 03 05 02 06 05 08 a1 09 01"),
    ),
  );
  assert.deepEqual(undeclared, { reason: "unknown_option", option: 9n });
  assertInvalid(undeclared);

  const versionOnAMeter = write({
    ...meter(undefined, 1),
    options: { pylontechVersion: PylontechVersion.V12 },
  });
  assert.deepEqual(checkBusesAndDevices(versionOnAMeter, RULES), {
    reason: "option_not_in_dialect",
    option: DeviceOption.PylontechVersion,
    dialect: Dialect.PZEM_DC,
  });
  const pylontech = write({
    ...pack(undefined, 1),
    bus: 2,
    dialect: PYLONTECH_STAND_IN,
    options: {
      pylontechVersion: PylontechVersion.V12,
      currentDirection: Direction.PositiveIsIn,
    },
  });
  assert.equal(checkBusesAndDevices(pylontech, RULES), undefined);

  const poll = (pollPeriodMs: number) =>
    write({ ...meter(undefined, 1), options: { pollPeriodMs } });
  assert.equal(checkBusesAndDevices(poll(500), RULES), undefined);
  assert.deepEqual(checkBusesAndDevices(poll(499), RULES), {
    reason: "poll_too_short",
    dialect: Dialect.PZEM_DC,
    min: 500,
  });

  const magnitude = refused(
    decodeBusesAndDevicesWrite(
      hex("a2 01 80 02 81 a6 02 01 03 41 02 04 04 05 03 06 01 08 a1 01 03"),
    ),
  );
  assert.deepEqual(magnitude, {
    reason: "out_of_schema",
    key: "device option current_direction",
  });
  assertInvalid(magnitude);
});

test("P-265: a missing bus, an address against P-202, or a dialect the bus cannot carry is invalid", () => {
  const nowhere = write({ ...meter(undefined, 1), bus: 9 });
  assert.deepEqual(checkBusesAndDevices(nowhere, RULES), {
    reason: "unknown_bus",
    bus: 9,
  });
  const { addr: _, ...unaddressed } = meter(undefined, 1);
  assert.equal(
    checkBusesAndDevices(write(unaddressed), RULES)?.reason,
    "addr_required",
  );
  const onVeDirect = write({
    dev: undefined,
    bus: 3,
    addr: Uint8Array.of(1),
    product: Product.VICTRON_MPPT_RS,
    dialect: Dialect.VICTRON_MPPT_RS_HEX,
    role: DeviceRole.SOLAR_CHARGER,
  });
  assert.equal(
    checkBusesAndDevices(onVeDirect, RULES)?.reason,
    "addr_not_addressed",
  );
  const twice = checkBusesAndDevices(
    write(meter(undefined, 1), pack(undefined, 1)),
    RULES,
  );
  assert.deepEqual(twice, { reason: "addr_twice", bus: 1 });
  assertInvalid(twice);
  const apart = write(meter(undefined, 1), {
    ...pack(undefined, 1),
    bus: 2,
    dialect: PYLONTECH_STAND_IN,
  });
  assert.equal(checkBusesAndDevices(apart, RULES), undefined);

  const onCan = checkBusesAndDevices(
    write({ ...meter(undefined, 1), bus: 2 }),
    RULES,
  );
  assert.deepEqual(onCan, {
    reason: "dialect_not_carried",
    dialect: Dialect.PZEM_DC,
    bus: 2,
  });
  assertInvalid(onCan);
  const undriven = write({
    ...pack(undefined, 1),
    dialect: Dialect.MORNINGSTAR_SUNSAVER_DUO,
  });
  assert.equal(
    checkBusesAndDevices(undriven, RULES)?.reason,
    "dialect_not_carried",
  );
});

test("P-265: a parent not listed, a loop and a chain past the depth are invalid", () => {
  assert.deepEqual(checkBusesAndDevices(write(pack(2, 1, 7)), RULES), {
    reason: "parent_not_listed",
    dev: 7,
  });
  assert.deepEqual(checkBusesAndDevices(write(pack(2, 1, 2)), RULES), {
    reason: "parent_loop",
    dev: 2,
  });
  const chain = (length: number) =>
    write(
      ...Array.from({ length }, (_, i) =>
        pack(i + 1, i + 1, i === 0 ? undefined : i),
      ),
    );
  assert.equal(checkBusesAndDevices(chain(4), RULES), undefined);
  const deep = checkBusesAndDevices(chain(5), RULES);
  assert.deepEqual(deep, { reason: "too_deep", dev: 5 });
  assertInvalid(deep);
});

test("P-265: MAX_CONFIG_DEVICES and max_devices, each at the limit and one over", () => {
  const devices = (count: number) =>
    Array.from({ length: count }, (_, i) => meter(undefined, i + 1));
  assert.equal(
    checkBusesAndDevices(write(...devices(MAX_CONFIG_DEVICES)), RULES),
    undefined,
  );
  const over = checkBusesAndDevices(
    write(...devices(MAX_CONFIG_DEVICES + 1)),
    RULES,
  );
  assert.deepEqual(over, {
    reason: "too_many",
    key: "buses and devices devices",
  });
  assertInvalid(over);

  // Seventeen on the wire decode to the end and are refused invalid.
  const onTheWire = refused(
    decodeBusesAndDevicesWrite(
      encodeBusesAndDevices(write(...devices(MAX_CONFIG_DEVICES + 1))),
    ),
  );
  assert.deepEqual(onTheWire, {
    reason: "too_many",
    key: "buses and devices devices",
  });
  assertInvalid(onTheWire);

  const reported = { ...RULES, maxDevices: 3 };
  assert.equal(checkBusesAndDevices(write(...devices(3)), reported), undefined);
  assert.equal(
    checkBusesAndDevices(write(...devices(4)), reported)?.reason,
    "too_many",
  );
});

test("a map key outside the signed 64-bit range is error 1, as Rust refuses it", () => {
  // An unknown section key 2^63: Rust cannot read it as a key at all.
  const sectionKey = refused(
    decodeBusesAndDevicesWrite(
      hex("a3 01 80 02 80 1b 80 00 00 00 00 00 00 00 00"),
    ),
  );
  assert.deepEqual(sectionKey, {
    reason: "cbor",
    failure: "integer_out_of_range",
  });
  assertMalformed(sectionKey);
  // The same key in an options map is error 1 too, not an unknown option.
  const optionKey = refused(
    decodeBusesAndDevicesWrite(
      hex(
        "a2 01 80 02 81 a5 02 01 04 03 05 02 06 05 08 a1 1b 80 00 00 00 00 00 00 00 00",
      ),
    ),
  );
  assert.deepEqual(optionKey, {
    reason: "cbor",
    failure: "integer_out_of_range",
  });
  // i64::MAX itself is a key, unknown and skipped; below i64::MIN is not.
  assert.ok(
    decodeBusesAndDevicesWrite(
      hex("a3 01 80 02 80 1b 7f ff ff ff ff ff ff ff 00"),
    ).ok,
  );
  assert.deepEqual(
    refused(
      decodeBusesAndDevicesWrite(
        hex("a3 01 80 02 80 3b 80 00 00 00 00 00 00 00 00"),
      ),
    ),
    { reason: "cbor", failure: "integer_out_of_range" },
  );
});

test("the check refuses what the decoder would, for a body built by hand", () => {
  const bus = (entry: Partial<BusesAndDevicesWrite["buses"][number]>) =>
    checkBusesAndDevices({ buses: [{ bus: 1, ...entry }], devices: [] }, RULES);
  assert.deepEqual(bus({ rate: 0 }), {
    reason: "out_of_schema",
    key: "bus entry rate",
  });
  assert.deepEqual(bus({ dataBits: 9 as 8 }), {
    reason: "out_of_schema",
    key: "bus entry data_bits",
  });
  assert.deepEqual(bus({ stopBits: 3 as 2 }), {
    reason: "out_of_schema",
    key: "bus entry stop_bits",
  });
  assertInvalid(bus({ rate: 0 }));

  const device = (entry: Partial<DeviceEntry<number | undefined>>) =>
    checkBusesAndDevices(write({ ...meter(undefined, 1), ...entry }), RULES);
  assert.deepEqual(device({ addr: new Uint8Array() }), {
    reason: "out_of_schema",
    key: "device entry addr",
  });
  assert.deepEqual(device({ addr: new Uint8Array(9) }), {
    reason: "out_of_schema",
    key: "device entry addr",
  });
  assert.deepEqual(device({ dev: 0 }), {
    reason: "out_of_schema",
    key: "device entry dev",
  });
  assert.deepEqual(device({ parent: 0 }), {
    reason: "out_of_schema",
    key: "device entry parent",
  });

  const nine: BusesAndDevicesWrite = {
    buses: Array.from({ length: 9 }, (_, i) => ({ bus: i + 1, rate: 9600 })),
    devices: [],
  };
  const board = {
    ...RULES,
    buses: Array.from({ length: 9 }, (_, i) => ({
      bus: i + 1,
      transport: Transport.Rs485,
    })),
  };
  assert.deepEqual(checkBusesAndDevices(nine, board), {
    reason: "too_many",
    key: "buses and devices buses",
  });
  assertInvalid(checkBusesAndDevices(nine, board));
  assert.equal(
    checkBusesAndDevices({ ...nine, buses: nine.buses.slice(0, 8) }, board),
    undefined,
  );
  // Nine on the wire decode to the end and are refused the same way.
  assert.deepEqual(
    refused(decodeBusesAndDevicesWrite(encodeBusesAndDevices(nine))),
    {
      reason: "too_many",
      key: "buses and devices buses",
    },
  );
});

test("an answer whose buses do not ascend is refused", () => {
  const backwards = refused(
    decodeBusesAndDevicesRead(
      encodeBusesAndDevices({
        buses: [
          { bus: 2, rate: 500_000 },
          { bus: 1, rate: 9600 },
        ],
        devices: [],
      }),
    ),
  );
  assert.deepEqual(backwards, { reason: "out_of_order", key: "bus entry bus" });
  assertMalformed(backwards);
});

test("a device breaking several value rules is refused for dev, then addr, then parent", () => {
  // dev 0, an empty addr and parent 0 in one entry: Rust notes dev first.
  const all = refused(
    decodeBusesAndDevicesWrite(
      hex("a2 01 80 02 81 a7 01 00 02 01 03 40 04 03 05 02 06 05 07 00"),
    ),
  );
  assert.deepEqual(all, { reason: "out_of_schema", key: "device entry dev" });
  const addrAndParent = refused(
    decodeBusesAndDevicesWrite(
      hex("a2 01 80 02 81 a6 02 01 03 40 04 03 05 02 06 05 07 00"),
    ),
  );
  assert.deepEqual(addrAndParent, {
    reason: "out_of_schema",
    key: "device entry addr",
  });
});

test("the check refuses a bus entry that sets nothing, as the decoder does", () => {
  const bare = checkBusesAndDevices(
    { buses: [{ bus: 1 }], devices: [] },
    RULES,
  );
  assert.deepEqual(bare, { reason: "nothing_set", key: "bus entry bus" });
  assert.ok(bare);
  assertMalformed(bare);
});

test("the check refuses a number wider than its field, as the Rust decoder does", () => {
  const tooWide = { reason: "cbor", failure: "integer_out_of_range" };
  const device = (entry: Partial<DeviceEntry<number | undefined>>) =>
    checkBusesAndDevices(write({ ...meter(undefined, 1), ...entry }), RULES);
  assert.deepEqual(device({ product: 0x1_0000 }), tooWide);
  assert.deepEqual(device({ dialect: -1 }), tooWide);
  assert.deepEqual(device({ role: 1.5 }), tooWide);
  assert.deepEqual(device({ dev: 0x1_0000 }), tooWide);
  assert.deepEqual(device({ parent: 0x1_0000 }), tooWide);
  assert.deepEqual(device({ bus: 256 }), tooWide);
  assert.deepEqual(device({ options: { pollPeriodMs: 2 ** 32 } }), tooWide);
  assert.deepEqual(
    checkBusesAndDevices(
      { buses: [{ bus: 256, rate: 9600 }], devices: [] },
      RULES,
    ),
    tooWide,
  );
  assert.deepEqual(
    checkBusesAndDevices(
      { buses: [{ bus: 1, rate: 2 ** 32 }], devices: [] },
      RULES,
    ),
    tooWide,
  );
  const refusal = device({ product: 0x1_0000 });
  assert.ok(refusal);
  assertMalformed(refusal);
});

test("a loop the checked device only hangs off is named where it closes", () => {
  assert.deepEqual(
    checkBusesAndDevices(
      write(pack(1, 1, 2), pack(2, 2, 3), pack(3, 3, 2)),
      RULES,
    ),
    { reason: "parent_loop", dev: 2 },
  );
});

test("the check refuses an enum value the registry does not allocate, as the decoder does", () => {
  const parity = checkBusesAndDevices(
    { buses: [{ bus: 1, parity: 99 as Parity }], devices: [] },
    RULES,
  );
  assert.deepEqual(parity, {
    reason: "unknown_value",
    key: "bus entry parity",
  });
  assert.ok(parity);
  assertMalformed(parity);
  const device = (options: DeviceEntry<number | undefined>["options"]) =>
    checkBusesAndDevices(
      write({
        ...pack(undefined, 1),
        bus: 2,
        dialect: PYLONTECH_STAND_IN,
        ...(options ? { options } : {}),
      }),
      RULES,
    );
  assert.deepEqual(device({ pylontechVersion: 9 as PylontechVersion }), {
    reason: "unknown_value",
    key: "device option pylontech_version",
  });
  assert.deepEqual(device({ currentDirection: 9 as Direction.PositiveIsIn }), {
    reason: "unknown_value",
    key: "device option current_direction",
  });
  const magnitude = device({
    currentDirection: Direction.MagnitudeOnly as Direction.PositiveIsIn,
  });
  assert.deepEqual(magnitude, {
    reason: "out_of_schema",
    key: "device option current_direction",
  });
  assertInvalid(magnitude);
});
