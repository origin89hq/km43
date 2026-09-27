/**
 * `0x0003 buses and devices`: what is wired to the controller and how to talk
 * to it. A client reads the controller's answer with
 * {@link decodeBusesAndDevicesRead}, edits it, checks it with
 * {@link checkBusesAndDevices} and writes it back. A device the client adds
 * carries no `dev`: the controller gives it one (P-262), and the next `Config`
 * says which.
 */
import { CborError, type CborFailure, CborReader, CborWriter } from "./cbor.js";
import {
  DeviceOption,
  Direction,
  ErrorCode,
  MAX_ADDR,
  MAX_CONFIG_BUSES,
  MAX_CONFIG_DEVICES,
  Parity,
  PylontechVersion,
  SetConfig,
  Transport,
} from "./generated.js";

/** The settings of one bus the board has (P-261). A setting left out is what the devices' dialects require. */
export interface BusEntry {
  /** Key 1, the inventory's `BusRow` key 1. */
  bus: number;
  /** Key 2, bit/s. */
  rate?: number;
  /** Key 3. */
  dataBits?: 7 | 8;
  /** Key 4. */
  parity?: Parity;
  /** Key 5. */
  stopBits?: 1 | 2;
}

/** Which way the battery current a device reports counts positive. */
export type CurrentDirection = Direction.PositiveIsIn | Direction.PositiveIsOut;

/** One device's options (P-264). An option left out is never guessed by the controller. */
export interface DeviceOptions {
  /** Option 1. */
  currentDirection?: CurrentDirection;
  /** Option 2. */
  pylontechVersion?: PylontechVersion;
  /** Option 3: the product's VE.Direct port runs at 3.3 V. */
  veDirect3v3?: boolean;
  /** Option 4, milliseconds between polls. */
  pollPeriodMs?: number;
}

/** One configured device. `D` is `number | undefined` in a write and `number` in an answer. */
export interface DeviceEntry<D extends number | undefined> {
  /** Key 1, the controller's id; a write leaves it out to add a device (P-262). */
  dev: D;
  /** Key 2. */
  bus: number;
  /** Key 3, present exactly on an addressed transport (P-202). */
  addr?: Uint8Array;
  /** Key 4, a `Product` value. */
  product: number;
  /** Key 5, a `Dialect` value. */
  dialect: number;
  /** Key 6, a `DeviceRole` value. */
  role: number;
  /** Key 7, another entry's `dev`. */
  parent?: number;
  /** Key 8; left out when no option is set. */
  options?: DeviceOptions;
}

/** The section's two lists. */
export interface BusesAndDevices<D extends number | undefined> {
  /** Key 1, at most {@link MAX_CONFIG_BUSES}. */
  buses: BusEntry[];
  /** Key 2, at most {@link MAX_CONFIG_DEVICES}. */
  devices: DeviceEntry<D>[];
}

/** The section as `SetConfig` writes it. */
export type BusesAndDevicesWrite = BusesAndDevices<number | undefined>;

/** The section as `Config` answers with it: every device has its `dev`. */
export type BusesAndDevicesRead = BusesAndDevices<number>;

export type { CborFailure } from "./cbor.js";

/** The CBOR underneath was refused. Always error 1. */
export interface CborRefusal {
  /** What went wrong. */
  reason: "cbor";
  /** Which rule the bytes broke. */
  failure: CborFailure;
}

/** A refusal about one key, named `entry key` as the Rust crate names it. */
export interface KeyRefusal {
  /** What went wrong. */
  reason:
    | "missing"
    | "duplicate"
    | "nothing_set"
    | "unknown_value"
    | "out_of_order"
    | "out_of_schema"
    | "too_many";
  /** The key to blame. */
  key: string;
}

/** An option key this document has not allocated (P-264). */
export interface UnknownOptionRefusal {
  /** What went wrong. */
  reason: "unknown_option";
  /** The key as it arrived. */
  option: bigint;
}

/** A refusal about one bus. */
export interface BusRefusal {
  /** What went wrong. */
  reason:
    | "unknown_bus"
    | "bus_twice"
    | "addr_required"
    | "addr_not_addressed"
    | "addr_twice";
  /** The bus. */
  bus: number;
}

/** A setting the bus's transport does not have (P-261). */
export interface TransportRefusal {
  /** What went wrong. */
  reason: "not_on_transport";
  /** The bus. */
  bus: number;
  /** The setting. */
  key: string;
}

/** A dialect the controller cannot drive over this bus, or at all (P-265). */
export interface DialectRefusal {
  /** What went wrong. */
  reason: "dialect_not_carried";
  /** The dialect. */
  dialect: number;
  /** The bus it was put on. */
  bus: number;
}

/** An option the device's dialect does not define (P-264). */
export interface OptionRefusal {
  /** What went wrong. */
  reason: "option_not_in_dialect";
  /** The option. */
  option: DeviceOption;
  /** The dialect. */
  dialect: number;
}

/** A poll period below the dialect's minimum (P-264). */
export interface PollRefusal {
  /** What went wrong. */
  reason: "poll_too_short";
  /** The dialect. */
  dialect: number;
  /** Its minimum, in milliseconds. */
  min: number;
}

/** A refusal about one device id or its parent chain (P-262, P-265). */
export interface DevRefusal {
  /** What went wrong. */
  reason: "dev_twice" | "parent_not_listed" | "parent_loop" | "too_deep";
  /** The device, 0 when it is one the write adds. */
  dev: number;
}

/** Why a body was refused. */
export type BusesAndDevicesRefusal =
  | CborRefusal
  | KeyRefusal
  | UnknownOptionRefusal
  | BusRefusal
  | TransportRefusal
  | DialectRefusal
  | OptionRefusal
  | PollRefusal
  | DevRefusal;

/** Error 1: the body is not the schema's shape. */
export interface MalformedAnswer {
  /** An `Error 0xFF`. */
  kind: "error";
  /** Its code. */
  code: ErrorCode.MalformedFrame;
}

/** Outcome 3: a body the schema forbids, and nothing stored. */
export interface InvalidAnswer {
  /** A `SetConfigAck`. */
  kind: "outcome";
  /** Its outcome. */
  outcome: SetConfig.Invalid;
}

/** How the controller answers a refused write (P-101). */
export type SectionAnswer = MalformedAnswer | InvalidAnswer;

/** A body that decoded. */
export interface DecodedBody<T> {
  /** It decoded. */
  ok: true;
  /** The body. */
  value: T;
}

/** A body that was refused. */
export interface RefusedBody {
  /** It did not decode. */
  ok: false;
  /** Why. */
  refusal: BusesAndDevicesRefusal;
}

/** A decoded body, or why it was refused. */
export type Decoded<T> = DecodedBody<T> | RefusedBody;

/** A bus the board has, as its inventory `BusRow` lists it. */
export interface BoardBus {
  /** `BusRow` key 1. */
  bus: number;
  /** `BusRow` key 2. */
  transport: Transport;
}

/** What the controller's driver for one dialect accepts. */
export interface DialectRule {
  /** The dialect. */
  dialect: number;
  /** The transports it can be carried over. */
  transports: readonly Transport[];
  /** The option keys it defines; any other is refused (P-264). */
  options: readonly DeviceOption[];
  /** The shortest poll period it accepts, in milliseconds. */
  minPollMs: number;
}

/** What a body is checked against that it does not carry. */
export interface SiteRules {
  /** The buses the inventory lists. */
  buses: readonly BoardBus[];
  /** One rule per dialect the controller drives; a dialect with none is one it cannot drive. */
  dialects: readonly DialectRule[];
  /** `max_devices`, `HelloReport` key 21. */
  maxDevices: number;
  /** `max_topology_depth`, `HelloReport` key 29: devices one parent chain may hold, its end included. */
  maxTopologyDepth: number;
}

/** The answer a controller gives a write refused for this reason. */
export function sectionAnswer(refusal: BusesAndDevicesRefusal): SectionAnswer {
  switch (refusal.reason) {
    case "cbor":
    case "missing":
    case "duplicate":
    case "nothing_set":
    case "unknown_value":
    case "out_of_order":
      return { kind: "error", code: ErrorCode.MalformedFrame };
    case "out_of_schema":
    case "too_many":
    case "unknown_option":
    case "unknown_bus":
    case "bus_twice":
    case "addr_required":
    case "addr_not_addressed":
    case "addr_twice":
    case "not_on_transport":
    case "dialect_not_carried":
    case "option_not_in_dialect":
    case "poll_too_short":
    case "dev_twice":
    case "parent_not_listed":
    case "parent_loop":
    case "too_deep":
      return { kind: "outcome", outcome: SetConfig.Invalid };
    default: {
      const unreachable: never = refusal;
      throw new Error(`unhandled refusal ${JSON.stringify(unreachable)}`);
    }
  }
}

/** Thrown inside the decoder for a refusal that ends it at once. */
class Refused extends Error {
  readonly refusal: BusesAndDevicesRefusal;

  constructor(refusal: BusesAndDevicesRefusal) {
    super(refusal.reason);
    this.refusal = refusal;
  }
}

/** The first value-level refusal met while the structure is still being read (P-101). */
class Invalid {
  first: BusesAndDevicesRefusal | undefined;

  note(refusal: BusesAndDevicesRefusal): void {
    this.first ??= refusal;
  }
}

const U8 = 0xff;
const U16 = 0xffff;
const U32 = 0xffff_ffff;

function isParity(value: number): value is Parity {
  return value === Parity.None || value === Parity.Even || value === Parity.Odd;
}

function isPylontechVersion(value: number): value is PylontechVersion {
  return value === PylontechVersion.V12 || value === PylontechVersion.V13;
}

function isDirection(value: number): value is Direction {
  return (
    value === Direction.PositiveIsIn ||
    value === Direction.PositiveIsOut ||
    value === Direction.MagnitudeOnly
  );
}

function deviceOption(key: bigint): DeviceOption | undefined {
  switch (key) {
    case BigInt(DeviceOption.CurrentDirection):
      return DeviceOption.CurrentDirection;
    case BigInt(DeviceOption.PylontechVersion):
      return DeviceOption.PylontechVersion;
    case BigInt(DeviceOption.VeDirect3v3):
      return DeviceOption.VeDirect3v3;
    case BigInt(DeviceOption.PollPeriod):
      return DeviceOption.PollPeriod;
    default:
      return undefined;
  }
}

function missing(key: string): Refused {
  return new Refused({ reason: "missing", key });
}

function once<T>(slot: T | undefined, key: string, value: T): T {
  if (slot !== undefined) {
    throw new Refused({ reason: "duplicate", key });
  }
  return value;
}

/**
 * One body being read: the reader, the first value-level refusal held back
 * while the structure is still being checked, and which shape is expected.
 */
class BodyReader {
  readonly #cbor: CborReader;
  readonly #invalid = new Invalid();
  readonly #answer: boolean;

  constructor(bytes: Uint8Array, answer: boolean) {
    this.#cbor = new CborReader(bytes);
    this.#answer = answer;
  }

  bus(): BusEntry {
    const cbor = this.#cbor;
    const invalid = this.#invalid;
    let bus: number | undefined;
    let rate: number | undefined;
    let dataBits: number | undefined;
    let parity: Parity | undefined;
    let stopBits: number | undefined;
    cbor.entries((key) => {
      switch (key) {
        case 1n:
          bus = once(bus, "bus entry bus", cbor.uint(U8));
          return;
        case 2n:
          rate = once(rate, "bus entry rate", cbor.uint(U32));
          return;
        case 3n:
          dataBits = once(dataBits, "bus entry data_bits", cbor.uint(U8));
          return;
        case 4n: {
          const value = cbor.uint(U8);
          if (!isParity(value)) {
            throw new Refused({
              reason: "unknown_value",
              key: "bus entry parity",
            });
          }
          parity = once(parity, "bus entry parity", value);
          return;
        }
        case 5n:
          stopBits = once(stopBits, "bus entry stop_bits", cbor.uint(U8));
          return;
        default:
          cbor.skip();
      }
    });
    if (bus === undefined) {
      throw missing("bus entry bus");
    }
    if (
      rate === undefined &&
      dataBits === undefined &&
      parity === undefined &&
      stopBits === undefined
    ) {
      throw new Refused({ reason: "nothing_set", key: "bus entry bus" });
    }
    const entry: BusEntry = { bus };
    if (rate !== undefined) {
      if (rate === 0) {
        invalid.note({ reason: "out_of_schema", key: "bus entry rate" });
      }
      entry.rate = rate;
    }
    if (dataBits !== undefined) {
      if (dataBits === 7 || dataBits === 8) {
        entry.dataBits = dataBits;
      } else {
        invalid.note({ reason: "out_of_schema", key: "bus entry data_bits" });
      }
    }
    if (parity !== undefined) {
      entry.parity = parity;
    }
    if (stopBits !== undefined) {
      if (stopBits === 1 || stopBits === 2) {
        entry.stopBits = stopBits;
      } else {
        invalid.note({ reason: "out_of_schema", key: "bus entry stop_bits" });
      }
    }
    return entry;
  }

  options(): DeviceOptions {
    const cbor = this.#cbor;
    const invalid = this.#invalid;
    const options: DeviceOptions = {};
    let count = 0;
    let direction: Direction | undefined;
    cbor.entries((key) => {
      count += 1;
      const option = deviceOption(key);
      switch (option) {
        case undefined:
          // Refused, not skipped: skipping is a setting the client sent and
          // the controller never used (P-264).
          invalid.note({ reason: "unknown_option", option: key });
          cbor.skip();
          return;
        case DeviceOption.CurrentDirection: {
          const value = cbor.uint(U8);
          if (!isDirection(value)) {
            throw new Refused({
              reason: "unknown_value",
              key: "device option current_direction",
            });
          }
          direction = value;
          return;
        }
        case DeviceOption.PylontechVersion: {
          const value = cbor.uint(U8);
          if (!isPylontechVersion(value)) {
            throw new Refused({
              reason: "unknown_value",
              key: "device option pylontech_version",
            });
          }
          options.pylontechVersion = value;
          return;
        }
        case DeviceOption.VeDirect3v3:
          options.veDirect3v3 = cbor.bool();
          return;
        case DeviceOption.PollPeriod:
          options.pollPeriodMs = cbor.uint(U32);
          return;
        default: {
          const unreachable: never = option;
          throw new Error(`unhandled option ${unreachable}`);
        }
      }
    });
    if (count === 0) {
      throw new Refused({ reason: "nothing_set", key: "device entry options" });
    }
    switch (direction) {
      case undefined:
        break;
      case Direction.PositiveIsIn:
      case Direction.PositiveIsOut:
        options.currentDirection = direction;
        break;
      case Direction.MagnitudeOnly:
        invalid.note({
          reason: "out_of_schema",
          key: "device option current_direction",
        });
        break;
      default: {
        const unreachable: never = direction;
        throw new Error(`unhandled direction ${unreachable}`);
      }
    }
    return options;
  }

  device(): DeviceEntry<number | undefined> {
    const cbor = this.#cbor;
    const invalid = this.#invalid;
    let dev: number | undefined;
    let bus: number | undefined;
    let addr: Uint8Array | undefined;
    let product: number | undefined;
    let dialect: number | undefined;
    let role: number | undefined;
    let parent: number | undefined;
    let options: DeviceOptions | undefined;
    cbor.entries((key) => {
      switch (key) {
        case 1n:
          dev = once(dev, "device entry dev", cbor.uint(U16));
          return;
        case 2n:
          bus = once(bus, "device entry bus", cbor.uint(U8));
          return;
        case 3n:
          addr = once(addr, "device entry addr", cbor.bytes());
          return;
        case 4n:
          product = once(product, "device entry product", cbor.uint(U16));
          return;
        case 5n:
          dialect = once(dialect, "device entry dialect", cbor.uint(U16));
          return;
        case 6n:
          role = once(role, "device entry role", cbor.uint(U16));
          return;
        case 7n:
          parent = once(parent, "device entry parent", cbor.uint(U16));
          return;
        case 8n:
          options = once(options, "device entry options", this.options());
          return;
        default:
          cbor.skip();
      }
    });
    if (product === undefined) {
      throw missing("device entry product");
    }
    if (dialect === undefined) {
      throw missing("device entry dialect");
    }
    if (role === undefined) {
      throw missing("device entry role");
    }
    if (bus === undefined) {
      throw missing("device entry bus");
    }
    if (this.#answer && dev === undefined) {
      throw missing("device entry dev");
    }
    if (dev === 0) {
      invalid.note({ reason: "out_of_schema", key: "device entry dev" });
    }
    if (addr !== undefined && (addr.length === 0 || addr.length > MAX_ADDR)) {
      invalid.note({ reason: "out_of_schema", key: "device entry addr" });
    }
    if (parent === 0) {
      invalid.note({ reason: "out_of_schema", key: "device entry parent" });
    }
    const entry: DeviceEntry<number | undefined> = {
      dev,
      bus,
      product,
      dialect,
      role,
    };
    if (addr !== undefined) {
      entry.addr = addr;
    }
    if (parent !== undefined) {
      entry.parent = parent;
    }
    if (options !== undefined) {
      entry.options = options;
    }
    return entry;
  }

  read(): Decoded<BusesAndDevicesWrite> {
    const cbor = this.#cbor;
    const invalid = this.#invalid;
    const section: BusesAndDevicesWrite = { buses: [], devices: [] };
    let buses = false;
    let devices = false;
    try {
      cbor.entries((key) => {
        switch (key) {
          case 1n: {
            buses = true;
            const count = cbor.array();
            for (let i = 0; i < count; i += 1) {
              const entry = this.bus();
              if (section.buses.length < MAX_CONFIG_BUSES) {
                section.buses.push(entry);
              } else {
                invalid.note({
                  reason: "too_many",
                  key: "buses and devices buses",
                });
              }
            }
            cbor.close();
            return;
          }
          case 2n: {
            devices = true;
            const count = cbor.array();
            for (let i = 0; i < count; i += 1) {
              const entry = this.device();
              if (section.devices.length < MAX_CONFIG_DEVICES) {
                section.devices.push(entry);
              } else {
                invalid.note({
                  reason: "too_many",
                  key: "buses and devices devices",
                });
              }
            }
            cbor.close();
            return;
          }
          default:
            cbor.skip();
        }
      });
      cbor.finish();
    } catch (error) {
      if (error instanceof CborError) {
        return {
          ok: false,
          refusal: { reason: "cbor", failure: error.failure },
        };
      }
      if (error instanceof Refused) {
        return { ok: false, refusal: error.refusal };
      }
      throw error;
    }
    if (!buses) {
      return {
        ok: false,
        refusal: { reason: "missing", key: "buses and devices buses" },
      };
    }
    if (!devices) {
      return {
        ok: false,
        refusal: { reason: "missing", key: "buses and devices devices" },
      };
    }
    if (invalid.first !== undefined) {
      return { ok: false, refusal: invalid.first };
    }
    return { ok: true, value: section };
  }
}

/** Read a `SetConfig` body: structure first, values after (P-101). */
export function decodeBusesAndDevicesWrite(
  bytes: Uint8Array,
): Decoded<BusesAndDevicesWrite> {
  return new BodyReader(bytes, false).read();
}

/**
 * Read a `Config` answer. Every device carries its `dev`, and buses and
 * devices ascend; an answer that breaks either is refused (P-262).
 */
export function decodeBusesAndDevicesRead(
  bytes: Uint8Array,
): Decoded<BusesAndDevicesRead> {
  const decoded = new BodyReader(bytes, true).read();
  if (!decoded.ok) {
    return decoded;
  }
  const devices: DeviceEntry<number>[] = [];
  for (const device of decoded.value.devices) {
    const { dev } = device;
    if (dev === undefined) {
      return {
        ok: false,
        refusal: { reason: "missing", key: "device entry dev" },
      };
    }
    devices.push({ ...device, dev });
  }
  const read: BusesAndDevicesRead = { buses: decoded.value.buses, devices };
  const refuse = (key: string): RefusedBody => ({
    ok: false,
    refusal: { reason: "out_of_order", key },
  });
  for (let i = 1; i < read.buses.length; i += 1) {
    const [before, after] = [read.buses[i - 1], read.buses[i]];
    if (
      before !== undefined &&
      after !== undefined &&
      before.bus >= after.bus
    ) {
      return refuse("bus entry bus");
    }
  }
  for (let i = 1; i < read.devices.length; i += 1) {
    const [before, after] = [read.devices[i - 1], read.devices[i]];
    if (
      before !== undefined &&
      after !== undefined &&
      before.dev >= after.dev
    ) {
      return refuse("device entry dev");
    }
  }
  return { ok: true, value: read };
}

function encodeOptions(cbor: CborWriter, options: DeviceOptions): void {
  const pairs = [
    options.currentDirection,
    options.pylontechVersion,
    options.veDirect3v3,
    options.pollPeriodMs,
  ].filter((value) => value !== undefined).length;
  cbor.map(pairs);
  if (options.currentDirection !== undefined) {
    cbor.uint(DeviceOption.CurrentDirection);
    cbor.uint(options.currentDirection);
  }
  if (options.pylontechVersion !== undefined) {
    cbor.uint(DeviceOption.PylontechVersion);
    cbor.uint(options.pylontechVersion);
  }
  if (options.veDirect3v3 !== undefined) {
    cbor.uint(DeviceOption.VeDirect3v3);
    cbor.bool(options.veDirect3v3);
  }
  if (options.pollPeriodMs !== undefined) {
    cbor.uint(DeviceOption.PollPeriod);
    cbor.uint(options.pollPeriodMs);
  }
}

/**
 * Encode a body, keys ascending (P-016). A device with no `dev` is written
 * without key 1, which in a write asks the controller to add it.
 */
export function encodeBusesAndDevices(
  section: BusesAndDevices<number | undefined>,
): Uint8Array {
  const cbor = new CborWriter();
  cbor.map(2);
  cbor.uint(1);
  cbor.array(section.buses.length);
  for (const bus of section.buses) {
    const settings = [bus.rate, bus.dataBits, bus.parity, bus.stopBits];
    cbor.map(1 + settings.filter((value) => value !== undefined).length);
    cbor.uint(1);
    cbor.uint(bus.bus);
    settings.forEach((value, index) => {
      if (value !== undefined) {
        cbor.uint(index + 2);
        cbor.uint(value);
      }
    });
  }
  cbor.uint(2);
  cbor.array(section.devices.length);
  for (const device of section.devices) {
    const options =
      setOptions(device.options).length > 0 ? device.options : undefined;
    const optional = [device.dev, device.addr, device.parent, options];
    cbor.map(4 + optional.filter((value) => value !== undefined).length);
    if (device.dev !== undefined) {
      cbor.uint(1);
      cbor.uint(device.dev);
    }
    cbor.uint(2);
    cbor.uint(device.bus);
    if (device.addr !== undefined) {
      cbor.uint(3);
      cbor.bytes(device.addr);
    }
    cbor.uint(4);
    cbor.uint(device.product);
    cbor.uint(5);
    cbor.uint(device.dialect);
    cbor.uint(6);
    cbor.uint(device.role);
    if (device.parent !== undefined) {
      cbor.uint(7);
      cbor.uint(device.parent);
    }
    if (options !== undefined) {
      cbor.uint(8);
      encodeOptions(cbor, options);
    }
  }
  return cbor.finish();
}

/**
 * What each transport lets a configuration say about a bus and its devices:
 * whether a device needs an `addr` (P-202), whether a `rate` means anything,
 * and whether it is a serial line with framing to set (P-261). A `Record` over
 * the enum, so a transport added to the registry does not compile until it is
 * given a row here.
 */
const TRANSPORTS: Record<
  Transport,
  { addressed: boolean; rate: boolean; serial: boolean }
> = {
  [Transport.Rs485]: { addressed: true, rate: true, serial: true },
  [Transport.Can]: { addressed: true, rate: true, serial: false },
  [Transport.VeDirect]: { addressed: false, rate: true, serial: true },
  [Transport.LocalIo]: { addressed: false, rate: false, serial: false },
  [Transport.Ip]: { addressed: true, rate: false, serial: false },
  [Transport.Onewire]: { addressed: false, rate: false, serial: false },
  [Transport.Internal]: { addressed: false, rate: false, serial: false },
};

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function setOptions(options: DeviceOptions | undefined): DeviceOption[] {
  const set: DeviceOption[] = [];
  if (options?.currentDirection !== undefined)
    set.push(DeviceOption.CurrentDirection);
  if (options?.pylontechVersion !== undefined)
    set.push(DeviceOption.PylontechVersion);
  if (options?.veDirect3v3 !== undefined) set.push(DeviceOption.VeDirect3v3);
  if (options?.pollPeriodMs !== undefined) set.push(DeviceOption.PollPeriod);
  return set;
}

/**
 * The rules the decoder applies to values, applied to a body built in memory.
 * The Rust types make these unrepresentable; these interfaces do not, so a
 * body a client edited is held to them here before the board is consulted.
 */
function schemaRefusal(
  section: BusesAndDevices<number | undefined>,
): BusesAndDevicesRefusal | undefined {
  const refuse = (key: string): BusesAndDevicesRefusal => ({
    reason: "out_of_schema",
    key,
  });
  if (section.buses.length > MAX_CONFIG_BUSES) {
    return { reason: "too_many", key: "buses and devices buses" };
  }
  for (const bus of section.buses) {
    if (bus.rate === 0) return refuse("bus entry rate");
    if (
      bus.dataBits !== undefined &&
      bus.dataBits !== 7 &&
      bus.dataBits !== 8
    ) {
      return refuse("bus entry data_bits");
    }
    if (
      bus.stopBits !== undefined &&
      bus.stopBits !== 1 &&
      bus.stopBits !== 2
    ) {
      return refuse("bus entry stop_bits");
    }
  }
  for (const device of section.devices) {
    if (device.dev === 0) return refuse("device entry dev");
    const { addr } = device;
    if (addr !== undefined && (addr.length === 0 || addr.length > MAX_ADDR)) {
      return refuse("device entry addr");
    }
    if (device.parent === 0) return refuse("device entry parent");
  }
  return undefined;
}

/**
 * Check a body against the values the decoder refuses and against what it
 * does not carry: the board's buses, the dialect table and the caps
 * `Hello 0x81` reports (P-261, P-264, P-265). The same
 * checks the controller makes, so a client can refuse a write before sending
 * one that would come back outcome 3.
 */
export function checkBusesAndDevices(
  section: BusesAndDevices<number | undefined>,
  rules: SiteRules,
): BusesAndDevicesRefusal | undefined {
  // The parent chain above one device: every link a listed `dev`, never
  // back round, and no deeper than the reported depth (P-187).
  const chain = (
    device: DeviceEntry<number | undefined>,
  ): BusesAndDevicesRefusal | undefined => {
    const depth = rules.maxTopologyDepth;
    const start = device.dev;
    let held = 1;
    let next = device.parent;
    for (let step = 0; step < MAX_CONFIG_DEVICES; step += 1) {
      if (next === undefined) {
        return held > depth
          ? { reason: "too_deep", dev: start ?? 0 }
          : undefined;
      }
      if (next === start) {
        return { reason: "parent_loop", dev: next };
      }
      const parent = next;
      const above = section.devices.find((other) => other.dev === parent);
      if (above === undefined) {
        return { reason: "parent_not_listed", dev: parent };
      }
      held += 1;
      next = above.parent;
    }
    return { reason: "parent_loop", dev: start ?? 0 };
  };
  const values = schemaRefusal(section);
  if (values !== undefined) {
    return values;
  }
  const transportOf = (bus: number) =>
    rules.buses.find((board) => board.bus === bus)?.transport;
  for (const [index, entry] of section.buses.entries()) {
    const transport = transportOf(entry.bus);
    if (transport === undefined) {
      return { reason: "unknown_bus", bus: entry.bus };
    }
    if (
      section.buses.slice(index + 1).some((other) => other.bus === entry.bus)
    ) {
      return { reason: "bus_twice", bus: entry.bus };
    }
    if (entry.rate !== undefined && !TRANSPORTS[transport].rate) {
      return {
        reason: "not_on_transport",
        bus: entry.bus,
        key: "bus entry rate",
      };
    }
    if (!TRANSPORTS[transport].serial) {
      if (entry.dataBits !== undefined) {
        return {
          reason: "not_on_transport",
          bus: entry.bus,
          key: "bus entry data_bits",
        };
      }
      if (entry.parity !== undefined) {
        return {
          reason: "not_on_transport",
          bus: entry.bus,
          key: "bus entry parity",
        };
      }
      if (entry.stopBits !== undefined) {
        return {
          reason: "not_on_transport",
          bus: entry.bus,
          key: "bus entry stop_bits",
        };
      }
    }
  }
  if (
    section.devices.length > rules.maxDevices ||
    section.devices.length > MAX_CONFIG_DEVICES
  ) {
    return { reason: "too_many", key: "buses and devices devices" };
  }
  for (const [index, device] of section.devices.entries()) {
    const transport = transportOf(device.bus);
    if (transport === undefined) {
      return { reason: "unknown_bus", bus: device.bus };
    }
    const later = section.devices.slice(index + 1);
    if (device.addr === undefined && TRANSPORTS[transport].addressed) {
      return { reason: "addr_required", bus: device.bus };
    }
    if (device.addr !== undefined && !TRANSPORTS[transport].addressed) {
      return { reason: "addr_not_addressed", bus: device.bus };
    }
    const { addr } = device;
    if (
      addr !== undefined &&
      later.some(
        (other) =>
          other.bus === device.bus &&
          other.addr !== undefined &&
          sameBytes(other.addr, addr),
      )
    ) {
      return { reason: "addr_twice", bus: device.bus };
    }
    const rule = rules.dialects.find(
      (candidate) =>
        candidate.dialect === device.dialect &&
        candidate.transports.includes(transport),
    );
    if (rule === undefined) {
      return {
        reason: "dialect_not_carried",
        dialect: device.dialect,
        bus: device.bus,
      };
    }
    for (const option of setOptions(device.options)) {
      if (!rule.options.includes(option)) {
        return {
          reason: "option_not_in_dialect",
          option,
          dialect: device.dialect,
        };
      }
    }
    const period = device.options?.pollPeriodMs;
    if (period !== undefined && period < rule.minPollMs) {
      return {
        reason: "poll_too_short",
        dialect: device.dialect,
        min: rule.minPollMs,
      };
    }
    if (
      device.dev !== undefined &&
      later.some((other) => other.dev === device.dev)
    ) {
      return { reason: "dev_twice", dev: device.dev };
    }
  }
  for (const device of section.devices) {
    const refusal = chain(device);
    if (refusal !== undefined) {
      return refusal;
    }
  }
  return undefined;
}
