/**
 * The CBOR a configuration body is made of, and nothing wider: unsigned and
 * negative integers, byte and text strings, arrays, maps and the two booleans.
 * Floats, tags, `null` and indefinite lengths are refused (P-018), as is a map
 * that carries one key twice, at any depth, skipped or not (P-015).
 *
 * Internal to the package. A body codec reads through it and turns a
 * `CborError` into its own refusal.
 */
import { MAX_DEPTH, MAX_STRING } from "./generated.js";

/** Why a body's CBOR was refused. Every one of these is error 1. */
export type CborFailure =
  | "end_of_input"
  | "trailing_bytes"
  | "indefinite_length"
  | "tag_not_allowed"
  | "float_not_allowed"
  | "simple_value_not_allowed"
  | "reserved_head"
  | "key_not_integer"
  | "repeated_key"
  | "depth_exceeded"
  | "string_too_long"
  | "invalid_utf8"
  | "wrong_type"
  | "integer_out_of_range";

/** Thrown inside the reader and caught at the body codec's boundary. */
export class CborError extends Error {
  /** Which rule the bytes broke. */
  readonly failure: CborFailure;

  constructor(failure: CborFailure) {
    super(failure);
    this.failure = failure;
  }
}

const UNSIGNED = 0;
const NEGATIVE = 1;
const BYTES = 2;
const TEXT = 3;
const ARRAY = 4;
const MAP = 5;
const TAG = 6;
const SIMPLE = 7;

interface Head {
  major: number;
  /** The argument; above `Number.MAX_SAFE_INTEGER` only as a bigint. */
  argument: bigint;
}

/**
 * Whether `bytes` are well-formed UTF-8 (RFC 3629): no overlong form, no
 * surrogate, nothing past U+10FFFF. Written out because the package targets no
 * runtime with a text decoder in its types.
 */
function isUtf8(bytes: Uint8Array): boolean {
  let at = 0;
  while (at < bytes.length) {
    const lead = bytes[at] ?? 0;
    let length: number;
    let low = 0x80;
    let high = 0xbf;
    if (lead < 0x80) {
      at += 1;
      continue;
    } else if (lead >= 0xc2 && lead <= 0xdf) {
      length = 2;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      length = 3;
      if (lead === 0xe0) low = 0xa0;
      if (lead === 0xed) high = 0x9f;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      length = 4;
      if (lead === 0xf0) low = 0x90;
      if (lead === 0xf4) high = 0x8f;
    } else {
      return false;
    }
    for (let i = 1; i < length; i += 1) {
      const next = bytes[at + i];
      if (
        next === undefined ||
        next < (i === 1 ? low : 0x80) ||
        next > (i === 1 ? high : 0xbf)
      ) {
        return false;
      }
    }
    at += length;
  }
  return true;
}

/** Reads one body out of bytes that may be anything at all. */
export class CborReader {
  readonly #bytes: Uint8Array;
  #at = 0;
  #depth = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /** The pair count of a map; a decoder reads pairs through `entries`. */
  map(): number {
    return this.#container(MAP);
  }

  /** The element count of an array. */
  array(): number {
    return this.#container(ARRAY);
  }

  /** Close a container the caller has read every item of. */
  close(): void {
    this.#depth -= 1;
  }

  /**
   * Each pair of a map, keys checked for repeats before the caller sees the
   * next one. The callback reads or skips the value.
   */
  entries(read: (key: bigint) => void): void {
    const pairs = this.map();
    const seen = new Set<bigint>();
    for (let i = 0; i < pairs; i += 1) {
      const key = this.key();
      if (seen.has(key)) {
        throw new CborError("repeated_key");
      }
      seen.add(key);
      read(key);
    }
    this.close();
  }

  /** A map key: an integer and nothing else (P-011). */
  key(): bigint {
    const head = this.#head();
    switch (head.major) {
      case UNSIGNED:
        return head.argument;
      case NEGATIVE:
        return -1n - head.argument;
      default:
        throw new CborError("key_not_integer");
    }
  }

  /** An unsigned integer no larger than `max`. */
  uint(max: number): number {
    const head = this.#head();
    if (head.major === NEGATIVE) {
      throw new CborError("integer_out_of_range");
    }
    if (head.major !== UNSIGNED) {
      throw new CborError("wrong_type");
    }
    if (head.argument > BigInt(max)) {
      throw new CborError("integer_out_of_range");
    }
    return Number(head.argument);
  }

  /** `true` or `false`. */
  bool(): boolean {
    const byte = this.#byte();
    if (byte === 0xf5) {
      return true;
    }
    if (byte === 0xf4) {
      return false;
    }
    this.#at -= 1;
    this.#head();
    throw new CborError("wrong_type");
  }

  /** A byte string, copied out. */
  bytes(): Uint8Array {
    const head = this.#head();
    if (head.major !== BYTES) {
      throw new CborError("wrong_type");
    }
    return this.#take(head.argument).slice();
  }

  /** Step over one item of any shape, refusing what a decoder would refuse. */
  skip(): void {
    const head = this.#head();
    switch (head.major) {
      case UNSIGNED:
      case NEGATIVE:
        return;
      case BYTES:
        this.#take(head.argument);
        return;
      case TEXT:
        this.#text(head.argument);
        return;
      case ARRAY: {
        this.#enter();
        for (let i = 0n; i < head.argument; i += 1n) {
          this.skip();
        }
        this.close();
        return;
      }
      case MAP: {
        this.#enter();
        const seen = new Set<bigint>();
        for (let i = 0n; i < head.argument; i += 1n) {
          const key = this.key();
          if (seen.has(key)) {
            throw new CborError("repeated_key");
          }
          seen.add(key);
          this.skip();
        }
        this.close();
        return;
      }
      default:
        // `#head` refuses tags and every simple value but the booleans, and a
        // boolean is major 7 with no argument to step over.
        return;
    }
  }

  /** Refuse bytes left over after the body. */
  finish(): void {
    if (this.#at !== this.#bytes.length) {
      throw new CborError("trailing_bytes");
    }
  }

  #container(major: number): number {
    const head = this.#head();
    if (head.major !== major) {
      throw new CborError("wrong_type");
    }
    // Every item is at least one byte, so a count past what is left is a
    // truncated body, and refusing it here keeps a loop from running on it.
    if (head.argument > BigInt(this.#bytes.length - this.#at)) {
      throw new CborError("end_of_input");
    }
    this.#enter();
    return Number(head.argument);
  }

  #enter(): void {
    if (this.#depth >= MAX_DEPTH) {
      throw new CborError("depth_exceeded");
    }
    this.#depth += 1;
  }

  #byte(): number {
    const byte = this.#bytes[this.#at];
    if (byte === undefined) {
      throw new CborError("end_of_input");
    }
    this.#at += 1;
    return byte;
  }

  #head(): Head {
    const initial = this.#byte();
    const major = initial >> 5;
    const info = initial & 0x1f;
    if (major === TAG) {
      throw new CborError("tag_not_allowed");
    }
    if (major === SIMPLE) {
      if (info === 20 || info === 21) {
        return { major, argument: 0n };
      }
      if (info >= 25 && info <= 27) {
        throw new CborError("float_not_allowed");
      }
      if (info >= 28 && info <= 30) {
        throw new CborError("reserved_head");
      }
      if (info === 31) {
        throw new CborError("indefinite_length");
      }
      throw new CborError("simple_value_not_allowed");
    }
    if (info < 24) {
      return { major, argument: BigInt(info) };
    }
    if (info === 31) {
      throw new CborError("indefinite_length");
    }
    if (info > 27) {
      throw new CborError("reserved_head");
    }
    const width = 1 << (info - 24);
    let argument = 0n;
    for (let i = 0; i < width; i += 1) {
      argument = (argument << 8n) | BigInt(this.#byte());
    }
    return { major, argument };
  }

  #take(length: bigint): Uint8Array {
    if (length > BigInt(this.#bytes.length - this.#at)) {
      throw new CborError("end_of_input");
    }
    const start = this.#at;
    this.#at += Number(length);
    return this.#bytes.subarray(start, this.#at);
  }

  #text(length: bigint): void {
    if (length > BigInt(MAX_STRING)) {
      throw new CborError("string_too_long");
    }
    if (!isUtf8(this.#take(length))) {
      throw new CborError("invalid_utf8");
    }
  }
}

/** Writes deterministic CBOR (P-016); the caller writes keys ascending. */
export class CborWriter {
  readonly #out: number[] = [];

  /** Open a map of `pairs` key-value pairs. */
  map(pairs: number): void {
    this.#head(MAP, pairs);
  }

  /** Open an array of `length` items. */
  array(length: number): void {
    this.#head(ARRAY, length);
  }

  /** An unsigned integer in its shortest form. */
  uint(value: number): void {
    this.#head(UNSIGNED, value);
  }

  /** `true` or `false`. */
  bool(value: boolean): void {
    this.#out.push(value ? 0xf5 : 0xf4);
  }

  /** A byte string. */
  bytes(value: Uint8Array): void {
    this.#head(BYTES, value.length);
    this.#out.push(...value);
  }

  /** The encoded body. */
  finish(): Uint8Array {
    return Uint8Array.from(this.#out);
  }

  #head(major: number, value: number): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new RangeError(
        `${value} is not a CBOR argument this writer carries`,
      );
    }
    const top = major << 5;
    if (value < 24) {
      this.#out.push(top | value);
    } else if (value <= 0xff) {
      this.#out.push(top | 24, value);
    } else if (value <= 0xffff) {
      this.#out.push(top | 25, value >> 8, value & 0xff);
    } else {
      this.#out.push(
        top | 26,
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
      );
    }
  }
}
