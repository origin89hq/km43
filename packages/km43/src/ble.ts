/** Bounded BLE values; adapters own discovery, FIFO stack admission and connection cleanup. */
import {
  BLE_INDEX_MASK,
  BLE_LAST_FLAG,
  BLE_MAX_MTU,
  BLE_MAX_VALUE,
  BLE_MIN_MTU,
  BLE_TIMEOUT_MS,
  MAX_PAYLOAD,
} from "./generated.js";

export {
  BLE_MAX_MTU,
  BLE_MAX_VALUE,
  BLE_MIN_MTU,
  BLE_TIMEOUT_MS,
  BLE_TX_CAPACITY,
  MAX_PAYLOAD as BLE_MAX_PAYLOAD,
} from "./generated.js";

/** Transport errors never stand for controller authorization or remote receipt. */
export type BleFailure =
  | "mtu"
  | "value_limit"
  | "length"
  | "sequence"
  | "busy"
  | "buffer"
  | "idle";
/** A whole message is delivered only after its final fragment. */
export type BleReceiveResult =
  | {
      /** The receiver retained a partial message. */
      status: "pending";
    }
  | {
      /** The final fragment completed a message. */
      status: "message";
      /** Owned envelope bytes, still requiring decoding and authentication. */
      bytes: Uint8Array;
    }
  | {
      /** The rejected fragment cleared the partial assembly. */
      status: "length" | "sequence" | "mtu";
    };

/** Validates an ATT MTU, returning a value length including the two KM43 bytes. */
export function bleValueLength(mtu: number): number | undefined {
  return Number.isInteger(mtu) && mtu >= BLE_MIN_MTU && mtu <= BLE_MAX_MTU
    ? Math.min(mtu - 3, BLE_MAX_VALUE)
    : undefined;
}

/** A selected transmit value length that remains fixed for one queued message. */
export class BleValueLimit {
  readonly #length: number;

  private constructor(length: number) {
    this.#length = length;
  }

  /** Use a platform's value length directly, including the two KM43 header bytes. */
  static fromValueLength(length: number): BleValueLimit | undefined {
    if (
      !Number.isInteger(length) ||
      length < BLE_MIN_MTU - 3 ||
      length > BLE_MAX_VALUE
    )
      return undefined;
    return new BleValueLimit(length);
  }

  /** Validate a selected length against a known MTU, or use its maximum when omitted. */
  static fromMtu(
    mtu: number,
    selectedLength?: number,
  ): BleValueLimit | undefined {
    const maximum = bleValueLength(mtu);
    if (maximum === undefined) return undefined;
    const selected = selectedLength ?? maximum;
    if (selected > maximum) return undefined;
    return BleValueLimit.fromValueLength(selected);
  }

  /** Includes KM43's header; subtract it only when sizing fragment data. */
  get valueLength(): number {
    return this.#length;
  }
}

/** One assembly per receiving direction; disconnect must reset it. */
export class BleReceiver {
  private readonly bytes = new Uint8Array(MAX_PAYLOAD);
  private length = 0;
  private active: { id: number; index: number; at: number } | undefined;

  /** Drops partial state when the connection or subscription is lost. */
  reset(): void {
    this.active = undefined;
    this.length = 0;
  }

  /** Drive from a monotonic millisecond timer even without incoming values. */
  expire(nowMs: number): void {
    if (
      this.active &&
      (!Number.isSafeInteger(nowMs) ||
        nowMs < this.active.at ||
        nowMs - this.active.at >= BLE_TIMEOUT_MS)
    )
      this.reset();
  }

  /** Returns an owned completed message; callers still decode and authenticate it. */
  receive(value: Uint8Array, mtu: number, nowMs: number): BleReceiveResult {
    this.expire(nowMs);
    const limit = bleValueLength(mtu);
    const id = value.at(0);
    const flags = value.at(1);
    if (limit === undefined) return this.reject("mtu");
    if (
      !Number.isSafeInteger(nowMs) ||
      nowMs < 0 ||
      id === undefined ||
      flags === undefined ||
      value.length < 3 ||
      value.length > limit
    )
      return this.reject("length");
    const index = flags & BLE_INDEX_MASK;
    const last = (flags & BLE_LAST_FLAG) !== 0;
    if (this.active && this.active.id !== id) this.reset();
    if (index !== (this.active?.index ?? 0)) return this.reject("sequence");
    if (!this.active) this.length = 0;
    const end = this.length + value.length - 2;
    if (
      end > MAX_PAYLOAD ||
      (!last && (end === MAX_PAYLOAD || index === BLE_INDEX_MASK))
    ) {
      return this.reject("length");
    }
    this.bytes.set(value.subarray(2), this.length);
    this.length = end;
    if (last) {
      this.active = undefined;
      return { status: "message", bytes: this.bytes.slice(0, end) };
    }
    this.active = { id, index: index + 1, at: nowMs };
    return { status: "pending" };
  }

  private reject(status: "length" | "sequence" | "mtu"): BleReceiveResult {
    this.reset();
    return { status };
  }
}

/** A successful offer gives the number of bytes written without advancing the queue. */
export type BleFragmentResult =
  | {
      /** A value was offered without advancing the queue. */
      status: "ok";
      /** Initialized bytes in the caller's destination. */
      length: number;
    }
  | {
      /** No value was offered and queue state was preserved. */
      status: "idle" | "buffer";
    };

/** One owned message slot; a full queue refuses admission without eviction. */
export class BleSender {
  private readonly bytes = new Uint8Array(MAX_PAYLOAD);
  private nextId = 0;
  private pending:
    | {
        length: number;
        offset: number;
        index: number;
        limit: number;
        offered: number | undefined;
      }
    | undefined;

  /** Keeps the prior message intact on every refusal. */
  enqueue(message: Uint8Array, limit: BleValueLimit): "ok" | BleFailure {
    if (this.pending) return "busy";
    if (message.length === 0 || message.length > MAX_PAYLOAD) return "length";
    this.bytes.set(message);
    this.pending = {
      length: message.length,
      offset: 0,
      index: 0,
      limit: limit.valueLength,
      offered: undefined,
    };
    return "ok";
  }

  /** While the stack is busy, repeated calls write identical values. */
  fragment(out: Uint8Array): BleFragmentResult {
    const pending = this.pending;
    if (!pending) return { status: "idle" };
    const end = Math.min(pending.length, pending.offset + pending.limit - 2);
    const length = end - pending.offset + 2;
    if (out.length < length) return { status: "buffer" };
    out.set([
      this.nextId,
      pending.index | (end === pending.length ? BLE_LAST_FLAG : 0),
    ]);
    out.set(this.bytes.subarray(pending.offset, end), 2);
    pending.offered = end;
    return { status: "ok", length };
  }

  /** Call only after successful FIFO stack admission, never merely after an offer. */
  accepted(): "ok" | "idle" {
    const pending = this.pending;
    if (!pending || pending.offered === undefined) return "idle";
    if (pending.offered === pending.length) {
      this.pending = undefined;
      this.nextId = (this.nextId + 1) % 256;
    } else {
      pending.offset = pending.offered;
      pending.index += 1;
      pending.offered = undefined;
    }
    return "ok";
  }

  /** The adapter also purges stack queues and cancels old connection callbacks. */
  reset(): void {
    this.pending = undefined;
    this.nextId = 0;
  }
}
