# @origin89/km43

The numbers of the [KM43 protocol](https://github.com/origin89hq/km43) as
TypeScript: every message type, outcome, error code, metric kind, capability
bit and enum member the registry allocates, generated from `protocol.toml` by
the same tool that generates the Rust crate's bindings. A number lives in one
place, so a client and a controller cannot disagree about what `0x8F` means.

```sh
pnpm add @origin89/km43
```

```ts
import { MessageType, MetricKind, LinkErrorCode, datasetName } from "@origin89/km43";

MessageType.ConcernsResponse; // 0x8f
MetricKind.DC_VOLTAGE;        // 0x0101
LinkErrorCode.BeforeLinkUp;   // 0x102

// The public equipment dataset's name for a reading, by kind, domain and role.
datasetName(MetricKind.DC_VOLTAGE, 0x01, 0x0003); // "battery-voltage"
```

The root export contains generated protocol identifiers. `@origin89/km43/ble`
adds `BleReceiver`, `BleSender` and `bleValueLength` for bounded BLE value
fragmentation. It does not decode CBOR or authenticate messages. BLE connection
or bonding grants no KM43 permission.

For each connection, create one receiver and sender. Pass the negotiated ATT
MTU (23 until exchange completes). `enqueue` owns a copy and refuses while busy;
`fragment` fills a caller-owned buffer without advancing; call `accepted` only
when the platform accepts those bytes into its ordered FIFO. Retry the same
fragment after backpressure. Feed received values and monotonic milliseconds to
`receive`, and call `expire` from a timer even when no values arrive. Reset both
objects on disconnect, notification disable or controller loss, and purge the
platform queue and old callbacks. The adapter must close a connection after
5000 ms without transmit progress; these classes do not run platform timers.

Discover the generated `BLE_SERVICE_UUID`, `BLE_RX_UUID` and `BLE_TX_UUID`, then
subscribe before sending Discover. Adapters whose APIs expose value length
instead of ATT MTU must account for that distinction as specified in
PROTOCOL.md. Rust and TypeScript tests consume the same `ble` action traces in
`docs/protocol/vectors/v1.json`; native phone and radio qualification remains
tracked by km43#81 and firmware#96. Host trace agreement is not BLE conformance.

Generated identifiers carry registry documentation and are regenerated together
with the Rust bindings. Pin the package version used by the client.

The specification, the registry and the published test vectors are in the
[km43 repository](https://github.com/origin89hq/km43). Licensed under either
MIT or Apache-2.0, at your option; both texts ship in the package.
