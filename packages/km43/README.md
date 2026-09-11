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

What this package does not do: frame, authenticate or decode a message. The
wire is bytes, CBOR, a MAC and a CRC, and the reference implementation of all
of that is the `km43` Rust crate. These bindings are the vocabulary a client
needs to read what that crate produces and to name what it asks for.

The generated file is the whole package. It is regenerated whenever the
registry changes and published under a new version, so pin the version you
built against: a renumbering is a breaking change and is released as one.

The specification, the registry and the published test vectors are in the
[km43 repository](https://github.com/origin89hq/km43). Licensed under either
MIT or Apache-2.0, at your option; both texts ship in the package.
