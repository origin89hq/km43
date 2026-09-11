![KM43 — a green kilometre marker beside a misty forest lake, with Buddy canoeing in the distance](https://raw.githubusercontent.com/origin89hq/brand/6d54a262123b170d27b2ba6e94a8f227f1f49ddf/situations/scenes/km43-canoe/km43-social.jpg)

# KM43

KM43 is the bounded, authenticated message protocol between an Origin89
controller and its clients. It is link-agnostic: UART, WebSocket, USB, BLE and
MQTT change the framing beneath it, not the message semantics above it. The
reasoning is in the [protocol rationale](docs/PROTOCOL-RATIONALE.md); the
controller that speaks it lives in
[origin89](https://github.com/origin89hq/origin89).

The specification is a normative draft. Nothing has shipped, so a wire format,
a number and a public signature are all free to change until the first paired
unit freezes key derivation, protocol versioning and serial numbers.

| Part | What it holds | Where |
| --- | --- | --- |
| Specification | The wire, message by message, and the controller–comms link | [`docs/PROTOCOL.md`](docs/PROTOCOL.md), [`docs/protocol/LINK.md`](docs/protocol/LINK.md) |
| Registry | Every allocated number, in the one file that owns them | [`crates/km43/protocol.toml`](crates/km43/protocol.toml), rendered as [`REGISTRY.md`](docs/protocol/REGISTRY.md) and [`MAP.md`](docs/protocol/MAP.md) |
| Vectors | Known-good bytes from a generator that never imports the implementation | [`docs/protocol/vectors/`](docs/protocol/vectors/) |
| Implementation | `km43`, a `no_std` crate with no allocator, built for the host and for the controller's Cortex-M0+ | [`crates/km43/`](crates/km43/) |
| Bindings | TypeScript types generated from the registry | [`packages/km43/`](packages/km43/) |
| Gate | The consistency checks CI runs, and the generators | [`crates/xtask/`](crates/xtask/) |

## Commands

`just --list` shows every recipe. `just check` runs what CI runs: formatting,
Clippy, the tests, rustdoc under deny-warnings, the TypeScript checks and
`cargo xtask check`, the specification gate that cross-compiles the crate for
the target and refuses a registry, a vector or a binding that disagrees with
the spec. `just registry`
and `just vectors` regenerate the committed artefacts after a change to
`protocol.toml` or to a generator; the gate refuses a checkout where they are
stale.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and the rules a protocol
change has to keep.

## Consumers

A consumer pins a version of this repository, and a change here reaches it
when the consumer moves its pin, not before. The controller in origin89 still
builds from its own copy of the crate until it is rewritten against this one.

## License

Code is licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. The specification and the other
documents under `docs/` are Origin89's original technical documentation; their
public-release terms are still to be confirmed and are not implied by the code
license.

The banner and social preview are Origin89 artwork, covered by the
[brand-use terms](https://github.com/origin89hq/brand/blob/main/LICENSE.md).
