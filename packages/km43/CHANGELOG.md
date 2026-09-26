# @origin89/km43

## 0.8.1

### Patch Changes

- 9af5951: Doc comments only. A member the registry names without a meaning, such as `Firmware.Accepted`, now shows that name as code. `Suite.X25519ChachapolySha256` and `LinkErrorCode.BeforeLinkUp` quote the identifiers they mention, and `Quality.Estimated` spells out *state of charge*. No value, name or type changed.

## 0.8.0

### Minor Changes

- 1f44896: A controller can vouch for an enrolment so a site can link its generation (origin89hq/km43#135). The bindings follow the registry:
  
  - `MessageType.Vouch` (`0x14`) carries a verifier's key, nonce and account binding, and `MessageType.VouchResponse` (`0x94`) the controller's tag over its epoch and the asking slot.
  - `Vouch.Vouched` (`1`) and `Vouch.BadVerifier` (`2`) are its outcomes.
  
  Every controller speaking this version answers `Vouch`; there is no capability bit to check first.
- 34ac1df: Pairing and sessions now run Noise key agreement, and every message after a handshake is sealed with ChaCha20-Poly1305 (origin89hq/km43#128). The bindings follow the registry:
  
  - `MessageType.Enrol` (`0x13`) and `MessageType.EnrolResponse` (`0x93`) carry pairing message 3 and the sealed enrolment result.
  - `ErrorCode.BadMAC` is now `ErrorCode.AuthenticationFailed` (still `0x0a`), and `ErrorCode.UnsupportedSuite` (`0x13`) refuses a suite the controller does not run.
  - `Pair.BadProof` is withdrawn: a wrong label is answered with error 10. `Pair.Proceed` (`6`) carries message 2, and `Pair.NotStored` (`7`) says the controller could not write the slot and the client should retry.
  - `Suite.X25519ChachapolySha256` (`1`) is the one suite.
  - Conditions `ENTROPY_UNAVAILABLE` and `CLIENT_TABLE_WRITE_FAILED` name two new controller concerns.
  
  A client built against 0.7 cannot pair with or open a session on a controller speaking this version, and the QR label format is now version 2 with the controller key's fingerprint.
- 0f94f45: Clients now hold a role, and a site can be managed by people who never stand at its panel (origin89hq/km43#129). The bindings follow the registry:
  
  - `Role` (`Owner`, `Admin`, `Viewer`) decides a client's capability mask; `ClientKind` is now only shown in the client list.
  - `MessageType.Clients` (`0x18`), `Invite` (`0x15`), `Approve` (`0x16`) and `Remove` (`0x17`), with their responses, list clients, propose and approve invites, and remove an enrolment. The last three are signed.
  - `Invite`, `Approve` and `Remove` outcome enums, and `InviteDecision`.
  - `ClientCapability.READ_PRIVATE`, `INVITE` and `APPROVE`.
  - `ErrorCode.RoleNotPermitted` (`0x18`) refuses a read the client's role does not allow.
  - `EventKind.CLIENT_REMOVED` (`0x0605`) and `INVITE_PROPOSED` (`0x0606`) are new, and `CLIENT_ENROLLED` (`0x0603`) is now live.
- e88e538: Writes no longer carry a per-client counter (origin89hq/km43#131). A `SetConfig`, `Command`, `Firmware` or `Time` is sealed with its operation as the whole inner body, and the bindings follow the registry:
  
  - `ErrorCode.CounterNotFresh` (`0x0b`) is retired and no longer exported.
  - Condition `COUNTER_WRITE_FAILED` (`0x0012`) is retired; `DEDUP_WRITE_FAILED` (`0x0018`) names the concern raised when a command's dedup entry cannot be persisted.
  - `HelloReport` key 11 is retired. A client skips it if an older controller still sends it.
  
  A client built against the previous version cannot send a write this controller accepts.

## 0.7.0

### Minor Changes

- 0d30431: Add `WS_PORT`, `WS_PATH`, `DNSSD_SERVICE` and `DNSSD_TXT_DEVICE_ID`: where a client reaches the WebSocket transport on the site network. Browse for `_km43._tcp`, open `ws://<host>:80/km43`, and run `Discover` on every result before trusting it; a result whose `id` TXT value is not your controller's `device_id` can be skipped. The path applies on the controller's setup access point too, so a client that opened `ws://192.168.4.1/` there must request `/km43` against firmware that implements P-223.

## 0.6.0

### Minor Changes

- aa81d4d: Add `MessageType.WifiScan` and `MessageType.WifiStatus` with their responses, the `wifi status changed` event kind, `CapabilityBit.WifiScanAndJoinStatus`, and the `ScanState`, `ScanRefusal`, `WifiSecurity`, `WifiBand`, `WifiState` and `WifiFailure` enums. A setup client can list the networks the controller's radio hears and read whether it joined the one written, keyed by the network section version. When a controller does not set capability bit 8, keep manual SSID entry.

## 0.5.0

### Minor Changes

- b12ba02: Add `BehaviourKey`, whose `Shadow` member is the key every behaviour config section carries its `shadow` flag under. `ConfigSection.IdentityAndSite` and `ConfigSection.Network` are no longer marked reserved: their section bodies are now defined.

### Patch Changes

- b12ba02: `MessageType.GetConfig` and `MessageType.SetConfig` are no longer marked reserved: their bodies, and the bodies of the identity and network sections, are now defined.

## 0.4.0

### Minor Changes

- b929023: Add `ErrorCode.ChallengeUnavailable` for a readable refusal when `Discover` cannot return a valid challenge. Clients may accept this code as an unauthenticated retry hint; `BusyRetry` still requires a MAC.
- b7bea40: Add registered BLE UUIDs and a bounded fragmentation API under `@origin89/km43/ble`. Rust and TypeScript consume shared transport traces; phone and board interoperability remains unverified.

## 0.3.0

### Minor Changes

- b79dff9: Add the `COMMS_BOOT_NOISE` event kind for the non-frame byte count from a comms boot attempt.

### Patch Changes

- da021dc: Every export and member now carries a doc comment generated from the registry: what a message's auth label means and which constant answers it, what each outcome, error code and enum member means with the rule that produces it, a metric kind's unit and scale, an event kind's class, and a caveat on every reserved number. No number or name changed.

## 0.2.0

### Minor Changes

- b660cf2: `BootReason` follows what the controller can tell apart: `PowerOn` becomes
  `Power`, `BrownOut` is retired, and `PinReset`, `OptionByteReload`,
  `WindowWatchdog` and `LowPowerEntry` are added.

## 0.1.1

### Patch Changes

- bc18fe8: Ship a README in the package: what the bindings are, what they are not, and
  how to name a reading.

## 0.1.0

### Minor Changes

- 3acb1a4: First published version: the TypeScript bindings generated from the KM43
  registry, as ES modules with declarations.
