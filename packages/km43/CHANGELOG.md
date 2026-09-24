# @origin89/km43

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
