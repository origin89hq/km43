---
"@origin89/km43": minor
---

Config section `0x0003` buses and devices can be read and written.

- `@origin89/km43/buses-and-devices` encodes the section and decodes it in both shapes: `decodeBusesAndDevicesWrite` for a `SetConfig` body, where a device with no `dev` is one to add, and `decodeBusesAndDevicesRead` for a `Config` answer, which must list every `dev` in ascending order.
- `checkBusesAndDevices` runs the checks the controller makes against the board's buses, its dialect table and the caps from `Hello`, so a client can find an outcome 3 refusal before it writes. `sectionAnswer` says whether a refusal is error 1 or outcome 3.
- New registry values: `DeviceOption`, `Parity`, `PylontechVersion`, and the limits `MAX_CONFIG_BUSES` (8), `MAX_CONFIG_DEVICES` (16), `MAX_ADDR`, `MAX_DEPTH` and `MAX_STRING`. `ConfigSection.BusesAndDevices` is no longer reserved.

A device option key the device's dialect does not define is refused, not skipped. A client built against an earlier version that sends only the keys it knows is unaffected.
