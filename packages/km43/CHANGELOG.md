# @origin89/km43

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
