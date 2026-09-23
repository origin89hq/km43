# @origin89/km43

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
