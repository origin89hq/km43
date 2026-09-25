---
"@origin89/km43": minor
---

Writes no longer carry a per-client counter (origin89hq/km43#131). A `SetConfig`, `Command`, `Firmware` or `Time` is sealed with its operation as the whole inner body, and the bindings follow the registry:

- `ErrorCode.CounterNotFresh` (`0x0b`) is retired and no longer exported.
- Condition `COUNTER_WRITE_FAILED` (`0x0012`) is retired; `DEDUP_WRITE_FAILED` (`0x0018`) names the concern raised when a command's dedup entry cannot be persisted.
- `HelloReport` key 11 is retired. A client skips it if an older controller still sends it.

A client built against the previous version cannot send a write this controller accepts.
