---
"@origin89/km43": minor
---

Adds `Dialect.VE_DIRECT_TEXT` (`0x000B`), `Dialect.PYLONTECH_CAN` (`0x000C`) and `Dialect.DS18B20` (`0x000D`), and `Product.DS18B20` (`0x000D`). All four are reserved: the numbers are fixed, and none of them says which Victron or Pylontech device is on the bus, which protocol version a pack speaks or which way its current is signed. A DS18B20 probe is its own device on a `onewire` bus, addressed by its 8-byte ROM code, and `onewire` is now an addressed transport under P-202. No existing number moved.
