---
"@origin89/km43": patch
---

`checkBusesAndDevices` now refuses a device on a `onewire` bus that carries no `addr`, as P-202 requires, with reason `addr_required` and outcome 3. It had treated 1-Wire as unaddressed, so a DS18B20 written without its ROM code passed the check and a write carrying one was refused as `addr_not_addressed`. A write whose 1-Wire devices carry their ROM codes is now accepted.
