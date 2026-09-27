---
"@origin89/km43": minor
---

Adds `Condition.VENDOR_FAULT` (`0x0019`), a fault the source reported that no other condition means, and `conditionNeedsVendorCode(cond)`. A `Concern` carrying `VENDOR_FAULT` is valid only with its vendor code and namespace (keys 11 and 12); treat one without them as malformed. The function returns `false` for every other condition, including ones this build does not know.
