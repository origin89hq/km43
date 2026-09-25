---
"@origin89/km43": minor
---

A controller can vouch for an enrolment so a site can link its generation (origin89hq/km43#135). The bindings follow the registry:

- `MessageType.Vouch` (`0x14`) carries a verifier's key, nonce and account binding, and `MessageType.VouchResponse` (`0x94`) the controller's tag over its epoch and the asking slot.
- `Vouch.Vouched` (`1`) and `Vouch.BadVerifier` (`2`) are its outcomes.

Every controller speaking this version answers `Vouch`; there is no capability bit to check first.
