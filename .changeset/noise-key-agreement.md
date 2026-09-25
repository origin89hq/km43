---
"@origin89/km43": minor
---

Pairing and sessions now run Noise key agreement, and every message after a handshake is sealed with ChaCha20-Poly1305 (origin89hq/km43#128). The bindings follow the registry:

- `MessageType.Enrol` (`0x13`) and `MessageType.EnrolResponse` (`0x93`) carry pairing message 3 and the sealed enrolment result.
- `ErrorCode.BadMAC` is now `ErrorCode.AuthenticationFailed` (still `0x0a`), and `ErrorCode.UnsupportedSuite` (`0x13`) refuses a suite the controller does not run.
- `Pair.BadProof` is withdrawn: a wrong label is answered with error 10. `Pair.Proceed` (`6`) carries message 2, and `Pair.NotStored` (`7`) says the controller could not write the slot and the client should retry.
- `Suite.X25519ChachapolySha256` (`1`) is the one suite.
- Conditions `ENTROPY_UNAVAILABLE` and `CLIENT_TABLE_WRITE_FAILED` name two new controller concerns.

A client built against 0.7 cannot pair with or open a session on a controller speaking this version, and the QR label format is now version 2 with the controller key's fingerprint.
