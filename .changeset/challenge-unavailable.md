---
"@origin89/km43": minor
---

Add `ErrorCode.ChallengeUnavailable` for a readable refusal when `Discover` cannot return a valid challenge. Clients may accept this code as an unauthenticated retry hint; `BusyRetry` still requires a MAC.
