---
name: protocol-change
description: Change the wire protocol — messages, fields, framing, auth. Use when touching PROTOCOL.md or anything that crosses a link.
---

# Changing the protocol

Read [docs/PROTOCOL.md](../../../docs/PROTOCOL.md). A fielded unit will meet a newer app, and neither side can be updated first.

## The rules that cannot be broken

- **Integer keys only. Never reuse a number.** A retired field's number is retired forever.
- **Unknown keys are skipped, not rejected.** v1 must survive v2's extra fields, and vice versa.
- **New fields are optional.** If a field's absence has no sane default, it is a new message type — not a new field.
- **The envelope is fixed forever.** It is an array. Anything that needs to change belongs in a body.
- **Bump the minor for an addition, the major only when old clients genuinely cannot cope.** A major bump refuses sessions.

## Every write is signed

If you add a message that changes anything — configuration, firmware, time, pairing, a command — it goes on the signed list and the MAC covers its type. Authenticating one write and not another is a locked door beside an open one.

## The check that catches the real bugs

**Read the spec back and confirm every field it promises actually exists.**

Two holes got through review this way: `HelloAck` told clients to read a counter that was not in its body, and `Hello` referenced a challenge that `Discover` never sent. Prose describing a property the wire format does not deliver is the failure mode of this document.

## After changing it

- Round-trip tests over every length, and a decode test for every truncation.
- Garbage input must never panic — a resynchronising receiver hands you arbitrary bytes.
- Update the message table, the error codes, and the limits table in the same commit.
