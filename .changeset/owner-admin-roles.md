---
"@origin89/km43": minor
---

Clients now hold a role, and a site can be managed by people who never stand at its panel (origin89hq/km43#129). The bindings follow the registry:

- `Role` (`Owner`, `Admin`, `Viewer`) decides a client's capability mask; `ClientKind` is now only shown in the client list.
- `MessageType.Clients` (`0x14`), `Invite` (`0x15`), `Approve` (`0x16`) and `Remove` (`0x17`), with their responses, list clients, propose and approve invites, and remove an enrolment. The last three are signed.
- `Invite`, `Approve` and `Remove` outcome enums, and `InviteDecision`.
- `ClientCapability.READ_PRIVATE`, `INVITE` and `APPROVE`.
- `ErrorCode.RoleNotPermitted` (`0x14`) refuses a read the client's role does not allow.
- `EventKind.CLIENT_REMOVED` (`0x0605`) and `INVITE_PROPOSED` (`0x0606`) are new, and `CLIENT_ENROLLED` (`0x0603`) is now live.
