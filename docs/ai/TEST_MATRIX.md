# TunnelProxy — Test Matrix

> Canonical list of capabilities and their test status. **Do not mark a
> capability as tested unless the test actually exists in the
> repository.** Status meanings:

- `—` not implemented
- `planned` scoped for a future session, no test yet
- `unit` unit tests exist
- `integration` cross-crate integration tests exist
- `e2e` end-to-end tests exist

| Capability                       | Unit | Integration | E2E | Notes                                   |
|----------------------------------|------|-------------|-----|-----------------------------------------|
| Workspace compiles and lints     | ✅   | —           | —   | Foundation-only checks in Session 01.   |
| Per-crate placeholder unit tests | ✅   | —           | —   | Identifiers / status enums.             |
| TCP networking                   | —    | —           | —   | Planned for Session 02.                 |
| Bidirectional streaming          | —    | —           | —   | Planned for Session 02.                 |
| HTTP reverse proxy               | —    | —           | —   | Planned after Session 02.               |
| Tunnel protocol framing          | —    | —           | —   | Planned for Session 02 (ADR-005).       |
| Agent ↔ Edge connection          | —    | —           | —   | Planned for Session 02.                 |
| Tunnel registration              | —    | —           | —   | Planned with control-plane work.        |
| Multiplexing                     | —    | —           | —   | Deferred until simple tunnel works.     |
| Reconnect                        | —    | —           | —   | Deferred until a stable tunnel exists.  |
| Backpressure                     | —    | —           | —   | INV-002; deferred with streaming.       |
| TLS                              | —    | —           | —   | Out of foundation scope.                |
| Authentication                   | —    | —           | —   | INV-003; deferred.                      |
| Request inspection               | —    | —           | —   | Deferred to V1.                         |
