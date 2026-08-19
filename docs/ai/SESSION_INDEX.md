# TunnelProxy — Session Index

> One line per session. Update at the end of every session.

| Session | Title                              | Status   |
|---------|------------------------------------|----------|
| 01      | Foundation                         | current  |
| 02      | TCP Networking Foundation          | planned  |

## Session 01 — Foundation — current

See [`CURRENT_STATE.md`](CURRENT_STATE.md) for the truthful end-of-
session state. See [`../TECH_DEBT.md`](../TECH_DEBT.md) for the
deliberate shortcuts.

## Session 02 — TCP Networking Foundation — planned

Scope (subject to refinement when Session 02 begins):

- Add `tokio` as a workspace dependency where genuinely needed.
- Outbound agent → edge TCP tunnel, with bounded bidirectional
  streaming (INV-002).
- Initial framing in `tunnelproxy-protocol`.
- Timeout and cancellation on long-running operations (INV-005).
- Unit + integration tests for the streaming primitives.
- Update `TEST_MATRIX.md` and `CURRENT_STATE.md` to reflect real
  coverage.
