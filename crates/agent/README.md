# `tunnelproxy-agent`

Future local TunnelProxy agent / CLI runtime.

## Responsibility (future)

- Initiate outbound tunnel to Edge (INV-001).
- Register tunnel metadata with the control plane.
- Forward public request traffic to a local service.
- Surface developer UX (CLI: `tunnelproxy http 3000`).

## Prohibited

- Accepting inbound public connections directly. The agent must never be
  reachable from the public internet without going through Edge.
- Hard-coding protocol details that should live in
  `tunnelproxy-protocol`.
- Persisting user data beyond what the runtime strictly needs.

## Current state

Foundation-only. Today this is a library crate exposing a single
`build_identifier()` helper. No networking.
