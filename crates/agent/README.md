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

The library opens an outbound TCP connection to Edge, performs the v1
HELLO → REGISTER → REGISTERED handshake, and exposes an established
`AgentSession`. Session 07 adds a heartbeat loop that validates Edge PING and
returns the matching PONG. Reconnect, local-service forwarding, traffic
streams, TLS, authentication, and the final CLI UX are not implemented yet.
