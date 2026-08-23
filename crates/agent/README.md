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
`AgentSession`. It validates Edge PING and returns the matching PONG. Session 09
adds `AgentSession::run_multiplexed`, which connects concurrent Edge-opened
streams to one configured local TCP service with bounded queues and DATA
frames, half-close, and per-stream reset/cleanup. Session 12 adds
`AgentRuntime` and the runnable `tunnelproxy-agent` binary with validated CLI
configuration and Ctrl-C/SIGTERM shutdown. Reconnect, TLS, authentication,
durable registration, and the final `tunnelproxy http` UX remain unimplemented.
