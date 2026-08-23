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

The library opens an outbound TCP connection to Edge, performs the v2
HELLO → REGISTER → REGISTERED handshake, and exposes an established
`AgentSession`. It validates Edge PING and returns the matching PONG. Session 09
adds `AgentSession::run_multiplexed`, which connects concurrent Edge-opened
streams to one configured local TCP service with bounded queues and DATA
frames, half-close, and per-stream reset/cleanup. Session 12 adds
`AgentRuntime` and the runnable `tunnelproxy-agent` binary with validated CLI
configuration and Ctrl-C/SIGTERM shutdown. Session 13 adds cancellable bounded
exponential reconnect with downward jitter, a stable-session failure-streak
reset, an optional consecutive-failure budget, and reconnect outcome counters.
Session 14 adds optional mutual TLS with trusted-CA/server-name verification,
an Agent client certificate, ALPN, bounded TLS negotiation, and terminal
certificate/authentication failures. Plaintext process configuration is limited
to loopback. Session 15 sends bounded `AgentId`/`TunnelId` registration intent,
classifies authorization rejection for reconnect, and preserves the durable
tunnel identity across fresh ephemeral sessions. Persistent control-plane
configuration, certificate lifecycle automation, and the final
`tunnelproxy http` UX remain unimplemented.
