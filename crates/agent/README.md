# `tunnelproxy-agent` / `tunnelproxy`

Local TunnelProxy Agent library and shared CLI runtime.

## Responsibility

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
configuration. Sessions 40–42 add authenticated managed-hostname lifecycle and
single-process HTTP orchestration. Session 43 moves the driver into the library
so the backwards-compatible `tunnelproxy-agent` and canonical `tunnelproxy`
wrappers cannot diverge, then adds strict bounded local config v1 and offline
TLS validation. Automatic account/config provisioning, DNS/public-certificate
automation, and external reachability probing remain unimplemented.

See [`../../docs/AGENT_CONFIG.md`](../../docs/AGENT_CONFIG.md) for the local
config schema and platform path resolution.
