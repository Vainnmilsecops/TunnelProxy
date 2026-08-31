# TunnelProxy — AI Project Context

> Read this first in every AI-assisted session. Keep it short enough to
> read in one pass.

## Project purpose

TunnelProxy is a developer-first secure reverse-tunneling and
traffic-debugging platform. A developer runs a local `agent` binary
that opens an outbound tunnel to a public `edge` node, so a service
on `localhost:<port>` becomes reachable on
`https://<host>.tunnelproxy.dev`.

## Golden path

```
Internet Client
    |
    v
https://<host>.tunnelproxy.dev
    |
    v
TunnelProxy Edge
    |
    | persistent secure outbound tunnel
    v
TunnelProxy Agent
    |
    v
localhost:<port>
```

## Major components

- `tunnelproxy-common` — shared strongly-typed primitives.
- `tunnelproxy-protocol` — Edge ↔ Agent wire framing and control types.
- `tunnelproxy-agent` — local CLI / runtime that opens the tunnel.
- `tunnelproxy-edge` — public ingress and live tunnel routing.
- `tunnelproxy-control-plane` — durable users, agents, tunnels, auth,
  quotas.

## Architectural principles

1. The agent only ever initiates outbound connections (INV-001).
2. No unbounded buffering anywhere on the data plane (INV-002).
3. Secrets are never logged (INV-003).
4. Wire-format changes require an explicit protocol version bump
   (INV-004).
5. Long-running network operations must have timeout and cancellation
   semantics (INV-005).
6. State-changing HTTP requests are not auto-replayed without safe
   semantics (INV-006).
7. Per-request routing on the edge never depends on a database query
   (INV-007).
8. Blocking I/O is forbidden on Tokio async paths (INV-008).
9. Client-supplied forwarding headers are never trusted blindly
   (INV-009).
10. Meaningful features come with automated tests (INV-010).
11. Public listener exposure is explicit, authenticated where required, and
    bounded globally and per source (INV-011).

## Engineering priorities (in order)

1. **Correctness** — the system does what it claims and only what it
   claims.
2. **Bounded resource usage** — no code path can exhaust memory, file
   descriptors, or CPU regardless of input.
3. **Observability** — every cross-cutting operation is structured,
   traceable, and explainable after the fact.
4. **Developer ergonomics** — installing and running the agent must
   feel trivial.
5. **Performance** — only after the first four are honest.

## What is NOT in scope right now

Automated account provisioning, DNS/TLS automation, custom domains, dashboard,
billing, distributed/shared request-rate
coordination, request inspection, stream replay, protected issuer custody,
multi-edge ownership, and cloud deployment are explicitly **not implemented**.
Sessions 39–42 provide
durable managed-hostname allocation plus authenticated Agent-facing
allocate/release and independent atomic hostname server identity/Agent-CA
rotation on the existing route catalog, followed by single-process
`tunnelproxy-agent http <port>` orchestration. Session 43 adds the canonical
`tunnelproxy http <port>` wrapper and strict local config v1 with offline
validation. Session 44 adds opt-in bounded HTTP/2 termination at Edge with
HTTP/1.1 fallback and local translation. Session 45 adds separately opt-in
bounded HTTP/1.1 WebSocket upgrade with strict client/local handshake checks,
session capacity, idle time, and task-owned drain. Session 46 adds separately
opt-in route-bound HTTP/1.1 CONNECT with exact authority-port/Host/SNI checks,
session/idle limits, direct opaque relay, and task-owned drain. Session 47 adds
separately opt-in classic HTTP/2 CONNECT with the same route-bound authority
policy, shared CONNECT capacity, and per-connection relay ownership. Session 48
adds separately opt-in RFC 8441 WebSocket with strict extended-CONNECT checks,
local HTTP/1.1 handshake translation, shared WebSocket admission, and the same
bounded h2 relay ownership. The implemented public
surfaces are opt-in opaque raw TCP and a bounded operator-configured HTTPS route
with default HTTP/1.1 and opt-in HTTP/2/WebSocket/CONNECT policies. Both use per-IP
concurrency admission and authenticated dynamic Agent authority; the HTTPS
slice also terminates reloadable public TLS, enforces exact
Host-or-authority/SNI routing from static or authenticated dynamically
distributed state, supports
opt-in capped sequential keep-alive with per-request deadlines, and applies
process-local global/per-IP request token buckets. Accepted HTTP/1.1 and RFC
8441 WebSockets plus
HTTP/1.1 and classic HTTP/2 route-bound CONNECT sessions relay opaque upgraded
bytes through the unchanged
tunnel after validation, but the
HTTPS surface is not yet the automatic future product UX. Control Plane has a separate
bounded, versioned SQLite catalog and operator CLI for durable exact-hostname
route intent; Edge can consume it through an independent bounded mutual-TLS
latest-value stream with atomic activation, fail-closed expiry, and independent
digest-manifest TLS reload on both ends. Agent, Edge, and
Control Plane have opt-in bounded loopback operations endpoints;
public/authenticated operations access and durable metrics storage are not
implemented. All three runnable components can emit collector-friendly,
secret-safe JSON Lines to stderr without changing their plain stdout command
contracts.

Managed HTTP startup validates complete Edge and hostname-service mTLS inputs,
allocates or reuses the hostname with the same AgentId/TunnelId, starts the
normal reconnecting Agent runtime, and prints the mapping after its first
successful registration. The hostname remains durable across shutdown and
reconnect. Wildcard DNS/public TLS and external reachability remain
operator-owned prerequisites rather than claims made by that stdout line.
