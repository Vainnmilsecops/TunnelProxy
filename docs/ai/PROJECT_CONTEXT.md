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

Automatic hostname allocation, custom domains, dashboard, billing,
distributed/shared request-rate coordination, request inspection, stream
replay, protected issuer custody, multi-edge ownership, and cloud deployment
are explicitly **not implemented**. The implemented public surfaces are opt-in
opaque raw TCP and a bounded operator-configured HTTPS/HTTP/1.1 route. Both use
per-IP concurrency admission and authenticated dynamic Agent authority; the
HTTPS slice also terminates reloadable public TLS, enforces exact Host/SNI
routing, and applies process-local global/per-IP request token buckets, but it
is not yet the automatic future product UX. Edge also has an opt-in bounded
loopback operations endpoint; public/authenticated operations access, durable
metrics storage, and Agent/Control Plane exporters are not implemented. All
three runnable components can emit collector-friendly, secret-safe JSON Lines
to stderr without changing their plain stdout command contracts.
