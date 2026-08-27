# TunnelProxy

> Developer-first secure reverse tunneling and traffic-debugging platform.

TunnelProxy exposes a local service to the public internet through an outbound
reverse tunnel initiated by an `agent` binary running on the developer's
machine. Public requests land on an `edge` node that fans them out to the
correct agent, which in turn proxies them into the local service.

## Current development status

**Early-stage / pre-MVP transport foundation.** This repository currently contains:

- The Cargo workspace layout and component boundaries.
- Async TCP echo, relay, and bounded local-forwarder primitives.
- Tunnel Protocol v2 binary framing with bounded durable registration and a
  64 KiB frame payload limit.
- Persistent outbound Agent → Edge handshake and Edge-initiated heartbeat.
- A multiplexed reverse TCP data path with bounded queues,
  half-close, typed reset, open/idle deadlines, and per-session routing.
- Lifecycle-managed raw-ingress routes with bounded global and per-source-IP
  connection admission, tracked stream completion, graceful drain, and
  Agent-disconnect cleanup.
- Runnable `tunnelproxy-edge` and `tunnelproxy-agent` binaries for one local
  tunnel, with Ctrl-C/SIGTERM-driven ordered shutdown and startup rollback.
- Cancellable bounded exponential Agent reconnect and automatic Edge raw-route
  recovery on the same address after a replacement session arrives.
- Optional mutual TLS on the Agent transport with Edge server-name validation,
  required Agent client certificates, ALPN, and plaintext restricted to
  loopback development.
- Certificate-bound `AgentId`/`TunnelId` authorization and cached durable
  tunnel-to-live-session routing. The raw listener stays bound while its Agent
  reconnects and fails closed while offline.
- Explicit public raw TCP exposure that requires Agent-facing mTLS, dynamic
  snapshot authorization, operator opt-in, and a bounded per-IP concurrency
  limit; loopback remains the default.
- Bounded public HTTPS/HTTP/1.1 ingress for one operator-configured exact
  hostname, including public TLS termination/reload, Host/SNI validation,
  forwarding-header sanitization, cached TunnelId routing, and bounded global
  plus per-source-IP request-rate admission with explicit `429` responses.
  Opt-in keep-alive permits a bounded number of sequential requests per TLS
  connection with per-request deadlines and graceful drain.
- An opt-in loopback-only Edge operations endpoint with bounded HTTP/1.1
  admission, liveness/readiness probes, and fixed-cardinality Prometheus
  metrics for authorization, raw ingress, HTTPS, and rate limiting.
- An opt-in loopback-only Agent operations endpoint with bounded admission,
  session-aware readiness, and fixed-cardinality connection/reconnect metrics.
- An opt-in loopback-only Control Plane operations endpoint with bounded
  admission, service readiness, and fixed-cardinality snapshot, refresh,
  enrollment, reconciliation, and operations metrics.
- Secret-safe process logging for Agent, Edge, and Control Plane with
  human-readable stderr output by default or schema-stable JSON Lines selected
  through `TUNNELPROXY_LOG_FORMAT=json` and filtered through `RUST_LOG`.
- Versioned latest-value authorization snapshot distribution with atomic Edge
  apply, stale/conflict protection, live grant revocation, and cached-state
  operation when the producer disconnects.
- Transactional SQLite snapshot persistence, strict JSON full-snapshot import,
  a runnable mutual-TLS Control Plane service, and snapshot-aware Edge CLI
  bootstrap/reconnect supervision.
- A transactional, versioned SQLite HTTPS route catalog with exact canonical
  hostname records, idempotent operator commands, and an independent bounded
  mutual-TLS latest-value stream for atomic Edge activation.
- Opt-in digest-bound TLS generation reload for Agent, Edge, snapshot, public
  HTTPS, and HTTPS route transports with last-known-good rollback, expiry
  enforcement, and static Agent-certificate authorization rotation.
- Real TCP/mTLS integration tests for framing, forwarding, lifecycle, liveness,
  public admission, revocation, and the reverse data path.
- Product, architecture, development, and AI context documentation.

The following are **not yet implemented**:

- Credit/window-based flow control and strict weighted stream scheduling.
- Automatic hostname allocation, custom-domain administration, and HTTP/2.
- Public-client access authorization, signed URLs, distributed request-rate
  coordination, and DDoS mitigation.
- General administrative/account API and protected issuer-key custody/CA
  rollover.
- Request inspection, replay, and webhook debugging.
- Public/authenticated operations access, metrics persistence/remote write,
  dashboards, and alerts.
- Multi-tenant or multi-edge runtime.

Any README, comment, or doc that suggests these features work today is a bug.
See [`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md) and
[`docs/ai/CURRENT_STATE.md`](docs/ai/CURRENT_STATE.md) for the truthful state.

## Conceptual architecture

```
            Internet Client
                  |
                  v
   https://<host>.tunnelproxy.dev
                  |
                  v
         +------------------+
         |   TunnelProxy    |
         |       Edge       |
         +------------------+
                  |
                  |  persistent secure
                  |  outbound tunnel
                  v
         +------------------+
         |  TunnelProxy     |
         |      Agent       |
         +------------------+
                  |
                  v
            localhost:<port>
```

The architecture conceptually separates:

- **Control Plane** — users, agents, tunnel metadata, authentication, quotas.
- **Data Plane** — live agent connections, public ingress, tunnel routing,
  request/response traffic.

Today the control-plane crate provides versioned certificate/Agent/tunnel
authorization snapshots, SQLite persistence, full-snapshot import, a runnable
authenticated distribution service, and a separate durable exact-hostname
route catalog with authenticated distribution to an in-memory Edge cache. The data plane has tested
opt-in public raw-TCP ingress plus a bounded HTTPS/HTTP/1.1 reverse-proxy
slice with exact static or dynamically distributed hostname routing, bounded
HTTP/1.1 keep-alive, public TLS reload, and local global/per-IP request-rate
enforcement. Edge and Agent can optionally export
bounded loopback health/readiness and fixed-cardinality Prometheus metrics. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full breakdown.

## Future UX (not implemented yet)

Eventually, exposing a local port should be as simple as:

```text
$ tunnelproxy http 3000
https://blue-cat.tunnelproxy.dev -> http://127.0.0.1:3000
```

This automatic hostname-allocation UX does not work yet. Session 25 provides
the Edge ingress path, Session 31 provides durable operator-managed route
intent, and Session 32 distributes that intent to Edge. Automatic allocation
remains future work.

## Repository structure

```
tunnelproxy/
├── Cargo.toml              # workspace root
├── README.md
├── .gitignore
├── rust-toolchain.toml
│
├── crates/
│   ├── common/             # shared strongly typed primitives
│   ├── protocol/           # Edge ↔ Agent framing and stream contracts
│   ├── agent/              # outbound Agent transport and local TCP bridge
│   ├── edge/               # Agent transport and bounded raw TCP ingress
│   └── control-plane/      # versioned authorization snapshot distribution
│
├── tests/                  # cross-crate integration tests (future)
├── scripts/                # local developer scripts
│
└── docs/
    ├── PRODUCT_SPEC.md
    ├── ARCHITECTURE.md
    ├── DEVELOPMENT.md
    ├── TECH_DEBT.md
    └── ai/
        ├── PROJECT_CONTEXT.md
        ├── CURRENT_STATE.md
        ├── MODULE_MAP.md
        ├── INVARIANTS.md
        ├── DECISIONS.md
        ├── TEST_MATRIX.md
        └── SESSION_INDEX.md
```

## Build and test

```bash
# Format
cargo fmt --all --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Test
cargo test --workspace

# Build
cargo build --workspace
```

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the full developer workflow
and Definition of Done.

## Roadmap summary

| Session | Focus |
|---------|-------|
| 01–06 _(complete)_ | foundation, relay/forwarder, framing, Agent ↔ Edge handshake |
| 07–09 _(complete)_ | heartbeat, reverse streams, bounded multiplexing and routing |
| 10–11 _(complete)_ | raw ingress lifecycle and supervised graceful shutdown |
| 12 _(complete)_ | runnable Edge/Agent entrypoints and OS signal wiring |
| 13 _(complete)_ | Agent reconnect and loopback raw-route recovery |
| 14 _(complete)_ | mutual TLS and certificate-authenticated Agent transport |
| 15 _(complete)_ | Protocol v2 authenticated identity and durable tunnel routing |
| 16–18 _(complete)_ | live revocation, persistent snapshots, and runnable Control Plane/Edge wiring |
| 19–20 _(complete)_ | bounded Edge cold-start cache and atomic TLS generation reload |
| 21–23 _(complete)_ | Agent enrollment/revocation and explicit public raw ingress |
| 24 _(complete)_ | reproducible dependency locking and cross-platform GitHub CI |
| 25 _(complete)_ | bounded public HTTPS/HTTP/1.1 ingress and exact hostname routing |
| 26 _(complete)_ | bounded global/per-IP HTTP request-rate limiting and observability |
| 27 _(complete)_ | bounded loopback Edge operations endpoint and Prometheus metrics |
| 28 _(complete)_ | secret-safe text/JSON process logging for all runnable components |
| 29 _(complete)_ | bounded loopback Agent operations endpoint and connection metrics |
| 30 _(complete)_ | bounded loopback Control Plane operations endpoint and service metrics |
| 31 _(complete)_ | durable versioned HTTPS route catalog and operator CLI administration |
| 32 _(complete)_ | authenticated HTTPS route distribution and atomic Edge activation |
| 33 _(complete)_ | atomic TLS generation reload for HTTPS route distribution |
| 34 _(complete)_ | bounded HTTP/1.1 keep-alive and per-request deadlines |

See [`docs/ai/SESSION_INDEX.md`](docs/ai/SESSION_INDEX.md) for the running
session log.

## License

Dual-licensed under MIT or Apache 2.0, at the licensee's option.
