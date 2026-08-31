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
- A multiplexed reverse TCP data path with globally bounded DATA admission,
  per-stream FIFO round-robin scheduling, bounded control-frame bursts,
  half-close, typed reset, open/idle deadlines, and per-session routing.
- Lifecycle-managed raw-ingress routes with bounded global and per-source-IP
  connection admission, tracked stream completion, graceful drain, and
  Agent-disconnect cleanup.
- Runnable `tunnelproxy-edge`, backwards-compatible `tunnelproxy-agent`, and
  canonical `tunnelproxy` binaries for one local tunnel, with
  Ctrl-C/SIGTERM-driven ordered shutdown and startup rollback.
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
- Bounded public HTTPS ingress for one operator-configured exact
  hostname, including public TLS termination/reload, Host/SNI validation,
  forwarding-header sanitization, cached TunnelId routing, and bounded global
  plus per-source-IP request-rate admission with explicit `429` responses.
  HTTP/1.1 remains the default with opt-in capped sequential keep-alive.
  HTTP/2 is separately opt-in with bounded concurrent streams, header/reset
  state, keepalive, per-stream deadlines, and graceful GOAWAY drain.
  HTTP/1.1 WebSocket upgrade is separately opt-in with strict handshake and
  local-response validation, a global session cap, idle deadline, opaque
  frame relay, fixed-cardinality metrics, and bounded drain.
  HTTP/1.1 CONNECT is separately opt-in and route-bound: exact authority
  hostname/port, Host, and SNI must agree before a capped, idle-bounded opaque
  tunnel begins. It never acts as an arbitrary forward proxy.
  Classic HTTP/2 CONNECT has its own opt-in, reuses the same route-bound
  authority policy and shared CONNECT capacity, and isolates each upgraded h2
  stream while retaining graceful GOAWAY/drain behavior.
- An opt-in loopback-only Edge operations endpoint with bounded HTTP/1.1
  admission, liveness/readiness probes, and fixed-cardinality Prometheus
  metrics for authorization, multiplexed transport, raw ingress, HTTPS, and
  rate limiting.
- An opt-in loopback-only Agent operations endpoint with bounded admission,
  session-aware readiness, connection/reconnect metrics, and multiplexed DATA
  saturation/fairness telemetry including live writer-pipeline capacity.
- An opt-in loopback-only Control Plane operations endpoint with bounded
  admission, service readiness, and fixed-cardinality snapshot, refresh,
  enrollment, reconciliation, and operations metrics.
- Secret-safe process logging for Agent, Edge, and Control Plane with
  human-readable stderr output by default or schema-stable JSON Lines selected
  through `TUNNELPROXY_LOG_FORMAT=json` and filtered through `RUST_LOG`.
  Optional bounded nonblocking buffering isolates runtime tasks from slow
  stderr and exports fixed-cardinality loss/failure counters.
- Versioned latest-value authorization snapshot distribution with atomic Edge
  apply, stale/conflict protection, live grant revocation, and cached-state
  operation when the producer disconnects.
- Transactional SQLite snapshot persistence, strict JSON full-snapshot import,
  a runnable mutual-TLS Control Plane service, and snapshot-aware Edge CLI
  bootstrap/reconnect supervision.
- A transactional, versioned SQLite HTTPS route catalog with exact canonical
  hostname records, idempotent operator commands, and an independent bounded
  mutual-TLS latest-value stream for atomic Edge activation.
- Durable managed-hostname allocation for one hostname per TunnelId using a
  bounded 128-bit OS-random DNS label, transactional release, collision retry,
  and live propagation through the existing Edge route stream.
- An opt-in authenticated Agent hostname lifecycle service with dedicated
  mTLS/ALPN, exact certificate/AgentId/TunnelId authorization, server-owned
  base domains, durable-before-live publication, atomic server TLS/Agent-CA
  rotation, and Agent allocate/release commands.
- A managed HTTP Agent command that validates all local, Edge, hostname, and
  TLS configuration before allocation, idempotently creates or reuses the
  durable hostname, starts the reconnecting Agent runtime, and prints the
  public URL once Protocol v2 registration succeeds.
- A strict bounded local Agent config v1 with CLI/environment/platform path
  resolution, relative credential paths, CLI override precedence, offline TLS
  validation, and no inline secret values. It enables `tunnelproxy http 3000`
  while retaining the long-form Session 42 command.
- Opt-in digest-bound TLS generation reload for Agent, Edge, snapshot, public
  HTTPS, HTTPS route, and Agent hostname transports with last-known-good
  rollback, expiry enforcement, and static Agent-certificate authorization
  rotation.
- Real TCP/mTLS integration tests for framing, forwarding, lifecycle, liveness,
  public admission, revocation, and the reverse data path.
- Product, architecture, development, and AI context documentation.

The following are **not yet implemented**:

- Peer-negotiated credit/window flow control and weighted byte scheduling.
- Automatic config/account provisioning, custom-domain administration, DNS or
  certificate automation, HTTP/2 extended CONNECT, WebSocket
  extensions, and HTTP/3.
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
opt-in public raw-TCP ingress plus a bounded HTTPS reverse-proxy slice with
exact static or dynamically distributed hostname routing, bounded HTTP/1.1
keep-alive, opt-in bounded HTTP/2, WebSocket and route-bound CONNECT, public
TLS reload, and local global/per-IP request-rate enforcement. Edge and Agent can optionally export
bounded loopback health/readiness and fixed-cardinality Prometheus metrics. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full breakdown and
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for collection, alert baselines, and
capacity interpretation.

## Managed HTTP orchestration

With operator-provisioned wildcard DNS/public TLS, the authenticated services
already running, and local config v1 installed, one Agent process can allocate
or reuse its hostname and expose a loopback HTTP port:

```text
tunnelproxy config validate
configuration valid
tunnelproxy http 3000
https://tp-0123456789abcdef0123456789abcdef.tunnelproxy.dev -> http://127.0.0.1:3000
```

The URL is printed once the allocation response has durably published the
catalog and the Agent transport is connected. Shutdown and reconnect never
release or rename the hostname; use `hostname-release` explicitly. This is not
an external reachability probe and does not create DNS records or public
certificates. See [`docs/AGENT_CONFIG.md`](docs/AGENT_CONFIG.md) for the strict
schema, platform paths, precedence, trust boundary, and long-form fallback.

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
    ├── OPERATIONS.md
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
| 35 _(complete)_ | bounded per-stream fair DATA scheduling |
| 36 _(complete)_ | multiplexed transport fairness and saturation telemetry |
| 37 _(complete)_ | live transport capacity telemetry and operator runbook |
| 38 _(complete)_ | bounded nonblocking process logging and sink telemetry |
| 39 _(complete)_ | durable managed-hostname allocation and release lifecycle |
| 40 _(complete)_ | authenticated Agent managed-hostname lifecycle service |
| 41 _(complete)_ | atomic TLS and Agent-CA rotation for the hostname service |
| 42 _(complete)_ | single-process managed HTTP hostname and Agent orchestration |
| 43 _(complete)_ | canonical `tunnelproxy` CLI and strict local Agent config v1 |
| 44 _(complete)_ | opt-in bounded HTTP/2 public HTTPS ingress |
| 45 _(complete)_ | bounded HTTP/1.1 WebSocket upgrade ingress |
| 46 _(complete)_ | bounded route-bound HTTP/1.1 CONNECT ingress |
| 47 _(complete)_ | bounded route-bound classic HTTP/2 CONNECT ingress |

See [`docs/ai/SESSION_INDEX.md`](docs/ai/SESSION_INDEX.md) for the running
session log.

## License

Dual-licensed under MIT or Apache 2.0, at the licensee's option.
