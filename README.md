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
- Versioned latest-value authorization snapshot distribution with atomic Edge
  apply, stale/conflict protection, live grant revocation, and cached-state
  operation when the producer disconnects.
- Transactional SQLite snapshot persistence, strict JSON full-snapshot import,
  a runnable mutual-TLS Control Plane service, and snapshot-aware Edge CLI
  bootstrap/reconnect supervision.
- Opt-in digest-bound TLS generation reload for Agent, Edge, and snapshot
  transports with last-known-good rollback, expiry enforcement, and static
  Agent-certificate authorization rotation.
- Real TCP/mTLS integration tests for framing, forwarding, lifecycle, liveness,
  public admission, revocation, and the reverse data path.
- Product, architecture, development, and AI context documentation.

The following are **not yet implemented**:

- Credit/window-based flow control and strict weighted stream scheduling.
- Public HTTP reverse proxy and hostname allocation.
- Public-ingress TLS and public-client access authorization.
- General administrative/account API and automated certificate issuance/key
  custody.
- Request inspection, replay, and webhook debugging.
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
authorization snapshots, SQLite persistence, full-snapshot import, and a
runnable authenticated distribution service. The data plane has a tested
opt-in public raw-TCP reverse path but no public HTTP/TLS routing. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full breakdown.

## Future UX (not implemented yet)

Eventually, exposing a local port should be as simple as:

```text
$ tunnelproxy http 3000
https://blue-cat.tunnelproxy.dev -> http://127.0.0.1:3000
```

This is the **target** experience. It does not work yet.

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

See [`docs/ai/SESSION_INDEX.md`](docs/ai/SESSION_INDEX.md) for the running
session log.

## License

Dual-licensed under MIT or Apache 2.0, at the licensee's option.
