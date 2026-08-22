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
- Tunnel Protocol v1 binary framing with a 64 KiB payload limit.
- Persistent outbound Agent → Edge handshake and Edge-initiated heartbeat.
- A loopback-only multiplexed reverse TCP data path with bounded queues,
  half-close, typed reset, open/idle deadlines, and per-session routing.
- Ephemeral loopback raw-ingress routes with bounded connection admission,
  tracked stream completion, graceful drain, and Agent-disconnect cleanup.
- Real loopback integration tests for framing, forwarding, lifecycle, liveness,
  and the reverse data path.
- Product, architecture, development, and AI context documentation.

The following are **not yet implemented**:

- Credit/window-based flow control and strict weighted stream scheduling.
- Public HTTP reverse proxy and hostname allocation.
- TLS and Agent authentication.
- Persistence and durable tunnel identity.
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

Today the control plane remains a placeholder while the data plane has a
tested loopback raw-TCP reverse path but no public HTTP/TLS routing. See
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
│   ├── edge/               # Agent transport and loopback raw TCP ingress
│   └── control-plane/      # future durable configuration and APIs
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
| 01–06 _(complete)_ | foundation, TCP relay/forwarder, framing, Agent ↔ Edge handshake |
| 07 _(complete)_ | Edge-initiated heartbeat, liveness timeout, dead-session cleanup |
| 08 _(complete)_ | one bounded reverse data stream before multiplexing |
| 09 _(planned)_ | bounded concurrent stream multiplexing and session routing |

See [`docs/ai/SESSION_INDEX.md`](docs/ai/SESSION_INDEX.md) for the running
session log.

## License

Dual-licensed under MIT or Apache 2.0, at the licensee's option.
