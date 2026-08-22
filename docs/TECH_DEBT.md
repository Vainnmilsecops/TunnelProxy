# TunnelProxy — Technical Debt Register

> Living log of deliberate shortcuts, deferred work, and known issues.
> Anything that violates an invariant in `docs/ai/INVARIANTS.md` should
> be either fixed or recorded here with a clear rationale and an exit
> plan.

## Template

```
### DEBT-<NNN> — <short title>

- **Introduced in:** Session <NN>
- **Category:** <foundation | correctness | security | ops | docs>
- **Impact:** <low | medium | high>
- **Rationale:** <why we accepted this shortcut>
- **Exit plan:** <how we intend to remove it>
- **Tracking:** <PR / issue link if available>
```

## Open items

### DEBT-002 — No CI configuration

- **Introduced in:** Session 01
- **Category:** ops
- **Impact:** medium
- **Rationale:** Foundation work is local-only by intent. CI selection
  (GitHub Actions vs. another provider) is deferred until the
  project's hosting is decided.
- **Exit plan:** Add a CI workflow that runs `cargo fmt --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and `cargo build --workspace` on every
  PR.
- **Tracking:** open.

### DEBT-003 — `Cargo.lock` not yet committed intentionally is undecided

- **Introduced in:** Session 01
- **Category:** foundation
- **Impact:** low
- **Rationale:** For a workspace that will ship application binaries,
  `Cargo.lock` should be committed. We have not yet produced a
  `Cargo.lock` because no build has been run in this environment.
- **Exit plan:** Commit `Cargo.lock` on the first build that
  successfully resolves dependencies.
- **Tracking:** open.

### DEBT-004 — Unbounded connection-task spawning on the edge echo listener

- **Introduced in:** Session 02
- **Category:** correctness
- **Impact:** medium
- **Rationale:** Session 02 establishes a Tokio `TcpListener` whose
  accept loop spawns one unbounded task per accepted connection via
  `tokio::spawn(handle_connection(...))`. There is no semaphore,
  per-IP rate limit, connection cap, or admission control on the
  echo baseline. The forwarder that supersedes the production
  intent (`Forwarder` in Session 04) already enforces a semaphore-
  bounded admission policy; the unbounded echo listener is kept as
  a deliberately small, regression-only artifact.
- **Exit plan:** Either remove the echo listener once the forwarder
  is the canonical surface, or wrap it in the same `Forwarder`
  semaphore. Either choice is fine; what is not fine is leaving the
  unbounded admission in the production surface.
- **Tracking:** open.

### DEBT-005 — No graceful shutdown for the edge listener — resolved

- **Introduced in:** Session 02
- **Category:** ops
- **Impact:** medium
- **Resolution:** Session 11 added a shared shutdown channel plus supervised
  `JoinSet` ownership for echo, relay, and forwarder connections. Admission
  stops on signal; children drain within `RuntimeShutdownConfig` and are
  explicitly aborted and joined after the deadline.
- **Tracking:** resolved in Session 11.

### DEBT-006 — No connection-level read/write idle timeout

- **Introduced in:** Session 02
- **Category:** correctness
- **Impact:** medium
- **Rationale:** `handle_connection` and `forward_handle_connection`
  can block forever on a read if a peer opens a TCP connection and
  never sends bytes or EOF. INV-005 explicitly requires timeouts
  on long-running network operations. Session 04 added the
  upstream-connect timeout (closes DEBT-007) but did not add an
  idle read deadline. Session 08's new single-stream path does have a
  configurable application-data idle deadline; this debt remains for the
  legacy echo/forwarder paths only.
- **Exit plan:** Wrap `copy_bidirectional` (or its driving
  half-copies) in a configurable idle deadline that aborts the
  relay without leaking sockets or the semaphore permit. Document
  the default in `docs/DEVELOPMENT.md`.
- **Tracking:** Session 05+ plan, `docs/ai/SESSION_INDEX.md`.

### DEBT-008 — No upstream connection pool

- **Introduced in:** Session 03
- **Category:** correctness
- **Impact:** low
- **Rationale:** `relay_connection` and `forward_handle_connection`
  open exactly one upstream TCP connection per downstream
  connection. This is deliberate for the byte-relay baseline: it
  keeps the failure mode local, the lifecycle obvious, and the
  tests simple. It is **not** a performance optimisation and it
  makes the relay more expensive under heavy fan-in than a pooled
  design would be. Session 04 deliberately preserved this policy
  in the `Forwarder`.
- **Exit plan:** If a future session shows a real fan-in workload,
  introduce an upstream-connection pool with its own admission
  control. Until then, keep the one-downstream-one-upstream
  mapping and document the cost in `docs/DEVELOPMENT.md`.
- **Tracking:** open.

### DEBT-009 — No per-IP admission control

- **Introduced in:** Session 04
- **Category:** correctness
- **Impact:** medium
- **Rationale:** `Forwarder` bounds the total number of in-flight
  relays but does not bound per-source-address concurrency. A
  single noisy peer can still consume a significant share of the
  permit pool. The capacity-exhaustion policy is global, not
  per-IP.
- **Exit plan:** Either track a per-peer counter inside
  `Forwarder` and reject connections that exceed a per-IP cap, or
  layer a per-IP semaphore in front of the global one. Document
  the chosen policy before implementing it.
- **Tracking:** Session 05+ plan, `docs/ai/SESSION_INDEX.md`.

### DEBT-010 — No production telemetry backend

- **Introduced in:** Session 04
- **Category:** ops
- **Impact:** low
- **Rationale:** Forwarder observability is implemented entirely as
  structured `tracing` events. There is no metrics backend, no
  Prometheus exporter, and no persisted counters. This is
  deliberate for the foundation: pushing to a metrics backend
  before the protocol is real would optimise the wrong thing.
- **Exit plan:** Wire a real metrics backend (and the
  `tracing-subscriber` JSON sink) once the V1 protocol exists and
  there are real production workloads to measure.
- **Tracking:** open.

### DEBT-012 — No graceful shutdown for Agent transport runtimes — resolved

- **Introduced in:** Session 06
- **Category:** ops
- **Impact:** medium
- **Resolution:** Session 11 added shutdown-aware Agent listeners, the legacy
  single-stream runtime, multiplexed Edge sessions, and multiplexed Agent
  streams. New admission is refused during drain; owned child tasks are joined
  or force-aborted under the configured process deadline.
- **Tracking:** resolved in Session 11.

### DEBT-013 — Single-stream runtime rejects concurrent ingress

- **Introduced in:** Session 08
- **Category:** correctness
- **Impact:** high for production, low for the bounded vertical slice
- **Rationale:** `SingleStreamEdgeRuntime` deliberately permits one connected
  Agent and one active logical stream. A second ingress is closed immediately.
  This isolates frame lifecycle, half-close, heartbeat interleaving, and
  backpressure before introducing concurrent socket ownership.
- **Exit plan:** Replace the single active state with a bounded per-session
  stream registry, one reader task, one bounded writer queue, per-stream
  cancellation, and explicit capacity/fairness policy. Preserve the Session 08
  wire payloads.
- **Tracking:** resolved in Session 09; the Session 08 compatibility runtime
  intentionally retains its single-stream contract.

### DEBT-014 — No credit-based flow-control window or weighted scheduler

- **Introduced in:** Session 09
- **Category:** performance
- **Impact:** medium
- **Rationale:** Session 09 bounds every queue and prioritizes heartbeat/reset
  traffic. DATA senders share Tokio's bounded FIFO channel, which provides
  cooperative backpressure but not byte-credit negotiation or weighted
  round-robin service for permanently backlogged streams.
- **Exit plan:** Add explicit per-stream/session byte credits and a deficit
  round-robin writer only after measurements show the bounded FIFO policy is
  insufficient.
- **Tracking:** open.

### DEBT-015 — Raw ingress routes are ephemeral transport bindings

- **Introduced in:** Session 10
- **Category:** product
- **Impact:** high for public use, low for the loopback vertical slice
- **Rationale:** `RawIngressRouteManager` targets a live process-local
  `TransportSessionId`. Routes disappear on Agent disconnect or Edge restart
  and cannot represent durable user intent. This is deliberate: Session 10
  proves listener/drain lifecycle without conflating transport identity with a
  future `TunnelId`/`AgentId` model.
- **Exit plan:** Add authenticated durable tunnel identity in the control plane,
  push a bounded route snapshot into Edge, then resolve that snapshot to live
  sessions without querying storage on the ingress hot path.
- **Tracking:** open; public ingress must not use ephemeral route IDs as durable
  identity.

## Resolved items

### DEBT-013 — Single-stream runtime rejects concurrent ingress

- **Introduced in:** Session 08
- **Resolved in:** Session 09
- **Resolution:** Added a bounded concurrent stream map, one reader and writer
  actor per transport, per-stream queues and cleanup, capacity reset, and exact
  live-session routing. The Session 08 runtime remains as a compatibility API.

### DEBT-011 — No heartbeat / liveness detection on established sessions

- **Introduced in:** Session 06
- **Resolved in:** Session 07
- **Category:** correctness
- **Impact:** medium
- **Resolution:** Edge now initiates a PING carrying a monotonic non-zero
  sequence after a configurable interval. Agent validates it and sends the
  matching PONG. A configurable deadline closes silent sessions and releases
  their capacity permit. Malformed, mismatched, unsolicited, or wrong-direction
  heartbeat frames close only the affected session. Reconnect remains separate
  future work.

### DEBT-001 — Foundation crates are placeholders only

- **Introduced in:** Session 01
- **Resolved in:** Session 02
- **Category:** foundation
- **Impact:** high (intentional)
- **Rationale:** Session 01 explicitly establishes component
  boundaries before any networking is written.
- **Resolution:** Session 02 replaces the `tunnelproxy-edge`
  placeholder with a real async TCP listener and echo handler, and the
  `tunnelproxy-agent` placeholder with a real async TCP client and
  verifier. `tunnelproxy-common`, `tunnelproxy-protocol`, and
  `tunnelproxy-control-plane` retain placeholder status because
  Session 02 does not require them to grow; their responsibility
  remains unchanged.

### DEBT-007 — No relay-path upstream connect deadline

- **Introduced in:** Session 03
- **Resolved in:** Session 04
- **Category:** correctness
- **Impact:** medium (intentional in Session 03)
- **Rationale:** `relay_connection` called `TcpStream::connect`
  without any timeout: if the upstream is blackholed, the connect
  could hang for the OS-default TCP timeout (often tens of seconds).
- **Resolution:** Session 04 introduces `ForwardConfig::connect_timeout`
  and wraps the upstream connect in
  `tokio::time::timeout(config.connect_timeout, TcpStream::connect(...))`
  inside `forward_handle_connection`. Timeouts are surfaced as the
  new `ForwardError::UpstreamConnectTimeout` variant, distinct
  from `ForwardError::UpstreamConnect`. The default is
  `DEFAULT_CONNECT_TIMEOUT = 5 s`. Tests
  (`forwarder_unreachable_upstream_surfaces_upstream_connect_failure`)
  cover the timeout path on a closed loopback port. The Session 03
  `relay_connection` is preserved for regression coverage but is no
  longer the production surface; new code should use
  `forward_handle_connection` / `Forwarder`.
