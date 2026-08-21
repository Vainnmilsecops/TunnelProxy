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

### DEBT-005 — No graceful shutdown for the edge listener

- **Introduced in:** Session 02
- **Category:** ops
- **Impact:** medium
- **Rationale:** Both `run_listener` and `Forwarder::run` execute an
  infinite accept loop and only return when `accept` itself errors
  (typically when the bound socket is dropped). There is no
  signal-driven graceful-shutdown path and no cancellation token
  passed to spawned connection tasks. In production we need clean
  draining of in-flight connections on SIGTERM.
- **Exit plan:** Add a `tokio::sync::watch` or `CancellationToken`
  channel that `Forwarder::run` selects on alongside `accept`, and
  that in-flight `forward_handle_connection` tasks also observe to
  abort their copies cleanly. The `Forwarder` is the right anchor
  for this change; the Session 02 echo baseline will follow the
  same pattern if it is kept around.
- **Tracking:** Session 05+ plan, `docs/ai/SESSION_INDEX.md`.

### DEBT-006 — No connection-level read/write idle timeout

- **Introduced in:** Session 02
- **Category:** correctness
- **Impact:** medium
- **Rationale:** `handle_connection` and `forward_handle_connection`
  can block forever on a read if a peer opens a TCP connection and
  never sends bytes or EOF. INV-005 explicitly requires timeouts
  on long-running network operations. Session 04 added the
  upstream-connect timeout (closes DEBT-007) but did not add an
  idle read deadline.
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

### DEBT-012 — No graceful shutdown for Agent transport listener

- **Introduced in:** Session 06
- **Category:** ops
- **Impact:** medium
- **Rationale:** `AgentTransportListener::run` executes an infinite
  accept loop and only returns when `accept` itself errors. There is
  no signal-driven graceful-shutdown path and no cancellation token
  passed to spawned session tasks. In production we need clean draining
  of in-flight connections on SIGTERM.
- **Exit plan:** Add a `tokio::sync::watch` or `CancellationToken`
  channel that `AgentTransportListener::run` selects on alongside
  `accept`, and that in-flight `agent_session_task` tasks also
  observe to abort their copies cleanly. DEBT-005 applies the same
  fix to `Forwarder::run`.
- **Tracking:** Session 07+ plan, `docs/ai/SESSION_INDEX.md`.

## Resolved items

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
