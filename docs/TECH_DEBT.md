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

### DEBT-004 — Unbounded connection-task spawning on the edge listener

- **Introduced in:** Session 02
- **Category:** correctness
- **Impact:** medium
- **Rationale:** Session 02 establishes a Tokio `TcpListener` whose
  accept loop spawns one unbounded task per accepted connection via
  `tokio::spawn(handle_connection(...))`. There is no semaphore,
  per-IP rate limit, connection cap, or admission control. This is
  acceptable for a learning baseline but unsafe in production: a
  single host opening thousands of sockets would exhaust memory and
  file descriptors.
- **Exit plan:** Introduce a bounded semaphore (e.g.
  `tokio::sync::Semaphore` with a configurable max in-flight
  connections), a global connection cap, and per-source-address
  throttling. This will be done in a session dedicated to the
  production server, after the byte-stream and protocol baseline
  stabilises.
- **Tracking:** Session 03+ plan, `docs/ai/SESSION_INDEX.md`.

### DEBT-005 — No graceful shutdown for the edge listener

- **Introduced in:** Session 02
- **Category:** ops
- **Impact:** low
- **Rationale:** `run_listener` runs an infinite accept loop and only
  returns when `accept` itself errors (typically when the listener is
  dropped). There is no signal-driven graceful-shutdown path and no
  cancellation token passed to spawned connection tasks. For a
  development baseline this is fine; for production we need clean
  draining of in-flight connections on SIGTERM.
- **Exit plan:** Add a `tokio::sync::watch` or `CancellationToken`
  channel that `run_listener` selects on alongside `accept`, and that
  in-flight `handle_connection` tasks also observe to abort their
  reads.
- **Tracking:** Session 03+ plan, `docs/ai/SESSION_INDEX.md`.

### DEBT-006 — No connection-level read/write timeout

- **Introduced in:** Session 02
- **Category:** correctness
- **Impact:** medium
- **Rationale:** `handle_connection` will block forever on a read if a
  peer opens a TCP connection and never sends bytes or EOF. The agent
  enforces a deadline on its outbound operations, but the edge has
  no equivalent for the inbound side. INV-005 explicitly requires
  timeouts on long-running network operations. Session 03 inherits
  this debt and adds an additional variant on the relay path.
- **Exit plan:** Wrap `stream.read(...)` in a `tokio::time::timeout`
  with a configurable idle deadline. Document the default in
  `docs/DEVELOPMENT.md`. Resolve in Session 04 together with the
  relay-path deadline (DEBT-007).
- **Tracking:** Session 04 plan.

### DEBT-007 — No relay-path idle timeout / upstream connect deadline

- **Introduced in:** Session 03
- **Category:** correctness
- **Impact:** medium
- **Rationale:** `relay_connection` calls `TcpStream::connect` without
  any timeout: if the upstream is blackholed, the connect can hang
  for the OS-default TCP timeout (often tens of seconds). Likewise,
  `relay_bidirectional` uses `tokio::io::copy_bidirectional` directly,
  so a half-open peer can pin a relay task indefinitely. INV-005
  explicitly requires deadlines on long-running network operations.
- **Exit plan:** Wrap `TcpStream::connect` in `tokio::time::timeout`
  with a configurable connect deadline; wrap each copy direction in
  a deadline shared with DEBT-006; surface a `RelayError` variant
  for the timed-out cases. Document defaults in
  `docs/DEVELOPMENT.md`.
- **Tracking:** Session 04 plan.

### DEBT-008 — No upstream connection pool

- **Introduced in:** Session 03
- **Category:** correctness
- **Impact:** low
- **Rationale:** `relay_connection` opens exactly one upstream TCP
  connection per downstream connection. This is deliberate for the
  byte-relay baseline: it keeps the failure mode local, the lifecycle
  obvious, and the tests simple. It is **not** a performance
  optimisation and it makes the relay more expensive under heavy
  fan-in than a pooled design would be.
- **Exit plan:** If a future session shows a real fan-in workload,
  introduce an upstream-connection pool with its own admission
  control. Until then, keep the one-downstream-one-upstream mapping
  and document the cost in `docs/DEVELOPMENT.md`.
- **Tracking:** open.

## Resolved items

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