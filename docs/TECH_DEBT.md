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

### DEBT-023 — HTTPS route-stream credentials require a process restart

- **Introduced in:** Session 32
- **Category:** ops / security
- **Impact:** medium during Control Plane or Edge credential rotation
- **Rationale:** Route distribution has a dedicated ALPN and TLS configuration.
  Session 32 reuses the trusted CA and leaf files at startup but deliberately
  does not couple this new protocol to the existing snapshot TLS generation
  reload supervisor. Last-known-good route data remains bounded by expiry.
- **Exit plan:** Add route-specific digest-manifest reload runtimes on both
  server and client, preserving independent ALPN validation, monotonic
  generations, last-known-good rollback, expiry termination, and real mTLS
  rotation coverage.
- **Tracking:** open.

### DEBT-022 — Durable HTTPS routes are not distributed to Edge — resolved

- **Introduced in:** Session 31
- **Category:** product / reliability
- **Impact:** medium for dynamic administration, low for the existing
  operator-configured single-route Edge
- **Rationale:** The first durable catalog establishes canonical identity,
  bounded transactional storage, versions, and CLI mutation without coupling a
  new distribution contract to the authorization snapshot or Edge hot path.
  Edge therefore continues to use explicit process-start HTTPS route config.
- **Exit plan:** Define a bounded authenticated latest-value catalog delivery
  and cache contract, then atomically reconcile immutable Edge routing tables
  without per-request Control Plane or SQLite lookups. Specify stale/expiry and
  revocation behavior before enabling multiple dynamic routes.
- **Resolution:** Session 32 added a separate bounded mutual-TLS latest-value
  protocol, atomic in-memory Edge replacement, and explicit stale-to-expired
  fail-closed behavior without a disk route cache or hot-path lookup.
- **Tracking:** resolved in Session 32.

### DEBT-021 — HTTP request-rate state is per-Edge and non-durable

- **Introduced in:** Session 26
- **Category:** reliability / security
- **Impact:** medium for multi-edge or externally metered quotas, low for the
  current single-Edge bounded ingress
- **Rationale:** Global and per-source-IP token buckets are intentionally held
  in one Edge process. They reset on restart and are not coordinated between
  Edge nodes. This protects the local Agent/tunnel path with bounded memory and
  no hot-path dependency, but it is not an authoritative account quota or
  distributed DDoS control.
- **Exit plan:** Introduce shared or hierarchically leased quota state only when
  multi-edge ownership is implemented, retaining a fail-closed local limiter
  and explicit behavior during coordination outages.
- **Tracking:** open.

### DEBT-020 — Public HTTP ingress is HTTP/1.1 single-request only

- **Introduced in:** Session 25
- **Category:** product / performance
- **Impact:** medium for production HTTP workloads, low for the bounded slice
- **Rationale:** The first public HTTPS surface disables keep-alive and supports
  exactly one HTTP/1.1 request per TLS connection. It rejects HTTP upgrade,
  WebSocket, CONNECT, and does not negotiate HTTP/2. This keeps request
  ownership, timeout, body bounds, drain, and tunnel-stream completion explicit
  while hostname and forwarding-header security are established.
- **Exit plan:** Add measured connection reuse and HTTP/2 only with explicit
  per-connection/per-stream admission, fair tunnel scheduling, independent body
  deadlines, graceful drain tests, and equivalent host-fronting/header
  sanitization coverage. Treat upgrades/CONNECT as separate policy surfaces.
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
- **Tracking:** Session 23 adds bounded per-IP RAII admission to the explicit
  public raw-ingress production path. This debt remains open only for the
  legacy standalone `Forwarder`, which is not used by that public route.

### DEBT-010 — Production telemetry is non-durable

- **Introduced in:** Session 04
- **Category:** ops
- **Impact:** low
- **Rationale:** Session 27 adds a bounded loopback Prometheus exporter for the
  Edge production data path. Session 28 gives Agent, Edge, and Control Plane a
  common secret-safe JSON Lines stderr sink and filter. Session 29 adds bounded
  Agent connection/readiness metrics. Session 30 adds bounded Control Plane
  readiness and service metrics. Metrics remain process-local, stderr emission
  is synchronous, and there is no remote write, durable history, dashboard, or
  alert policy.
- **Exit plan:** Add operator-owned collection/retention guidance and an
  optional bounded nonblocking sink before
  claiming complete production observability. Keep external backend I/O off
  request routing.
- **Tracking:** partially resolved by Edge metrics in Session 27, shared logs
  in Session 28, Agent metrics in Session 29, and Control Plane metrics in
  Session 30; open for durable backend integration.

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

### DEBT-015 — Durable route snapshots are not persisted across restarts — resolved

- **Introduced in:** Session 10
- **Category:** product
- **Impact:** high for public use, low for the loopback vertical slice
- **Resolution:** Session 17 persists the latest full authorization snapshot
  and version in transactional SQLite, reloads it after Control Plane restart,
  and exposes a dedicated mutually authenticated snapshot service. A fresh Edge
  bootstraps from that service; reconnect uses its last in-memory version, and
  ingress continues to use cached memory without storage/network lookup.
- **Tracking:** persistence resolved in Session 17 and runnable process wiring
  completed in Session 18. Edge cold-start cache is tracked separately below.

### DEBT-019 — Issuer custody and CA rollover remain manual

- **Introduced in:** Session 20
- **Category:** security / ops
- **Impact:** high for production credential operations, low for the tested
  operator-managed reload boundary
- **Rationale:** Session 21 provides authenticated Agent-owned-key
  enrollment, short-lived leaf issuance, hashed bootstrap/renewal tokens,
  manifest publication, and old/new leaf overlap with explicit activation.
  Session 22 adds snapshot-level emergency revocation, token invalidation, and
  bounded cleanup of abandoned pending replacements. The issuer key and local
  secret directories still rely on operator filesystem protection. There is no
  HSM/KMS integration, CA rollover/multi-CA overlap, or CRL/OCSP enforcement at
  the TLS handshake layer.
- **Exit plan:** Add protected issuer custody and audit boundaries, explicit CA
  overlap/trust distribution, and optional CRL/OCSP where rejecting a revoked
  leaf before application authorization is required.
- **Tracking:** leaf issuance was reduced in Session 21; emergency revocation
  and abandoned-overlap cleanup landed in Session 22. Production CA lifecycle
  remains open; dynamic Edge enrollment is not a complete PKI.

## Resolved items

### DEBT-002 — No CI configuration — resolved

- **Introduced in:** Session 01
- **Resolved in:** Session 24
- **Category:** ops
- **Impact:** medium
- **Resolution:** Added a least-privilege GitHub Actions workflow for pull
  requests, pushes to `main`, and manual runs. It checks format, all targets,
  and Clippy on Ubuntu; tests and builds on Ubuntu plus Windows MSVC; and checks
  the declared Rust 1.75 MSRV. Commands use the committed dependency lock and
  concurrent runs for superseded revisions are cancelled.
- **Tracking:** resolved in Session 24.

### DEBT-003 — `Cargo.lock` not yet committed intentionally is undecided — resolved

- **Introduced in:** Session 01
- **Resolved in:** Session 24
- **Category:** foundation
- **Impact:** low
- **Resolution:** TunnelProxy ships binaries, so `Cargo.lock` is now tracked.
  CI uses `--locked` to reject uncommitted dependency-resolution drift, while
  the version-3 lock format remains readable by the Rust 1.75 toolchain.
- **Tracking:** resolved in Session 24.

### DEBT-017 — TLS certificates are static process-start configuration

- **Introduced in:** Session 14
- **Resolved in:** Session 20
- **Category:** security / ops
- **Impact:** high for production certificate lifecycle, low for the tested
  transport foundation
- **Resolution:** Agent, Edge, snapshot client, and snapshot server can opt
  into strict digest-bound monotonic generation manifests. Complete rustls
  configurations are validated and atomically published for new handshakes;
  invalid candidates retain last-known-good, leaf validity is observable, and
  active-credential expiry is terminal. Static Edge certificate authorization
  rotates in its Agent-facing generation and reconciles removed sessions.
- **Residual boundary:** Issuance, key custody, CA/CRL/OCSP lifecycle, and
  hostile local-filesystem defense are tracked by DEBT-019. Arbitrary existing
  TLS sessions adopt new material only after reconnect.

### DEBT-018 — Dynamic Edge cannot cold start without Control Plane

- **Introduced in:** Session 18
- **Resolved in:** Session 19
- **Category:** reliability / security
- **Impact:** medium
- **Resolution:** An opt-in generation-file cache now persists only canonical
  snapshots received through authenticated mTLS. Durable write precedes memory
  publication, lower/conflicting versions fail closed, online bootstrap is
  preferred, and only availability failures may use a fresh cache. Offline
  startup is observable as `Stale`; reconnect restores `Live`, while the
  configured stale deadline terminates Edge and releases its listeners.
- **Residual boundary:** SHA-256 detects corruption but is not a signature.
  The local Edge host/filesystem remains trusted; adversarial local rollback is
  outside this debt item.

### DEBT-016 — Runnable tunnel stops after its sole Agent disconnects

- **Introduced in:** Session 12
- **Resolved in:** Session 13
- **Category:** reliability
- **Impact:** high for unattended use, low for the local lifecycle slice
- **Resolution:** `AgentRuntime` now retries transient failures with cancellable
  bounded exponential backoff and jitter. `EdgeRuntime` keeps accepting Agent
  transports, waits for dead-session route cleanup, and rebinds the same
  loopback raw address to a replacement session. Recovery remains deliberately
  separate from durable identity (DEBT-015), and interrupted streams are not
  replayed.

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
