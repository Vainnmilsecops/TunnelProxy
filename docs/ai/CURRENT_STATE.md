# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Runnable Snapshot Service & Operations Wiring** (Session 18).

## Completed

- Outbound Agent → Edge TCP control connection (INV-001: Agent dials Edge only).
- Tunnel Protocol v2 handshake runtime: HELLO → REGISTER → REGISTERED.
- HELLO payload schema: 1 byte role (`0x01` = AGENT), strictly validated.
- REGISTER payload: bounded length-prefixed `AgentId` and `TunnelId` intent.
- REGISTERED payload: 8-byte big-endian non-zero `TransportSessionId`.
- Strongly typed process-local session IDs with safe non-zero allocation.
- Edge `AgentTransportListener` with bounded concurrent admission (`Semaphore`).
- Edge handshake timeout (10 s default; affects handshake only).
- Strict handshake sequencing and best-effort ERROR response on violations.
- Edge-initiated heartbeat after handshake: PING followed by matching PONG.
- PING/PONG payload: exactly one non-zero 8-byte big-endian sequence.
- Only one PING is outstanding; sequences start at 1 and never wrap to zero.
- Configurable `heartbeat_interval` (15 s default) and `pong_timeout` (10 s
  default), both rejected when zero.
- Agent `AgentSession::run()` validates PING and automatically writes the
  matching PONG. `AgentSession::close()` provides an explicit local close path.
- Timeout, malformed payload, mismatched sequence, unsolicited PONG,
  Agent-initiated PING, and unexpected frames close only the affected session.
- Session capacity permit is held through handshake and heartbeat lifetime and
  released through RAII on every close/failure path.
- Structured heartbeat tracing includes session ID, peer, sequence, RTT, and
  close reason without logging payload bytes.
- Protocol stream lifecycle: Edge OPEN_STREAM request, Agent OPEN_STREAM
  acknowledgment, binary DATA, directional END_STREAM, and typed RESET_STREAM.
- `SingleStreamEdgeRuntime` binds separate loopback Agent and raw-TCP ingress
  listeners and supports exactly one active stream.
- Agent `run_with_local_target` connects an opened stream to one configured
  local TCP service under a deadline.
- Fixed 16 KiB reads, 64 KiB protocol frame ceiling, sequential writes, and no
  unbounded application queues.
- Stream IDs start at 1, increase without reuse/wrap, and support sequential
  stream reuse on one Agent session.
- TCP half-close is preserved independently in both directions.
- Stream-open timeout (5 s default), local-connect timeout supplied by Agent,
  and active-stream idle timeout (60 s default).
- Heartbeat remains live while DATA frames are flowing or a local service is
  slow. Stream failure/reset cleans up only that stream.
- 10 real-TCP Session 08 integration tests cover golden path, 256 KiB binary
  traffic, half-close, sequential reuse, monotonic IDs, busy admission,
  heartbeat interleaving, idle timeout, local-connect failure, and lifecycle
  violations.
- 20 Agent transport integration tests cover the handshake and heartbeat paths.
- 112 explicit workspace tests were present through Session 08 (94 through
  Session 07 plus 18 for Session 08).
- Prior Session 01–07 capabilities and tests are preserved.
- `MultiplexedEdgeRuntime` accepts multiple loopback Agent transports and
  publishes only live `TransportSessionId` values through `EdgeSessionRouter`.
- `EdgeSessionRouter::open_stream` routes an accepted TCP socket to one exact
  ephemeral Agent session and returns after OPEN_STREAM is acknowledged.
- Agent `run_multiplexed` bridges a configurable number of concurrent logical
  streams to its configured local service.
- Every session has one frame reader and one writer actor. Separate bounded
  lifecycle/heartbeat and DATA queues keep control traffic responsive; DATA
  and END_STREAM share FIFO ordering so half-close cannot overtake payloads.
- Per-stream inbound queues, a 16 KiB DATA-frame limit, bounded session queues,
  capacity admission, and open/connect/idle deadlines bound memory and failure
  scope.
- Four new reset codes cover capacity, unknown streams, queue/flow overflow,
  and closing sessions without changing Protocol v1 frame numbers.
- Real-TCP tests cover eight simultaneous streams, capacity rejection,
  two-Agent exact routing, local failure isolation, and heartbeat during load.
- 120 explicit workspace tests were present through Session 09.
- `EdgeSessionRouter::open_stream_tracked` returns a `RoutedStream` completion
  handle while the Session 09 `open_stream` API remains compatible.
- `RawIngressRouteManager` creates bounded loopback TCP listeners targeting one
  exact live `TransportSessionId`; no registry lock is held across network I/O.
- Route lifecycle is explicit: `Active` → `Draining` or
  `TargetDisconnected` → `Removed`. Removing stops acceptance immediately and
  active streams retain their sockets until actual completion.
- Route count and per-route connection count are bounded. Drain has a typed
  deadline and never force-kills active streams on timeout.
- Live-session snapshots remove routes targeting a disconnected Agent and
  prevent stale ephemeral session IDs from accepting more ingress.
- Ten real-TCP Session 10 tests cover byte-exact traffic, concurrent clients,
  two-Agent routing, capacity, drain, drain timeout, disconnect, and recovery.
- Shared idempotent `ShutdownTrigger` / `ShutdownSignal` primitives preserve
  shutdown requests made before a runtime begins waiting.
- Echo, relay, forwarder, Agent transport, single-stream, multiplexed Edge,
  multiplexed Agent, and raw-route runtimes expose explicit shutdown paths.
- Listener admission stops first. Supervised child tasks drain under a shared
  configurable deadline and report `Drained` or `Forced` outcomes.
- Multiplexed Edge rejects new routed streams while draining and sends a drain
  command to every live Agent session. Multiplexed Agent rejects later
  `OPEN_STREAM` frames with `SessionClosing` while current streams finish.
- Raw ingress shutdown is process-wide, prevents route reuse, joins connection
  tasks, and force-aborts remaining routes only after the deadline.
- `EdgeRuntime` composes one multiplexed Agent listener with one loopback raw
  ingress route. It waits for the sole Agent before binding ingress and rolls
  the transport back if route startup fails.
- `AgentRuntime` composes outbound connect/handshake with the multiplexed local
  bridge and accepts cancellation even before connection completes.
- Runnable `tunnelproxy-edge` and `tunnelproxy-agent` binaries expose validated
  addresses, capacity, timeout, and drain CLI flags.
- Ctrl-C is supported on all platforms and SIGTERM on Unix. Signal observation
  only triggers cancellation; owning supervisors perform ordered cleanup.
- Edge shutdown drains raw routes before Agent transports. Forced stage results
  and unexpected peer disconnects produce non-zero process exits.
- Real-TCP composition tests cover byte-exact forwarding, shutdown before an
  Agent arrives, startup rollback, and Agent cancellation before connect.
- `AgentRuntime` retries transient connection and established-session failures
  with validated bounded exponential delay, downward jitter, shutdown-aware
  sleep, a stable-session streak reset, and an optional consecutive-failure
  budget. Protocol violations remain terminal.
- Agent outcomes report attempts, established sessions, successful reconnects,
  and the last ephemeral session ID. Structured events expose attempts,
  scheduled delay, establishment, disconnect recovery, and route generation.
- `EdgeRuntime` keeps its transport listener alive after an Agent disconnect,
  waits for dead-session route cleanup, and binds the same configured loopback
  raw address to the next live ephemeral Agent session.
- Recovery never reuses a `TransportSessionId` and does not replay interrupted
  streams. No Protocol v1 frame or payload changed.
- Real-TCP recovery tests cover shutdown during backoff, typed retry exhaustion,
  Agent replacement on one Edge, and Agent recovery across an Edge restart.
- The runnable/multiplexed Agent transport supports mutual TLS using rustls.
  Agent validates the Edge CA and DNS server name; Edge requires a client
  certificate signed by its configured Agent CA before Protocol v1 begins.
- Session 14 introduced versioned TunnelProxy ALPN; missing or mismatched ALPN
  never reaches protocol registration. TLS has its own bounded handshake deadline and Edge
  holds the existing session-capacity permit throughout negotiation.
- Plaintext runtime transport is restricted to loopback. TLS permits a
  non-loopback Agent listener while raw ingress remains loopback-only.
- TLS identity/authentication failures are terminal on Agent; transient TCP/TLS
  transport failures and TLS timeouts remain governed by Session 13 reconnect.
- Certificate/key PEM data is parsed into rustls configuration and omitted from
  Debug, errors, and structured logs. Tests generate their PKI at runtime.
- 18 new unit/real-TCP tests cover config/CLI validation, mTLS forwarding,
  wrong CA/name, missing ALPN, missing/untrusted client certificates, capacity
  release, timeout/cancellation, secure restart, and secret-safe diagnostics.
- Protocol header version and TLS ALPN are now v2 / `tunnelproxy/2`. Protocol
  v1 clients fail explicitly with no downgrade.
- Durable IDs contain 1–64 ASCII letters, digits, `-`, or `_`; malformed,
  truncated, oversized, or unsafe REGISTER payloads fail closed.
- The control-plane crate builds immutable authorization snapshots mapping
  SHA-256 client-leaf-certificate fingerprints to exact Agent and Tunnel grants.
- Edge authorizes the certificate/Agent/Tunnel tuple before REGISTERED and
  session publication. Unknown certificates, false identity claims, disabled
  tunnels, and unauthorized tunnels are terminal Agent failures.
- One live transport may claim a TunnelId. Duplicate claims receive typed
  `TunnelAlreadyConnected`, retry under bounded reconnect policy, and release
  through RAII on every connection exit.
- `EdgeSessionRouter` caches `TunnelId -> TransportSessionId` alongside its
  ephemeral session registry; ingress performs no database/network lookup.
- Runnable raw ingress targets TunnelId, binds before Agent availability, stays
  bound across reconnect, and closes accepted sockets while the tunnel is
  offline instead of reusing a stale session.
- Agent and Edge CLIs expose durable IDs; TLS Edge configuration also requires
  the exact public Agent certificate used for the current static authorization
  mapping.
- 14 new unit/real-TCP tests cover v2 codec/ID/config bounds, v1 rejection,
  authorization mismatches, disabled/duplicate tunnels, claim release, and
  durable offline/online routing.
- Authorization snapshots now carry a non-zero monotonic `SnapshotVersion` and
  use full-replacement semantics. Higher versions may skip intermediates;
  duplicates are idempotent and stale/same-version-conflicting updates fail
  before distribution.
- Control plane publishes through a bounded latest-value channel. Subscribers
  always see the newest complete authority without accumulating a delta queue.
- Edge can start a durable raw listener from an empty dynamic snapshot and
  apply add/enable/disable/remove or identity reassignment without restart.
- REGISTER authorization is revalidated immediately before publication.
  Publication, cached-route stream enqueue, and reconciliation share one gate,
  closing the authorize-before-publication race.
- Live revocation removes durable and ephemeral router entries before closing
  the exact transport. Active streams fail closed; the raw listener remains
  bound and can use a later authorized replacement Agent.
- Unrelated snapshot changes preserve healthy sessions. If every publisher
  closes, Edge reports `Stale` source state and retains the last cached snapshot.
- `EdgeSessionRouter` exposes current/subscribed authorization status including
  snapshot version, source health, and cumulative revoked-session count.
- Eight new unit/real-TCP tests cover version ordering, gaps, idempotency,
  conflicts, bounded latest-value delivery, cached state after source close,
  publication-race revalidation, live grant add, unrelated updates, active
  revocation, and re-enable on the same listener.
- Authorization snapshots have a canonical bounded binary representation and
  SHA-256 digest independent of input/hash-map ordering.
- `SqliteSnapshotRepository` durably commits the complete grant set plus its
  version/digest in one transaction and reloads the exact state after restart.
- `PersistentSnapshotAuthority` performs blocking SQLite work away from Tokio,
  rejects empty storage, serializes writers, and never publishes before commit.
- A separate mTLS snapshot service uses ALPN `tunnelproxy-snapshot/1`; it does
  not modify or multiplex over Agent ↔ Edge Tunnel Protocol v2.
- Edge authenticates the Control Plane server, presents its own client
  certificate, bootstraps a full snapshot before creating the live policy, and
  resumes reconnects from the last in-memory version.
- Snapshot-service loss changes source health to `Stale` without clearing the
  cached authority. Successful authenticated reconnect returns it to `Live` and
  later versions continue through Session 16 atomic reconciliation.
- Snapshot operators can import one strict JSON full snapshot through the
  runnable Control Plane binary. Reads stop at 1 MiB and all domain/storage
  validation occurs before durable replacement.
- `ControlPlaneRuntime` refuses uninitialized storage, refreshes externally
  committed versions without blocking Tokio, owns the mTLS distribution server,
  and shuts down its listener and connection tasks under explicit supervision.
- `tunnelproxy-control-plane serve|import` exposes validated database, listener,
  TLS identity/trust, capacity, deadline, and refresh configuration with stable
  process exit classes.
- `SnapshotAwareEdgeRuntime` authenticates and receives the initial snapshot
  before binding Edge listeners, then supervises snapshot reconnect and the data
  plane together.
- The runnable Edge CLI supports three explicit authorization modes: plaintext
  loopback development, static certificate-bound mTLS, or dynamic snapshot mTLS.
  Partial or conflicting flag groups fail before network startup.
- 226 explicit workspace tests are present; all prior behavior is preserved.

## Not implemented

- Certificate issuance, CA/trust revocation, rotation, expiry monitoring, and
  TLS-config hot reload (DEBT-017 open).
- General administrative mutation API and Edge disk cache for cold startup
  while the Control Plane is unavailable (DEBT-018).
- Credit/window-based flow control and strict weighted fairness between
  continuously backlogged streams.
- Multiple tunnel registrations on one Agent transport.
- Public tunnel endpoints / hostname allocation.
- Public HTTP/TLS reverse proxy and raw public ingress.
- Multi-edge ownership/failover for durable tunnel identity.
- Upstream connection pool (DEBT-008 open).
- Relay-path idle read deadline (DEBT-006 remains open outside Agent heartbeat).
- Per-IP admission control on the forwarder (DEBT-009 open).
- Production telemetry / metrics backend (DEBT-010 open).

## Next planned session

**Session 19 — Edge Cold-Start Snapshot Cache.**

Goals:

- Persist only the last authenticated, canonical snapshot on Edge with atomic
  replacement, integrity metadata, and rollback protection.
- Permit explicit stale cold startup when Control Plane is unavailable, while
  preferring authenticated online bootstrap and never blocking ingress on disk.
- Reconcile a newer server snapshot immediately after reconnect and retain the
  existing `Live`/`Stale` observability contract.
- Keep admin APIs, certificate lifecycle, public ingress, and multi-edge
  consensus outside the session unless explicitly expanded.
