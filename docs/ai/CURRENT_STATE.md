# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Atomic Agent Hostname Service TLS Rotation** (Session 41).

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
- Every session has one frame reader and one writer actor. DATA admission is
  globally bounded across channel, scheduler, and in-flight encode state.
  Active streams are served round-robin with per-stream FIFO ordering, so
  END_STREAM cannot overtake payloads. Lifecycle/heartbeat traffic retains
  priority with a bounded eight-frame control burst.
- Agent and Edge aggregate fixed-cardinality multiplexed telemetry for active
  and peak streams, directional DATA frames/bytes, admission waits, current
  and peak writer-pipeline depth, live aggregate writer-pipeline capacity,
  locally initiated flow-control resets, and control-burst DATA yields. Queue,
  stream, and session-capacity gauges use RAII and return to zero on
  close/error paths.
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
- `EdgeRuntime` composes one multiplexed Agent listener with one durable raw
  ingress route. Loopback is the default; it binds before Agent availability
  and rolls the transport back if route startup fails.
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
  non-loopback Agent listener; Session 23 public raw ingress additionally
  requires explicit exposure and dynamic snapshot authorization.
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
- Edge can opt into an explicit generation-file snapshot cache with a bounded
  stale age. Online bootstrap remains preferred; availability failure can cold
  start from the last authenticated canonical snapshot as `Stale`.
- Cache generations carry format/length/time metadata and SHA-256 integrity,
  reject corruption, expiry, lower versions, and same-version conflicts, and
  are synchronized before memory publication. Cache I/O never enters ingress.
- Authenticated reconnect refreshes the durable generation before returning to
  `Live`. Failure to reconnect before the stale deadline stops the composed
  Edge and releases both listeners.
- TLS identity, ALPN, protocol, and server-rejection errors never fall back to
  disk. The local filesystem is an explicit trust boundary; the digest is not a
  snapshot signature.
- Agent, Edge Agent-facing TLS, Edge snapshot-client TLS, and Control Plane
  snapshot-server TLS can opt into polling a strict generation manifest.
  Each manifest names the exact expected files and their SHA-256 digests;
  unknown/missing entries, partial writes, stale/conflicting generations, and
  invalid PEM/configuration are rejected before publication.
- TLS handshakes take an immutable `Arc<rustls::*Config>` snapshot. A complete
  newer generation is swapped for new handshakes without restarting the
  process, while a rejected generation leaves the prior configuration active.
- Static Edge authorization reloads the exact authorized Agent certificate in
  the same Agent-facing generation and reconciles live sessions. Dynamic Edge
  authorization remains owned by the Control Plane snapshot stream.
- Leaf-identity validity is decoded at bootstrap/reload. Runtime status exposes
  `Current`, `Expiring`, `ReloadFailed`, or `Expired`; structured events contain
  generation and health only. If last-known-good credentials expire before a
  valid replacement arrives, the owning process supervisor exits non-zero.
- Reload manifests are optional and plaintext behavior is unchanged. Polling
  uses skipped missed ticks and bounded blocking reads; PEM bytes, keys, file
  contents, and paths are not emitted in status or reload events.
- Agent can generate an ECDSA P-256 key and CSR locally, enroll over bounded
  server-authenticated TLS, and publish a short-lived client credential through
  the Session 20 manifest boundary without exporting its private key.
- Bootstrap and renewal tokens are random 256-bit file secrets. Control Plane
  stores only SHA-256 hashes, binds bootstrap use to exact Agent/Tunnel IDs,
  enforces expiry, and never writes token/key bytes to logs or errors.
- Issuance and activation use idempotent request IDs and two SQLite
  transactions. The first adds the replacement fingerprint with overlap; the
  second removes the predecessor only after Agent reload activation.
- Control Plane can supervise the opt-in enrollment listener and provision a
  bound token with `create-token`. Agent supports `--enroll-only` and an
  automatic expiry-window renewal supervisor with a crash-recoverable journal.
- Credential records now migrate to explicit `Pending`, `Active`, `Retired`,
  `Revoked`, and `Expired` states with an issuance-time activation deadline.
- A bounded reconciler runs inside the supervised enrollment service. It
  tombstones overdue requests and atomically removes pending fingerprints while
  preserving an active renewal predecessor.
- `revoke-agent` durably invalidates matching bootstrap/renewal tokens and
  removes one exact Agent/Tunnel authorization. Dynamic Edge reconciliation
  closes its live session and active streams after snapshot publication.
- `credential-status` exposes only fingerprint, generation, state and times.
  Agent stops on terminal revocation/authentication failures, but clears an
  expired request journal so renewal can restart with a valid predecessor.
- Raw ingress has explicit `LoopbackOnly` and `Public` exposure policies.
  Public mode requires operator opt-in, a bounded per-IP active-connection
  limit, Agent-facing mutual TLS, and external dynamic snapshot authorization.
- The per-IP admission map contains only admitted active peers, is bounded by
  the existing global connection semaphore, and releases through RAII on every
  connection/open/session/shutdown path.
- Public raw listeners retain cached exact-TunnelId routing, offline
  fail-close, reconnect continuity, drain semantics, and live credential
  revocation without a database or Control Plane lookup on ingress.
- Route status and structured events expose accepted, global-capacity,
  per-IP-capacity, and unavailable-target outcomes without payload bytes.
- The application workspace commits `Cargo.lock`; CI uses `--locked` so
  manifest and dependency-resolution changes must land atomically.
- GitHub Actions checks format, all targets, and warning-free Clippy on Ubuntu;
  runs the full test/build suite on Ubuntu and Windows MSVC; and checks the
  declared Rust 1.75 MSRV under least-privilege, cancellable workflows.
- The MSRV path retains the workspace-level `forbid(unsafe_code)` policy while
  avoiding redundant crate-level lint overrides, and locks transitive
  dependencies to Cargo-1.75-readable releases.
- Edge can replace its raw listener with bounded HTTPS/HTTP/1.1 ingress for one
  exact configured DNS hostname and TunnelId. HTTP routing uses only cached
  hostname and live-session state; Agent-offline requests fail closed.
- Public HTTPS has explicit global/per-source-IP connection admission, public
  opt-in, Agent-facing mTLS, and external dynamic snapshot requirements.
  Loopback remains the safe default.
- Public TLS is a separate server-only rustls configuration with bounded
  handshake time, HTTP/1.1 ALPN, secret-safe diagnostics, expiry status, and
  optional atomic digest-manifest generation reload.
- Host, SNI, and absolute-form authority are normalized and compared exactly.
  CONNECT, upgrades, unknown hosts, duplicate/missing Host, and host-fronting
  attempts are rejected before a tunnel stream opens.
- Edge strips hop-by-hop fields plus untrusted `Forwarded` and
  `X-Forwarded-*`, then supplies canonical `X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Forwarded-Host`, and Host values to the local service.
- Header bytes/count, request-body size, header-read/full-request deadlines,
  connection count, per-IP count, duplex capacity, and drain deadline are
  bounded. HTTPS drains before Agent transport shutdown.
- Public HTTP/1.1 keep-alive is opt-in with a default cap of one and hard cap
  of 1024 sequential requests per TLS connection. Every request revalidates
  routing/security/admission state; errors close, deadlines cover response
  bodies, and shutdown gracefully closes idle reused connections.
- `EdgeSessionRouter` now accepts any bounded async byte stream internally, so
  the HTTP client connection can reuse the existing multiplexed Tunnel
  Protocol v2 path without a wire-format change.
- HTTPS ingress atomically applies integer fixed-point global and
  socket-source-IP token buckets after hostname validation and before request
  body forwarding or tunnel-stream creation. Rejections return `429` with an
  integer `Retry-After`.
- Per-IP rate state is cardinality-bounded, uses bounded-batch idle-TTL
  reclamation, and fails closed when full. Live status exposes admitted and
  category-specific rejection totals plus current/peak tracked peers.
- The runnable Edge exposes validated request-rate, burst, peer-capacity, and
  idle-TTL flags. Rate state is process-local and resets on restart.
- The runnable Edge optionally binds a loopback-only, connection/header/time
  bounded HTTP/1.1 operations endpoint. `/healthz`, `/readyz`, and `/metrics`
  expose liveness, live-tunnel readiness, and Prometheus text metrics.
- Operations metrics use only fixed labels and contain no peer, hostname,
  durable identity, session, certificate, secret, or payload values. Raw and
  HTTPS counters remain process-local and reset on restart.
- Shutdown marks readiness false before ingress drain, keeps operations
  observable during that drain, then drains operations before Agent transport.
- Agent, Edge, Control Plane, and their runnable development examples share one
  process logging initializer. Text is the default; JSON Lines is explicitly
  selected with `TUNNELPROXY_LOG_FORMAT=json`, while `RUST_LOG` controls event
  filtering in either format.
- Every structured event is written to stderr. JSON events have stable
  `timestamp`, `level`, `target`, and nested `fields` keys with ANSI disabled;
  help and operator report output remain plain stdout.
- Invalid logging configuration fails with exit code 2 before CLI-driven
  network binding or file mutation. JSON-mode argument failures omit multiline
  usage text so stderr remains parseable JSON Lines.
- Synchronous stderr remains the compatibility default. Optional bounded
  nonblocking mode formats whole events under a 16 KiB ceiling, uses a strict
  drop-newest FIFO of at most 1024 events, and owns stderr on one worker thread.
  Shutdown drain is bounded to 1..=5000 ms; a blocked writer is detached after
  the deadline.
- Agent, Edge, and Control Plane operations metrics expose fixed-cardinality
  logging enabled/capacity, accepted, dropped, oversized, and write-failure
  values without querying or writing the sink during a scrape.
- The runnable Agent optionally binds a loopback-only, connection/header/time
  bounded HTTP/1.1 operations endpoint. `/healthz`, `/readyz`, and `/metrics`
  expose process liveness, established-session readiness, and connection
  lifecycle counters.
- Agent status distinguishes offline, connecting, connected, reconnect
  backoff, draining, and stopped. Readiness turns false before Agent drain;
  operations remains observable until transport, TLS reload, and enrollment
  supervisors have stopped, then releases its own listener.
- Agent metrics have only fixed connection-state labels and exclude AgentId,
  TunnelId, addresses, session IDs, certificates, secrets, and payloads.
  Operations bind failure occurs before the first outbound Edge connection.
- The runnable Control Plane optionally binds a loopback-only bounded HTTP/1.1
  operations listener. `/healthz`, `/readyz`, and `/metrics` expose process
  liveness, authority/distribution/enrollment readiness, and process-local
  snapshot, refresh, enrollment, reconciliation, and admission counters.
- Control Plane scrapes read only atomics: no SQLite or network query is made.
  Labels are a fixed outcome set and output excludes IDs, addresses, database
  paths, fingerprints, digests, tokens, certificates, keys, and payloads.
  Readiness becomes false before child-service shutdown; operations stops last.
- Shared `PublicHostname` validation now gives Control Plane catalog records and
  Edge HTTPS ingress one exact canonical DNS identity contract.
- A separate SQLite HTTPS route catalog stores at most 64 exact
  hostname-to-TunnelId records with enabled/disabled status and an independent
  non-zero monotonic version. Immediate transactions make record and version
  changes atomic; identical upserts and absent removals do not bump version.
- Control Plane CLI commands `https-route-upsert`, `https-route-remove`, and
  `https-route-list` validate before storage mutation, produce deterministic
  secret-safe output, and preserve the existing snapshot schema/state.
- Control Plane CLI commands `https-hostname-allocate` and
  `https-hostname-release` own one durable managed hostname per TunnelId under
  an explicit base domain. Allocation uses 128 bits of OS randomness in a
  DNS-safe `tp-<hex>` label, retries collisions at most 16 times, and is
  idempotent for the same tunnel/base-domain pair.
- Managed allocation metadata and its enabled route are committed in the same
  immediate SQLite transaction as one catalog-version increment. Release is
  likewise atomic; legacy/manual routes remain operator-owned, and generic
  route commands cannot overwrite or remove managed names.
- Control Plane can opt into a bounded Agent-facing hostname service using
  mutual TLS and dedicated ALPN `tunnelproxy-hostname/1`. Each request is
  authorized against the current certificate/AgentId/TunnelId snapshot before
  allocation or release; the managed base domain is server-owned.
- Hostname mutations serialize with route refresh, commit to SQLite, reload the
  complete durable catalog, and publish it to the existing Edge route stream
  before a success response is sent. Duplicate allocation and absent release
  retain their idempotent version semantics.
- Agent exposes `hostname-allocate` and `hostname-release` commands with bounded
  TCP, TLS, and request deadlines. TLS material is read from files and never
  accepted as command-line secret bytes.
- Control Plane runtime supervises the hostname listener with its snapshot,
  route, enrollment, and operations children. Fixed-cardinality hostname
  admission, TLS, authorization, and outcome metrics contain no identities or
  hostnames.
- Hostname server TLS can independently bootstrap and reload a strict
  digest-bound generation containing its server certificate, private key, and
  Agent client CA while preserving `tunnelproxy-hostname/1`. New handshakes
  atomically use increasing complete generations; invalid/stale/partial
  candidates retain last-known-good and active server-certificate expiry stops
  Control Plane supervision.
- Hostname-specific cert/key paths may override the shared Control Plane
  identity without breaking the Session 40 static defaults. Reload events emit
  only generation, fixed health, and outcome values.
- The Control Plane may expose an independent bounded mutual-TLS route service
  using a strict versioned full-catalog protocol and latest-value publication.
- Dynamic HTTPS Edge mode bootstraps online before binding, atomically replaces
  immutable in-memory routes, never queries SQLite/network per request, and
  continues with stale state only until a configured deadline. Expired state
  rejects every hostname until authenticated recovery; there is no disk cache.
- The HTTPS route server and client have separate opt-in digest manifests and
  reload supervisors. Candidates preserve the dedicated route ALPN, publish
  only increasing complete generations, keep the last-known-good generation
  on rejection, and terminate supervision after certificate expiry.
- Edge readiness and fixed-cardinality metrics report dynamic route source,
  catalog version, enabled route count, and fail closed after expiry.
- Operator-owned collection, retention, query, and alert-baseline guidance
  documents loopback scrape topology, process-restart semantics, capacity
  utilization, privacy constraints, and the evidence required before adding
  peer credits.
- 367 explicit workspace tests are present; all prior behavior is preserved.

## Not implemented

- Protected issuer key custody, CA rollover, multi-CA overlap, and CRL/OCSP at
  the TLS layer (DEBT-019 open). Snapshot-level emergency revocation and
  abandoned-overlap cleanup are implemented.
- Existing TLS connections generally retain their negotiated session until
  reconnect; static Edge certificate authorization is the exception because
  its snapshot update actively reconciles and revokes the old Agent session.
- General administrative mutation API and snapshot signing/hardware-backed
  rollback protection.
- Peer-negotiated credit/window flow control and weighted byte fairness.
  Session 35 implements bounded process-local frame round-robin scheduling;
  Sessions 36–37 expose saturation/fairness measurements plus their live
  capacity denominator and operator decision guide.
- Multiple tunnel registrations on one Agent transport.
- Complete automatic public-port/local-service orchestration. Authenticated
  Agent hostname allocate/release, durable route distribution, and Edge
  activation are implemented; DNS/TLS automation is not.
- HTTP/2, WebSocket/upgrade, CONNECT, custom-domain
  administration, and signed access URLs.
- Public-client authentication for arbitrary raw protocols, distributed/shared
  request-rate coordination, and DDoS mitigation.
- Multi-edge ownership/failover for durable tunnel identity.
- Upstream connection pool (DEBT-008 open).
- Relay-path idle read deadline (DEBT-006 remains open outside Agent heartbeat).
- Per-IP admission control on the forwarder (DEBT-009 open).
- Embedded durable/remote-write telemetry, log rotation/shipping, dashboards,
  and alerting. Collection and retention remain operator-owned (DEBT-010
  resolved by Sessions 37–38).

## Next planned session

Session 42 has not been selected. DNS/public-certificate automation, the complete
`tunnelproxy http` UX, HTTP/2, signed access URLs, and multi-edge ownership
remain separate scopes. Collect workload evidence using the Session 37 runbook
before proposing peer-negotiated transport flow control.
