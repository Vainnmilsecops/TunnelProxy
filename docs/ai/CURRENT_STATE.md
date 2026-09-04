# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Bounded Activity-Aware Legacy TCP Relay Idle Timeout** (Session 58).

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
- Edge can replace its raw listener with bounded HTTPS ingress for one
  exact configured DNS hostname and TunnelId. HTTP routing uses only cached
  hostname and live-session state; Agent-offline requests fail closed.
- Public HTTPS has explicit global/per-source-IP connection admission, public
  opt-in, Agent-facing mTLS, and external dynamic snapshot requirements.
  Loopback remains the safe default.
- Public TLS is a separate server-only rustls configuration with bounded
  handshake time, default HTTP/1.1 ALPN, optional `h2` ALPN, secret-safe
  diagnostics, expiry status, and optional atomic digest-manifest generation
  reload that preserves the selected protocol policy.
- Host, SNI, and request authority are normalized and compared exactly.
  Unsupported CONNECT, HTTP/2 upgrade/extended-CONNECT attempts, unknown hosts, duplicate
  Host, missing authority, and host-fronting attempts are rejected before a
  tunnel stream opens.
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
- Public HTTP/2 is separately opt-in. Each TLS connection has a hard concurrent
  stream cap, bounded header/reset/send/flow-control state, PING keepalive, and
  per-stream body/deadline/rate-limit enforcement. HTTP/2 authority, optional
  Host, and TLS SNI must agree exactly; accepted requests are normalized to
  HTTP/1.1 for the existing Agent/local path without a Tunnel Protocol change.
- HTTP/2 stream failure, oversized bodies, and request timeout remain isolated
  from sibling streams. Shutdown sends graceful GOAWAY and drains within the
  existing HTTPS deadline. HTTP/1.1 fallback remains available when enabled.
- HTTP/1.1 WebSocket upgrade is separately opt-in and default-off. Edge accepts
  only GET/version-13 handshakes with one canonical 16-byte key, no request
  body or extensions, exact Host/SNI routing, and the existing request-rate
  admission. The local service must return a matching `101`, accept digest,
  Upgrade tokens, and an offered subprotocol before opaque relay begins.
- WebSocket sessions have an independent global cap no larger than HTTPS
  connection capacity, a finite activity-based read/write idle deadline, RAII
  current/peak accounting, and fixed-cardinality accept/reject/timeout metrics.
  Their relay future remains owned by the HTTP/1.1 connection task, so graceful
  close may drain and the existing HTTPS deadline force-aborts stalled peers.
- HTTP/1.1 CONNECT is separately opt-in, default-off, and route-bound. The URI
  authority and Host must carry the exact cached route hostname plus the
  configured authority port, and TLS SNI must match; schemes, paths, bodies,
  transfer encoding, and upgrade headers fail closed.
- CONNECT opens only the selected TunnelId's fixed Agent local target. Edge
  never dials the client authority or forwards CONNECT to the local service.
  Independent global session capacity, activity idle timeout, RAII metrics,
  connection-task ownership, and the existing drain deadline bound the opaque
  relay without a Tunnel Protocol change.
- Classic HTTP/2 CONNECT is independently opt-in and requires the existing
  bounded HTTP/2 policy. It reuses exact authority-port/SNI/optional-Host route
  validation, request-rate admission, and the same global CONNECT semaphore as
  HTTP/1.1 without silently expanding the older opt-in.
- Hyper's HTTP/2 `OnUpgrade` stream is relayed opaquely through the cached
  TunnelId. A per-connection bounded relay supervisor owns all upgraded h2
  streams, preserves DATA half-close, isolates resets, applies the shared
  activity idle deadline, and joins or force-aborts them under GOAWAY/drain.
- HTTP/2 CONNECT exposes fixed-cardinality accepted/rejected/current/peak/idle
  metrics. Its classic CONNECT flag still rejects `:protocol` and arbitrary
  client-selected destination dialing; RFC 8441 requires its separate policy.
- RFC 8441 WebSocket over HTTP/2 is independently opt-in and conditionally
  advertises extended CONNECT. It requires HTTPS scheme/path, exact
  authority/optional-Host/SNI routing, version 13, no key/accept,
  connection-specific, body-framing, or extension fields, and the existing
  request-rate admission.
- Edge generates a fresh internal WebSocket key, translates the request into a
  sanitized local HTTP/1.1 GET Upgrade, validates the local `101` accept digest
  and selected subprotocol, then returns HTTP/2 `200` and relays frames
  opaquely. HTTP/1.1 and HTTP/2 share one WebSocket session/idle policy.
- RFC 8441 streams use the bounded h2 relay supervisor, stream-local reset and
  half-close, graceful GOAWAY, and the HTTPS forced-drain deadline. Aggregate
  and HTTP/2-specific WebSocket metrics remain fixed-cardinality.
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
- `tunnelproxy-agent http <port>` maps one non-zero port to loopback, requires
  complete Edge and hostname-service mTLS inputs, and validates the normal
  runtime, reload/enrollment, and optional operations configuration before
  requesting a durable allocation.
- Managed HTTP startup allocates or reuses the hostname with the same
  AgentId/TunnelId used for Protocol v2, starts the existing reconnecting Agent
  supervisor, and emits exactly one stable public-to-local stdout mapping after
  the transport first reaches `Connected`.
- Managed hostname ownership outlives the Agent process. Shutdown, reconnect,
  local refusal, and terminal runtime failure do not auto-release it; repeated
  startup reuses the URL without a catalog version change, while explicit
  `hostname-release` remains the only removal path.
- `tunnelproxy` is the canonical installed Agent executable. The historical
  `tunnelproxy-agent` binary remains a thin compatibility wrapper over the same
  library driver, preserving parsing, logging, exit, stdout, and lifecycle
  behavior.
- Strict local config v1 supplies managed HTTP Edge/hostname endpoints,
  identities, trust names, and credential paths. Reads are capped at 64 KiB;
  unknown/duplicate fields and unsupported versions fail closed. Relative
  paths resolve from the config directory, and layering is CLI over config over
  defaults with deterministic explicit/environment/platform path selection.
- Strict config v2 moves tunnel shape into a bounded 1â€“16 entry list for
  `tunnelproxy start`; shared identity, endpoints, TLS paths, public
  reachability policy, and offline validation retain the v1 trust boundary.
- Config v2 can opt into strict digest-manifest polling for atomic local-port
  generations. Only the existing TunnelIds' ports may change; invalid
  candidates retain the complete last-known-good map. New streams snapshot the
  active target while existing streams and Agent transports remain unchanged.
- `tunnelproxy config validate` performs bounded offline schema, runtime, path,
  and dual-TLS validation without network access or durable mutation.
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
- 423 explicit workspace tests are present; all prior behavior is preserved.

## Session 51 delivered

- Managed HTTP can opt in to a bounded public HTTPS challenge after Agent
  registration and gate the URL stdout line on its exact proof.
- Edge answers the strict no-store well-known challenge only after normal
  request-rate admission, Host/SNI route agreement, and live TunnelId lookup;
  it never opens a tunnel stream or forwards the request to localhost.
- The Agent uses bundled Web PKI roots or an explicit bounded CA, retries under
  per-attempt and total deadlines, observes shutdown, and preserves the
  durable hostname on terminal probe failure.
- Config v1 remains compatible through one optional object, while CLI/config
  validation is offline and tuning without opt-in fails closed.
- Secret-safe fixed-cardinality metrics and unit/real-TLS tests cover strict
  parsing, cancellation, success, wrong CA, signed-access coexistence, and no
  local forwarding. The workspace contains 402 explicit tests.

## Session 52 delivered

- Added separately opt-in continuous fixed-delay probing after the Session 51
  startup proof, with 10-second to one-hour interval and 1-to-10 consecutive
  failure threshold bounds.
- Added `Disabled`, `Pending`, `Healthy`, `Degraded`, and `Unhealthy` Agent
  reachability states. The threshold gates `/readyz`; one valid proof recovers
  readiness without stopping the tunnel or releasing the durable hostname.
- Prevented overlapping attempts, made monitor sleep/I/O shutdown-aware, and
  returned monitored reconnects to pending until a fresh public proof.
  Session 51 one-shot reconnect behavior remains unchanged.
- Extended config v1 compatibly, added fixed-cardinality state/cycle/failure/
  transition/recovery telemetry, and logs only state and failure class.
- Added parser, validation, scheduler, threshold, reconnect-compatibility, and
  real-TLS route-loss/re-registration/recovery coverage. The workspace contains
  405 explicit tests.

## Session 53 delivered

- Added strict config v2 and `tunnelproxy start` for 1â€“16 unique managed HTTP
  TunnelIds with non-zero loopback local ports. Config v1 and
  `tunnelproxy http <port>` remain compatible and command/version mismatches
  fail before network or durable mutation.
- Added `MultiAgentRuntime`, composing one existing Protocol v2 transport per
  tunnel. Transient failures retain child-local reconnect; terminal child
  failure triggers shared bounded drain. TLS reload, enrollment, operations,
  OS shutdown, and exit remain single process-level owners.
- Allocates each durable hostname, prints each mapping only after its child is
  ready, and applies optional startup/continuous reachability independently.
  Aggregate `/readyz` requires every child; `/healthz` remains process health.
- Added fixed-cardinality configured/ready tunnel gauges, state counts, and
  summed connection/reachability/transport telemetry without hostname or
  identity labels.
- Added strict parser/bounds/compatibility, supervisor/aggregation, offline
  config validation, and real-mTLS/public-TLS two-hostname-to-two-local-service
  coverage. The workspace contains 412 explicit tests.

## Session 54 delivered

- Added a bounded, versioned `GET`/`HEAD /tunnels` JSON inventory to the
  loopback-only Agent operations listener for managed `http` and `start`
  commands. Raw tunnel operations remain compatible and return `404`.
- Each deterministic TunnelId-sorted entry reports only its configured
  loopback target, published public URL, connection state, reachability state,
  and readiness. Configured/ready totals match the same live status handles
  used by aggregate `/readyz` and metrics.
- Kept hostname publication live through a cloneable metadata handle while
  preserving the existing fail-fast order: the operations socket binds before
  any durable hostname allocation. Public URL remains `null` until allocation
  succeeds.
- Enforced the existing 1-to-16 tunnel bound, duplicate rejection, a 16 KiB
  response invariant, no-store responses, GET/HEAD-only access, and no AgentId,
  credential, certificate, token, peer, or challenge fields.
- Preserved fixed-cardinality identity-free Prometheus metrics and added unit,
  loopback HTTP, compatibility, and real-mTLS two-tunnel inventory coverage.
  The workspace contains 416 explicit tests.

## Session 55 delivered

- Added optional strict `tunnel_reload` config-v2 settings with a relative
  digest manifest and a bounded 100â€“60000 ms polling interval. Startup and
  offline validation require a valid non-zero initial generation.
- Reused the shared bounded generation loader to verify the exact config bytes,
  enforce monotonic generations, and atomically publish one complete map. Only
  `local_port` values may change; TunnelId set or shared profile mutation is
  rejected while the last-known-good generation remains active.
- New logical streams snapshot the current target once. Existing streams stay
  connected to their original local service and all Protocol v2 transports,
  registrations, hostnames, and routes remain live across a reload.
- `/tunnels` reports the active target map. Fixed-cardinality metrics expose
  generation, successful/failed reload counts, and disabled/healthy/failed
  health without identity, address, path, or digest labels.
- Added atomic snapshot, manifest/bootstrap, mutation rejection, cancellation,
  operations, and real-TCP continuity coverage. The workspace contains 423
  explicit tests.

## Session 56 delivered

- Added opt-in `--https-request-history-capacity <1..128>` to the runnable
  Edge. It requires both HTTPS ingress and the loopback operations listener;
  disabled and raw-ingress modes return `404` for `/requests`.
- Added a newest-first bounded process-local ring for admitted ordinary HTTP
  requests. Capacity eviction is deterministic and request-ID exhaustion
  fails closed without unbounded allocation.
- Added versioned `GET`/`HEAD /requests` JSON with no-store responses and a
  64 KiB serialization ceiling. Entries contain only request ID, canonical
  hostname, TunnelId, bounded method/path, HTTP version, response status,
  response-header latency, and a fixed outcome.
- Never retain query strings, signed-access tokens, headers, bodies, peer IPs,
  credentials, certificates, or payload bytes. Reachability probes,
  WebSocket/CONNECT traffic, and pre-admission rejections are excluded.
- Added fixed-cardinality capacity, retention, eviction, exhaustion, and
  outcome metrics plus registry, parser/config, operations, redaction,
  HTTP/1.1, HTTP/2, timeout, rejection, and lifecycle coverage. The workspace
  contains 429 explicit tests.

## Session 57 delivered

- Added strict optional `limit=<1..128>` and non-zero decimal
  `before=<request_id>` pagination to loopback `GET`/`HEAD /requests`.
  Defaults preserve the Session 56 single-page behavior.
- Pages remain newest-first and select only retained IDs strictly below the
  cursor. Pagination is stateless; eviction gaps and an empty page for an old
  cursor are safe outcomes.
- Extended the versioned JSON additively with `eligible`, `has_more`, and
  `next_before`. `truncated` now reports either the caller's page limit or the
  unchanged 64 KiB serialization ceiling leaving eligible entries.
- Unknown, duplicate, encoded, malformed, zero, and out-of-range query values
  fail closed with `400`; disabled history still returns `404`, other methods
  remain `405`, and all successful responses remain no-store.
- Added parser, cursor ordering/no-duplicate, eviction-gap, size-bound, and
  real HTTP/1.1/HTTP/2 pagination coverage. The workspace contains 431
  explicit tests.

## Session 58 delivered

- Added a shared activity-aware idle deadline to the preserved Edge TCP echo,
  relay, and local-forwarder primitives. A successful non-empty write in
  either direction resets the deadline; silent reads, blocked writes, and
  blocked half-closes terminate within it.
- Added a 60-second default and strict 1 ms-to-1 hour
  `relay_idle_timeout` forwarder bound. The `edge_dev` example exposes
  `--relay-idle-timeout-ms`; compatibility helpers retain their signatures and
  use the default.
- Added typed `RelayError::IdleTimeout` and
  `ForwardError::RelayIdleTimeout`/`RelayIdleTimeout` lifecycle reporting.
  Timeout drops both sockets, releases the admission permit through RAII, and
  leaves the listener usable.
- Preserved fixed 8 KiB buffers, byte-exact full duplex, byte counters, and TCP
  half-close behavior without detached copy tasks or payload logging.
- Added config/category, echo activity, bidirectional relay activity, typed
  permit-release, and development CLI coverage. The workspace contains 437
  explicit tests across all targets.

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
- Multiple tunnel registrations on one Agent transport. Session 53 runs
  multiple managed tunnels over bounded independent transports instead.
- Automatic account/profile creation, inline secret custody, named profiles,
  and wildcard DNS/public TLS provisioning. The canonical
  `tunnelproxy http <port>` executable, strict path-based local config, and
  opt-in bounded external reachability verification are implemented.
- Arbitrary forward-proxy CONNECT, non-WebSocket extended CONNECT, WebSocket
  extension negotiation, HTTP/3, and custom-domain administration. Bounded
  route-bound HTTP/1.1/classic HTTP/2 CONNECT plus HTTP/1.1/RFC 8441 WebSocket
  ingress are implemented. Ed25519 signed access URLs now protect ordinary
  HTTP/1.1/HTTP/2 plus both WebSocket forms; classic CONNECT is intentionally
  incompatible because it has no query component. Ordinary request forwarding
  and the WebSocket handshake to the local application remain HTTP/1.1.
  Signed-access public-key rings support opt-in atomic digest-manifest reload,
  monotonically increasing generations, bounded overlap, and last-known-good
  retention without listener restart.
- Public-client authentication for arbitrary raw protocols, distributed/shared
  request-rate coordination, and DDoS mitigation.
- Multi-edge ownership/failover for durable tunnel identity.
- Upstream connection pool (DEBT-008 open).
- Per-IP admission control on the forwarder (DEBT-009 open).
- Embedded durable/remote-write telemetry, log rotation/shipping, dashboards,
  and alerting. Collection and retention remain operator-owned (DEBT-010
  resolved by Sessions 37–38).
- Durable request history, header/body capture, value-based query filtering or
  search, public operations access, and request replay. Sessions 56–57
  implement only bounded redacted process-local metadata and stateless ID
  cursor traversal for admitted ordinary HTTPS requests.

## Next planned session

Session 59 has not been selected. DNS/public-certificate automation and
multi-edge ownership remain separate scopes. Collect
workload evidence using the Session 37 runbook
before proposing peer-negotiated transport flow control.
