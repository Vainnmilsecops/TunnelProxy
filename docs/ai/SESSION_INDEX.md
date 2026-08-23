# TunnelProxy — Session Index

> One line per session. Update at the end of every session.

| Session | Title                                          | Status   |
| ------- | ---------------------------------------------- | -------- |
| 01      | Foundation                                     | complete |
| 02      | TCP Networking Foundation                      | complete |
| 03      | Bidirectional TCP Streaming / TCP Relay        | complete |
| 04      | TCP Relay Lifecycle Hardening / Local Port Forwarding | complete |
| 05      | Tunnel Protocol v1: Binary Framing & Message Design | complete |
| 06      | Persistent Agent ↔ Edge Transport & Protocol Handshake | complete |
| 07      | Heartbeat, Liveness & Dead-Session Detection   | complete |
| 08      | Single-Stream Reverse Data Path                | complete |
| 09      | Bounded Stream Multiplexing & Session Routing  | complete |
| 10      | Raw Ingress Binding & Route Lifecycle          | complete |
| 11      | Graceful Runtime Shutdown & Supervision        | complete |
| 12      | Production Runtime Entrypoints & OS Signal Wiring | complete |
| 13      | Agent Reconnect & Route Recovery               | complete |
| 14      | Mutual TLS & Agent Authentication              | complete |
| 15      | Authenticated Tunnel Identity & Registration   | complete |
| 16      | Control-Plane Snapshot Distribution & Live Revocation | complete |
| 17      | Persistent Snapshot Storage & Authenticated Edge Bootstrap | complete |

## Session 01 — Foundation — complete

See [`CURRENT_STATE.md`](CURRENT_STATE.md) for the truthful end-of-
session state. See [`../TECH_DEBT.md`](../TECH_DEBT.md) for the
deliberate shortcuts.

## Session 02 — TCP Networking Foundation — complete

Scope that was actually delivered:

- Added `tokio` (with `net`, `io-util`, `time`, `macros`, `rt-multi-thread`,
  `sync` features), `tracing`, and `tracing-subscriber` to the workspace
  dependency table. Only `tunnelproxy-edge` and `tunnelproxy-agent`
  depend on them; `common`, `protocol`, and `control-plane` remain
  dependency-free.
- `tunnelproxy-edge` exposes `run_listener(SocketAddr)` and
  `handle_connection(TcpStream, SocketAddr)`. Each accepted connection
  is handled in its own Tokio task. Reads use a fixed 8 KiB buffer
  (`READ_BUFFER_SIZE`); writes echo exactly the bytes read. `read == 0`
  is treated as a normal EOF. No payload bytes are logged.
- `tunnelproxy-agent` exposes `send_and_verify(SocketAddr, &[u8], Duration) -> RunOutcome`
  and a thin `run(SocketAddr)` wrapper. Deterministic `TEST_PAYLOAD =
  b"hello tunnelproxy"`. The read is bounded by
  `DEFAULT_OPERATION_TIMEOUT` to honor INV-005.
- Two development binaries exist as `cargo run --example` targets:
  `tunnelproxy-edge/examples/edge_dev.rs` (echo) and
  `tunnelproxy-agent/examples/agent_dev.rs`.
- Real TCP integration tests live in
  `crates/edge/tests/edge_tcp.rs`. All tests bind on `127.0.0.1:0`
  (ephemeral) and drive the public API only.

## Session 03 — Bidirectional TCP Streaming / TCP Relay — complete

Scope that was actually delivered:

- Added the bidirectional TCP relay primitives to
  `tunnelproxy-edge`: `run_relay_listener(bind_addr, upstream_addr)`,
  `relay_connection(downstream, peer, upstream_addr) -> Result<RelayStats, RelayError>`,
  `relay_bidirectional(downstream, upstream) -> Result<RelayStats, RelayError>`,
  plus the small [`RelayStats`], [`RelayError`], and [`RelayDirection`]
  types. Relay bytes flow via
  [`tokio::io::copy_bidirectional`], which honors TCP half-close: when
  one direction finishes it, the matching write half is shut down so
  the remote peer observes EOF.
- Each accepted downstream connection opens exactly one fresh
  upstream TCP connection (`TcpStream::connect`). There is no upstream
  connection pool, by intent (Session 04 may revisit this).
- Connection isolation: a per-connection upstream-connect failure
  closes only that downstream connection; the listener keeps serving
  the next caller.
- Development binary `edge_dev` runs as a relay by default
  (`TUNNELPROXY_EDGE_ADDR` defaults to `127.0.0.1:7000`,
  `TUNNELPROXY_EDGE_UPSTREAM` defaults to `127.0.0.1:8000`). A new
  `upstream_echo_dev` example is provided for manual smoke tests.
  `agent_dev` is unchanged; it transparently verifies the echo
  through the relay.
- Real TCP integration tests for the relay live in
  `crates/edge/tests/relay_tcp.rs` (7 tests):
  - `relay_round_trip_small_payload`
  - `relay_round_trip_large_payload` (256 KiB deterministic, binary-safe)
  - `relay_preserves_half_close`
  - `relay_listener_survives_unreachable_upstream`
  - `relay_bidirectional_returns_byte_counts`
  - `relay_connection_reports_upstream_connect_failure`
  - `run_relay_listener_binds_and_serves_one_connection`
- The Session 02 echo baseline (`run_listener` / `handle_connection`
  and `tests/edge_tcp.rs`) is preserved unchanged.

## Session 04 — TCP Relay Lifecycle Hardening / Local Port Forwarding — complete

Scope that was actually delivered:

- Hardened the Session 03 relay into a small, lifecycle-aware local
  TCP forwarder. The relay primitives (`run_relay_listener`,
  `relay_connection`, `relay_bidirectional`, `RelayStats`,
  `RelayError`, `RelayDirection`) are preserved unchanged for
  regression coverage; the new code lives alongside them.
- New public surface in `tunnelproxy-edge`:
  - `ForwardConfig { listen_addr, upstream_addr, max_connections,
    connect_timeout }` with `dev_defaults()` and `validate()`.
  - `ForwardConfigError::{ZeroMaxConnections, ZeroConnectTimeout}`.
  - `ConnectionId(u64)` + `ConnectionIdAllocator` (atomic counter,
    monotonic).
  - `ConnectionLifecycle::{Accepted, CapacityRejected,
    ConnectingUpstream, UpstreamConnectFailed, UpstreamConnectTimeout,
    Relaying, RelayIoFailed, Closed}` + `as_str()`.
  - `ForwardError::{CapacityExhausted, UpstreamConnect,
    UpstreamConnectTimeout, RelayIo}` + `category()` and `phase()`.
  - `ConnectionOutcome { connection_id, peer, upstream, outcome,
    duration, final_phase() }`.
  - `Forwarder::new(config)` and `forwarder.run()` — binds the
    listener, owns an `Arc<Semaphore>`, and runs the accept loop.
  - `forward_handle_connection(...)` — the lifecycle-aware per-
    connection function exposed publicly.
- Bounded upstream connect via `tokio::time::timeout(config.connect_timeout,
  TcpStream::connect(...))`. Timeouts and I/O errors are distinguished
  and surface as `UpstreamConnectTimeout` vs `UpstreamConnect`.
- Bounded concurrent admission via `tokio::sync::Semaphore::new(
  config.max_connections)`. Accepted connections with no available
  permit are rejected cleanly (downstream shut down, listener keeps
  running). Permit is owned by the per-connection task via RAII
  (`OwnedSemaphorePermit`).
- Per-connection resources (`downstream TcpStream`, `upstream
  TcpStream`, semaphore permit) are owned by the per-connection task;
  dropping the task drops everything — no detached child tasks.
- Structured `tracing` events carry `connection_id` everywhere and
  emit `phase`, `error_category`, `duration_ms`, `bytes_*` for
  observability.
- Development binary `edge_dev` now exposes a CLI:
  `--listen`, `--upstream`, `--max-connections`,
  `--connect-timeout-ms`, `--help`. Defaults match the previous
  environment-driven behaviour.
- Real TCP integration tests for the forwarder live in
  `crates/edge/tests/forwarder.rs` (9 tests):
  - `forwarder_golden_path_round_trip`
  - `forwarder_capacity_limit_one_rejects_then_releases`
  - `forwarder_preserves_half_close`
  - `forwarder_large_payload_round_trip` (256 KiB)
  - `forwarder_unreachable_upstream_surfaces_upstream_connect_failure`
  - `forwarder_recoverable_failure_does_not_kill_listener`
  - `forwarder_new_rejects_invalid_config`
  - `forwarder_failure_then_recovery_via_restart`
  - `connection_id_allocator_yields_unique_ids`
- All Session 02 echo tests (`tests/edge_tcp.rs`) and Session 03
  relay tests (`tests/relay_tcp.rs`) still pass unchanged.
- Manual smoke test of the CLI-driven `edge_dev` against an
  `upstream_echo_dev`, including an upstream stop / restart cycle,
  confirmed lifecycle logs and byte stats.
- Updated `docs/ai/CURRENT_STATE.md`, `docs/ai/TEST_MATRIX.md`,
  `docs/TECH_DEBT.md` (closes DEBT-007; DEBT-005 and DEBT-006 remain
  open by design), and `docs/ARCHITECTURE.md` (added §2.6.1 for the
  forwarder).

Out of scope (explicitly NOT delivered in Session 04):

- Reverse tunnel, persistent Agent ↔ Edge tunnel, framing protocol.
- Graceful shutdown channel on the listener (DEBT-005 still open).
- Idle read deadline on the relay path (DEBT-006 still open).
- Upstream connection pooling (DEBT-008 still open).

## Session 05 — Tunnel Protocol v1: Binary Framing & Message Design — complete

Scope that was actually delivered:

- Replaced the placeholder `tunnelproxy-protocol` crate with a real,
  test-covered wire protocol foundation.
- New module `crates/protocol/src/wire.rs`: `MAGIC = [0x54, 0x50, 0x58, 0x31]`
  ("TPX1"), `VERSION = 1`, `HEADER_SIZE = 16`, `MAX_FRAME_PAYLOAD = 65536`.
- New module `crates/protocol/src/frame.rs`: `FrameType` enum (stable numeric
  values 0x01–0xFF), `Scope` (Control / Stream), `StreamId` newtype wrapper,
  `Frame` struct with validated construction. Stream scope validation enforced
  at construction time.
- New module `crates/protocol/src/error.rs`: `ProtocolError` typed enum with
  distinct variants for every failure class (I/O, invalid magic, unsupported
  version, unknown frame type, unsupported flags, invalid stream scope,
  frame too large, truncated header, truncated payload).
- New module `crates/protocol/src/codec.rs`: `FrameEncoder::encode` (async,
  `write_all` semantics, validates before writing) and
  `FrameDecoder::decode` (async, stateful cursor, handles fragmentation and
  coalescing). Decoder validates announced payload length **before
  allocating buffer**. Three-way EOF distinction.
- 26 deterministic codec tests covering: round-trip (control + stream),
  binary/non-UTF8 payload, fragmented header (1 byte/read), fragmented
  payload (1 byte/read), coalesced frames, clean EOF, truncated header,
  truncated payload, invalid magic, unsupported version, unknown frame
  type, unsupported flags, invalid stream scope (both directions),
  oversized encode reject, oversized decode reject, and a real loopback
  TCP test using `TcpListener` / `TcpStream`.
- New file `docs/TUNNEL_PROTOCOL_V1.md`: complete wire format documentation,
  header layout table, frame type registry, scope rules, EOF semantics,
  error taxonomy, security rationale, explicit "not yet defined" statements
  for all frame payload schemas and runtime behaviors.
- Added `tokio` and `thiserror` as dependencies of `tunnelproxy-protocol`.
  Protocol crate remains free of `tunnelproxy-edge`, `tunnelproxy-agent`,
  and `tunnelproxy-control-plane` dependencies.
- Updated `docs/ai/CURRENT_STATE.md`, `docs/ai/SESSION_INDEX.md`,
  `docs/ai/TEST_MATRIX.md` (added tunnel protocol framing row), and
  `docs/ai/DECISIONS.md` (ADR-007 for length-prefixed binary framing).
- All quality gates pass: `cargo fmt --all`, `cargo clippy --workspace`,
  `cargo test --workspace` (58 tests, 0 failures), `cargo build --workspace`.

Out of scope (explicitly NOT delivered in Session 05):

- Persistent Agent ↔ Edge connection.
- HELLO / REGISTER / REGISTERED handshake behavior (types exist, semantics not implemented).
- Stream multiplexing runtime (stream IDs exist as values, demux logic not implemented).
- PING / PONG keepalive timer (types exist, timer not implemented).
- Any payload schema for any frame type (all payloads are opaque `Vec<u8>`).
- Authentication, TLS, HTTP, WebSocket.
- Graceful shutdown (DEBT-005 still open).
- Idle read deadline (DEBT-006 still open).
- Upstream connection pool (DEBT-008 still open).
- Per-IP admission control (DEBT-009 still open).
- Telemetry backend (DEBT-010 still open).

## Session 06 — Persistent Agent ↔ Edge Transport & Protocol Handshake — complete

Scope that was actually delivered:

- Extended `tunnelproxy-protocol` with the handshake type module
  (`crates/protocol/src/handshake.rs`): `HelloRole`, `TransportSessionId`,
  `TransportSessionIdAllocator`, `HandshakeErrorCode`, plus the wire
  constants `HELLO_PAYLOAD_SIZE`, `REGISTERED_PAYLOAD_SIZE`, `ERROR_PAYLOAD_SIZE`.
- Added `tunnelproxy-edge` dependency on `tunnelproxy-protocol`.
- Added `tunnelproxy-agent` dependency on `tunnelproxy-protocol`.
- New Edge module `crates/edge/src/agent_transport.rs`:
  `AgentListenerConfig`, `AgentTransportListener`, `TransportSessionIdAllocator`,
  `HandshakeState`, `AgentTransportError`, `AgentSession`. The listener
  binds via `bind()` and runs via `run()`. Per-connection task performs the
  v1 handshake under a bounded semaphore and timeout. Strict state machine:
  AWAIT_HELLO → AWAIT_REGISTER → ESTABLISHED → CLOSED. ERROR frame sent for
  protocol violations. Established session waits for incoming bytes / EOF.
- New Agent module `crates/agent/src/agent_transport.rs`:
  `AgentError`, `AgentSession`, `ConnectOutcome`, `connect()`.
  Performs HELLO → REGISTER → REGISTERED handshake. `AgentSession` owns
  the socket and exposes `read_frame()` for future use.
- Strict handshake sequencing enforced on both sides: HELLO must be first,
  REGISTER must be second. Any deviation is a protocol violation.
- Bounded concurrent admission: `Semaphore` sized to `max_agent_sessions`,
  permit acquired **before** handshake, held until connection closes.
- Bounded handshake timeout: Tokio timeout wraps the handshake phase only.
  Established session lifetime is unlimited in Session 06.
- Structured `tracing` events throughout with `session_id`, `peer`, `duration_ms`.
- New integration tests in `crates/edge/tests/agent_transport.rs` (12 tests):
  valid handshake, invalid first/second frames, invalid payloads, timeout,
  capacity release, peer disconnect cleanup, session ID uniqueness, session
  remains open.
- New unit tests in `crates/edge/src/agent_transport.rs` (6 tests):
  config validation, allocator monotonicity, handshake state.
- New unit tests in `crates/protocol/src/handshake.rs` (4 tests):
  role roundtrip, session ID validity/bytes, error code roundtrip.
- All 80 explicit workspace tests pass (58 pre-existing + 22 Session 06
  protocol/unit/integration tests).
- New `docs/AGENT_EDGE_TRANSPORT.md`: topology, handshake sequence diagram,
  payload schemas, TransportSessionId semantics, state machines, bounded
  admission, timeout semantics, disconnect behavior, ERROR codes, reader/writer
  ownership note, what is NOT implemented.
- Updated `docs/TUNNEL_PROTOCOL_V1.md`: Session 06 payload schemas,
  handshake error codes, updated "What Is NOT Implemented" section.
- Updated `docs/ai/CURRENT_STATE.md`, `docs/ai/TEST_MATRIX.md`,
  `docs/ai/SESSION_INDEX.md`.

Out of scope (explicitly NOT delivered in Session 06):

- TLS / encryption (transport is development-only, loopback only).
- Agent authentication.
- Heartbeat / PING-PONG timers (PING/PONG frame types exist, behavior not implemented).
- Reconnect logic.
- Stream multiplexing (OPEN_STREAM / DATA frames have no runtime).
- Durable tunnel registration (REGISTER here means only "register this
  TCP connection as an ephemeral transport session").
- Public endpoint / hostname allocation.
- Traffic forwarding / reverse tunneling.
- Graceful shutdown channel (DEBT-005 still open).
- Idle read deadline on established sessions (DEBT-006 still open).
- Upstream connection pool (DEBT-008 still open).
- Per-IP admission control (DEBT-009 still open).
- Telemetry backend (DEBT-010 still open).

## Session 07 — Heartbeat, Liveness & Dead-Session Detection — complete

Scope delivered:

- Protocol heartbeat contract: exported `HeartbeatSequence`,
  `HeartbeatErrorCode`, and `HEARTBEAT_PAYLOAD_SIZE = 8`.
- Edge-initiated PING and Agent PONG with an identical non-zero big-endian
  sequence. Only one heartbeat is outstanding at a time.
- Edge `AgentListenerConfig` now validates configurable heartbeat interval and
  PONG timeout values (15 s / 10 s defaults).
- Established sessions decode complete frames instead of reading one arbitrary
  byte. Timeout, malformed PONG, sequence mismatch, unsolicited PONG,
  Agent-initiated PING, and unsupported frames close only that session.
- Agent `AgentSession::run()` drives the heartbeat responder and
  `AgentSession::close()` exposes an explicit local close path.
- Heartbeat timeout releases the session semaphore permit through RAII.
- Structured heartbeat events include session, peer, sequence, RTT, and close
  reason without logging network payloads.
- Added 14 tests: 4 protocol unit tests, 2 Edge config tests, and 8 real-TCP
  integration tests. The repository contains 94 explicit tests after Session 07.
- Updated protocol, transport, current-state, test-matrix, decision, and
  technical-debt documentation.

Out of scope:

- Reconnect and exponential backoff.
- OPEN_STREAM / DATA runtime and multiplexing.
- Reverse traffic forwarding and public HTTP ingress.
- TLS, Agent authentication, durable tunnel registration, and hostnames.
- Listener graceful shutdown and relay-path idle timeout.

## Session 08 — Single-Stream Reverse Data Path — complete

Scope delivered:

- Activated Protocol v1 stream semantics without changing the reserved frame
  numbers or 16-byte header: empty OPEN_STREAM request/acknowledgment,
  non-empty binary DATA, empty directional END_STREAM, and two-byte typed
  RESET_STREAM.
- Added seven reset categories: local connect failure/timeout, I/O failure,
  protocol violation, stream busy, open timeout, and idle timeout.
- Added Agent `run_with_local_target(local_addr, connect_timeout)`, which
  connects one opened stream to a configured local TCP service and returns to
  idle after stream cleanup.
- Added loopback-only `SingleStreamEdgeRuntime` with separate Agent and raw TCP
  ingress listeners. Exactly one Agent and one active stream are permitted.
- Edge allocates monotonic non-zero stream IDs. A transport can serve multiple
  streams sequentially without ID reuse.
- Preserved directional TCP half-close and kept Edge heartbeat live while a
  stream is active.
- Bounded application reads at 16 KiB, retained the 64 KiB codec ceiling, used
  sequential writes, and introduced no unbounded queues.
- Added stream-open and stream-idle deadlines plus the existing Agent local
  connect deadline. Failures reset only the affected stream when the transport
  remains valid.
- Added 18 tests: 2 protocol unit tests, 6 Edge configuration tests, and 10
  real-TCP integration tests. The workspace contains 112 explicit tests.
- Updated protocol, architecture, transport, current-state, decision,
  test-matrix, technical-debt, and crate documentation.

Out of scope:

- Concurrent stream multiplexing and flow-control windows.
- Public HTTP/HTTPS ingress, TLS termination, hostname allocation, and routing.
- Agent authentication, durable registration/identity, and control-plane state.
- Reconnect and exponential backoff.
- Production CLI wiring, graceful process shutdown, and multi-edge operation.

## Session 09 — Bounded Stream Multiplexing & Session Routing — complete

Scope delivered:

- Added bounded concurrent stream maps on Edge and Agent while preserving the
  Session 08 OPEN_STREAM/DATA/END_STREAM/RESET_STREAM wire contract.
- Added one decoder owner and one bounded writer actor per transport, bounded
  per-stream receive queues, a shared bounded DATA queue, and priority handling
  for heartbeat and reset traffic.
- Added `MultiplexedEdgeRuntime`, a live session registry, and
  `EdgeSessionRouter::open_stream(TransportSessionId, TcpStream)` for exact
  ephemeral session routing.
- Added Agent `run_multiplexed(MultiplexedAgentConfig)` with independent local
  TCP tasks, half-close, connect/idle deadlines, and stream-local cleanup.
- Added capacity, unknown-stream, flow-control, and session-closing reset codes.
- Added eight unit/integration tests. Real TCP coverage includes eight
  concurrent streams, capacity rejection, two-Agent routing, local failure
  isolation, bounded framing, and heartbeat interleaving. The workspace now
  contains 120 explicit tests.

Out of scope:

- Public HTTP/HTTPS ingress, hostname allocation, and TLS termination.
- Durable tunnel/Agent identity, persistent routing, and control-plane state.
- Authentication, reconnect/backoff, graceful process shutdown, and multi-edge.
- Credit-based flow-control windows and strict weighted scheduling.

## Session 10 — Raw Ingress Binding & Route Lifecycle — complete

Scope delivered:

- Added `EdgeSessionRouter::open_stream_tracked` and `RoutedStream` completion
  signals while preserving the Session 09 `open_stream` API.
- Added live-session snapshot subscriptions for disconnect-aware route cleanup.
- Added `RawIngressRouteManager` with bounded route count, loopback-only
  listeners, per-route connection admission, monotonic process-local route IDs,
  and typed configuration/lifecycle errors.
- Defined `Active`, `Draining`, `TargetDisconnected`, and `Removed` states.
  Removing stops new accepts and waits for real stream completion; drain timeout
  never silently aborts active traffic.
- Added 13 tests: three route/config unit tests and ten real-TCP integration
  tests covering byte-exact traffic, concurrency, two-Agent exact routing,
  capacity, drain, timeout, disconnect, and local-service recovery. The
  workspace now contains 133 explicit tests.

Out of scope:

- Public HTTP/HTTPS ingress, hostname allocation, TLS, and authentication.
- Durable route/tunnel identity, persistence, reconnect, and automatic rebind.
- Process-wide graceful shutdown, OS signal wiring, and multi-edge operation.
- Credit-based flow control and weighted DATA scheduling.

## Session 11 — Graceful Runtime Shutdown & Supervision — complete

Scope delivered:

- Added shared idempotent shutdown trigger/signal primitives, a validated
  process drain deadline, and typed drained/forced completion outcomes.
- Added shutdown-aware echo, relay, forwarder, Agent listener, legacy
  single-stream, multiplexed Edge, and multiplexed Agent runtime APIs.
- Replaced detached accept-loop work with supervised task sets. Shutdown stops
  admission first, drains children, then aborts and joins deadline overruns.
- Made multiplex routing fail closed during drain and reused the protocol's
  `SessionClosing` reset for late Agent stream requests.
- Added global raw-route manager shutdown, post-shutdown admission rejection,
  child connection supervision, and forced cleanup after its deadline.
- Added 12 unit/integration tests for signal races, graceful and forced paths,
  listener release, route-manager terminal state, and Agent/Edge admission.
  The workspace now contains 145 explicit tests.
- Resolved DEBT-005 and DEBT-012.

Out of scope:

- OS signal wiring and production runtime composition.
- Public HTTP/HTTPS ingress, TLS, authentication, and hostname allocation.
- Durable identity/routes, persistence, reconnect, and automatic rebind.
- Credit/window flow control and weighted DATA scheduling.

## Session 12 — Production Runtime Entrypoints & OS Signal Wiring — complete

Scope delivered:

- Added validated `EdgeRuntime` and `AgentRuntime` process supervisors.
- Edge waits for one Agent, binds one loopback raw route, performs route-first
  ordered shutdown, and rolls back its transport if route startup fails.
- Agent composes cancellable outbound connect/handshake with the bounded
  multiplexed local bridge; reconnect remains disabled.
- Added runnable `tunnelproxy-edge` and `tunnelproxy-agent` binaries with
  addresses, capacity, connect/handshake, and drain CLI settings.
- Added Ctrl-C observation on every platform and SIGTERM on Unix. Signal code
  only requests cancellation; runtime owners retain cleanup responsibility.
- Defined exit codes for graceful shutdown, runtime/forced failure, and invalid
  configuration.
- Added 17 unit/integration tests for config/outcomes, both CLI parsers,
  cancellation before startup, byte-exact composed forwarding, ordered
  shutdown, listener release, and startup rollback. The workspace now contains
  162 explicit tests.
- Recorded the one-Agent/no-reconnect limitation as DEBT-016.

Out of scope:

- Reconnect/backoff and automatic raw-route rebind.
- Authentication, TLS, public HTTP ingress, and hostname allocation.
- Durable tunnel/Agent identity, persistence, and control-plane routing state.
- Multi-Agent route selection and multi-edge operation.

## Session 13 — Agent Reconnect & Route Recovery — complete

Scope delivered:

- Added validated `ReconnectConfig` with bounded exponential delay, downward
  jitter, a stable-session failure-streak reset, and an optional consecutive
  failure budget.
- Changed `AgentRuntime` into a cancellation-aware reconnect supervisor.
  Transient connect, timeout, established I/O, and peer-close failures retry;
  protocol and handshake-contract violations remain terminal.
- Added Agent attempt/session/reconnect outcomes and structured recovery events,
  plus CLI flags for every reconnect policy input.
- Kept the Edge Agent listener running after disconnect. Once dead-session route
  cleanup releases its listener, `EdgeRuntime` binds the same configured
  loopback raw address to the next live ephemeral session.
- Added typed recovery failure and Edge generation/recovery counters. Every
  handshake still receives a new `TransportSessionId`; no stream is replayed.
- Added five tests, including four real-TCP scenarios for backoff cancellation,
  retry-budget exhaustion, replacement Agent recovery, and Edge restart
  recovery. The workspace now contains 167 explicit tests.
- Resolved DEBT-016. DEBT-015 remains open because routes and session identity
  are still process-local and non-durable.

Out of scope:

- Authentication, TLS, public HTTP ingress, and hostname allocation.
- Durable tunnel/Agent identity, persistence, and control-plane routing state.
- In-flight stream replay/migration, multi-Agent route selection, and multi-edge
  operation.
- Credit/window flow control and weighted DATA scheduling.

## Session 14 — Mutual TLS & Agent Authentication — complete

Scope delivered:

- Added rustls/tokio-rustls transport security with ALPN `tunnelproxy/1` while
  retaining the unchanged Protocol v1 frame and handshake contract.
- Added safe PEM builders for Edge server identity/client CA and Agent client
  identity/Edge CA/server name. Private-key material is omitted from Debug,
  errors, logs, and committed test fixtures.
- Refactored multiplexed session I/O to support either boxed plaintext TCP or
  TLS without duplicating heartbeat, stream lifecycle, or bounded writer code.
- Edge now authenticates the Agent certificate under a separate TLS deadline
  while holding the existing capacity permit. A session becomes routable only
  after TLS and Protocol v1 both succeed.
- Agent now treats CA, server-name, ALPN, and client-auth rejection as terminal;
  transient transport failure and TLS timeout remain reconnectable. Secure
  Edge restart performs a fresh TLS and protocol handshake.
- Plaintext is rejected for non-loopback runnable transport; mTLS permits a
  non-loopback Agent listener. Raw ingress remains loopback-only.
- Added TLS flags to both CLIs with complete-set validation and asynchronous PEM
  loading. Partial configuration exits as invalid configuration.
- Added 18 tests for config and CLI validation, authenticated byte forwarding,
  wrong Edge CA/name, missing ALPN, missing/untrusted Agent certificates, TLS
  timeout and capacity recovery, cancellation, secure reconnect, and
  secret-safe Debug. The workspace now contains 185 explicit tests.
- Recorded static certificate lifecycle limitations as DEBT-017.

Out of scope:

- Durable Agent/tunnel identity, certificate-to-Agent mapping, and tunnel
  authorization.
- Certificate issuance, rotation, revocation, and hot reload.
- Public HTTP/HTTPS ingress, hostname allocation, and public raw ingress.
- Protocol v2, token registration, multi-edge routing, and stream replay.

## Session 15 — Authenticated Tunnel Identity & Registration — complete

Scope delivered:

- Bumped the wire header to Protocol v2 and TLS ALPN to `tunnelproxy/2`.
  Protocol v1 peers are rejected explicitly; no downgrade is attempted.
- Added bounded `AgentId`/`TunnelId` validation and a deterministic REGISTER
  schema: two big-endian `u16` lengths followed by UTF-8 identifier bytes.
- Replaced the control-plane placeholder with immutable authorization
  snapshots mapping SHA-256 client-certificate fingerprints to exact Agent and
  enabled Tunnel grants.
- Edge now extracts the authenticated TLS leaf certificate, authorizes the
  claimed identity before REGISTERED, and returns typed terminal rejection for
  unknown certificates, identity mismatch, unauthorized/disabled tunnels, and
  malformed registration.
- Added RAII live-tunnel claims. A duplicate TunnelId is rejected before
  publication; `TunnelAlreadyConnected` is the only retryable registration
  rejection and the claim releases on every close/failure path.
- Added cached `TunnelId -> TransportSessionId` routing. The runnable raw
  listener targets TunnelId, stays bound while Agent is offline, fails closed,
  and starts using the fresh session after authenticated reconnect without a
  storage lookup or listener rebind.
- Added Agent/Edge identity CLI flags and exact authorized-client-certificate
  input for the single-tunnel TLS CLI.
- Added 14 tests for ID/codec/config bounds, v1 rejection, snapshot authorization,
  same-CA unassigned certificates, false identity claims, disabled/duplicate
  tunnels, claim release, and durable offline/online routing. The workspace now
  contains 199 explicit tests.

Out of scope:

- Persistent database/API control plane and live snapshot distribution.
- Certificate issuance, rotation, revocation, expiry monitoring, and hot reload.
- Public HTTP/HTTPS or raw ingress, hostname allocation, and access policy.
- Multiple tunnels on one transport, multi-edge routing, and stream replay.

## Session 16 — Control-Plane Snapshot Distribution & Live Revocation — complete

Scope delivered:

- Added non-zero monotonic `SnapshotVersion` and complete
  `VersionedAuthorizationSnapshot` values. Higher versions replace all grants;
  equal content is idempotent, stale updates and same-version conflicts are
  typed failures, and version gaps are valid.
- Added a bounded Tokio watch publisher/subscriber in the control-plane crate.
  It retains only the latest complete snapshot; source closure preserves the
  cached value for fail-static Edge operation.
- Converted mutual-TLS Edge authorization from a startup-only snapshot to a
  shared live subscription while preserving the existing static CLI builder.
  Tunnel administrative state is now only enabled/disabled; connectivity stays
  in Edge's runtime registry.
- Revalidated the authenticated certificate/Agent/Tunnel principal immediately
  before session publication. One authorization gate orders publication,
  stream enqueue, and reconciliation so older authorization cannot race back
  into routing after an applied revoke.
- Snapshot reconciliation removes revoked TunnelId and TransportSessionId
  mappings before cancelling their exact Agent sessions. Active streams close,
  raw ingress remains bound, and later authorized Agents can reconnect without
  Edge restart or listener rebind.
- Added observable cached authorization status: current version, static/live/
  stale source state, and cumulative revoked-session count. A closed producer
  keeps the last cached snapshot active and reports stale state.
- Added eight tests for version ordering/gaps, duplicate/conflict/stale updates,
  bounded latest-value delivery, cached state after close, publication-race
  revalidation, live grant add, unrelated updates, active revocation, and
  re-enable on the same raw listener. The workspace now contains 207 explicit
  tests.

Out of scope:

- Persistent database/schema and restart-safe snapshot storage.
- Authenticated cross-process control-plane API or transport.
- Certificate issuance/rotation/hot reload and multi-edge consistency.
- Public HTTP/HTTPS/raw ingress, hostname allocation, and access policy.
- Protocol v3, multiple tunnels per Agent transport, and stream replay.

## Session 17 — Persistent Snapshot Storage & Authenticated Edge Bootstrap — complete

Scope delivered:

- Added a canonical, bounded binary codec for complete authorization snapshots,
  including stable ordering, SHA-256 content digests, strict identifier/status
  validation, and a 1 MiB wire ceiling.
- Added a synchronous `SnapshotRepository` boundary and a bundled-SQLite
  implementation. Full snapshot replacement and its version/digest head commit
  in one `IMMEDIATE` transaction with WAL and `synchronous = FULL`.
- Added `PersistentSnapshotAuthority`, which loads the latest committed
  snapshot on startup, rejects an uninitialized repository, serializes commits
  off the async executor, and publishes only after durable commit succeeds.
- Added a dedicated snapshot protocol and mTLS service using ALPN
  `tunnelproxy-snapshot/1`; Tunnel Protocol v2 is unchanged. Edge sends its last
  applied version, receives a full snapshot or `UpToDate`, and rejects an
  ahead/invalid response.
- Added the reconnecting Edge snapshot client and a composition helper for
  building `EdgeRegistrationPolicy`. Loss of the service marks authorization
  `Stale` while retaining the last cached full snapshot; reconnect resumes from
  the in-memory version and returns the source to `Live`.
- Bounded Edge-client admission, TLS/connect/subscribe/read-write operations,
  snapshot size/cardinality, latest-value delivery, retry delay, and shutdown
  cancellation are enforced.
- Added eight unit/integration tests for canonical/malformed codecs, SQLite
  reopen and ordering, durable-before-publish behavior, protocol strictness,
  real mTLS bootstrap/push/reconnect, wrong server identity, and cancellation.
  The workspace now contains 215 explicit tests.

Out of scope:

- Runnable Control Plane daemon/CLI and production configuration loading.
- Administrative mutation API, accounts, quotas, and certificate issuance.
- Edge disk cache across a Control Plane outage at cold startup.
- Certificate rotation/hot reload, multi-edge ownership, and public ingress.
