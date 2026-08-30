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
| 18      | Runnable Snapshot Service & Operations Wiring  | complete |
| 19      | Edge Cold-Start Snapshot Cache                 | complete |
| 20      | Certificate Lifecycle & Atomic TLS Reload      | complete |
| 21      | Automated Agent Enrollment & Renewal           | complete |
| 22      | Emergency Credential Revocation & Reconciliation | complete |
| 23      | Public Raw TCP Ingress & Per-IP Admission      | complete |
| 24      | Reproducible Builds & GitHub CI                | complete |
| 25      | Bounded Public HTTPS/HTTP/1.1 Ingress          | complete |
| 26      | Bounded HTTP Request Rate Limiting & Observability | complete |
| 27      | Bounded Edge Operations Endpoint & Prometheus Metrics | complete |
| 28      | Secret-Safe Structured JSON Logging            | complete |
| 29      | Bounded Agent Operations Endpoint & Connection Metrics | complete |
| 30      | Bounded Control Plane Operations Endpoint & Service Metrics | complete |
| 31      | Durable HTTPS Route Catalog & CLI Administration | complete |
| 32      | Authenticated HTTPS Route Distribution & Atomic Edge Activation | complete |
| 33      | Atomic TLS Generation Reload for HTTPS Route Distribution | complete |
| 34      | Bounded HTTP/1.1 Keep-Alive & Per-Request Deadlines | complete |
| 35      | Bounded Fair DATA Scheduling                  | complete |
| 36      | Multiplexed Transport Fairness Telemetry       | complete |
| 37      | Live Transport Capacity Telemetry & Operator Runbook | complete |
| 38      | Bounded Nonblocking Process Logging & Sink Telemetry | complete |
| 39      | Durable Managed-Hostname Allocation & Release | complete |
| 40      | Authenticated Agent Managed-Hostname Lifecycle | complete |
| 41      | Atomic TLS & Agent-CA Rotation for Hostname Service | complete |
| 42      | Managed HTTP Agent Orchestration              | complete |
| 43      | Canonical Agent CLI & Strict Local Config v1  | complete |
| 44      | Bounded HTTP/2 Public HTTPS Ingress           | complete |
| 45      | Bounded WebSocket Upgrade Ingress             | complete |
| 46      | Bounded Route-Bound HTTP/1.1 CONNECT Ingress  | complete |

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

## Session 18 — Runnable Snapshot Service & Operations Wiring — complete

Scope delivered:

- Added a strict, unknown-field-denying JSON manifest for complete snapshots.
  Input, agent/tunnel cardinality, IDs, fingerprints, status, duplicate grants,
  and non-zero versions are validated before storage.
- Added `tunnelproxy-control-plane import`, which reads at most 1 MiB and uses
  Session 17 transaction/idempotency/stale/conflict rules to initialize or
  replace the durable authority.
- Added `PersistentSnapshotAuthority::refresh_from_repository` and a supervised
  `ControlPlaneRuntime`. The runtime refuses uninitialized storage, polls with
  skipped missed ticks, publishes only committed versions, owns the mTLS server,
  and joins it on shutdown.
- Added `tunnelproxy-control-plane serve` with required database/server
  certificate/key/Edge CA inputs plus bounded capacity, TLS, request, and
  refresh settings. Ctrl-C/SIGTERM maps to owned runtime cleanup and stable exit
  codes.
- Added `SnapshotAwareEdgeRuntime`, which completes authenticated bootstrap
  before binding Edge listeners and supervises Edge plus snapshot reconnect
  under one shutdown lifecycle.
- Extended the Edge CLI with a mutually exclusive dynamic snapshot mode while
  preserving plaintext loopback and static mTLS authorization modes.
- Added 11 unit, integration, and process tests for manifests, import CLI,
  external refresh, uninitialized startup, Control Plane restart, full routed
  Edge composition, cold-bootstrap listener rollback, CLI modes, and shutdown.
  The workspace now contains 226 explicit tests.

Out of scope:

- General admin HTTP/CRUD APIs, users/accounts, quotas, and billing.
- Edge disk cache for cold startup while Control Plane is unavailable.
- Certificate rotation/hot reload, public ingress, and multi-edge consensus.

## Session 19 — Edge Cold-Start Snapshot Cache — complete

Scope delivered:

- Added an opt-in filesystem cache with an explicit non-zero maximum stale age.
  Cache records contain versioned canonical payloads, authentication timestamps,
  bounded lengths, format metadata, and SHA-256 integrity digests.
- Added cross-platform generation-file replacement: unique temporary write,
  file synchronization, rename to an immutable final generation, then cleanup.
  Temporary crash remnants are ignored and filesystem work runs off Tokio.
- Enforced monotonic durable state. Lower versions, filename/payload mismatch,
  same-version conflicting content, corruption, future timestamps, and expired
  records fail closed. Durable cache write precedes in-memory publication.
- Added online-first bootstrap. Only connection/timeout availability failures
  may use disk; TLS identity, ALPN, protocol, server rejection, and update
  errors remain terminal and cannot be hidden by cache fallback.
- Added bounded stale runtime behavior. Offline cold start reports `Stale`,
  reconnect uses the cached version, authenticated `Snapshot`/`UpToDate`
  refreshes disk before `Live`, and deadline expiry stops Edge listeners.
- Extended `SnapshotAwareEdgeRuntime` and the Edge CLI with optional paired
  `--snapshot-cache-dir` / `--snapshot-cache-max-stale-ms` configuration while
  retaining the existing online-only API and static/plaintext modes.
- Added seven unit/integration tests for cache envelopes, generations, ordering,
  expiry, online/offline bootstrap, TLS non-fallback, reconciliation, routed
  cold-start traffic, persistence-before-publication failure, and listener
  release. The workspace now contains 233 explicit tests.

Out of scope:

- Cryptographic snapshot signing, TPM/secure monotonic state, and hostile local
  administrator rollback resistance.
- Certificate issuance/rotation/hot reload, general admin APIs, public ingress,
  and multi-edge consensus.

## Session 20 — Certificate Lifecycle & Atomic TLS Reload — complete

Scope delivered:

- Added a shared reload primitive with strict, bounded JSON manifests,
  SHA-256 verification of an exact file set, non-zero monotonic generations,
  same-generation conflict detection, and blocking file reads off Tokio.
- Converted Agent client, Edge server, snapshot client, and snapshot server
  rustls configurations to last-known-good atomic snapshots. New handshakes
  observe one complete config generation; invalid or partial candidates never
  replace the active generation.
- Added optional CLI reload manifests, polling intervals, and expiry-warning
  thresholds to all three runnable processes. Supervisors stop non-zero if the
  active leaf identity expires before a valid replacement is published.
- Coupled static Edge certificate authorization to its Agent-facing TLS
  manifest. Rotating the exact Agent certificate advances the local full
  snapshot and revokes sessions authorized by the previous certificate.
- Added secret-safe generation/health observability with `Current`, `Expiring`,
  `ReloadFailed`, and `Expired` state.
- Added six unit/real-mTLS integration tests for strict manifests, monotonic
  publication, expiry, Agent/Edge rotation, snapshot server/client rotation,
  old-credential rejection, and invalid-generation last-known-good rollback.
  The workspace now contains 239 explicit tests.

Out of scope:

- Automated issuance/enrollment, protected key custody, CRL/OCSP distribution,
  public ingress, and multi-edge consensus.
- Forced renegotiation of arbitrary established TLS connections. New
  handshakes use the new generation; static Edge authorization additionally
  closes sessions removed by its local snapshot update.

## Session 21 — Automated Agent Enrollment & Renewal — complete

Scope delivered:

- Added bounded Enrollment Protocol v1 over server-authenticated TLS and ALPN
  `tunnelproxy-enroll/1`, with redacted tokens and typed failures.
- Added 256-bit bootstrap/renewal tokens stored only as hashes, expiry and
  Agent/Tunnel binding, plus `create-token` secret-file CLI provisioning.
- Added a short-lived client-auth certificate issuer. Agent generates and keeps
  its ECDSA P-256 private key and submits only a signed CSR.
- Made issuance, token consumption, credential state, and new fingerprint
  snapshot publication one SQLite transaction. Exact request retries return the
  original durable certificate.
- Added two-phase renewal: publish the new fingerprint with overlap, atomically
  publish the Agent credential manifest, observe live reload, then activate and
  remove the predecessor in a later full snapshot.
- Added a durable Agent pending journal and recovery for crashes before/after
  issuance, activation, token replacement, or journal cleanup.
- Integrated optional enrollment service supervision into Control Plane and
  `--enroll-only` plus automatic expiry-window renewal into the Agent CLI.
- Added unit, CLI, repository, and real-TLS integration coverage for strict
  protocol parsing, token binding/expiry/idempotency, secret-safe provisioning,
  bootstrap, renewal, overlap, activation, and old-fingerprint revocation. The
  workspace now contains 249 explicit tests.

Out of scope:

- HSM/KMS issuer custody, CA rollover, CRL/OCSP, and emergency revocation.
- Automatic expiry cleanup for an issued credential whose Agent never sends
  activation, static Edge enrollment, and multi-Control-Plane consensus.
- Public ingress, accounts, billing, and general administrative CRUD APIs.

## Session 22 — Emergency Credential Revocation & Reconciliation — complete

Scope delivered:

- Migrated Session 21 SQLite state to explicit pending, active, retired,
  revoked, and expired states with activation deadlines and terminal times.
- Added terminal `CredentialRevoked` and recoverable `RequestExpired`
  enrollment errors without changing the bounded wire framing.
- Added idempotent Agent/Tunnel revocation that invalidates bootstrap/renewal
  tokens and removes exact authorization through the same durable full-snapshot
  transaction.
- Added a bounded supervised reconciler that tombstones abandoned pending
  requests and removes only replacement fingerprints, preserving an active
  renewal predecessor.
- Added Agent retry classification: authentication/revocation/configuration
  failures stop; network/internal failures retry; expired journals are cleared
  so a valid predecessor token can create a fresh request.
- Added `revoke-agent` and secret-safe `credential-status` operator commands,
  plus activation-grace and reconciliation-interval service controls.
- Added migration, state-machine, idempotency, token invalidation, CLI secrecy,
  real enrollment TLS, supervised expiry, and real Agent/Edge mTLS session
  revocation tests. The workspace now contains 257 explicit tests.

Out of scope:

- HSM/KMS issuer custody, CA rollover, CRL/OCSP, and multi-CA trust overlap.
- General remote admin API, roles/audit retention, public ingress, and
  multi-Control-Plane consensus.
- Static Edge enrollment and hostile local-filesystem defense.

## Session 23 — Public Raw TCP Ingress & Per-IP Admission — complete

Scope delivered:

- Added explicit `LoopbackOnly` and `Public` raw-ingress exposure policies;
  loopback remains the default and non-loopback binds require operator opt-in.
- Required Agent-facing mutual TLS and external dynamic snapshot authorization
  for the runnable public mode. Plaintext, static-certificate authorization,
  incomplete public flags, and invalid per-IP bounds fail before listener use.
- Added a per-source-IP active-connection limiter alongside the existing global
  semaphore. Its admitted-IP map is bounded by global capacity and RAII releases
  counts after route/open/session/shutdown failures.
- Added secret-safe public admission events and cumulative route counters for
  accepted connections, global rejection, per-IP rejection, and unavailable
  targets without logging traffic bytes.
- Preserved exact cached `TunnelId` routing, offline fail-close, listener
  continuity across reconnect, half-close, drain, and zero Control Plane lookup
  on the ingress hot path.
- Added config/CLI, wildcard-listener real TCP, per-IP rejection/release, static
  policy rejection, and dynamic mTLS durable-revocation coverage. The workspace
  now contains 261 explicit tests.

Out of scope:

- Public HTTP/HTTPS termination, hostname allocation, and signed access URLs.
- Request-rate limiting, distributed DDoS mitigation, and multi-edge ownership.
- Multiple tunnels per Agent transport, inspection/replay, and public-client
  authentication for arbitrary raw protocols.

## Session 24 — Reproducible Builds & GitHub CI — complete

Scope delivered:

- Changed the application-workspace policy to track `Cargo.lock`, retaining its
  Rust-1.75-readable version-3 format and requiring hosted Cargo commands to use
  `--locked`.
- Added a least-privilege GitHub Actions workflow for pull requests, pushes to
  `main`, and manual dispatch, with immutable checkout action pinning, no
  persisted credentials, bounded job timeouts, and cancellation of superseded
  runs.
- Added an Ubuntu quality job for format, all-target checking, and warning-free
  Clippy; a non-fail-fast Ubuntu/Windows MSVC matrix for all workspace tests and
  builds; and an explicit Rust 1.75 all-target MSRV check.
- Exercised the MSRV gate locally, locked `zeroize` to a Cargo-1.75-compatible
  release, and removed redundant crate-level `deny(unsafe_code)` attributes
  while preserving the stronger workspace `forbid(unsafe_code)` policy.
- Documented how to reproduce the locked gates locally and clarified that the
  hosted Windows image supplies MSVC while native local Windows builds still
  require the Visual Studio C++ workload.
- Closed DEBT-002 and DEBT-003 without changing Tunnel Protocol v2, runtime
  behavior, ingress policy, or the existing count of 261 explicit tests.

Out of scope:

- GitHub branch-protection configuration, release artifacts, code signing,
  automated dependency updates, and vulnerability/license auditing.
- Public HTTP/HTTPS termination, hostname allocation, signed access URLs, and
  multi-edge ownership.

## Session 25 — Bounded Public HTTPS/HTTP/1.1 Ingress — complete

Scope delivered:

- Added a runnable HTTPS ingress mode that replaces raw ingress and routes one
  exact normalized hostname to the configured durable TunnelId through the
  existing cached multiplexed Agent transport.
- Added independent public server TLS with HTTP/1.1 ALPN, handshake deadline,
  secret-safe typed failures, certificate validity status, and optional atomic
  generation-manifest reload for new handshakes.
- Required exact Host/SNI/absolute-authority agreement and rejected missing or
  duplicate Host, host fronting, unknown hosts, CONNECT, and upgrades before
  opening a logical tunnel stream.
- Removed hop-by-hop and client-supplied forwarding headers and emitted trusted
  canonical forwarding metadata. Requests are converted to origin form and
  response hop-by-hop fields are removed.
- Bounded global and public per-IP connections, header bytes/count, request
  body size, header/TLS/request deadlines, duplex buffering, and shutdown drain.
  Public mode requires explicit opt-in plus Agent mTLS and dynamic snapshots.
- Generalized the internal router ingress from `TcpStream` to bounded async I/O
  without changing existing APIs or Tunnel Protocol v2, and shared the RAII
  per-IP admission implementation with public raw ingress.
- Added unit, CLI, real TLS/HTTP, offline/fronting policy, security-policy, and
  public TLS reload coverage. The workspace now contains 270 explicit tests.

Out of scope:

- Automatic hostname allocation/catalog, custom domains, signed access URLs,
  and public-client authentication.
- HTTP/2, public keep-alive, WebSocket/upgrade, CONNECT, request-rate limiting,
  distributed DDoS controls, and multi-edge ownership.

## Session 26 — Bounded HTTP Request Rate Limiting & Observability — complete

Scope delivered:

- Added integer fixed-point token buckets that atomically enforce global and
  socket-source-IP request rates after authority validation and before request
  body forwarding or logical tunnel-stream creation.
- Added strict rate/burst validation, deterministic integer refill and retry
  calculation, and `429 Too Many Requests` responses with `Retry-After`.
- Bounded per-IP state by configured cardinality, idle TTL, and fixed-size
  cleanup batches. A full table fails closed and client forwarding headers are
  never used as source identity.
- Added live ingress status for admitted requests, global/per-IP/peer-capacity
  rejections, and current/peak tracked peers, plus payload-free structured
  rejection events and abort-safe active-connection accounting.
- Added runnable Edge CLI controls for global/per-IP rate and burst, maximum
  tracked peers, and idle TTL, all validated before TLS file loading or bind.
- Added token-bucket boundary tests, status/response tests, CLI validation, and
  a real TLS integration test proving rejection occurs before the local service
  and refill restores admission. The workspace now contains 279 explicit tests.

Out of scope:

- Distributed/shared quota coordination, durable limiter state, authoritative
  account billing quotas, and DDoS mitigation.
- HTTP/2, public keep-alive, WebSocket/upgrade, CONNECT, signed access URLs,
  public-client authentication, and multi-edge ownership.

## Session 27 — Bounded Edge Operations Endpoint & Prometheus Metrics — complete

Scope delivered:

- Added an opt-in loopback-only HTTP/1.1 operations runtime with typed config,
  startup/runtime failures, bounded connections/headers/timeouts/drain, and
  `/healthz`, `/readyz`, and `/metrics` for `GET`/`HEAD`.
- Defined readiness as a live configured TunnelId binding while the Edge is not
  draining. Authorization source/version/revocation and raw/HTTPS ingress state
  are read only from existing in-memory caches and status handles.
- Added fixed-cardinality Prometheus output for operations admission, raw
  ingress, HTTPS, TLS rejection, and request-rate limiting without identity,
  peer, certificate, secret, or payload labels.
- Integrated CLI opt-in and ordered lifecycle: readiness turns false, ingress
  drains while operations remains observable, operations drains next, and
  Agent transport stops last. Operations bind failure rolls back raw startup.
- Added unit, CLI, real TCP lifecycle/capacity/readiness, raw metrics, and real
  TLS HTTPS/rate-limit metrics coverage. The workspace now contains 286
  explicit tests.

Out of scope:

- Public or authenticated operations access, TLS for the operations listener,
  metrics persistence/remote write, dashboards, alerts, and JSON log output.
- Agent/Control Plane exporters, distributed rate limiting, hostname
  administration, HTTP/2, and multi-edge ownership.

## Session 28 — Secret-Safe Structured JSON Logging — complete

Scope delivered:

- Added one shared, typed logging initializer for Agent, Edge, Control Plane,
  and runnable development examples. `TUNNELPROXY_LOG_FORMAT` accepts only
  `text` or `json`; `RUST_LOG` is validated and defaults to `info`.
- Standardized JSON Lines stderr events with ANSI disabled and stable
  `timestamp`, `level`, `target`, and nested `fields` keys. Text remains the
  default and all existing tracing filters continue to apply.
- Preserved help and operator reports as plain stdout. JSON-mode CLI failures
  avoid multiline usage contamination, and invalid logging configuration exits
  before component file or network side effects.
- Added pure configuration tests and Agent/Edge/Control Plane subprocess tests
  for schema, filtering, ANSI exclusion, stdout/stderr separation, pre-mutation
  failure, and enrollment-token secrecy. The workspace now contains 296
  explicit tests.

Out of scope:

- Log file rotation, durable or remote shipping, asynchronous/nonblocking
  buffering, dashboards, and alerts.
- Agent/Control Plane metrics, hostname administration, transport fairness,
  HTTP/2, signed access URLs, and multi-edge ownership.

## Session 29 — Bounded Agent Operations Endpoint & Connection Metrics — complete

Scope delivered:

- Added process-local Agent runtime status for offline, connecting, connected,
  reconnect backoff, draining, and stopped phases plus bounded monotonic
  connection lifecycle counters.
- Added an opt-in loopback-only HTTP/1.1 operations runtime with bounded
  connections, headers, request deadline, drain deadline, and
  `/healthz`, `/readyz`, and `/metrics` for `GET`/`HEAD`.
- Defined readiness as one established registered session outside shutdown
  drain. Metrics use only a fixed state label set and exclude durable identity,
  addresses, session IDs, certificates, secrets, and payloads.
- Integrated Agent CLI flags and ordered supervision. Operations bind failure
  occurs before outbound dial; shutdown removes readiness, drains Agent/TLS/
  enrollment work, then drains operations and releases its listener.
- Added unit, CLI subprocess, and real-TCP tests for configuration/rendering,
  pre-dial rollback, offline→connected→reconnect readiness, counters, capacity
  RAII, ordered shutdown, and port release. The workspace now contains 302
  explicit tests.

Out of scope:

- Control Plane metrics, stream/byte telemetry, public/authenticated operations,
  remote write, durable metric history, dashboards, alerts, and log buffering.
- Hostname administration, transport fairness, HTTP/2, signed access URLs, and
  multi-edge ownership.

## Session 30 — Bounded Control Plane Operations Endpoint & Service Metrics — complete

Scope delivered:

- Added an opt-in loopback-only HTTP/1.1 operations listener with bounded
  connections, headers, request/drain deadlines, and `GET`/`HEAD` health,
  readiness, and metrics routes.
- Defined readiness as initialized snapshot authority with live distribution
  and optional enrollment supervisors outside drain. Scrapes read only
  process-local atomics and never query SQLite or another service.
- Added fixed-cardinality snapshot, refresh, enrollment, reconciliation, and
  operations metrics without identity, address, path, certificate, secret, or
  payload values.
- Integrated CLI configuration, bind rollback, and ordered shutdown: readiness
  is removed first, child services stop next, and operations drains last.
- Added unit, CLI, real-TCP, and mTLS-backed tests. The workspace now contains
  306 explicit tests.

Out of scope:

- Database state gauges, one-shot command metrics, public/authenticated
  operations, persistence/remote write, dashboards, alerts, and schema changes.

## Session 31 — Durable HTTPS Route Catalog & CLI Administration — complete

Scope delivered:

- Promoted exact canonical DNS hostname validation into the shared
  `PublicHostname` type and retained Edge `HttpHostname` source compatibility.
- Added a separate SQLite catalog capped at 64 exact hostname-to-TunnelId
  records with enabled/disabled status and an independent non-zero monotonic
  version. Immediate transactions atomically commit each record/version change.
- Made identical upserts and absent removals idempotent without version bumps;
  catalog reads validate stored state, fail closed, and sort by hostname.
- Added `https-route-upsert`, `https-route-remove`, and `https-route-list`
  Control Plane commands with validation before database creation, stable exit
  codes, deterministic output, and secret-safe repository errors.
- Added shared validation, repository durability/capacity/corruption/migration,
  parser, and subprocess CLI coverage. The workspace now contains 316 explicit
  tests.

Out of scope:

- Catalog distribution or activation at Edge, changes to the authorization
  snapshot or Tunnel Protocol v2, and an administrative HTTP API.
- Automatic/random hostname allocation, DNS/TLS automation, custom domains,
  signed access URLs, HTTP/2, and multi-edge ownership.

## Session 32 — Authenticated HTTPS Route Distribution & Atomic Edge Activation — complete

Scope delivered:

- Added an independent `TPR1` mutual-TLS protocol with a strict 64 KiB frame,
  canonical complete catalogs, 64-route bound, monotonic version checks, and a
  latest-value Control Plane publication service.
- Integrated the persistent route authority into Control Plane refresh,
  supervision, CLI startup, rollback, and ordered shutdown without changing
  authorization snapshots or Tunnel Protocol v2.
- Added opt-in dynamic HTTPS Edge bootstrap/reconnect. Catalog replacement is
  atomic and request routing reads only immutable process-local state.
- Defined outage behavior as `live` → `stale` → `expired`: stale routes remain
  usable only for the configured in-memory window, expiry rejects all hosts,
  and authenticated same-address recovery restores service. No route disk
  cache is written.
- Added dynamic route readiness and fixed-cardinality source/version/count
  metrics plus codec, protocol, CLI, atomic routing, and real mTLS tests. The
  workspace now contains 325 explicit tests.

Out of scope:

- Automatic hostname allocation, DNS or certificate automation, custom
  domains, an administrative HTTP API, HTTP/2/WebSocket/CONNECT, signed URLs,
  multi-edge ownership, and authorization-snapshot/Tunnel Protocol changes.

## Session 33 — Atomic TLS Generation Reload for HTTPS Route Distribution — complete

Scope delivered:

- Generalized the snapshot TLS reload builders internally so each protocol
  supplies its own immutable ALPN while retaining the existing public snapshot
  API and shared digest-generation engine.
- Added route-server and route-client reload configurations and runtimes with
  independent manifests, monotonic publication, status reporting,
  last-known-good rollback, and certificate-expiry termination.
- Integrated dedicated route reload flags into Control Plane and Edge startup,
  validation, supervision, and ordered shutdown.
- Added parser coverage and real mTLS rotation coverage proving generation
  publication, old-credential rejection, reconnect with rotated credentials,
  and retention of generation 2 after an invalid generation 3. The workspace
  now contains 326 explicit tests.

Out of scope:

- Forced renegotiation of established TLS connections, CRL/OCSP, CA-overlap
  orchestration, protocol/schema changes, route disk cache, HTTP/2, automatic
  hostname or certificate issuance, and multi-edge ownership.

## Session 34 — Bounded HTTP/1.1 Keep-Alive & Per-Request Deadlines — complete

Scope delivered:

- Added an opt-in `max_requests_per_connection` contract with a CLI flag,
  compatibility default of one, and hard maximum of 1024.
- Enabled sequential HTTP/1.1 reuse while repeating Host/SNI validation,
  dynamic route lookup, request-rate admission, forwarding sanitization, body
  bounds, and tunnel creation for every request. Physical connection permits
  remain held for the full TLS lifetime.
- Replaced the former whole-connection request timeout with a fresh deadline
  per request, including response-body streaming. Error, rejection, final-cap,
  and timeout responses close the connection.
- Added graceful Hyper shutdown for established keep-alive connections and
  fixed-cardinality reuse/timeout counters in status, outcomes, and metrics.
- Added config, CLI, body-deadline, real-TLS reuse/cap, reused-rate-limit,
  timeout, and graceful/forced shutdown coverage. The workspace now contains
  332 explicit tests.

Out of scope:

- HTTP/2, HTTP pipelining guarantees, WebSocket/upgrade, CONNECT, request
  replay, distributed request-rate coordination, and multi-edge ownership.

## Session 35 — Bounded Fair DATA Scheduling — complete

Scope delivered:

- Added a reusable bounded per-key FIFO scheduler with round-robin service and
  semaphore-backed admission shared across channel, scheduler, and in-flight
  writer state.
- Integrated the scheduler into both multiplexed Agent and Edge writers. DATA
  and END_STREAM preserve stream-local ordering while continuously backlogged
  streams receive alternating frame service.
- Retained control-frame priority with a hard burst of eight frames so
  heartbeat and lifecycle traffic remain responsive without starving DATA.
- Added deterministic scheduler and writer-order tests plus a real-TCP stress
  test with eight 256 KiB streams, a two-frame DATA admission bound, and live
  heartbeat. The workspace now contains 338 explicit tests.

Out of scope:

- Peer-negotiated byte-credit windows, weighted/deficit byte scheduling,
  adaptive weights, protocol or ALPN changes, and distributed coordination.

## Session 36 — Multiplexed Transport Fairness Telemetry — complete

Scope delivered:

- Added shared atomic multiplex telemetry for active/peak streams,
  directional DATA frames/bytes, admission waits, current/peak admitted DATA
  pipeline depth, flow-control resets, and control-burst DATA yields.
- Extended the semaphore-backed queue with exact first-attempt wait
  classification and an RAII occupancy guard that spans channel, scheduler,
  encode, receiver close, and writer error paths.
- Integrated one aggregate into each Agent process runtime and Edge runtime;
  reconnects/sessions contribute to the same process-local counters while
  separately constructed runtimes never share state.
- Exported the metrics through existing loopback Agent and Edge operations
  endpoints with only the fixed `sent`/`received` direction label.
- Added deterministic counter/RAII tests and real-TCP coverage that sends four
  concurrent 256 KiB streams, verifies exact directional byte totals on both
  processes, and rejects identity/payload leakage. The workspace now contains
  341 explicit tests.

Out of scope:

- Wire-protocol or ALPN changes, peer byte-credit windows, weighted/deficit
  scheduling, remote write, durable metric history, dashboards, and alerts.

## Session 37 — Transport Capacity Telemetry & Operator Runbook — complete

Scope delivered:

- Added a live aggregate DATA writer-capacity gauge to shared multiplex
  telemetry. A per-session RAII guard publishes capacity before queue creation
  and removes it after close, reconnect, writer error, or shutdown cleanup.
- Integrated capacity lifecycle into Agent and Edge without changing Tunnel
  Protocol v2. Agent reports zero while offline; Edge sums bounds across live
  sessions.
- Exported fixed-cardinality Agent and Edge
  `transport_data_pipeline_capacity_frames` metrics so current utilization can
  be calculated from occupancy divided by live capacity.
- Added unit, operations reconnect, and concurrent real-TCP coverage for
  aggregation, release/republication, exact configured capacity, and continued
  identity/payload exclusion. The workspace now contains 343 explicit tests.
- Added an operator runbook for loopback collection topology, external
  retention, restart-safe PromQL, alert baselines, privacy, capacity tuning,
  and the evidence required before proposing peer byte credits.

Out of scope:

- Tunnel Protocol or ALPN changes, peer byte-credit windows, weighted/deficit
  scheduling, embedded remote write/storage, dashboards, paging, public
  operations access, and changes to default queue capacity.

## Session 38 — Bounded Nonblocking Process Logging — complete

Scope delivered:

- Preserved synchronous stderr as the default and added strict opt-in
  `TUNNELPROXY_LOG_BUFFER_CAPACITY` plus bounded
  `TUNNELPROXY_LOG_DRAIN_TIMEOUT_MS` configuration.
- Added one process-wide FIFO and stderr worker. Events are formatted under a
  16 KiB hard ceiling, admitted with nonblocking `try_send`, kept FIFO, and
  dropped newest when full; oversized events are discarded whole.
- Added a process-lifetime guard that drains healthy sinks and detaches a
  blocked writer after the configured deadline. Agent, Edge, Control Plane,
  and runnable examples retain it through process exit.
- Exported fixed-cardinality nonblocking-enabled, capacity, accepted, dropped,
  oversized, and write-failure metrics through all three operations endpoints.
- Added fake healthy/failed/blocked sink tests and buffered text/JSON subprocess
  coverage for all production binaries while preserving startup rollback and
  secret-safe stderr. The workspace now contains 351 explicit tests.
- Documented memory, loss, shutdown, scrape, and operator-owned retention
  semantics and resolved DEBT-010 without embedding remote backend I/O.

Out of scope:

- Durable spooling, file rotation, remote log/metric shipping, dashboards,
  paging, public operations access, protocol/schema changes, and hostname
  lifecycle.

## Session 39 — Durable Managed Hostname Allocation — complete

Scope delivered:

- Added a canonical managed base-domain type and one 128-bit OS-random
  lowercase `tp-<hex>` allocation label. Complete hostname collisions retry
  under a hard 16-attempt ceiling.
- Added durable one-hostname-per-TunnelId ownership metadata alongside the
  existing route catalog. Allocation/release, enabled route content, and one
  monotonic catalog-version change commit in a single immediate SQLite
  transaction; same-input allocation and absent release are idempotent.
- Migrated existing route databases without claiming legacy records. Generic
  route commands reject managed names, different-base reallocation is an
  explicit conflict, and repository validation fails closed on inconsistent
  ownership metadata.
- Added `https-hostname-allocate` and `https-hostname-release` Control Plane
  commands with canonical pre-storage validation, stable stdout, and existing
  exit-code/logging contracts.
- Kept the route protocol unchanged: the existing Control Plane refresh and
  authenticated full-catalog stream publish allocation and release live to
  Edge. Repository, subprocess CLI, and real route-stream coverage bring the
  workspace to 357 explicit tests.
- Documented wildcard DNS/TLS prerequisites, rollback, ownership, collision,
  restart, privacy, and failure semantics.

Out of scope:

- Agent-facing allocation, the complete `tunnelproxy http` UX, DNS or
  certificate automation, friendly names, hostname rename/rotation, custom
  domains, administrative APIs, HTTP/2, and multi-edge ownership.

## Session 40 — Authenticated Agent Hostname Lifecycle Service — complete

Scope delivered:

- Added the bounded `TPH1` request/response protocol with dedicated ALPN
  `tunnelproxy-hostname/1`, strict canonical identifiers/hostnames, a 1 KiB
  payload ceiling, and fixed error codes.
- Added a separately configurable mutual-TLS Control Plane listener. Agent leaf
  fingerprint, AgentId, and enabled TunnelId must match the current in-memory
  authorization snapshot, while the canonical allocation base domain remains
  server-owned.
- Serialized allocation/release with route refresh and made the response
  ordering durable SQLite commit → complete catalog publication → Agent
  success. Session 39 idempotency and atomic version semantics are preserved.
- Integrated bounded concurrency, deadlines, runtime supervision, shutdown,
  CLI configuration, and identity-free fixed-cardinality telemetry with the
  existing Control Plane lifecycle.
- Added an Agent mTLS client plus `hostname-allocate` and `hostname-release`
  commands with file-based TLS inputs and stable result output.
- Added protocol/parser coverage and a real-TLS integration test for exact
  authorization, unknown identity/wrong binding rejection, idempotent
  allocation, live route publication, and release. The workspace now contains
  365 explicit tests.
- Documented protocol, trust boundaries, startup, mutation ordering,
  observability, and rollback.

Out of scope:

- The complete `tunnelproxy http <port>` orchestration, DNS or public
  certificate automation, hostname rename/rotation, friendly names, custom
  domains, general administrative APIs, HTTP/2, and multi-edge ownership.

## Session 41 — Atomic Agent Hostname Service TLS Rotation — complete

Scope delivered:

- Added hostname-specific server TLS reload config/runtime on the shared
  atomic protocol TLS engine while fixing ALPN to
  `tunnelproxy-hostname/1` for every generation.
- Bound each strict digest manifest to exactly the hostname server certificate,
  private key, and Agent client CA. Only complete valid increasing generations
  publish for new handshakes; rejected candidates retain last-known-good.
- Added optional hostname-specific certificate/key paths with compatible
  fallback to the existing Control Plane paths, plus a dedicated
  `--hostname-tls-reload-manifest` and existing bounded poll/expiry tuning.
- Supervised hostname reload with snapshot and route reloaders so active
  server-leaf expiry triggers ordered Control Plane shutdown and listener
  release. Shared structured events remain generation/health-only.
- Added parser coverage and real mTLS tests for simultaneous server identity
  and Agent-CA rotation, old-client rejection, invalid-generation rollback,
  continued allocate/release, and terminal expiry. The workspace now contains
  367 explicit tests.
- Documented manifest schema, publication ordering, CA overlap, rollback,
  expiry, trust boundaries, and the one-shot Agent client behavior.

Out of scope:

- CRL/OCSP, protected key custody, automatic CA orchestration, active TLS
  renegotiation, DNS/public-certificate automation, the complete
  `tunnelproxy http` UX, custom domains, HTTP/2, and multi-edge ownership.

## Session 42 — Managed HTTP Agent Orchestration — complete

Scope delivered:

- Added `tunnelproxy-agent http <port>` with a fixed loopback target and strict
  rejection of zero ports, `--local`, `--enroll-only`, incomplete Edge mTLS,
  or incomplete hostname-service configuration.
- Validates and constructs transport TLS/reload, enrollment, Agent runtime, and
  optional operations listener before durable mutation. It then performs one
  authenticated idempotent allocation using the exact AgentId/TunnelId that
  Protocol v2 registers.
- Reuses the existing reconnecting Agent supervisor and adds a bounded,
  shutdown-aware readiness observer. One stable public-to-local mapping is
  written to stdout after the transport first reaches `Connected`; structured
  allocation/publication/readiness events remain on stderr.
- Preserves durable hostname ownership across shutdown, reconnect, local
  refusal, and terminal runtime error. Repeated startup reuses the same URL and
  catalog version; only explicit `hostname-release` removes ownership.
- Added parser and subprocess CLI-contract coverage plus real mTLS/HTTPS
  integration across authenticated allocation, dynamic exact-host activation,
  Agent mTLS registration, public wildcard TLS, local HTTP forwarding,
  idempotent retry, and persistence after Agent shutdown. The workspace now
  contains 371 explicit tests.
- Documented startup ordering, stdout meaning, observability, offline behavior,
  wildcard prerequisites, and non-destructive rollback semantics.

Out of scope:

- DNS/public-certificate automation, an external reachability probe, persisted
  account/config profiles, the shorter `tunnelproxy http` executable, custom
  domains, HTTP/2/upgrade/CONNECT, multi-edge ownership, and protocol changes.

## Session 43 — Canonical Agent CLI and Strict Local Config — complete

Scope delivered:

- Added the canonical `tunnelproxy` executable while retaining
  `tunnelproxy-agent` as a compatibility wrapper. Both delegate to one library
  driver, so parsing, structured logging, stdout, exit codes, and managed HTTP
  supervision cannot drift.
- Added strict versioned JSON config for the repeated Edge,
  hostname-service, identity, trust-name, and credential-path inputs. Reads are
  bounded to 64 KiB; unknown/duplicate fields, unsupported versions, invalid
  addresses/IDs, empty paths, and invalid TLS material fail closed.
- Added deterministic config resolution (`--config`, `TUNNELPROXY_CONFIG`,
  then platform default), config-relative credential paths, and CLI-over-config-
  over-default layering while preserving the Session 42 long-form command.
- Added `tunnelproxy config validate`, which validates schema, runtime values,
  and both TLS clients without network access or durable mutation.
- Added parser/unit coverage for layering, strict schema, path precedence, and
  the size bound plus subprocess coverage for the canonical help/validation,
  no-network guarantee, and secret-safe failure. The workspace now contains
  376 explicit tests.
- Documented the schema, platform paths, migration, trust boundary, offline
  validation, compatibility surface, and operational rollout.

Out of scope:

- Automatic account/profile creation, inline secrets, named profiles,
  DNS/public-certificate automation, external reachability probing, custom
  domains, HTTP/2/upgrade/CONNECT, multi-edge ownership, and protocol changes.

## Session 44 — Bounded HTTP/2 Public HTTPS Ingress — complete

Scope delivered:

- Added opt-in `h2` ALPN with HTTP/1.1 fallback while preserving the
  HTTP/1.1-only default. Public TLS bootstrap and every atomic reload generation
  use the same immutable protocol policy.
- Added explicit concurrent-stream, pending/local reset, header-list,
  send-buffer, flow-control-window, and PING keepalive bounds. Existing global
  and per-IP connection admission remains outside those per-connection bounds.
- Unified HTTP/1.1 Host and HTTP/2 authority handling with exact SNI matching,
  duplicate/conflicting authority rejection, shared header/body/rate/deadline
  enforcement, and unchanged CONNECT/upgrade rejection.
- Normalized accepted HTTP/2 requests to canonical origin-form HTTP/1.1 before
  using the existing cached TunnelId route and Tunnel Protocol v2 stream. No
  Agent, local-service, route protocol, or wire-format change was required.
- Added graceful HTTP/2 GOAWAY/drain and fixed-cardinality HTTP/1/HTTP/2
  connection plus active/peak stream telemetry.
- Added strict CLI configuration and real TLS coverage for ALPN, two concurrent
  streams, HTTP/1.1 fallback, host fronting, oversized-body and timeout
  isolation, local HTTP/1.1 translation, telemetry, and idle graceful shutdown.
  The workspace now contains 378 explicit tests.
- Documented policy, resource bounds, translation, rollout/rollback,
  observability, trust checks, and remaining protocol exclusions.

Out of scope:

- h2c, HTTP/2 to local applications, WebSocket/upgrade, CONNECT, HTTP/3,
  DNS/public-certificate automation, signed access URLs, distributed rate
  limiting, multi-edge ownership, and Tunnel Protocol changes.

## Session 45 — Bounded WebSocket Upgrade Ingress — complete

Scope delivered:

- Added an explicit default-off HTTP/1.1 WebSocket policy with CLI session and
  idle-time limits. WebSocket capacity cannot exceed the existing HTTPS
  connection cap; tuning flags without opt-in fail before listener bind.
- Validated GET/version-13 client handshakes, canonical Base64 keys, Upgrade
  tokens, zero request bodies, exact Host/SNI/route agreement, request-rate
  admission, and bounded subprotocol offers. Extension negotiation is rejected.
- Rebuilt the local HTTP/1.1 handshake after hop-by-hop and untrusted forwarding
  sanitization. Edge accepts local upgrade only after an exact `101`, matching
  RFC accept digest, Upgrade tokens, no extensions, and an offered subprotocol.
- Relayed upgraded bytes opaquely through the existing cached TunnelId and
  Tunnel Protocol v2 stream. One connection task owns the Hyper driver, both
  upgrade futures, route completion, session permit, idle timer, and drain.
- Added fixed-cardinality accepted/rejected/current/peak/idle-timeout metrics,
  cancellation-safe driver cleanup, graceful session completion, and forced
  cleanup at the existing HTTPS drain deadline.
- Added one relay unit test and two real TLS Edge-to-Agent-to-local E2E tests
  covering text/binary/ping bytes, spoofed forwarding cleanup, host fronting,
  malformed client and local handshakes, capacity rejection/release, idle
  timeout, sibling isolation, and forced shutdown. The workspace now contains
  381 explicit tests.

Out of scope:

- CONNECT, HTTP/2 extended CONNECT/WebSocket, WebSocket extension negotiation,
  h2c, HTTP/3, public-client authentication, distributed admission, multi-edge
  ownership, and Tunnel Protocol changes.

## Session 46 — Bounded Route-Bound HTTP/1.1 CONNECT Ingress — complete

Scope delivered:

- Added an explicit default-off HTTP/1.1 CONNECT policy with CLI session cap,
  activity idle deadline, and operator-configured authority port. Tuning flags
  without opt-in fail before listener bind, and the session cap cannot exceed
  HTTPS connection capacity.
- Required authority-form URI and exact configured port, matching Host and TLS
  SNI, a cached enabled hostname route, zero request body, no transfer encoding,
  no upgrade headers, and existing request-rate admission. HTTP/2 CONNECT and
  malformed/fronted requests fail closed before tunnel creation.
- Kept CONNECT route-bound rather than acting as a forward proxy: Edge opens
  only the selected TunnelId's fixed Agent local target, returns `200`, and
  relays opaque bytes directly through unchanged Tunnel Protocol v2 without
  forwarding an HTTP CONNECT request to the local application.
- Added independent RAII session admission, fixed directional buffers, an
  activity-based read/write/half-close idle deadline, and connection-task
  ownership through graceful or forced HTTPS drain.
- Added fixed-cardinality accepted/rejected/current/peak/idle-timeout metrics,
  strict config/parser coverage, shared opaque-relay tests, and two real TLS
  Edge-to-Agent-to-local E2Es covering byte-exact relay, wrong host/port/body,
  capacity release, idle timeout, and forced shutdown. The workspace now
  contains 383 explicit tests.
- Documented trust boundaries, rollout/rollback, observability, failure status,
  compatibility defaults, and the non-forward-proxy contract.

Out of scope:

- Arbitrary forward-proxy destinations, HTTP/2 extended CONNECT/WebSocket,
  h2c, HTTP/3, public-client authorization, distributed admission, multi-edge
  ownership, and Tunnel Protocol changes.
