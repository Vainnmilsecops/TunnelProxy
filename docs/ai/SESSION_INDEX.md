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
