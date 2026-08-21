# TunnelProxy — Session Index

> One line per session. Update at the end of every session.

| Session | Title                                          | Status   |
| ------- | ---------------------------------------------- | -------- |
| 01      | Foundation                                     | complete |
| 02      | TCP Networking Foundation                      | complete |
| 03      | Bidirectional TCP Streaming / TCP Relay        | complete |
| 04      | TCP Relay Lifecycle Hardening / Local Port Forwarding | complete |
| 05      | Tunnel Protocol v1: Binary Framing & Message Design | complete |

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