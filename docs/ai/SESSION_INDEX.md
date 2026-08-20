# TunnelProxy — Session Index

> One line per session. Update at the end of every session.

| Session | Title                                          | Status   |
| ------- | ---------------------------------------------- | -------- |
| 01      | Foundation                                     | complete |
| 02      | TCP Networking Foundation                      | complete |
| 03      | Bidirectional TCP Streaming / TCP Relay         | complete |
| 04      | Local TCP Forwarding / Relay Lifecycle Hardening | planned |

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
- Development binary `edge_dev` now runs as a relay by default
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

## Session 04 — Local TCP Forwarding / Relay Lifecycle Hardening — planned

Scope (subject to refinement when Session 04 begins):

- Add a configurable per-connection idle deadline on the relay path
  (resolve DEBT-006 carried over from Session 02).
- Add a graceful-shutdown channel to `run_relay_listener` so SIGTERM
  in the dev binary drains in-flight relay connections (resolve
  DEBT-005).
- Decide and document whether to introduce upstream connection
  pooling or keep the strict one-downstream-one-upstream mapping.
- Extend integration tests for idle timeouts, graceful shutdown,
  large concurrent fan-out, and isolation against a second upstream
  peer.
- Update `TEST_MATRIX.md`, `CURRENT_STATE.md`, and `SESSION_INDEX.md`
  to reflect Session 04 reality.