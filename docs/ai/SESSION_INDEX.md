# TunnelProxy — Session Index

> One line per session. Update at the end of every session.

| Session | Title                              | Status   |
| ------- | ---------------------------------- | -------- |
| 01      | Foundation                         | complete |
| 02      | TCP Networking Foundation          | complete |
| 03      | Bidirectional TCP Streaming        | planned  |

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
  `DEFAULT_OPERATION_TIMEOUT` to honour INV-005.
- Two development binaries exist as `cargo run --example` targets:
  `tunnelproxy-edge/examples/edge_dev.rs` and
  `tunnelproxy-agent/examples/agent_dev.rs`. They are smoke-test entry
  points only; production startup wiring is deliberately out of scope.
- Real TCP integration tests live in
  `crates/edge/tests/edge_tcp.rs`. All tests bind on `127.0.0.1:0`
  (ephemeral) and drive the public API only. There is no fake or
  helper-only test in the suite.

## Session 03 — Bidirectional TCP Streaming — planned

Scope (subject to refinement when Session 03 begins):

- Replace the single-direction echo in `tunnelproxy-edge` with
  bidirectional copy loops that forward bytes in both directions at the
  same time (e.g. `tokio::io::copy_bidirectional`).
- Introduce a small `BidirectionalStream` helper that is reusable for
  the future Agent ↔ Edge tunnel and for testing.
- Decide and document the timeout / cancellation shape for long-lived
  bidirectional copies (INV-005).
- Extend integration tests to cover bidirectional traffic, large
  payloads, and clean shutdown initiated from either side.
- Update `TEST_MATRIX.md` and `CURRENT_STATE.md` to reflect real
  coverage.