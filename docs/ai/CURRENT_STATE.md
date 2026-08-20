# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**TCP Networking Foundation** (Session 02).

## Completed

- Repository baseline (`README.md`, `Cargo.toml`, `rust-toolchain.toml`,
  `.gitignore`).
- Cargo workspace with five crates (`common`, `protocol`, `agent`,
  `edge`, `control-plane`).
- Component boundaries documented per crate and per architecture
  document.
- Documentation baseline: `PRODUCT_SPEC.md`, `ARCHITECTURE.md`,
  `DEVELOPMENT.md`, `TECH_DEBT.md`.
- AI context layer: `PROJECT_CONTEXT.md`, `CURRENT_STATE.md`,
  `MODULE_MAP.md`, `INVARIANTS.md`, `DECISIONS.md`, `TEST_MATRIX.md`,
  `SESSION_INDEX.md`.
- Development workflow documented (format / lint / test / build /
  Definition of Done).
- Initial placeholder unit tests in every crate.
- Asynchronous TCP listener baseline in `tunnelproxy-edge`
  (`run_listener`, `handle_connection`, bound on `127.0.0.1:7000` by
  default, real Tokio `TcpListener`, bounded 8 KiB read buffer).
- Asynchronous TCP client baseline in `tunnelproxy-agent`
  (`send_and_verify`, `run`, deterministic `hello tunnelproxy` payload,
  hard 2-second operation deadline that honours INV-005).
- Per-connection task handling: each accepted connection is spawned as
  an independent Tokio task; a recoverable client error is logged and
  dropped without affecting the listener loop.
- Bounded byte streaming: 8 KiB fixed buffer reused across reads; no
  `read_to_end` on a live socket (INV-002).
- EOF handling: `read == 0` is treated as a normal peer close, not as
  an error.
- Structured `tracing` instrumentation for lifecycle events
  (`tcp_server_started`, `tcp_connection_accepted`,
  `tcp_connection_closed`, `tcp_connection_error`,
  `tcp_client_payload_sent`, `tcp_client_run_success`, etc.). Payload
  contents are never logged (INV-003).
- Real TCP integration tests covering: byte-exact echo, multiple
  sequential writes, immediate EOF, listener survival across an abrupt
  client close, multi-client sequential connections, and
  `run_listener` bind smoke test. All tests use `127.0.0.1:0` for
  ephemeral ports.

## Not implemented

- Bidirectional tunnel piping (copying bytes in both directions
  simultaneously between two connected sockets).
- HTTP.
- Tunnel wire protocol beyond the `PROTOCOL_VERSION = 1` constant.
- Agent ↔ Edge connection is still a flat echo, not a multiplexed
  tunnel.
- Tunnel registration.
- Heartbeat.
- Reconnect.
- Multiplexing.
- TLS.
- Authentication.
- Persistence.
- Request inspection.
- Webhooks, dashboards, custom domains, rate limiting, replay, cloud
  deployment.

Any of the above is out of scope for Session 02 and must not appear in
the Session 02 commit.

## Next planned session

**Session 03 — Bidirectional TCP Streaming.**

Goals (subject to refinement when Session 03 begins):

- Replace the single-direction echo with two simultaneous
  bidirectional copy loops per connection (e.g. `tokio::io::copy_bidirectional`).
- Introduce a `BidirectionalStream` helper that can be reused for the
  future Agent ↔ Edge tunnel.
- Decide and document the timeout / cancellation shape for long-lived
  copy loops.
- Extend integration tests to cover bidirectional traffic, large
  payloads, and connection shutdown in both directions.