# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Bidirectional TCP Streaming / TCP Relay** (Session 03).

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
  hard 2-second operation deadline that honors INV-005).
- Per-connection task handling: each accepted connection is spawned
  as an independent Tokio task; a recoverable client error is logged
  and dropped without affecting the listener loop.
- Bounded byte streaming: 8 KiB fixed buffer reused across reads; no
  `read_to_end` on a live socket (INV-002).
- EOF handling: `read == 0` is treated as a normal peer close, not
  as an error.
- Structured `tracing` instrumentation for lifecycle events
  (`tcp_server_started`, `tcp_connection_accepted`,
  `tcp_connection_closed`, `tcp_connection_error`,
  `tcp_client_payload_sent`, `tcp_client_run_success`,
  `relay_connection_accepted`, `relay_upstream_connected`,
  `relay_started`, `relay_completed`, `relay_failed`). Payload
  contents are never logged (INV-003).
- **Bidirectional TCP relay** in `tunnelproxy-edge`
  (`run_relay_listener`, `relay_connection`, `relay_bidirectional`,
  [`RelayStats`], [`RelayError`], [`RelayDirection`]). Each accepted
  downstream connection opens a fresh upstream TCP connection and
  forwards raw bytes concurrently in both directions via
  [`tokio::io::copy_bidirectional`]. TCP half-close is preserved
  because `copy_bidirectional` shuts down the matching write half
  when one direction finishes.
- Per-direction byte counters returned by the relay so callers (and
  tests) can assert that traffic actually flowed in both directions.
- Connection-level isolation: an upstream connect failure closes only
  that downstream connection and is logged; the listener keeps
  accepting new connections.
- Development binary surface: `edge_dev` now defaults to running as a
  relay (`127.0.0.1:7000` → `127.0.0.1:8000`); a new
  `upstream_echo_dev` example is provided for manual smoke tests.
  `agent_dev` is unchanged; it just connects to the relay and
  verifies the byte-exact echo through it.
- Real TCP integration tests for the relay (7 tests in
  `crates/edge/tests/relay_tcp.rs`): basic round-trip, 256 KiB
  binary-safe payload, half-close preservation, listener survives an
  unreachable upstream, byte-counts assertion on
  `relay_bidirectional` directly, `UpstreamConnect` error surfaced
  when upstream is unreachable, and a smoke test for
  `run_relay_listener` itself. All use ephemeral ports.

## Not implemented

- Reverse tunnel.
- Tunnel wire protocol beyond the `PROTOCOL_VERSION = 1` constant.
- Persistent Agent ↔ Edge tunnel connection.
- Tunnel registration.
- Heartbeat.
- Reconnect.
- Multiplexing.
- HTTP.
- TLS.
- Authentication.
- Persistence.
- Request inspection.
- Webhooks, dashboards, custom domains, rate limiting, replay, cloud
  deployment.
- Upstream connection pooling. Each downstream connection opens its
  own upstream connection.
- Per-connection idle read timeout on the relay path (DEBT-006
  carries over from Session 02 and remains open).

Any of the above is out of scope for Session 03 and must not appear
in the Session 03 commit.

## Next planned session

**Session 04 — Local TCP Forwarding / Relay Lifecycle Hardening.**

Goals (subject to refinement when Session 04 begins):

- Add a configurable per-connection idle deadline on the relay path
  (resolve DEBT-006).
- Add a graceful-shutdown channel to `run_relay_listener` so SIGTERM
  in the dev binary drains in-flight relay connections (resolve
  DEBT-005).
- Decide and document whether to introduce an upstream-connection
  pool, or to keep the one-downstream-one-upstream mapping.
- Extend integration tests for: idle timeouts, graceful shutdown,
  large concurrent fan-out, and a second upstream peer to confirm
  isolation.