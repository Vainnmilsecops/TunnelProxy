# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**TCP Relay Lifecycle Hardening / Local Port Forwarding** (Session 04).

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
- **Local TCP forwarder** in `tunnelproxy-edge`
  (`ForwardConfig`, `ForwardConfigError`, `Forwarder`, `ForwardError`,
  `ConnectionId`, `ConnectionIdAllocator`, `ConnectionLifecycle`,
  `ConnectionOutcome`, `forward_handle_connection`,
  `DEFAULT_MAX_CONNECTIONS = 100`,
  `DEFAULT_CONNECT_TIMEOUT = 5 s`). The forwarder is the
  Session 04 hardening of the Session 03 relay:
    - explicit, validated forwarding configuration
      (`ForwardConfig::validate` rejects zero `max_connections` and
      zero `connect_timeout`);
    - a process-local [`ConnectionId`] is allocated at accept time
      and appears on every lifecycle log line;
    - structured lifecycle phases
      ([`ConnectionLifecycle`]: `Accepted`, `CapacityRejected`,
      `ConnectingUpstream`, `UpstreamConnectFailed`,
      `UpstreamConnectTimeout`, `Relaying`, `RelayIoFailed`,
      `Closed`);
    - the upstream TCP connect is wrapped in
      `tokio::time::timeout` so a blackholed upstream cannot pin a
      task;
    - bounded concurrent admission via
      `tokio::sync::Semaphore` (`max_connections`); accepted
      connections with no available permit are rejected cleanly
      (downstream shut down) and the listener keeps running;
    - per-connection resources (`downstream TcpStream`, `upstream
      TcpStream`, semaphore permit) are owned by the per-connection
      task so dropping the task drops everything;
    - per-connection outcome (`bytes_downstream_to_upstream`,
      `bytes_upstream_to_downstream`, `duration`, lifecycle phase,
      structured error category) is exposed for tests and runtime
      observability.
- Development binary surface: `edge_dev` is now a CLI-driven
  forwarder (`--listen`, `--upstream`, `--max-connections`,
  `--connect-timeout-ms`, `--help`). `upstream_echo_dev` and
  `agent_dev` are unchanged. The CLI is intentionally narrow.
- Real TCP integration tests for the forwarder (9 tests in
  `crates/edge/tests/forwarder.rs`): golden-path round-trip,
  capacity-limit (1-permit reject then release), half-close
  preservation, 256 KiB binary-safe payload, unreachable upstream
  surfaced as `UpstreamConnect` / `UpstreamConnectTimeout`,
  recoverable failure does not kill the listener, config validation,
  failure-isolation-then-recovery across a forwarder restart, and
  `ConnectionIdAllocator` monotonicity. All use ephemeral ports.
- All Session 02 echo tests (`tests/edge_tcp.rs`) and Session 03
  relay tests (`tests/relay_tcp.rs`) continue to pass unchanged.

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
- Process-wide graceful shutdown / SIGTERM-driven draining of
  in-flight relays (DEBT-005 remains open; see TECH_DEBT).

Any of the above is out of scope for Session 04 and must not appear
in the Session 04 commit.

## Next planned session

**Session 05 — Tunnel Protocol v1 Design / Framing Foundation.**

Goals (subject to refinement when Session 05 begins):

- Design the on-wire frame layout for the Agent ↔ Edge tunnel
  (length-prefixed, version-tagged) — no implementation yet, just
  the framing primitives in `tunnelproxy-protocol`.
- Bump `PROTOCOL_VERSION` to a draft value in the protocol crate
  once the framing is agreed.
- Decide on the initial message set (HELLO / OPEN_TUNNEL / OPEN_STREAM
  / DATA / CLOSE / HEARTBEAT / ERROR) and document it.
- Lay out per-stream isolation as a protocol-level concept that the
  edge / agent runtime will respect.
- Do **not** yet implement a real Agent → Edge persistent tunnel;
  this session only ships the framing foundation.