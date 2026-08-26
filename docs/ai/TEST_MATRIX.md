# TunnelProxy — Test Matrix

> Canonical list of capabilities and their test status. **Do not mark a
> capability as tested unless the test actually exists in the
> repository.** Status meanings:
>
> - `—` not implemented
> - `planned` scoped for a future session, no test yet
> - `unit` unit tests exist
> - `integration` cross-crate integration tests exist
> - `e2e` end-to-end tests exist

| Capability                                | Unit | Integration | E2E | Notes                                                                                                                       |
| ----------------------------------------- | ---- | ----------- | --- | --------------------------------------------------------------------------------------------------------------------------- |
| Workspace compiles and lints              | ✅   | —           | —   | Foundation checks; Session 04 keeps networking deps and lint-clean code.                                                    |
| Reproducible cross-platform CI             | ✅   | ✅          | —   | GitHub Actions enforces locked format/check/Clippy on Ubuntu, test/build on Ubuntu and Windows MSVC, plus a Rust 1.75 MSRV check. |
| Per-crate placeholder unit tests          | ✅   | —           | —   | Identifiers / status enums.                                                                                                 |
| Edge: bind async TCP listener (echo)      | ✅   | ✅          | —   | `run_listener`; integration test binds via `127.0.0.1:0`, asserts `TcpStream::connect` succeeds.                             |
| Edge: accept connections                  | ✅   | ✅          | —   | Each connection is spawned via `tokio::spawn`.                                                                              |
| Edge: echo arbitrary bytes                | ✅   | ✅          | —   | `handle_connection` reads into a fixed 8 KiB buffer, writes back exactly `n` bytes.                                          |
| Edge: `read == 0` is normal EOF           | ✅   | ✅          | —   | `immediate_eof_is_normal_close` (lib) and `echo_server_returns_empty_for_immediate_close` (integration).                    |
| Edge: recoverable error doesn't crash     | ✅   | —           | —   | `listener_survives_abrupt_client_close` drops a connection mid-stream and asserts the listener keeps serving.                |
| Agent: connect to server                  | ✅   | —           | —   | `send_and_verify_round_trip` (lib); smoke test via `agent_dev` example.                                                     |
| Agent: send deterministic payload         | ✅   | —           | —   | `TEST_PAYLOAD = b"hello tunnelproxy"`.                                                                                      |
| Agent: verify echoed bytes                | ✅   | —           | —   | Byte-exact equality asserted; structured `RunOutcome::Success` / `Mismatch`.                                                 |
| Agent: timeout on long operations         | ✅   | —           | —   | `DEFAULT_OPERATION_TIMEOUT` wraps `read_to_end`; mismatched server surfaces as `RunOutcome::Mismatch`.                       |
| TCP networking (round-trip baseline)      | ✅   | ✅          | —   | Session 02 deliverables.                                                                                                    |
| Edge: TCP relay basic round-trip          | ✅   | ✅          | —   | `relay_round_trip_small_payload`; `run_relay_listener` smoke test.                                                          |
| Edge: TCP relay large (256 KiB) payload   | ✅   | ✅          | —   | `relay_round_trip_large_payload`; deterministic pseudo-random bytes incl. nulls / high values.                              |
| Edge: TCP relay preserves half-close       | —    | ✅          | —   | `relay_preserves_half_close`; client EOF on write side, upstream responds after draining request, relay forwards response.  |
| Edge: TCP relay connection isolation      | —    | ✅          | —   | `relay_listener_survives_unreachable_upstream`; unreachable upstream does not kill the listener; later valid conn works.     |
| Edge: TCP relay byte counts (`RelayStats`)| ✅   | ✅          | —   | `relay_bidirectional_returns_byte_counts`; asserted via `RelayStats`.                                                        |
| Edge: TCP relay `UpstreamConnect` error   | ✅   | ✅          | —   | `relay_connection_reports_upstream_connect_failure` surfaces `RelayError::UpstreamConnect`.                                  |
| Bidirectional streaming                   | ✅   | ✅          | —   | Session 03 deliverables.                                                                                                    |
| Forwarder: explicit forwarding config     | ✅   | ✅          | —   | `ForwardConfig::validate` rejects zero-capacity / zero-timeout; `Forwarder::new` returns `ForwardConfigError`; covered in lib and in `forwarder_new_rejects_invalid_config`. |
| Forwarder: per-connection `ConnectionId`  | ✅   | ✅          | —   | `ConnectionIdAllocator` is monotonic and process-local; allocator unit test + `connection_id_allocator_yields_unique_ids` integration. |
| Forwarder: lifecycle phases               | ✅   | ✅          | —   | `ConnectionLifecycle` + `ForwardError::phase` cover all observed phases; `forwarder_golden_path_round_trip` asserts `Closed`. |
| Forwarder: bounded concurrency            | ✅   | ✅          | —   | `Forwarder::available_permits` exposes live permit count; `forwarder_capacity_limit_one_rejects_then_releases` exercises the deterministic capacity-exhaustion policy (accept / permit / write / hold / second-client-rejected / release / third-client-succeeds). |
| Forwarder: upstream connect timeout       | ✅   | ✅          | —   | `ForwardError::UpstreamConnectTimeout` is distinct from `ForwardError::UpstreamConnect`; covered in `forwarder_unreachable_upstream_surfaces_upstream_connect_failure` (loopback closed port can surface as either on Windows). |
| Forwarder: failure isolation              | —    | ✅          | —   | `forwarder_recoverable_failure_does_not_kill_listener` proves two consecutive failed connections do not stop the listener. |
| Forwarder: failure → recovery             | —    | ✅          | —   | `forwarder_failure_then_recovery_via_restart` simulates upstream restart and verifies a later connection succeeds.          |
| Forwarder: byte / duration observability  | ✅   | ✅          | —   | `ConnectionOutcome` carries `RelayStats` + `duration`; covered by `forwarder_golden_path_round_trip` and `forwarder_large_payload_round_trip`. |
| Forwarder: large (256 KiB) payload        | ✅   | ✅          | —   | `forwarder_large_payload_round_trip`; same byte-exact assertion as Session 03.                                              |
| Forwarder: half-close preserved           | —    | ✅          | —   | `forwarder_preserves_half_close`.                                                                                           |
| Forwarder: structured error categories    | ✅   | ✅          | —   | `ForwardError::category()` returns `"capacity_exhausted"`, `"upstream_connect_failed"`, `"upstream_connect_timeout"`, `"relay_io_failed"`; logged as `error_category`. |
| Edge: TCP forwarder CLI                   | —    | —           | —   | `edge_dev` accepts `--listen`, `--upstream`, `--max-connections`, `--connect-timeout-ms`, `--help`; manually smoke-tested.   |
| HTTPS/HTTP/1.1 reverse proxy              | ✅   | ✅          | —   | Real TLS crosses exact Host/SNI routing through Edge → Agent → local HTTP and validates the returned response. |
| HTTP host-fronting defense                | ✅   | ✅          | —   | Exact Host/SNI/absolute authority validation rejects mismatches; unknown/offline routes fail closed. |
| HTTP forwarding-header sanitization      | ✅   | ✅          | —   | Real local HTTP capture proves spoofed forwarding and Connection-nominated headers are removed and trusted values replace them. |
| HTTP ingress resource bounds             | ✅   | ✅          | —   | Config/CLI validate global/per-IP connections and request rates, bounded rate-peer state, header bytes/count, body, TLS/header/request deadlines, duplex capacity, and drain. |
| HTTP global/per-IP request admission     | ✅   | ✅          | —   | Integer fixed-point token-bucket tests cover isolation, atomic rejection, refill, saturation, and clock regression; real TLS proves per-IP `429` then refill. |
| HTTP rate-peer cardinality and idle TTL  | ✅   | —           | —   | Bounded table rejects when full, scans a fixed cleanup batch, and reclaims expired peers without trusting forwarding headers. |
| HTTP rate-limit response and isolation   | ✅   | ✅          | —   | `429` includes integer `Retry-After`; the real TLS test proves a rejected request does not reach the Agent's local HTTP service. |
| HTTP ingress live rate status            | ✅   | ✅          | —   | Status snapshots report admitted and categorized rejected requests plus current/peak tracked peers; runtime outcome asserts final totals. |
| Edge operations endpoint bounds          | ✅   | ✅          | —   | Config rejects non-loopback/zero/oversized bounds; real TCP proves connection capacity rejection, RAII release, startup rollback, and listener release. |
| Edge health and tunnel readiness         | ✅   | ✅          | —   | Real TCP covers `/healthz` plus readiness `503 → 200 → 503` across Agent connect/disconnect and proves readiness is false while operations remains observable during ingress drain. |
| Edge Prometheus metrics                  | ✅   | ✅          | —   | Fixed-cardinality text output reports authorization and raw/HTTPS/rate-limit counters, including real `429` and TLS rejection, without identity, peer, certificate, secret, or payload values. |
| Public HTTPS TLS generation reload       | ✅   | ✅          | —   | Typed/secret-safe config plus a real manifest runtime test prove complete monotonic public certificate/key generation publication. |
| Tunnel protocol framing                   | ✅   | —           | —   | Protocol v2 codec covers round-trip, binary, fragmentation, truncation, invalid magic/version/frame/flags/scope, bounds, real TCP, and explicit v1 rejection. |
| Tunnel protocol: control stream scope    | ✅   | —           | —   | `frame::tests::frame_control_scope_validation` and `frame::tests::frame_stream_scope_validation`. |
| Tunnel protocol: binary-safe payloads     | ✅   | —           | —   | `codec::tests::roundtrip_binary_payload` exercises 0x00–0xFF byte range. |
| Tunnel protocol: 64 KiB max payload       | ✅   | —           | —   | `frame::tests::frame_max_payload_is_exactly_64kib`. |
| Tunnel protocol: EOF vs truncation        | ✅   | —           | —   | `codec::tests::clean_eof`, `codec::tests::truncated_header`, `codec::tests::truncated_payload`. |
| Tunnel protocol: real loopback TCP        | ✅   | —           | —   | `codec::tests::real_tcp_loopback_roundtrip` binds a real `TcpListener` and exchanges frames over `TcpStream`. |
| Agent ↔ Edge protocol handshake           | ✅   | ✅          | —   | Implemented in Session 06. See `docs/AGENT_EDGE_TRANSPORT.md`.                                         |
| Agent ↔ Edge: valid handshake (HELLO → REGISTER → REGISTERED) | ✅ | ✅ | — | `valid_handshake_establishes_session`; 20 integration tests in `agent_transport.rs`. |
| Agent ↔ Edge: invalid first frame (REGISTER before HELLO) | ✅ | ✅ | — | `invalid_first_frame_register_before_hello`. |
| Agent ↔ Edge: invalid second frame (DATA before REGISTER) | ✅ | ✅ | — | `invalid_second_frame_data_instead_of_register`. |
| Agent ↔ Edge: invalid HELLO (empty payload) | ✅ | ✅ | — | `invalid_hello_empty_payload`. |
| Agent ↔ Edge: invalid HELLO (unknown role) | ✅ | ✅ | — | `invalid_hello_unknown_role`. |
| Agent ↔ Edge: invalid REGISTER payload | ✅ | ✅ | — | Golden bounded AgentId/TunnelId codec plus malformed length/UTF-8/ID coverage; arbitrary non-schema payload is rejected. |
| Agent ↔ Edge: handshake timeout | ✅ | ✅ | — | `handshake_timeout_no_hello`. |
| Agent ↔ Edge: timeout releases capacity permit | ✅ | ✅ | — | `timeout_releases_capacity`. |
| Agent ↔ Edge: peer disconnect cleans up session | ✅ | ✅ | — | `peer_disconnect_cleans_up_session`. |
| Agent ↔ Edge: session ID uniqueness | ✅ | ✅ | — | `session_id_uniqueness`. |
| Agent ↔ Edge: session remains open after handshake | ✅ | ✅ | — | `session_remains_open_after_handshake`. |
| Agent ↔ Edge: TransportSessionId strongly typed | ✅ | —  | — | `transport_session_id_validity`, `transport_session_id_be_bytes` (unit tests). |
| Agent ↔ Edge: TransportSessionIdAllocator monotonic | ✅ | ✅ | — | `transport_session_id_allocator_starts_at_one`, `transport_session_id_allocator_monotonic` (unit), `transport_session_id_allocator_regression` (integration). |
| Agent ↔ Edge heartbeat payload types | ✅ | — | — | `HeartbeatSequence` rejects zero, round-trips big-endian, increments without wrapping; heartbeat error codes round-trip. |
| Agent ↔ Edge heartbeat golden path | — | ✅ | — | `heartbeat_ping_pong_keeps_session_alive`; Agent `run()` answers Edge PING with matching PONG. |
| Agent ↔ Edge heartbeat sequence | ✅ | ✅ | — | `edge_heartbeat_sequence_is_monotonic` observes sequences 1, 2, and 3 over real TCP. |
| Agent ↔ Edge dead-session detection | — | ✅ | — | `heartbeat_timeout_releases_capacity` proves a silent established Agent is closed and its only permit is reusable. |
| Agent ↔ Edge mismatched PONG | — | ✅ | — | `mismatched_pong_closes_session_with_error` verifies typed ERROR response. |
| Agent ↔ Edge malformed heartbeat | — | ✅ | — | `malformed_pong_payload_is_rejected` and `agent_rejects_malformed_edge_ping`. |
| Agent ↔ Edge heartbeat direction | — | ✅ | — | `unsolicited_pong_is_rejected` and `agent_ping_is_rejected_for_edge_initiated_heartbeat`. |
| Single-stream reset-code contract | ✅ | — | — | All known `StreamResetCode` values round-trip as two big-endian bytes; unknown values are rejected. |
| Single-stream golden path | — | ✅ | — | `single_stream_golden_path_is_byte_exact` crosses ingress → Edge → Agent → local echo and back. |
| Single-stream bounded framing | — | ✅ | — | `large_payload_is_split_across_bounded_data_frames` round-trips 256 KiB through 16 KiB reads under the 64 KiB frame ceiling. |
| Single-stream half-close | — | ✅ | — | `client_half_close_still_allows_local_response` verifies a response after client write shutdown. |
| Sequential stream reuse and IDs | — | ✅ | — | `established_agent_supports_sequential_streams` and `sequential_stream_ids_are_monotonic`. |
| Single-stream failure isolation | — | ✅ | — | Local connect failure and idle timeout reset only the stream; the Agent transport remains live. |
| Single-stream admission | — | ✅ | — | `second_concurrent_ingress_is_rejected` proves the one-active-stream limit. |
| Heartbeat during stream traffic | — | ✅ | — | `heartbeat_remains_live_during_active_stream` spans multiple heartbeat intervals during a slow local response. |
| Stream lifecycle violation | — | ✅ | — | `data_before_open_is_reset_without_killing_agent_session`. |
| Authenticated tunnel registration         | ✅   | ✅          | —   | Protocol v2 binds exact client-certificate fingerprint → AgentId → enabled TunnelId before REGISTERED/session publication. |
| Versioned snapshot ordering               | ✅   | —           | —   | Non-zero versions, valid gaps, idempotent duplicate, stale rejection, and same-version conflict are covered in control-plane unit tests. |
| Bounded latest-value distribution         | ✅   | —           | —   | Watch delivery skips superseded full snapshots, retains the newest value, and preserves cache after publisher close. |
| Live grant add / enable                    | —    | ✅          | —   | `live_snapshot_add_authorizes_tunnel_without_edge_restart` starts Edge from an empty snapshot and routes after a live grant without listener rebind. |
| Live revoke and re-enable                  | ✅   | ✅          | —   | Principal revalidation closes publication race; real mTLS proves unrelated updates preserve sessions, revoke closes active streams, and re-enable restores the same raw listener. |
| Snapshot source health                    | —    | ✅          | —   | Runtime status reports version and Live/Stale state; cached authorization remains usable after the producer closes. |
| Canonical snapshot codec                  | ✅   | —           | —   | Stable ordering/digest, versioned round-trip, malformed payloads, strict IDs/status, cardinality, and 1 MiB bounds. |
| Persistent snapshot repository            | ✅   | —           | —   | SQLite commit/reopen preserves exact state; stale/conflicting versions fail and injected commit failure never publishes. |
| Authenticated snapshot bootstrap          | ✅   | ✅          | —   | Real mTLS tests cover SQLite-backed bootstrap, live push, wrong server identity, disconnect `Stale`, reconnect `Live`, and shutdown cancellation. |
| Edge cold-start snapshot cache            | ✅   | ✅          | —   | Record corruption/expiry/version ordering and atomic generation cleanup are unit tested; real mTLS covers online persistence, offline bootstrap, reconnect reconciliation, and no fallback on wrong TLS identity. |
| Stale cache runtime deadline              | —    | ✅          | —   | A cached Edge routes real Agent traffic while offline, then cache expiry stops the composed runtime and releases Agent/raw listeners. |
| Snapshot manifest and import CLI          | ✅   | ✅          | —   | Strict JSON, unknown/invalid/oversized input, process exit codes, and durable database initialization are covered. |
| Runnable Control Plane lifecycle          | ✅   | ✅          | —   | Uninitialized startup fails; external import refresh, same-database restart, listener shutdown, and reconnect are real-TCP tested. |
| Snapshot-aware runnable Edge              | ✅   | ✅          | —   | Three CLI authorization modes are validated; bootstrap precedes bind and routed mTLS traffic survives Control Plane restart via stale cache. |
| Multiplexing                              | ✅   | ✅          | —   | `eight_streams_run_concurrently_without_cross_talk` drives eight byte-exact real-TCP streams on one Agent session. |
| Live session and durable tunnel routing   | ✅   | ✅          | —   | Exact session routing plus cached `TunnelId -> TransportSessionId`; duplicate claim rejects and releases after disconnect. |
| Multiplexed capacity and isolation        | ✅   | ✅          | —   | Capacity rejection preserves the session; one Agent local failure does not affect another Agent. |
| Raw ingress route golden path             | ✅   | ✅          | —   | `raw_route_golden_path_is_byte_exact_and_drains` binds an ephemeral listener and crosses Edge → Agent → local service. |
| Raw ingress concurrent routing            | —    | ✅          | —   | Six concurrent clients remain byte-exact; two routes target two exact Agent sessions. |
| Raw route admission                       | ✅   | ✅          | —   | Global route and per-route connection bounds reject excess work without stopping healthy routes. |
| Explicit public raw exposure              | ✅   | ✅          | —   | Config/CLI tests reject implicit, plaintext, static, and incomplete public modes; real TCP binds a wildcard listener only with dynamic mTLS authorization. |
| Public raw per-IP admission               | ✅   | ✅          | —   | Bounds reject zero/greater-than-global values; real TCP proves excess same-IP sockets close, counters advance, and RAII release permits a replacement connection. |
| Public raw durable revocation             | —    | ✅          | —   | Real wildcard TCP plus Agent mTLS and SQLite-backed dynamic authority proves emergency revoke closes the exact live public stream without listener-side storage lookup. |
| Raw route drain lifecycle                 | ✅   | ✅          | —   | Remove stops accept, active streams finish, and drain timeout is typed without forced cancellation. |
| Raw route disconnect cleanup              | —    | ✅          | —   | Agent disconnect removes its route; local-connect failure leaves the route available for recovery. |
| Shutdown signal semantics                 | ✅   | ✅          | —   | Requests are idempotent and not lost before wait; dropping a trigger is not cancellation. |
| Supervised listener shutdown              | ✅   | ✅          | —   | Echo, forwarder, Agent listener, and single-stream tests cover listener release, child cancellation, graceful completion, and forced deadline outcomes. |
| Multiplexed Edge/Agent drain              | ✅   | ✅          | —   | Edge releases admission and its router fails closed; Agent honors a shutdown already requested before its multiplex loop starts. |
| Raw route process shutdown                | ✅   | ✅          | —   | Global route drain rejects manager reuse and force-aborts an active route only after its deadline. |
| Agent process runtime                     | ✅   | ✅          | —   | Config validation, cancellable bounded reconnect, typed retry exhaustion, and composed outbound handshake/multiplex lifecycle. |
| Edge process runtime                      | ✅   | ✅          | —   | Binds one TunnelId raw route before Agent availability, fails closed offline, keeps the listener across reconnect, and shuts down route→transport. |
| Runnable Edge/Agent CLIs                  | ✅   | ✅          | —   | Parsers cover durable IDs, reconnect/TLS flags, exact authorized client certificate, complete argument sets, and invalid values. |
| Process logging contract                  | ✅   | ✅          | —   | Pure parsing tests cover text/JSON format and `RUST_LOG`; Agent, Edge, and Control Plane subprocess tests cover JSON schema, filtering, no ANSI, stdout/stderr separation, pre-mutation config failure, and token secrecy. |
| Composed local tunnel                     | —    | ✅          | —   | Real TCP crosses runnable Edge→Agent→local echo byte-exactly, then releases both listener ports after shutdown. |
| OS process shutdown observation           | ✅   | —           | —   | Ctrl-C on all platforms and SIGTERM on Unix compile behind Tokio's signal feature; runtime cleanup is tested via injected shutdown signals. |
| Reconnect                                 | ✅    | ✅           | —   | Backoff bounds/jitter are unit tested; real TCP covers cancellation, retry exhaustion, Edge restart, and same-address route recovery. |
| Backpressure                              | ✅   | ✅          | —   | Session 09 adds bounded per-stream, command, control, and DATA queues plus a 16 KiB runtime DATA limit. Credit windows remain deferred. |
| Agent transport mutual TLS                | ✅    | ✅           | —   | Runtime-generated PKI covers byte-exact mTLS with ALPN v2, wrong CA/name, timeout/cancellation, secret-safe Debug, and secure reconnect. |
| Agent certificate authentication          | ✅    | ✅           | —   | Missing/untrusted certs, same-CA unassigned certs, false Agent/Tunnel claims, and disabled tunnels never become routable. |
| Atomic TLS generation reload              | ✅    | ✅           | —   | Strict digest manifests and monotonic last-known-good publication are unit tested; real mTLS rotates Agent/Edge and snapshot client/server without restart, rejects old credentials, and retains the active generation after an invalid candidate. |
| TLS expiry enforcement                    | ✅    | ✅           | —   | Health distinguishes expiring/reload-failed/expired without secrets, and runtime expiry terminates when no valid replacement arrives. |
| Enrollment protocol and token secrecy     | ✅    | —           | —   | Strict 64 KiB `TPE1` frames, all message round-trips, malformed inputs, unknown codes, and redacted token Debug are covered. |
| Bound bootstrap token provisioning        | ✅    | ✅           | —   | SQLite tests cover expiry, identity binding, consumption and exact retry; process CLI verifies a secret file is created and token bytes are not printed. |
| Agent-owned-key certificate issuance      | ✅    | ✅           | —   | Real TLS generates the Agent key/CSR locally, validates the issued key/cert/fingerprint, and publishes a digest-bound bundle. |
| Transactional Agent renewal and activation| ✅    | ✅           | —   | Repository and real TLS tests prove overlap, idempotency, live snapshot publication, activation, token rotation, and predecessor fingerprint removal. |
| Pending credential deadline/reconciliation| ✅    | ✅           | —   | Repository tests cover the exact deadline, durable tombstoning, retry rejection, and predecessor preservation; real enrollment TLS proves the supervised reconciler removes an abandoned overlap. |
| Emergency Agent/Tunnel revocation         | ✅    | ✅           | —   | Repository and process-CLI tests prove idempotency, token invalidation, safe status output, and unrelated-grant preservation; real mTLS proves dynamic Edge closes the exact live session and stream. |
| Enrollment terminal/retry classification  | ✅    | ✅           | —   | Agent unit tests classify policy/authentication rejection as terminal and request expiry as recoverable; real TLS returns the typed `CredentialRevoked` rejection. |
| Session 21 enrollment schema migration    | ✅    | —           | —   | SQLite migration test opens the legacy schema and verifies revocation, activation-deadline, terminal-time, and schema-version fields before use. |
| Durable raw route offline/reconnect       | ✅    | ✅           | —   | Listener remains bound, closes sockets while offline, and resolves the fresh authenticated session without rebind or storage lookup. |
| Plaintext transport restriction           | ✅    | ✅           | —   | Runnable plaintext is loopback-only; a non-loopback Agent listener validates only when mutual TLS is configured. |
| Request inspection                        | ✅   | ✅          | —   | Session 25 inspects only routing/security metadata for HTTP/1.1; application payload inspection, access rules, and replay remain deferred. |
