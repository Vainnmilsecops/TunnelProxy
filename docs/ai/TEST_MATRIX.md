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
| HTTP reverse proxy                        | —    | —           | —   | Planned after Session 04.                                                                                                   |
| Tunnel protocol framing                   | ✅   | —           | —   | 26 codec tests in `crates/protocol/src/codec.rs`: round-trip, binary, fragmented header/payload, coalesced frames, clean EOF, truncated header/payload, invalid magic/version/frame-type/flags, invalid stream scope, oversized encode/decode, real TCP loopback. |
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
| Agent ↔ Edge: invalid REGISTER (non-empty payload) | ✅ | ✅ | — | `invalid_register_non_empty_payload`. |
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
| Tunnel registration                       | —    | —           | —   | Planned with control-plane work.                                                                                            |
| Multiplexing                              | ✅   | ✅          | —   | `eight_streams_run_concurrently_without_cross_talk` drives eight byte-exact real-TCP streams on one Agent session. |
| Live session routing                      | ✅   | ✅          | —   | `router_targets_the_requested_agent_session` proves exact routing across two connected Agents. |
| Multiplexed capacity and isolation        | ✅   | ✅          | —   | Capacity rejection preserves the session; one Agent local failure does not affect another Agent. |
| Reconnect                                 | —    | —           | —   | Deferred until a stable tunnel exists.                                                                                      |
| Backpressure                              | ✅   | ✅          | —   | Session 09 adds bounded per-stream, command, control, and DATA queues plus a 16 KiB runtime DATA limit. Credit windows remain deferred. |
| TLS                                       | —    | —           | —   | Out of foundation scope.                                                                                                    |
| Authentication                            | —    | —           | —   | INV-003; deferred.                                                                                                          |
| Request inspection                        | —    | —           | —   | Deferred to V1.                                                                                                             |
