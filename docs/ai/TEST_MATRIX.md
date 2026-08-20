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
| Workspace compiles and lints              | ✅   | —           | —   | Foundation checks; Session 03 keeps networking deps and lint-clean code.                                                     |
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
| HTTP reverse proxy                        | —    | —           | —   | Planned after Session 04.                                                                                                   |
| Tunnel protocol framing                   | —    | —           | —   | Planned with the multiplexed tunnel (ADR-005).                                                                              |
| Agent ↔ Edge protocol handshake           | —    | —           | —   | Out of scope until framing exists.                                                                                          |
| Tunnel registration                       | —    | —           | —   | Planned with control-plane work.                                                                                            |
| Multiplexing                              | —    | —           | —   | Deferred until simple bidirectional tunnel works.                                                                           |
| Reconnect                                 | —    | —           | —   | Deferred until a stable tunnel exists.                                                                                      |
| Backpressure                              | —    | —           | —   | INV-002 satisfied at read-buffer level; full backpressure on the future tunnel is deferred.                                 |
| TLS                                       | —    | —           | —   | Out of foundation scope.                                                                                                    |
| Authentication                            | —    | —           | —   | INV-003; deferred.                                                                                                          |
| Request inspection                        | —    | —           | —   | Deferred to V1.                                                                                                             |