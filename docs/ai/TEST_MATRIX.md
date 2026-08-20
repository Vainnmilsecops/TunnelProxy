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

| Capability                            | Unit | Integration | E2E | Notes                                                                                                        |
| ------------------------------------- | ---- | ----------- | --- | ------------------------------------------------------------------------------------------------------------ |
| Workspace compiles and lints          | ✅   | —           | —   | Foundation checks; Session 02 adds networking deps and lint-clean code.                                      |
| Per-crate placeholder unit tests      | ✅   | —           | —   | Identifiers / status enums.                                                                                  |
| Edge: bind async TCP listener         | ✅   | ✅          | —   | `run_listener`; integration test binds via `127.0.0.1:0`, asserts `TcpStream::connect` succeeds.              |
| Edge: accept connections              | ✅   | ✅          | —   | Each connection is spawned via `tokio::spawn`.                                                               |
| Edge: echo arbitrary bytes            | ✅   | ✅          | —   | `handle_connection` reads into a fixed 8 KiB buffer, writes back exactly `n` bytes.                           |
| Edge: `read == 0` is normal EOF       | ✅   | ✅          | —   | `immediate_eof_is_normal_close` (lib) and `echo_server_returns_empty_for_immediate_close` (integration).     |
| Edge: recoverable error doesn't crash | ✅   | —           | —   | `listener_survives_abrupt_client_close` drops a connection mid-stream and asserts the listener keeps serving. |
| Agent: connect to server              | ✅   | —           | —   | `send_and_verify_round_trip` (lib); smoke test via `agent_dev` example.                                      |
| Agent: send deterministic payload     | ✅   | —           | —   | `TEST_PAYLOAD = b"hello tunnelproxy"`.                                                                       |
| Agent: verify echoed bytes            | ✅   | —           | —   | Byte-exact equality asserted; structured `RunOutcome::Success` / `Mismatch`.                                  |
| Agent: timeout on long operations     | ✅   | —           | —   | `DEFAULT_OPERATION_TIMEOUT` wraps `read_to_end`; mismatched server surfaces as `RunOutcome::Mismatch`.        |
| TCP networking (round-trip baseline)  | ✅   | ✅          | —   | Session 02 deliverables.                                                                                     |
| Bidirectional streaming               | —    | —           | —   | Planned for Session 03.                                                                                      |
| HTTP reverse proxy                    | —    | —           | —   | Planned after Session 03.                                                                                    |
| Tunnel protocol framing               | —    | —           | —   | Planned with the multiplexed tunnel (ADR-005).                                                               |
| Agent ↔ Edge protocol handshake       | —    | —           | —   | Out of scope until framing exists.                                                                           |
| Tunnel registration                   | —    | —           | —   | Planned with control-plane work.                                                                             |
| Multiplexing                          | —    | —           | —   | Deferred until simple bidirectional tunnel works.                                                            |
| Reconnect                             | —    | —           | —   | Deferred until a stable tunnel exists.                                                                       |
| Backpressure                          | —    | —           | —   | INV-002 satisfied at read-buffer level; full backpressure on the future tunnel is deferred.                  |
| TLS                                   | —    | —           | —   | Out of foundation scope.                                                                                     |
| Authentication                        | —    | —           | —   | INV-003; deferred.                                                                                           |
| Request inspection                    | —    | —           | —   | Deferred to V1.                                                                                              |