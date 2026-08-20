# Integration Tests

Cross-crate integration tests for TunnelProxy live in per-crate
`tests/` directories (Cargo's standard integration-test layout), for
example:

- `crates/edge/tests/edge_tcp.rs` — end-to-end TCP tests for
  `tunnelproxy-edge`. Bind a real Tokio listener on an ephemeral port
  and drive it from a real Tokio client. No hardcoded port numbers are
  used.

This directory at the workspace root holds shared documentation about
how integration tests are organised. It is **not** itself a Cargo test
target.

## Running

From the workspace root:

```bash
cargo test --workspace
```

To run only the integration tests in a specific crate:

```bash
cargo test --test edge_tcp -p tunnelproxy-edge
```

## What these tests are not

These tests do **not** exercise the TunnelProxy reverse-tunnel
protocol, the Agent ↔ Edge handshake, registration, heartbeat, or any
forwarding logic. Those belong to future sessions. Anything beyond a
byte-oriented echo over TCP is out of scope here.