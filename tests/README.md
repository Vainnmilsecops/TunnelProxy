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

The per-crate integration suites now exercise TCP echo/relay/forwarding,
Tunnel Protocol framing, Agent ↔ Edge handshake, heartbeat liveness, and the
single-stream reverse TCP data path. They still do **not** exercise public HTTP
ingress, TLS, authentication, durable tunnel registration, or multiplexing.
