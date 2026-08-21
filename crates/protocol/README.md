# `tunnelproxy-protocol`

Wire protocol between `tunnelproxy-edge` and `tunnelproxy-agent`.

## Responsibility

- Protocol versioning.
- Frame layout.
- Message / enum definitions.
- Codecs (encode + decode).
- Backwards-compatibility tests.

## Prohibited

- Network I/O. This crate owns types and codecs, not sockets.
- Business logic.
- Configuration parsing.
- Anything that depends on `tunnelproxy-agent` or `tunnelproxy-edge`
  directly — this crate sits strictly below them.

## Current state

Tunnel Protocol v1 framing is implemented: fixed 16-byte headers, binary-safe
payloads capped at 64 KiB, strict frame/stream scope validation, typed errors,
and async encode/decode. HELLO/REGISTER/REGISTERED handshake payloads and the
Session 07 PING/PONG heartbeat payload are defined and tested. Stream traffic
types exist, but their runtime semantics are not implemented yet.
