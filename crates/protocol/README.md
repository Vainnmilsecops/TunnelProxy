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

Tunnel Protocol v2 framing is implemented: fixed 16-byte headers, binary-safe
payloads capped at 64 KiB, strict frame/stream scope validation, typed errors,
and async encode/decode. REGISTER carries bounded durable `AgentId`/`TunnelId`
intent and v1 is rejected explicitly. HELLO/REGISTER/REGISTERED payloads and the
Session 07 PING/PONG heartbeat payload are defined and tested. Session 08
defines OPEN_STREAM acknowledgment, binary DATA, directional END_STREAM, and
typed RESET_STREAM semantics. Session 09 multiplexing retains those stream
frame numbers and payloads.
