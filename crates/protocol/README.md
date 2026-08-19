# `tunnelproxy-protocol`

Wire protocol between `tunnelproxy-edge` and `tunnelproxy-agent`.

## Responsibility (future)

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

Foundation-only. The only export today is `PROTOCOL_VERSION = 1` so that
later sessions can wire up version negotiation without a phantom API.
