# `tunnelproxy-common`

Shared strongly-typed primitives for the TunnelProxy workspace.

## Responsibility

- Define cross-component identifiers (`AgentId`, `TunnelId`, future
  `UserId`, `EdgeId`).
- Define cross-component error sentinels when they truly belong to every
  layer.
- Define small, allocation-light helpers shared by more than one crate.

## Prohibited

- Network I/O of any kind.
- Wire-format code (that belongs in `tunnelproxy-protocol`).
- Configuration parsing.
- Business logic specific to a single component.
- Generic "utility dumping ground" — if a helper is only useful in one
  other crate, keep it there.

See [`docs/ai/MODULE_MAP.md`](../../docs/ai/MODULE_MAP.md) for the
authoritative scope.
