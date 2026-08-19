# `tunnelproxy-control-plane`

Future durable tunnel / account configuration and APIs.

## Responsibility (future)

- Users, accounts, agents, tunnel metadata.
- Authentication / authorisation of agents and admins.
- Domain configuration (`*.tunnelproxy.dev` ownership).
- Quotas and billing-related state.
- Configuration APIs used by both Edge and Agent.

## Prohibited

- Touching live request / response payloads. The control plane is not on
  the data-plane hot path.
- Running its own per-request database query to decide routing
  (INV-007). Edge must be able to route with cached / pushed state.
- Logging secrets (INV-003).

## Current state

Foundation-only. Today this is a library crate exposing only a
`TunnelStatus` enum. No database, no API server.
