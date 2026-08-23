# `tunnelproxy-control-plane`

Durable tunnel authorization model and future account/configuration APIs.

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

Session 15 implements immutable authorization snapshots that map an exact
SHA-256 client-certificate fingerprint to `AgentId`, allowed `TunnelId` values,
and tunnel status. Edge consumes these snapshots from memory, outside the
ingress hot path. There is still no database, API server, persistence, or live
snapshot distribution.
