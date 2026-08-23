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
and enabled/disabled status. Session 16 adds non-zero monotonic snapshot
versions and a bounded latest-value publisher/subscriber. Higher full snapshots
replace the previous authority, duplicate content is idempotent, and stale or
same-version conflicting updates fail closed. Edge consumes the latest cached
snapshot outside the ingress hot path. There is still no database, external API
server, cross-process transport, or restart persistence.
