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
snapshot outside the ingress hot path. Session 17 adds canonical encoding,
transactional SQLite persistence, durable-before-live publication, and a
dedicated mutually authenticated Edge bootstrap/push service with bounded
reconnect. Session 18 adds strict JSON full-snapshot import, repository refresh,
and the runnable `tunnelproxy-control-plane serve|import` process. There is
also transactional Agent enrollment/activation/revocation and an optional
bounded loopback operations endpoint for health, readiness, and process-local
service metrics. Session 31 adds a separate 64-record, monotonically versioned
SQLite catalog for exact public HTTPS hostname routes plus idempotent
`https-route-upsert`, `https-route-remove`, and `https-route-list` operator
commands. Operations scrapes read only in-memory atomics. Catalog distribution
to Edge uses a separate authenticated latest-value stream. Session 39 adds
transactional `https-hostname-allocate`/`https-hostname-release` commands for
one OS-random managed hostname per TunnelId under an operator-supplied base
domain. An Agent-facing allocation API, DNS/TLS automation, a general
administrative API, protected issuer-key service, durable metrics, and
multi-edge coordination are still absent.
