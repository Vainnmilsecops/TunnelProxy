# TunnelProxy — Module Map

> Authoritative scope of every crate. If a crate starts doing something
> outside its responsibility, the change is wrong, not the rule.

## `tunnelproxy-common`

**Responsibility**

- Cross-component value types and identifiers (`AgentId`, `TunnelId`,
  future `UserId`, `EdgeId`).
- Cross-component error sentinels when they are genuinely shared.
- Small allocation-light helpers used by more than one other crate.
- Cross-platform process termination observation shared by Edge and Agent.

**Prohibited**

- Network I/O of any kind.
- Wire-format types (those belong in `tunnelproxy-protocol`).
- Configuration parsing.
- Component-specific business logic.
- "Generic utils" dumping ground.

## `tunnelproxy-protocol`

**Current implementation:** Version 2 framing, durable REGISTER payload,
handshake rejection, heartbeat, and multiplexed stream payload types/codecs.

**Responsibility (future)**

- Protocol versioning (`PROTOCOL_VERSION`).
- Frame layout and codec.
- Message / enum definitions shared between Edge and Agent.
- Backwards-compatibility tests.

**Prohibited**

- Network I/O. This crate owns types, not sockets.
- Business logic.
- Configuration parsing.
- Direct dependency on `tunnelproxy-agent` or `tunnelproxy-edge`. It
  sits strictly below them.

## `tunnelproxy-agent`

**Current implementation:** Outbound mutual-TLS-or-loopback transport,
certificate-bound Protocol v2 registration intent, handshake/heartbeat,
bounded multiplexed local bridging, and a runnable reconnecting single-session
process supervisor/CLI.

**Responsibility (future)**

- Initiate outbound tunnel to Edge (INV-001).
- Register tunnel metadata with the control plane.
- Forward public request traffic to a local service.
- CLI surface for developers (`tunnelproxy http 3000`).

**Prohibited**

- Accepting inbound public connections directly.
- Hard-coding protocol details that should live in
  `tunnelproxy-protocol`.
- Persisting user data beyond what the runtime strictly needs.

## `tunnelproxy-edge`

**Current implementation:** TCP baselines, bounded forwarder, Agent transport,
bounded stream multiplexing, lifecycle-managed loopback raw TCP routes, and a
runnable single-tunnel process supervisor/CLI whose durable TunnelId route stays
bound across replacement Agent sessions. Its Agent listener can require mutual
TLS and exact certificate-to-Agent/Tunnel authorization before publication.
Versioned full snapshot updates atomically unpublish and close revoked sessions
without placing control-plane storage on the ingress hot path. Edge can
bootstrap that cache from the dedicated authenticated snapshot service and
retain it as stale during reconnect. The runnable CLI can supervise this
snapshot client alongside the data plane without binding before bootstrap.

**Responsibility (future)**

- Terminate TLS for `*.tunnelproxy.dev` (and future custom domains).
- Authenticate / authorise incoming public requests.
- Route requests to the correct agent tunnel using **cached** state.
- Stream request and response bodies with bounded buffers (INV-002).
- Enforce per-tunnel access control.

**Prohibited**

- Trusting client-supplied forwarding headers blindly (INV-009).
- Reaching into the control plane on the hot path of per-request
  routing (INV-007).
- Blocking I/O on async paths (INV-008).

## `tunnelproxy-control-plane`

**Current implementation:** Immutable certificate-fingerprint → AgentId →
TunnelId authorization snapshots, non-zero monotonic versions, canonical
bounded encoding, transactional SQLite persistence, bounded latest-value
distribution, and a dedicated mutual-TLS snapshot service for Edge bootstrap
and reconnect. A runnable binary supports strict full-snapshot import and a
supervised SQLite-refreshing distribution service.

**Responsibility (future)**

- Users, accounts, agents, tunnels, domains, quotas.
- Authentication / authorisation of agents and admins.
- Configuration APIs used by both Edge and Agent.
- Pushing routing state to Edge so per-request routing does not need a
  database query (INV-007).

**Prohibited**

- Touching live request / response payloads.
- Running on the data-plane hot path.
- Logging secrets (INV-003).
