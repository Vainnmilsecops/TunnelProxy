# TunnelProxy — Module Map

> Authoritative scope of every crate. If a crate starts doing something
> outside its responsibility, the change is wrong, not the rule.

## `tunnelproxy-common`

**Responsibility**

- Cross-component value types and identifiers (`AgentId`, `TunnelId`,
  future `UserId`, `EdgeId`).
- Cross-component error sentinels when they are genuinely shared.
- Small allocation-light helpers used by more than one other crate.

**Prohibited**

- Network I/O of any kind.
- Wire-format types (those belong in `tunnelproxy-protocol`).
- Configuration parsing.
- Component-specific business logic.
- "Generic utils" dumping ground.

## `tunnelproxy-protocol`

**Current implementation:** Version 1 framing, handshake, heartbeat, and
single-stream lifecycle payload types/codecs.

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

**Current implementation:** Outbound handshake/heartbeat plus a one-active-
stream bridge to one configured local TCP service.

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
and loopback-only one-active-stream raw TCP ingress.

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
