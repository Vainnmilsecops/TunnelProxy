# TunnelProxy — Module Map

> Authoritative scope of every crate. If a crate starts doing something
> outside its responsibility, the change is wrong, not the rule.

## `tunnelproxy-common`

**Responsibility**

- Cross-component value types and identifiers (`AgentId`, `TunnelId`, exact
  canonical `PublicHostname`, future `UserId`, `EdgeId`).
- Cross-component error sentinels when they are genuinely shared.
- Small allocation-light helpers used by more than one other crate.
- Cross-platform process termination observation shared by Edge and Agent.
- Process-wide text/JSON stderr logging configuration shared by runnable
  components and development examples, including the optional bounded
  nonblocking writer, lifetime guard, and fixed-cardinality sink telemetry.
- Fixed-cardinality process-local multiplex telemetry and RAII lifecycle
  guards shared by Agent and Edge.

**Prohibited**

- Network I/O of any kind.
- Wire-format types (those belong in `tunnelproxy-protocol`).
- Component-specific configuration parsing.
- Component-specific business logic.
- "Generic utils" dumping ground.

## `tunnelproxy-protocol`

**Current implementation:** Version 2 framing, durable REGISTER payload,
handshake rejection, heartbeat, multiplexed stream payload types/codecs, and
the separate bounded Enrollment Protocol v1 message codec.

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
bounded multiplexed local bridging, a runnable reconnecting single-session
process supervisor/CLI, a bounded loopback operations endpoint with connection
status/metrics, and Agent-owned-key bootstrap/renewal that publishes atomic
credential manifests.

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
bounded stream multiplexing, lifecycle-managed raw TCP routes, and bounded
HTTPS/HTTP/1.1 ingress with opt-in capped keep-alive, per-request deadlines,
and graceful connection drain. The runnable
single-tunnel process keeps its durable TunnelId listener bound across
replacement Agent sessions. Loopback is the default; explicit public raw mode
requires Agent mTLS, dynamic snapshot authority, global admission, and a
bounded per-source-IP active-connection permit. Its Agent listener requires
exact certificate-to-Agent/Tunnel authorization before publication.
Versioned full snapshot updates atomically unpublish and close revoked sessions
without placing control-plane storage on the ingress hot path. Edge can
bootstrap that cache from the dedicated authenticated snapshot service and
retain it as stale during reconnect. The runnable CLI can supervise this
snapshot client alongside the data plane without binding before bootstrap.
In dynamic HTTPS mode, Edge bootstraps an independent authenticated route
stream, atomically reads immutable in-memory catalogs on the request path, and
serves the last authenticated catalog only until its configured stale deadline.
Public raw ingress remains opaque TCP. The alternative HTTPS mode terminates a
separate reloadable public TLS identity, requires exact SNI/Host routing,
sanitizes forwarding/hop-by-hop headers, streams through the cached tunnel
router, and enforces connection/header/body/time bounds plus process-local
global/per-source-IP request token buckets without hot-path control-plane
access. Its rate-limit peer state and live counters are explicitly bounded.
An optional loopback-only operations listener reads these in-memory snapshots
for health/readiness and fixed-cardinality Prometheus output, remains available
during ingress drain, and performs no Control Plane or storage lookup.

**Responsibility (future)**

- Allocate and administer `*.tunnelproxy.dev` hostnames and future custom domains.
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
and reconnect. A runnable binary supports strict full-snapshot import, a
supervised SQLite-refreshing distribution service, bound bootstrap-token
provisioning, short-lived Agent leaf issuance, and transactional enrollment
snapshot activation. Credential persistence includes activation deadlines and
terminal tombstones; a bounded supervised reconciler expires abandoned
overlaps. Operator commands expose secret-safe credential status and an
idempotent Agent/Tunnel emergency revoke that invalidates tokens and commits
through the same complete-snapshot authority path. An optional bounded,
loopback-only operations listener reports in-memory readiness and
fixed-cardinality snapshot, refresh, enrollment, and reconciliation metrics
without querying SQLite during a scrape. A separate transactional SQLite HTTPS
route catalog holds at most 64 exact hostname-to-TunnelId/status records with
its own monotonic version and idempotent operator CLI administration. A
separate bounded mutual-TLS service distributes complete latest-value route
catalogs to Edge without changing authorization snapshots or Tunnel Protocol
v2. Its server and Edge client configurations support separate digest-manifest
TLS reload supervisors while retaining the route-specific ALPN and atomic
last-known-good publication semantics.

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
