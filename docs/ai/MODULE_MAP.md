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
- Strict component-neutral digest/generation loading plus the bounded
  signed-access token, key-ring, overlap, and reload handle shared by offline
  tooling and Edge.

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
bounded multiplexed local bridging, runnable reconnecting single-session and
bounded multi-session process supervisors/CLI, a bounded loopback operations endpoint with connection
status/metrics, and Agent-owned-key bootstrap/renewal that publishes atomic
credential manifests. The `http <port>` command composes one authenticated
managed-hostname allocation with that supervisor and announces the URL after
the transport becomes ready without coupling hostname lifetime to process
lifetime. A shared library driver powers the canonical `tunnelproxy`
executable and compatibility `tunnelproxy-agent` wrapper. Strict bounded local
config v1 supplies the repeated managed HTTP endpoints, identities, and
credential paths, with offline validation and deterministic layering. Managed
HTTP can gate stdout on a bounded exact-host public HTTPS proof and optionally
continue non-overlapping checks that drive fixed-cardinality local readiness
through pending, degraded, unhealthy, and recovery states.
Strict config v2 and `tunnelproxy start` compose 1â€“16 managed HTTP tunnels,
each on an independent transport, while aggregating readiness and
fixed-cardinality telemetry under one process lifecycle. Optional config-v2
target reload verifies a digest-bound generation and atomically replaces only
the existing TunnelIds' local ports; new streams read the active snapshot and
existing streams retain their local sockets.

**Responsibility (future)**

- Initiate outbound tunnel to Edge (INV-001).
- Register tunnel metadata with the control plane.
- Forward public request traffic to a local service.
- Extend canonical CLI ergonomics without weakening config strictness or
  duplicating the shared driver.

**Prohibited**

- Accepting inbound public connections directly.
- Hard-coding protocol details that should live in
  `tunnelproxy-protocol`.
- Persisting user data beyond what the runtime strictly needs.

## `tunnelproxy-edge`

**Current implementation:** TCP baselines, bounded forwarder, Agent transport,
bounded stream multiplexing, lifecycle-managed raw TCP routes, and bounded
HTTPS ingress with default HTTP/1.1 and opt-in bounded HTTP/2, per-request
deadlines, protocol-specific keepalive, graceful connection drain, and an
independently opt-in HTTP/1.1 WebSocket upgrade surface with strict handshake,
session-cap, idle-timeout, and task-ownership bounds. The runnable
route-bound HTTP/1.1 CONNECT policy has independent authority-port validation,
session/idle bounds, opaque relay ownership, and fixed-cardinality telemetry.
Classic HTTP/2 CONNECT is independently opt-in, shares that policy/capacity,
and adds bounded per-h2-connection relay supervision. RFC 8441 WebSocket is
independently opt-in, shares WebSocket capacity/idle policy, translates a
strict extended CONNECT into a validated local HTTP/1.1 upgrade, and reuses the
same h2 relay supervisor. The runnable
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
separate reloadable public TLS identity, requires exact SNI/Host-or-authority routing,
sanitizes forwarding/hop-by-hop headers, streams through the cached tunnel
router, and enforces connection/header/body/time bounds plus process-local
global/per-source-IP request token buckets without hot-path control-plane
access. Signed-access verification can atomically reload a bounded public-key
ring from a digest manifest while retaining last-known-good and exposing only
fixed-cardinality generation/health counters. Validated HTTP/1.1 and RFC 8441 WebSocket upgrades reuse that route and
Tunnel Protocol v2 stream as opaque bytes without frame inspection. Validated HTTP/1.1 and
classic HTTP/2 CONNECT sessions
reuse the route's fixed local target directly and never dial client-selected
destinations. Its rate-limit peer state and
live counters are explicitly bounded.
The fixed public reachability endpoint runs after request-rate admission,
requires exact Host/SNI route plus a live TunnelId, returns a no-store proof,
and never opens a local tunnel stream.
An optional loopback-only operations listener reads these in-memory snapshots
for health/readiness and fixed-cardinality Prometheus output, remains available
during ingress drain, and performs no Control Plane or storage lookup. It can
also expose an independently opt-in bounded, redacted, process-local history
of admitted ordinary HTTPS request metadata; query/header/body/IP data and
WebSocket, CONNECT, or reachability-probe traffic never enter that registry.

**Responsibility (future)**

- Terminate and route managed `*.tunnelproxy.dev` hostnames and future custom
  domains distributed by the Control Plane.
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
its own monotonic version and idempotent operator CLI administration. Managed
hostname commands allocate one durable `tp-<128-bit hex>` name per TunnelId
under an explicit base domain, protect it from generic route mutation, and
release ownership plus route content transactionally. A dedicated bounded
`TPH1` mutual-TLS service authorizes the Agent certificate, AgentId, and
enabled TunnelId against the current snapshot, applies the server-owned base
domain, and publishes durable route state before success. A
hostname-specific digest-manifest runtime can atomically replace its server
identity and Agent CA for new handshakes while preserving last-known-good and
expiry termination. A
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
