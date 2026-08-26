# TunnelProxy — Architecture

> Status: **pre-MVP data-path foundation.** Local TCP primitives, protocol
> framing, Agent → Edge handshake, heartbeat, bounded multiplexing, and
> durable-identity raw-ingress routes, persistent authorization, and
> authenticated Edge snapshot bootstrap are implemented. Public TLS/HTTP
> ingress and multi-edge routing are not.

## 1. High-level architecture

```
                    +--------------------------+
                    |      Internet Client     |
                    |   (browser / curl / SaaS) |
                    +--------------------------+
                                |
                                |  HTTPS request
                                v
                    +--------------------------+
                    |   *.tunnelproxy.dev      |
                    |        TLS termination   |
                    +--------------------------+
                                |
                                v
                    +--------------------------+
                    |     TunnelProxy Edge     |
                    |  - authenticate request  |
                    |  - resolve tunnel        |
                    |  - stream to agent       |
                    +--------------------------+
                                |
                                |  persistent secure
                                |  outbound tunnel
                                v
                    +--------------------------+
                    |     TunnelProxy Agent    |
                    |  - demux to local port   |
                    |  - forward + stream back |
                    +--------------------------+
                                |
                                v
                    +--------------------------+
                    |     Local Service        |
                    |     (localhost:3000)     |
                    +--------------------------+
```

Three runtime components, plus an off-path control plane.

## 2. Component roles

### 2.1 Agent

Runs on the developer's machine. Responsibilities (future):

- Initiate an **outbound** secure tunnel to one Edge node (INV-001).
- Authenticate itself with the control plane.
- Register which local ports it wants to expose.
- Demultiplex inbound streams to the correct local service.
- Stream request / response bytes back to the Edge.

The agent **never accepts inbound connections** from the public
internet. If it did, the security story collapses.

### 2.2 Edge

Runs in a data center or cloud. Responsibilities (future):

- Terminate TLS for `*.tunnelproxy.dev` (and future custom domains).
- Authenticate the incoming public request.
- Resolve the request to a specific agent tunnel using **cached**
  routing state (INV-007).
- Forward the request across the agent's persistent tunnel and stream
  the response back to the public client.
- Enforce per-tunnel access control.
- Bound every buffer on the hot path (INV-002).

### 2.3 Control plane

Off the data-plane hot path. Responsibilities (future):

- Own durable state: users, agents, tunnels, domains, auth, quotas.
- Issue short-lived routing state to Edge so per-request routing does
  not need a database round-trip (INV-007).
- Provide configuration APIs to agents and admins.
- Manage authentication material.

### 2.4 Local service

The developer-owned process the agent forwards into. Not part of
TunnelProxy. Out of scope for security guarantees beyond best-effort
isolation in the agent process.

### 2.5 Public client

Anyone making an HTTPS request to a tunnel URL. Could be a browser, a
mobile app, a CLI, a SaaS webhook. Treated as untrusted input. Edge
never trusts client-supplied headers verbatim (INV-009).

### 2.6 Layer-4 TCP relay (Session 03)

Session 03 introduces a small **layer-4 TCP relay** inside
`tunnelproxy-edge`, separate from the agent ↔ edge tunnel of the
golden path:

```
Downstream TCP Client
    |
    v
TunnelProxy Edge (relay)
    |
    v
Configured TCP Upstream
```

This is **not** the reverse tunnel. It is a generic byte-oriented
TCP relay: for every accepted downstream connection, the relay dials
a fresh upstream TCP connection and forwards bytes concurrently in
both directions using
[`tokio::io::copy_bidirectional`], which honors TCP half-close. The
relay preserves bounded buffers (no `read_to_end`, no payload
logging) and isolates per-connection failures so the listener keeps
running. The relay exists to validate the byte-stream pipeline that
later sessions will reuse for the actual agent ↔ edge tunnel.

### 2.6.1 Local TCP forwarder (Session 04)

Session 04 hardens the Session 03 relay into a small,
lifecycle-aware **local TCP forwarder** that lives next to the
relay primitives inside `tunnelproxy-edge`. The forwarder keeps the
same byte-stream contract but adds:

```
            ForwardConfig
   listen_addr:  SocketAddr
   upstream_addr: SocketAddr
   max_connections: usize           # bounded concurrent admission
   connect_timeout:  Duration       # upstream TCP connect deadline
```

- **Connection identity.** Every accepted downstream connection is
  tagged with a process-local `ConnectionId(u64)` allocated from a
  shared `Arc<ConnectionIdAllocator>`. The id appears on every
  structured lifecycle log line.
- **Connection lifecycle.** Each connection progresses through
  observable phases
  ([`ConnectionLifecycle::Accepted`], `ConnectingUpstream`,
  `Relaying`, `Closed`, plus the failure phases
  `CapacityRejected`, `UpstreamConnectFailed`,
  `UpstreamConnectTimeout`, `RelayIoFailed`).
- **Bounded admission.** A `tokio::sync::Semaphore` of size
  `max_connections` is acquired *before* dialing the upstream.
  Accepted connections with no available permit are rejected
  cleanly (downstream shut down) and the listener keeps running.
  The permit is owned by the per-connection task via RAII
  (`OwnedSemaphorePermit`), so the permit is always released when
  the connection ends — by success or by failure.
- **Bounded upstream connect.** The upstream dial is wrapped in
  `tokio::time::timeout(config.connect_timeout, TcpStream::connect(...))`.
  A timed-out connect is categorised as
  `ForwardError::UpstreamConnectTimeout`; an I/O error is
  `ForwardError::UpstreamConnect`. The two are deliberately distinct
  so dashboards can tell "host unreachable" from "host slow".
- **Resource lifetime.** Every per-connection resource — the
  downstream `TcpStream`, the upstream `TcpStream`, and the
  semaphore permit — is owned by the per-connection task. Dropping
  the task drops all of them. There are no detached child tasks.
- **Statistics.** Each connection surfaces a `ConnectionOutcome`
  carrying `RelayStats` (bytes each direction) and a `Duration`,
  usable for runtime observability and for tests.
- **Forwarder API.** `Forwarder::new(ForwardConfig)` validates the
  config; `forwarder.run()` binds the listener and runs the
  lifecycle loop until `accept` itself fails.

The forwarder is **not** the reverse tunnel either. It is the
production-quality local-TCP forwarder that the agent ↔ edge
tunnel will eventually be layered on top of. The Session 03 relay
primitives remain in the public API for regression coverage and
for tests that want a minimal surface; new code should use the
forwarder.

### 2.7 Single-stream reverse data path (Session 08)

Session 08 connects the previously separate foundations into one vertical
slice. `SingleStreamEdgeRuntime` accepts one loopback raw TCP ingress, opens a
framed stream over the established Agent transport, and the Agent connects that
stream to one configured local TCP service.

Only one stream is active at a time. Stream IDs increase monotonically and the
same Agent connection can serve later streams sequentially. Fixed 16 KiB reads,
the protocol's 64 KiB frame ceiling, direct sequential writes, open/connect/idle
deadlines, and per-stream reset keep resource use bounded. Directional
`END_STREAM` preserves TCP half-close, while PING/PONG remains active during
data transfer.

The ingress is deliberately loopback raw TCP. There is no public listener,
hostname resolution, HTTP parsing, TLS, authentication, durable registration,
or concurrent multiplexing in this runtime.

### 2.8 Bounded multiplexing and session routing (Session 09)

`MultiplexedEdgeRuntime` owns a live registry keyed by process-local
`TransportSessionId`. `EdgeSessionRouter` clones only a bounded command sender
from that registry, releases the registry lock, then asks the selected session
to open a stream. Registry removal on session exit makes stale IDs fail closed.

Each Agent transport is split once: one task decodes frames and dispatches them
to bounded per-stream queues, and one writer actor serializes all outbound
frames. Heartbeat/reset traffic has a priority queue; DATA and END_STREAM use a
shared FIFO so lifecycle frames cannot overtake earlier bytes. Each logical
stream owns its ingress/local socket and failure cleanup, so one stream or one
Agent failure does not corrupt neighboring streams or sessions.

This layer remains loopback raw TCP and ephemeral. It does not assign public
hostnames, authenticate Agents, persist routes, reconnect, terminate TLS, or
implement credit/window flow control.

### 2.9 Raw ingress binding and route lifecycle (Session 10)

`RawIngressRouteManager` binds an independent loopback `TcpListener` for each
ephemeral route and targets one live `TransportSessionId`. Global route count
and per-route accepted connections are bounded. Accepted sockets pass to
`EdgeSessionRouter::open_stream_tracked`; a completion handle holds the route
permit until the logical stream actually releases the socket.

Removing a route closes its listener and transitions it to draining. Existing
streams finish normally, after which the route is removed. A configured drain
deadline returns a typed timeout but does not silently abort traffic. Live
session snapshots stop and clean routes when their target Agent disconnects.

These routes are process-local development bindings, not durable tunnel
records or public endpoints. They do not survive restart or reconnect and are
never reassigned to another Agent session.

### 2.10 Graceful runtime shutdown and supervision (Session 11)

`tunnelproxy-common` owns an idempotent watch-based shutdown trigger/signal and
the shared drain deadline. Runtime APIs stop listener admission before waiting
on their `JoinSet` children. Completion is explicit: `Drained` counts joined
tasks, while `Forced` reports both completed and deadline-aborted tasks.

Multiplexed Edge flips its router to a fail-closed draining state before asking
live sessions to stop accepting stream commands. The Agent answers any later
`OPEN_STREAM` with `SessionClosing` and lets existing local bridges finish.
Raw-route shutdown similarly prevents new route creation and supervises every
routed connection. OS signal handling remains one layer above these mechanisms
and is wired by the Session 12 process entrypoints.

### 2.11 Runnable process composition (Session 12)

`EdgeRuntime` is a single-tunnel process supervisor. It binds the Agent
transport first, waits for the one permitted Agent to register, then creates a
loopback raw route targeting that ephemeral session. A route bind failure
triggers startup rollback and joins the transport before returning an error.
On shutdown, raw admission and routed streams drain before the Agent transport
is told to close.

`AgentRuntime` owns one outbound connect, handshake, and multiplexed local
bridge. Cancellation can win before connect completes or while the session is
established.

The `tunnelproxy-edge` and `tunnelproxy-agent` binaries translate Ctrl-C on all
platforms and SIGTERM on Unix into the shared idempotent trigger. OS handlers
never perform socket cleanup themselves. This is production-style lifecycle
composition over a development-only loopback route; it is not public ingress.

### 2.12 Reconnect and route recovery (Session 13)

`AgentRuntime` retries transient connect, timeout, established-session I/O, and
peer-close failures with bounded exponential delay and downward jitter. A
shutdown signal interrupts both connection attempts and backoff sleep. Protocol
violations remain terminal, an optional consecutive-failure budget can stop the
loop, and a sufficiently stable session resets the failure streak.

`EdgeRuntime` no longer exits when its sole Agent disconnects. The raw route is
removed with the dead session, the transport listener remains available, and
the same configured loopback address is rebound to the next live session.
Active streams are not replayed. Each handshake still receives a new ephemeral
`TransportSessionId`; reconnect does not introduce durable Agent or tunnel
identity, persistence, authentication, or any wire-protocol change.

### 2.13 Mutual TLS Agent transport (Session 14)

The runnable multiplexed transport accepts either explicit loopback-only
plaintext for development or mutual TLS. In mTLS mode, Agent verifies the Edge
CA and DNS server name; Edge verifies the Agent client-certificate chain. Both
advertise ALPN `tunnelproxy/1`. Edge holds its bounded session permit while TLS
negotiates, applies a separate TLS deadline, and publishes the session only
after TLS and Protocol v1 both succeed.

TLS wraps the byte stream below framing, so HELLO, the empty REGISTER payload,
REGISTERED, heartbeat, and multiplex frames are unchanged. Authentication means
only possession of a certificate signed by the configured CA. No certificate
is mapped to durable `AgentId`/`TunnelId` or tunnel authorization yet. Private
key material is parsed into rustls configuration and excluded from diagnostics.

### 2.14 Authenticated durable tunnel routing (Session 15)

Protocol v2 and ALPN `tunnelproxy/2` add bounded `AgentId`/`TunnelId` intent to
REGISTER. After mTLS, Edge computes the SHA-256 fingerprint of the authenticated
leaf certificate and checks an immutable authorization snapshot:

```text
certificate fingerprint -> AgentId -> TunnelId -> enabled/disabled
```

The session is not published until authorization and a unique live TunnelId
claim both succeed. Edge retains its ephemeral session registry for stream
ownership and adds a cached `TunnelId -> TransportSessionId` registry for
durable route resolution. The lookup is in-memory and never reaches control
plane storage on ingress (INV-007).

The runnable raw listener is created from TunnelId before Agent availability.
It remains bound while the tunnel is offline, closes new sockets when there is
no live mapping, and automatically resolves the next authenticated session.
Existing streams remain owned by their original session and are never replayed.
Session 15 snapshots and route intent began as startup configuration.

### 2.15 Versioned snapshot distribution and live revocation (Session 16)

The control-plane model now wraps each complete authorization snapshot in a
non-zero monotonic `SnapshotVersion` and distributes only the latest value over
a bounded watch channel. A higher version replaces the complete authority;
equal content at the same version is idempotent, while stale versions and
same-version conflicts are rejected before distribution. Skipping intermediate
versions is safe because snapshots are full replacements rather than deltas.

Edge reads the current cached snapshot during REGISTER and revalidates the
authenticated certificate/Agent/Tunnel principal immediately before route
publication. Publication, tunnel stream enqueue, and snapshot reconciliation
share an authorization gate. Applying a new snapshot removes revoked durable
and ephemeral mappings before signalling their session to close, so no later
stream can enter a revoked route. Active streams fail closed with the revoked
transport; raw listeners remain bound and can use a newly authorized Agent
without restart or rebind.

If the in-process producer closes, Edge marks its authorization source stale
but retains the last complete cached snapshot. Session 16 itself did not yet
provide external distribution or restart persistence; Session 17 adds those
without changing this cache behavior.

### 2.16 Persistent snapshots and authenticated Edge bootstrap (Session 17)

The Control Plane stores the latest complete authorization snapshot in SQLite.
Agent grants and tunnel status rows are replaced together with a singleton
version/digest head under one `IMMEDIATE` transaction. The canonical digest is
verified on reload, so malformed identifiers, status values, versions, or
inconsistent state fail closed. SQLite work runs outside Tokio worker threads,
and the live publisher advances only after the durable commit returns.

```text
Admin/import (future UI)
        |
        v
PersistentSnapshotAuthority -- transaction --> SQLite
        |
        +-- bounded watch --> mTLS snapshot service
                                  |
                         full snapshot / UpToDate
                                  |
                                  v
                         Edge in-memory cache
                                  |
                         registration + ingress
                         (no storage lookup)
```

Snapshot distribution is a dedicated protocol with its own magic/version,
strict 1 MiB bound, mutual TLS, and ALPN `tunnelproxy-snapshot/1`. It is not a
Tunnel Protocol v2 frame and never shares the Agent transport. A fresh Edge
requests version zero and must receive a complete snapshot before constructing
its dynamic registration policy. After disconnect, it continues using the last
complete cached snapshot with `Stale` health and retries with bounded backoff;
an authenticated `UpToDate` or newer full snapshot restores `Live` health.

Session 17 exposes this as a library composition surface; Session 18 adds the
runnable ownership described next.

### 2.17 Runnable snapshot operations and Edge supervision (Session 18)

Operators initialize and replace authority with a strict, bounded JSON full
snapshot. The import command validates the complete model before the Session 17
transaction commits it. `ControlPlaneRuntime` rejects an empty repository,
owns the mTLS listener, and periodically reloads SQLite on a blocking worker.
Only a newly committed version advances its bounded publisher; missed timer
ticks are skipped rather than queued.

The Control Plane binary has separate `import` and `serve` commands. Serving
requires an explicit database, server certificate/key, and trusted Edge client
CA. There is no plaintext distribution mode and no general mutation API.

The Edge CLI chooses exactly one authorization source. Development plaintext
uses its explicit loopback grant; static mTLS uses one exact Agent certificate;
dynamic mTLS requires the complete snapshot server/CA/client identity/server
name group. `SnapshotAwareEdgeRuntime` finishes dynamic bootstrap before Edge
binds Agent or raw listeners, then supervises the reconnecting snapshot client
and data plane under one cancellation tree. Transient service loss preserves
the in-memory snapshot as `Stale`; unexpected terminal snapshot failure stops
the composed Edge rather than silently abandoning refresh.

### 2.18 Bounded Edge cold-start snapshot cache (Session 19)

Dynamic Edge may opt into a local cache directory plus a non-zero maximum stale
age. The client still attempts authenticated online bootstrap first. Only
availability failures may load the latest valid generation; TLS identity,
ALPN, protocol, server rejection, rollback, and conflicting content fail
closed. Offline bootstrap is exposed as `Stale` and reconnect continues with
the cached version.

Each immutable generation contains format metadata, authentication time, the
canonical versioned snapshot, and a SHA-256 integrity digest. The file is fully
written and synchronized before a rename to its final name, and the in-memory
publisher advances only after that durable step. Older generations are cleaned
afterward. Cache loading and writing run on blocking workers; Agent registration
and raw ingress continue reading only immutable memory state. If the stale
deadline expires before authenticated recovery, the snapshot supervisor stops
the complete Edge runtime and releases its listeners.

The integrity digest is not a signature. Local host/filesystem compromise and
cryptographic rollback resistance remain outside the model.

### 2.19 Atomic TLS generation reload (Session 20)

Every implemented mTLS role may retain its startup-only behavior or opt into a
polling reload manifest. A manifest is the commit point for one role-specific
bundle: Agent client (`server_ca`, `client_certificate`,
`client_private_key`), Edge Agent-facing server (`server_certificate`,
`server_private_key`, `client_ca`, plus
`authorized_client_certificate` in static authorization mode), snapshot client,
or snapshot server. It declares a non-zero generation and SHA-256 digest for
the exact expected files.

The loader performs bounded filesystem reads on a blocking worker, verifies the
whole file set, constructs and validates a complete rustls configuration, then
atomically swaps the immutable configuration used by future handshakes. A
stale, conflicting, partial, corrupt, not-yet-valid, expired, or otherwise
invalid candidate leaves last-known-good active. Leaf expiry is observable and
becomes terminal when no replacement arrives. Reload does not renegotiate an
established TLS session; reconnect selects the latest generation. Static Edge
authorization is generation-coupled and its full-snapshot reconciliation
revokes a session whose exact client leaf was removed.

### 2.20 Agent enrollment and two-phase renewal (Session 21)

Dynamic authorization mode may run a separate server-authenticated enrollment
listener using ALPN `tunnelproxy-enroll/1`. Agent creates and retains an ECDSA
P-256 private key, journals the CSR and request ID, and authenticates with a
file-delivered bootstrap or renewal token. Control Plane stores only token
hashes and signs a client-auth-only short-lived leaf after token preflight.

Issuance is one SQLite transaction that records credential state, consumes the
bootstrap token when applicable, and advances the complete authorization
snapshot with the new fingerprint. The previous fingerprint remains during
renewal. Agent verifies the returned fingerprint and key pair, writes the three
credential files, publishes the strict Session 20 manifest, and waits for that
generation to become live. A second authenticated activation transaction then
removes the predecessor and retires it. Exact request replay returns durable
state, so either process may crash between phases without generating a second
logical issuance.

This mutation path feeds the existing snapshot publisher; Edge ingress still
uses only cached immutable state. See
[`AGENT_ENROLLMENT.md`](AGENT_ENROLLMENT.md) for trust boundaries and commands.

### 2.21 Emergency credential revocation and reconciliation (Session 22)

Enrollment credentials now have explicit `pending`, `active`, `retired`,
`revoked`, and `expired` states. Each issuance records a bounded activation
deadline. Activation at or after that deadline atomically expires the pending
credential, removes only its temporary fingerprint from the full snapshot,
and preserves a durable tombstone so an exact request replay receives
`RequestExpired` instead of creating another logical issuance.

The supervised enrollment runtime periodically reconciles abandoned pending
credentials in bounded batches. State transition, snapshot mutation, and
snapshot-version advancement share one SQLite transaction; publication occurs
only after commit. A terminal reconciliation or publication failure stops the
Control Plane runtime instead of silently leaving authority stale.

`revoke-agent` performs the emergency path for one exact Agent/Tunnel pair. It
revokes pending and active credentials, invalidates their renewal and bootstrap
tokens, removes that pair's grants while preserving unrelated tunnels, and
advances the snapshot only when authority changed. The operation is idempotent.
Dynamic Edge reconciliation then closes matching live mTLS sessions and active
streams without adding database access to the data-plane hot path.

The Agent treats revocation and other policy/authentication rejections as
terminal. An expired pending request is retryable after its local pending
journal is removed, allowing renewal from the still-active predecessor. This
is application-level authorization revocation; it is not CRL/OCSP or general
PKI revocation.

### 2.22 Explicit public raw ingress and per-IP admission (Session 23)

The durable raw route may now opt into `Public` exposure; `LoopbackOnly`
remains the default. A non-loopback runnable listener is valid only when the
operator supplies the public flag and a non-zero per-IP active-connection bound
that does not exceed the existing global route bound. Public mode also requires
Agent-facing mutual TLS and authorization owned by the external dynamic
snapshot stream. Static certificate policy and plaintext development mode fail
configuration before the raw listener binds.

```text
public TCP client
       |
       v
global route semaphore
       |
       v
per-source-IP RAII permit
       |
       v
cached TunnelId -> live TransportSessionId -> Agent local service
```

The per-IP map stores only admitted active peers, so its cardinality cannot
exceed the global connection limit. The permit is held through logical stream
completion and released after every open failure, disconnect, revocation,
drain, or forced task abort. Capacity rejection closes only that accepted
socket. Route status keeps cumulative accepted/global/per-IP/unavailable
counters, and structured events include peer address and outcome but never
traffic bytes.

Public exposure does not change Tunnel Protocol v2 or the snapshot format.
Ingress still reads only immutable cached routing state. When a tunnel is
offline the socket closes fail-closed; a valid reconnect is used without
listener rebind. Dynamic snapshot removal closes the Agent session and active
public streams through the existing authorization gate. Raw TCP is opaque: the
Edge does not provide public-client TLS or application authentication, and a
stale Edge cache retains the bounded availability/revocation-delay tradeoff
defined in Session 19.

### 2.23 Bounded public HTTPS/HTTP/1.1 ingress (Session 25)

The runnable Edge can replace its raw listener with one explicitly configured
HTTPS listener. Public mode requires the same Agent-facing mutual TLS and live
dynamic snapshot authority as public raw ingress. The public side uses a
separate server-only TLS identity with ALPN `http/1.1`; its complete
certificate/key generation can reload atomically for new handshakes.

```text
HTTPS client -> global/per-IP admission -> TLS + SNI -> HTTP/1.1 parser
             -> exact cached Host -> TunnelId -> live Agent stream -> local HTTP
```

Configured DNS hostnames are ASCII-normalized and matched exactly. Each request
must carry one valid Host matching TLS SNI; an absolute-form request target must
match as well. Unknown hosts, host-fronting attempts, offline tunnels, CONNECT,
and upgrades fail closed. Edge removes hop-by-hop fields and all untrusted
`Forwarded`/`X-Forwarded-*` input, then writes canonical trusted forwarding
headers before sending origin-form HTTP to the Agent's local service.

Connection, per-IP, header-buffer, header-count, body, TLS-handshake,
header-read, full-request, and duplex-buffer bounds are explicit. HTTP ingress
reads only the immutable hostname table and the existing in-memory
`TunnelId -> TransportSessionId` router; it never queries the Control Plane.
Shutdown stops HTTPS admission and drains or force-joins its connection tasks
before Agent transport shutdown. The first slice deliberately supports one
HTTP/1.1 request per public TLS connection, with no HTTP/2, WebSocket/upgrade,
CONNECT, automatic hostname allocation, or public-client authentication.

### 2.24 Bounded HTTP request-rate admission (Session 26)

After TLS and exact Host/SNI/absolute-authority validation, but before reading
the request body or opening a tunnel stream, HTTPS ingress atomically admits a
request against both a process-wide token bucket and a source-IP token bucket:

```text
validated request -> global bucket + socket-peer-IP bucket
                  -> admitted -> request body -> Agent stream
                  -> rejected -> 429 + integer Retry-After -> close
```

Buckets use integer fixed-point refill accounting, so admission is deterministic
and does not depend on floating-point rounding. One lock covers the global and
peer decisions; a per-IP rejection does not consume a global token. The peer
table is bounded, idle entries expire after a configured TTL, and admission
performs only a fixed-size cleanup batch when capacity is needed. A full table
fails closed with `429` instead of allocating unbounded state. Source identity
comes only from the accepted socket address, never from client-supplied
forwarding headers.

Live status exposes admitted requests, each rejection category, and current and
peak tracked-peer counts. Structured rejection events contain only peer,
hostname, category, and retry delay. State is deliberately local to one Edge
process and resets on restart; it is a bounded local abuse control, not shared
quota enforcement or distributed DDoS protection. Tunnel Protocol v2 and the
authorization snapshot format are unchanged.

### 2.25 Bounded Edge operations endpoint (Session 27)

The runnable Edge may bind a separate opt-in loopback-only HTTP/1.1 listener
for `GET`/`HEAD /healthz`, `/readyz`, and `/metrics`. It has explicit global
connection, header bytes/count, header-read, full-request, and drain bounds;
keep-alive is disabled. Non-loopback configuration fails before listener use,
and no public opt-in exists for this surface.

Readiness is computed only from cached Edge state: the configured durable
TunnelId must currently resolve to a live Agent session and process drain must
not have begun. Metrics read the same in-memory router plus raw-route or HTTPS
status handles. They never query the Control Plane or storage and never place
external backend I/O on ingress routing:

```text
loopback collector -> operations HTTP -> cached router/authorization status
                                    \-> raw or HTTPS atomic/watch counters
```

The Prometheus text schema has a fixed metric/label set. It reports liveness,
readiness, authorization source/version/revocations, operations admission, and
raw or HTTPS ingress counters including rate-limit state. Peer addresses,
hostnames, TunnelIds, AgentIds, session IDs, certificates, secrets, and traffic
payloads are never metric values or labels.

On shutdown, Edge first marks readiness false, then drains public ingress while
operations remains observable. It next drains operations and finally stops the
Agent transport. The endpoint and counters are process-local and non-durable;
public/authenticated operations, remote write, dashboards, alerting, and
Agent/Control Plane exporters remain separate work. Tunnel Protocol v2 and the
snapshot format are unchanged.

### 2.26 Secret-safe process logging (Session 28)

Every runnable Agent, Edge, and Control Plane process initializes tracing
through `tunnelproxy-common` before parsing component arguments or touching
network/file resources. `TUNNELPROXY_LOG_FORMAT` selects `text` (the default)
or `json`; `RUST_LOG` provides the same validated filter in either format.
Invalid values fail startup with a configuration exit before component side
effects.

Both renderers write events to stderr. JSON mode emits one object per line,
disables ANSI, and retains stable top-level `timestamp`, `level`, `target`, and
nested `fields` keys. CLI help and operator reports remain plain stdout.
Multiline usage is omitted after JSON-mode argument errors so collectors never
receive mixed JSON/text stderr. Existing invariant INV-003 still governs event
construction: tokens, private keys, certificates, paths to secret material,
and traffic bodies are not event fields.

The sink is deliberately local and synchronous. File rotation, durable or
remote shipping, dashboards/alerts, and an asynchronous buffering queue remain
operator/backend work tracked by DEBT-010. Protocol and snapshot schemas are
unchanged.

### 2.27 Bounded Agent operations endpoint (Session 29)

The runnable Agent may bind a separate loopback-only HTTP/1.1 operations
listener. A process-local atomic status handle records one of six fixed phases:
offline, connecting, connected, reconnect backoff, draining, or stopped. It
also records monotonic connection attempts, established sessions, reconnects,
disconnects, connection failures, and the current consecutive-failure streak.
The reconnect supervisor is the only counter writer; the process supervisor
may atomically force `draining`, which later reconnect transitions cannot
overwrite.

`/healthz` reports operations-listener liveness. `/readyz` is true only for an
established registered Agent session. `/metrics` renders the status and bounded
operations-admission counters with a fixed state label set. No durable identity,
address, transport session, certificate, secret, or traffic value is exposed.
The operations listener has explicit connection/header/time/drain limits and
is unavailable on non-loopback addresses.

Startup binds operations before polling the Agent connection future, so bind
failure creates no outbound connection. Shutdown marks Agent readiness false,
drains the transport/TLS/enrollment supervisors while operations remains
available, then stops operations and releases its port. Metrics are
process-local and reset on restart. Control Plane metrics, remote write,
durability, dashboards, and alerting remain tracked by DEBT-010; protocol and
snapshot formats are unchanged.

## 3. Control plane vs data plane

| Concern                | Control Plane | Data Plane |
|------------------------|---------------|------------|
| User accounts          | yes           | no         |
| Agent registration     | yes           | no         |
| Tunnel metadata (durable) | yes        | no         |
| Routing state (cached) | issuer        | consumer   |
| Live public requests   | no            | yes        |
| Live agent connections | no            | yes        |
| Quota counters         | yes           | reports    |
| Authentication         | authoritative | enforces   |
| TLS termination        | mints configs | terminates |
| Per-request hot path   | never         | always     |

The conceptual separation matters even for the single-node MVP. If the
Edge ever needs to look up a database row to decide where to forward a
request, the system will not scale and will not survive a database
hiccup. The control plane's job is to push authoritative state into
the data plane so the data plane never has to ask.

## 4. Golden request flow

```
Public Client                  Edge                     Agent                Local
     |                           |                        |                     |
     |--- HTTPS request -------->|                        |                     |
     |                           |--- resolve tunnel      |                     |
     |                           |   (from cached state)  |                     |
     |                           |--- open stream -------------------------------->|
     |                           |                        |--- forward to local |
     |                           |                        |<-- response ---------|
     |<--------- HTTPS response --|<------- stream --------|                     |
     |                           |                        |                     |
```

Step-by-step:

1. Public client opens TLS to `<host>.tunnelproxy.dev`.
2. Edge terminates TLS, validates any required auth, and resolves the
   host to a tunnel identifier using **cached** routing state.
3. Edge opens (or reuses) a multiplexed stream on the agent's
   persistent tunnel.
4. Agent demultiplexes the stream, opens a TCP connection to the
   configured local service, and forwards bytes bidirectionally.
5. Agent streams the local response back through the tunnel.
6. Edge writes the response to the public client, enforcing bounded
   buffers and timeouts (INV-002, INV-005).

## 5. Rationale

Why a reverse tunnel rather than opening an inbound port on the
developer machine? Because developers sit behind NATs, corporate
firewalls, and dynamic IPs. Reverse tunnels let the agent be a normal
outbound TCP client, which works almost everywhere.

Why separate control plane from data plane? Because mixing them is the
single most common reason developer-tool platforms fall over under
load: every request becomes a database query. We commit now so the
code structure never lets that creep in (INV-007).

Why Rust? Because the data plane is exactly the kind of code where
memory safety, bounded buffers, and predictable latency matter, and
the ecosystem gives us strong async primitives and excellent
observability tools without dragging in a garbage collector.
