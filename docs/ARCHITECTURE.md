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
before Agent transport shutdown. Session 25 initially supported one HTTP/1.1
request per public TLS connection; Session 34 extends that boundary below.
HTTP/2, WebSocket/upgrade, CONNECT, automatic hostname allocation, and
public-client authentication remain excluded.

### 2.32 Bounded HTTP/1.1 keep-alive and per-request deadlines (Session 34)

HTTP/1.1 connection reuse is opt-in through a request cap whose default is one
and hard maximum is 1024. A connection owns its global and per-source-IP
admission permits until close. Each sequential request independently repeats
Host/SNI/absolute-authority validation, dynamic route resolution, request-rate
admission, header sanitization, body bounding, and tunnel stream creation. No
request is replayed after uncertain delivery.

The header-read deadline also bounds idle time between requests. A fresh
request deadline covers upstream response acquisition and the streamed
downstream response body. The last permitted response closes the connection;
all rejection, rate-limit, upstream-failure, and timeout paths also close so an
unread or ambiguous body is never followed by another request. On process
shutdown, Hyper stops accepting requests on established connections and
gracefully finishes active work before the existing drain deadline can abort
the task. Fixed-cardinality counters expose reused requests and request
timeouts without peer, hostname, TunnelId, or payload labels.

### 2.33 Bounded fair DATA scheduling (Session 35)

Each multiplexed Agent↔Edge writer admits DATA and END_STREAM frames through a
shared semaphore-backed bound. A permit follows a frame from producer wait,
through the channel and per-stream scheduler, until encoding completes, so
moving frames between internal structures cannot multiply the configured
memory allowance.

The writer preserves FIFO order within each stream and serves active streams
round-robin. END_STREAM uses the same per-stream queue as DATA and therefore
cannot overtake earlier payload. Lifecycle and heartbeat frames retain
priority, but a continuously ready control producer is limited to eight frames
before one queued DATA frame is served. The scheduler is process-local and
frame-based: it adds no wire fields, ALPN change, peer credit negotiation,
weighted byte fairness, or distributed flow control.

### 2.34 Multiplexed transport fairness telemetry (Session 36)

Agent and Edge each aggregate process-local multiplexed transport telemetry in
shared atomics. DATA frames and payload bytes are counted by the fixed
`sent`/`received` direction set. RAII guards measure current and peak active
streams, while the semaphore-backed queue holds a second RAII guard from
admission through encoding to expose current and peak DATA pipeline depth.
The first failed immediate permit attempt increments one admission-wait event;
inbound queue overflow/oversize resets and control-burst DATA yields have
separate monotonic counters.

The existing loopback operations endpoints render these values without
acquiring session locks, querying storage, or performing network I/O. Metrics
contain no AgentId, TunnelId, StreamId, session ID, address, hostname,
certificate, secret, or payload label. Counters reset on process restart. No
Tunnel Protocol v2 frame, payload, handshake, or ALPN value changes; remote
write, durable history, alerting, peer credits, and weighted byte scheduling
remain outside this slice.

### 2.35 Live transport capacity and operator interpretation (Session 37)

Each running multiplex session registers its configured DATA writer capacity
with the process aggregate before creating its bounded queue. An RAII guard
removes exactly that capacity only after the session writer and its admitted
items have drained. Agent therefore reports zero capacity while offline and
its configured capacity while connected; Edge reports the sum across live
sessions. Snapshot ordering preserves the observable relationship that current
pipeline occupancy cannot exceed live aggregate capacity.

The Agent and Edge loopback exporters expose the aggregate as
`*_transport_data_pipeline_capacity_frames` without a session or identity
label. Operators calculate utilization against current pipeline frames and
correlate waits, resets, fairness yields, readiness, and reconnects. The
operator runbook owns scrape topology, retention, baseline queries, and the
decision threshold for a future flow-control proposal. TunnelProxy still does
not perform remote write, durable metric storage, dashboard rendering, or
paging, and Tunnel Protocol v2 is unchanged.

### 2.36 Bounded nonblocking process logging (Session 38)

Synchronous stderr remains the compatibility default. When explicitly
enabled, tracing formats each complete event into a 16 KiB-bounded buffer and
uses `try_send` to admit it to one process-wide FIFO of at most 1024 events.
One dedicated OS thread owns stderr writes. Full queues drop the newest event;
oversized events are discarded whole so JSON Lines cannot be truncated.

A process-lifetime guard stops new admission and waits only for the configured
bounded drain deadline. A blocked stderr writer is detached after that
deadline rather than holding process shutdown. Agent, Edge, and Control Plane
operations endpoints read shared atomics for enabled capacity, accepted,
dropped, oversized, and write-failure events. No request/session labels,
storage query, remote write, file rotation, or network backend is introduced.
Together with Session 37's operator-owned collection/retention runbook, this
resolves DEBT-010 without coupling external observability I/O to data routing.

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
Agent and Control Plane exporters are supplied by Sessions 29–30. Tunnel Protocol v2 and the
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

The compatibility sink is deliberately local and synchronous by default.
Session 38 adds an optional bounded nonblocking worker and loss telemetry;
file rotation plus durable/remote shipping remain operator/backend work.
Protocol and snapshot schemas are unchanged.

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
process-local and reset on restart. Control Plane metrics arrive in Session 30;
Session 37 documents external collection and Session 38 exposes optional
nonblocking-sink loss. Protocol and snapshot formats are unchanged.

### 2.28 Bounded Control Plane operations endpoint (Session 30)

The runnable Control Plane may bind a separate loopback-only HTTP/1.1
operations listener. A shared process-local atomic telemetry handle is updated
by the SQLite refresh supervisor, snapshot distribution service, optional
enrollment service, and reconciliation loop. Scraping never performs SQLite or
network I/O.

`/healthz` reports operations-listener liveness. `/readyz` is true only after
the durable authority is initialized and required snapshot and optional
enrollment supervisors are running outside shutdown drain. `/metrics` reports
snapshot version, fixed refresh/enrollment outcomes, snapshot and enrollment
admission, reconciliation, and operations admission. Labels are fixed and no
identity, address, database path, fingerprint, digest, secret, certificate,
key, or payload is emitted.

Operations configuration is validated before storage is opened. A later bind
failure drops already-bound child listeners. Shutdown removes readiness first,
stops snapshot distribution and enrollment next, then drains operations last.
The endpoint is disabled by default and cannot bind a non-loopback address.
Metrics reset on restart; durable storage, remote write, public/authenticated
access, dashboards, and alerts remain out of scope.

### 2.29 Durable HTTPS route catalog (Session 31)

The Control Plane owns a separate SQLite catalog mapping one canonical exact
`PublicHostname` to one durable `TunnelId` and an enabled/disabled status. The
shared hostname type lowercases ASCII DNS names, removes one terminal dot, and
rejects IP literals, ports, wildcards, invalid labels, and oversized names, so
the operator catalog and Edge ingress use the same identity rules.

The catalog starts at non-zero version 1 and holds at most 64 routes. Upsert
and removal take an immediate SQLite transaction, change the record and
monotonic version atomically, and do not advance the version for an identical
upsert or absent removal. Reads validate every stored field, fail closed on
corruption or overflow, and return routes sorted by hostname. The catalog
coexists with the authorization snapshot schema without modifying its wire or
storage contract.

Session 31 provides local operator CLI administration and leaves distribution
to the next independent protocol described below. It does not alter the
authorization snapshot or Tunnel Protocol v2.

### 2.30 Authenticated HTTPS route distribution (Session 32)

The Control Plane exposes an opt-in route listener with mutual TLS and the
dedicated `tunnelproxy-https-routes/1` ALPN. A strict `TPR1` protocol carries a
subscription version and complete canonical catalogs bounded to 64 KiB and 64
records. The route service owns its own connection semaphore and I/O deadline;
it neither extends the authorization snapshot nor shares the Agent data-plane
wire format.

Edge must complete online route bootstrap before it binds dynamic HTTPS
ingress. Each higher catalog version replaces the complete immutable in-memory
view atomically. Host lookup reads only that view and the live tunnel router;
it performs no database or Control Plane operation on the request path.
Duplicate versions are idempotent, while stale and same-version-conflicting
content fail closed.

After the authenticated stream disconnects, Edge marks the catalog stale and
continues serving it for a configured maximum age. At expiry it retains the
bytes only for version-aware recovery but exposes zero routable hosts and
reports not-ready. Reauthentication restores live state, including an
up-to-date response with no redundant catalog. Route state is intentionally
not persisted to disk, so a cold start cannot serve unauthenticated old intent.

Static `--https-host` routing remains supported and is mutually exclusive with
`--https-route-server`. Automatic allocation, DNS/TLS automation, custom
domains, signed access, HTTP/2, and multi-edge coordination remain separate.

### 2.31 Atomic HTTPS route TLS generation reload (Session 33)

The route server and Edge route client each expose a dedicated opt-in digest
manifest and supervised reload runtime. They reuse the generic atomic TLS
generation engine but inject `tunnelproxy-https-routes/1` when building every
candidate, so snapshot and route protocol configuration cannot cross ALPN
boundaries. Manifests require exact file sets, SHA-256 digests, and strictly
increasing non-zero generations.

Candidate bytes are fully loaded, verified, parsed, and validated before one
shared configuration pointer is replaced. A malformed, incomplete, stale, or
cryptographically invalid generation is observable as reload failure while the
last-known-good generation remains active. Certificate expiry without a valid
replacement terminates the owning supervisor. Existing TLS sessions retain
their negotiated generation; new connections and reconnects use the latest
published generation. Route catalog versions and TLS generations remain
independent domains.

### 2.37 Durable managed hostname lifecycle (Session 39)

Managed hostname provenance is Control Plane storage metadata, not Edge route
state. A separate `managed_https_hostnames` table maps one durable TunnelId to
one exact enabled route and its canonical base domain. Existing route rows have
no mapping and therefore remain operator-owned after migration. A foreign key
ties managed ownership to the route while repository validation also checks
canonical values, exact TunnelId/status agreement, and the `tp-<32 hex>` label
shape on every open and mutation.

Allocation takes an immediate SQLite transaction, returns an existing mapping
for the same tunnel/base-domain pair, or checks capacity and the next catalog
version before requesting randomness. It encodes 16 OS-random bytes into a
lowercase DNS label and checks the complete hostname against all routes,
retrying at most 16 collisions. The enabled route, ownership metadata, and one
catalog-version increment commit together. Entropy, collision, capacity,
version, storage, or validation failure rolls the transaction back. Release
deletes metadata first, then its exact route, and advances the catalog once;
an absent mapping is an idempotent no-op. Generic route mutation rejects names
with managed ownership.

The existing `TPR1` full-catalog stream needs no new field: Edge only requires
the exact hostname, TunnelId, and enabled status for request routing. The
Control Plane refresh loop therefore distributes allocation and release like
any other catalog update, and Edge applies or removes the exact route without
restart or hot-path storage access. Wildcard DNS/TLS provisioning,
rename/rotation, custom domains, and multi-edge ownership remain separate
control-plane concerns.

### 2.38 Authenticated Agent hostname lifecycle (Session 40)

The opt-in Agent hostname listener is separate from Tunnel Protocol v2,
snapshot distribution, enrollment, and route distribution. It negotiates only
`tunnelproxy-hostname/1`, requires an Agent client certificate signed by the
configured Agent CA, and handles exactly one bounded `TPH1` allocate or release
request per TLS connection. TCP connect, TLS handshake, protocol I/O, message
size, active clients, and child tasks all have explicit bounds.

TLS identity is necessary but not sufficient. The leaf fingerprint plus the
requested AgentId and TunnelId must authorize successfully against the current
in-memory snapshot, including enabled tunnel state. The Agent never chooses the
base domain: server configuration owns one canonical suffix, preventing a
valid credential from requesting arbitrary namespaces.

An authorized mutation enters the route authority's serialization gate,
commits through the Session 39 immediate SQLite transaction, reloads the full
durable catalog, and publishes it to route subscribers before success is sent
to the Agent. Therefore a success response never precedes the corresponding
live Edge-distribution state. Repeated allocation and absent release remain
idempotent. The runtime supervises this listener with the other Control Plane
children and exposes only fixed-cardinality aggregate metrics.

### 2.39 Agent hostname service TLS generations (Session 41)

The hostname listener reuses the shared protocol-server reload engine but owns
an independent manifest and fixed hostname ALPN. One generation binds exactly
three files by SHA-256 digest: server certificate, server private key, and
Agent client CA. The entire file set is loaded and parsed before a candidate
rustls server configuration is published through the shared reloadable pointer.

Generation numbers are non-zero and strictly increasing. Missing, unknown,
partial, stale, same-generation-conflicting, digest-mismatched, malformed, or
cryptographically incompatible candidates mark reload health failed without
replacing the active configuration. Every accepted TCP connection snapshots
the current immutable configuration before TLS negotiation, so new handshakes
observe an applied generation while an in-flight one-request connection keeps
the generation it negotiated.

The hostname reloader is supervised alongside snapshot and route reloaders.
Expiry of the last-known-good server leaf is terminal: Control Plane begins its
ordered shutdown and releases all listeners. Reload events contain generation
and fixed health only. Hostname cert/key paths may be separate from the
snapshot identity; static Session 40 startup remains compatible when no
hostname manifest is configured.

### 2.40 Managed HTTP Agent orchestration (Session 42)

`tunnelproxy-agent http <port>` is process composition, not a new wire
protocol. The command maps the non-zero port to `127.0.0.1:<port>`, requires
complete Edge and hostname-service mTLS inputs, and constructs the normal
Agent runtime, enrollment/reload supervisors, and optional operations listener
before requesting any durable mutation.

Startup then performs one authenticated hostname allocation using the same
AgentId, TunnelId, and client credential as Protocol v2 registration. The
Session 40 response establishes durable commit and in-process catalog
publication; the Agent runtime then owns connection and reconnect. A bounded,
shutdown-aware readiness observer prints the public-to-local mapping once the
runtime status first becomes `Connected`. It does not probe DNS, public TLS,
Edge catalog convergence, or the local HTTP application.

Allocation and transport lifetimes deliberately differ. The hostname remains
durable when the command is cancelled, reconnecting, offline, or terminated by
a runtime error. Edge keeps the route intent but fails closed without a live
tunnel. Re-running allocation returns the same hostname and does not advance
the catalog; only explicit release removes it. This preserves URL stability
and avoids destructive rollback after an ambiguous client-side failure.

### 2.41 Canonical Agent CLI and local config (Session 43)

The production Agent CLI driver now lives in the Agent library. Two minimal
Tokio wrappers call it with their executable name: `tunnelproxy-agent` retains
the historical contract, while `tunnelproxy` is the canonical developer
surface. Argument parsing, structured-log target, stdout, exit classes,
supervision, and managed HTTP behavior therefore share one implementation.

Local config v1 is a strict bounded startup input, not Control Plane state. It
contains Edge and hostname-service addresses/trust names plus durable IDs and
credential file paths. It contains no inline PEM, key, or token bytes. Reads
stop after 64 KiB; unknown/duplicate fields, unsupported versions, invalid
addresses/IDs, and empty paths fail before socket creation or allocation.
Relative credential paths resolve from the config directory. Explicit CLI
values override config, and config overrides process defaults.

Config selection is deterministic: explicit flag, environment path, then one
platform default. `config validate` loads both TLS client configurations and a
default Agent runtime without opening a network connection. The local host and
filesystem remain a trust boundary because changing the file can select other
trust roots and credential paths. Account provisioning, key custody, DNS, and
public-certificate automation remain outside this local representation.

### 2.42 Bounded HTTP/2 public ingress (Session 44)

HTTP/2 is an explicit public HTTPS policy, not a replacement transport. The
default TLS generation still advertises only `http/1.1`; enabling HTTP/2 makes
every initial and reloaded generation advertise `h2` first with HTTP/1.1
fallback. A missing ALPN retains the compatible HTTP/1.1 path, while any other
negotiated protocol fails before request parsing.

After TLS, Edge selects a Hyper HTTP/1.1 or HTTP/2 connection driver around one
shared request service. HTTP/2 `:authority`, an optional Host field, and TLS SNI
must canonicalize to the same exact hostname. Header count/list size, request
body, request deadline, global/per-IP rate admission, cached route lookup, and
Tunnel Protocol stream admission are repeated independently for every stream.
Ordinary requests reject CONNECT and upgrade semantics unless the independent
Session 47 classic CONNECT policy is enabled.

HTTP/2 connection state is explicitly bounded: concurrent and pending/local
reset streams have the same hard cap, send buffers and initial flow-control
windows are capped, PING keepalive has finite interval/timeout, and connection
admission remains global plus per source IP. Accepted requests are rewritten to
origin-form HTTP/1.1 with canonical forwarding headers before entering the
existing Edge-to-Agent byte stream, so Tunnel Protocol v2 and local services do
not change.

One rejected, oversized, or timed-out stream returns its own response without
closing healthy siblings. Shutdown stops listener admission, initiates Hyper's
HTTP/2 graceful shutdown/GOAWAY, and lets active response bodies finish within
the existing HTTPS drain deadline before task abort. Status and operations
metrics expose only protocol counters and active/peak stream cardinality.
Hostnames, peer addresses, durable IDs, and payload data are not labels.

### 2.43 Bounded HTTP/1.1 WebSocket upgrade ingress (Session 45)

WebSocket is an explicit public HTTPS policy and remains disabled by default.
It applies only to HTTP/1.1 GET requests; HTTP/2 extended CONNECT remains
rejected and route-bound HTTP/1.1 CONNECT requires the separate Session 46
policy. Before opening a tunnel stream, Edge requires
`Connection: Upgrade`, exact `Upgrade: websocket`, version 13, one canonical
Base64 key representing 16 bytes, no request body, and no extension offer. The
normal exact Host/SNI/route checks and global/per-IP request-rate admission run
unchanged. Subprotocol offers are bounded by the existing header limits and
must be unique HTTP tokens.

Edge strips hop-by-hop and client-supplied forwarding fields, writes canonical
trusted forwarding metadata, and reconstructs only the validated WebSocket
handshake for the local HTTP/1.1 service. A local `101` is accepted only when
its Connection/Upgrade tokens and RFC accept digest match and any selected
subprotocol was offered by the client. Local extension negotiation is rejected.
Non-`101` local responses remain ordinary bounded HTTP responses; malformed
`101` responses become `502` and never expose an upgraded public stream.

After both Hyper upgrade futures resolve, Edge relays bytes opaquely through
the existing cached TunnelId and Tunnel Protocol v2 logical stream. It does not
parse or log WebSocket frames. A dedicated global session semaphore cannot
exceed HTTPS connection capacity, and one fixed-size buffer per direction plus
an activity-based idle deadline bounds relay resources. One HTTP/1.1 connection
task owns both Hyper drivers, upgrade futures, route completion, semaphore
permit, idle timer, and relay, preventing detached work after timeout.

Shutdown stops new HTTPS admission and lets an upgraded session close within
the normal HTTPS drain window. The outer connection task is force-aborted when
that deadline expires, which drops the relay, local stream, route, and permit
together. Fixed-cardinality metrics expose accepted/rejected upgrades,
active/peak sessions, and idle timeouts without host, peer, ID, or payload
labels.

### 2.44 Bounded route-bound HTTP/1.1 CONNECT ingress (Session 46)

CONNECT is a separate default-off HTTP/1.1 policy. It is not a general forward
proxy: the authority hostname must resolve through the existing exact route
cache, its port must equal the operator-configured CONNECT authority port, and
the Host authority and TLS SNI must name the same hostname and port. Schemes,
paths, request bodies, transfer encoding, and upgrade headers fail closed
before a tunnel stream opens. Classic HTTP/2 CONNECT requires the independent
Session 47 opt-in. Existing header bounds and
process-local global/per-IP request-rate admission still apply.

After route and admission checks, Edge opens the existing Tunnel Protocol v2
logical stream to the route's fixed Agent local target and returns `200 OK`.
It does not forward the CONNECT request to the local service and does not use
the client authority to select any arbitrary destination. The upgraded public
TLS stream and the route byte stream are then relayed opaquely with one fixed
buffer per direction. Tunnel Protocol v2 and Agent configuration are unchanged.

An independent session semaphore cannot exceed HTTPS connection capacity. An
activity-based idle deadline covers reads, writes, and half-close propagation.
The HTTP/1.1 connection task owns the upgrade future, relay, route completion,
permit, and timer; graceful shutdown may drain it only within the existing
HTTPS deadline, after which one task abort releases all resources. Metrics
expose accepted/rejected, active/peak, and idle-timeout totals without
authority, hostname, peer, durable ID, or payload labels.

### 2.45 Bounded route-bound classic HTTP/2 CONNECT ingress (Session 47)

Classic HTTP/2 CONNECT is another explicit default-off policy. Enabling it
requires the bounded HTTP/2 listener but does not implicitly enable HTTP/1.1
CONNECT, and the older HTTP/1.1 flag does not broaden itself to h2. Both
protocols reuse one `ConnectIngressConfig`: exact operator-selected authority
port, finite activity idle deadline, and one shared session semaphore, so
enabling both cannot double the configured CONNECT resource ceiling.

The request must use classic CONNECT authority form. Its canonical authority
hostname, optional Host field, and TLS SNI must agree with one enabled cached
route, while schemes, paths, non-zero Content-Length, transfer encoding,
upgrade headers, and RFC 8441 `:protocol` fail closed. Normal header and
request-rate admission runs before route or stream creation. Edge never dials
the authority and never forwards a CONNECT request; the authority selects only
the existing route whose TunnelId owns one fixed Agent local target.

Hyper 1.6 represents successful classic h2 CONNECT as `OnUpgrade` on both
sides, backed by HTTP/2 DATA frames and flow control. Edge returns an empty
successful response, awaits the upgraded stream under the request deadline,
and reuses the fixed-buffer opaque relay used by HTTP/1.1 CONNECT. Half-close
maps to h2 end-of-stream, resets affect only the selected logical stream, and
Tunnel Protocol v2 remains unchanged.

Each HTTP/2 connection owns a bounded relay channel and `JoinSet` sized by the
shared CONNECT limit. The connection supervisor drives Hyper, starts accepted
relays, observes their completion, sends graceful GOAWAY on shutdown, and owns
all remaining relay tasks until the existing HTTPS drain deadline force-aborts
the connection task. RAII retains both aggregate and HTTP/2-specific
current/peak session gauges; fixed-cardinality counters expose accepted,
rejected, and idle-timeout outcomes without identity or payload labels.

### 2.46 Bounded route-bound RFC 8441 WebSocket ingress (Session 48)

RFC 8441 WebSocket is independently default-off and requires bounded HTTP/2.
Only that policy causes Hyper to advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`;
HTTP/1.1 WebSocket and classic HTTP/2 CONNECT retain their independent flags.
HTTP/1.1 and HTTP/2 WebSockets share one session semaphore and activity idle
deadline, so enabling both cannot double the configured WebSocket ceiling.

Edge accepts only HTTP/2 extended CONNECT with `:protocol = websocket`, HTTPS
scheme, an origin-form path, exact authority/optional-Host/TLS-SNI agreement,
WebSocket version 13, no body framing, no connection-specific fields, and no
extension offer. Cached route and request-rate admission still run before
tunnel creation. Other extended protocols fail closed and the authority never
becomes a dial target.

RFC 8441 omits the HTTP/1.1 key/accept exchange. Edge therefore generates a
fresh 16-byte key, constructs a sanitized local HTTP/1.1 GET Upgrade request,
and requires the local service to return a valid `101`, matching accept digest,
no extension, and at most one offered subprotocol. Edge then returns HTTP/2
`200` with only the selected subprotocol and relays the two upgraded byte
streams without parsing WebSocket frames.

The Session 47 per-connection relay supervisor also owns RFC 8441 streams.
END_STREAM, reset isolation, activity idle expiry, graceful GOAWAY, and the
existing forced drain deadline remain bounded. Aggregate WebSocket telemetry is
retained and HTTP/2-specific accepted/rejected/current/peak/idle metrics add no
hostname, peer, subprotocol, or payload labels. Agent behavior and Tunnel
Protocol v2 are unchanged.

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
