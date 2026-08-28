# TunnelProxy — Architecture Decision Records

> Each decision is recorded as an ADR. Do not delete old ADRs; supersede
> them with a new one that links back.

---

## ADR-001 — Rust is the primary networking and backend language

**Status:** Accepted (Session 01).

**Context:** TunnelProxy's data plane is a latency-sensitive, security-
critical network service that must enforce bounded buffers and
predictable behaviour under load.

**Decision:** We write the agent, edge, control plane, and protocol
codecs in Rust.

**Consequences:**

- Memory safety without a garbage collector on the hot path.
- Strong async ecosystem (Tokio).
- Predictable binary size and cold-start latency.
- Higher contributor bar than Go or Node; we accept this.

---

## ADR-002 — Tokio is the intended asynchronous runtime

**Status:** Accepted (Session 01).

**Context:** TunnelProxy's networking code will be heavily I/O-bound
and needs a mature async runtime.

**Decision:** Tokio is the intended runtime for Session 02 and
onwards. It is **not yet added as a dependency** in Session 01
because no networking code exists yet; adding it would be premature.

**Consequences:**

- Future crates depending on Tokio must do so explicitly per-crate.
- No code in Session 01 uses Tokio. Do not pretend otherwise.
- Any non-Tokio runtime choice requires a new ADR.

---

## ADR-003 — Cargo workspace defines component boundaries

**Status:** Accepted (Session 01).

**Context:** The product has five clear components (common, protocol,
agent, edge, control plane). Collapsing them into one crate would let
responsibilities blur.

**Decision:** Each component is a workspace member crate with its own
`Cargo.toml`. Cross-crate dependencies are declared explicitly.

**Consequences:**

- Cycles between components become structurally hard to introduce.
- Per-crate documentation (`crates/<name>/README.md`) is required.
- Tests can be run per crate when needed.

---

## ADR-004 — Control Plane and Data Plane concerns are conceptually separated

**Status:** Accepted (Session 01).

**Context:** Mixing control-plane state into the data-plane hot path
is the canonical scaling mistake for developer-tool platforms.

**Decision:** The control plane owns durable state and pushes
authoritative routing state to the data plane. Per-request routing on
the edge never queries the control plane (INV-007).

**Consequences:**

- Edge must accept pushed / cached routing state, not pull it.
- The control plane may go down briefly without immediately breaking
  live tunnels, by design.
- The MVP may be a single process, but it must not structurally
  require per-request database access.

---

## ADR-005 — Start with a simple tunnel transport before investigating HTTP/2 or QUIC

**Status:** Accepted (Session 01).

**Context:** HTTP/2 and QUIC add real complexity (HPACK, streams,
connection migration, congestion control). Choosing one before we have
a working TCP tunnel would optimise for the wrong thing.

**Decision:** Session 02 and the MVP will use a simple, length-
framed TCP transport. HTTP/2 and QUIC are explicit future options to
be re-evaluated against real measurements.

**Consequences:**

- MVP does not need an HTTP/2 or QUIC stack.
- The protocol crate is deliberately minimal until we have empirical
  reasons to grow it.
- Switching transports later is possible because the protocol crate
  is the single boundary.

---

## ADR-006 — Optimise first for correctness, bounded resource usage, and observability rather than premature performance claims

**Status:** Accepted (Session 01).

**Context:** It is tempting to publish benchmarks early. Early
benchmarks on a non-existent data plane would mislead more than
inform.

**Decision:** Until the MVP ships, we optimise for:

1. Correctness — invariant violations are bugs, not style issues.
2. Bounded resource usage — every buffer has a limit (INV-002).
3. Observability — every cross-cutting operation is structured and
   traceable.

Performance claims are deferred until we have a measurable data
plane.

**Consequences:**

- The README does not claim performance numbers.
- Tech debt entries that trade correctness for speed are not
  accepted.

---

## ADR-007 — Length-prefixed binary framing with fixed header for Tunnel Protocol v1

**Status:** Accepted (Session 05).

**Context:** TCP provides an ordered byte stream without message boundaries.
Before any Agent ↔ Edge tunnel runtime can exist, we need a deterministic
way to reconstruct application messages from that stream. We also need to
enforce bounded resource usage (INV-002) before reading any payload.

**Decision:** Tunnel Protocol v1 uses a fixed 16-byte binary header followed
by a bounded payload:

```
Offset  Size  Field           Type
0       4     Magic           [0x54, 0x50, 0x58, 0x31] ("TPX1")
4       1     Version         u8  (1)
5       1     Frame Type      u8
6       2     Flags           u16 (big-endian; must be 0 in v1)
8       4     Stream ID       u32 (big-endian)
12      4     Payload Length  u32 (big-endian; max 64 KiB)
16      N     Payload         [u8; N]
```

All multi-byte integers use big-endian / network byte order.

**Consequences:**

- Fixed header size (16 bytes) is known at compile time — no parsing
  overhead beyond the initial header read.
- Length-prefix approach is deterministic: the decoder always knows
  how many payload bytes to expect before allocating.
- Big-endian encoding is architecture-neutral and matches the network
  standard used by TCP/IP.
- Opaque payloads: no UTF-8 assumption, no schema coupling, no
  serialization format commitment.
- Stream ID field is present and validated (scope rules) so the
  multiplexing runtime can be layered on top without wire-format changes.
- Maximum payload (64 KiB) is enforced before allocation, making it
  impossible for a malicious peer to exhaust memory by announcing a
  large length.
- Explicit version rejection prevents silent wire-format confusion
  between incompatible peers.
- Switching to HTTP/2 or QUIC later remains possible; the protocol
  crate boundary is the single point of change.

---

## ADR-008 — Ephemeral process-local TransportSessionId with strict handshake sequencing

**Status:** Accepted (Session 06).

**Context:** Before the Agent ↔ Edge transport can be established, both peers need a shared
notion of "which session is this?" for observability and debugging. We also need
to validate that the Agent is who it claims to be (no auth yet) and that the
handshake order is correct (no frame substitution or replay).

**Decision:** Edge allocates a monotonically increasing `TransportSessionId` (u64)
per accepted TCP connection using a process-local `AtomicU64`. The ID is sent to the
Agent in a REGISTERED frame. Zero is reserved as invalid. The handshake is strictly
sequenced: HELLO must be first, REGISTER must be second. Any deviation triggers an
ERROR frame and immediate connection close.

**Consequences:**

- The ID is ephemeral: it exists for the TCP connection's lifetime only.
- The ID is process-local: it has no meaning outside the Edge process.
- The ID is not a durable identity: it is not a `TunnelId`, `AgentId`, or `UserId`.
- Wraparound after 2^64 allocations returns `None` (safe failure rather than a
  silent zero-ID session).
- Strict sequencing prevents replay or substitution attacks during the handshake.
- No database or external state is required for the ID itself.
- Future sessions may layer additional authentication (TLS client certs, shared secrets)
  on top of this foundation without changing the ID semantics.

---

## ADR-009 — Edge-initiated heartbeat with one outstanding sequence

**Status:** Accepted (Session 07).

**Context:** After Session 06, Edge retained a semaphore permit for every
established Agent TCP connection but could not distinguish an idle healthy
Agent from a crashed process or partitioned network. Edge is the authority that
owns live routing/session capacity, so it must be able to make this decision
without depending on Agent timers.

**Decision:** Edge initiates heartbeat after a configurable interval. Every
PING contains an 8-byte big-endian non-zero sequence. Agent returns a PONG with
the identical sequence before a configurable deadline. Only one PING may be
outstanding. Any timeout or invalid heartbeat transition closes that session.

**Consequences:**

- Edge has a deterministic upper bound for retaining a silent Agent session.
- The semaphore permit is released by the same task/RAII path used by all other
  session exits.
- PING/PONG direction is fixed in v1: Agent-initiated PING is rejected.
- Heartbeat does not implement reconnect; Agent recovery remains a separate
  state machine.
- Sequential reader/writer ownership remains sufficient before multiplexing.
  A future multiplexed runtime will replace it with one reader task and one
  bounded writer queue without changing the heartbeat wire payload.

---

## ADR-010 — One active stream with directional half-close before multiplexing

**Status:** Accepted (Session 08).

**Context:** The framing, handshake, and heartbeat layers were tested, but no
application byte could cross the persistent Agent transport. Implementing a
full concurrent multiplexer at the same time would combine socket ownership,
fairness, capacity, flow control, routing, and lifecycle risk in one change.

**Decision:** Activate the already-reserved Protocol v1 stream frame numbers
for exactly one active stream. Edge allocates the stream ID and sends empty
OPEN_STREAM; Agent acknowledges with the same frame after its bounded local
connect succeeds. DATA is binary and bounded, END_STREAM closes only the
sender's direction, and RESET_STREAM aborts one stream with a typed code. One
task owns each framed reader/writer state machine, and the Agent transport may
serve later streams sequentially.

**Consequences:**

- The project now proves a complete raw-TCP Edge → Agent → local-service path.
- Half-close and heartbeat behavior are exercised together before concurrency.
- Fixed buffers, direct writes, and explicit open/connect/idle deadlines keep
  the vertical slice bounded.
- A second concurrent ingress is rejected; this is tracked as DEBT-013.
- The loopback ingress is not the public product surface and provides no HTTP,
  TLS, hostname routing, authentication, or durable registration.
- Session 09 can replace the single active state with a bounded stream map and
  writer queue without changing Session 08 payload semantics.

---

## ADR-011 — One reader, one writer actor, bounded per-stream dispatch

**Status:** Accepted (Session 09).

**Context:** Concurrent logical streams must not read or write the same framed
TCP transport independently. Unbounded fan-in queues would turn a slow peer or
local service into process-wide memory growth, while lifecycle priority must
not reorder END_STREAM ahead of DATA from the same direction.

**Decision:** Each established transport has one decoder owner and one writer
actor. The reader dispatches to bounded per-stream queues. Heartbeat and reset
frames use a priority queue; DATA and END_STREAM share FIFO ordering. Edge keeps
an ephemeral registry keyed only by live `TransportSessionId`, and routing
copies the session sender before releasing the registry lock.

**Consequences:** Concurrent streams and Agent sessions are failure-isolated,
all application queues have explicit capacity, and stale session IDs fail
closed. This is cooperative bounded backpressure, not a credit-based flow
control protocol or strict weighted scheduler.

---

## ADR-012 — Ephemeral raw routes stop accept before draining streams

**Status:** Accepted (Session 10).

**Context:** A bound ingress listener must be removable without dropping
already-routed client traffic. Counting accepted sockets is insufficient
because Edge transfers socket ownership into per-stream tasks, and a stale
`TransportSessionId` must never silently target a replacement Agent.

**Decision:** `open_stream_tracked` returns a completion receiver for the real
stream task. A raw route holds one semaphore permit per accepted connection
until that receiver completes. Remove first closes the listener and enters
`Draining`; removal from the registry happens only after all permits return.
Agent session snapshots transition targeted routes to `TargetDisconnected` and
the route manager never retargets an existing route automatically.

**Consequences:** Active streams survive route removal, drain timeout is
observable without forced traffic loss, and stale sessions fail closed. Routes
remain loopback-only and ephemeral; durable tunnel routing is separate work
tracked by DEBT-015.

---

## ADR-013 — Reconnect creates a fresh ephemeral session and route generation

**Status:** Accepted (Session 13).

**Context:** The runnable tunnel should recover from transient Agent or Edge
loss, but Protocol v1 has no authenticated durable Agent/tunnel identity and an
old `TransportSessionId` must never become valid for a replacement connection.

**Decision:** Agent retries only transient transport failures with cancellable,
bounded exponential backoff. Every successful handshake creates a fresh
ephemeral session. Edge removes the raw route targeting a disconnected session,
waits for its listener to be released, and creates a new route generation on
the same configured loopback address after a replacement session appears.
Protocol failures are terminal and interrupted streams are not replayed.

**Consequences:** Local development tunnels recover automatically without
conflating transport and durable identity. There is a deliberate availability
gap while no Agent is connected, active connections fail with their old
session, and durable routing/authentication remain separate work under
DEBT-015.

---

## ADR-014 — Mutual TLS precedes unchanged Protocol v1 registration

**Status:** Accepted (Session 14).

**Context:** Agent traffic must be encrypted and an untrusted peer must never
become routable. Adding a token to the empty REGISTER payload would change the
wire contract and require Protocol v2, while certificate issuance and durable
Agent/tunnel identity do not yet exist.

**Decision:** Wrap the multiplexed Agent byte stream in rustls mutual TLS before
HELLO. Agent verifies the configured Edge CA and DNS name; Edge requires a
client certificate signed by its configured Agent CA. Both configure ALPN
`tunnelproxy/1`. Plaintext is valid only for loopback development. Edge holds
the bounded session permit throughout TLS negotiation, which has its own
deadline. Certificate/authentication errors are terminal; transient transport
failure and timeout remain reconnectable.

**Consequences:** Protocol v1 frames and the empty REGISTER payload remain
unchanged, so INV-004 requires no version bump. mTLS proves certificate
possession but does not assign durable `AgentId`/`TunnelId` or tunnel
authorization. Certificate lifecycle remains static and is tracked by
DEBT-017.

---

## ADR-015 — Protocol v2 binds authenticated certificates to durable tunnel intent

**Status:** Accepted (Session 15).

**Context:** A CA-valid client certificate proves possession but does not say
which durable Agent or tunnel the peer may claim. Routing by ephemeral
`TransportSessionId` also forces the raw listener to be recreated after every
reconnect and cannot express stable tunnel intent.

**Decision:** Protocol version 2 and ALPN `tunnelproxy/2` replace the empty
REGISTER payload with two bounded length-prefixed identifiers: `AgentId` and
`TunnelId`. Edge hashes the authenticated leaf certificate with SHA-256 and
authorizes the exact certificate/Agent/tunnel tuple against an immutable
control-plane snapshot before sending REGISTERED. One live session may claim a
TunnelId; duplicate claims fail closed. Edge maintains an in-memory
`TunnelId -> TransportSessionId` map, and runnable raw ingress remains bound to
the durable TunnelId while the Agent is offline or reconnecting.

**Consequences:** Protocol v1 peers fail explicitly with `UnsupportedVersion`
and there is no silent downgrade. Reconnect creates a new transport session but
does not recreate the raw listener or change tunnel identity. Ingress routing
uses only cached Edge state, satisfying INV-007. Snapshot distribution,
persistence, certificate rotation/revocation, public ingress, and multi-edge
coordination remain future work.

---

## ADR-016 — Full versioned snapshots drive atomic live Edge revocation

**Status:** Accepted (Session 16).

**Context:** Session 15 authorizes durable tunnel intent from an immutable
startup snapshot. Edge must accept authorization changes without restart while
preventing stale updates, unbounded queues, storage lookups on ingress, and a
race where a handshake authorized by an older snapshot becomes routable after
revocation.

**Decision:** The authority publishes complete snapshots carrying a non-zero
monotonic `SnapshotVersion` over a bounded latest-value channel. Higher versions
replace all prior grants and may skip intermediate versions. Equal version and
equal content is idempotent; lower versions and equal-version conflicting
content are rejected. Edge revalidates the authenticated principal immediately
before publication. Route publication, stream enqueue, and snapshot
reconciliation share a gate that defines their ordering. Reconciliation first
removes every unauthorized durable and ephemeral mapping, then closes the
affected transport and active streams. Closing the publisher marks the source
stale but preserves the last cached complete snapshot.

**Consequences:** Add, enable, disable, remove, and reassignment take effect on
a running Edge without a protocol change, listener rebind, or per-ingress
storage query. Revocation is fail-closed rather than graceful for active
streams. The latest-value channel deliberately skips superseded snapshots.
Persistence, authenticated cross-process distribution, restart bootstrap,
certificate rotation, and multi-edge consistency remain separate work.

---

## ADR-017 — SQLite commits precede dedicated mTLS full-snapshot publication

**Status:** Accepted (Session 17).

**Context:** Session 16 has atomic in-memory authorization updates but cannot
recover authority after a Control Plane restart or bootstrap a separate Edge
process. Persistence must not leak into Edge ingress, publication must never
precede durable commit, and control-plane distribution must not alter or share
the Agent ↔ Edge Tunnel Protocol v2 channel.

**Decision:** Store only the latest complete snapshot in SQLite behind a
`SnapshotRepository` boundary. A single transaction replaces grants and writes
the non-zero version plus canonical SHA-256 digest; `synchronous = FULL` and WAL
are enabled. `PersistentSnapshotAuthority` runs repository calls on blocking
workers, serializes commits, and updates its bounded watch publisher only after
the repository succeeds. Cross-process distribution uses a separate framed
protocol with a 1 MiB ceiling over mandatory mutual TLS and ALPN
`tunnelproxy-snapshot/1`. Edge bootstraps with version zero, reconnects with its
last in-memory version, and retains cached authorization as `Stale` while the
service is unavailable.

**Consequences:** Control Plane restart preserves the latest authority and a
fresh Edge can receive it without a database query on the ingress hot path.
Commit failure cannot expose non-durable policy. Full snapshots make reconnect
and skipped intermediate versions simple, at the cost of a bounded whole-state
transfer. This does not provide an administrative mutation API, Edge disk cache,
certificate lifecycle, or multi-writer/multi-edge consensus.

---

## ADR-018 — Offline full-snapshot import feeds supervised runnable processes

**Status:** Accepted (Session 18).

**Context:** Session 17 provides persistent and authenticated library pieces but
no operator workflow or process owner. A production-shaped slice needs safe
initialization, live import pickup, explicit shutdown, and Edge CLI composition
without prematurely creating account/admin HTTP APIs or letting Edge bind with
no authenticated authority.

**Decision:** Operators import a complete, non-zero-version JSON manifest into
SQLite through a bounded command. The manifest denies unknown fields and is
converted into the same validated canonical domain snapshot before the existing
transaction commits. The Control Plane daemon refuses empty storage and polls
the repository at a bounded interval, skipping missed ticks; only newer durable
heads reach the live publisher. Edge snapshot mode authenticates and bootstraps
before binding any Agent/raw listener. A snapshot-aware supervisor owns both the
reconnecting client and Edge runtime. The CLI requires exactly one of plaintext
development, static certificate authorization, or dynamic snapshot
authorization.

**Consequences:** A real `serve|import` workflow now exercises persistence and
cross-process distribution, including Control Plane restart, without database
access on Edge ingress. Imports are complete replacements, so omission revokes.
A fresh dynamic Edge still requires an online Control Plane because no trusted
disk cache exists. General admin APIs, credential lifecycle, and multi-edge
coordination remain separate work.

---

## ADR-019 — Authenticated snapshot generations permit bounded stale cold start

**Status:** Accepted (Session 19).

**Context:** A running Edge can retain its in-memory authority through a Control
Plane outage, but a restarted Edge previously had no authority and could not
bind. Persisting policy must not add disk I/O to ingress, allow indefinite stale
grants, hide authentication failures, or publish an update that cannot survive
the next process crash.

**Decision:** Edge may opt into a local cache directory and a non-zero maximum
stale age. Authenticated online bootstrap is always attempted first. Only
connection availability and bounded timeout failures may fall back to disk;
TLS identity, ALPN, protocol, server rejection, and version conflicts remain
terminal. Cache records contain a versioned canonical snapshot, authentication
timestamp, format metadata, length, and SHA-256 integrity digest under a 1 MiB
payload ceiling. A new immutable generation is written, synchronized, and
renamed before the snapshot is published to memory; lower versions and
equal-version conflicting content are rejected. An offline Edge reports
`Stale`, reconnects immediately, and shuts down its listeners when the stale
deadline expires.

**Consequences:** A previously authenticated Edge can restart during a bounded
Control Plane outage without querying storage on ingress, and a reconnecting
server can atomically advance or revoke its cached policy. The digest detects
corruption but is not a cryptographic signature: the Edge host and cache
filesystem are trusted, and hostile local rollback requires future signed or
hardware-backed state. Cache use is explicit and the existing online-only API
remains available.

---

## ADR-020 — Digest-bound generations are the atomic TLS reload boundary

**Status:** Accepted (Session 20).

**Context:** Agent, Edge, and the snapshot service previously parsed TLS files
only at process start. Independently replacing a certificate, private key, CA,
or static certificate authorization can expose a mismatched intermediate state.
Reload must preserve the last valid configuration, avoid blocking Tokio, never
log credential material, and terminate rather than silently run after the
active identity expires.

**Decision:** Each opt-in reload group has one strict JSON manifest containing
a non-zero generation and the SHA-256 digest of every expected material file.
The loader bounds and reads the manifest plus exact file set on a blocking
worker, verifies all digests, builds a complete rustls candidate, validates the
leaf identity time range, then publishes one immutable `Arc` for subsequent
handshakes. Generations only increase; an identical current generation is
idempotent, while lower or conflicting generations fail closed. Candidate
failure marks health but retains last-known-good. Expiry of that active leaf is
terminal. Static Edge mode includes its authorized Agent leaf in the same
Agent-facing manifest and publishes a full local authorization snapshot before
activating the new TLS candidate so removed identities fail closed.

**Consequences:** Operators can rotate all currently implemented mTLS roles
without process restart, and concurrent handshakes never observe a partly built
rustls configuration. Existing negotiated TLS sessions are not generically
renegotiated; they adopt new material on reconnect. Static Edge authorization
does reconcile and close a session removed by local rotation, while dynamic
authorization continues to use Control Plane snapshots. The manifest is an
atomic commit marker, not a certificate issuer, key vault, signature, or defense
against a compromised local filesystem; those remain future work.

---

## ADR-021 — Agent-owned keys and transactional two-phase certificate rotation

**Status:** Accepted (Session 21).

**Context:** Session 20 can atomically load operator-provided credentials but
does not create them. Enrollment must not export Agent private keys, authorize a
certificate before durable state exists, revoke a working predecessor before
the replacement is loaded, or let retries mint inconsistent leaves.

**Decision:** Agent generates an ECDSA P-256 key and CSR locally and journals the
request before contacting a separate server-authenticated TLS service using
ALPN `tunnelproxy-enroll/1`. A random bootstrap token is stored hashed, expires,
and is bound to one Agent/Tunnel pair. Agent supplies the next random renewal
token; Control Plane stores only its hash. Issuance, bootstrap consumption,
credential metadata, and a full snapshot containing the new fingerprint commit
in one SQLite `IMMEDIATE` transaction. Agent validates the returned
certificate/key/fingerprint, publishes a Session 20 bundle, waits for the live
generation, then sends an authenticated activation. Activation removes the old
fingerprint in a later transaction. Request IDs make exact retries idempotent,
and authorization is preflighted before CA signing.

**Consequences:** Dynamic Edge can accept bootstrap and renewal without process
restart or private-key transport, and a crash at any protocol boundary can be
retried from durable state. There is a bounded two-fingerprint overlap until
activation. Static Edge mode is intentionally unsupported. Issuer key custody,
CA rollover, CRL/OCSP/emergency revocation, abandoned-overlap cleanup, hostile
local filesystem defense, and multi-writer consensus remain future boundaries.

---

## ADR-022 — Snapshot revocation and terminal tombstones reconcile credentials

**Status:** Accepted (Session 22).

**Context:** Session 21 overlaps old and new Agent fingerprints until explicit
activation. An Agent that disappears can leave the pending fingerprint
authorized indefinitely, while operators have no durable emergency mechanism
to invalidate an active renewal token and close its live Edge session.

**Decision:** Credential state is persisted as `Pending`, `Active`, `Retired`,
`Revoked`, or `Expired`. Issuance stores a bounded activation deadline. The
supervised enrollment service periodically expires a bounded batch of overdue
pending rows, removes only their fingerprints in the same SQLite transaction,
and publishes afterward; a renewal predecessor remains active. Expired request
IDs remain terminal tombstones so replay cannot mint another leaf. An offline
`revoke-agent` transaction marks all pending/active credentials for one exact
Agent/Tunnel pair revoked, invalidates matching bootstrap and renewal tokens,
and removes that tunnel from the complete snapshot. Dynamic Edge's existing
reconciliation closes the exact live session. Repeated expiry/revoke is
idempotent. Agent treats revocation as terminal but discards an expired pending
journal so a still-active predecessor token may begin a fresh request.

**Consequences:** Emergency application-level revocation and abandoned-overlap
cleanup are durable, bounded, restart-safe, and require no Edge database lookup
or Tunnel Protocol change. A CA-valid revoked leaf may still complete the TLS
layer before snapshot authorization rejects it; CRL/OCSP is not added. The
issuer filesystem boundary, HSM/KMS, CA rollover, general admin API, and
multi-writer consensus remain future work.

---

## ADR-023 — Public raw ingress is explicit and requires dynamic mTLS authority

**Status:** Accepted (Session 23).

**Context:** The durable raw listener was deliberately restricted to loopback.
The transport, snapshot, and credential layers can now authenticate an Agent,
reconcile live authorization, and revoke an exact session, but allowing an
arbitrary non-loopback bind without an explicit policy would turn a safe
development default into an accidental public exposure. The existing global
connection semaphore also lets one source IP occupy every route permit.

**Decision:** Raw routes carry an explicit exposure policy. `LoopbackOnly`
remains the default and rejects non-loopback addresses. `Public` requires a
non-zero per-source-IP limit no greater than the route's global connection
limit. The runnable Edge additionally requires Agent-facing mutual TLS and an
external dynamic authorization snapshot; plaintext and static-certificate
authorization cannot enable public raw ingress. A bounded per-IP map counts
only admitted active connections, is bounded by the global semaphore, and is
released through RAII on every close and failure path. Ingress still resolves
only cached `TunnelId` state and performs no Control Plane lookup.

**Consequences:** An operator may explicitly expose an opaque TCP service while
retaining bounded admission, offline fail-close, reconnect, drain, and Session
22 revocation behavior. The Edge does not encrypt or authenticate the public
client side of an arbitrary raw protocol; the tunneled service must provide
those properties when required. Public HTTP/TLS termination, hostname routing,
request-rate limiting, DDoS protection, and multi-edge ownership remain
separate work. A configured stale snapshot cache may continue serving within
its existing bounded stale window, so revocation delivery can be delayed while
the Control Plane is unavailable.

---

## ADR-024 — Binary workspace dependencies are locked and PRs receive CI checks

**Status:** Accepted (Session 24).

**Context:** TunnelProxy ships three runnable application binaries and now has
261 security-sensitive tests, but dependency resolution remained local-only and
no hosted check ran before merge. The workspace declares Rust 1.75 while local
development follows stable, and native Windows dependencies require the MSVC
toolchain. A change could therefore pass on one developer machine while
breaking the declared MSRV or another supported platform.

**Decision:** Commit the workspace `Cargo.lock` and use `--locked` for hosted
Cargo commands. GitHub Actions runs for pull requests, pushes to `main`, and
manual dispatch. One Ubuntu job enforces format, all-target checking, and
warning-free Clippy; a non-fail-fast Ubuntu/Windows matrix runs all tests and a
workspace build; and a separate Ubuntu job checks all targets with Rust 1.75.
Transitive releases that Cargo 1.75 cannot parse remain pinned in the lockfile,
and the workspace-level `forbid(unsafe_code)` lint is the single authority
rather than being redundantly weakened or restated in each crate.
The workflow has read-only repository permissions, pins its checkout action to
an immutable commit, does not persist checkout credentials, sets explicit job
timeouts, and cancels superseded runs for the same ref or pull request.

**Consequences:** Dependency changes must update their manifests and lockfile
atomically, and the main supported build paths receive automatic regression
coverage before merge. Stable remains the normal development toolchain while
the explicit MSRV job prevents accidental compiler-version drift. Hosted
Windows validates the MSVC path without removing the local Visual Studio Build
Tools requirement. Branch-protection settings, release artifacts, dependency
update bots, vulnerability auditing, and code signing remain separate operator
or future-session work.

---

## ADR-025 — Public HTTPS is an exact, bounded HTTP/1.1 ingress mode

**Status:** Accepted (Session 25).

**Context:** The authenticated multiplexed transport and dynamic authorization
cache can already carry public raw TCP, but an HTTP product surface must
terminate public TLS, prevent hostname confusion and forwarding-header spoofing,
bound parser/request resources, and preserve the rule that ingress never asks
the Control Plane to route a request.

**Decision:** The runnable single-tunnel Edge may replace raw ingress with one
HTTPS listener and an immutable exact hostname-to-TunnelId table. Public
exposure requires explicit opt-in, global/per-IP admission, Agent mTLS, and
external dynamic snapshot authorization. Public TLS uses an independent
server-only rustls configuration and optional atomic generation reload. Every
HTTP/1.1 request must have exactly one normalized Host equal to TLS SNI and any
absolute-form authority. Edge rejects CONNECT/upgrades, strips hop-by-hop and
untrusted forwarding headers, writes canonical forwarding metadata, and routes
through the existing cached TunnelId/session map over a generic bounded async
stream. Header, body, handshake, request, buffer, connection, and drain limits
are validated before bind.

**Consequences:** A manually configured hostname can reach a local HTTP service
through public HTTPS without a Tunnel Protocol v2 or snapshot-format change and
without storage/network lookup on the request hot path. The initial surface
closes after one HTTP/1.1 request and deliberately excludes HTTP/2, upgrades,
CONNECT, automatic hostname allocation, signed access URLs, public-client auth,
distributed rate limiting, and multi-edge ownership. A configured stale
snapshot cache retains the existing bounded revocation-delay tradeoff.

---

## ADR-026 — HTTP request admission uses bounded process-local token buckets

**Status:** Accepted (Session 26).

**Context:** Session 25 bounded concurrent HTTPS connections, but a client could
still issue an unlimited sequence of short connections and repeatedly open
logical streams toward an Agent. The abuse control must remain deterministic,
memory-bounded, observable, and independent of the Control Plane hot path.

**Decision:** After TLS and exact request-authority validation, Edge atomically
checks integer fixed-point token buckets for the whole process and the accepted
socket's source IP before reading the body or opening a tunnel stream. The peer
table has a configured cardinality cap, idle TTL, and fixed-size reclamation
batch; exhaustion fails closed. Rejections use `429 Too Many Requests` and an
integer `Retry-After`. Live status and structured events distinguish global,
per-IP, and peer-table-capacity rejection without recording payload data or
trusting forwarded client identity.

**Consequences:** One Edge protects its local request and tunnel capacity with
bounded memory and no database/network lookup. The global and per-IP decisions
are consistent, and rejected requests cannot reach the local service. State is
not durable or coordinated, resets at process restart, and is not a substitute
for distributed DDoS protection or authoritative account quotas. No Tunnel
Protocol v2 or authorization snapshot change is required.

---

## ADR-027 — Edge operations use a bounded loopback-only pull endpoint

**Status:** Accepted (Session 27).

**Context:** Edge now owns meaningful live authorization, ingress, and
rate-limit state, but operators can observe it only through structured events
or final shutdown outcomes. Exporting metrics must not add unbounded labels,
publicly expose internal topology, or introduce backend I/O into request
routing. Readiness must also distinguish a live process from a tunnel that can
currently serve traffic.

**Decision:** The runnable Edge may opt into a separate loopback-only bounded
HTTP/1.1 operations listener. It serves liveness, live-tunnel readiness, and
Prometheus text metrics by reading cached router/authorization state plus raw
or HTTPS in-memory counters. Metric names and labels are fixed and exclude all
peer, hostname, durable identity, session, certificate, secret, and payload
values. Shutdown marks readiness false before ingress drain, keeps the endpoint
available during that drain, then drains operations before Agent transport.

**Consequences:** A local Prometheus collector and process supervisor can
observe the production Edge data path without storage/Control Plane lookup or
new wire protocol. The listener has no public mode, authentication, or TLS and
must not be port-forwarded externally. Counters reset on restart; remote write,
durable history, dashboards/alerts, JSON logging, and Agent/Control Plane
exporters remain out of scope. Tunnel Protocol v2 and snapshots are unchanged.

---

## ADR-028 — Runnable components share secret-safe stderr logging

**Status:** Accepted (Session 28).

**Context:** Agent, Edge, and Control Plane each configured a human-readable
subscriber independently. Operators need collector-friendly output, but log
selection must fail before process side effects, preserve command stdout, and
never mix multiline usage text into a JSON stream or weaken INV-003.

**Decision:** A shared common-crate initializer validates
`TUNNELPROXY_LOG_FORMAT=text|json` and `RUST_LOG`, installs exactly one stderr
subscriber, and returns the selected format to the entrypoint. JSON output is
JSON Lines with ANSI disabled and stable `timestamp`, `level`, `target`, and
nested `fields` keys. Help and reports remain stdout. JSON-mode CLI failures
emit the structured error without raw usage; invalid logging configuration
exits before component parsing, listener bind, or file mutation.

**Consequences:** All runnable components and development examples have the
same operational contract and can feed ordinary stderr collectors without a
wire or domain schema change. Event authors remain responsible for excluding
tokens, certificates, private keys, payloads, and bodies. At Session 28 the
synchronous stderr sink had no rotation, durable retention, remote shipping,
backpressure queue, dashboard, or alert policy; ADR-038 later adds only the
optional bounded queue and sink telemetry.

---

## ADR-029 — Agent operations are loopback-only and session-ready

**Status:** Accepted (Session 29).

**Context:** Structured logs describe individual Agent transitions, but a local
supervisor or collector cannot cheaply distinguish a live process from an
Agent with an established routable session. Metrics must not expose durable
identity, local topology, ephemeral session IDs, or traffic values, and
observability must remain available while the data path drains.

**Decision:** The runnable Agent may opt into a separate bounded loopback-only
HTTP/1.1 listener serving liveness, established-session readiness, and
Prometheus connection-lifecycle metrics. The reconnect runtime publishes one
fixed phase and monotonic counters through process-local atomics. The process
supervisor forces `draining` before cancellation; runtime state updates cannot
overwrite it. Operations binds before the outbound connection future is
polled, remains available while Agent-owned supervisors drain, and stops last.
Metric labels are fixed and omit identities, addresses, sessions,
certificates, secrets, and payloads.

**Consequences:** Local process supervisors can tell whether the Agent is
alive, connected, reconnecting, or draining without scraping logs or touching
Edge/Control Plane state. The endpoint is unauthenticated because it cannot be
publicly bound. Session 29 metrics reset on restart and initially excluded
stream/byte telemetry; ADR-036 later adds that bounded process-local slice.
Control Plane metrics are handled by ADR-030; durable/remote storage,
dashboards, alerts, and nonblocking log shipping remain outside this decision.

---

## ADR-030 — Control Plane operations are loopback-only and memory-backed

**Status:** Accepted (Session 30).

**Context:** Operators need to distinguish liveness from an initialized and
distributing Control Plane and observe refresh/enrollment failures without
querying SQLite per scrape or exposing durable identities and secrets.

**Decision:** The runnable Control Plane may opt into a bounded loopback-only
HTTP/1.1 listener serving liveness, service readiness, and Prometheus metrics.
Authority, refresh, distribution, enrollment, reconciliation, and operations
code update one process-local atomic telemetry handle. Labels use only fixed
outcomes. Readiness becomes false before child-service drain; operations stays
available until snapshot and enrollment stop, then drains last. Configuration
rejects non-loopback binding and is validated before storage initialization.

**Consequences:** Local supervisors can scrape the Control Plane without
SQLite/network work or identity, address, path, fingerprint, digest, token,
certificate, key, or payload values. Metrics reset at restart. Public or
authenticated access, persistence, remote write, dashboards, alerts, and
protocol/schema changes remain outside this decision.

---

## ADR-031 — HTTPS route administration uses an independent versioned catalog

**Status:** Accepted (Session 31).

**Context:** Public HTTPS ingress accepts one exact operator-configured route,
but the Control Plane had no durable hostname authority. Route identity must be
identical across components, mutations must survive restart without partial
version changes, and this bounded step must not silently alter authorization
snapshot consumers or put SQLite on the request path.

**Decision:** `PublicHostname` is a shared canonical ASCII DNS value type used
by both Edge and Control Plane. The Control Plane stores at most 64 exact
hostname, TunnelId, and enabled/disabled records in a separate SQLite catalog
with its own non-zero monotonic version. An immediate transaction couples each
effective upsert/removal with one version increment; semantic no-ops do not
increment. Reads validate all durable values and return deterministic order.
Operator CLI commands are the only mutation surface in this session.

**Consequences:** Operators can safely prepare and inspect durable HTTPS route
intent, including across process restarts, without changing Tunnel Protocol v2,
authorization snapshots, or current Edge routing. Edge does not consume this
catalog yet, so process-start `--https-host` remains authoritative there.
Automatic allocation, DNS/TLS automation, custom domains, signed URLs,
administrative HTTP APIs, and multi-edge coordination remain out of scope.

---

## ADR-032 — HTTPS routes use an independent authenticated latest-value stream

**Status:** Accepted (Session 32).

**Context:** The durable route catalog must reach Edge without putting SQLite
or network I/O on the public request path, coupling route churn to Agent
authorization, or silently serving indefinitely after authority loss.

**Decision:** Control Plane distributes complete canonical route catalogs over
a dedicated bounded `TPR1` mutual-TLS service and ALPN. Edge bootstraps online,
atomically swaps immutable latest values, accepts monotonic versions, and keeps
the last authenticated value in memory during a bounded stale interval. Once
expired, route resolution and dynamic readiness fail closed until an
authenticated reconnect. No route disk cache is created.

**Consequences:** Operator CLI mutations become live without Edge restart and
requests remain independent of Control Plane/storage availability within the
explicit stale window. Authorization snapshots and Tunnel Protocol v2 remain
unchanged. Cold-start offline routing, automatic allocation, custom domains,
HTTP/2, and multi-edge replication remain outside this decision.

---

## ADR-033 — HTTPS route TLS reload uses protocol-bound atomic generations

**Status:** Accepted (Session 33).

**Context:** The route stream has a dedicated ALPN but initially loaded its
server and client credentials only at process start. Reusing the snapshot
reloader directly would risk constructing a candidate for the wrong protocol,
while independent ad hoc reload logic would duplicate atomicity and expiry
semantics.

**Decision:** Snapshot and HTTPS route wrappers share internal server/client
generation loaders, but every bootstrap captures an immutable protocol ALPN.
The route server and client each use their own strict digest manifest and
supervised runtime. A complete, valid, strictly newer generation is published
atomically; rejected candidates retain the last-known-good configuration, and
certificate expiry terminates the supervisor if no valid replacement arrives.

**Consequences:** Route credentials rotate without process restart and normal
reconnects authenticate with the new generation, while the route and snapshot
wire protocols remain isolated. Existing sessions are not forcibly
renegotiated. The runnable binaries still reuse their existing PEM path groups;
operators publish bytes before the corresponding manifest. CA overlap,
CRL/OCSP, automated issuance, and protocol changes remain outside this
decision.

---

## ADR-034 — HTTP/1.1 connection reuse is opt-in, capped, and revalidated

**Status:** Accepted (Session 34).

**Context:** Public HTTPS originally closed after one request. Unbounded
keep-alive would let clients retain scarce global/per-IP permits, turn the
whole-connection timeout into an incorrect lifetime limit, and risk reusing a
connection after a rejected request body or stale routing decision.

**Decision:** `max_requests_per_connection` defaults to one and is capped at
1024. Values above one enable sequential HTTP/1.1 keep-alive. Every request
repeats security, route, rate-limit, sanitization, size, and tunnel admission
checks. Header-read timeout bounds idle time; a fresh deadline covers request
processing and response-body delivery. The last allowed response and every
rejection, timeout, or upstream failure close the connection. Connection
permits span the TLS lifetime, and process shutdown invokes graceful Hyper
drain before the existing hard deadline.

**Consequences:** Operators may reduce TLS handshake overhead without adding
unbounded connection ownership or stale per-connection authorization. The
default behavior remains compatible, requests are never automatically
replayed, and metrics remain fixed-cardinality. HTTP/2, pipelining guarantees,
WebSocket/upgrade, CONNECT, distributed quotas, and multi-edge coordination
remain outside this decision.

---

## ADR-035 — DATA writers use bounded per-stream round-robin scheduling

**Status:** Accepted (Session 35).

**Context:** The multiplexed writer had separate control and DATA channels, but
all streams shared FIFO DATA service. A backlogged stream could occupy the
queue ahead of later streams, and moving admitted frames into an additional
scheduler must not silently multiply memory capacity. Unlimited control
priority could also starve application DATA.

**Decision:** Agent and Edge share a semaphore-backed DATA admission bound whose
permit remains attached through channel, scheduler, and frame encoding. The
writer groups DATA and END_STREAM by StreamId, preserves per-stream FIFO, and
serves active streams round-robin. Control frames remain preferred for at most
eight consecutive writes while DATA is queued.

**Consequences:** Backlogged streams cannot monopolize frame service, half-close
ordering is preserved, and the configured DATA bound remains global to the
writer pipeline. This is local frame fairness, not byte fairness: no protocol
fields, ALPN, peer credits, stream weights, or cross-process coordination are
introduced.

---

## ADR-036 — Transport fairness is measured with process-local atomic telemetry

**Status:** Accepted (Session 36).

**Context:** Session 35 prevents frame starvation, but DEBT-014 requires
measurement before introducing peer credits or a weighted scheduler. Queue
length sampled at one point would miss time spent waiting for admission and
could leak gauges on writer failure. Dynamic stream/session labels would also
create unbounded Prometheus cardinality.

**Decision:** Agent and Edge aggregate transport metrics in one atomic handle
per process runtime. DATA direction uses only the fixed `sent` and `received`
label values. Stream and admitted-pipeline gauges are RAII-owned; the latter
travels with the semaphore permit until the frame leaves the writer pipeline.
One counter records failure of the first immediate admission attempt, while
flow-control resets and control-burst DATA yields are explicit counters.
Existing loopback operations endpoints read snapshots without session locks,
storage, or external I/O.

**Consequences:** Operators can distinguish payload volume, concurrency,
saturation, overflow, and scheduler intervention without identity or payload
labels. Metrics aggregate reconnects and Edge sessions and reset on process
restart. They provide evidence for a later flow-control decision but do not
add peer credits, byte fairness, protocol fields, remote persistence,
dashboards, or alerts.

---

## ADR-037 — Live session capacity is an RAII aggregate; collection stays operator-owned

**Status:** Accepted (Session 37).

**Context:** Pipeline depth and admission waits from Session 36 have no useful
utilization denominator when the number of live sessions changes. Exporting
configured process capacity would incorrectly report capacity while Agent is
offline, while per-session labels would expose identity and create cardinality
risk. Embedding remote-write/backend I/O would also couple request routing to
an operator-specific observability system.

**Decision:** Every established multiplex session registers its configured
DATA queue slots in the shared process telemetry before queue creation and
holds an RAII capacity guard until its writer pipeline is gone. Agent and Edge
export the resulting fixed-cardinality capacity gauge through their existing
loopback endpoints. Collection, retention, PromQL evaluation, dashboards, and
paging remain external operator responsibilities documented in the operations
runbook.

**Consequences:** Agent capacity becomes zero across disconnect/backoff and is
restored on reconnect; Edge capacity is the sum of live session bounds.
Operators can calculate current utilization without dynamic labels and can
distinguish no-session from saturation by correlating readiness. The high-water
mark remains process-lifetime state, counters reset on restart, and aggregate
telemetry alone cannot justify peer byte credits or weighted scheduling.

---

## ADR-038 — Slow stderr is isolated by an opt-in bounded drop-newest worker

**Status:** Accepted (Session 38).

**Context:** The shared Session 28 subscriber writes synchronously to stderr.
When a pipe or local collector is slow, formatting callers can block Tokio
runtime threads. An unbounded asynchronous logger would move the outage into
memory growth, while a durable/remote sink would couple TunnelProxy to an
operator-specific backend.

**Decision:** Preserve synchronous stderr by default. An explicit bounded
capacity enables one FIFO and one stderr worker. Each event is formatted into
a hard-bounded buffer; producers use nonblocking `try_send`, full queues drop
the newest event, and oversized events are discarded whole. A lifetime guard
drains only until a configured deadline and then detaches a blocked writer.
Fixed-cardinality operations metrics expose capacity, accepted, dropped,
oversized, and write-failure totals.

**Consequences:** Slow stderr cannot indefinitely block enabled runtime paths,
memory and shutdown latency have explicit ceilings, JSON Lines remain whole,
and event loss is observable. Buffered mode may lose the newest events under
pressure and is not durable. Rotation, retention, encryption, and remote
shipping remain operator-owned; no Tunnel Protocol or snapshot schema changes.
