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
