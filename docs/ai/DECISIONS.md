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
