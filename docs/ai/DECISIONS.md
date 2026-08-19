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
