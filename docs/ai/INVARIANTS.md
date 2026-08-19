# TunnelProxy — Invariants

> Architecture and operational rules that must hold across every
> session. Violations are bugs, not style issues. Amending an invariant
> requires explicit rationale recorded here.

---

## INV-001 — Agent tunnel connections are outbound initiated

The `tunnelproxy-agent` binary must never accept inbound connections
from the public internet. Every tunnel is opened outbound from the
agent to a `tunnelproxy-edge` node.

**Rationale:** developers sit behind NATs and corporate firewalls; the
only connection model that works almost everywhere is outbound. It is
also the only model that does not require opening inbound ports on
untrusted networks.

---

## INV-002 — Unbounded buffering of network payloads is forbidden

No code path may buffer an unbounded amount of network payload. Every
reader, writer, queue, and channel between a public client and a local
service must declare and enforce a capacity limit. Backpressure must
propagate, not be silently absorbed.

**Rationale:** the edge is the most attack-prone surface in the
system. A single misbehaving client must not be able to exhaust edge
memory.

---

## INV-003 — Secrets must never be logged

Authentication tokens, signing keys, session cookies, and any value
explicitly marked as a secret must never appear in logs, error
messages, traces, or panic messages. Structured log fields containing
secrets are equally forbidden.

**Rationale:** logs are usually the first place credentials leak from
production systems.

---

## INV-004 — Tunnel wire protocol changes require explicit protocol versioning

Any change to the framing, message set, or codec of the
Edge ↔ Agent protocol requires bumping `PROTOCOL_VERSION` in
`tunnelproxy-protocol`. Silent wire-format changes are forbidden.

**Rationale:** an agent and an edge that disagree on the wire format
will produce either crashes or silent corruption. Versioning is the
cheapest way to detect and reject the mismatch.

---

## INV-005 — Long-running network operations must have timeout and cancellation semantics

Any network operation expected to run for more than a single request
must expose both a timeout and a cancellation path. Callers must be
able to abort the operation without leaking resources.

**Rationale:** in a long-lived daemon, leaks accumulate. A network
operation that cannot be cancelled will eventually pin a task, a
socket, or a buffer.

---

## INV-006 — State-changing HTTP requests must not be automatically replayed after uncertain delivery unless explicitly designed with safe semantics

Replaying a captured `POST`, `PUT`, `PATCH`, or `DELETE` against the
local service after delivery is uncertain is forbidden by default. If
replay is offered, it must be explicit, opt-in, and visibly
documented as unsafe for non-idempotent requests.

**Rationale:** users routinely tunnel webhooks. Silently re-firing a
`POST /charge` request can double-bill or corrupt state.

---

## INV-007 — Per-request runtime routing must not depend on a PostgreSQL query

Per-request routing on the edge must use cached / pre-pushed routing
state. The edge may not synchronously query the control-plane database
to decide where to forward a request.

**Rationale:** routing on the hot path is the single biggest scaling
cliff. The control plane's job is to push authoritative state into the
edge; the edge's job is to consume that state without asking again.

---

## INV-008 — Blocking I/O must not be introduced into Tokio async execution paths

Code that runs on a Tokio executor must not perform blocking I/O.
File, DNS, and similar potentially-blocking operations must use
their async equivalents or be moved to a dedicated blocking-thread
pool.

**Rationale:** blocking the executor stalls every other task on the
same worker thread. In a latency-sensitive server, this is fatal.

---

## INV-009 — Client-supplied forwarding headers must not later be blindly trusted by Edge

Headers such as `X-Forwarded-For`, `X-Forwarded-Proto`,
`X-Forwarded-Host`, and `Forwarded` are attacker-controlled when they
arrive from a public client. Edge must either strip them on ingress or
treat any value derived from them as untrusted.

**Rationale:** forwarding headers are the canonical way to spoof
origin IP / protocol / host. Trusting them enables trivial
authentication bypasses and cache poisoning.

---

## INV-010 — Meaningful features require appropriate automated tests

Any feature beyond trivial placeholder code must ship with unit tests,
integration tests, or end-to-end tests appropriate to its risk. A
capability is not "done" until its tests are written and pass.

**Rationale:** TunnelProxy is a security-sensitive developer tool.
Untested code is unsafe code. The TEST_MATRIX exists to make this
rule auditable.
