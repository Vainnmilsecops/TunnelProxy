# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Project Foundation** (Session 01).

## Completed

- Repository baseline (`README.md`, `Cargo.toml`, `rust-toolchain.toml`,
  `.gitignore`).
- Cargo workspace with five crates (`common`, `protocol`, `agent`,
  `edge`, `control-plane`).
- Component boundaries documented per crate and per architecture
  document.
- Documentation baseline: `PRODUCT_SPEC.md`, `ARCHITECTURE.md`,
  `DEVELOPMENT.md`, `TECH_DEBT.md`.
- AI context layer: `PROJECT_CONTEXT.md`, `CURRENT_STATE.md`,
  `MODULE_MAP.md`, `INVARIANTS.md`, `DECISIONS.md`, `TEST_MATRIX.md`,
  `SESSION_INDEX.md`.
- Development workflow documented (format / lint / test / build /
  Definition of Done).
- Initial placeholder unit tests in every crate.

## Not implemented

- TCP networking.
- HTTP proxying.
- Tunnel wire protocol (only `PROTOCOL_VERSION = 1` is defined).
- Agent ↔ Edge connection.
- Authentication.
- TLS.
- Persistence.
- Request inspection.

Any of the above is out of scope for Session 01 and must not appear in
the Session 01 commit.

## Next planned session

**Session 02 — TCP Networking Foundation.**

Goals (subject to refinement when Session 02 begins):

- Outbound TCP tunnel from agent to edge.
- Bounded bidirectional byte streaming primitives.
- First iteration of framing in `tunnelproxy-protocol`.
- Initial timeout / cancellation semantics on long-running operations
  (INV-005).
- Unit + integration tests for the streaming primitives.
