# TunnelProxy — Technical Debt Register

> Living log of deliberate shortcuts, deferred work, and known issues.
> Anything that violates an invariant in `docs/ai/INVARIANTS.md` should
> be either fixed or recorded here with a clear rationale and an exit
> plan.

## Template

```
### DEBT-<NNN> — <short title>

- **Introduced in:** Session <NN>
- **Category:** <foundation | correctness | security | ops | docs>
- **Impact:** <low | medium | high>
- **Rationale:** <why we accepted this shortcut>
- **Exit plan:** <how we intend to remove it>
- **Tracking:** <PR / issue link if available>
```

## Open items

### DEBT-001 — Foundation crates are placeholders only

- **Introduced in:** Session 01
- **Category:** foundation
- **Impact:** high (intentional)
- **Rationale:** Session 01 explicitly establishes component
  boundaries before any networking is written. The five crates today
  expose only identification / status types so the workspace compiles
  and tests green while remaining honest about capability.
- **Exit plan:** Session 02 introduces real TCP listener / tunnel
  primitives in `tunnelproxy-agent` and `tunnelproxy-edge`. Each
  placeholder API is removed or replaced by a real one, not
  accumulated alongside it.
- **Tracking:** Session 02 plan, `docs/ai/SESSION_INDEX.md`.

### DEBT-002 — No CI configuration

- **Introduced in:** Session 01
- **Category:** ops
- **Impact:** medium
- **Rationale:** Foundation work is local-only by intent. CI selection
  (GitHub Actions vs. another provider) is deferred until the
  project's hosting is decided.
- **Exit plan:** Add a CI workflow that runs `cargo fmt --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and `cargo build --workspace` on every
  PR.
- **Tracking:** open.

### DEBT-003 — `Cargo.lock` not yet committed intentionally is undecided

- **Introduced in:** Session 01
- **Category:** foundation
- **Impact:** low
- **Rationale:** For a workspace that will ship application binaries,
  `Cargo.lock` should be committed. We have not yet produced a
  `Cargo.lock` because no build has been run in this environment.
- **Exit plan:** Commit `Cargo.lock` on the first build that
  successfully resolves dependencies.
- **Tracking:** open.

## Resolved items

_None yet._
