# TunnelProxy — Development Guide

## 1. Prerequisites

- **Rust** stable toolchain. The repository pins the toolchain in
  `rust-toolchain.toml`; running `cargo` inside the workspace will
  auto-install it via `rustup` if needed.
- **`rustup` components** `rustfmt` and `clippy` (also pinned in
  `rust-toolchain.toml`).
- **Git** for version control.
- A POSIX-like shell for the developer scripts in `scripts/`. On
  Windows, use WSL or Git Bash.

No database, no Docker, no cloud account is required for foundation or
MVP work.

## 2. Rust toolchain

The repository ships a `rust-toolchain.toml` that pins the channel and
required components so every contributor and CI run uses the same
compiler:

```toml
[toolchain]
channel = "stable"
profile = "minimal"
components = ["rustfmt", "clippy"]
```

If you need a newer stable compiler, bump `channel` intentionally and
mention the reason in the PR description. Do not silently override the
toolchain locally.

## 3. Workspace commands

All commands run from the workspace root.

```bash
# Format check
cargo fmt --all --check

# Format apply
cargo fmt --all

# Lint (treats warnings as errors)
cargo clippy --workspace --all-targets -- -D warnings

# Run all tests
cargo test --workspace

# Build everything
cargo build --workspace

# Build optimized
cargo build --workspace --release
```

## 4. Formatting

- We use the default `rustfmt` configuration. There is no custom
  `rustfmt.toml` on purpose.
- PRs that fail `cargo fmt --all --check` will not be merged.

## 5. Linting

- We run `cargo clippy --workspace --all-targets -- -D warnings`.
- Do not suppress legitimate Clippy warnings with `#[allow(...)]`
  unless the suppression is justified in a comment and a tracking
  entry in `docs/TECH_DEBT.md`.

## 6. Testing

- Unit tests live next to the code they exercise (`src/foo.rs`,
  `#[cfg(test)] mod tests`).
- Cross-crate integration tests will live in `tests/` once they
  exist.
- See `docs/ai/TEST_MATRIX.md` for the canonical list of capabilities
  and their test status. **Do not mark a capability as tested unless
  the test actually exists.**

## 7. Git branch conventions

- Long-lived branches: `main`.
- Feature / session branches: `feat/<short-name>` (e.g.
  `feat/session-01-foundation`, `feat/session-02-tcp-networking`).
- Bugfix branches: `fix/<short-name>`.
- Documentation-only branches: `docs/<short-name>`.

Branch names are kebab-case.

## 8. Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short imperative summary>

[optional body]

[optional footer]
```

Common types:

- `feat` — user-visible feature
- `fix` — bug fix
- `chore` — maintenance / foundation work with no user-visible effect
- `docs` — documentation only
- `refactor` — code change that neither fixes a bug nor adds a feature
- `test` — adding or correcting tests

Examples from this session:

```
chore(project): establish TunnelProxy foundation
```

## 9. Definition of Done

A change is "done" only when **all** of the following hold:

- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] `cargo build --workspace` passes.
- [ ] New public surface is documented (doc comments + relevant
      `docs/` file if it changes architecture or workflow).
- [ ] If invariants in `docs/ai/INVARIANTS.md` are touched, the
      invariant is preserved or explicitly amended with rationale.
- [ ] No secrets are committed (INV-003).
- [ ] `docs/ai/CURRENT_STATE.md` and `docs/ai/SESSION_INDEX.md` are
      updated if a session ends.
- [ ] `docs/TECH_DEBT.md` records any deliberate shortcut.

## 10. Exercising graceful shutdown

Long-running runtimes expose a shutdown-aware variant accepting a cloneable
`ShutdownSignal` and `RuntimeShutdownConfig`. Create one process-level pair with
`shutdown_channel()`, clone only the signal into runtimes, and invoke
`trigger.shutdown()` once. The default drain deadline is 10 seconds; zero is
rejected. Runtime tests should assert the returned `RuntimeShutdownOutcome` and
verify that listener addresses can be rebound after completion.

## 11. Running the local tunnel processes

Start a local service on `127.0.0.1:3000`, then run Edge and Agent in separate
terminals:

```bash
cargo run -p tunnelproxy-edge --bin tunnelproxy-edge -- \
  --agent-listen 127.0.0.1:7100 \
  --raw-listen 127.0.0.1:7000

cargo run -p tunnelproxy-agent --bin tunnelproxy-agent -- \
  --edge 127.0.0.1:7100 \
  --local 127.0.0.1:3000 \
  --reconnect-initial-ms 250 \
  --reconnect-max-ms 30000
```

TCP clients can then connect to `127.0.0.1:7000`. Press Ctrl-C to request
ordered shutdown. Unix also observes SIGTERM. Exit code `0` means a locally
requested graceful shutdown, `1` means runtime failure/forced drain or
retry-budget exhaustion, and `2` means invalid CLI or runtime
configuration. Agent reconnect flags also expose the multiplier, downward
jitter percentage, stable-session reset duration, and optional maximum
consecutive failure count; use `--help` for their exact names and defaults.

This entrypoint intentionally supports one Agent and one loopback route. Agent
disconnects are recovered by rebinding that address to a replacement ephemeral
session. It does not provide authentication, durable identity, or public
ingress, and interrupted streams are not replayed.
