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

No external database server, Docker, or cloud account is required. Session 17
uses bundled SQLite when exercising persistent snapshots.

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

### 3.1 Reproducible dependency resolution and CI

TunnelProxy ships application binaries, so the workspace commits `Cargo.lock`.
Do not remove or regenerate the lockfile casually. CI uses `--locked`; a
manifest change whose resolved dependencies are not committed fails before
compilation.

GitHub Actions runs on every pull request and push to `main`. The quality job
checks formatting, all targets, and Clippy on Ubuntu. Test/build jobs run on
both Ubuntu and Windows MSVC, and a separate job checks the declared Rust 1.75
MSRV. Run the equivalent stable-toolchain gates locally before opening a PR:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
```

The hosted Windows runner includes the MSVC native build toolchain. A local
native Windows build still requires Visual Studio Build Tools with the
"Desktop development with C++" workload; alternatively run the Linux gates in
WSL.

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
  --raw-listen 127.0.0.1:7000 \
  --agent-id agent-dev \
  --tunnel-id tunnel-dev

cargo run -p tunnelproxy-agent --bin tunnelproxy-agent -- \
  --edge 127.0.0.1:7100 \
  --local 127.0.0.1:3000 \
  --agent-id agent-dev \
  --tunnel-id tunnel-dev \
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

For mutual TLS, provision an Edge certificate for the name Agents will verify,
an Agent client certificate, and the corresponding CA certificates. No private
keys are supplied through command-line values; only PEM file paths are passed:

```bash
cargo run -p tunnelproxy-edge --bin tunnelproxy-edge -- \
  --agent-listen 0.0.0.0:7100 \
  --raw-listen 127.0.0.1:7000 \
  --tls-cert edge.pem \
  --tls-key edge-key.pem \
  --tls-client-ca agent-ca.pem \
  --authorized-client-cert agent.pem \
  --agent-id agent-prod \
  --tunnel-id tunnel-prod

cargo run -p tunnelproxy-agent --bin tunnelproxy-agent -- \
  --edge 192.0.2.10:7100 \
  --local 127.0.0.1:3000 \
  --agent-id agent-prod \
  --tunnel-id tunnel-prod \
  --tls-ca edge-ca.pem \
  --tls-client-cert agent.pem \
  --tls-client-key agent-key.pem \
  --tls-server-name edge.example.com
```

All TLS arguments for one process are required together. Edge additionally
requires the exact public client certificate to bind its fingerprint to the
configured Agent/Tunnel grant. TLS uses ALPN `tunnelproxy/2`; its handshake
timeout defaults to 10 seconds. Plaintext is
rejected for non-loopback Agent transport addresses.

This entrypoint intentionally supports one Agent and one loopback route. The raw
listener targets durable TunnelId, stays bound across Agent reconnect, and
fails closed while no authorized session is live. Reconnect receives a fresh
TransportSessionId and interrupted streams are not replayed. Public ingress and
certificate lifecycle automation remain absent.

## 12. Exercising live authorization snapshots

The library runtime can consume live in-process full snapshots. Create a
versioned initial value, retain the publisher in the authoritative owner, and
pass its subscription to Edge:

```rust
let (publisher, subscription) = authorization_snapshot_channel(
    VersionedAuthorizationSnapshot::new(SnapshotVersion::FIRST, initial),
);
edge_config.multiplex.registration =
    EdgeRegistrationPolicy::mutual_tls_updates(subscription);

publisher.publish(VersionedAuthorizationSnapshot::new(
    SnapshotVersion::new(2).expect("version is non-zero"),
    replacement,
))?;
```

Each update is a complete replacement. Omitting a previous grant revokes it;
an empty snapshot revokes all grants. A higher version may skip intermediate
numbers. Reusing the current version is valid only for identical content.
Ingress continues to use Edge's in-memory maps and never awaits this publisher.

The CLI retains static version-1 authorization through
`--authorized-client-cert`, but it can instead select the external snapshot
mode described below. See
[`SNAPSHOT_DISTRIBUTION.md`](SNAPSHOT_DISTRIBUTION.md).

## 13. Running persistent snapshot distribution

Create a complete JSON manifest using the schema in
[`SNAPSHOT_DISTRIBUTION.md`](SNAPSHOT_DISTRIBUTION.md), then initialize SQLite:

```bash
cargo run -p tunnelproxy-control-plane --bin tunnelproxy-control-plane -- \
  import --database snapshots.sqlite --snapshot snapshot.json
```

Run the mTLS snapshot service:

```bash
cargo run -p tunnelproxy-control-plane --bin tunnelproxy-control-plane -- \
  serve --database snapshots.sqlite --listen 127.0.0.1:7200 \
  --tls-cert control-plane.pem --tls-key control-plane-key.pem \
  --edge-client-ca edge-ca.pem
```

Configure Edge dynamic authorization in addition to its Agent-facing TLS:

```bash
cargo run -p tunnelproxy-edge --bin tunnelproxy-edge -- \
  --tls-cert edge-server.pem --tls-key edge-server-key.pem \
  --tls-client-ca agent-ca.pem --tunnel-id tunnel-prod \
  --snapshot-server 127.0.0.1:7200 --snapshot-ca control-plane-ca.pem \
  --snapshot-client-cert edge-client.pem \
  --snapshot-client-key edge-client-key.pem \
  --snapshot-server-name control-plane.internal \
  --snapshot-cache-dir edge-snapshot-cache \
  --snapshot-cache-max-stale-ms 300000
```

Do not also pass `--authorized-client-cert` in snapshot mode. Partial groups are
invalid. The two cache flags are optional but must be supplied together, and
the stale duration must be non-zero. Edge prefers authenticated online
bootstrap. If the service is temporarily unavailable, a fresh valid cache can
bind the listeners with `Stale` authorization; TLS/authentication or protocol
failure never falls back. Later imports with a higher version are durably
cached before publication. If reconnect does not succeed before the stale
deadline, Edge shuts down and releases both listeners. Cache filesystem I/O is
never performed on the ingress path.

## 14. Rotating TLS without process restart

TLS reload is opt-in. Keep the normal PEM path flags and add the matching
manifest flag. Agent and Control Plane use `--tls-reload-manifest`; Edge uses
that flag for Agent-facing TLS and `--snapshot-tls-reload-manifest` for its
Control Plane snapshot-client identity. The route service and route client use
`--https-route-tls-reload-manifest`. All processes accept
`--tls-reload-interval-ms` and `--tls-expiry-warning-ms`.

The manifest is strict JSON. `generation` must be non-zero; a replacement must
be greater than the active generation. Each digest is SHA-256 over the exact
bytes at the existing PEM path. For static Edge authorization the complete
manifest is:

```json
{
  "generation": 2,
  "files": {
    "server_certificate": "<64 lowercase hex characters>",
    "server_private_key": "<64 lowercase hex characters>",
    "client_ca": "<64 lowercase hex characters>",
    "authorized_client_certificate": "<64 lowercase hex characters>"
  }
}
```

Other exact file sets are:

- Agent, snapshot client, and HTTPS route client: `server_ca`, `client_certificate`,
  `client_private_key`.
- Control Plane snapshot server and HTTPS route server: `server_certificate`,
  `server_private_key`, `client_ca`.
- Dynamic Edge Agent-facing server: `server_certificate`,
  `server_private_key`, `client_ca`.
- Control Plane snapshot server: `server_certificate`,
  `server_private_key`, `client_ca`.

Publish material files first, calculate their digests, write the complete
manifest to a sibling temporary file, then atomically replace the configured
manifest path. The manifest is the commit marker. If polling observes an
intermediate write, wrong digest, invalid key/certificate pair, stale version,
or unknown field, it keeps last-known-good and reports `ReloadFailed`. Reusing
the current generation is accepted only when the manifest bytes are identical.

Reload affects new TLS handshakes. Existing connections normally use the
credentials negotiated at their last connection; static Edge mode additionally
reconciles the authorized certificate snapshot and closes a session removed by
rotation. The runtime reports an expiry warning for the active leaf certificate
and exits non-zero if that leaf expires before a valid newer generation is
loaded. Manifests and local PEM permissions remain an operator trust boundary;
this feature does not issue certificates or protect private keys.

## 15. Enrolling and renewing Agent credentials

Session 21 adds issuance for dynamic Edge authorization. Read
[`AGENT_ENROLLMENT.md`](AGENT_ENROLLMENT.md) before configuring production-like
credentials. The minimum workflow is:

1. Initialize the snapshot database with `tunnelproxy-control-plane import`.
2. Create a short-lived, Agent/Tunnel-bound token with
   `tunnelproxy-control-plane create-token`; its value is written only to the
   requested secret file.
3. Start `serve` with the complete `--enrollment-*`, `--issuer-*`, and
   `--agent-server-ca` group. `--enrollment-activation-grace-ms` bounds the
   issue-to-activate window (minimum 1000 ms), and
   `--enrollment-reconcile-interval-ms` controls the supervised
   abandoned-request sweep.
4. Run `tunnelproxy-agent --enroll-only` with the token/pending paths, target
   credential paths, and reload manifest path.
5. Start the normal Agent with the same enrollment group to enable automatic
   renewal inside `--renew-before-ms`.

Do not place tokens or private-key contents in command-line arguments, logs, or
version control. The Agent private key and pending journal are local secret
files. Automated enrollment requires the Agent TLS reload manifest and a
dynamic Control Plane snapshot; static Edge authorization cannot follow these
snapshot mutations.

Inspect only non-secret credential metadata for one identity:

```text
tunnelproxy-control-plane credential-status --database snapshots.sqlite \
  --agent-id agent-1 --tunnel-id tunnel-1
```

Emergency-revoke that exact Agent/Tunnel identity:

```text
tunnelproxy-control-plane revoke-agent --database snapshots.sqlite \
  --agent-id agent-1 --tunnel-id tunnel-1
```

Revocation is durable and idempotent. It invalidates enrollment tokens and
removes the identity from the complete authorization snapshot. A running
Control Plane publishes the committed version through its normal repository
refresh, after which dynamic Edge instances close the revoked live session.
Creating a new bootstrap token later is an explicit operator decision to
re-enroll the identity.

## 16. Running explicit public raw TCP ingress

Loopback raw ingress remains the default. A non-loopback listener requires
both explicit exposure and a per-source-IP active-connection limit:

```text
tunnelproxy-edge \
  --raw-listen 0.0.0.0:7000 \
  --allow-public-raw-ingress \
  --max-raw-connections 32 \
  --max-raw-connections-per-ip 4 \
  --tls-cert edge-server.pem \
  --tls-key edge-server-key.pem \
  --tls-client-ca agent-ca.pem \
  --snapshot-server 127.0.0.1:7200 \
  --snapshot-ca control-plane-ca.pem \
  --snapshot-client-cert edge-client.pem \
  --snapshot-client-key edge-client-key.pem \
  --snapshot-server-name control-plane.internal
```

Public mode requires the complete Agent mTLS and dynamic snapshot groups.
Plaintext, static `--authorized-client-cert`, a missing public opt-in, a missing
per-IP limit, zero, or a per-IP value greater than the global limit all fail
configuration. The per-IP bound counts active accepted connections and releases
after stream completion or failure; it is concurrency admission, not a
requests-per-second rate limiter.

The exposed protocol is opaque TCP. TunnelProxy does not terminate public TLS,
assign a hostname, or authenticate arbitrary public raw clients. Run a
TLS/authenticated local service when the raw endpoint requires those properties
and apply host firewall policy appropriate for the deployment. Snapshot-cache
cold start retains its configured stale deadline: traffic may continue from
cached authority during a Control Plane outage, and revocation delivery waits
for authenticated reconnect or stale-deadline shutdown.

## 17. Running bounded public HTTPS ingress

HTTPS ingress replaces raw ingress for the runnable single-tunnel Edge. A
public listener requires the complete Agent mTLS and dynamic snapshot groups,
an explicit public opt-in, and a per-source-IP connection bound:

```text
tunnelproxy-edge \
  --https-listen 0.0.0.0:443 \
  --https-host demo.example.test \
  --public-tls-cert public-server.pem \
  --public-tls-key public-server-key.pem \
  --allow-public-https-ingress \
  --max-http-connections 32 \
  --max-http-connections-per-ip 4 \
  --http-requests-per-second 100 \
  --http-request-burst 200 \
  --http-requests-per-ip-per-second 20 \
  --http-request-burst-per-ip 40 \
  --max-http-rate-limit-peers 4096 \
  --http-rate-limit-idle-ms 300000 \
  --tls-cert edge-server.pem \
  --tls-key edge-server-key.pem \
  --tls-client-ca agent-ca.pem \
  --snapshot-server 127.0.0.1:7200 \
  --snapshot-ca control-plane-ca.pem \
  --snapshot-client-cert edge-client.pem \
  --snapshot-client-key edge-client-key.pem \
  --snapshot-server-name control-plane.internal
```

`--https-host` is one exact DNS hostname for the configured TunnelId. Host and
TLS SNI must match; wildcard allocation is not implemented. Raw-ingress flags
and HTTPS mode are mutually exclusive. The listener speaks HTTP/1.1 only and
rejects CONNECT/upgrades. `--max-http-requests-per-connection` defaults to `1`
and may opt into at most 1024 sequential requests on one TLS connection. The
header-read timeout is also the idle deadline between requests, while
`--http-request-timeout-ms` is restarted for every request and covers both
upstream response acquisition and downstream response-body delivery.

Every reused request repeats Host/SNI validation, route lookup, global/per-IP
rate admission, and forwarding-header sanitization. The physical connection
retains its global/per-IP permit for its whole lifetime. The final allowed
response carries `Connection: close`; validation failures, `429`, upstream
errors, and timeouts also close immediately so unread bodies cannot be reused.
During shutdown, keep-alive admission stops and Hyper drains the active request
within the existing process drain deadline.

Request admission additionally uses global and socket-peer-IP token buckets.
Rates are tokens per second and bursts are token capacities; each burst must be
at least its rate, and per-IP values cannot exceed the global values. The peer
table has an explicit cardinality bound and reclaims idle entries after the
configured TTL. A depleted bucket or full peer table returns `429 Too Many
Requests` with an integer `Retry-After`, before the request body is forwarded or
a local-service stream is opened. These counters and buckets are per Edge
process, reset on restart, and do not provide distributed DDoS protection.

Optional public certificate reload uses `--public-tls-reload-manifest` and the
same monotonic digest-bound generation rules as the other TLS surfaces. The
manifest must contain exactly `public_server_certificate` and
`public_server_private_key`. A rejected generation leaves the last-known-good
configuration active; expiry without a valid replacement terminates the
supervisor. Public TLS authenticates the endpoint to clients but does not add
signed access URLs or end-user authentication.

## 18. Running the Edge operations endpoint

The runnable Edge can expose opt-in health, readiness, and Prometheus metrics
on a separate loopback-only listener:

```text
tunnelproxy-edge \
  --ops-listen 127.0.0.1:9090 \
  --max-ops-connections 8 \
  --ops-header-timeout-ms 2000 \
  --ops-request-timeout-ms 5000
```

`GET /healthz` reports process liveness while the operations listener is
running. `GET /readyz` returns `200` only while the configured TunnelId resolves
to a live Agent session and shutdown drain has not started; otherwise it
returns `503`. `GET /metrics` uses Prometheus text format and exports only
fixed-cardinality Edge authorization, raw/HTTPS ingress, operations, and HTTP
rate-limit state, plus aggregate multiplexed transport occupancy and live
capacity. `HEAD` is also accepted; other methods return `405` and unknown paths
return `404`.

The endpoint is disabled unless `--ops-listen` is supplied and rejects every
non-loopback bind. It has explicit connection/header/time/drain bounds, closes
after one HTTP/1.1 request, and is intentionally unauthenticated because it is
local-only. Do not expose it through a public port forward. Metric labels never
contain peer IPs, hostnames, TunnelIds, AgentIds, session IDs, certificates, or
payload data. Remote write, persistence, dashboards, and an embedded alert
engine are not implemented. See [`OPERATIONS.md`](OPERATIONS.md) for the
operator-owned collection and alert baseline.

## 19. Configuring process logs

Agent, Edge, Control Plane, and the development examples write structured
events to stderr. Human-readable text is the default. Set
`TUNNELPROXY_LOG_FORMAT=json` for one JSON object per line with stable
`timestamp`, `level`, `target`, and `fields` keys. ANSI is disabled in JSON
mode. `RUST_LOG` uses tracing-subscriber filter directives in both modes and
defaults to `info`.

Synchronous stderr remains the default. Set
`TUNNELPROXY_LOG_BUFFER_CAPACITY` to an integer from 1 through 1024 to move
stderr writes onto one dedicated worker with a bounded FIFO. Each formatted
event is capped at 16 KiB. Producers use nonblocking admission and drop the
newest event when the queue is full; oversized events are dropped whole so a
partial JSON object is never emitted. Optionally set
`TUNNELPROXY_LOG_DRAIN_TIMEOUT_MS` from 1 through 5000 (default 500) to bound
shutdown draining. Supplying a drain timeout without enabling the buffer is a
configuration error.

PowerShell:

```powershell
$env:TUNNELPROXY_LOG_FORMAT = "json"
$env:TUNNELPROXY_LOG_BUFFER_CAPACITY = "256"
$env:TUNNELPROXY_LOG_DRAIN_TIMEOUT_MS = "1000"
$env:RUST_LOG = "info,tunnelproxy_edge=debug"
cargo run -p tunnelproxy-edge --bin tunnelproxy-edge -- --help
```

Bash:

```bash
TUNNELPROXY_LOG_FORMAT=json \
TUNNELPROXY_LOG_BUFFER_CAPACITY=256 \
TUNNELPROXY_LOG_DRAIN_TIMEOUT_MS=1000 \
RUST_LOG=info,tunnelproxy_edge=debug \
cargo run -p tunnelproxy-edge --bin tunnelproxy-edge -- --help
```

Help and machine-readable command reports stay on stdout; events stay on
stderr. In JSON mode, invalid CLI arguments produce a JSON error event without
appending multiline usage text. Invalid `TUNNELPROXY_LOG_FORMAT` or `RUST_LOG`
stops the process with exit code 2 before CLI-driven listener binding or file
mutation. Never place tokens, keys, certificates, payloads, or traffic bodies
in filter directives or event fields. Agent, Edge, and Control Plane
operations endpoints expose buffer capacity plus accepted, dropped, oversized,
and write-failure event counters. See [`OPERATIONS.md`](OPERATIONS.md) for
queries and alert guidance.

## 20. Running the Agent operations endpoint

The runnable Agent can expose local health, readiness, and Prometheus
connection metrics on an opt-in loopback listener:

```text
tunnelproxy-agent \
  --ops-listen 127.0.0.1:9091 \
  --max-ops-connections 8 \
  --ops-header-timeout-ms 2000 \
  --ops-request-timeout-ms 5000
```

`GET /healthz` returns `200` while the operations listener is running.
`GET /readyz` returns `200` only after the Agent has completed registration and
its outbound session is active; it returns `503` during initial connection,
reconnect backoff, disconnect, and shutdown drain. `GET /metrics` reports
connection attempts, established sessions, reconnects, disconnects, failures,
the current fixed connection phase, operations admission counters, and
aggregate multiplexed transport occupancy/capacity. `HEAD` is supported; other
methods return `405` and unknown paths return `404`.

The endpoint is disabled by default, rejects non-loopback addresses, closes
after one HTTP/1.1 request, and has explicit connection/header/request/drain
bounds. An operations bind failure stops startup before the Agent dials Edge.
During orderly shutdown readiness becomes false first; the endpoint remains
available while Agent-owned supervisors drain and is stopped last. Metrics do
not contain AgentId, TunnelId, addresses, session IDs, certificates, secrets,
or traffic payloads. Do not expose this unauthenticated endpoint through a
public port forward. Collection and alert guidance is in
[`OPERATIONS.md`](OPERATIONS.md).

## 21. Running the Control Plane operations endpoint

Add the optional operations flags to `tunnelproxy-control-plane serve`:

```text
tunnelproxy-control-plane serve \
  ... \
  --ops-listen 127.0.0.1:9092 \
  --max-ops-connections 8 \
  --ops-header-timeout-ms 2000 \
  --ops-request-timeout-ms 5000
```

`GET /healthz` returns `200` while the listener runs. `GET /readyz` returns
`200` only when durable authority, snapshot distribution, and optional
enrollment are live; drain returns `503`. `GET /metrics` emits process-local
Prometheus text for snapshot, refresh, enrollment, reconciliation, and
operations admission. `HEAD` is supported; other methods return `405` and
unknown paths return `404`.

The endpoint is disabled by default, accepts loopback addresses only, closes
after one bounded HTTP/1.1 request, and performs no SQLite query during a
scrape. Do not expose it through a public port forward. Metrics exclude IDs,
addresses, database paths, fingerprints, digests, tokens, certificates, keys,
and protocol payloads.

## 22. Administering the durable HTTPS route catalog

The Control Plane CLI stores exact HTTPS hostname routes in the same SQLite
database used by the durable authority, while keeping catalog versions
independent from authorization snapshot versions:

```text
tunnelproxy-control-plane https-route-upsert \
  --database state.sqlite \
  --hostname Demo.Example.test. \
  --tunnel-id tunnel-a \
  --status enabled

tunnelproxy-control-plane https-route-list --database state.sqlite

tunnelproxy-control-plane https-route-remove \
  --database state.sqlite \
  --hostname demo.example.test
```

Hostnames are canonicalized to lowercase without a trailing dot. Wildcards,
IP literals, ports, non-ASCII names, invalid DNS labels, and names over the DNS
length limits are rejected with exit code 2 before the database is opened.
Successful mutations print `catalog_version=<n> changed=true|false`; repeated
identical upserts and absent removals are successful no-ops. Listing prints the
catalog version followed by routes in deterministic hostname order. Repository
failures use exit code 1 and do not expose the database path.

The catalog is capped at 64 records and mutations are transactional. Static
Edge routing continues to support explicit `--https-host` and `--tunnel-id`.

## 23. Distributing HTTPS routes to Edge

Enable the independent authenticated route listener on the Control Plane:

```text
tunnelproxy-control-plane serve \
  --database state.sqlite \
  --listen 127.0.0.1:7200 \
  --https-route-listen 127.0.0.1:7201 \
  --tls-cert control-plane.pem \
  --tls-key control-plane-key.pem \
  --edge-client-ca edge-client-ca.pem
```

Dynamic HTTPS Edge mode reuses the snapshot client trust identity but connects
to the route listener with its separate ALPN:

```text
tunnelproxy-edge \
  --https-listen 127.0.0.1:8443 \
  --https-route-server 127.0.0.1:7201 \
  --https-route-max-stale-ms 300000 \
  --max-agent-sessions 8 \
  --public-tls-cert public.pem \
  --public-tls-key public-key.pem \
  --snapshot-server 127.0.0.1:7200 \
  --snapshot-ca control-plane-ca.pem \
  --snapshot-client-cert edge-client.pem \
  --snapshot-client-key edge-client-key.pem \
  --snapshot-server-name control-plane.internal \
  --tls-cert edge.pem \
  --tls-key edge-key.pem \
  --tls-client-ca agent-ca.pem
```

`--https-host` and `--https-route-server` are mutually exclusive. Dynamic
mode requires snapshot authorization because distributed records may target
multiple authenticated tunnels. `--max-agent-sessions` bounds how many of
those tunnels may be connected concurrently. Edge must bootstrap both streams online before
binding; route state has no cold-start disk cache. During a route-service
outage the last authenticated catalog remains usable only until the stale
deadline, then every host fails closed until mutual-TLS recovery.
Route-stream reload is opt-in and independent of snapshot reload even though
the runnable processes reuse the same PEM path flags. Add
`--https-route-tls-reload-manifest <path>` to both commands. Publish all PEM
bytes first and each matching manifest last. Snapshot and route manifests have
their own monotonic generation numbers and supervisors; every route candidate
is rebuilt with `tunnelproxy-https-routes/1`, while snapshot candidates retain
their snapshot ALPN. A rejected route generation leaves the active generation
serving, and expiry without a valid replacement terminates the process
supervisor. Existing authenticated connections are not renegotiated; the next
connection or normal reconnect uses the new generation.

## 24. Allocating and releasing managed HTTPS hostnames

Session 39 adds an operator-invoked lifecycle on top of the durable route
catalog. Supply a base domain that already has wildcard DNS and TLS coverage:

```text
tunnelproxy-control-plane https-hostname-allocate \
  --database state.sqlite \
  --base-domain tunnelproxy.dev \
  --tunnel-id tunnel-a
```

Successful first allocation prints one DNS-safe hostname plus the new catalog
version:

```text
hostname=tp-<32-lowercase-hex>.tunnelproxy.dev catalog_version=7 changed=true
```

The label contains 128 bits from the operating-system random source. The
allocator checks the complete hostname against the catalog and retries a
collision at most 16 times. One TunnelId owns at most one managed hostname.
Repeating the command with the same canonical base domain returns the same
hostname with `changed=false`; requesting a different base domain is an
explicit conflict and requires release first.

Release by durable tunnel identity:

```text
tunnelproxy-control-plane https-hostname-release \
  --database state.sqlite \
  --tunnel-id tunnel-a
```

Allocation/release, route content, and catalog version are one immediate
SQLite transaction. A release removes the route and advances the catalog once;
an absent release returns `hostname=- ... changed=false`. The existing route
distribution supervisor publishes effective mutations to Edge without a
restart. `https-route-upsert` and `https-route-remove` reject managed names so
generic administration cannot silently steal or delete lifecycle ownership.
Routes created before Session 39 migrate as operator-owned routes.

This command does not create DNS records or certificates. Keep wildcard
DNS/TLS provisioning, base-domain policy, and direct database access under
operator control.

## 25. Running the authenticated Agent hostname service

Enable route distribution and the dedicated hostname listener together. The
snapshot database must already contain the Agent certificate fingerprint and
enabled AgentId/TunnelId grant:

```text
tunnelproxy-control-plane serve \
  --database state.sqlite \
  --listen 127.0.0.1:7200 \
  --https-route-listen 127.0.0.1:7201 \
  --hostname-listen 127.0.0.1:7400 \
  --hostname-base-domain tunnelproxy.dev \
  --hostname-agent-ca agent-ca.pem \
  --tls-cert control-plane.pem \
  --tls-key control-plane-key.pem \
  --edge-client-ca edge-ca.pem
```

Allocate from the authenticated Agent identity:

```text
tunnelproxy-agent hostname-allocate \
  --hostname-server 127.0.0.1:7400 \
  --hostname-ca control-plane-ca.pem \
  --hostname-server-name control.tunnelproxy.test \
  --tls-client-cert agent.pem \
  --tls-client-key agent-key.pem \
  --agent-id agent-a \
  --tunnel-id tunnel-a
```

Use the same arguments with `hostname-release` to remove it. Success prints
`hostname`, `catalog_version`, and `changed`. A wrong certificate/AgentId/
TunnelId binding is rejected even when TLS trust succeeds. The Agent cannot
override `--hostname-base-domain`. The service commits the mutation and
publishes the durable catalog to live route subscribers before responding.

These manual commands do not start the tunnel, inspect a local port, change
DNS, or issue public certificates. Session 42 composes allocation with the
existing Agent runtime through the separate `http <port>` command.

## 26. Rotating hostname-service TLS without restart

Session 41 gives the Agent hostname listener its own optional digest manifest.
The hostname certificate/key may remain the shared `--tls-cert`/`--tls-key`
paths, or use independent paths:

```text
tunnelproxy-control-plane serve \
  --database state.sqlite \
  --listen 127.0.0.1:7200 \
  --https-route-listen 127.0.0.1:7201 \
  --hostname-listen 127.0.0.1:7400 \
  --hostname-base-domain tunnelproxy.dev \
  --hostname-agent-ca hostname-agent-ca.pem \
  --hostname-tls-cert hostname-server.pem \
  --hostname-tls-key hostname-server-key.pem \
  --hostname-tls-reload-manifest hostname-tls.json \
  --tls-cert control-plane.pem \
  --tls-key control-plane-key.pem \
  --edge-client-ca edge-ca.pem
```

The manifest uses the shared strict schema and exactly these logical names:

```json
{
  "generation": 2,
  "files": {
    "server_certificate": "<sha256-hex>",
    "server_private_key": "<sha256-hex>",
    "client_ca": "<sha256-hex>"
  }
}
```

Write and synchronize all three PEM files first, then atomically replace the
manifest last. A valid higher generation changes only new TLS handshakes.
Invalid PEM, incompatible key/certificate, stale generation, unexpected file
set, or digest mismatch keeps the prior generation active and marks reload
health failed. If that last-known-good server certificate expires before a
valid replacement is published, the Control Plane supervisor exits non-zero
and releases its listeners.

The manual Agent commands are one-shot clients and read their
CA/certificate/key files on every invocation. The managed HTTP command also
performs exactly one hostname request at startup; the long-running Edge
transport retains its existing independent TLS reload supervisor. During Agent
CA rotation, publish an overlap bundle when both old and new credentials must
be accepted temporarily; publish the new-only bundle when the overlap ends.

## 27. Running one managed HTTP Agent process

Prerequisites remain operator-owned: wildcard DNS must direct the configured
base domain to Edge, public TLS must cover that wildcard, Control Plane route
distribution and hostname services must be live, and the Agent certificate
must authorize the exact AgentId/TunnelId pair.

```text
tunnelproxy-agent http 3000 \
  --edge edge.example.test:7100 \
  --hostname-server control.example.test:7400 \
  --hostname-ca control-plane-ca.pem \
  --hostname-server-name control.example.test \
  --tls-ca edge-ca.pem \
  --tls-client-cert agent.pem \
  --tls-client-key agent-key.pem \
  --tls-server-name edge.example.test \
  --agent-id agent-a \
  --tunnel-id tunnel-a
```

`http <port>` accepts only a non-zero TCP port and always targets
`127.0.0.1:<port>`; combining it with `--local` is rejected. Complete Edge
mTLS and hostname-service inputs are mandatory. All runtime, TLS, enrollment,
operations-listener, and reconnect configuration is validated before the
hostname mutation. The command then allocates or reuses the durable hostname,
starts the normal Agent supervisor, and prints exactly one mapping after the
Agent reaches `Connected`:

```text
https://tp-0123456789abcdef0123456789abcdef.tunnelproxy.dev -> http://127.0.0.1:3000
```

Human or JSON operational logs remain on stderr. The stdout line means the
Control Plane accepted and published the hostname and Edge accepted Protocol
v2 registration; it is not a DNS, public-certificate, or external
reachability probe. Ctrl-C, reconnect, a missing local service, and terminal
runtime errors do not release the hostname. Repeating the command reuses the
same hostname without advancing the catalog version. Use the explicit
`hostname-release` command when permanent withdrawal is intended.

## 28. Using the canonical Agent CLI and local config

Session 43 installs `tunnelproxy` as the canonical executable while retaining
`tunnelproxy-agent` as a compatibility wrapper over the same driver. Existing
long-form commands therefore keep their parsing, exit codes, stderr logging,
and stdout contracts.

Create a strict config v1 as described in `docs/AGENT_CONFIG.md`, then validate
its schema, paths, identifiers, addresses, and both TLS client configurations
without opening a network connection:

```text
tunnelproxy config validate --config ./config.json
```

After validation, expose the loopback service with the shorter command:

```text
tunnelproxy http 3000 --config ./config.json
```

Explicit CLI values override fields from the selected file. Relative CA,
certificate, and key paths resolve from the directory containing that file,
not from the current working directory. `--config` overrides
`TUNNELPROXY_CONFIG`, which overrides the platform default. A missing explicit
or environment-selected file is always an error; a missing platform-default
file is ignored only when the complete managed HTTP identity and mTLS input is
provided explicitly on the CLI.

The file stores credential paths, never inline PEM or token bytes. Keep it and
the referenced private key readable only by the intended local account. This
feature does not provision accounts, DNS, or wildcard certificates. Session 51
can verify operator-provisioned public reachability before printing the URL:

```text
tunnelproxy http 3000 --config ./config.json \
  --verify-public-reachability \
  --public-reachability-timeout-ms 30000
```

Public Web PKI roots are used by default. For local/private PKI add
`--public-reachability-ca ./public-ca.pem`. Config validation parses that CA
and validates all bounds offline without DNS, socket, hostname allocation, or
other external mutation. The probe starts only after the Agent tunnel is
routable, retries within one finite deadline, and is cancellation-aware.
Failure returns exit code 1 without releasing the durable hostname.

To continue checking after startup, add a fixed delay and optional consecutive
failure threshold:

```text
tunnelproxy http 3000 --config ./config.json \
  --verify-public-reachability \
  --public-reachability-monitor-interval-ms 60000 \
  --public-reachability-failure-threshold 3
```

The delay starts after the preceding attempt finishes, so probes cannot
overlap. Background failure is health data rather than a process error;
`/readyz` becomes `503` only at the threshold and recovers on the next valid
proof. A reconnect returns monitored readiness to pending until a new proof.

## 29. Enabling bounded HTTP/2 at Edge

HTTP/1.1 remains the default. Enable HTTP/2 only on an HTTPS listener and keep
the existing public-listener authorization/admission requirements:

```text
tunnelproxy-edge \
  --https-listen 0.0.0.0:443 \
  --https-route-server control.example.test:7201 \
  --public-tls-cert wildcard.pem \
  --public-tls-key wildcard-key.pem \
  --allow-public-https-ingress \
  --max-http-connections 32 \
  --max-http-connections-per-ip 4 \
  --enable-http2 \
  --max-http2-concurrent-streams 32 \
  --http2-keepalive-interval-ms 30000 \
  --http2-keepalive-timeout-ms 10000 \
  <snapshot, route, and Agent mTLS options>
```

When enabled, public TLS advertises `h2` followed by `http/1.1`; the same order
is retained by atomic TLS reload. HTTP/1.1 clients continue to work. HTTP/2
stream concurrency is capped at 128 and the configured stream cap also bounds
pending/local reset state. The existing header, body, request deadline,
rate-limit, connection/per-IP, duplex, and drain settings continue to apply.

HTTP/2 is terminated at Edge. Requests are canonicalized, stripped of
hop-by-hop and untrusted forwarding fields, then sent through the existing
tunnel as HTTP/1.1 to the local application. This session does not enable h2c,
HTTP/2 to localhost, HTTP/2 WebSocket/extended CONNECT, CONNECT, or HTTP/3.

## 30. Enabling bounded HTTP/1.1 WebSocket upgrades at Edge

WebSocket remains disabled unless it is explicitly enabled on an HTTPS
listener. The session cap must be no larger than the existing HTTPS connection
cap, and both the cap and idle deadline require the opt-in flag:

```text
tunnelproxy-edge \
  --https-listen 0.0.0.0:443 \
  --https-route-server control.example.test:7201 \
  --public-tls-cert wildcard.pem \
  --public-tls-key wildcard-key.pem \
  --allow-public-https-ingress \
  --max-http-connections 32 \
  --max-http-connections-per-ip 4 \
  --enable-websocket-upgrade \
  --max-websocket-sessions 16 \
  --websocket-idle-timeout-ms 60000 \
  <snapshot, route, and Agent mTLS options>
```

The public request must use HTTP/1.1 GET, WebSocket version 13, one canonical
16-byte Base64 key, no body, and no extension offer. Host, TLS SNI, and route
selection follow the normal exact-match policy. Existing request-rate admission
runs before the WebSocket session permit is acquired. Edge removes spoofed
forwarding and hop-by-hop fields, then reconstructs the validated upgrade for
the local HTTP/1.1 service.

The local service must return `101 Switching Protocols`, matching
Connection/Upgrade tokens and `Sec-WebSocket-Accept`, no extension response,
and at most one subprotocol that the client offered. Any malformed local `101`
becomes `502`; a non-`101` response remains an ordinary bounded HTTP response.
After upgrade, Edge relays bytes without parsing WebSocket frames. Activity in
either direction resets the idle deadline. Shutdown lets the session close only
within the configured Edge drain timeout before force cleanup.

This option does not enable CONNECT, RFC 8441 extended CONNECT, WebSocket over
HTTP/2, compression/extensions, h2c, or HTTP/3.

## 31. Enabling bounded route-bound HTTP/1.1 CONNECT at Edge

CONNECT remains disabled unless explicitly enabled. Its session cap cannot
exceed the HTTPS connection cap. The authority port is an Edge policy value,
not a destination chosen by the client:

```text
tunnelproxy-edge \
  --https-listen 0.0.0.0:443 \
  --https-route-server control.example.test:7201 \
  --public-tls-cert wildcard.pem \
  --public-tls-key wildcard-key.pem \
  --allow-public-https-ingress \
  --max-http-connections 32 \
  --max-http-connections-per-ip 4 \
  --enable-connect \
  --max-connect-sessions 16 \
  --connect-idle-timeout-ms 60000 \
  --connect-authority-port 443 \
  <snapshot, route, and Agent mTLS options>
```

A request must be HTTP/1.1 authority-form CONNECT with matching
`Host: <route-host>:<configured-port>` and TLS SNI. Schemes, paths, a missing or
different port, bodies, transfer encoding, and WebSocket/Upgrade headers are
rejected before tunnel creation. The exact cached hostname route and normal
request-rate admission run unchanged.

Edge returns `200 OK`, then relays opaque bytes to the route's already
configured Agent local target. It never dials the requested authority and does
not forward CONNECT as HTTP to the local application. Activity in either
direction resets the idle deadline; graceful shutdown is bounded by the normal
Edge drain timeout. This option does not enable an arbitrary forward proxy,
classic or extended HTTP/2 CONNECT, RFC 8441 WebSocket, h2c, or HTTP/3.

## 32. Enabling bounded route-bound classic HTTP/2 CONNECT at Edge

Classic h2 CONNECT is a separate policy layered on the existing bounded HTTP/2
listener. It uses the same CONNECT limit, idle timeout, and authority port as
HTTP/1.1, but either protocol may be enabled independently:

```text
tunnelproxy-edge \
  --https-listen 0.0.0.0:443 \
  --https-route-server control.example.test:7201 \
  --public-tls-cert wildcard.pem \
  --public-tls-key wildcard-key.pem \
  --allow-public-https-ingress \
  --max-http-connections 32 \
  --max-http-connections-per-ip 4 \
  --enable-http2 \
  --max-http2-concurrent-streams 32 \
  --enable-http2-connect \
  --max-connect-sessions 16 \
  --connect-idle-timeout-ms 60000 \
  --connect-authority-port 443 \
  <snapshot, route, and Agent mTLS options>
```

The request must be classic HTTP/2 CONNECT with authority
`<route-host>:<configured-port>`, matching TLS SNI and any optional Host field.
Client DATA becomes opaque tunnel bytes only after cached-route, rate, and
shared CONNECT admission succeeds. Half-close and reset stay scoped to that h2
stream; multiple accepted CONNECT streams may share one connection.

The classic CONNECT flag does not advertise RFC 8441 extended CONNECT; that
requires the separate HTTP/2 WebSocket policy below. It also does not enable
arbitrary forward-proxy dialing, h2c, or HTTP/3. Removing `--enable-http2-connect`
restores the previous HTTP/2 behavior without changing route, Agent, or Tunnel
Protocol state.

## 33. Enabling bounded RFC 8441 WebSocket at Edge

RFC 8441 is a separate policy layered on bounded HTTP/2. It shares WebSocket
capacity and idle tuning with the HTTP/1.1 upgrade surface:

```text
tunnelproxy-edge \
  --https-listen 0.0.0.0:443 \
  --https-route-server control.example.test:7201 \
  --public-tls-cert wildcard.pem \
  --public-tls-key wildcard-key.pem \
  --allow-public-https-ingress \
  --max-http-connections 32 \
  --max-http-connections-per-ip 4 \
  --enable-http2 \
  --max-http2-concurrent-streams 32 \
  --enable-http2-websocket \
  --max-websocket-sessions 16 \
  --websocket-idle-timeout-ms 60000 \
  <snapshot, route, and Agent mTLS options>
```

The public request must use extended CONNECT with `:protocol = websocket`,
`:scheme = https`, a path, exact authority/SNI agreement, version 13, and no
key/accept, connection-specific, body-framing, or extension fields. Edge
generates the HTTP/1.1 WebSocket key used only for the sanitized local GET
Upgrade handshake, validates the local `101`, then returns HTTP/2 `200` and
relays frames opaquely.

HTTP/1.1 and HTTP/2 WebSockets may be enabled independently or together. When
both are enabled they share one session cap; HTTP/2 streams also remain bounded
by the connection's normal concurrent-stream limit and GOAWAY/drain ownership.
This does not enable extension negotiation, non-WebSocket extended CONNECT,
h2c, HTTP/3, destination dialing, or any Agent/Tunnel Protocol change.

## 34. Generating and enabling signed access URLs

Generate one offline signer and its Edge public-key ring:

```text
tunnelproxy-control-plane signed-access-keygen --key-id 1 --private-key-output signed-access-private.json --public-keyring-output signed-access-public.json
```

Keep the private file off Edge. Start Edge HTTPS with
`--require-signed-access --signed-access-keyring signed-access-public.json` and
optionally tune `--signed-access-max-ttl-seconds` (default 3600) and
`--signed-access-clock-skew-seconds` (default 30). This mode cannot be combined
with either classic CONNECT flag.

Issue a URL without contacting a running Control Plane:

```text
tunnelproxy-control-plane sign-access-url --private-key signed-access-private.json --url https://demo.example.test/path --ttl-seconds 300
```

The existing query is preserved, while any pre-existing exact `tp_access`
parameter is rejected. A valid token is reusable until expiry and is removed
before the request reaches the local application.

### Rotating the Edge public-key ring without restart

Create the next signer while retaining the active public key for an overlap
generation:

```text
tunnelproxy-control-plane signed-access-keygen --key-id 2 --private-key-output signed-access-private-2.json --public-keyring-output signed-access-overlap.json --existing-public-keyring signed-access-public.json
```

Publish the validated keyring before its manifest commit marker:

```text
tunnelproxy-control-plane signed-access-keyring-publish --source-keyring signed-access-overlap.json --keyring-output signed-access-active.json --reload-manifest-output signed-access-generation.json --generation 2
```

Start Edge with `--signed-access-keyring signed-access-active.json` and
`--signed-access-keyring-reload-manifest signed-access-generation.json`, then
optionally set `--signed-access-reload-interval-ms` (default 1000). Generation
numbers must be non-zero and strictly increase. After issuers have moved to
key 2 and the maximum old-token lifetime has elapsed, publish a key-2-only
ring at generation 3. At most eight keys may overlap.

## 35. Running a bounded multi-tunnel Agent process

Create config v2 as documented in `docs/AGENT_CONFIG.md`. The shared identity
must be authorized for every listed TunnelId, and Edge must allow at least the
same number of Agent sessions. Validate the whole profile without network I/O:

```text
tunnelproxy config validate --config ./config-v2.json
```

Then start all managed HTTP tunnels:

```text
tunnelproxy start --config ./config-v2.json
```

The profile accepts 1â€“16 unique TunnelIds and non-zero local ports. Each entry
runs the existing reconnecting Agent runtime on its own transport, so no
Tunnel Protocol change is involved. Shared CLI flags may override shared
endpoint, identity, TLS, reconnect, operations, and reachability settings;
`--local`, `--tunnel-id`, and `--enroll-only` are rejected in this mode.

For local validation, run two HTTP servers on the configured loopback ports,
set Edge `--max-agent-sessions` to at least two, and verify both printed public
hostnames return their corresponding response bodies. Restart Edge to exercise
reconnect. `/readyz` must remain false until the full configured set and any
public proofs are ready; terminal failure of one child drains the process.
Config v1 remains the rollback path through `tunnelproxy http <port>`.
