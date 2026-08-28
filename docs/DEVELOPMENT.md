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

PowerShell:

```powershell
$env:TUNNELPROXY_LOG_FORMAT = "json"
$env:RUST_LOG = "info,tunnelproxy_edge=debug"
cargo run -p tunnelproxy-edge --bin tunnelproxy-edge -- --help
```

Bash:

```bash
TUNNELPROXY_LOG_FORMAT=json \
RUST_LOG=info,tunnelproxy_edge=debug \
cargo run -p tunnelproxy-edge --bin tunnelproxy-edge -- --help
```

Help and machine-readable command reports stay on stdout; events stay on
stderr. In JSON mode, invalid CLI arguments produce a JSON error event without
appending multiline usage text. Invalid `TUNNELPROXY_LOG_FORMAT` or `RUST_LOG`
stops the process with exit code 2 before CLI-driven listener binding or file
mutation. Never place tokens, keys, certificates, payloads, or traffic bodies
in filter directives or event fields.

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
