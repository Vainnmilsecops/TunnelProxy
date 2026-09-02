# TunnelProxy Operations Runbook

This runbook describes operator-owned collection and interpretation of the
process-local metrics exposed by TunnelProxy. It does not make the operations
listeners public, add a remote-write client to the data path, or prescribe a
durable metrics backend.

## Collection topology

Agent, Edge, and Control Plane operations listeners are opt-in,
unauthenticated, and loopback-only. Run the collector in the same host or
network namespace as the TunnelProxy process. For containers, use a sidecar in
the same pod/network namespace. Do not publish or port-forward an operations
listener.

One node-local Prometheus-compatible collector can use targets such as:

```yaml
scrape_configs:
  - job_name: tunnelproxy-edge
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9090"]
  - job_name: tunnelproxy-agent
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9091"]
  - job_name: tunnelproxy-control-plane
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9092"]
```

Collection, retention, access control, encryption, remote write, dashboards,
and paging belong to that external collector/backend. Set retention to match
the operator's incident window. TunnelProxy counters and peak gauges reset on
every process restart, so use `rate()` or `increase()` rather than subtracting
raw samples across restarts.

## Transport capacity semantics

Agent and Edge export these fixed-cardinality gauges:

- `*_transport_data_pipeline_frames` is the number of admitted DATA or
  END_STREAM frames still owned by a writer pipeline.
- `*_transport_data_pipeline_capacity_frames` is the sum of configured DATA
  slots for live multiplex sessions in that process.
- Capacity is zero while no multiplex session is live. Agent reconnect and
  Edge multi-session aggregation update it through RAII.
- `*_transport_peak_data_pipeline_frames` is a process-lifetime high-water
  mark and therefore can remain above current live capacity after a session
  closes or reconnects with a smaller configuration.

For a single role, calculate current utilization only while capacity is
positive:

```promql
tunnelproxy_agent_transport_data_pipeline_frames
/
tunnelproxy_agent_transport_data_pipeline_capacity_frames
```

```promql
tunnelproxy_edge_transport_data_pipeline_frames
/
tunnelproxy_edge_transport_data_pipeline_capacity_frames
```

An absent result caused by division by zero means no live session, not a full
pipeline. Correlate it with `tunnelproxy_agent_ready` or
`tunnelproxy_edge_ready` and the connection/disconnect counters.

## Starting alert baseline

These thresholds are starting points, not protocol guarantees. Tune them from
normal workload history and keep identity such as AgentId, TunnelId, hostname,
peer address, or StreamId out of metric labels.

Sustained local pipeline pressure:

```promql
(
  tunnelproxy_agent_transport_data_pipeline_frames
  / tunnelproxy_agent_transport_data_pipeline_capacity_frames
) > 0.80
```

Use the equivalent Edge metrics and require the condition for at least ten
minutes. A short peak alone is expected backpressure.

Admission had to wait during the last five minutes:

```promql
increase(tunnelproxy_agent_transport_data_admission_waits_total[5m]) > 0
```

Locally initiated flow-control resets occurred:

```promql
increase(tunnelproxy_agent_transport_flow_control_resets_total[5m]) > 0
```

Repeat both queries with the `tunnelproxy_edge_` prefix. A reset is more
urgent than an admission wait because it closes one logical stream. An
increase in `*_transport_control_burst_yields_total` is not itself an error;
it shows that DATA fairness intervened while control traffic was continuously
ready.

Useful invariant alerts are:

```promql
tunnelproxy_agent_ready == 1
and
tunnelproxy_agent_transport_data_pipeline_capacity_frames == 0
```

```promql
tunnelproxy_edge_ready == 1
and
tunnelproxy_edge_transport_data_pipeline_capacity_frames == 0
```

## Capacity and protocol decision guide

1. If utilization is briefly high without admission waits or resets, take no
   action; bounded queuing is working as intended.
2. If utilization and admission waits remain high but resets and application
   latency remain acceptable, consider a measured increase to the local DATA
   queue capacity. Each slot can retain up to one 16 KiB DATA payload plus
   frame overhead, so validate the memory budget first.
3. If resets rise, inspect slow local services, stream idle timeouts, inbound
   per-stream queue pressure, and reconnects before enlarging the writer
   queue.
4. Consider peer-negotiated byte credits or deficit scheduling only when
   repeatable workload measurements show cross-stream latency/throughput
   interference after local bounds are tuned. Aggregate metrics alone do not
   prove byte unfairness.

Any protocol proposal must remain a separate session because it changes the
compatibility and failure model of Tunnel Protocol v2.

## Privacy and scrape safety

Operations scrapes read process-local atomic snapshots. They do not acquire a
live session lock, query SQLite, or perform remote backend I/O. Exported labels
use bounded enumerations only. Never add tokens, certificates, payloads,
hostnames, durable IDs, session IDs, stream IDs, or addresses as metric labels.

## Nonblocking process-log sink

Synchronous stderr is the compatibility default. For long-running processes,
enable the bounded worker documented in `DEVELOPMENT.md` so a slow local log
collector cannot block Tokio runtime tasks. The queue drops the newest event
when full, rejects any formatted event larger than 16 KiB, and drains only
within the configured shutdown deadline. A permanently blocked stderr writer
is detached at the deadline so process exit is not held indefinitely.

Every operations endpoint exports role-prefixed logging metrics:

- `*_logging_nonblocking_enabled`
- `*_logging_buffer_capacity_events`
- `*_logging_accepted_events_total`
- `*_logging_dropped_events_total`
- `*_logging_oversized_events_total`
- `*_logging_write_failures_total`

Alert on any new event loss or sink failure, using the appropriate
`tunnelproxy_agent_`, `tunnelproxy_edge_`, or `tunnelproxy_control_plane_`
prefix:

```promql
increase(tunnelproxy_edge_logging_dropped_events_total[5m]) > 0
or
increase(tunnelproxy_edge_logging_oversized_events_total[5m]) > 0
or
increase(tunnelproxy_edge_logging_write_failures_total[5m]) > 0
```

Queue capacity bounds event count, not total payload alone. The hard 16 KiB
event ceiling bounds queued payload memory to approximately
`capacity * 16 KiB`, plus one worker event and small formatting/channel
overhead. Increase capacity only after confirming the process memory budget.

The worker is not a durable spool. Collection, rotation, retention, encryption,
remote shipping, and access policy remain responsibilities of the local
collector and its operator-owned backend.

## Managed hostname prerequisites and rollback

Before allocation, provision wildcard DNS and a matching public certificate
for the chosen base domain. For `tunnelproxy.dev`, both
`*.tunnelproxy.dev` DNS and TLS coverage must already direct clients to the
Edge HTTPS listener. TunnelProxy does not modify DNS or request certificates.

Allocate only after the target TunnelId is present in the authorization
snapshot and the corresponding Agent can connect. The new route is enabled
immediately and is published by the existing Control Plane refresh loop:

```text
tunnelproxy-control-plane https-hostname-allocate \
  --database state.sqlite \
  --base-domain tunnelproxy.dev \
  --tunnel-id tunnel-a
```

Record the returned hostname and catalog version in the operator change log.
Repeating the same allocation is safe and returns `changed=false`. A collision,
catalog/version limit, entropy failure, database failure, or base-domain
conflict leaves both the route and catalog version unchanged.

Rollback with `https-hostname-release --database state.sqlite --tunnel-id
tunnel-a`. Release removes the route transactionally; after Edge observes the
new catalog version, exact-host routing fails closed. An absent release is a
successful no-op. Generic route upsert/remove commands intentionally reject a
managed hostname, so use the lifecycle command rather than editing its route.

Allocation hostnames and TunnelIds are operator-visible identity, not metric
labels. Do not add either to Prometheus labels or emit database paths through
failure messages. Protect database access because the operator commands remain
an administrative boundary. The Session 40 Agent service exposes only
allocate/release for the exact currently authorized certificate/AgentId/
TunnelId and a server-owned base domain; it is not a general remote admin API.

When the Agent hostname listener is enabled, keep `--hostname-agent-ca`
separate from the Edge client CA unless the deployment intentionally shares a
trust root. Bind it only on the intended control network, set
`--max-hostname-clients` and `--hostname-request-timeout-ms` for that network,
and monitor the fixed-cardinality `tunnelproxy_control_plane_hostname_*`
metrics. TLS rejection, authorization rejection, capacity rejection, and
failed mutation counters contain no AgentId, TunnelId, hostname, certificate,
or peer-address labels.

An Agent success means both the SQLite transaction and in-process route
publication completed. It does not prove that every disconnected Edge has
received the catalog, nor does it provision wildcard DNS or public TLS. During
rollback, issue `hostname-release`, record the returned catalog version, and
confirm Edge route-source/catalog metrics have advanced before considering the
hostname withdrawn everywhere.

### Managed HTTP Agent lifecycle

`tunnelproxy-agent http <port>` validates its complete runtime and TLS inputs,
binds any requested loopback operations listener, and only then requests the
managed hostname. It emits `managed_http_allocation_started`,
`managed_http_hostname_published`, and `managed_http_ready` structured events.
The stable public mapping is the only stdout output and appears after the Agent
transport becomes ready.

Do not interpret that stdout line as an external availability check. Alert and
debug the Control Plane route-source version, Edge route-source health, Agent
readiness, DNS, and public certificate separately. Allocation is durable:
normal shutdown, reconnect backoff, local-port refusal, and Agent runtime
failure intentionally leave the route present but fail closed while its tunnel
is offline. This makes restart URL-stable and avoids destructive rollback after
an ambiguous client failure. Permanent withdrawal remains an explicit
`hostname-release` operation.

### Multi-tunnel Agent lifecycle

Use config v2 with `tunnelproxy start --config <path>` to run 1â€“16 managed
HTTP tunnels in one process. Validate first, and configure the Edge
`--max-agent-sessions` ceiling at or above the number of profile entries. Each
entry consumes one independent Agent transport and its own per-transport
stream/queue capacity; size total capacity as the per-tunnel bounds multiplied
by the configured count.

Every tunnel allocates or reuses a durable hostname before runtime startup.
Partial allocation or later terminal failure does not release earlier routes;
use explicit `hostname-release` after diagnosis. Transient connection loss
uses only the affected child's reconnect loop. A terminal registration,
protocol, or reconnect-budget failure fails the process closed and drains all
siblings, preventing a service manager from treating a partially configured
set as healthy.

`/readyz` returns success only when every configured tunnel is ready, including
any enabled reachability proof. Use
`tunnelproxy_agent_{configured,ready}_tunnels` and the fixed state-count gauges
to identify aggregate loss without identity labels. `/healthz` remains process
liveness. URL mappings arrive independently on stdout as children become
ready; do not depend on config-order output. TLS reload, renewal, operations,
and shutdown are shared process owners, so one failure in those supervisors
also drains the set.

### Hostname TLS and Agent-CA rotation

Use an independent `--hostname-tls-reload-manifest` when the hostname endpoint
must rotate without a Control Plane restart. The generation binds
`server_certificate`, `server_private_key`, and `client_ca`; publish PEM files
before the matching manifest. Never increment the manifest before every file
is durable and its digest has been verified.

For a no-outage Agent CA change, first publish a CA bundle containing old and
new roots, migrate Agent credentials, then publish a higher generation with
only the new root. After that publication, new connections using the removed
CA fail at mTLS before a hostname request is parsed. Existing one-request
connections retain their negotiated generation only until that request ends.

Watch secret-safe `tls_reload_applied` and `tls_reload_health` events for the
new generation. `ReloadFailed` means last-known-good is still active; it is not
permission to ignore the failure because expiry of that active server leaf is
terminal and initiates ordered Control Plane shutdown. Roll back by restoring
the last valid three-file set and publishing it as a new, higher generation;
never lower or reuse a generation number.

### Canonical Agent config rollout

Use `tunnelproxy config validate --config <path>` as the preflight step before
starting or restarting a managed HTTP Agent. Validation is offline: it reads a
maximum of 64 KiB, rejects unknown or duplicate JSON fields and unsupported
versions, resolves relative credential paths from the config directory, and
parses both TLS client identities without connecting to Edge or Control Plane.

Treat the config directory as part of the credential trust boundary. An actor
who can replace the file can redirect the Agent or select different trust
roots and key paths. Apply restrictive file permissions, deploy referenced PEM
files before atomically replacing the config, and never place inline private
keys or tokens in the JSON. Validation errors and structured logs intentionally
omit file contents and secret values.

For migration, keep the existing `tunnelproxy-agent` invocation available as
a rollback path because it executes the same shared driver. Prefer an explicit
`--config` in service definitions; use `TUNNELPROXY_CONFIG` only when the
service manager owns the environment. Do not assume the platform-default file
exists. A successful validation proves local configuration integrity, not DNS,
public TLS, Edge catalog freshness, or external reachability.

### HTTP/2 rollout and rollback

Roll out `--enable-http2` on a canary Edge first. Confirm negotiated-protocol
counts, active/peak stream occupancy, request timeouts, rate-limit rejections,
Tunnel DATA saturation, and drain outcomes before increasing the default
32-stream cap. The hard supported cap is 128 streams per TLS connection;
global and per-IP connection admission still apply outside that bound.

Keep HTTP/2 keepalive enabled with non-zero interval and acknowledgement
timeout. A silent client is closed when the PING acknowledgement deadline is
missed. During shutdown, Edge sends graceful GOAWAY and waits for active
streams only until the configured ingress drain deadline. Forced shutdown is
observable through the existing runtime outcome.

TLS generation rotation must not change protocol policy: certificate and key
files are published before the manifest as usual, while the running Edge
rebuilds each generation with the startup ALPN list. Roll back HTTP/2 by
removing the opt-in and restarting Edge; clients then negotiate HTTP/1.1 only.
No route catalog, Agent credential, hostname allocation, or Tunnel Protocol
rollback is required.

### WebSocket rollout and rollback

Canary `--enable-websocket-upgrade` for HTTP/1.1 independently. Canary RFC 8441
with both `--enable-http2` and `--enable-http2-websocket`; neither WebSocket
flag enables the other protocol. Both surfaces share one session cap and finite
idle timeout, so size them for combined workload. Monitor
`tunnelproxy_edge_https_websocket_upgrades_total`,
`tunnelproxy_edge_https_websocket_rejections_total`,
`tunnelproxy_edge_https_active_websocket_sessions`, its peak gauge, idle
timeouts, the corresponding `http2_websocket` accepted/rejected/active/peak/idle
metrics, HTTPS connection occupancy, Tunnel DATA saturation, and forced drain
outcomes. None carries hostname, peer, ID, subprotocol, or payload labels.

An increase in `502` responses indicates the local service returned a malformed
upgrade response, a mismatched accept digest, an unoffered subprotocol, or an
extension. Capacity rejection returns `503`; increase the session cap only
after confirming HTTPS connection and Tunnel stream headroom. Idle timeout
closes the upgraded byte stream without closing the Agent transport or sibling
connections.

During shutdown, active WebSockets may finish until the normal Edge drain
deadline. HTTP/2 GOAWAY stops new streams while accepted RFC 8441 relays drain.
Stalled sessions are then force-aborted and release their route and session
permits together. Roll back one surface by removing
`--enable-websocket-upgrade` or `--enable-http2-websocket` and restarting Edge.
No TLS generation, route catalog, Agent credential, or Tunnel Protocol rollback
is required.

### CONNECT rollout and rollback

Canary `--enable-connect` for HTTP/1.1 independently from WebSocket and HTTP/2.
Canary classic h2 CONNECT separately with both `--enable-http2` and
`--enable-http2-connect`; neither CONNECT flag enables the other protocol.
Both protocols share one session cap, authority port, and finite idle timeout,
so size the cap for their combined workload. Monitor
`tunnelproxy_edge_https_connect_sessions_total`,
`tunnelproxy_edge_https_connect_rejections_total`,
`tunnelproxy_edge_https_active_connect_sessions`, its peak gauge,
`tunnelproxy_edge_https_connect_idle_timeouts_total`, HTTPS connection
occupancy, Tunnel DATA saturation, and forced drain outcomes.

For the h2 slice, additionally monitor
`tunnelproxy_edge_https_http2_connect_sessions_total`, its rejection counter,
active/peak gauges, and idle-timeout counter. A successful stream is classic
CONNECT carried by HTTP/2 DATA. This flag alone does not advertise RFC 8441;
when the separate HTTP/2 WebSocket flag is enabled, `:protocol=websocket` is
handled only by that policy and never becomes a classic CONNECT destination.
GOAWAY stops new streams while the bounded relay supervisor drains accepted
ones under the normal HTTPS deadline.

`400` indicates malformed authority/body/upgrade semantics, `421` indicates
Host/SNI fronting, `404` indicates no cached route, and `503` indicates session
or tunnel capacity/unavailability. CONNECT never uses the requested authority
as a dial target; it always reaches the fixed local target already owned by the
selected TunnelId. Roll back one surface by removing its corresponding
`--enable-connect` or `--enable-http2-connect` flag and restarting Edge.
Existing HTTP/1.1, WebSocket, ordinary HTTP/2, route, TLS, and Tunnel Protocol
state require no migration or rollback.

## Signed access URL rollout and rollback

Generate signing material offline, distribute only the public-key ring to Edge,
and canary `--require-signed-access` on one HTTPS listener. Keep token TTLs well
below the configured maximum and allow only the clock skew needed by measured
host synchronization. Monitor:

- `tunnelproxy_edge_https_signed_access_requests_total`
- `tunnelproxy_edge_https_signed_access_missing_rejections_total`
- `tunnelproxy_edge_https_signed_access_invalid_rejections_total`
- `tunnelproxy_edge_https_signed_access_expired_rejections_total`
- `tunnelproxy_edge_https_signed_access_keyring_generation`
- `tunnelproxy_edge_https_signed_access_keyring_reload_failed`
- `tunnelproxy_edge_https_signed_access_keyring_reload_successes_total`
- `tunnelproxy_edge_https_signed_access_keyring_reload_failures_total`
- the existing global/per-IP rate-limit rejection counters

Rate limiting precedes signature verification, so abusive invalid traffic is
still subject to the configured buckets. A spike in expired rejections usually
indicates stale links or clock drift; invalid rejections indicate corruption,
wrong hostname/key, or tampering. Roll back by removing
`--require-signed-access` and its key-ring/tuning flags, then restart Edge. Key
rotation uses an overlapping public ring (maximum eight keys) while issuers
move to the new non-zero key ID. With the reload manifest configured, publish
the keyring file first and the matching SHA-256 manifest last. Only a higher
generation activates; stale, conflicting, malformed, oversized, or
digest-mismatched candidates leave the last-known-good ring active and raise
the failure gauge/counter. Removing a key takes effect for new requests as
soon as that generation activates, so wait at least the old token TTL plus
clock skew before retiring it. Pre-expiry per-token revocation is not
implemented.

## Managed HTTP public reachability verification

Canary the opt-in Agent flag after wildcard DNS and public TLS are already
provisioned:

```text
tunnelproxy http 3000 --verify-public-reachability
```

For continuous monitoring, add for example
`--public-reachability-monitor-interval-ms 60000`. The interval is a delay
after each completed attempt, not a fixed-rate ticker, so slow attempts cannot
overlap. `--public-reachability-failure-threshold` defaults to 3. Failures below
the threshold are degraded but keep readiness available; reaching it makes
`/readyz` return `503`. A later valid proof recovers readiness without process
restart. Transport disconnect always makes readiness false, and monitored
reconnect remains pending until a fresh proof.

The Agent waits for Protocol v2 registration, then connects to the allocated
hostname on port 443, verifies SNI and the certificate chain, sends a fresh
bounded challenge, and accepts only the exact no-store proof from Edge. Edge
serves that well-known request only when Host/SNI map to a configured route and
the exact TunnelId is live. It passes through existing global/per-IP request
rate admission, bypasses signed URL verification only for this narrow endpoint,
and never opens a tunnel stream or forwards the challenge to localhost.

Monitor the Agent counters
`tunnelproxy_agent_public_reachability_{attempts,successes,timeouts,cancellations}_total`
and its fixed failure-class counters for TLS, connect, route, and protocol
failures. Edge exports
`tunnelproxy_edge_https_reachability_probe_{requests,successes,failures}_total`.
None has hostname, TunnelId, address, or challenge labels. Logs likewise omit
challenge/proof bytes.

Continuous monitoring additionally exports the fixed-label
`tunnelproxy_agent_public_reachability_state` gauge and counters/gauges for
monitor cycles, monitor failures, consecutive failures, unhealthy transitions,
and recoveries. Alert on sustained `state="unhealthy"` or an increasing
unhealthy-transition counter; use degraded as diagnostic context rather than a
paging condition.

DNS/connect failures usually indicate propagation or network policy; TLS
failures indicate trust/name/certificate issues; route failures indicate that
Edge has no live exact tunnel; protocol failures indicate interception,
misrouting, or an incompatible response. The default total deadline is 30
seconds and the maximum is five minutes. Roll back by removing the opt-in flag
or setting the optional config block to `enabled: false`; the default startup
contract remains registration-only. A timeout exits 1 and intentionally leaves
the durable hostname allocated for diagnosis and retry.
