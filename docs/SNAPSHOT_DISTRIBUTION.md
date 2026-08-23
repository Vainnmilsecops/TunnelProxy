# Authorization Snapshot Persistence and Distribution

Sessions 17–18 turn the Session 16 in-process authorization source into a
durable, runnable cross-process surface. It remains entirely outside live
ingress.

## Durable authority

`SqliteSnapshotRepository` stores the latest complete state in three tables:

- `snapshot_head`: singleton non-zero version and 32-byte canonical digest.
- `snapshot_agents`: certificate fingerprint to durable Agent ID.
- `snapshot_tunnels`: certificate/tunnel pairs and enabled/disabled status.

A commit uses one SQLite `IMMEDIATE` transaction to replace grant rows and the
head. WAL, foreign keys, and `synchronous = FULL` are enabled. Equal version and
content is idempotent; a lower version or equal-version different content fails.
Reload reconstructs validated domain values and verifies the digest.

`PersistentSnapshotAuthority` requires an initialized repository. It performs
blocking repository work through Tokio's blocking pool, serializes commits, and
publishes to the bounded Session 16 watch channel only after commit succeeds.

## Wire channel

Snapshot traffic uses its own `TPS1` framed protocol version 1 and TLS ALPN:

```text
tunnelproxy-snapshot/1
```

It is intentionally separate from Agent ↔ Edge ALPN `tunnelproxy/2`. The
Control Plane requires an Edge client certificate, and Edge verifies the
Control Plane CA and server name. PEM key material is never included in Debug
or user-facing errors.

Each frame has a 12-byte header: four-byte magic, one-byte version, one-byte
message type, two zero flag bytes, and a four-byte big-endian payload length.
Payloads are capped at 1 MiB before allocation. Message types are:

- `Subscribe(last_applied_version)`: zero means no local snapshot.
- `Snapshot(version, complete_authority)`: replaces all prior grants.
- `UpToDate(version)`: server and Edge already hold the same version.
- `Error(code)`: invalid request, uninitialized repository, or client ahead.

Snapshots cap both agents and tunnels per agent at 4096 and use canonical
fingerprint/Tunnel ID ordering. Identifiers retain the common 1–64 safe-ASCII
contract.

## Edge lifecycle and cold-start cache

`SnapshotBootstrapClient::bootstrap` must authenticate and receive a complete
snapshot before returning an Edge subscription. The returned runtime owns the
stream and reconnect loop. Later complete snapshots feed the existing atomic
revocation path.

When the stream fails, source health becomes `Stale`, but the last snapshot is
not cleared. Reconnect sleeps and network/TLS/subscription operations are
bounded and cancellation-aware. Reconnect sends the last in-memory version;
`UpToDate` or a valid newer snapshot changes health back to `Live`.

Session 19 adds an explicit filesystem cache through
`SnapshotBootstrapClient::bootstrap_with_cache`. Online bootstrap is attempted
first. Connection failure/timeout may load a fresh cache, while TLS identity,
ALPN, protocol, server rejection, and version errors never fall back. The cache
uses immutable generation files containing format/version metadata, an
authentication timestamp, canonical payload, and SHA-256 digest. Edge writes
and synchronizes a new generation before publishing it, then removes older
generations. Temporary files are ignored after a crash.

Cached bootstrap begins as `Stale`. Its configured maximum age applies to both
cold startup and the running reconnect loop; expiry is terminal and the
snapshot-aware supervisor closes Edge listeners. Disk is touched only during
bootstrap or authenticated snapshot refresh, never while authorizing ingress.
The digest detects accidental corruption, not a malicious local administrator;
the Edge host and cache directory are inside the trust boundary.

## Operator workflow

Initialize or replace the complete durable authority with a strict manifest:

```text
tunnelproxy-control-plane import --database snapshots.sqlite --snapshot snapshot.json
```

Then run the mutually authenticated service:

```text
tunnelproxy-control-plane serve --database snapshots.sqlite \
  --tls-cert control-plane.pem --tls-key control-plane-key.pem \
  --edge-client-ca edge-ca.pem
```

The manifest contains a non-zero version and a complete `agents` array. It is
bounded to 1 MiB, rejects unknown fields and malformed fingerprints/IDs/status,
and uses the repository's stale/conflict/idempotency rules. The runtime refuses
uninitialized storage and periodically refreshes committed imports. There is no
delta operation: omission is revocation.

`SnapshotAwareEdgeRuntime` bootstraps before binding Edge listeners and then
supervises both the data plane and reconnecting snapshot client. The Edge CLI
selects exactly one authorization mode: plaintext loopback development, static
mTLS certificate authorization, or mTLS plus the complete snapshot flag group.

Sessions 18–19 do not include a general admin API, snapshot signing,
certificate rotation, or multi-edge consensus.
