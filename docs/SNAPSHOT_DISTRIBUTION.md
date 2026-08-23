# Authorization Snapshot Persistence and Distribution

Session 17 turns the Session 16 in-process authorization source into a durable,
cross-process library surface. It remains entirely outside live ingress.

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

## Edge lifecycle

`SnapshotBootstrapClient::bootstrap` must authenticate and receive a complete
snapshot before returning an Edge subscription. The returned runtime owns the
stream and reconnect loop. Later complete snapshots feed the existing atomic
revocation path.

When the stream fails, source health becomes `Stale`, but the last snapshot is
not cleared. Reconnect sleeps and network/TLS/subscription operations are
bounded and cancellation-aware. Reconnect sends the last in-memory version;
`UpToDate` or a valid newer snapshot changes health back to `Live`.

Session 17 does not include a runnable Control Plane daemon, admin mutation API,
Edge disk cache, certificate rotation, or multi-edge consensus.
