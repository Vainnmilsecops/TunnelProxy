# Agent Enrollment and Renewal

Session 21 adds an opt-in credential lifecycle for Agents using dynamic Control
Plane snapshots. It does not change Tunnel Protocol v2 or the snapshot protocol.

## Trust model

- The Agent generates its ECDSA P-256 private key and CSR locally. The private
  key is never sent to the Control Plane.
- Enrollment uses server-authenticated TLS with ALPN
  `tunnelproxy-enroll/1`. Bootstrap does not require a client certificate.
- A bootstrap token is 256 random bits, stored only as SHA-256 in SQLite, bound
  to one `AgentId` and one `TunnelId`, and expires at a configured time.
- The Control Plane issuer CA signs short-lived client-auth-only leaves. The
  configured lifetime is non-zero and at most 30 days.
- Successful issuance atomically stores the credential record, consumes a
  bootstrap token when applicable, and publishes the new certificate
  fingerprint in the same SQLite transaction as the next full snapshot.
- The Agent publishes CA, certificate, and private-key files before publishing
  the strict Session 20 reload manifest. It activates the snapshot only after
  the running Agent observes the new TLS generation.
- During renewal, old and new fingerprints overlap until activation. Activation
  removes the predecessor in a later snapshot. Exact retries are idempotent.
- Every issuance has a bounded activation deadline. A supervised reconciler
  marks overdue requests expired and removes only the pending fingerprint; an
  active renewal predecessor and its token remain usable.
- Emergency revocation targets one exact Agent/Tunnel pair, invalidates its
  bootstrap and active renewal tokens, and removes its authorization through a
  durable full-snapshot transaction.

Bootstrap and renewal secrets are supplied only through files. `Debug`, errors,
and structured events do not include token or key bytes.

## Protocol

Each message has a 12-byte `TPE1` header: version, message type, two zero flag
bytes, and a big-endian payload length. Messages are capped at 64 KiB before
allocation. The request flow is:

```text
Agent                                Control Plane
  |-- Enroll(request, token, next token, IDs, CSR) -->|
  |<-- Issued(generation, leaf, Edge CA, fingerprint)-|
  |   validate key/cert/fingerprint; publish manifest |
  |-- Activate(request, next token, fingerprint) ---->|
  |<-- Activated(snapshot version) -------------------|
```

The Agent durably journals its request ID, next renewal token, private key, and
CSR before sending. A retry after either side crashes reuses that journal. The
Control Plane preflights token authorization before signing and returns the
durable certificate for an exact repeated request, including after a bootstrap
token was consumed.

## Operator workflow

Initialize the snapshot database first, then create a bound token:

```text
tunnelproxy-control-plane create-token \
  --database snapshots.sqlite \
  --agent-id agent-prod --tunnel-id tunnel-prod \
  --output secrets/agent-prod.token --ttl-ms 600000
```

Run the Control Plane snapshot service with the additional enrollment group:

```text
tunnelproxy-control-plane serve \
  --database snapshots.sqlite \
  --tls-cert control-plane.pem --tls-key control-plane-key.pem \
  --edge-client-ca edge-ca.pem \
  --enrollment-listen 0.0.0.0:7300 \
  --issuer-cert agent-issuer-ca.pem --issuer-key agent-issuer-ca-key.pem \
  --agent-server-ca edge-server-ca.pem \
  --enrollment-activation-grace-ms 600000 \
  --enrollment-reconcile-interval-ms 30000
```

The enrollment listener reuses the Control Plane server certificate/key for
server authentication. `--agent-server-ca` is the CA Agents must use to verify
the Edge server; it is public certificate material, not the Agent issuer.

Bootstrap the Agent credential files and manifest:

```text
tunnelproxy-agent --enroll-only \
  --agent-id agent-prod --tunnel-id tunnel-prod \
  --enrollment-server control-plane.internal:7300 \
  --enrollment-ca control-plane-ca.pem \
  --enrollment-server-name control-plane.internal \
  --enrollment-token secrets/agent-prod.token \
  --enrollment-pending secrets/agent-prod.pending \
  --tls-ca runtime/edge-ca.pem \
  --tls-client-cert runtime/agent.pem \
  --tls-client-key runtime/agent-key.pem \
  --tls-server-name edge.internal \
  --tls-reload-manifest runtime/agent-tls.json
```

Use the same enrollment arguments during the normal Agent run. The renewal
runtime polls certificate health and rotates when the active leaf enters the
configured `--renew-before-ms` window. Dynamic Edge authorization is required;
static Edge mode cannot consume these Control Plane snapshot mutations.

Inspect or revoke one exact identity without exposing token/certificate
material:

```text
tunnelproxy-control-plane credential-status \
  --database snapshots.sqlite \
  --agent-id agent-prod --tunnel-id tunnel-prod

tunnelproxy-control-plane revoke-agent \
  --database snapshots.sqlite \
  --agent-id agent-prod --tunnel-id tunnel-prod
```

The status command prints fingerprint, generation, lifecycle state, expiry,
activation deadline, terminal time, and snapshot version only. Repeating
revocation is safe. A running Control Plane observes the durable snapshot and
Dynamic Edge closes a matching active Agent session through normal snapshot
reconciliation.

## Deliberate boundaries

Issuer keys and token/output directories are trusted operator filesystem
boundaries. HSM/KMS custody, CA rollover, CRL/OCSP,
multi-Control-Plane consensus, and hostile local-filesystem defense are not
implemented. Emergency revocation here is snapshot/application authorization;
a CA-valid revoked leaf may still complete TLS before Edge rejects registration.
