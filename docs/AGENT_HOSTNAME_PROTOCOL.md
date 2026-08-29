# Agent Hostname Lifecycle Protocol

Session 40 adds a dedicated, bounded protocol for an authenticated Agent to
allocate or release its managed public hostname. It is not Tunnel Protocol v2
and carries no application traffic.

## Transport and authentication

- TCP protected by TLS 1.2/1.3 through rustls.
- ALPN is exactly `tunnelproxy-hostname/1`.
- Control Plane presents a server certificate verified by Agent against the
  configured server CA and DNS name.
- Agent presents a client certificate verified by Control Plane against the
  configured Agent CA.
- Control Plane hashes the peer leaf DER with SHA-256 and authorizes that exact
  fingerprint, AgentId, and enabled TunnelId against its current snapshot.
- One connection carries one request and one response. All phases have
  configurable non-zero deadlines and server admission is semaphore-bounded.
- Control Plane can opt into digest-manifest TLS generations containing the
  server certificate, server private key, and Agent client CA. Complete newer
  generations apply only to new handshakes; invalid candidates retain the
  last-known-good configuration and active server-certificate expiry is
  terminal.

## Frame

Every message starts with a 12-byte header:

```text
offset  size  field
0       4     magic "TPH1"
4       1     version 1
5       1     message type
6       2     reserved, must be zero
8       4     big-endian payload length
```

Payloads are capped at 1024 bytes. Strings use an unsigned big-endian 16-bit
byte length followed by canonical UTF-8 bytes. Unknown types, flags, error
codes, malformed identifiers/hostnames, zero catalog versions, inconsistent
release state, trailing bytes, and oversized inputs fail closed.

Message types are:

- `1 Allocate`: AgentId, TunnelId.
- `2 Release`: AgentId, TunnelId.
- `3 Allocated`: PublicHostname, non-zero catalog version, changed flag.
- `4 Released`: optional PublicHostname, non-zero catalog version, changed
  flag. `changed=true` requires a hostname; `changed=false` forbids one.
- `5 Error`: fixed code `InvalidRequest`, `Unauthorized`, `Conflict`,
  `Capacity`, or `Internal`.

## Mutation ordering

The request never carries a base domain. Control Plane owns the configured
canonical suffix and uses the durable Session 39 allocator. For an authorized
request, successful ordering is:

1. serialize with catalog refresh and other lifecycle mutations;
2. commit ownership, route, and catalog version atomically in SQLite;
3. reload and publish the complete durable catalog to live route subscribers;
4. send the success response.

Allocation retry is idempotent for the same TunnelId/base domain. Releasing an
absent allocation is a successful unchanged response. A success does not
provision DNS or certificates and does not imply a disconnected Edge has
already reconnected.
