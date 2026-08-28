# TunnelProxy Protocol v2 — Authenticated Tunnel Registration

> **Status:** Implemented in Session 15. Protocol v1 is not negotiated or
> silently downgraded; a v1 header returns `UnsupportedVersion(1)`.

## Transport precondition

Production Agent transport uses mutual TLS with ALPN `tunnelproxy/2`. Agent
validates the Edge CA and server name. Edge validates the client chain and
extracts the leaf certificate before reading any protocol frame. Plaintext is
available only for an explicit loopback development allowlist.

## Frame header

The 16-byte framing layout and 64 KiB payload ceiling are retained:

```text
Offset  Size  Field             Type      Value / Notes
0       4     Magic             [u8; 4]   "TPX1" protocol-family marker
4       1     Version           u8        2
5       1     Frame Type        u8        stable frame number
6       2     Flags             u16 BE    must be zero
8       4     Stream ID         u32 BE    0 control, >0 logical stream
12      4     Payload Length    u32 BE    at most 65,536
16      N     Payload           [u8; N]
```

The family magic remains `TPX1`; the explicit version byte is authoritative.
Unknown versions, frame types, flags, and invalid stream scope fail closed.

## Handshake

```text
Agent                                      Edge
  | HELLO(role = AGENT)                     |
  |---------------------------------------->|
  | REGISTER(AgentId, TunnelId)             |
  |---------------------------------------->|
  |                         authorize tuple |
  |                  reserve live TunnelId  |
  | REGISTERED(TransportSessionId)          |
  |<----------------------------------------|
```

Edge publishes the session only after TLS, REGISTER decoding, authorization,
duplicate-claim admission, and REGISTERED transmission all succeed.

### REGISTER payload

```text
Offset                      Field
0..2                        AgentId length, u16 big-endian
2..4                        TunnelId length, u16 big-endian
4..4+agent_length           AgentId UTF-8 bytes
remaining                   TunnelId UTF-8 bytes
```

Both identifiers contain 1–64 ASCII letters, digits, `-`, or `_`. The maximum
payload is 132 bytes. Declared lengths must consume the payload exactly;
truncation, trailing bytes, invalid UTF-8, empty IDs, oversized IDs, and unsafe
characters return `InvalidRegister`.

`AgentId` and `TunnelId` are durable domain identifiers. They are never
substituted for `TransportSessionId`, which remains a non-zero process-local
`u64` allocated for each successful connection.

### Authorization

For mutual TLS, Edge computes SHA-256 over the authenticated leaf certificate
DER and evaluates:

```text
certificate fingerprint -> AgentId -> TunnelId -> status
```

Each snapshot value is immutable and already present in Edge memory. Session 16
can atomically replace that cached value with a higher complete version.
Registration and per-connection route resolution perform no database or
network lookup.

Handshake rejection codes are two-byte big-endian values:

- `1` unexpected frame
- `2` invalid HELLO
- `3` invalid REGISTER
- `4` protocol violation
- `5` unauthorized Agent/certificate binding
- `6` unauthorized Tunnel
- `7` disabled Tunnel
- `8` Tunnel already has a live session

Only code 8 is retryable by Agent. All identity, authorization, and malformed
protocol failures are terminal.

## Established session

Heartbeat and bounded multiplexed stream frames retain their Session 09–14
numbers and payloads. Edge keeps both registries:

- `TransportSessionId -> session command sender` for stream ownership.
- `TunnelId -> live TransportSessionId` for durable route resolution.

A duplicate live `TunnelId` is rejected before REGISTERED. The claim is RAII
owned and releases on handshake failure, EOF, protocol failure, timeout, or
shutdown. Reconnect therefore receives a fresh `TransportSessionId` and
reattaches the same `TunnelId` only after the prior claim is gone.

Session 35 changes only local writer scheduling. DATA and END_STREAM frames are
admitted under one hard process-local bound, retain FIFO order per stream, and
are served round-robin between active streams. Control frames retain priority
with a bounded burst. Frame numbers, payloads, ALPN, and peer behavior are
unchanged; no credit/window field is negotiated on this protocol.

## Raw ingress behavior

The runnable raw listener defaults to loopback-only. Session 23 permits an
explicit public policy only with Agent mTLS, dynamic snapshot authorization,
and bounded global/per-IP active connection admission. It is configured with
`TunnelId`, binds before Agent availability, and stays bound across Agent
disconnect/reconnect. Each accepted socket resolves the current in-memory live
session. If no session exists, the socket is closed; no stale session is reused.

## Deliberate limits

- No protocol downgrade or simultaneous v1/v2 support.
- Protocol framing itself performs no database or control-plane lookup; durable
  snapshots and the external service are separate from this wire contract.
- No certificate issuance or managed PKI. Session 20 can reload operator-
  published TLS generations, and Session 16 authorization snapshots can revoke
  an exact Agent leaf.
- Public HTTPS/HTTP/1.1 termination and exact hostname routing are implemented
  at Edge in Session 25 by adapting HTTP to this existing byte-stream API; no
  frame or payload changed. Automatic hostname allocation, multiple tunnels per
  transport, multi-edge coordination, and interrupted-stream replay remain out
  of scope. Explicit opaque public raw TCP remains available under Session 23.
