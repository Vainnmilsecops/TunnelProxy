# TunnelProxy Agent ↔ Edge Transport

> **Status:** Implemented through Session 14.
> **Scope:** This document describes the Agent ↔ Edge control transport and the
> bounded multiplexed raw-TCP transport. It does not describe public HTTP/TLS
> ingress or durable routing.

## Purpose

The Agent ↔ Edge transport is a persistent, protocol-aware TCP control
connection over which Agent and Edge establish an ephemeral transport
session and exchange heartbeat frames. It is the foundation for future
tunnel registration and stream multiplexing.

Session 09 carries bounded concurrent raw TCP streams over this transport.
It is not yet a public reverse-tunnel product surface.

## Topology

```
TunnelProxy Agent
   (outbound TCP + optional mTLS)
        |
        |   loopback plaintext or certificate-authenticated TLS
        v
TunnelProxy Edge
```

**INV-001 is strictly enforced:** the Agent initiates the connection.
Edge does not dial Agent.

## Security Status

Session 14 adds optional mutual TLS before Protocol v1. Agent validates the
configured Edge CA and DNS server name. Edge requires a client certificate
signed by its configured Agent CA, and requires ALPN `tunnelproxy/1`, before it
reads HELLO or publishes a session to the router. TLS negotiation has a
separate deadline and consumes the same bounded admission permit as protocol
handshake/session lifetime.

Plaintext remains available only when the runnable Agent and Edge endpoints are
loopback. mTLS authenticates possession of a CA-issued certificate; it does not
yet map that certificate to a durable `AgentId`, authorize a tunnel, rotate or
revoke certificates, or secure the future public HTTP ingress.

## Handshake Sequence

```
Agent                         Edge
  |                             |
  |---- TCP connect ------------>|
  |<=== mutual TLS + ALPN ======>|  (when configured)
  |                             |
  |---- HELLO(role=AGENT) ----->|
  |                             | (validate HELLO)
  |                             |
  |---- REGISTER -------------->|
  |                             | (validate REGISTER)
  |                             | (allocate TransportSessionId)
  |                             |
  |<--- REGISTERED(session_id) --|
  |                             |
  |    [SESSION ESTABLISHED]    |
  |                             |
  |<=== heartbeat + one stream ==>|
  |                             |
  |    [EOF or error]           |
  |                             |
```

The sequence is strict: HELLO must be first, REGISTER must be second.
Any deviation is a protocol violation and the connection is closed.

## Frame Payload Schemas

### HELLO

```
Frame type:  HELLO (0x01)
Stream ID:   0 (control)
Payload:     1 byte

byte 0:     peer role
              0x01 = AGENT
```

Unknown role bytes are rejected.

### REGISTER

```
Frame type:  REGISTER (0x02)
Stream ID:   0 (control)
Payload:     empty (0 bytes)
```

In Session 06, REGISTER means only: "register this TCP connection as an
ephemeral transport session." It does NOT mean: create a public tunnel,
allocate a hostname, authenticate a user, persist an Agent, or create a
durable `TunnelId`.

A non-empty REGISTER payload is a protocol violation.

### REGISTERED

```
Frame type:  REGISTERED (0x03)
Stream ID:   0 (control)
Payload:     8 bytes (big-endian)

bytes 0-7:  TransportSessionId (non-zero u64)
```

## TransportSessionId

A `TransportSessionId` is:

- **Process-local:** valid only within the Edge process that allocated it.
- **Ephemeral:** exists for the lifetime of the TCP connection.
- **Non-zero:** zero is reserved as invalid.
- **Not a durable identity:** it is NOT a `TunnelId`, `AgentId`, or
  `UserId`.
- **Monotonically allocated:** Edge uses an `AtomicU64` counter starting
  at 1. Wraparound after 2^64 allocations returns `None` (safe failure).

## Edge Handshake State Machine

```
TCP_ACCEPTED
    |
    | (semaphore permit acquired)
    v
AWAIT_HELLO
    |
    | timeout/EOF
    v
CLOSED

AWAIT_HELLO
    |
    | valid HELLO(role=AGENT)
    v
AWAIT_REGISTER
    |
    | timeout/EOF/wrong frame
    v
CLOSED

AWAIT_REGISTER
    |
    | valid REGISTER(empty)
    v
ESTABLISHED
    |
    | EOF or read error
    v
CLOSED
```

## Agent Handshake State Machine

```
DISCONNECTED
    |
    v
CONNECTING (TCP connect)
    |
    | connect error/timeout
    v
CLOSED

CONNECTING
    |
    | TCP connected
    v
HELLO_SENT
    |
    v
REGISTER_SENT
    |
    v
ESTABLISHED
    |
    | EOF or error
    v
CLOSED
```

## Bounded Admission

Edge limits concurrent Agent transport sessions using a `tokio::sync::Semaphore`
sized to `max_agent_sessions`. A permit is acquired **before the handshake
begins** and held until the connection closes. This ensures that slow or
malicious handshakes cannot exhaust capacity.

When capacity is exhausted, Edge closes the incoming TCP connection
immediately without sending any response.

## Handshake Timeout

The entire handshake (HELLO → REGISTER → REGISTERED) is bounded by
`handshake_timeout`. The timeout begins after TCP acceptance and ends
when REGISTERED is successfully sent.

**The handshake timeout does NOT limit the established session lifetime.**

Established sessions remain open until the Agent disconnects, an I/O error
occurs, or the heartbeat state machine detects a dead/invalid peer.

## Established Session Behavior

Session 07 adds Edge-initiated heartbeat:

1. Edge waits `heartbeat_interval` after establishment or a valid PONG.
2. Edge sends `PING` with a non-zero 8-byte big-endian sequence.
3. Agent validates the payload and returns `PONG` with the same sequence.
4. Edge requires the matching PONG within `pong_timeout`.
5. Timeout, malformed payload, mismatched sequence, unsolicited PONG, Agent-
   initiated PING, or any unsupported frame closes the session.

Only one PING may be outstanding. The first sequence is 1 and subsequent
sequences increase monotonically without wrapping to zero. On clean EOF the
session closes normally. The connection's semaphore permit is held until this
loop exits, so heartbeat timeout releases capacity through RAII.

## Session 08 Single-Stream Data Path

`SingleStreamEdgeRuntime` binds two loopback listeners: one for the existing
Agent handshake and one raw TCP ingress. It supports one connected Agent and
one active ingress stream, while allowing multiple streams sequentially on the
same transport. Configuration validation rejects non-loopback addresses because
this development runtime has no TLS or authentication.

1. Edge accepts an ingress socket and sends empty `OPEN_STREAM` with a new
   monotonic non-zero stream ID.
2. Agent connects to its configured local TCP service under a deadline.
3. Agent echoes empty `OPEN_STREAM` as acknowledgment, or sends
   `RESET_STREAM` on failure.
4. Both peers convert fixed-buffer TCP reads into binary `DATA` frames.
5. TCP EOF emits empty `END_STREAM`; the other direction remains open.
6. After both directions end, both state machines return to idle.

The application read buffer is 16 KiB and the protocol codec rejects frames
over 64 KiB before allocation. `stream_open_timeout` bounds acknowledgment and
`stream_idle_timeout` bounds an active stream with no application-data
progress. Heartbeat remains active during streaming. A concurrent second
ingress connection is closed immediately; multiplexing is deferred.

## Disconnect Semantics

- **Agent disconnects (EOF):** Edge observes EOF, releases the semaphore
  permit, and cleans up the session.
- **Edge disconnects:** The TCP connection is closed. Agent observes EOF
  or an I/O error.
- **Handshake violation:** Edge best-effort sends an ERROR frame, then
  closes the connection.
- **Heartbeat timeout or violation:** Edge best-effort sends an ERROR frame,
  shuts down its write side, closes the connection, and releases capacity.
- **Stream reset/failure:** Only the ingress/local stream is closed; a valid
  Agent transport returns to idle for a later sequential stream.
- **Transport disconnect during a stream:** Both stream sockets are dropped by
  ownership cleanup.

## ERROR Frame Payload

Handshake violations may return an ERROR frame before closing:

```
Frame type:  ERROR (0xFF)
Stream ID:   0 (control)
Payload:     2 bytes (big-endian)

bytes 0-1:  error code
              1 = UnexpectedFrame
              2 = InvalidHello
              3 = InvalidRegister
              4 = ProtocolViolation
```

During an established session, the same 2-byte ERROR payload carries a
state-dependent `HeartbeatErrorCode`: timeout (1), sequence mismatch (2),
unsolicited PONG (3), Agent PING not supported (4), invalid heartbeat payload
(5), or unexpected frame (6).

For malformed protocol input (bad magic, version, etc.), Edge logs the
error and closes without attempting an ERROR response.

## Reader/Writer Ownership

Session 09 keeps exactly one decoder and one writer actor per Agent transport:

- The handshake is sequential; no concurrent reads/writes during handshake.
- After establishment, the reader dispatches frames to bounded per-stream
  queues. Independent tasks own ingress/local sockets.
- One writer actor serializes bounded control and DATA queues. DATA and
  END_STREAM share FIFO order so half-close cannot overtake payload bytes.

## Configuration

### Edge (Agent Listener)

```rust
AgentListenerConfig {
    listen_addr: SocketAddr,      // default: 127.0.0.1:7100
    max_agent_sessions: usize,   // default: 50
    handshake_timeout: Duration,  // default: 10s
    heartbeat_interval: Duration, // default: 15s
    pong_timeout: Duration,       // default: 10s
}

MultiplexedEdgeConfig {
    security: EdgeTransportSecurity,
    // PlaintextLoopback or MutualTls(EdgeTlsConfig)
    // EdgeTlsConfig is built from server cert/key + trusted client CA PEM.
    // TLS handshake timeout is separate from Protocol v1 handshake timeout.
    // Other bounded multiplex fields omitted here.
}
```

The Session 08 vertical slice additionally uses:

```rust
SingleStreamEdgeConfig {
    agent_listener: AgentListenerConfig, // max_agent_sessions must be 1
    ingress_listen_addr: SocketAddr,     // loopback-only development ingress
    stream_open_timeout: Duration,       // default: 5s
    stream_idle_timeout: Duration,       // default: 60s
}
```

### Agent (Client)

```rust
connect(
    edge_addr: SocketAddr,
    connect_timeout: Duration,   // default: 5s
    handshake_timeout: Duration, // default: 10s
) -> ConnectOutcome

connect_with_security(
    edge_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    security: &AgentTransportSecurity,
) -> ConnectOutcome

AgentRuntimeConfig {
    security: AgentTransportSecurity,
    // PlaintextLoopback or MutualTls(AgentTlsConfig)
    // AgentTlsConfig is built from trusted Edge CA, client cert/key,
    // verified server name, and TLS handshake timeout.
    // Other runtime fields omitted here.
}

AgentSession::run_with_local_target(
    local_addr: SocketAddr,
    connect_timeout: Duration,
)
```

Session 09 adds `AgentSession::run_multiplexed(MultiplexedAgentConfig)` with
bounded stream and writer queues. Session 10 adds loopback
`RawIngressRouteManager` listeners above `EdgeSessionRouter`.
`open_stream_tracked` returns a completion handle so route permits remain held
until the logical stream closes. Removal stops accept, drains existing streams,
and cleans the route if its target ephemeral Agent session disconnects. No wire
protocol change was required.

Session 11 adds `run_until_shutdown` / `run_multiplexed_until_shutdown`
variants. Edge stops Agent and ingress admission first, then drains supervised
sessions under `RuntimeShutdownConfig`. During multiplexed drain, new routed
streams fail closed and Agent rejects new `OPEN_STREAM` frames with the existing
`SessionClosing` reset code. Shutdown introduces no wire-format change.

Session 12 composes the transport into `EdgeRuntime` and `AgentRuntime`. The
Edge entrypoint waits for one registered Agent before binding its loopback raw
route; the Agent entrypoint owns one outbound session. OS shutdown and startup
rollback remain process concerns and introduce no protocol changes.

Session 13 adds process-level recovery without changing Protocol v1.
`AgentRuntime` creates a fresh outbound handshake after transient transport
failure using bounded exponential backoff. Every successful handshake receives
a new ephemeral `TransportSessionId`. `EdgeRuntime` removes the route targeting
the disconnected session, keeps its Agent listener alive, and rebinds the same
configured loopback raw address after a replacement session registers. In-flight
streams are not replayed or migrated.

Session 14 wraps the byte stream in mutual TLS before the unchanged
HELLO → REGISTER → REGISTERED sequence. No Protocol v1 frame, payload, or type
number changed. A reconnect performs a fresh TCP, TLS, and Protocol v1
handshake. Certificate/identity rejection is terminal; transient transport
loss and TLS timeout remain retryable.

## What Is NOT Implemented

- Durable Agent identity/authorization and certificate-to-Agent mapping
- Certificate issuance, rotation, revocation, and hot reload
- Credit/window-based flow control and weighted scheduling
- Tunnel registration
- Public endpoint allocation
- Public HTTP/TLS ingress and hostname routing
- Durable identity (TunnelId, AgentId)
