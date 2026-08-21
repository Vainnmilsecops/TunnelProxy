# TunnelProxy Agent ↔ Edge Transport

> **Status:** Implemented (Session 06).
> **Scope:** This document describes the Agent ↔ Edge control transport
> layer established in Session 06. It does NOT describe tunnel traffic,
> stream multiplexing, or any data-plane forwarding.

## Purpose

The Agent ↔ Edge transport is a persistent, protocol-aware TCP control
connection over which Agent and Edge establish an ephemeral transport
session. It is the foundation for all future Agent ↔ Edge communication,
including tunnel registration, stream multiplexing, and heartbeat.

This transport does **not** implement reverse tunnel traffic. Traffic
forwarding will be layered on top in a future session.

## Topology

```
TunnelProxy Agent
   (outbound TCP)
        |
        |   127.0.0.1:7100 (development; loopback only)
        v
TunnelProxy Edge
```

**INV-001 is strictly enforced:** the Agent initiates the connection.
Edge does not dial Agent.

## Security Status

**This transport is unauthenticated and unencrypted in Session 06.**

The development listener binds `127.0.0.1` only. In production, this
transport requires TLS and Agent authentication before use. The README
and documentation do not describe this as a "secure tunnel" until those
features are implemented.

## Handshake Sequence

```
Agent                         Edge
  |                             |
  |---- TCP connect ------------>|
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
  |    ... future frames ...     |
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

Established sessions remain open until:
- The Agent disconnects (EOF).
- An I/O error occurs.
- A future session adds idle/liveness timeouts.

## Established Session Behavior

In Session 06, no traffic frames are implemented. After the handshake:

- Edge waits for any incoming byte or EOF.
- If any frame is received (e.g. DATA), it is logged as an unsupported
  frame and the session closes.
- If EOF is received, the session closes cleanly.

Future sessions will:
- Implement PING/PONG heartbeat.
- Implement OPEN_STREAM / DATA frames.
- Implement stream multiplexing.

## Disconnect Semantics

- **Agent disconnects (EOF):** Edge observes EOF, releases the semaphore
  permit, and cleans up the session.
- **Edge disconnects:** The TCP connection is closed. Agent observes EOF
  or an I/O error.
- **Handshake violation:** Edge best-effort sends an ERROR frame, then
  closes the connection.

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

For malformed protocol input (bad magic, version, etc.), Edge logs the
error and closes without attempting an ERROR response.

## Reader/Writer Ownership

Session 06 uses a simple sequential write / sequential read model:

- The handshake is sequential; no concurrent reads/writes during handshake.
- After establishment, Edge owns the socket in a single task that waits
  for incoming frames.

Future sessions that implement multiplexing will likely need explicit
reader/writer ownership (via `tokio::io::split` or `TcpStream::into_split`)
to allow concurrent frame processing.

## Configuration

### Edge (Agent Listener)

```rust
AgentListenerConfig {
    listen_addr: SocketAddr,      // default: 127.0.0.1:7100
    max_agent_sessions: usize,   // default: 50
    handshake_timeout: Duration,  // default: 10s
}
```

### Agent (Client)

```rust
connect(
    edge_addr: SocketAddr,
    connect_timeout: Duration,   // default: 5s
    handshake_timeout: Duration, // default: 10s
) -> ConnectOutcome
```

## What Is NOT Implemented

- TLS / encryption
- Agent authentication
- Heartbeat / PING-PONG timers
- Reconnect logic
- Stream multiplexing
- Tunnel registration
- Public endpoint allocation
- Traffic forwarding
- Durable identity (TunnelId, AgentId)
