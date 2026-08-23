# TunnelProxy Protocol v1 — Wire Framing

> **Status:** Implemented (Session 05).
> **Wire format is stable** once both peers speak v1.
> Payload schemas are intentionally left undefined until Agent ↔ Edge
> session behavior is designed.

## Purpose

TCP provides only an ordered byte stream. It does not preserve application
message boundaries — a single `read` may return a partial frame, multiple
frames, or a mixture of both.

Tunnel Protocol v1 introduces a fixed-size binary frame header that encodes
the length of each payload, allowing a decoder to reconstruct complete
messages regardless of how the underlying `TcpStream` delivers bytes.

## Wire Framing

Every frame begins with a fixed 16-byte header followed by a bounded payload:

```
Offset  Size  Field             Type      Value / Notes
------  ----  -----             ----      ----------------
0        4    Magic            [u8; 4]   0x54 0x50 0x58 0x31 ("TPX1")
4        1    Version          u8         1
5        1    Frame Type       u8         See Frame Types below.
6        2    Flags            u16 BE     0 in v1; non-zero is a protocol error.
8        4    Stream ID        u32 BE     0 = control, >0 = stream scope.
12       4    Payload Length   u32 BE     Bytes in payload. 0 = empty payload.
16       N    Payload          [u8; N]    Arbitrary binary data.
```

**Total frame size** = `16 + payload_length` bytes.

All multi-byte integers use **big-endian / network byte order** (most
significant byte first). This makes the wire format deterministic across
all CPU architectures.

### Magic

The four bytes `0x54 0x50 0x58 0x31` spell `"TPX1"` in ASCII. A decoder
that encounters any other magic must reject the frame with
`ProtocolError::InvalidMagic`.

### Version

The version byte must be `1`. A decoder that receives any other value
must reject the frame with `ProtocolError::UnsupportedVersion`. There is
no silent downgrade.

### Flags

Protocol v1 defines no flags. The flags field must be zero. Any non-zero
value is a protocol error (`ProtocolError::UnsupportedFlags`).

This policy prevents a peer from silently sending a flag byte that the
other peer ignores — flag misuse would be visible immediately.

### Stream ID

An unsigned 32-bit stream identifier.

| Value      | Meaning                                           |
|------------|---------------------------------------------------|
| `stream_id == 0` | Connection-scoped / control frame.            |
| `stream_id > 0`  | Logical stream-scoped frame.                |

The stream ID has no meaning within the protocol itself — it is a handle
that higher-layer code (not yet implemented) uses to demultiplex logical
streams over a single TCP connection.

`stream_id == 0` is reserved for control frames. Attempting to send a
stream-scoped frame with `stream_id == 0`, or a control-scoped frame with
`stream_id > 0`, is a protocol error.

> **Note:** Session 09 uses the same stream lifecycle concurrently on a bounded
> number of logical streams. Frame numbers and payload schemas are unchanged.

## Frame Types

| Value   | Name           | Scope      | Payload semantics |
|---------|----------------|------------|-------------------|
| `0x01`  | `HELLO`        | Control    | 1-byte role. |
| `0x02`  | `REGISTER`     | Control    | Empty in v1. |
| `0x03`  | `REGISTERED`   | Control    | 8-byte non-zero session ID. |
| `0x10`  | `OPEN_STREAM`  | Stream     | Empty request/acknowledgment payload. |
| `0x11`  | `DATA`         | Stream     | Non-empty binary bytes, maximum 64 KiB. |
| `0x12`  | `END_STREAM`   | Stream     | Empty directional half-close. |
| `0x13`  | `RESET_STREAM` | Stream     | 2-byte big-endian reset code. |
| `0x20`  | `PING`         | Control    | 8-byte non-zero heartbeat sequence. |
| `0x21`  | `PONG`         | Control    | Echoes the matching PING sequence. |
| `0xFF`  | `ERROR`        | Control    | 2-byte state-dependent error code. |

Frame types are defined as stable numeric constants. Unknown frame type
bytes are rejected with `ProtocolError::UnknownFrameType` — they are not
silently mapped to a default variant.

Payload interpretation is state-dependent, but every currently implemented
frame type has a fixed schema described below.

### Session 06 Payload Schemas

Session 06 defines the payload schemas for the handshake frame types:

| Value   | Name         | Scope   | Payload schema |
|---------|--------------|---------|---------------|
| `0x01` | `HELLO`      | Control | 1 byte: role (`0x01` = AGENT). Exactly 1 byte. |
| `0x02` | `REGISTER`   | Control | Empty (0 bytes). |
| `0x03` | `REGISTERED` | Control | 8 bytes big-endian: `TransportSessionId` (non-zero). |
| `0xFF` | `ERROR`      | Control | 2 bytes big-endian: error code (see below). |

### Session 07 Heartbeat Payloads

PING and PONG both carry exactly 8 bytes: a non-zero `u64` heartbeat
sequence encoded in big-endian order. Edge initiates PING and permits only
one outstanding sequence. Agent responds with PONG carrying the identical
payload. Zero, malformed lengths, mismatched PONG, unsolicited PONG, and
Agent-initiated PING are protocol violations that close the session.

### Session 08 Stream Payloads

Edge alone allocates monotonically increasing non-zero stream IDs and sends an
empty `OPEN_STREAM`. After connecting to its configured local service, Agent
echoes an empty `OPEN_STREAM` with the same ID as acknowledgment. Edge does not
forward ingress bytes before this acknowledgment.

`DATA` carries arbitrary non-empty binary bytes. Runtime producers use a fixed
16 KiB read buffer, while the protocol-wide 64 KiB maximum remains enforced by
the codec. `END_STREAM` has an empty payload and closes only the sender's data
direction; the opposite direction remains usable until it also sends
`END_STREAM`. `RESET_STREAM` carries exactly one known two-byte reset code and
aborts only that logical stream.

Session 08 permits one active stream per Agent transport and allows sequential
reuse after cleanup. Heartbeat frames remain valid while a stream is active.

## Payload Maximum

The maximum payload size is **64 KiB** (`65,536` bytes).

Both encoder and decoder enforce this limit:

- **Encoder** rejects `Frame::new` / `FrameEncoder::encode` if the payload
  exceeds 64 KiB.
- **Decoder** reads the announced payload length from the header and
  **validates it before allocating any buffer**. If the announced length
  exceeds 64 KiB, the decoder returns `ProtocolError::FrameTooLarge`
  without reading or allocating the oversized amount.

This is a direct application of INV-002: "Never allocate unbounded memory
based on remote lengths."

## Encoder Behavior

`FrameEncoder::encode` writes a complete frame to an `AsyncWrite` stream:

1. Validates the frame (payload size, flags, stream scope).
2. Constructs the exact 16-byte header (big-endian fields).
3. Writes the header via `write_all` (handles partial writes).
4. Writes the payload via `write_all` (handles partial writes).

The encoder never performs an unbounded allocation or write.

## Decoder Behavior

`FrameDecoder::decode` reads a single frame from an `AsyncRead` stream.
It is a stateful cursor that reads until one complete frame is available.

### Partial Read Handling

The decoder correctly handles:

- **Fragmented headers** — if `read` returns fewer than 16 bytes, the
  decoder continues reading until all 16 header bytes arrive.
- **Fragmented payloads** — after the header, the decoder reads the exact
  announced payload length across multiple reads if necessary.
- **Coalesced frames** — after returning one frame, the decoder's next call
  resumes reading the next frame's header from where the previous call
  stopped.

The decoder **never assumes** that one `read` returns one frame.

### EOF Semantics

The decoder distinguishes three cases:

| Condition                               | Result                       |
|-----------------------------------------|------------------------------|
| EOF before any byte of next header      | `Ok(None)` — clean EOF.     |
| EOF after partial header (≥1 byte, <16) | `Err(TruncatedHeader)`       |
| EOF after complete header, partial payload | `Err(TruncatedPayload)`    |

These are three distinct outcomes, not one generic "connection closed"
error. Callers can therefore provide precise diagnostics.

## Protocol Errors

`ProtocolError` is a focused typed enum (no giant project-wide hierarchy):

```
I/O
  └── Io(Error)

Wire format
  ├── InvalidMagic([u8; 4])
  ├── UnsupportedVersion(u8)
  ├── UnknownFrameType(u8)
  └── UnsupportedFlags(u16)

Frame structure
  ├── InvalidStreamScope { frame_type, required, got }
  ├── FrameTooLarge(u32)
  ├── TruncatedHeader { got: usize }
  └── TruncatedPayload { got: usize, expected: usize }

Encoding
  ├── EncodeFrameTooLarge(u32)
  └── EncodeValidation(String)
```

All protocol errors are recoverable. The decoder never panics on malformed
input.

### Handshake Error Codes

Session 06 defines a minimal set of handshake-level error codes transmitted
in ERROR frame payloads:

| Code | Name | Meaning |
|------|------|---------|
| 1 | `UnexpectedFrame` | Frame was not expected at this point in the handshake. |
| 2 | `InvalidHello` | HELLO frame had an invalid payload. |
| 3 | `InvalidRegister` | REGISTER frame had a non-empty payload. |
| 4 | `ProtocolViolation` | General protocol violation. |

### Heartbeat Error Codes

After REGISTERED, ERROR payloads use the established-session heartbeat code
registry. Decoding is state-dependent because the payload remains a compact
2-byte big-endian value:

| Code | Name | Meaning |
|------|------|---------|
| 1 | `HeartbeatTimeout` | Matching PONG was not received before the deadline. |
| 2 | `HeartbeatSequenceMismatch` | PONG sequence differs from the outstanding PING. |
| 3 | `UnsolicitedPong` | PONG arrived while no PING was outstanding. |
| 4 | `AgentPingNotSupported` | Agent initiated PING in the Edge-initiated v1 model. |
| 5 | `InvalidHeartbeatPayload` | PING/PONG payload is not one non-zero 8-byte sequence. |
| 6 | `UnexpectedFrame` | A frame arrived in a control-session state where it is not permitted. |

### Stream Reset Codes

RESET_STREAM uses a state-independent two-byte big-endian code:

| Code | Name | Meaning |
|------|------|---------|
| 1 | `LocalConnectFailed` | Agent could not connect to the configured local service. |
| 2 | `LocalConnectTimeout` | Agent's local connect deadline expired. |
| 3 | `IoFailure` | Local or ingress stream I/O failed. |
| 4 | `ProtocolViolation` | Stream lifecycle, ID, or payload was invalid. |
| 5 | `StreamBusy` | A second open was attempted while one stream was active. |
| 6 | `OpenTimeout` | Edge did not receive Agent's open acknowledgment. |
| 7 | `IdleTimeout` | The active stream made no application-data progress. |
| 8 | `CapacityExceeded` | The session reached its concurrent-stream limit. |
| 9 | `UnknownStream` | A frame referenced a stream that is no longer active. |
| 10 | `FlowControlExceeded` | A bounded receive queue or frame budget was exceeded. |
| 11 | `SessionClosing` | The transport cannot accept more stream work. |

## Security Considerations

- All validated untrusted input. Every byte of every incoming frame is
  treated as attacker-controlled.
- Maximum payload length enforced **before allocation** — a malicious peer
  cannot trigger unbounded memory growth by announcing a large payload.
- Magic, version, frame type, and flags are all validated explicitly.
  Unknown values are rejected, not silently ignored.
- Arbitrary binary payloads are accepted without assuming UTF-8 or any
  other encoding. Binary-safe round-trip is guaranteed.
- No secrets are ever logged (INV-003).

## What Is NOT Implemented

Protocol v1 framing does **not** include:

- TLS records or encryption primitives. Session 14 wraps the Protocol v1 byte
  stream in mutual TLS without changing this framing format.
- Authentication messages or credentials. Session 14 client-certificate
  authentication completes before the first Protocol v1 frame.
- Credit/window-based flow control and weighted scheduling.
- Session resumption or reconnect signaling. Session 13 process runtimes
  reconnect by performing a completely fresh Protocol v1 handshake.
- HTTP, WebSocket, or any higher-layer protocol.
- Tunnel registration, hostname allocation, or durable identity.
- Public HTTP/TLS traffic routing; Session 08 is raw TCP loopback only.

## Dependencies

`crate::protocol` has no dependencies on `crate::edge`, `crate::agent`,
or `crate::control-plane`. It sits strictly below them in the dependency
graph.

```
protocol
  ↑   ↑
edge agent
```
