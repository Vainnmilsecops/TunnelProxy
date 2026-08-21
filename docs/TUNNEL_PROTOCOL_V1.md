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

> **Note:** Stream multiplexing is **not implemented** in Session 05.
> The stream ID field and scope rules exist now so that the protocol
> foundation is correct before the multiplexing runtime is added.

## Frame Types

| Value   | Name           | Scope      | Payload semantics |
|---------|----------------|------------|-------------------|
| `0x01`  | `HELLO`        | Control    | Not yet defined.  |
| `0x02`  | `REGISTER`     | Control    | Not yet defined.  |
| `0x03`  | `REGISTERED`   | Control    | Not yet defined.  |
| `0x10`  | `OPEN_STREAM`  | Stream     | Not yet defined.  |
| `0x11`  | `DATA`         | Stream     | Not yet defined.  |
| `0x12`  | `END_STREAM`   | Stream     | Not yet defined.  |
| `0x13`  | `RESET_STREAM` | Stream     | Not yet defined.  |
| `0x20`  | `PING`         | Control    | Not yet defined.  |
| `0x21`  | `PONG`         | Control    | Not yet defined.  |
| `0xFF`  | `ERROR`        | Control    | Not yet defined.  |

Frame types are defined as stable numeric constants. Unknown frame type
bytes are rejected with `ProtocolError::UnknownFrameType` — they are not
silently mapped to a default variant.

**Payload schemas for each frame type are not yet defined.** The payload
field is opaque binary bytes in Session 05. Future sessions will introduce
typed payload structures (e.g. JSON, protobuf, or a custom binary schema)
as the Agent ↔ Edge handshake is designed.

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

- Authentication, credentials, or TLS.
- Agent ↔ Edge handshake behavior (HELLO / REGISTER / REGISTERED frames
  exist as types but carry no domain semantics yet).
- Stream multiplexing runtime (stream IDs exist as a concept but the
  demultiplexing logic is not implemented).
- Heartbeat timer or keepalive behavior (PING / PONG frame types exist
  as types but the behavior is not implemented).
- Reconnect logic.
- HTTP, WebSocket, or any higher-layer protocol.
- Payload schemas for any frame type.

## Dependencies

`crate::protocol` has no dependencies on `crate::edge`, `crate::agent`,
or `crate::control-plane`. It sits strictly below them in the dependency
graph.

```
protocol
  ↑   ↑
edge agent
```
