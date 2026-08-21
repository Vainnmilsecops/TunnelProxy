# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Tunnel Protocol v1 Framing Foundation** (Session 05).

## Completed

- Fixed 16-byte binary frame header for the Agent ↔ Edge wire protocol
  (`MAGIC = "TPX1"`, `VERSION = 1`, `HEADER_SIZE = 16`).
- Big-endian / network byte order for all multi-byte integer fields.
- Stable frame type registry with explicit numeric values:
  `HELLO (0x01)`, `REGISTER (0x02)`, `REGISTERED (0x03)`,
  `OPEN_STREAM (0x10)`, `DATA (0x11)`, `END_STREAM (0x12)`,
  `RESET_STREAM (0x13)`, `PING (0x20)`, `PONG (0x21)`, `ERROR (0xFF)`.
- `StreamId` strongly-typed wrapper around `u32`; `StreamId(0)` is
  `CONTROL`, `StreamId(N > 0)` is `STREAM`.
- Stream scope validation: control frames require `stream_id == 0`,
  stream frames require `stream_id > 0`; invalid combinations are rejected.
- Bounded payloads: maximum 64 KiB per frame (`MAX_FRAME_PAYLOAD`).
- Encoder (`FrameEncoder::encode`) and decoder (`FrameDecoder::decode`)
  for Tokio `AsyncRead` / `AsyncWrite` streams.
- Partial-read handling: decoder handles fragmented headers, fragmented
  payloads, and coalesced frames correctly (never assumes one read == one
  frame).
- Three-way EOF distinction: clean `Ok(None)`, `TruncatedHeader`,
  `TruncatedPayload`.
- Typed `ProtocolError` taxonomy covering I/O, invalid magic, unsupported
  version, unknown frame type, unsupported flags, invalid stream scope,
  oversized frame, truncated header, truncated payload.
- Decoder validates announced payload length **before allocating**, preventing
  unbounded memory growth from malicious input (INV-002).
- Payload remains opaque binary bytes; no UTF-8 assumption, no schema.
- `tunnelproxy-protocol` crate has no dependencies on `tunnelproxy-edge`,
  `tunnelproxy-agent`, or `tunnelproxy-control-plane`.
- 26 deterministic codec tests pass, including a real loopback TCP test.
- `docs/TUNNEL_PROTOCOL_V1.md` documents the wire format, frame types, scope
  rules, EOF semantics, error taxonomy, and security rationale.
- All prior Session 01–04 deliverables remain intact and passing.

## Not implemented

- Persistent Agent ↔ Edge tunnel connection.
- Protocol handshake behavior (HELLO / REGISTER / REGISTERED frame types
  exist as types but carry no domain semantics yet).
- Stream multiplexing runtime (stream IDs exist as a concept but demux
  logic is not implemented).
- Actual tunnel registration.
- Heartbeat timer or keepalive behavior (PING / PONG exist as types).
- Reconnect.
- Payload schemas for any frame type (payload is opaque bytes for now).
- TLS.
- HTTP / WebSocket.
- Authentication.
- Persistence.
- Request inspection, replay, dashboards, billing, or cloud deployment.
- Upstream connection pooling (DEBT-008 open).
- Graceful shutdown channel on the edge listener (DEBT-005 open).
- Per-connection idle read deadline (DEBT-006 open).
- Per-IP admission control on the forwarder (DEBT-009 open).
- Production telemetry / metrics backend (DEBT-010 open).

## Next planned session

**Session 06 — Persistent Agent ↔ Edge Transport and Protocol Handshake.**

Goals (subject to refinement when Session 06 begins):

- Implement the persistent Agent → Edge outbound TCP connection.
- Define HELLO / REGISTER / REGISTERED frame payload schemas.
- Implement the protocol handshake: agent opens connection, sends HELLO,
  edge responds with REGISTERED, tunnel is established.
- Agent heartbeat via PING / PONG frames (timer-based).
- Graceful connection teardown on error.
- Update the forwarder to use the new tunnel protocol.
