# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Persistent Agent ↔ Edge Transport & Protocol Handshake** (Session 06).

## Completed

- Outbound Agent → Edge TCP control connection (INV-001: Agent dials Edge only).
- Tunnel Protocol v1 handshake runtime: HELLO → REGISTER → REGISTERED.
- HELLO payload schema: 1 byte role (`0x01` = AGENT), strictly validated.
- REGISTER payload: empty in v1 (no durable tunnel creation).
- REGISTERED payload: 8-byte big-endian non-zero `TransportSessionId`.
- Strongly typed `TransportSessionId` with zero-as-invalid policy.
- Process-local `TransportSessionIdAllocator` (atomic monotonic counter).
- `HandshakeErrorCode` enum with 4 defined codes for ERROR frames.
- Edge `AgentTransportListener` with bounded concurrent admission (`Semaphore`).
- Edge handshake timeout (10 s default; affects handshake only, not established lifetime).
- Strict handshake sequencing (HELLO first, REGISTER second; no deviations accepted).
- Established session: connection stays open after REGISTERED; clean EOF handling.
- Edge per-session ERROR frame response for handshake violations.
- Agent `connect()` API with configurable timeouts.
- Agent `AgentSession` type with `session_id`, `edge_addr`, `established_at`.
- Structured tracing events throughout (no payload logging).
- Agent ↔ Edge transport documentation (`docs/AGENT_EDGE_TRANSPORT.md`).
- Protocol v1 payload schemas documented (`docs/TUNNEL_PROTOCOL_V1.md`).
- 12 new integration tests covering all handshake scenarios.
- 6 new unit tests for config/allocator/handshake types.
- All 82 workspace tests pass (70 existing + 12 new).
- Prior Session 01–05 capabilities and tests preserved unchanged.

## Not implemented

- TLS / encryption.
- Agent authentication.
- Heartbeat / PING-PONG liveness timers.
- Reconnect logic.
- Stream multiplexing (OPEN_STREAM / DATA frames have no runtime yet).
- Tunnel registration (REGISTER in Session 06 is ephemeral transport registration only).
- Public tunnel endpoints / hostname allocation.
- Traffic forwarding / reverse tunneling.
- Durable Agent identity (TunnelId, AgentId).
- Upstream connection pool (DEBT-008 open).
- Graceful shutdown channel on listeners (DEBT-005 open).
- Per-connection idle read deadline (DEBT-006 open).
- Per-IP admission control on the forwarder (DEBT-009 open).
- Production telemetry / metrics backend (DEBT-010 open).

## Next planned session

**Session 07 — Heartbeat, Liveness & Dead-Session Detection.**

Goals:
- Implement PING / PONG frame handling in established sessions.
- Add configurable idle timeout on established sessions.
- Detect and clean up dead sessions (peer crash / network partition).
- Agent sends periodic PING; Edge responds with PONG; missing PONG closes session.
