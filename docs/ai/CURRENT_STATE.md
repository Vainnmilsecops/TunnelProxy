# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Heartbeat, Liveness & Dead-Session Detection** (Session 07).

## Completed

- Outbound Agent → Edge TCP control connection (INV-001: Agent dials Edge only).
- Tunnel Protocol v1 handshake runtime: HELLO → REGISTER → REGISTERED.
- HELLO payload schema: 1 byte role (`0x01` = AGENT), strictly validated.
- REGISTER payload: empty in v1 (no durable tunnel creation).
- REGISTERED payload: 8-byte big-endian non-zero `TransportSessionId`.
- Strongly typed process-local session IDs with safe non-zero allocation.
- Edge `AgentTransportListener` with bounded concurrent admission (`Semaphore`).
- Edge handshake timeout (10 s default; affects handshake only).
- Strict handshake sequencing and best-effort ERROR response on violations.
- Edge-initiated heartbeat after handshake: PING followed by matching PONG.
- PING/PONG payload: exactly one non-zero 8-byte big-endian sequence.
- Only one PING is outstanding; sequences start at 1 and never wrap to zero.
- Configurable `heartbeat_interval` (15 s default) and `pong_timeout` (10 s
  default), both rejected when zero.
- Agent `AgentSession::run()` validates PING and automatically writes the
  matching PONG. `AgentSession::close()` provides an explicit local close path.
- Timeout, malformed payload, mismatched sequence, unsolicited PONG,
  Agent-initiated PING, and unexpected frames close only the affected session.
- Session capacity permit is held through handshake and heartbeat lifetime and
  released through RAII on every close/failure path.
- Structured heartbeat tracing includes session ID, peer, sequence, RTT, and
  close reason without logging payload bytes.
- 20 Agent transport integration tests cover the handshake and heartbeat paths.
- 94 explicit workspace tests are present (80 through Session 06 plus 14 for
  Session 07).
- Prior Session 01–06 capabilities and tests are preserved.

## Not implemented

- TLS / encryption.
- Agent authentication.
- Reconnect logic.
- Stream multiplexing (`OPEN_STREAM` / `DATA` frames have no runtime yet).
- Tunnel registration (REGISTER is ephemeral transport registration only).
- Public tunnel endpoints / hostname allocation.
- Traffic forwarding / reverse tunneling.
- Durable Agent identity (`TunnelId`, `AgentId`).
- Upstream connection pool (DEBT-008 open).
- Graceful shutdown channel on listeners (DEBT-005 / DEBT-012 open).
- Relay-path idle read deadline (DEBT-006 remains open outside Agent heartbeat).
- Per-IP admission control on the forwarder (DEBT-009 open).
- Production telemetry / metrics backend (DEBT-010 open).

## Next planned session

**Session 08 — Single-Stream Reverse Data Path.**

Goals:

- Implement one `OPEN_STREAM` / `DATA` / `END_STREAM` flow without multiplexing.
- Forward one Edge-side TCP connection through the Agent to one local port.
- Preserve half-close, bounded buffers, cancellation, and per-stream cleanup.
- Keep multiplexing, public HTTP ingress, TLS, and reconnect out of scope.
