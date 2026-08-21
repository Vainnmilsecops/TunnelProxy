# TunnelProxy — Current State

> Snapshot of the repository at the end of the most recent completed
> session. AI agents must read this to avoid claiming capabilities that
> do not exist.

## Current milestone

**Single-Stream Reverse Data Path** (Session 08).

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
- Protocol stream lifecycle: Edge OPEN_STREAM request, Agent OPEN_STREAM
  acknowledgment, binary DATA, directional END_STREAM, and typed RESET_STREAM.
- `SingleStreamEdgeRuntime` binds separate loopback Agent and raw-TCP ingress
  listeners and supports exactly one active stream.
- Agent `run_with_local_target` connects an opened stream to one configured
  local TCP service under a deadline.
- Fixed 16 KiB reads, 64 KiB protocol frame ceiling, sequential writes, and no
  unbounded application queues.
- Stream IDs start at 1, increase without reuse/wrap, and support sequential
  stream reuse on one Agent session.
- TCP half-close is preserved independently in both directions.
- Stream-open timeout (5 s default), local-connect timeout supplied by Agent,
  and active-stream idle timeout (60 s default).
- Heartbeat remains live while DATA frames are flowing or a local service is
  slow. Stream failure/reset cleans up only that stream.
- 10 real-TCP Session 08 integration tests cover golden path, 256 KiB binary
  traffic, half-close, sequential reuse, monotonic IDs, busy admission,
  heartbeat interleaving, idle timeout, local-connect failure, and lifecycle
  violations.
- 20 Agent transport integration tests cover the handshake and heartbeat paths.
- 112 explicit workspace tests are present (94 through Session 07 plus 18 for
  Session 08).
- Prior Session 01–07 capabilities and tests are preserved.

## Not implemented

- TLS / encryption.
- Agent authentication.
- Reconnect logic.
- Concurrent stream multiplexing and flow-control windows.
- Tunnel registration (REGISTER is ephemeral transport registration only).
- Public tunnel endpoints / hostname allocation.
- Public HTTP/TLS reverse proxy and raw public ingress.
- Durable Agent identity (`TunnelId`, `AgentId`).
- Upstream connection pool (DEBT-008 open).
- Graceful shutdown channel on listeners (DEBT-005 / DEBT-012 open).
- Relay-path idle read deadline (DEBT-006 remains open outside Agent heartbeat).
- Per-IP admission control on the forwarder (DEBT-009 open).
- Production telemetry / metrics backend (DEBT-010 open).

## Next planned session

**Session 09 — Bounded Stream Multiplexing & Session Routing.**

Goals:

- Replace the single-active-stream state with a bounded concurrent stream map.
- Introduce one reader task and one bounded writer queue per Agent transport.
- Add per-stream cancellation, capacity admission, and fair dispatch.
- Keep public HTTP/TLS ingress, durable routing, authentication, and reconnect
  out of scope until multiplexing is proven over raw TCP.
