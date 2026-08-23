# `tunnelproxy-edge`

Future TunnelProxy public ingress and live tunnel routing.

## Responsibility (future)

- Terminate public HTTPS on `*.tunnelproxy.dev` hostnames.
- Authenticate / authorise incoming public requests.
- Route requests to the correct agent tunnel.
- Stream request and response bodies with bounded buffers (INV-002).

## Prohibited

- Trusting client-supplied forwarding headers blindly (INV-009).
- Reaching into the control plane on the hot path of per-request routing
  (INV-007).
- Blocking I/O on async paths (INV-008).
- Persisting data — that belongs to the control plane.

## Current state

The crate contains tested TCP echo/relay primitives, a bounded local forwarder,
and the protocol-aware Agent transport listener. The listener performs the v2
handshake, bounds concurrent sessions, and uses Edge-initiated PING/PONG to
remove dead sessions. Session 09 adds a loopback-only `MultiplexedEdgeRuntime`
and `EdgeSessionRouter` for bounded concurrent raw TCP streams routed to exact
live Agent sessions. Session 10 adds bounded ephemeral raw ingress listeners
with tracked completion and drain cleanup. Public HTTP/TLS ingress,
public-client authorization and credit-based flow control are not implemented
yet. Session 12 adds `EdgeRuntime` and the runnable
`tunnelproxy-edge` binary, composing one Agent with one loopback raw route,
startup rollback, and ordered route-before-transport shutdown.
Session 13 introduced reconnect and ephemeral route recovery.
Session 14 lets the multiplexed Agent listener require mutual TLS before the
Protocol v1 handshake. Only client certificates signed by the configured CA
can become routable, TLS handshakes retain bounded admission and deadlines, and
plaintext remains available only for loopback development. This certificate
authentication alone is not durable Agent/tunnel authorization. Session 15
bumps to Protocol v2/ALPN `tunnelproxy/2`, binds the exact leaf-certificate
fingerprint to `AgentId` and `TunnelId`, rejects duplicate live claims, and
routes through an in-memory `TunnelId -> TransportSessionId` map. The runnable
raw listener now stays bound across Agent reconnect and closes new sockets while
the tunnel is offline. Session 16 consumes versioned full authorization
snapshots while running. Applying an update atomically removes revoked tunnel
and ephemeral-session routes before closing their active transports/streams;
add or re-enable takes effect without restarting Edge. The raw listener remains
bound throughout. Persistence, an external snapshot service, and public ingress
are still not implemented.
