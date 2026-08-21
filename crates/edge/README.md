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
and the protocol-aware Agent transport listener. The listener performs the v1
handshake, bounds concurrent sessions, and uses Edge-initiated PING/PONG to
remove dead sessions. Public HTTP ingress, TLS, authentication, durable routing,
and reverse traffic streams are not implemented yet.
