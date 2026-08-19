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

Foundation-only. Today this is a library crate exposing only `EdgeId`.
No sockets, no TLS, no HTTP.
