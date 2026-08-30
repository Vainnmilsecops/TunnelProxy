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

The crate contains tested TCP baselines, bounded raw ingress, authenticated
Protocol v2 Agent transport, multiplexed routing, reconnect-safe durable route
binding, and supervised process shutdown. Dynamic Agent authorization and HTTPS
route catalogs arrive through independent bounded mTLS latest-value streams and
are read only from immutable in-memory state on ingress.

Public HTTPS terminates reloadable TLS, validates exact SNI and Host/authority,
sanitizes forwarding headers, applies global/per-IP admission and request-rate
limits, then streams to the selected Agent without a storage or Control Plane
lookup. HTTP/1.1 is the compatible default. Session 44 adds explicit bounded
HTTP/2 ALPN with concurrent-stream/reset/header/keepalive limits, per-stream
failure isolation, HTTP/1.1 local translation, fixed-cardinality telemetry, and
graceful GOAWAY drain. WebSocket, CONNECT, HTTP/3, distributed rate limiting,
and multi-edge ownership remain outside the current implementation.
