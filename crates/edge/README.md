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
graceful GOAWAY drain. Session 45 adds explicit HTTP/1.1 WebSocket upgrades
with strict client/local handshakes, bounded active sessions and idle time,
opaque bidirectional relay, and bounded drain. Session 46 adds explicit
route-bound HTTP/1.1 CONNECT with exact authority-port/Host/SNI validation,
independent session and idle bounds, direct opaque tunnel relay, and bounded
drain. Arbitrary forward-proxy CONNECT, HTTP/2 extended CONNECT, WebSocket
extensions, HTTP/3, distributed rate limiting, and
multi-edge ownership remain outside the current implementation.
