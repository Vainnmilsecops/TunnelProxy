# TunnelProxy — Architecture

> Status: **architecture baseline only.** No networking is implemented.
> This document fixes the conceptual shape so future sessions can grow
> into it without restructuring.

## 1. High-level architecture

```
                    +--------------------------+
                    |      Internet Client     |
                    |   (browser / curl / SaaS) |
                    +--------------------------+
                                |
                                |  HTTPS request
                                v
                    +--------------------------+
                    |   *.tunnelproxy.dev      |
                    |        TLS termination   |
                    +--------------------------+
                                |
                                v
                    +--------------------------+
                    |     TunnelProxy Edge     |
                    |  - authenticate request  |
                    |  - resolve tunnel        |
                    |  - stream to agent       |
                    +--------------------------+
                                |
                                |  persistent secure
                                |  outbound tunnel
                                v
                    +--------------------------+
                    |     TunnelProxy Agent    |
                    |  - demux to local port   |
                    |  - forward + stream back |
                    +--------------------------+
                                |
                                v
                    +--------------------------+
                    |     Local Service        |
                    |     (localhost:3000)     |
                    +--------------------------+
```

Three runtime components, plus an off-path control plane.

## 2. Component roles

### 2.1 Agent

Runs on the developer's machine. Responsibilities (future):

- Initiate an **outbound** secure tunnel to one Edge node (INV-001).
- Authenticate itself with the control plane.
- Register which local ports it wants to expose.
- Demultiplex inbound streams to the correct local service.
- Stream request / response bytes back to the Edge.

The agent **never accepts inbound connections** from the public
internet. If it did, the security story collapses.

### 2.2 Edge

Runs in a data center or cloud. Responsibilities (future):

- Terminate TLS for `*.tunnelproxy.dev` (and future custom domains).
- Authenticate the incoming public request.
- Resolve the request to a specific agent tunnel using **cached**
  routing state (INV-007).
- Forward the request across the agent's persistent tunnel and stream
  the response back to the public client.
- Enforce per-tunnel access control.
- Bound every buffer on the hot path (INV-002).

### 2.3 Control plane

Off the data-plane hot path. Responsibilities (future):

- Own durable state: users, agents, tunnels, domains, auth, quotas.
- Issue short-lived routing state to Edge so per-request routing does
  not need a database round-trip (INV-007).
- Provide configuration APIs to agents and admins.
- Manage authentication material.

### 2.4 Local service

The developer-owned process the agent forwards into. Not part of
TunnelProxy. Out of scope for security guarantees beyond best-effort
isolation in the agent process.

### 2.5 Public client

Anyone making an HTTPS request to a tunnel URL. Could be a browser, a
mobile app, a CLI, a SaaS webhook. Treated as untrusted input. Edge
never trusts client-supplied headers verbatim (INV-009).

## 3. Control plane vs data plane

| Concern                | Control Plane | Data Plane |
|------------------------|---------------|------------|
| User accounts          | yes           | no         |
| Agent registration     | yes           | no         |
| Tunnel metadata (durable) | yes        | no         |
| Routing state (cached) | issuer        | consumer   |
| Live public requests   | no            | yes        |
| Live agent connections | no            | yes        |
| Quota counters         | yes           | reports    |
| Authentication         | authoritative | enforces   |
| TLS termination        | mints configs | terminates |
| Per-request hot path   | never         | always     |

The conceptual separation matters even for the single-node MVP. If the
Edge ever needs to look up a database row to decide where to forward a
request, the system will not scale and will not survive a database
hiccup. The control plane's job is to push authoritative state into
the data plane so the data plane never has to ask.

## 4. Golden request flow (future)

```
Public Client                  Edge                     Agent                Local
     |                           |                        |                     |
     |--- HTTPS request -------->|                        |                     |
     |                           |--- resolve tunnel      |                     |
     |                           |   (from cached state)  |                     |
     |                           |--- open stream -------------------------------->|
     |                           |                        |--- forward to local |
     |                           |                        |<-- response ---------|
     |<--------- HTTPS response --|<------- stream --------|                     |
     |                           |                        |                     |
```

Step-by-step:

1. Public client opens TLS to `<host>.tunnelproxy.dev`.
2. Edge terminates TLS, validates any required auth, and resolves the
   host to a tunnel identifier using **cached** routing state.
3. Edge opens (or reuses) a multiplexed stream on the agent's
   persistent tunnel.
4. Agent demultiplexes the stream, opens a TCP connection to the
   configured local service, and forwards bytes bidirectionally.
5. Agent streams the local response back through the tunnel.
6. Edge writes the response to the public client, enforcing bounded
   buffers and timeouts (INV-002, INV-005).

## 5. Rationale

Why a reverse tunnel rather than opening an inbound port on the
developer machine? Because developers sit behind NATs, corporate
firewalls, and dynamic IPs. Reverse tunnels let the agent be a normal
outbound TCP client, which works almost everywhere.

Why separate control plane from data plane? Because mixing them is the
single most common reason developer-tool platforms fall over under
load: every request becomes a database query. We commit now so the
code structure never lets that creep in (INV-007).

Why Rust? Because the data plane is exactly the kind of code where
memory safety, bounded buffers, and predictable latency matter, and
the ecosystem gives us strong async primitives and excellent
observability tools without dragging in a garbage collector.
