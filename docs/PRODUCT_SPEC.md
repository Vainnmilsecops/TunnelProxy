# TunnelProxy — Product Specification

> Status: **early-stage foundation.** This document describes the intended
> product and the boundaries of the upcoming MVP / V1. It does **not**
> claim that any of these capabilities are implemented today. See
> `docs/ai/CURRENT_STATE.md` for the truthful state of the repository.

## 1. Problem statement

Developers constantly need to expose a service running on their laptop to
the outside world: to demo a feature, to receive webhooks from a SaaS
provider, to test a mobile app against a real backend, or to share a
branch environment with a teammate. The traditional answers (deploying
to staging, opening a firewall port, configuring ngrok alternatives,
writing bespoke SSH tunnels) are either slow, insecure, painful to
operate, or all three.

TunnelProxy aims to make "expose my local port on a public URL" a
single-command, secure-by-default, observable developer experience,
without forcing the developer to babysit TLS certificates, NAT
traversal, or auth tokens.

## 2. Target users

**Primary**

- Backend and full-stack developers who iterate against locally running
  services (Node, Go, Rust, Python, JVM, etc.).
- Mobile and front-end developers who need a stable URL pointing at a
  local backend.
- Webhook integrators who need a real public endpoint to receive events
  from third-party services (Stripe, GitHub, Slack, etc.).

**Secondary (later V1)**

- Platform / SRE teams who want a self-hostable tunneling component for
  internal environments.
- QA / support engineers who need to inspect and replay captured
  requests on behalf of users.

## 3. Primary use cases

1. **Demo a local server on a public URL.**
   `tunnelproxy http 3000` → `https://<host>.tunnelproxy.dev`.
2. **Receive webhooks locally.** Point the SaaS provider at the public
   URL; observe and inspect each delivery.
3. **Share a local environment with a teammate.** Generate a shareable
   tunnel URL scoped to a specific requester.
4. **Debug live traffic.** Inspect requests and responses on a tunnel
   without rerunning the scenario.
5. **Replay a captured request** for reproducibility.

## 4. Product positioning

TunnelProxy is **not** a generic VPN, **not** a corporate ZTNA product,
and **not** a load-balancer-as-a-service. It is a developer-first
reverse-tunneling platform that intentionally sits between the
developer laptop and the public internet.

The closest analogues are ngrok, Cloudflare Tunnel, and Tailscale
Funnel. TunnelProxy differs by:

- Treating request inspection and replay as first-class, not as
  afterthought add-ons.
- Defaulting to per-tunnel access control instead of "anyone with the
  URL".
- Being written primarily in Rust with explicit, observable resource
  bounds.

## 5. Initial MVP (Session 02 → a handful of follow-up sessions)

The MVP must demonstrate the full golden path end-to-end with the
minimum surface:

- A developer runs `tunnelproxy http <port>` on their machine.
- A reverse tunnel is opened outbound to a single Edge node.
- Public HTTPS on `<random>.tunnelproxy.dev` reaches the local port.
- One active tunnel per agent.
- One local TCP port per tunnel.
- HTTP/1.1 only.
- No auth beyond a signed tunnel URL.
- No persistence — agent and edge are stateless across restarts.
- No dashboard.
- No replay / inspection UI (raw logging only).

## 6. Long-term V1 scope

Building on the MVP, V1 adds:

- **HTTP/1.1, HTTP/2, raw TCP** tunnel kinds.
- **Multiple tunnels per agent** with per-tunnel configuration.
- **Authentication** — agent tokens, optional end-user access tokens.
- **Custom domains** beyond `*.tunnelproxy.dev`.
- **Request inspection UI** with body capture (redacted by default).
- **Replay** of captured requests with safe, idempotent semantics
  (INV-006).
- **Webhook-specific UX** — signature-aware delivery views.
- **Bounded observability** — metrics, structured logs, tracing.
- **Reconnect with exponential backoff** and session resume.
- **Backpressure** on the tunnel (INV-002).

Explicitly **out of V1**: full ZTNA, billing, audit log retention
beyond a short window, custom CA issuance, on-prem appliances.

## 7. Non-goals (now and near-term)

- Replacing VPN or ZTNA products.
- Hosting long-lived production user traffic. TunnelProxy targets
  developer loops, not always-on customer traffic.
- Building a generic API gateway.
- Supporting browsers as tunnel endpoints in the near term.
- Becoming a public PaaS for arbitrary code execution.

## 8. Success criteria

For the foundation (Session 01):

- A clean Cargo workspace compiles and tests.
- Component boundaries and AI context layer exist before any
  networking code is written.

For the eventual MVP:

- A new user can install the agent binary and have a working public
  URL within two minutes, with no account-creation step required for
  the first tunnel.
- A misbehaving agent cannot exhaust edge memory or CPU.
- Reasonable observability exists for every request that crosses the
  edge.

For V1:

- A user can authenticate, expose multiple tunnels, attach a custom
  domain, inspect live traffic, and replay captured requests, all
  without restarting the agent.
