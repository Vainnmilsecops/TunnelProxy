# Local Agent Configuration v1 and v2

Session 43 adds the canonical `tunnelproxy` executable and one strict local
configuration file for the repeated identity, Edge, and hostname-service
arguments required by managed HTTP startup.

Session 53 adds config v2 for a bounded multi-tunnel process. Config v1 and
`tunnelproxy http <port>` remain unchanged.

## Resolution order

For `tunnelproxy http <port>`, configuration is selected in this order:

1. `--config <path>`;
2. `TUNNELPROXY_CONFIG`;
3. `%APPDATA%\TunnelProxy\config.json` on Windows;
4. `$XDG_CONFIG_HOME/tunnelproxy/config.json` on Unix, or
   `$HOME/.config/tunnelproxy/config.json` when XDG is unset.

Explicit CLI flags override matching values from the file. File values
override the existing process defaults. A missing platform-default file is
ignored only when every required value was supplied explicitly, preserving the
Session 42 long-form command. An explicit or environment-selected missing file
is always an error.

## Config v1 schema

The UTF-8 JSON file is limited to 64 KiB. Version mismatch, unknown fields,
duplicate fields, malformed addresses, unsafe identifiers, empty paths, and
incomplete objects fail before any network connection or hostname mutation.

```json
{
  "version": 1,
  "edge": {
    "address": "edge.example.test:7100",
    "ca": "edge-ca.pem",
    "server_name": "edge.example.test"
  },
  "hostname": {
    "address": "control.example.test:7400",
    "ca": "control-plane-ca.pem",
    "server_name": "control.example.test"
  },
  "identity": {
    "agent_id": "agent-a",
    "tunnel_id": "tunnel-a",
    "client_certificate": "agent.pem",
    "client_private_key": "agent-key.pem"
  },
  "public_reachability": {
    "enabled": true,
    "ca": "public-ca.pem",
    "timeout_ms": 30000,
    "monitor_interval_ms": 60000,
    "failure_threshold": 3
  }
}
```

## Config v2 multi-tunnel schema

Config v2 moves `tunnel_id` out of the shared identity and requires a
`tunnels` array containing 1â€“16 entries. Every local target is loopback-only;
`local_port` must be non-zero. TunnelIds must be unique, while multiple
TunnelIds may intentionally point to the same local port.

```json
{
  "version": 2,
  "edge": {
    "address": "edge.example.test:7100",
    "ca": "edge-ca.pem",
    "server_name": "edge.example.test"
  },
  "hostname": {
    "address": "control.example.test:7400",
    "ca": "control-plane-ca.pem",
    "server_name": "control.example.test"
  },
  "identity": {
    "agent_id": "agent-a",
    "client_certificate": "agent.pem",
    "client_private_key": "agent-key.pem"
  },
  "tunnels": [
    { "tunnel_id": "frontend", "local_port": 3000 },
    { "tunnel_id": "webhooks", "local_port": 4000 }
  ],
  "public_reachability": {
    "enabled": true,
    "monitor_interval_ms": 60000,
    "failure_threshold": 3
  }
}
```

Run v2 only through `tunnelproxy start [--config <path>]`. `--local`,
`--tunnel-id`, and `--enroll-only` are rejected because tunnel shape belongs
to the profile. Shared CLI values still override shared config fields. Config
v1 is rejected by `start`, and config v2 is rejected by `http <port>`, so a
version mismatch cannot silently select a different runtime shape.

`public_reachability` is optional in both versions, so every existing v1 file
remains valid.
All nested fields except `enabled` are optional, but may only be supplied when
`enabled` is true. Without `ca`, the probe uses the Agent's bundled public Web
PKI roots. The startup timeout must be between 1 ms and 300000 ms.
`monitor_interval_ms` enables continuous fixed-delay checks and must be between
10000 and 3600000 ms. `failure_threshold` requires a monitor interval, must be
between 1 and 10, and defaults to 3.

Relative CA, certificate, and key paths resolve from the directory containing
the config file, not the process working directory. The file contains paths,
not PEM, private-key, or token bytes. It is still security-sensitive because
it selects trust roots, identities, and credential locations; protect it and
its referenced files using normal host filesystem controls.

## Offline validation

Validate schema, paths, identifiers, addresses, both TLS client
configurations, and the default Agent runtime without opening a socket:

```text
tunnelproxy config validate --config path/to/config.json
configuration valid
```

Omit `--config` to use the environment/platform resolution order. Failures use
exit code 2 and never echo config contents, PEM, key, or token bytes.

## Managed HTTP startup

Once the config is installed at the platform-default path:

```text
tunnelproxy http 3000
https://tp-0123456789abcdef0123456789abcdef.tunnelproxy.dev -> http://127.0.0.1:3000
```

The Session 42 default lifecycle is unchanged: allocation is idempotent,
stdout waits for the first registered Agent transport, reconnect uses the
normal bounded policy, and process shutdown does not release the durable
hostname. When `public_reachability.enabled` is true (or the matching CLI flag
is supplied), stdout additionally waits for a successful public HTTPS
challenge. Probe timeout is terminal with exit code 1, while the durable
hostname remains allocated. With a monitor interval, subsequent failures are
non-terminal: readiness becomes degraded and then returns `503` at the failure
threshold. The next successful proof restores readiness. Attempts never
overlap, and disconnect/reconnect requires a fresh proof before readiness is
restored. This configuration does not provision wildcard DNS or public TLS.

## Multi-tunnel startup

After validating config v2, start every configured tunnel with one command:

```text
tunnelproxy config validate --config path/to/config-v2.json
tunnelproxy start --config path/to/config-v2.json
```

Each tunnel allocates or reuses its durable hostname and runs on a separate
Agent transport. URL lines appear independently after each transport and any
enabled public proof become ready. `/healthz` remains process health;
`/readyz` requires all configured tunnels. Metrics expose only aggregate
configured/ready counts and fixed state counts, never TunnelId or hostname
labels. Terminal failure in any child fails closed and drains all children;
ordinary reconnect remains isolated to that child. Hostname allocations are
not automatically released on partial startup failure or shutdown.

The backwards-compatible `tunnelproxy-agent` executable uses the same driver
and also accepts `http <port> --config <path>`. Manual hostname commands and
the legacy no-subcommand runtime keep their existing flag contracts.
