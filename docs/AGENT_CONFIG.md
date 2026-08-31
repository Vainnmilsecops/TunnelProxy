# Local Agent Configuration v1

Session 43 adds the canonical `tunnelproxy` executable and one strict local
configuration file for the repeated identity, Edge, and hostname-service
arguments required by managed HTTP startup.

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

## Schema

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
    "timeout_ms": 30000
  }
}
```

`public_reachability` is optional, so every existing v1 file remains valid.
Its `ca` and `timeout_ms` fields are optional, but may only be supplied when
`enabled` is true. Without `ca`, the probe uses the Agent's bundled public Web
PKI roots. The timeout must be between 1 ms and 300000 ms.

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
hostname remains allocated. This configuration does not provision wildcard
DNS or public TLS.

The backwards-compatible `tunnelproxy-agent` executable uses the same driver
and also accepts `http <port> --config <path>`. Manual hostname commands and
the legacy no-subcommand runtime keep their existing flag contracts.
