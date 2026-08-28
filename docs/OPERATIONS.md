# TunnelProxy Operations Runbook

This runbook describes operator-owned collection and interpretation of the
process-local metrics exposed by TunnelProxy. It does not make the operations
listeners public, add a remote-write client to the data path, or prescribe a
durable metrics backend.

## Collection topology

Agent, Edge, and Control Plane operations listeners are opt-in,
unauthenticated, and loopback-only. Run the collector in the same host or
network namespace as the TunnelProxy process. For containers, use a sidecar in
the same pod/network namespace. Do not publish or port-forward an operations
listener.

One node-local Prometheus-compatible collector can use targets such as:

```yaml
scrape_configs:
  - job_name: tunnelproxy-edge
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9090"]
  - job_name: tunnelproxy-agent
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9091"]
  - job_name: tunnelproxy-control-plane
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9092"]
```

Collection, retention, access control, encryption, remote write, dashboards,
and paging belong to that external collector/backend. Set retention to match
the operator's incident window. TunnelProxy counters and peak gauges reset on
every process restart, so use `rate()` or `increase()` rather than subtracting
raw samples across restarts.

## Transport capacity semantics

Agent and Edge export these fixed-cardinality gauges:

- `*_transport_data_pipeline_frames` is the number of admitted DATA or
  END_STREAM frames still owned by a writer pipeline.
- `*_transport_data_pipeline_capacity_frames` is the sum of configured DATA
  slots for live multiplex sessions in that process.
- Capacity is zero while no multiplex session is live. Agent reconnect and
  Edge multi-session aggregation update it through RAII.
- `*_transport_peak_data_pipeline_frames` is a process-lifetime high-water
  mark and therefore can remain above current live capacity after a session
  closes or reconnects with a smaller configuration.

For a single role, calculate current utilization only while capacity is
positive:

```promql
tunnelproxy_agent_transport_data_pipeline_frames
/
tunnelproxy_agent_transport_data_pipeline_capacity_frames
```

```promql
tunnelproxy_edge_transport_data_pipeline_frames
/
tunnelproxy_edge_transport_data_pipeline_capacity_frames
```

An absent result caused by division by zero means no live session, not a full
pipeline. Correlate it with `tunnelproxy_agent_ready` or
`tunnelproxy_edge_ready` and the connection/disconnect counters.

## Starting alert baseline

These thresholds are starting points, not protocol guarantees. Tune them from
normal workload history and keep identity such as AgentId, TunnelId, hostname,
peer address, or StreamId out of metric labels.

Sustained local pipeline pressure:

```promql
(
  tunnelproxy_agent_transport_data_pipeline_frames
  / tunnelproxy_agent_transport_data_pipeline_capacity_frames
) > 0.80
```

Use the equivalent Edge metrics and require the condition for at least ten
minutes. A short peak alone is expected backpressure.

Admission had to wait during the last five minutes:

```promql
increase(tunnelproxy_agent_transport_data_admission_waits_total[5m]) > 0
```

Locally initiated flow-control resets occurred:

```promql
increase(tunnelproxy_agent_transport_flow_control_resets_total[5m]) > 0
```

Repeat both queries with the `tunnelproxy_edge_` prefix. A reset is more
urgent than an admission wait because it closes one logical stream. An
increase in `*_transport_control_burst_yields_total` is not itself an error;
it shows that DATA fairness intervened while control traffic was continuously
ready.

Useful invariant alerts are:

```promql
tunnelproxy_agent_ready == 1
and
tunnelproxy_agent_transport_data_pipeline_capacity_frames == 0
```

```promql
tunnelproxy_edge_ready == 1
and
tunnelproxy_edge_transport_data_pipeline_capacity_frames == 0
```

## Capacity and protocol decision guide

1. If utilization is briefly high without admission waits or resets, take no
   action; bounded queuing is working as intended.
2. If utilization and admission waits remain high but resets and application
   latency remain acceptable, consider a measured increase to the local DATA
   queue capacity. Each slot can retain up to one 16 KiB DATA payload plus
   frame overhead, so validate the memory budget first.
3. If resets rise, inspect slow local services, stream idle timeouts, inbound
   per-stream queue pressure, and reconnects before enlarging the writer
   queue.
4. Consider peer-negotiated byte credits or deficit scheduling only when
   repeatable workload measurements show cross-stream latency/throughput
   interference after local bounds are tuned. Aggregate metrics alone do not
   prove byte unfairness.

Any protocol proposal must remain a separate session because it changes the
compatibility and failure model of Tunnel Protocol v2.

## Privacy and scrape safety

Operations scrapes read process-local atomic snapshots. They do not acquire a
live session lock, query SQLite, or perform remote backend I/O. Exported labels
use bounded enumerations only. Never add tokens, certificates, payloads,
hostnames, durable IDs, session IDs, stream IDs, or addresses as metric labels.
