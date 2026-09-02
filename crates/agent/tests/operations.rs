use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Instant};
use tunnelproxy_agent::{
    AgentOperationsConfig, AgentOperationsRuntime, AgentOperationsTunnel, AgentRuntime,
    AgentRuntimeConfig, RuntimeShutdownConfig,
};
use tunnelproxy_common::{shutdown_channel, PublicHostname, TunnelId};
use tunnelproxy_edge::agent_transport::{AgentListenerConfig, AgentTransportListener};

async fn request(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    request_method(addr, "GET", path).await
}

async fn request_method(addr: SocketAddr, method: &str, path: &str) -> std::io::Result<String> {
    let mut socket = TcpStream::connect(addr).await?;
    socket
        .write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await?;
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response).unwrap())
}

fn response_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("HTTP response has a header terminator")
}

async fn wait_for_status(addr: SocketAddr, code: u16) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(response) = request(addr, "/readyz").await {
            if response.starts_with(&format!("HTTP/1.1 {code}")) {
                return response;
            }
        }
        assert!(Instant::now() < deadline, "readiness never became {code}");
        sleep(Duration::from_millis(10)).await;
    }
}

async fn start_edge(
    listen_addr: SocketAddr,
) -> (
    tunnelproxy_common::ShutdownTrigger,
    tokio::task::JoinHandle<()>,
) {
    let mut config = AgentListenerConfig::dev_defaults();
    config.listen_addr = listen_addr;
    config.handshake_timeout = Duration::from_millis(500);
    config.heartbeat_interval = Duration::from_millis(25);
    config.pong_timeout = Duration::from_millis(100);
    let mut listener = AgentTransportListener::bind(config).await.unwrap();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(async move {
        listener
            .run_until_shutdown(signal, RuntimeShutdownConfig::new(Duration::from_secs(1)))
            .await
            .unwrap();
    });
    (trigger, task)
}

#[tokio::test]
async fn readiness_tracks_offline_connected_reconnect_and_ordered_shutdown() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = probe.local_addr().unwrap();
    drop(probe);

    let mut config = AgentRuntimeConfig::new(edge_addr, "127.0.0.1:9".parse().unwrap());
    config.connect_timeout = Duration::from_millis(100);
    config.handshake_timeout = Duration::from_millis(500);
    config.reconnect.initial_delay = Duration::from_millis(20);
    config.reconnect.max_delay = Duration::from_millis(50);
    config.reconnect.jitter_percent = 0;
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    let runtime = AgentRuntime::new(config).unwrap();
    let status = runtime.status_handle();
    let control = runtime.control();
    let operations = AgentOperationsRuntime::bind(
        AgentOperationsConfig::loopback("127.0.0.1:0".parse().unwrap()),
        status,
    )
    .await
    .unwrap();
    let operations_addr = operations.local_addr();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let (operations_trigger, operations_signal) = shutdown_channel();
    let agent_task = tokio::spawn(runtime.run_until_shutdown(agent_signal));
    let operations_task = tokio::spawn(operations.run_until_shutdown(operations_signal));

    wait_for_status(operations_addr, 503).await;
    let (edge_trigger, edge_task) = start_edge(edge_addr).await;
    wait_for_status(operations_addr, 200).await;
    let metrics = request(operations_addr, "/metrics").await.unwrap();
    assert!(metrics.contains("tunnelproxy_agent_transport_data_pipeline_capacity_frames 128"));

    edge_trigger.shutdown();
    edge_task.await.unwrap();
    wait_for_status(operations_addr, 503).await;
    let metrics = request(operations_addr, "/metrics").await.unwrap();
    assert!(metrics.contains("tunnelproxy_agent_disconnects_total 1"));
    assert!(metrics.contains("tunnelproxy_agent_connection_failures_total"));
    assert!(metrics.contains("tunnelproxy_agent_transport_data_pipeline_capacity_frames 0"));
    assert!(!metrics.contains("agent-dev"));
    assert!(!metrics.contains("tunnel-dev"));
    assert!(!metrics.contains(&edge_addr.to_string()));

    let (replacement_trigger, replacement_task) = start_edge(edge_addr).await;
    wait_for_status(operations_addr, 200).await;
    let metrics = request(operations_addr, "/metrics").await.unwrap();
    assert!(metrics.contains("tunnelproxy_agent_reconnects_total 1"));
    assert!(metrics.contains("tunnelproxy_agent_transport_data_pipeline_capacity_frames 128"));

    control.begin_draining();
    wait_for_status(operations_addr, 503).await;
    agent_trigger.shutdown();
    timeout(Duration::from_secs(2), agent_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(request(operations_addr, "/healthz")
        .await
        .unwrap()
        .starts_with("HTTP/1.1 200"));

    operations_trigger.shutdown();
    let outcome = timeout(Duration::from_secs(2), operations_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!outcome.was_forced());
    assert!(TcpStream::connect(operations_addr).await.is_err());
    replacement_trigger.shutdown();
    replacement_task.await.unwrap();
}

#[tokio::test]
async fn capacity_rejection_releases_after_the_stalled_connection_closes() {
    let runtime = AgentRuntime::new(AgentRuntimeConfig::new(
        "127.0.0.1:9".parse().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
    ))
    .unwrap();
    let mut config = AgentOperationsConfig::loopback("127.0.0.1:0".parse().unwrap());
    config.max_concurrent_connections = 1;
    config.header_read_timeout = Duration::from_secs(1);
    let operations = AgentOperationsRuntime::bind(config, runtime.status_handle())
        .await
        .unwrap();
    let addr = operations.local_addr();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(operations.run_until_shutdown(signal));

    let held = TcpStream::connect(addr).await.unwrap();
    sleep(Duration::from_millis(20)).await;
    let mut rejected = TcpStream::connect(addr).await.unwrap();
    let _ = rejected
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await;
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(1), rejected.read_to_end(&mut bytes)).await;
    assert!(bytes.is_empty());

    drop(held);
    let deadline = Instant::now() + Duration::from_secs(2);
    let metrics = loop {
        if let Ok(response) = request(addr, "/metrics").await {
            if response.starts_with("HTTP/1.1 200") {
                break response;
            }
        }
        assert!(
            Instant::now() < deadline,
            "capacity permit was not released"
        );
        sleep(Duration::from_millis(10)).await;
    };
    assert!(metrics.contains("tunnelproxy_agent_operations_capacity_rejections_total 1"));

    trigger.shutdown();
    let outcome = task.await.unwrap().unwrap();
    assert!(!outcome.was_forced());
}

#[tokio::test]
async fn managed_inventory_is_sorted_live_and_method_bounded() {
    let first_runtime = AgentRuntime::new(AgentRuntimeConfig::new(
        "127.0.0.1:9".parse().unwrap(),
        "127.0.0.1:3001".parse().unwrap(),
    ))
    .unwrap();
    let second_runtime = AgentRuntime::new(AgentRuntimeConfig::new(
        "127.0.0.1:9".parse().unwrap(),
        "127.0.0.1:3000".parse().unwrap(),
    ))
    .unwrap();
    let tunnel_b = AgentOperationsTunnel::new(
        TunnelId::new("tunnel-b").unwrap(),
        "127.0.0.1:3001".parse().unwrap(),
        first_runtime.status_handle(),
    );
    let tunnel_a = AgentOperationsTunnel::new(
        TunnelId::new("tunnel-a").unwrap(),
        "127.0.0.1:3000".parse().unwrap(),
        second_runtime.status_handle(),
    );
    let operations = AgentOperationsRuntime::bind_tunnels(
        AgentOperationsConfig::loopback("127.0.0.1:0".parse().unwrap()),
        vec![tunnel_b.clone(), tunnel_a],
    )
    .await
    .unwrap();
    let addr = operations.local_addr();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(operations.run_until_shutdown(signal));

    let initial = request(addr, "/tunnels").await.unwrap();
    assert!(initial.starts_with("HTTP/1.1 200"));
    assert!(initial.contains("content-type: application/json; charset=utf-8"));
    assert!(initial.contains("cache-control: no-store"));
    let body = response_body(&initial);
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["version"], 1);
    assert_eq!(parsed["configured"], 2);
    assert_eq!(parsed["ready"], 0);
    assert_eq!(parsed["tunnels"][0]["tunnel_id"], "tunnel-a");
    assert_eq!(parsed["tunnels"][1]["tunnel_id"], "tunnel-b");
    assert!(parsed["tunnels"][1]["public_url"].is_null());

    tunnel_b.publish_hostname(PublicHostname::new("b.example.test").unwrap());
    let updated = request(addr, "/tunnels").await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(response_body(&updated)).unwrap();
    assert_eq!(parsed["tunnels"][1]["public_url"], "https://b.example.test");

    let head = request_method(addr, "HEAD", "/tunnels").await.unwrap();
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(response_body(&head).is_empty());
    assert!(request_method(addr, "POST", "/tunnels")
        .await
        .unwrap()
        .starts_with("HTTP/1.1 405"));

    trigger.shutdown();
    assert!(!task.await.unwrap().unwrap().was_forced());
}

#[tokio::test]
async fn unmanaged_operations_do_not_expose_tunnel_inventory() {
    let runtime = AgentRuntime::new(AgentRuntimeConfig::new(
        "127.0.0.1:9".parse().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
    ))
    .unwrap();
    let operations = AgentOperationsRuntime::bind(
        AgentOperationsConfig::loopback("127.0.0.1:0".parse().unwrap()),
        runtime.status_handle(),
    )
    .await
    .unwrap();
    let addr = operations.local_addr();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(operations.run_until_shutdown(signal));

    assert!(request(addr, "/tunnels")
        .await
        .unwrap()
        .starts_with("HTTP/1.1 404"));

    trigger.shutdown();
    assert!(!task.await.unwrap().unwrap().was_forced());
}
