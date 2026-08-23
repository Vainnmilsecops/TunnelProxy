//! Session 12 real-TCP coverage for process-level Edge/Agent composition.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use tunnelproxy_agent::{
    AgentRuntime, AgentRuntimeConfig, AgentRuntimeOutcome, RuntimeShutdownConfig,
};
use tunnelproxy_edge::{
    shutdown_channel, EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeError, RuntimeShutdownOutcome,
};

async fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn edge_config(raw_addr: SocketAddr) -> EdgeRuntimeConfig {
    let mut config = EdgeRuntimeConfig::dev_defaults();
    config.multiplex.agent_listener.listen_addr = "127.0.0.1:0".parse().unwrap();
    config.multiplex.agent_listener.handshake_timeout = Duration::from_secs(1);
    config.multiplex.agent_listener.heartbeat_interval = Duration::from_millis(25);
    config.multiplex.agent_listener.pong_timeout = Duration::from_millis(100);
    config.multiplex.stream_open_timeout = Duration::from_secs(1);
    config.multiplex.stream_idle_timeout = Duration::from_secs(2);
    config.raw_listen_addr = raw_addr;
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    config
}

fn agent_runtime(edge_addr: SocketAddr, local_addr: SocketAddr) -> AgentRuntime {
    let mut config = AgentRuntimeConfig::new(edge_addr, local_addr);
    config.connect_timeout = Duration::from_secs(1);
    config.handshake_timeout = Duration::from_secs(1);
    config.multiplex.connect_timeout = Duration::from_secs(1);
    config.multiplex.stream_idle_timeout = Duration::from_secs(2);
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    AgentRuntime::new(config).unwrap()
}

async fn connect_eventually(addr: SocketAddr) -> TcpStream {
    timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect(addr).await {
                Ok(socket) => break socket,
                Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
            }
        }
    })
    .await
    .expect("raw route was not bound")
}

async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            if count == 0 {
                let _ = socket.shutdown().await;
                break;
            }
            socket.write_all(&buffer[..count]).await.unwrap();
        }
    });
    (addr, task)
}

#[tokio::test]
async fn edge_shutdown_before_agent_releases_transport_listener() {
    let raw_addr = unused_addr().await;
    let runtime = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let agent_addr = runtime.agent_addr();
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();

    let outcome = runtime.run_until_shutdown(signal).await.unwrap();
    assert_eq!(outcome.raw_addr, None);
    assert_eq!(
        outcome.raw_routes,
        RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
    );
    assert!(!outcome.was_forced());
    TcpListener::bind(agent_addr).await.unwrap();
}

#[tokio::test]
async fn composed_runtimes_forward_bytes_and_shutdown_cleanly() {
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let edge = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));

    let mut client = connect_eventually(raw_addr).await;
    let payload = b"session-12-runtime";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
    let mut end = Vec::new();
    client.read_to_end(&mut end).await.unwrap();

    edge_trigger.shutdown();
    agent_trigger.shutdown();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(edge_outcome.raw_addr, Some(raw_addr));
    assert!(!edge_outcome.was_forced());
    let agent_outcome = agent_task.await.unwrap().unwrap();
    assert!(matches!(
        agent_outcome,
        AgentRuntimeOutcome::SessionClosed { .. }
    ));
    local_task.await.unwrap();
    TcpListener::bind(edge_addr).await.unwrap();
    TcpListener::bind(raw_addr).await.unwrap();
}

#[tokio::test]
async fn raw_bind_failure_rolls_back_the_agent_listener() {
    let occupied_raw = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw_addr = occupied_raw.local_addr().unwrap();
    let edge = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (_edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (_agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(
        agent_runtime(edge_addr, unused_addr().await).run_until_shutdown(agent_signal),
    );

    assert!(matches!(
        edge_task.await.unwrap(),
        Err(EdgeRuntimeError::RouteStartup(_))
    ));
    let _ = agent_task.await.unwrap();
    TcpListener::bind(edge_addr)
        .await
        .expect("startup rollback must release Agent listener");
}

#[tokio::test]
async fn agent_shutdown_before_connect_skips_network_startup() {
    let runtime = agent_runtime(unused_addr().await, unused_addr().await);
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();
    assert_eq!(
        runtime.run_until_shutdown(signal).await.unwrap(),
        AgentRuntimeOutcome::ShutdownBeforeConnect
    );
}
