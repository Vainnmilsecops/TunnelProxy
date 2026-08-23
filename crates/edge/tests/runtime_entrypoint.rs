//! Session 13 real-TCP coverage for process-level Edge/Agent recovery.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use tunnelproxy_agent::{
    AgentRuntime, AgentRuntimeConfig, AgentRuntimeError, AgentRuntimeOutcome, RuntimeShutdownConfig,
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
    config.reconnect.initial_delay = Duration::from_millis(10);
    config.reconnect.max_delay = Duration::from_millis(40);
    config.reconnect.jitter_percent = 0;
    config.reconnect.stable_session_reset_after = Duration::from_secs(1);
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
    spawn_echo_connections(1).await
}

async fn spawn_echo_connections(
    connection_count: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..connection_count {
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
        }
    });
    (addr, task)
}

async fn round_trip(raw_addr: SocketAddr, payload: &[u8]) {
    let mut client = connect_eventually(raw_addr).await;
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
    let mut end = Vec::new();
    client.read_to_end(&mut end).await.unwrap();
}

async fn wait_until_bindable(addr: SocketAddr) {
    timeout(Duration::from_secs(2), async {
        loop {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    drop(listener);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
            }
        }
    })
    .await
    .expect("listener was not released");
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

    round_trip(raw_addr, b"session-13-runtime").await;

    edge_trigger.shutdown();
    agent_trigger.shutdown();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(edge_outcome.raw_addr, Some(raw_addr));
    assert!(!edge_outcome.was_forced());
    let agent_outcome = agent_task.await.unwrap().unwrap();
    assert!(agent_outcome.established_sessions >= 1);
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
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(
        agent_runtime(edge_addr, unused_addr().await).run_until_shutdown(agent_signal),
    );

    assert!(matches!(
        edge_task.await.unwrap(),
        Err(EdgeRuntimeError::RouteStartup(_))
    ));
    agent_trigger.shutdown();
    let _ = agent_task.await.unwrap();
    TcpListener::bind(edge_addr)
        .await
        .expect("startup rollback must release Agent listener");
}

#[tokio::test]
async fn agent_shutdown_interrupts_a_long_reconnect_backoff() {
    let mut config = AgentRuntimeConfig::new(unused_addr().await, unused_addr().await);
    config.connect_timeout = Duration::from_millis(100);
    config.reconnect.initial_delay = Duration::from_secs(5);
    config.reconnect.max_delay = Duration::from_secs(5);
    config.reconnect.jitter_percent = 0;
    let runtime = AgentRuntime::new(config).unwrap();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(runtime.run_until_shutdown(signal));

    tokio::time::sleep(Duration::from_millis(50)).await;
    trigger.shutdown();
    let outcome = timeout(Duration::from_millis(250), task)
        .await
        .expect("shutdown did not interrupt reconnect sleep")
        .unwrap()
        .unwrap();
    assert_eq!(outcome.connection_attempts, 1);
    assert_eq!(outcome.established_sessions, 0);
}

#[tokio::test]
async fn reconnect_budget_exhaustion_is_typed() {
    let mut config = AgentRuntimeConfig::new(unused_addr().await, unused_addr().await);
    config.connect_timeout = Duration::from_millis(100);
    config.reconnect.initial_delay = Duration::from_millis(5);
    config.reconnect.max_delay = Duration::from_millis(5);
    config.reconnect.jitter_percent = 0;
    config.reconnect.max_attempts = Some(2);
    let runtime = AgentRuntime::new(config).unwrap();
    let (_trigger, signal) = shutdown_channel();

    let error = timeout(Duration::from_secs(1), runtime.run_until_shutdown(signal))
        .await
        .expect("reconnect budget was not exhausted")
        .unwrap_err();
    assert!(matches!(
        error,
        AgentRuntimeError::ReconnectExhausted {
            consecutive_failures: 2,
            ..
        }
    ));
}

#[tokio::test]
async fn edge_rebinds_the_same_raw_address_to_a_replacement_agent() {
    let (local_addr, local_task) = spawn_echo_connections(2).await;
    let raw_addr = unused_addr().await;
    let edge = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let (_agent_one_trigger, agent_one_signal) = shutdown_channel();
    let agent_one_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_one_signal));
    round_trip(raw_addr, b"first-agent").await;

    agent_one_task.abort();
    let _ = agent_one_task.await;
    wait_until_bindable(raw_addr).await;

    let (agent_two_trigger, agent_two_signal) = shutdown_channel();
    let agent_two_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_two_signal));
    round_trip(raw_addr, b"replacement-agent").await;

    agent_two_trigger.shutdown();
    edge_trigger.shutdown();
    let agent_outcome = agent_two_task.await.unwrap().unwrap();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(agent_outcome.established_sessions, 1);
    assert_eq!(edge_outcome.raw_addr, Some(raw_addr));
    assert_eq!(edge_outcome.agent_sessions_seen, 2);
    assert_eq!(edge_outcome.route_generations, 2);
    assert_eq!(edge_outcome.successful_recoveries, 1);
    local_task.await.unwrap();
}

#[tokio::test]
async fn agent_reconnects_after_edge_restart() {
    let (local_addr, local_task) = spawn_echo_connections(2).await;
    let agent_addr = unused_addr().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.agent_listener.listen_addr = agent_addr;

    let edge_one = EdgeRuntime::bind(config.clone()).await.unwrap();
    let (edge_one_trigger, edge_one_signal) = shutdown_channel();
    let edge_one_task = tokio::spawn(edge_one.run_until_shutdown(edge_one_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(agent_addr, local_addr).run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"before-edge-restart").await;

    edge_one_trigger.shutdown();
    edge_one_task.await.unwrap().unwrap();
    let edge_two = timeout(Duration::from_secs(1), EdgeRuntime::bind(config))
        .await
        .expect("second Edge bind timed out")
        .expect("second Edge could not reuse listener addresses");
    let (edge_two_trigger, edge_two_signal) = shutdown_channel();
    let edge_two_task = tokio::spawn(edge_two.run_until_shutdown(edge_two_signal));
    round_trip(raw_addr, b"after-edge-restart").await;

    agent_trigger.shutdown();
    edge_two_trigger.shutdown();
    let agent_outcome = agent_task.await.unwrap().unwrap();
    let edge_outcome = edge_two_task.await.unwrap().unwrap();
    assert!(agent_outcome.connection_attempts >= 2);
    assert!(agent_outcome.established_sessions >= 2);
    assert!(agent_outcome.successful_reconnects >= 1);
    assert_eq!(edge_outcome.raw_addr, Some(raw_addr));
    local_task.await.unwrap();
}

#[tokio::test]
async fn agent_shutdown_before_connect_skips_network_startup() {
    let runtime = agent_runtime(unused_addr().await, unused_addr().await);
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();
    assert_eq!(
        runtime.run_until_shutdown(signal).await.unwrap(),
        AgentRuntimeOutcome {
            connection_attempts: 0,
            established_sessions: 0,
            successful_reconnects: 0,
            last_session_id: None,
        }
    );
}
