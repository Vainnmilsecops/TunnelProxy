//! Session 10 real-TCP coverage for raw ingress route lifecycle.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use tunnelproxy_agent::{connect, ConnectOutcome, MultiplexedAgentConfig};
use tunnelproxy_edge::{
    EdgeSessionRouter, MultiplexedEdgeConfig, MultiplexedEdgeRuntime, RawIngressManagerConfig,
    RawIngressRouteConfig, RawIngressRouteError, RawIngressRouteId, RawIngressRouteManager,
    RawIngressRouteState,
};
use tunnelproxy_protocol::TransportSessionId;

struct Harness {
    router: EdgeSessionRouter,
    session_id: TransportSessionId,
    edge: tokio::task::JoinHandle<std::io::Result<()>>,
    agent: tokio::task::JoinHandle<
        Result<tunnelproxy_agent::AgentSessionCloseReason, tunnelproxy_agent::AgentError>,
    >,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.edge.abort();
        self.agent.abort();
    }
}

fn fast_edge_config() -> MultiplexedEdgeConfig {
    let mut config = MultiplexedEdgeConfig::dev_defaults();
    config.agent_listener.heartbeat_interval = Duration::from_millis(25);
    config.agent_listener.pong_timeout = Duration::from_millis(100);
    config.stream_open_timeout = Duration::from_secs(1);
    config.stream_idle_timeout = Duration::from_secs(3);
    config
}

async fn spawn_harness(local_addr: SocketAddr) -> Harness {
    let runtime = MultiplexedEdgeRuntime::bind(fast_edge_config())
        .await
        .unwrap();
    let edge_addr = runtime.agent_addr();
    let router = runtime.router();
    let edge = tokio::spawn(runtime.run());
    let session = match connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("Agent handshake failed: {reason}"),
    };
    let session_id = session.session_id;
    let mut config = MultiplexedAgentConfig::new(local_addr);
    config.connect_timeout = Duration::from_millis(300);
    config.stream_idle_timeout = Duration::from_secs(3);
    let agent = tokio::spawn(session.run_multiplexed(config));
    wait_until_registered(&router, session_id).await;
    Harness {
        router,
        session_id,
        edge,
        agent,
    }
}

async fn wait_until_registered(router: &EdgeSessionRouter, session_id: TransportSessionId) {
    timeout(Duration::from_secs(1), async {
        loop {
            if router.is_connected(session_id).await {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("session was not registered");
}

fn manager(router: &EdgeSessionRouter) -> RawIngressRouteManager {
    RawIngressRouteManager::new(router.clone(), RawIngressManagerConfig::default()).unwrap()
}

fn route_config(session_id: TransportSessionId) -> RawIngressRouteConfig {
    let mut config = RawIngressRouteConfig::new("127.0.0.1:0".parse().unwrap(), session_id);
    config.drain_timeout = Duration::from_secs(1);
    config
}

#[tokio::test]
async fn manager_shutdown_drains_routes_and_rejects_reuse() {
    let (local_addr, local) = spawn_echo_service(0).await;
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();

    let outcome = manager
        .shutdown(tunnelproxy_edge::RuntimeShutdownConfig::new(
            Duration::from_secs(1),
        ))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        tunnelproxy_edge::RuntimeShutdownOutcome::Drained { completed_tasks: 1 }
    );
    assert!(matches!(
        manager.add_route(route_config(harness.session_id)).await,
        Err(RawIngressRouteError::ManagerShuttingDown)
    ));
    local.await.unwrap();
}

#[tokio::test]
async fn manager_shutdown_forces_routes_that_exceed_the_deadline() {
    let (local_addr, local) = spawn_echo_service(1).await;
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let route = manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();
    let mut client = TcpStream::connect(route.local_addr).await.unwrap();
    client.write_all(b"active").await.unwrap();
    let mut echoed = [0_u8; 6];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"active");

    let outcome = manager
        .shutdown(tunnelproxy_edge::RuntimeShutdownConfig::new(
            Duration::from_millis(20),
        ))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        tunnelproxy_edge::RuntimeShutdownOutcome::Forced {
            completed_tasks: 0,
            aborted_tasks: 1,
        }
    );
    drop(client);
    local.await.unwrap();
}

async fn spawn_echo_service(connection_count: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = spawn_echo_on(listener, connection_count);
    (addr, task)
}

async fn spawn_fixed_response_service(response: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"route-me");
        socket.write_all(response).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    addr
}

fn spawn_echo_on(listener: TcpListener, connection_count: usize) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut handlers = Vec::with_capacity(connection_count);
        for _ in 0..connection_count {
            let (mut socket, _) = listener.accept().await.unwrap();
            handlers.push(tokio::spawn(async move {
                let mut buffer = [0_u8; 8192];
                loop {
                    let count = socket.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        socket.shutdown().await.unwrap();
                        break;
                    }
                    socket.write_all(&buffer[..count]).await.unwrap();
                }
            }));
        }
        for handler in handlers {
            handler.await.unwrap();
        }
    })
}

async fn round_trip(addr: SocketAddr, payload: Vec<u8>) -> Vec<u8> {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .expect("raw route stream timed out")
        .unwrap();
    received
}

async fn wait_for_active(
    manager: &RawIngressRouteManager,
    route_id: RawIngressRouteId,
    expected: usize,
) {
    timeout(Duration::from_secs(1), async {
        loop {
            if manager
                .get_route(route_id)
                .await
                .map(|route| route.active_connections == expected)
                .unwrap_or(false)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("route active count did not converge");
}

async fn wait_until_removed(manager: &RawIngressRouteManager, route_id: RawIngressRouteId) {
    timeout(Duration::from_secs(1), async {
        loop {
            if matches!(
                manager.get_route(route_id).await,
                Err(RawIngressRouteError::RouteNotFound(_))
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("route was not removed");
}

#[tokio::test]
async fn raw_route_golden_path_is_byte_exact_and_drains() {
    let (local_addr, local) = spawn_echo_service(1).await;
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let route = manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();
    let payload = b"session-10\0raw-route\xff".to_vec();

    assert_eq!(round_trip(route.local_addr, payload.clone()).await, payload);
    manager.drain_route(route.route_id).await.unwrap();
    wait_until_removed(&manager, route.route_id).await;
    local.await.unwrap();
    assert!(!harness.agent.is_finished());
}

#[tokio::test]
async fn remove_route_without_active_stream_stops_listener_and_cleans_registry() {
    let (local_addr, local) = spawn_echo_service(0).await;
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let route = manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();

    manager.remove_route(route.route_id).await.unwrap();
    wait_until_removed(&manager, route.route_id).await;
    assert!(TcpStream::connect(route.local_addr).await.is_err());
    local.await.unwrap();
}

#[tokio::test]
async fn concurrent_route_clients_do_not_cross_talk_and_heartbeat_survives() {
    let count = 6;
    let (local_addr, local) = spawn_echo_service(count).await;
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let route = manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for index in 0..count {
        let addr = route.local_addr;
        let payload: Vec<u8> = (0..48 * 1024)
            .map(|offset| ((offset + index * 31) % 251) as u8)
            .collect();
        tasks.push(tokio::spawn(async move {
            assert_eq!(round_trip(addr, payload.clone()).await, payload);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!harness.agent.is_finished());
    assert!(!harness.edge.is_finished());
    manager.drain_route(route.route_id).await.unwrap();
    local.await.unwrap();
}

#[tokio::test]
async fn two_raw_routes_target_two_exact_agent_sessions() {
    let runtime = MultiplexedEdgeRuntime::bind(fast_edge_config())
        .await
        .unwrap();
    let edge_addr = runtime.agent_addr();
    let router = runtime.router();
    let edge = tokio::spawn(runtime.run());
    let local_a = spawn_fixed_response_service(b"raw-agent-a").await;
    let local_b = spawn_fixed_response_service(b"raw-agent-b").await;

    let session_a = match connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("Agent A failed: {reason}"),
    };
    let id_a = session_a.session_id;
    let agent_a = tokio::spawn(session_a.run_multiplexed(MultiplexedAgentConfig::new(local_a)));
    let session_b = match connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("Agent B failed: {reason}"),
    };
    let id_b = session_b.session_id;
    let agent_b = tokio::spawn(session_b.run_multiplexed(MultiplexedAgentConfig::new(local_b)));
    wait_until_registered(&router, id_a).await;
    wait_until_registered(&router, id_b).await;
    let manager = manager(&router);
    let route_a = manager.add_route(route_config(id_a)).await.unwrap();
    let route_b = manager.add_route(route_config(id_b)).await.unwrap();

    let (response_b, response_a) = tokio::join!(
        round_trip(route_b.local_addr, b"route-me".to_vec()),
        round_trip(route_a.local_addr, b"route-me".to_vec()),
    );
    assert_eq!(response_a, b"raw-agent-a");
    assert_eq!(response_b, b"raw-agent-b");
    manager.drain_route(route_a.route_id).await.unwrap();
    manager.drain_route(route_b.route_id).await.unwrap();

    agent_a.abort();
    agent_b.abort();
    edge.abort();
}

#[tokio::test]
async fn route_capacity_rejects_only_the_extra_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let local = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let mut config = route_config(harness.session_id);
    config.max_concurrent_connections = 1;
    let route = manager.add_route(config).await.unwrap();
    let first = TcpStream::connect(route.local_addr).await.unwrap();
    wait_for_active(&manager, route.route_id, 1).await;

    let mut second = TcpStream::connect(route.local_addr).await.unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(1), second.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert!(received.is_empty());
    assert_eq!(
        manager.get_route(route.route_id).await.unwrap().state,
        RawIngressRouteState::Active
    );
    drop(first);
    local.abort();
}

#[tokio::test]
async fn drain_stops_accepting_but_allows_active_stream_to_finish() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let local = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        let _ = request_tx.send(request);
        let _ = release_rx.await;
        socket.write_all(b"drained-response").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let mut config = route_config(harness.session_id);
    config.drain_timeout = Duration::from_secs(3);
    let route = manager.add_route(config).await.unwrap();
    let mut client = TcpStream::connect(route.local_addr).await.unwrap();
    client.write_all(b"active-request").await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(request_rx.await.unwrap(), b"active-request");

    let draining_manager = manager.clone();
    let route_id = route.route_id;
    let drain = tokio::spawn(async move { draining_manager.drain_route(route_id).await });
    timeout(Duration::from_secs(1), async {
        loop {
            if manager
                .get_route(route_id)
                .await
                .map(|status| status.state == RawIngressRouteState::Draining)
                .unwrap_or(false)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        timeout(
            Duration::from_millis(200),
            TcpStream::connect(route.local_addr)
        )
        .await,
        Ok(Err(_)) | Err(_)
    ));
    let _ = release_tx.send(());
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"drained-response");
    drain.await.unwrap().unwrap();
    local.await.unwrap();
}

#[tokio::test]
async fn drain_timeout_is_typed_and_route_finishes_after_connection_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let local = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let mut config = route_config(harness.session_id);
    config.drain_timeout = Duration::from_millis(50);
    let route = manager.add_route(config).await.unwrap();
    let client = TcpStream::connect(route.local_addr).await.unwrap();
    wait_for_active(&manager, route.route_id, 1).await;

    assert!(matches!(
        manager.drain_route(route.route_id).await,
        Err(RawIngressRouteError::DrainTimeout(id)) if id == route.route_id
    ));
    drop(client);
    local.abort();
    wait_until_removed(&manager, route.route_id).await;
}

#[tokio::test]
async fn agent_disconnect_removes_bound_route() {
    let (local_addr, local) = spawn_echo_service(0).await;
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let route = manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();

    harness.agent.abort();
    wait_until_removed(&manager, route.route_id).await;
    assert!(TcpStream::connect(route.local_addr).await.is_err());
    assert!(manager.list_routes().await.is_empty());
    local.await.unwrap();
}

#[tokio::test]
async fn manager_capacity_and_disconnected_target_are_rejected() {
    let (local_addr, local) = spawn_echo_service(0).await;
    let harness = spawn_harness(local_addr).await;
    let manager = RawIngressRouteManager::new(
        harness.router.clone(),
        RawIngressManagerConfig { max_routes: 1 },
    )
    .unwrap();
    let first = manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();
    assert!(matches!(
        manager.add_route(route_config(harness.session_id)).await,
        Err(RawIngressRouteError::RouteCapacityExceeded)
    ));
    let missing = TransportSessionId::new(harness.session_id.get() + 100).unwrap();
    assert!(matches!(
        manager.add_route(route_config(missing)).await,
        Err(RawIngressRouteError::TargetSessionNotConnected(id)) if id == missing
    ));
    manager.drain_route(first.route_id).await.unwrap();
    local.await.unwrap();
}

#[tokio::test]
async fn local_connect_failure_does_not_kill_route_listener() {
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = unavailable.local_addr().unwrap();
    drop(unavailable);
    let harness = spawn_harness(local_addr).await;
    let manager = manager(&harness.router);
    let route = manager
        .add_route(route_config(harness.session_id))
        .await
        .unwrap();

    let mut failed = TcpStream::connect(route.local_addr).await.unwrap();
    let mut empty = Vec::new();
    timeout(Duration::from_secs(1), failed.read_to_end(&mut empty))
        .await
        .unwrap()
        .unwrap();
    assert!(empty.is_empty());
    assert_eq!(
        manager.get_route(route.route_id).await.unwrap().state,
        RawIngressRouteState::Active
    );

    let local_listener = TcpListener::bind(local_addr).await.unwrap();
    let local = spawn_echo_on(local_listener, 1);
    assert_eq!(
        round_trip(route.local_addr, b"recovered".to_vec()).await,
        b"recovered"
    );
    manager.drain_route(route.route_id).await.unwrap();
    local.await.unwrap();
}
