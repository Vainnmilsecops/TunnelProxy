//! Session 09 real-TCP coverage for bounded stream multiplexing and routing.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use tunnelproxy_agent::{
    connect, connect_registered_with_security, AgentTransportSecurity, ConnectOutcome,
    MultiplexedAgentConfig,
};
use tunnelproxy_common::{AgentId, TunnelId};
use tunnelproxy_edge::{
    EdgeRegistrationPolicy, EdgeSessionRouter, MultiplexedEdgeConfig, MultiplexedEdgeRuntime,
    RouteError,
};
use tunnelproxy_protocol::{HandshakeErrorCode, RegistrationRequest, TransportSessionId};

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
    config.stream_idle_timeout = Duration::from_secs(2);
    config
}

fn registration(label: &str) -> RegistrationRequest {
    RegistrationRequest::new(
        AgentId::new(format!("agent-{label}")).unwrap(),
        TunnelId::new(format!("tunnel-{label}")).unwrap(),
    )
}

async fn connect_as(edge_addr: SocketAddr, label: &str) -> tunnelproxy_agent::AgentSession {
    let registration = registration(label);
    match connect_registered_with_security(
        edge_addr,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &AgentTransportSecurity::PlaintextLoopback,
        &registration,
    )
    .await
    {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("Agent {label} failed: {reason}"),
    }
}

async fn spawn_harness(local_addr: SocketAddr, edge_config: MultiplexedEdgeConfig) -> Harness {
    let data_queue_capacity = edge_config.data_queue_capacity;
    let per_stream_queue_capacity = edge_config.per_stream_queue_capacity;
    let runtime = MultiplexedEdgeRuntime::bind(edge_config).await.unwrap();
    let edge_addr = runtime.agent_addr();
    let router = runtime.router();
    let edge = tokio::spawn(runtime.run());

    let outcome = connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await;
    let session = match outcome {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("Agent handshake failed: {reason}"),
    };
    let session_id = session.session_id;
    let mut agent_config = MultiplexedAgentConfig::new(local_addr);
    agent_config.connect_timeout = Duration::from_millis(300);
    agent_config.data_queue_capacity = data_queue_capacity;
    agent_config.per_stream_queue_capacity = per_stream_queue_capacity;
    agent_config.stream_idle_timeout = Duration::from_secs(2);
    let agent = tokio::spawn(session.run_multiplexed(agent_config));
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
            if router.connected_session_ids().await.contains(&session_id) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("session was not published to router");
}

#[tokio::test]
async fn duplicate_tunnel_is_rejected_and_claim_releases_after_disconnect() {
    let runtime = MultiplexedEdgeRuntime::bind(fast_edge_config())
        .await
        .unwrap();
    let edge_addr = runtime.agent_addr();
    let router = runtime.router();
    let edge = tokio::spawn(runtime.run());

    let first = match connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("first Agent failed: {reason}"),
    };
    wait_until_registered(&router, first.session_id).await;
    assert_eq!(
        router
            .resolve_tunnel(&TunnelId::new("tunnel-dev").unwrap())
            .await,
        Some(first.session_id)
    );

    let duplicate = connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await;
    assert!(matches!(
        duplicate,
        ConnectOutcome::Failed {
            reason: tunnelproxy_agent::AgentError::RegistrationRejected {
                code: Some(HandshakeErrorCode::TunnelAlreadyConnected)
            }
        }
    ));

    drop(first);
    timeout(Duration::from_secs(1), async {
        while router
            .resolve_tunnel(&TunnelId::new("tunnel-dev").unwrap())
            .await
            .is_some()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("tunnel claim was not released");

    assert!(matches!(
        connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await,
        ConnectOutcome::Established(_)
    ));
    edge.abort();
}

#[tokio::test]
async fn runtime_shutdown_releases_listener_and_router_rejects_new_streams() {
    let runtime = MultiplexedEdgeRuntime::bind(fast_edge_config())
        .await
        .unwrap();
    let addr = runtime.agent_addr();
    let router = runtime.router();
    let (trigger, signal) = tunnelproxy_edge::shutdown_channel();
    trigger.shutdown();

    let outcome = runtime
        .run_until_shutdown(
            signal,
            tunnelproxy_edge::RuntimeShutdownConfig::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome,
        tunnelproxy_edge::RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
    );
    TcpListener::bind(addr)
        .await
        .expect("multiplexed listener must be released");

    let pair_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::spawn(TcpStream::connect(pair_listener.local_addr().unwrap()));
    let (server, _) = pair_listener.accept().await.unwrap();
    let _client = client.await.unwrap().unwrap();
    let session_id = TransportSessionId::new(1).unwrap();
    assert!(matches!(
        router.open_stream(session_id, server).await,
        Err(RouteError::RuntimeDraining)
    ));
}

#[tokio::test]
async fn agent_honors_shutdown_requested_before_multiplex_loop_starts() {
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = MultiplexedEdgeRuntime::bind(fast_edge_config())
        .await
        .unwrap();
    let edge_addr = runtime.agent_addr();
    let edge = tokio::spawn(runtime.run());
    let session = match connect(edge_addr, Duration::from_secs(1), Duration::from_secs(1)).await {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("Agent handshake failed: {reason}"),
    };
    let config = MultiplexedAgentConfig::new(local.local_addr().unwrap());
    let (trigger, signal) = tunnelproxy_edge::shutdown_channel();
    trigger.shutdown();

    let reason = session
        .run_multiplexed_until_shutdown(
            config,
            signal,
            tunnelproxy_agent::RuntimeShutdownConfig::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    assert_eq!(
        reason,
        tunnelproxy_agent::AgentSessionCloseReason::LocalShutdown
    );
    edge.abort();
}

async fn spawn_echo_service(connection_count: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
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
    });
    (addr, task)
}

async fn route_client(
    router: &EdgeSessionRouter,
    session_id: TransportSessionId,
) -> Result<TcpStream, RouteError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap());
    let accepted = listener.accept();
    let (client, accepted) = tokio::join!(client, accepted);
    let client = client.unwrap();
    let (ingress, _) = accepted.unwrap();
    router.open_stream(session_id, ingress).await?;
    Ok(client)
}

async fn round_trip(mut client: TcpStream, payload: Vec<u8>) -> Vec<u8> {
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .expect("stream timed out")
        .unwrap();
    received
}

#[tokio::test]
async fn eight_streams_run_concurrently_without_cross_talk() {
    let stream_count = 8;
    let (local_addr, local) = spawn_echo_service(stream_count).await;
    let harness = spawn_harness(local_addr, fast_edge_config()).await;
    let mut tasks = Vec::new();

    for index in 0..stream_count {
        let client = route_client(&harness.router, harness.session_id)
            .await
            .unwrap();
        let payload: Vec<u8> = (0..64 * 1024)
            .map(|offset| ((offset + index * 17) % 251) as u8)
            .collect();
        tasks.push(tokio::spawn(async move {
            let received = round_trip(client, payload.clone()).await;
            assert_eq!(received, payload);
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
    timeout(Duration::from_secs(2), local)
        .await
        .unwrap()
        .unwrap();
    assert!(!harness.edge.is_finished());
    assert!(!harness.agent.is_finished());
}

#[tokio::test]
async fn saturated_data_queues_preserve_all_stream_progress_and_heartbeat() {
    let stream_count = 8;
    let (local_addr, local) = spawn_echo_service(stream_count).await;
    let mut config = fast_edge_config();
    config.data_queue_capacity = 2;
    config.per_stream_queue_capacity = 64;
    config.stream_idle_timeout = Duration::from_secs(5);
    let harness = spawn_harness(local_addr, config).await;
    let mut tasks = Vec::new();

    for index in 0..stream_count {
        let client = route_client(&harness.router, harness.session_id)
            .await
            .unwrap();
        let payload: Vec<u8> = (0..256 * 1024)
            .map(|offset| ((offset + index * 29) % 251) as u8)
            .collect();
        tasks.push(tokio::spawn(async move {
            let received = round_trip(client, payload.clone()).await;
            assert!(
                received == payload,
                "stream {index} response mismatch: received {} of {} bytes",
                received.len(),
                payload.len()
            );
        }));
    }

    timeout(Duration::from_secs(10), async {
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .expect("saturated fair DATA queues did not make bounded progress");
    timeout(Duration::from_secs(2), local)
        .await
        .unwrap()
        .unwrap();
    assert!(!harness.edge.is_finished());
    assert!(!harness.agent.is_finished());
}

#[tokio::test]
async fn stream_capacity_rejection_does_not_close_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let local = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let mut config = fast_edge_config();
    config.max_streams_per_session = 1;
    let harness = spawn_harness(local_addr, config).await;

    let first = route_client(&harness.router, harness.session_id)
        .await
        .unwrap();
    let second = route_client(&harness.router, harness.session_id).await;
    assert_eq!(
        second.unwrap_err(),
        RouteError::CapacityExceeded(harness.session_id)
    );
    assert!(!harness.agent.is_finished());
    drop(first);
    local.abort();
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

#[tokio::test]
async fn router_targets_the_requested_agent_session() {
    let mut edge_config = fast_edge_config();
    edge_config.registration =
        EdgeRegistrationPolicy::loopback_allowlist(vec![registration("a"), registration("b")]);
    let runtime = MultiplexedEdgeRuntime::bind(edge_config).await.unwrap();
    let edge_addr = runtime.agent_addr();
    let router = runtime.router();
    let edge = tokio::spawn(runtime.run());
    let local_a = spawn_fixed_response_service(b"agent-a").await;
    let local_b = spawn_fixed_response_service(b"agent-b").await;

    let session_a = connect_as(edge_addr, "a").await;
    let id_a = session_a.session_id;
    let agent_a = tokio::spawn(session_a.run_multiplexed(MultiplexedAgentConfig::new(local_a)));
    let session_b = connect_as(edge_addr, "b").await;
    let id_b = session_b.session_id;
    let agent_b = tokio::spawn(session_b.run_multiplexed(MultiplexedAgentConfig::new(local_b)));
    wait_until_registered(&router, id_a).await;
    wait_until_registered(&router, id_b).await;

    let client_b = route_client(&router, id_b).await.unwrap();
    let client_a = route_client(&router, id_a).await.unwrap();
    let (response_b, response_a) = tokio::join!(
        round_trip(client_b, b"route-me".to_vec()),
        round_trip(client_a, b"route-me".to_vec()),
    );
    assert_eq!(response_a, b"agent-a");
    assert_eq!(response_b, b"agent-b");

    agent_a.abort();
    agent_b.abort();
    edge.abort();
}

#[tokio::test]
async fn one_agent_local_failure_is_isolated_from_another_agent() {
    let mut edge_config = fast_edge_config();
    edge_config.registration =
        EdgeRegistrationPolicy::loopback_allowlist(vec![registration("good"), registration("bad")]);
    let runtime = MultiplexedEdgeRuntime::bind(edge_config).await.unwrap();
    let edge_addr = runtime.agent_addr();
    let router = runtime.router();
    let edge = tokio::spawn(runtime.run());
    let good_local = spawn_fixed_response_service(b"healthy").await;
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_local = unavailable.local_addr().unwrap();
    drop(unavailable);

    let good = connect_as(edge_addr, "good").await;
    let good_id = good.session_id;
    let good_task = tokio::spawn(good.run_multiplexed(MultiplexedAgentConfig::new(good_local)));
    let bad = connect_as(edge_addr, "bad").await;
    let bad_id = bad.session_id;
    let mut bad_config = MultiplexedAgentConfig::new(bad_local);
    bad_config.connect_timeout = Duration::from_millis(200);
    let bad_task = tokio::spawn(bad.run_multiplexed(bad_config));
    wait_until_registered(&router, good_id).await;
    wait_until_registered(&router, bad_id).await;

    let failed_route = route_client(&router, bad_id).await;
    assert!(
        matches!(failed_route, Err(RouteError::StreamRejected(_))),
        "unexpected failed-route outcome: {failed_route:?}"
    );
    let response = round_trip(
        route_client(&router, good_id).await.unwrap(),
        b"route-me".to_vec(),
    )
    .await;
    assert_eq!(response, b"healthy");
    assert!(!good_task.is_finished());
    assert!(!bad_task.is_finished());

    good_task.abort();
    bad_task.abort();
    edge.abort();
}
