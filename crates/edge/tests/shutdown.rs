//! Session 11 real-TCP coverage for supervised runtime shutdown.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use tunnelproxy_edge::agent_transport::{
    AgentListenerConfig, AgentTransportListener, SingleStreamEdgeConfig, SingleStreamEdgeRuntime,
};
use tunnelproxy_edge::{
    run_listener_until_shutdown, shutdown_channel, ForwardConfig, Forwarder, RuntimeShutdownConfig,
    RuntimeShutdownOutcome,
};

async fn unused_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn connect_eventually(addr: SocketAddr) -> TcpStream {
    timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(socket) = TcpStream::connect(addr).await {
                break socket;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener did not bind")
}

#[tokio::test]
async fn shutdown_requested_before_start_is_not_lost() {
    let addr = unused_loopback_addr().await;
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();

    let outcome = run_listener_until_shutdown(
        addr,
        signal,
        RuntimeShutdownConfig::new(Duration::from_secs(1)),
    )
    .await
    .unwrap();

    assert_eq!(
        outcome,
        RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
    );
    TcpListener::bind(addr)
        .await
        .expect("shutdown must release the listener");
}

#[tokio::test]
async fn echo_forces_a_connection_that_exceeds_the_deadline() {
    let addr = unused_loopback_addr().await;
    let (trigger, signal) = shutdown_channel();
    let runtime = tokio::spawn(run_listener_until_shutdown(
        addr,
        signal,
        RuntimeShutdownConfig::new(Duration::from_millis(20)),
    ));
    let mut client = connect_eventually(addr).await;
    client.write_all(b"accepted").await.unwrap();
    let mut echoed = [0_u8; 8];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"accepted");
    trigger.shutdown();

    assert_eq!(
        runtime.await.unwrap().unwrap(),
        RuntimeShutdownOutcome::Forced {
            completed_tasks: 0,
            aborted_tasks: 1,
        }
    );
}

#[tokio::test]
async fn forwarder_forces_a_stalled_relay_and_joins_it() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (socket, _) = upstream.accept().await.unwrap();
        let _ = accepted_tx.send(());
        std::future::pending::<()>().await;
        drop(socket);
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let forwarder = Forwarder::new(ForwardConfig {
        listen_addr,
        upstream_addr,
        max_connections: 1,
        connect_timeout: Duration::from_secs(1),
        relay_idle_timeout: tunnelproxy_edge::DEFAULT_RELAY_IDLE_TIMEOUT,
    })
    .unwrap();
    let (trigger, signal) = shutdown_channel();
    let runtime = tokio::spawn(forwarder.run_with_listener_until_shutdown(
        listener,
        signal,
        RuntimeShutdownConfig::new(Duration::from_millis(20)),
    ));
    let _client = TcpStream::connect(listen_addr).await.unwrap();
    timeout(Duration::from_secs(3), accepted_rx)
        .await
        .unwrap()
        .unwrap();
    trigger.shutdown();

    assert_eq!(
        runtime.await.unwrap().unwrap(),
        RuntimeShutdownOutcome::Forced {
            completed_tasks: 0,
            aborted_tasks: 1,
        }
    );
    upstream_task.abort();
    assert!(upstream_task.await.unwrap_err().is_cancelled());
    TcpListener::bind(listen_addr)
        .await
        .expect("forwarder releases listener");
}

#[tokio::test]
async fn prebound_forwarder_honors_shutdown_before_accept() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();
    // A queued client must not be admitted after shutdown was requested.
    let _client = TcpStream::connect(addr).await.unwrap();
    let result = Forwarder::new(ForwardConfig::dev_defaults())
        .unwrap()
        .run_with_listener_until_shutdown(
            listener,
            signal,
            RuntimeShutdownConfig::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    assert_eq!(
        result,
        RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
    );
    TcpListener::bind(addr).await.unwrap();
}

#[tokio::test]
async fn prebound_forwarder_drains_an_admitted_relay() {
    timeout(Duration::from_secs(5), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = ForwardConfig::dev_defaults();
        config.upstream_addr = upstream.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (trigger, signal) = shutdown_channel();
        let runtime = tokio::spawn(
            Forwarder::new(config)
                .unwrap()
                .run_with_listener_until_shutdown(
                    listener,
                    signal,
                    RuntimeShutdownConfig::new(Duration::from_secs(3)),
                ),
        );
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut upstream_socket, _) = upstream.accept().await.unwrap();
        trigger.shutdown();
        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        upstream_socket.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"x");
        upstream_socket.write_all(b"y").await.unwrap();
        upstream_socket.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"y");
        assert!(matches!(
            runtime.await.unwrap().unwrap(),
            RuntimeShutdownOutcome::Drained { .. }
        ));
        TcpListener::bind(addr).await.unwrap();
    })
    .await
    .expect("graceful relay drain exceeded deadline");
}

#[tokio::test]
async fn agent_listener_propagates_shutdown_to_a_silent_handshake() {
    let mut config = AgentListenerConfig::dev_defaults();
    config.listen_addr = "127.0.0.1:0".parse().unwrap();
    config.handshake_timeout = Duration::from_secs(5);
    let mut listener = AgentTransportListener::bind(config).await.unwrap();
    let addr = listener.local_addr();
    let (trigger, signal) = shutdown_channel();
    let runtime = tokio::spawn(async move {
        listener
            .run_until_shutdown(signal, RuntimeShutdownConfig::new(Duration::from_secs(1)))
            .await
    });
    let _silent_agent = TcpStream::connect(addr).await.unwrap();
    tokio::task::yield_now().await;
    trigger.shutdown();

    assert!(matches!(
        runtime.await.unwrap().unwrap(),
        RuntimeShutdownOutcome::Drained {
            completed_tasks: 0 | 1
        }
    ));
}

#[tokio::test]
async fn single_stream_runtime_releases_both_listeners_on_shutdown() {
    let mut config = SingleStreamEdgeConfig::dev_defaults();
    config.agent_listener.listen_addr = "127.0.0.1:0".parse().unwrap();
    config.ingress_listen_addr = "127.0.0.1:0".parse().unwrap();
    let runtime = SingleStreamEdgeRuntime::bind(config).await.unwrap();
    let agent_addr = runtime.agent_addr();
    let ingress_addr = runtime.ingress_addr();
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();

    assert_eq!(
        runtime
            .run_until_shutdown(signal, RuntimeShutdownConfig::new(Duration::from_secs(1)),)
            .await
            .unwrap(),
        RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
    );
    TcpListener::bind(agent_addr).await.unwrap();
    TcpListener::bind(ingress_addr).await.unwrap();
}
