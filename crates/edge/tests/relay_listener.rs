//! Legacy wrappers exercise the production Forwarder admission and shutdown path.
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tunnelproxy_edge::{
    run_relay_listener_until_shutdown, run_relay_listener_with_listener,
    run_relay_listener_with_listener_until_shutdown, shutdown_channel, ForwardConfig,
    ForwardConfigError, Forwarder, RuntimeShutdownConfig, RuntimeShutdownOutcome,
};

#[test]
fn forwarder_rejects_unsupported_semaphore_capacity_without_panicking() {
    for capacity in [Semaphore::MAX_PERMITS + 1, usize::MAX] {
        let config = ForwardConfig {
            max_connections: capacity,
            ..ForwardConfig::dev_defaults()
        };
        assert_eq!(
            config.validate(),
            Err(ForwardConfigError::MaxConnectionsTooLarge)
        );
        assert!(matches!(
            Forwarder::new(config.clone()),
            Err(ForwardConfigError::MaxConnectionsTooLarge)
        ));
        assert!(matches!(
            Forwarder::new_with_per_ip_limit(config, 1),
            Err(ForwardConfigError::MaxConnectionsTooLarge)
        ));
    }
    for capacity in [1, Semaphore::MAX_PERMITS] {
        let config = ForwardConfig {
            max_connections: capacity,
            ..ForwardConfig::dev_defaults()
        };
        assert_eq!(
            Forwarder::new(config.clone()).unwrap().available_permits(),
            capacity
        );
        assert_eq!(
            Forwarder::new_with_per_ip_limit(config, 1)
                .unwrap()
                .available_permits(),
            capacity
        );
    }
}

async fn admission(global: bool, graceful: bool) {
    timeout(Duration::from_secs(15), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (trigger, signal) = shutdown_channel();
        let server = tokio::spawn(async move {
            if graceful {
                run_relay_listener_with_listener_until_shutdown(
                    listener,
                    upstream_addr,
                    signal,
                    RuntimeShutdownConfig::new(Duration::from_secs(3)),
                )
                .await
                .map(|_| ())
            } else {
                run_relay_listener_with_listener(listener, upstream_addr).await
            }
        });
        let mut clients = Vec::new();
        let mut peers = Vec::new();
        for index in 0..if global { 100 } else { 25 } {
            let socket = TcpSocket::new_v4().unwrap();
            socket
                .bind(format!("127.0.0.{}:0", index / 25 + 1).parse().unwrap())
                .unwrap();
            let client = socket.connect(addr).await.unwrap();
            let (peer, _) = upstream.accept().await.unwrap();
            clients.push(client);
            peers.push(peer);
        }
        // For global rejection use a source with an unused peer bucket.
        let socket = TcpSocket::new_v4().unwrap();
        socket
            .bind(
                if global { "127.0.0.5:0" } else { "127.0.0.1:0" }
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        let mut rejected = socket.connect(addr).await.unwrap();
        let mut byte = [0];
        assert_eq!(rejected.read(&mut byte).await.unwrap(), 0);

        // Close one admitted relay; EOF synchronizes with cleanup and capacity release.
        clients[0].shutdown().await.unwrap();
        assert_eq!(peers[0].read(&mut byte).await.unwrap(), 0);
        peers[0].shutdown().await.unwrap();
        assert_eq!(clients[0].read(&mut byte).await.unwrap(), 0);
        let mut replacement = TcpStream::connect(addr).await.unwrap();
        replacement.write_all(b"r").await.unwrap();
        let (mut replacement_peer, _) = upstream.accept().await.unwrap();
        // If rejection had dialed upstream, accept would return that stale connection.
        replacement_peer.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'r']);
        replacement_peer.write_all(b"s").await.unwrap();
        replacement.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b's']);
        drop(clients);
        drop(peers);
        drop(replacement);
        drop(replacement_peer);
        if graceful {
            trigger.shutdown();
            server.await.unwrap().unwrap();
        } else {
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        }
        TcpListener::bind(addr).await.unwrap();
    })
    .await
    .expect("admission scenario exceeded deadline");
}

#[tokio::test]
async fn relay_wrapper_enforces_peer_limit_and_releases_capacity() {
    admission(false, false).await;
}
#[tokio::test]
async fn relay_wrapper_enforces_global_limit_and_releases_capacity() {
    admission(true, false).await;
}
#[tokio::test]
async fn shutdown_relay_wrapper_enforces_peer_limit() {
    admission(false, true).await;
}
#[tokio::test]
async fn shutdown_relay_wrapper_enforces_global_limit() {
    admission(true, true).await;
}

#[tokio::test]
async fn relay_shutdown_before_accept_and_invalid_config_release_listener() {
    timeout(Duration::from_secs(5), async {
        for invalid in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (trigger, signal) = shutdown_channel();
            trigger.shutdown();
            let _queued = TcpStream::connect(addr).await.unwrap();
            let result = run_relay_listener_with_listener_until_shutdown(
                listener,
                upstream.local_addr().unwrap(),
                signal,
                RuntimeShutdownConfig::new(if invalid {
                    Duration::ZERO
                } else {
                    Duration::from_secs(1)
                }),
            )
            .await;
            if invalid {
                assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
            } else {
                assert_eq!(
                    result.unwrap(),
                    RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
                );
            }
            TcpListener::bind(addr).await.unwrap();
        }
        let (trigger, signal) = shutdown_channel();
        trigger.shutdown();
        assert_eq!(
            run_relay_listener_until_shutdown(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
                signal,
                RuntimeShutdownConfig::new(Duration::from_secs(1))
            )
            .await
            .unwrap(),
            RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_wrapper_drains_half_closed_connection() {
    shutdown_relay(false).await;
}
#[tokio::test]
async fn relay_wrapper_forces_stalled_connection() {
    shutdown_relay(true).await;
}

async fn shutdown_relay(force: bool) {
    timeout(Duration::from_secs(5), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (trigger, signal) = shutdown_channel();
        let server = tokio::spawn(run_relay_listener_with_listener_until_shutdown(
            listener,
            upstream.local_addr().unwrap(),
            signal,
            RuntimeShutdownConfig::new(if force {
                Duration::from_millis(20)
            } else {
                Duration::from_secs(3)
            }),
        ));
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut peer, _) = upstream.accept().await.unwrap();
        trigger.shutdown();
        if force {
            assert_eq!(
                server.await.unwrap().unwrap(),
                RuntimeShutdownOutcome::Forced {
                    completed_tasks: 0,
                    aborted_tasks: 1
                }
            );
            let mut byte = [0];
            assert_eq!(client.read(&mut byte).await.unwrap(), 0);
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        } else {
            client.write_all(b"request").await.unwrap();
            client.shutdown().await.unwrap();
            let mut request = Vec::new();
            peer.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            peer.write_all(b"response").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
            assert!(matches!(
                server.await.unwrap().unwrap(),
                RuntimeShutdownOutcome::Drained { .. }
            ));
        }
        TcpListener::bind(addr).await.unwrap();
    })
    .await
    .expect("shutdown scenario exceeded deadline");
}
