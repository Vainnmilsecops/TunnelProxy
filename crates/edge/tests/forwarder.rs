//! End-to-end TCP forwarder integration tests for `tunnelproxy-edge`.
//!
//! These tests drive the public Session 04 API ([`Forwarder`],
//! [`ForwardConfig`], [`forward_handle_connection`],
//! [`ConnectionIdAllocator`]) over real loopback TCP sockets. They
//! bind on `127.0.0.1:0` (ephemeral ports), never touch the public
//! internet, and use deterministic synchronization rather than
//! arbitrary sleeps.
//!
//! Tests covering the Session 03 byte-stream semantics (full-duplex,
//! large payload, half-close) live in `tests/relay_tcp.rs`. Tests
//! covering the Session 02 echo baseline live in `tests/edge_tcp.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use tunnelproxy_edge::{
    forward_handle_connection, forward_handle_connection_with_idle_timeout, ConnectionId,
    ConnectionIdAllocator, ConnectionLifecycle, ConnectionOutcome, ForwardConfig,
    ForwardConfigError, ForwardError, Forwarder, RelayStats,
};

/// Per-connection buffer used by upstream test servers.
const TEST_BUFFER_SIZE: usize = 16 * 1024;

/// Spawn a tiny echo upstream bound on an ephemeral port.
async fn spawn_echo_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; TEST_BUFFER_SIZE];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    (addr, task)
}

/// Spawn an upstream that, for each accepted connection, reads until
/// EOF and then writes a deterministic response.
async fn spawn_request_then_reply_upstream(
    response: Vec<u8>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; TEST_BUFFER_SIZE];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => return,
            }
        }
        let _ = stream.write_all(&response).await;
    });
    (addr, task)
}

/// Keep an ephemeral port bound without listening throughout the failure test.
fn reserve_unreachable_addr() -> (tokio::net::TcpSocket, SocketAddr) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

// ---------------------------------------------------------------------------
// TEST 1 — Golden path. Drives `forward_handle_connection` against a
// real loopback upstream echo to prove the Session 04 lifecycle
// produces the same byte-exact relay the Session 03 API did.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_golden_path_round_trip() {
    let (upstream_addr, echo_task) = spawn_echo_upstream().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();

    let handler = tokio::spawn(async move {
        let (downstream, peer) = listener.accept().await.unwrap();
        let sem = Arc::new(Semaphore::new(1));
        let permit = sem.try_acquire_owned().unwrap();
        forward_handle_connection(
            ConnectionId(1),
            downstream,
            peer,
            upstream_addr,
            Duration::from_secs(2),
            permit,
        )
        .await
    });

    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let payload: &[u8] = b"hello forwarder";
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .expect("client read timed out")
        .unwrap();
    assert_eq!(received, payload);

    let outcome: ConnectionOutcome = handler.await.unwrap();
    echo_task.await.unwrap();
    let outcome_ref = &outcome;
    let stats = outcome_ref
        .outcome
        .as_ref()
        .expect("forward completed successfully");
    assert_eq!(stats.bytes_downstream_to_upstream, payload.len() as u64);
    assert_eq!(stats.bytes_upstream_to_downstream, payload.len() as u64);
    assert_eq!(outcome_ref.final_phase(), ConnectionLifecycle::Closed);
}

// ---------------------------------------------------------------------------
// TEST 2 — Capacity limit. Real `Forwarder` with `max_connections=1`,
// an echo handshake that proves admission. While A is in
// flight, B must be capacity-rejected. After A closes, C must
// succeed.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_capacity_limit_one_rejects_then_releases() {
    admission_rejects_before_dial_and_releases(1).await;
}

#[tokio::test]
async fn forwarder_per_ip_limit_rejects_before_upstream_dial_and_releases() {
    admission_rejects_before_dial_and_releases(2).await;
}

async fn admission_rejects_before_dial_and_releases(global_limit: usize) {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (accepted_tx, mut accepted_rx) = mpsc::channel(2);
    let upstream_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (mut stream, _) = upstream.accept().await.unwrap();
            accepted_tx.send(()).await.unwrap();
            tasks.spawn(async move {
                let mut buffer = [0_u8; TEST_BUFFER_SIZE];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) if stream.write_all(&buffer[..read]).await.is_err() => break,
                        Ok(_) => {}
                    }
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let config = ForwardConfig {
        listen_addr,
        upstream_addr,
        max_connections: global_limit,
        connect_timeout: Duration::from_secs(1),
        relay_idle_timeout: Duration::from_secs(1),
    };
    let forwarder = Forwarder::new_with_per_ip_limit(config, 1).unwrap();
    let server = tokio::spawn(forwarder.run_with_listener(listener));

    let mut client_a = TcpStream::connect(listen_addr).await.unwrap();
    client_a.write_all(b"a").await.unwrap();
    let mut byte = [0_u8; 1];
    timeout(Duration::from_secs(3), client_a.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&byte, b"a");
    timeout(Duration::from_secs(1), accepted_rx.recv())
        .await
        .expect("client A should dial upstream")
        .expect("upstream observer should remain live");

    let mut client_b = TcpStream::connect(listen_addr).await.unwrap();
    let rejected = timeout(Duration::from_secs(1), client_b.read(&mut byte))
        .await
        .expect("same-IP connection above capacity should close")
        .unwrap();
    assert_eq!(rejected, 0);
    assert!(
        accepted_rx.try_recv().is_err(),
        "rejection must not dial upstream"
    );

    client_a.write_all(b"z").await.unwrap();
    timeout(Duration::from_secs(3), client_a.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&byte, b"z");
    // Exercise clean-close recovery for the global limit and idle recovery
    // for the per-IP limit, without using sleeps to arrange either case.
    if global_limit == 1 {
        client_a.shutdown().await.unwrap();
    }
    let closed = timeout(Duration::from_secs(3), client_a.read(&mut byte))
        .await
        .expect("client A should close and release admission")
        .unwrap();
    assert_eq!(closed, 0);

    let mut client_c = TcpStream::connect(listen_addr).await.unwrap();
    client_c.write_all(b"c").await.unwrap();
    timeout(Duration::from_secs(3), client_c.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&byte, b"c");
    timeout(Duration::from_secs(1), accepted_rx.recv())
        .await
        .expect("released per-IP slot should permit client C's upstream dial")
        .expect("upstream observer should remain live");

    client_c.shutdown().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), client_c.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    timeout(Duration::from_secs(3), upstream_task)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn forwarder_idle_timeout_is_typed_and_releases_its_permit() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (_socket, _) = upstream.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let downstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream.local_addr().unwrap();
    let permits = Arc::new(Semaphore::new(1));
    let handler_permits = Arc::clone(&permits);
    let handler = tokio::spawn(async move {
        let (stream, peer) = downstream.accept().await.unwrap();
        let permit = handler_permits.try_acquire_owned().unwrap();
        forward_handle_connection_with_idle_timeout(
            ConnectionId(2),
            stream,
            peer,
            upstream_addr,
            Duration::from_secs(1),
            Duration::from_millis(100),
            permit,
        )
        .await
    });

    let mut client = TcpStream::connect(downstream_addr).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("idle forwarder connection should close")
        .unwrap();
    assert_eq!(read, 0);

    let outcome = handler.await.unwrap();
    assert!(matches!(
        &outcome.outcome,
        Err(ForwardError::RelayIdleTimeout { idle_timeout })
            if *idle_timeout == Duration::from_millis(100)
    ));
    assert_eq!(outcome.final_phase(), ConnectionLifecycle::RelayIdleTimeout);
    assert_eq!(permits.available_permits(), 1);
    let _replacement_permit = permits
        .try_acquire_owned()
        .expect("replacement connection can reuse the released permit");
    upstream_task.abort();
    assert!(upstream_task.await.unwrap_err().is_cancelled());
}

// ---------------------------------------------------------------------------
// TEST 3 — Half-close preserved through the forwarder.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_preserves_half_close() {
    let response: Vec<u8> = b"upstream reply after client EOF".to_vec();
    let (upstream_addr, reply_task) = spawn_request_then_reply_upstream(response.clone()).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        let (downstream, peer) = listener.accept().await.unwrap();
        let sem = Arc::new(Semaphore::new(1));
        let permit = sem.try_acquire_owned().unwrap();
        forward_handle_connection(
            ConnectionId(7),
            downstream,
            peer,
            upstream_addr,
            Duration::from_secs(2),
            permit,
        )
        .await
    });

    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    client.write_all(b"request body").await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .expect("half-close read timed out")
        .unwrap();
    assert_eq!(received, response);

    let outcome = handler.await.unwrap();
    assert_eq!(outcome.final_phase(), ConnectionLifecycle::Closed);
    reply_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// TEST 4 — Large payload through `forward_handle_connection` directly.
// Re-verifies the Session 03 large-payload invariant under Session 04.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_large_payload_round_trip() {
    let (upstream_addr, echo_task) = spawn_echo_upstream().await;

    const SIZE: usize = 256 * 1024;
    let mut payload = Vec::with_capacity(SIZE);
    let mut state: u32 = 0xA17EC0DE;
    while payload.len() < SIZE {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        for b in state.to_le_bytes() {
            payload.push(b);
        }
    }
    payload.truncate(SIZE);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let payload_for_task = payload.clone();
    let handler = tokio::spawn(async move {
        let (downstream, peer) = listener.accept().await.unwrap();
        let sem = Arc::new(Semaphore::new(1));
        let permit = sem.try_acquire_owned().unwrap();
        forward_handle_connection(
            ConnectionId(42),
            downstream,
            peer,
            upstream_addr,
            Duration::from_secs(5),
            permit,
        )
        .await
    });

    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    for chunk in payload_for_task.chunks(16 * 1024) {
        client.write_all(chunk).await.unwrap();
    }
    client.shutdown().await.unwrap();

    let mut received = Vec::with_capacity(SIZE);
    timeout(Duration::from_secs(5), client.read_to_end(&mut received))
        .await
        .expect("large payload read timed out")
        .unwrap();
    assert_eq!(received.len(), SIZE);
    assert_eq!(received, payload);

    let outcome = handler.await.unwrap();
    echo_task.await.unwrap();
    let stats = outcome.outcome.expect("large payload relay completed");
    assert_eq!(
        stats,
        RelayStats {
            bytes_downstream_to_upstream: SIZE as u64,
            bytes_upstream_to_downstream: SIZE as u64,
        }
    );
}

// ---------------------------------------------------------------------------
// TEST 5 — Unreachable upstream surfaces `UpstreamConnect` and the
// connection duration is observable.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_unreachable_upstream_surfaces_upstream_connect_failure() {
    let (_reserved_upstream, unreachable_addr) = reserve_unreachable_addr();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (downstream, peer) = listener.accept().await.unwrap();
        let sem = Arc::new(Semaphore::new(2));
        let permit = sem.try_acquire_owned().unwrap();
        forward_handle_connection(
            ConnectionId(100),
            downstream,
            peer,
            unreachable_addr,
            Duration::from_millis(500),
            permit,
        )
        .await
    });

    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let mut buf = [0u8; 64];
    let read = timeout(Duration::from_secs(3), client.read(&mut buf))
        .await
        .expect("client should observe close after failed upstream")
        .unwrap();
    assert_eq!(read, 0);

    let outcome = server_task.await.unwrap();
    // The closed local port may surface as either an I/O error or a
    // timeout depending on the OS / network stack. Both are valid
    // outcomes for "upstream is unreachable on loopback".
    match outcome.outcome {
        Err(ForwardError::UpstreamConnect { .. }) => {}
        Err(ForwardError::UpstreamConnectTimeout) => {}
        other => panic!("expected UpstreamConnect or UpstreamConnectTimeout, got {other:?}"),
    }
    assert!(
        matches!(
            outcome.final_phase(),
            ConnectionLifecycle::UpstreamConnectFailed
                | ConnectionLifecycle::UpstreamConnectTimeout
        ),
        "unexpected final_phase {:?}",
        outcome.final_phase()
    );
    // Duration is observable (AC-08).
    let _ms = outcome.duration;
}

// ---------------------------------------------------------------------------
// TEST 6 — Listener survives two failed connections in a row.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_recoverable_failure_does_not_kill_listener() {
    let (_reserved_upstream, unreachable_addr) = reserve_unreachable_addr();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();

    let cfg = ForwardConfig {
        listen_addr,
        upstream_addr: unreachable_addr,
        max_connections: 4,
        connect_timeout: Duration::from_millis(300),
        relay_idle_timeout: tunnelproxy_edge::DEFAULT_RELAY_IDLE_TIMEOUT,
    };
    let forwarder = Forwarder::new_with_per_ip_limit(cfg, 1).expect("valid per-IP configuration");
    let server = tokio::spawn(forwarder.run_with_listener(listener));

    for _ in 0..2 {
        let mut c = TcpStream::connect(listen_addr).await.unwrap();
        let mut buf = [0u8; 16];
        let r = timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("client should observe close after each failure")
            .unwrap();
        assert_eq!(r, 0);
        drop(c);
    }

    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

// ---------------------------------------------------------------------------
// TEST 7 — Config validation surfaces as `ForwardConfigError`.
// ---------------------------------------------------------------------------
#[test]
fn forwarder_new_rejects_invalid_config() {
    let bad_max = ForwardConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_addr: "127.0.0.1:1".parse().unwrap(),
        max_connections: 0,
        connect_timeout: Duration::from_secs(1),
        relay_idle_timeout: tunnelproxy_edge::DEFAULT_RELAY_IDLE_TIMEOUT,
    };
    assert_eq!(
        Forwarder::new(bad_max).err(),
        Some(ForwardConfigError::ZeroMaxConnections)
    );

    let bad_timeout = ForwardConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_addr: "127.0.0.1:1".parse().unwrap(),
        max_connections: 16,
        connect_timeout: Duration::ZERO,
        relay_idle_timeout: tunnelproxy_edge::DEFAULT_RELAY_IDLE_TIMEOUT,
    };
    assert_eq!(
        Forwarder::new(bad_timeout).err(),
        Some(ForwardConfigError::ZeroConnectTimeout)
    );
}

// ---------------------------------------------------------------------------
// TEST 8 — Failure isolation + recovery. Forwarder pointed at an
// unreachable upstream for one connection (A) which fails cleanly;
// then reconfigured to a healthy upstream, then a second connection
// (B) succeeds.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_failure_then_recovery_via_restart() {
    // Stage 1: forwarder pointed at an unreachable upstream.
    let (_reserved_upstream, unreachable_addr) = reserve_unreachable_addr();
    let listener_bad = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr_bad = listener_bad.local_addr().unwrap();
    let cfg_bad = ForwardConfig {
        listen_addr: listen_addr_bad,
        upstream_addr: unreachable_addr,
        max_connections: 16,
        connect_timeout: Duration::from_millis(300),
        relay_idle_timeout: tunnelproxy_edge::DEFAULT_RELAY_IDLE_TIMEOUT,
    };
    let server_bad = tokio::spawn(
        Forwarder::new(cfg_bad)
            .unwrap()
            .run_with_listener(listener_bad),
    );

    {
        let mut c = TcpStream::connect(listen_addr_bad).await.unwrap();
        let mut buf = [0u8; 16];
        let r = timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("client should observe close (bad upstream)")
            .unwrap();
        assert_eq!(r, 0);
    }
    server_bad.abort();
    assert!(server_bad.await.unwrap_err().is_cancelled());

    // Stage 2: pick a fresh listen address to avoid any port-reuse
    // timing races, then point the new forwarder at a healthy
    // upstream.
    let listener_good = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr_good = listener_good.local_addr().unwrap();
    let (upstream_addr, echo_task) = spawn_echo_upstream().await;
    let cfg_good = ForwardConfig {
        listen_addr: listen_addr_good,
        upstream_addr,
        max_connections: 16,
        connect_timeout: Duration::from_secs(2),
        relay_idle_timeout: tunnelproxy_edge::DEFAULT_RELAY_IDLE_TIMEOUT,
    };
    let server_good = tokio::spawn(
        Forwarder::new(cfg_good)
            .unwrap()
            .run_with_listener(listener_good),
    );

    let mut client = TcpStream::connect(listen_addr_good).await.unwrap();
    client.write_all(b"recovery hello").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut got))
        .await
        .expect("recovery read timed out")
        .unwrap();
    assert_eq!(got, b"recovery hello");
    echo_task.await.unwrap();

    server_good.abort();
    assert!(server_good.await.unwrap_err().is_cancelled());
}

// ---------------------------------------------------------------------------
// TEST 9 — ConnectionIdAllocator is monotonic and process-local.
// ---------------------------------------------------------------------------
#[test]
fn connection_id_allocator_yields_unique_ids() {
    let alloc = ConnectionIdAllocator::new();
    let a = alloc.next_id();
    let b = alloc.next_id();
    let c = alloc.next_id();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_eq!(a.to_string(), "conn#1");
    assert_eq!(b.to_string(), "conn#2");
    assert_eq!(c.to_string(), "conn#3");
}
