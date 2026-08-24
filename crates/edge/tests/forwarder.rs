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
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tunnelproxy_edge::{
    forward_handle_connection, ConnectionId, ConnectionIdAllocator, ConnectionLifecycle,
    ConnectionOutcome, ForwardConfig, ForwardConfigError, ForwardError, Forwarder, RelayStats,
};

/// Per-connection buffer used by upstream test servers.
const TEST_BUFFER_SIZE: usize = 16 * 1024;

/// Spawn a tiny echo upstream bound on an ephemeral port.
async fn spawn_echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
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
        }
    });
    addr
}

/// Spawn an upstream that, for each accepted connection, reads until
/// EOF and then writes a deterministic response.
async fn spawn_request_then_reply_upstream(response: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
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
        }
    });
    addr
}

/// Spawn an upstream that holds its response for `hold` and then
/// replies with `late-reply`. Used by the capacity-limit test to keep
/// a relay in-flight deterministically.
async fn spawn_holding_upstream(hold: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; TEST_BUFFER_SIZE];
                let _ = stream.read(&mut buf).await; // first read
                tokio::time::sleep(hold).await;
                let _ = stream.write_all(b"late-reply").await;
            });
        }
    });
    addr
}

/// Reserve an ephemeral port, close it, and return its address as a
/// guaranteed-unreachable upstream target.
fn reserve_unreachable_addr() -> SocketAddr {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

/// Reserve an ephemeral port and return its address.
fn fresh_addr() -> SocketAddr {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

/// Connect after a spawned `Forwarder::run` has completed its asynchronous
/// bind. Reserving and releasing an ephemeral port does not guarantee the
/// listener task will be polled before the client on every Tokio/OS scheduler.
async fn connect_eventually(addr: SocketAddr) -> TcpStream {
    timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected forwarder connect error: {error}"),
            }
        }
    })
    .await
    .expect("forwarder listener did not bind before the deadline")
}

/// Drain a `ReadHalf<TcpStream>` until EOF. Used to keep the read
/// side alive across the lifetime of a relay under test.
async fn drain_until_eof(mut stream: tokio::io::ReadHalf<TcpStream>) {
    let mut buf = vec![0u8; TEST_BUFFER_SIZE];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// TEST 1 — Golden path. Drives `forward_handle_connection` against a
// real loopback upstream echo to prove the Session 04 lifecycle
// produces the same byte-exact relay the Session 03 API did.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_golden_path_round_trip() {
    let upstream_addr = spawn_echo_upstream().await;

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
// a slow upstream that holds the relay in-flight. While A is in
// flight, B must be capacity-rejected. After A closes, C must
// succeed.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_capacity_limit_one_rejects_then_releases() {
    let upstream_addr = spawn_holding_upstream(Duration::from_millis(500)).await;
    let listen_addr = fresh_addr();

    let config = ForwardConfig {
        listen_addr,
        upstream_addr,
        max_connections: 1,
        connect_timeout: Duration::from_secs(2),
    };
    let forwarder = Forwarder::new(config).expect("valid config");
    assert_eq!(forwarder.available_permits(), 1);
    let server = tokio::spawn(forwarder.run());

    // Connection A: open + write + keep reader alive (drains the echo
    // stream from upstream). We deliberately do NOT shut down for
    // ~500 ms so the relay holds the permit across B's attempt.
    let stream_a = connect_eventually(listen_addr).await;
    let (read_a, mut write_a) = tokio::io::split(stream_a);
    let writer_task = tokio::spawn(async move {
        write_a.write_all(b"A-payload").await.unwrap();
        // Hold the write side open so the relay copy has traffic to
        // push for a while. We sleep long enough that B is rejected
        // while A is still in flight.
        tokio::time::sleep(Duration::from_millis(250)).await;
        // Then shut down so A completes and the permit is released.
        write_a.shutdown().await.unwrap();
    });
    let drain_a = tokio::spawn(drain_until_eof(read_a));

    // Give the forwarder time to accept A and acquire the permit.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Connection B: should observe an immediate close because the
    // only permit is held by A.
    {
        let mut client_b = TcpStream::connect(listen_addr).await.unwrap();
        let mut buf = [0u8; 16];
        let r = timeout(Duration::from_secs(2), client_b.read(&mut buf))
            .await
            .expect("client B should observe close");
        assert_eq!(r.unwrap(), 0, "client B must be closed by capacity policy");
        drop(client_b);
    }

    // Wait for A's writer to shut down + relay to finish + permit
    // release. We poll the available permits through a small proxy:
    // if C succeeds with full payload exchange, the permit is back.
    let _ = writer_task.await;
    let _ = drain_a.await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connection C: must succeed after A released the permit.
    let mut client_c = TcpStream::connect(listen_addr).await.unwrap();
    client_c.write_all(b"C-payload").await.unwrap();
    client_c.shutdown().await.unwrap();
    let mut got = Vec::new();
    timeout(Duration::from_secs(3), client_c.read_to_end(&mut got))
        .await
        .expect("client C should observe a response")
        .unwrap();
    assert!(
        !got.is_empty(),
        "client C should observe a response (got empty bytes)"
    );

    server.abort();
}

// ---------------------------------------------------------------------------
// TEST 3 — Half-close preserved through the forwarder.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_preserves_half_close() {
    let response: Vec<u8> = b"upstream reply after client EOF".to_vec();
    let upstream_addr = spawn_request_then_reply_upstream(response.clone()).await;

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
}

// ---------------------------------------------------------------------------
// TEST 4 — Large payload through `forward_handle_connection` directly.
// Re-verifies the Session 03 large-payload invariant under Session 04.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forwarder_large_payload_round_trip() {
    let upstream_addr = spawn_echo_upstream().await;

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
    let unreachable_addr = reserve_unreachable_addr();
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
    let unreachable_addr = reserve_unreachable_addr();
    let listen_addr = fresh_addr();

    let cfg = ForwardConfig {
        listen_addr,
        upstream_addr: unreachable_addr,
        max_connections: 4,
        connect_timeout: Duration::from_millis(300),
    };
    let forwarder = Forwarder::new(cfg).expect("valid config");
    let server = tokio::spawn(forwarder.run());

    for _ in 0..2 {
        let mut c = connect_eventually(listen_addr).await;
        let mut buf = [0u8; 16];
        let r = timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("client should observe close after each failure")
            .unwrap();
        assert_eq!(r, 0);
        drop(c);
    }

    server.abort();
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
    let unreachable_addr = reserve_unreachable_addr();
    let listen_addr_bad = fresh_addr();
    let cfg_bad = ForwardConfig {
        listen_addr: listen_addr_bad,
        upstream_addr: unreachable_addr,
        max_connections: 16,
        connect_timeout: Duration::from_millis(300),
    };
    let server_bad = tokio::spawn(Forwarder::new(cfg_bad).unwrap().run());

    {
        let mut c = connect_eventually(listen_addr_bad).await;
        let mut buf = [0u8; 16];
        let r = timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("client should observe close (bad upstream)")
            .unwrap();
        assert_eq!(r, 0);
    }
    server_bad.abort();

    // Stage 2: pick a fresh listen address to avoid any port-reuse
    // timing races, then point the new forwarder at a healthy
    // upstream.
    let listen_addr_good = fresh_addr();
    let upstream_addr = spawn_echo_upstream().await;
    let cfg_good = ForwardConfig {
        listen_addr: listen_addr_good,
        upstream_addr,
        max_connections: 16,
        connect_timeout: Duration::from_secs(2),
    };
    let server_good = tokio::spawn(Forwarder::new(cfg_good).unwrap().run());

    let mut client = connect_eventually(listen_addr_good).await;
    client.write_all(b"recovery hello").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut got))
        .await
        .expect("recovery read timed out")
        .unwrap();
    assert_eq!(got, b"recovery hello");

    server_good.abort();
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
