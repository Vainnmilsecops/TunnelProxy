//! End-to-end TCP relay integration tests for `tunnelproxy-edge`.
//!
//! These tests live in `tests/` so they exercise the crate as an
//! external consumer would: only the public API. They bind real Tokio
//! listeners on ephemeral ports and route bytes through the relay
//! against a real Tokio echo upstream. No hardcoded port numbers are
//! used, so the tests do not conflict with each other or with a
//! locally-running development server.
//!
//! These tests complement the Session 02 echo tests in
//! `tests/edge_tcp.rs`. The Session 02 file is kept intact so the echo
//! baseline remains covered.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tunnelproxy_edge::{
    relay_bidirectional, relay_bidirectional_with_idle_timeout, relay_connection,
    run_relay_listener, run_relay_listener_with_listener, RelayError, RelayStats,
};

/// Size of the intermediate read buffer used by the upstream echo
/// server. Larger than the relay's default internal buffer so we can
/// exercise multi-read traffic.
const UPSTREAM_BUFFER_SIZE: usize = 16 * 1024;

/// One-connection fixture with an explicitly owned task.
async fn spawn_echo_upstream() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; UPSTREAM_BUFFER_SIZE];
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

/// Serve a pre-bound production relay and return its address and owned tasks.
async fn spawn_relay_against_upstream(
) -> (SocketAddr, JoinHandle<()>, JoinHandle<std::io::Result<()>>) {
    let (upstream_addr, upstream_task) = spawn_echo_upstream().await;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let server = tokio::spawn(run_relay_listener_with_listener(
        relay_listener,
        upstream_addr,
    ));
    (relay_addr, upstream_task, server)
}

async fn finish_fixture(upstream: JoinHandle<()>, server: JoinHandle<std::io::Result<()>>) {
    timeout(Duration::from_secs(3), upstream)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

/// Spawn a one-connection Tokio TCP listener that
/// reads until EOF, then writes a deterministic response and closes.
/// Used for half-close coverage (TEST 3).
async fn spawn_request_then_reply_upstream(response: Vec<u8>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; UPSTREAM_BUFFER_SIZE];
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

// ---------------------------------------------------------------------------
// TEST 1 — Basic relay: client -> relay -> upstream echo -> relay -> client
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_round_trip_small_payload() {
    let (relay_addr, upstream, server) = spawn_relay_against_upstream().await;

    let mut client = TcpStream::connect(relay_addr).await.unwrap();
    let payload: &[u8] = b"hello tunnelproxy relay";
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .expect("relay did not respond in time")
        .unwrap();
    assert_eq!(
        received.as_slice(),
        payload,
        "echo through relay should be byte-exact"
    );
    finish_fixture(upstream, server).await;
}

// ---------------------------------------------------------------------------
// TEST 2 — Payload significantly larger than the relay buffer
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_round_trip_large_payload() {
    let (relay_addr, upstream, server) = spawn_relay_against_upstream().await;

    // 256 KiB deterministic pseudo-random bytes. Using a fixed seed
    // keeps the test deterministic; the bytes intentionally include
    // nulls and high values so we exercise binary safety (AC-07).
    const SIZE: usize = 256 * 1024;
    let mut payload = Vec::with_capacity(SIZE);
    let mut state: u32 = 0xC0FFEE01;
    while payload.len() < SIZE {
        // xorshift32 — simple, deterministic, no_std-friendly.
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let chunk = state.to_le_bytes();
        for b in chunk {
            payload.push(b);
        }
    }
    payload.truncate(SIZE);

    let mut client = TcpStream::connect(relay_addr).await.unwrap();

    // Write in slices so the kernel actually flushes across multiple
    // read iterations on the relay side. This is what proves the
    // implementation does not assume one read equals one message
    // (AC-08, Session 03 AC-08).
    let chunk_size = 16 * 1024;
    for chunk in payload.chunks(chunk_size) {
        client.write_all(chunk).await.unwrap();
    }
    client.shutdown().await.unwrap();

    let mut received = Vec::with_capacity(SIZE);
    timeout(Duration::from_secs(5), client.read_to_end(&mut received))
        .await
        .expect("relay did not deliver large payload in time")
        .unwrap();
    assert_eq!(
        received.len(),
        payload.len(),
        "relay truncated large payload"
    );
    assert_eq!(received, payload, "relay corrupted large payload");
    finish_fixture(upstream, server).await;
}

// ---------------------------------------------------------------------------
// TEST 3 — Half-close: client shuts down its write side; upstream still
// sends a response; client still receives the response through the relay.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_preserves_half_close() {
    let response: Vec<u8> = b"upstream response after client EOF".to_vec();
    let (upstream_addr, upstream) = spawn_request_then_reply_upstream(response.clone()).await;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let server = tokio::spawn(run_relay_listener_with_listener(
        relay_listener,
        upstream_addr,
    ));

    let mut client = TcpStream::connect(relay_addr).await.unwrap();
    client.write_all(b"request body").await.unwrap();
    // Signal "I am done sending"; continue reading.
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .expect("relay did not forward upstream response")
        .unwrap();
    assert_eq!(
        received, response,
        "relay should forward upstream response even after client EOF"
    );
    finish_fixture(upstream, server).await;
}

// ---------------------------------------------------------------------------
// TEST 4 — Connection isolation: a relay task whose upstream is
// unavailable must not kill the listener; another client is accepted and
// independently closed after its own upstream failure.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_listener_survives_unreachable_upstream() {
    // Retain a bound, non-listening socket so another test cannot steal the port.
    let reserved = TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let unreachable_addr = reserved.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(run_relay_listener_with_listener(listener, unreachable_addr));
    // Both connections must be closed: failure does not stop the accept loop.
    for _ in 0..2 {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(4), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    TcpListener::bind(addr)
        .await
        .expect("listener released after joined abort");
}

// ---------------------------------------------------------------------------
// Bonus: drive `relay_bidirectional` directly with two pre-built
// streams so the primitive itself is covered without a listener.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_bidirectional_returns_byte_counts() {
    // We need two cooperating peers: a "downstream" peer that writes
    // bytes for the relay to forward upstream, and an "upstream" peer
    // that writes bytes for the relay to forward downstream. We use
    // two simple listener tasks to play those roles.
    //
    // - `downstream_listener` accepts the relay's downstream socket
    //   and writes a fixed payload into it (this is what the relay
    //   will forward upstream).
    // - `upstream_listener` accepts the relay's upstream socket and
    //   reads bytes from it (proving the relay really forwarded
    //   them), then writes a fixed response that the relay must
    //   forward back downstream.
    let downstream_payload: Vec<u8> = (0u32..64).flat_map(|i| i.to_le_bytes()).collect();
    let upstream_response: Vec<u8> = b"PONG".to_vec();
    let downstream_payload_len = downstream_payload.len();
    let upstream_response_len = upstream_response.len();

    // Downstream peer: once we accept, write the payload and close.
    let downstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream_listener.local_addr().unwrap();
    let downstream_payload_for_task = downstream_payload.clone();
    let downstream_peer = tokio::spawn(async move {
        if let Ok((mut s, _)) = downstream_listener.accept().await {
            s.write_all(&downstream_payload_for_task).await.unwrap();
            s.shutdown().await.unwrap();
            let mut response = Vec::new();
            timeout(Duration::from_secs(3), s.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, b"PONG");
        }
    });

    // Upstream peer: once we accept, read everything (assert length),
    // then write a response.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_peer = tokio::spawn(async move {
        if let Ok((mut s, _)) = upstream_listener.accept().await {
            let mut buf = Vec::new();
            timeout(Duration::from_secs(3), s.read_to_end(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                buf.len(),
                downstream_payload_len,
                "upstream should have received exactly the downstream payload"
            );
            s.write_all(&upstream_response).await.unwrap();
            s.shutdown().await.unwrap();
        }
    });

    // Build the two socket halves by connecting to the peers.
    let downstream = TcpStream::connect(downstream_addr).await.unwrap();
    let upstream = TcpStream::connect(upstream_addr).await.unwrap();

    let stats = timeout(
        Duration::from_secs(5),
        relay_bidirectional(downstream, upstream),
    )
    .await
    .unwrap()
    .expect("relay_bidirectional should succeed");
    assert_eq!(
        stats,
        RelayStats {
            bytes_downstream_to_upstream: downstream_payload_len as u64,
            bytes_upstream_to_downstream: upstream_response_len as u64,
        }
    );

    timeout(Duration::from_secs(3), downstream_peer)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(3), upstream_peer)
        .await
        .unwrap()
        .unwrap();
}

// ---------------------------------------------------------------------------
// Bonus: relay_connection surfaces UpstreamConnect when the upstream is
// unreachable.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_connection_reports_upstream_connect_failure() {
    let probe = TcpSocket::new_v4().unwrap();
    probe.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let unreachable_addr = probe.local_addr().unwrap();

    // Open a real downstream side by binding a listener, accepting one
    // connection, and then handing the accepted stream to
    // `relay_connection`. We never read from the downstream side — the
    // relay must close it after a failed upstream connect.
    let downstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream_listener.local_addr().unwrap();
    let downstream = TcpStream::connect(downstream_addr).await.unwrap();
    let (_peer, _) = downstream_listener.accept().await.unwrap();
    let result = timeout(
        Duration::from_secs(4),
        relay_connection(downstream, downstream_addr, unreachable_addr),
    )
    .await
    .unwrap();
    match result {
        Err(RelayError::UpstreamConnect { upstream, .. }) => {
            assert_eq!(upstream, unreachable_addr);
        }
        other => panic!("expected UpstreamConnect, got {other:?}"),
    }
}

#[tokio::test]
async fn relay_activity_in_either_direction_resets_shared_idle_deadline() {
    let downstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream_listener.local_addr().unwrap();
    let mut downstream_client = TcpStream::connect(downstream_addr).await.unwrap();
    let (downstream_relay, _) = downstream_listener.accept().await.unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_relay = TcpStream::connect(upstream_addr).await.unwrap();
    let (mut upstream_server, _) = upstream_listener.accept().await.unwrap();

    let relay = tokio::spawn(relay_bidirectional_with_idle_timeout(
        downstream_relay,
        upstream_relay,
        Duration::from_millis(300),
    ));

    downstream_client.write_all(b"a").await.unwrap();
    let mut byte = [0_u8; 1];
    upstream_server.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"a");
    tokio::time::sleep(Duration::from_millis(180)).await;

    upstream_server.write_all(b"b").await.unwrap();
    downstream_client.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"b");
    tokio::time::sleep(Duration::from_millis(180)).await;

    downstream_client.write_all(b"c").await.unwrap();
    upstream_server.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"c");

    let result = timeout(Duration::from_secs(1), relay)
        .await
        .expect("silent relay should finish by its idle deadline")
        .unwrap();
    assert!(matches!(
        result,
        Err(RelayError::IdleTimeout { idle_timeout })
            if idle_timeout == Duration::from_millis(300)
    ));
}

// Bind-only API reports collisions without a reserve/drop/rebind readiness race.
#[tokio::test]
async fn run_relay_listener_reports_bind_failure() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = occupied.local_addr().unwrap();
    let error = run_relay_listener(addr, addr).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
}
