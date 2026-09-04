//! End-to-end TCP integration tests for `tunnelproxy-edge`.
//!
//! These tests live in `tests/` (not in `src/`) so they exercise the
//! crate as an external consumer would: only the public API. They bind a
//! real Tokio listener on an ephemeral port and talk to it over real
//! TCP sockets. No hardcoded port numbers are used, so they do not
//! conflict with each other or with a locally-running development
//! server.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tunnelproxy_edge::{handle_connection, handle_connection_with_idle_timeout, run_listener};

/// Bind a `TcpListener` on an ephemeral port and start `run_listener`
/// in the background. Returns the bound address and the join handle for
/// the spawned server task.
async fn spawn_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        // `run_listener` returns on accept error; for the test we abort
        // the handle when finished, so any error is acceptable here.
        let _ = run_listener_on(listener).await;
    });
    (addr, handle)
}

/// Minimal `run_listener`-style loop that takes ownership of a
/// pre-bound `TcpListener` so tests can assert against an already-bound
/// ephemeral port. We re-implement the loop here instead of using
/// `run_listener(SocketAddr)` because `run_listener` would rebind,
/// potentially racing with another test.
async fn run_listener_on(listener: TcpListener) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(handle_connection(stream, peer));
            }
            Err(err) => return Err(err),
        }
    }
}

#[tokio::test]
async fn echo_server_round_trip() {
    let (addr, server) = spawn_echo_server().await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    let payload: &[u8] = b"hello tunnelproxy";
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut received))
        .await
        .expect("server did not respond in time")
        .unwrap();
    assert_eq!(received.as_slice(), payload);

    server.abort();
}

#[tokio::test]
async fn echo_server_handles_multiple_clients_sequentially() {
    let (addr, server) = spawn_echo_server().await;

    for i in 0u8..4 {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let payload = [b'k', i, b'-', b'p', b'a', b'y'];
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut received))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(received, payload);
    }

    server.abort();
}

#[tokio::test]
async fn echo_server_returns_empty_for_immediate_close() {
    let (addr, server) = spawn_echo_server().await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut received))
        .await
        .expect("timeout")
        .unwrap();
    assert!(
        received.is_empty(),
        "expected zero-byte response, got {received:?}"
    );

    server.abort();
}

#[tokio::test]
async fn echo_activity_resets_idle_deadline_then_silence_closes_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_connection_with_idle_timeout(stream, peer, Duration::from_millis(300)).await;
    });
    let mut client = TcpStream::connect(addr).await.unwrap();

    for byte in b"live" {
        client.write_all(&[*byte]).await.unwrap();
        let mut echoed = [0_u8; 1];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed[0], *byte);
        if *byte != b'e' {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    let mut after_idle = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), client.read(&mut after_idle))
        .await
        .expect("silent echo connection should close by its idle deadline")
        .unwrap();
    assert_eq!(read, 0);
    handler.await.unwrap();
}

/// Smoke test that `run_listener` itself binds successfully. This is
/// the public surface the development binary will use.
#[tokio::test]
async fn run_listener_binds_and_returns_on_drop() {
    // Bind on an ephemeral port first so we know the address is free,
    // then close the probe and let `run_listener` rebind it. This avoids
    // racing with another test or a stray dev process.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let server = tokio::spawn(async move {
        let _ = run_listener(addr).await;
    });

    // Give the listener a moment to bind, then attempt a real connect.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let result = TcpStream::connect(addr).await;
    assert!(result.is_ok(), "expected to connect to run_listener");

    server.abort();
}
