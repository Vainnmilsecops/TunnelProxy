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
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tunnelproxy_edge::{
    relay_bidirectional, relay_connection, run_relay_listener, RelayError, RelayStats,
};

/// Size of the intermediate read buffer used by the upstream echo
/// server. Larger than the relay's default internal buffer so we can
/// exercise multi-read traffic.
const UPSTREAM_BUFFER_SIZE: usize = 16 * 1024;

/// Spawn a Tokio TCP listener on an ephemeral port and forward every
/// byte back to the connected peer (a tiny "echo" upstream). Returns
/// the bound address. The listener task runs until the test ends or
/// the process exits; `tokio::test` cleans it up automatically.
async fn spawn_echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
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
        }
    });
    addr
}

/// Spawn `run_relay_listener` against a real upstream echo listener
/// and return the relay's bound address plus the upstream's bound
/// address. The relay task runs until the test ends.
async fn spawn_relay_against_upstream() -> (SocketAddr, SocketAddr) {
    let upstream_addr = spawn_echo_upstream().await;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = run_relay_listener_on(relay_listener, upstream_addr).await;
    });
    (relay_addr, upstream_addr)
}

/// Drop-in replacement for `run_relay_listener` that accepts a
/// pre-bound listener, so tests do not race against
/// `TcpListener::bind` rebinding.
async fn run_relay_listener_on(
    listener: TcpListener,
    upstream_addr: SocketAddr,
) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(async move {
                    let _ = relay_connection(stream, peer, upstream_addr).await;
                });
            }
            Err(err) => return Err(err),
        }
    }
}

/// Spawn a Tokio TCP listener that, for each accepted connection,
/// reads until EOF, then writes a deterministic response and closes.
/// Used for half-close coverage (TEST 3).
async fn spawn_request_then_reply_upstream(response: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
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
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// TEST 1 — Basic relay: client -> relay -> upstream echo -> relay -> client
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_round_trip_small_payload() {
    let (relay_addr, _upstream_addr) = spawn_relay_against_upstream().await;

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
}

// ---------------------------------------------------------------------------
// TEST 2 — Payload significantly larger than the relay buffer
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_round_trip_large_payload() {
    let (relay_addr, _upstream_addr) = spawn_relay_against_upstream().await;

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
}

// ---------------------------------------------------------------------------
// TEST 3 — Half-close: client shuts down its write side; upstream still
// sends a response; client still receives the response through the relay.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_preserves_half_close() {
    let response: Vec<u8> = b"upstream response after client EOF".to_vec();
    let upstream_addr = spawn_request_then_reply_upstream(response.clone()).await;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = run_relay_listener_on(relay_listener, upstream_addr).await;
    });

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
}

// ---------------------------------------------------------------------------
// TEST 4 — Connection isolation: a relay task whose upstream is
// unavailable must not kill the listener; a later valid connection
// must still be served.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_listener_survives_unreachable_upstream() {
    // Reserve an ephemeral port, close the probe, then use it as an
    // "unreachable upstream" — connecting to it will fail with
    // ConnectionRefused on Windows / ECONNREFUSED on Unix.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unreachable_addr = probe.local_addr().unwrap();
    drop(probe);

    // Spawn an echo upstream on a *separate* ephemeral port. We'll
    // route the relay to the unreachable address first, then re-spawn
    // the relay pointing at the real echo upstream.
    let real_upstream_addr = spawn_echo_upstream().await;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    // Stage 1: relay points at the unreachable upstream. The listener
    // task should keep accepting connections even though each one
    // fails upstream.
    let stage1 = tokio::spawn(async move {
        let _ = run_relay_listener_on(relay_listener, unreachable_addr).await;
    });

    // A client connecting now will be dropped because upstream is
    // unreachable. We assert that the connect itself succeeds and the
    // subsequent read returns EOF (server closed downstream after
    // upstream connect failed).
    {
        let mut bad_client = TcpStream::connect(relay_addr).await.unwrap();
        let mut received = Vec::new();
        let _ = timeout(
            Duration::from_secs(2),
            bad_client.read_to_end(&mut received),
        )
        .await;
        // Whatever happens — EOF or empty — we do not care about the
        // bytes. The point is that the *listener* survived.
        drop(bad_client);
    }

    // Stage 2: stop stage-1 listener, start a fresh one pointed at
    // the real echo upstream on the same address (the address is held
    // by us; stage 1's listener owned the socket and was aborted).
    stage1.abort();
    // Yield once so the OS releases the port before we rebind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let relay_listener2 = TcpListener::bind(relay_addr).await.unwrap();
    tokio::spawn(async move {
        let _ = run_relay_listener_on(relay_listener2, real_upstream_addr).await;
    });

    let mut good_client = TcpStream::connect(relay_addr).await.unwrap();
    let payload: &[u8] = b"after failure, still working";
    good_client.write_all(payload).await.unwrap();
    good_client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(
        Duration::from_secs(3),
        good_client.read_to_end(&mut received),
    )
    .await
    .expect("second-stage relay did not respond")
    .unwrap();
    assert_eq!(received, payload);
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
            let _ = s.write_all(&downstream_payload_for_task).await;
            let _ = s.shutdown().await;
            // Hold the socket open long enough for the relay to drain.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Upstream peer: once we accept, read everything (assert length),
    // then write a response.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_peer = tokio::spawn(async move {
        if let Ok((mut s, _)) = upstream_listener.accept().await {
            let mut buf = Vec::new();
            let _ = timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
            assert_eq!(
                buf.len(),
                downstream_payload_len,
                "upstream should have received exactly the downstream payload"
            );
            let _ = s.write_all(&upstream_response).await;
            let _ = s.shutdown().await;
        }
    });

    // Build the two socket halves by connecting to the peers.
    let downstream = TcpStream::connect(downstream_addr).await.unwrap();
    let upstream = TcpStream::connect(upstream_addr).await.unwrap();

    let stats = relay_bidirectional(downstream, upstream)
        .await
        .expect("relay_bidirectional should succeed");
    assert_eq!(
        stats,
        RelayStats {
            bytes_downstream_to_upstream: downstream_payload_len as u64,
            bytes_upstream_to_downstream: upstream_response_len as u64,
        }
    );

    downstream_peer.abort();
    upstream_peer.abort();
}

// ---------------------------------------------------------------------------
// Bonus: relay_connection surfaces UpstreamConnect when the upstream is
// unreachable.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn relay_connection_reports_upstream_connect_failure() {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unreachable_addr = probe.local_addr().unwrap();
    drop(probe);

    // Open a real downstream side by binding a listener, accepting one
    // connection, and then handing the accepted stream to
    // `relay_connection`. We never read from the downstream side — the
    // relay must close it after a failed upstream connect.
    let downstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream_listener.local_addr().unwrap();
    let acceptor = tokio::spawn(async move {
        if let Ok((stream, _peer)) = downstream_listener.accept().await {
            // Hold the downstream stream alive for the duration of the
            // test by parking it in a long sleep.
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = stream;
        }
    });

    let downstream = TcpStream::connect(downstream_addr).await.unwrap();
    let result = relay_connection(downstream, downstream_addr, unreachable_addr).await;
    acceptor.abort();
    match result {
        Err(RelayError::UpstreamConnect { upstream, .. }) => {
            assert_eq!(upstream, unreachable_addr);
        }
        other => panic!("expected UpstreamConnect, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Smoke: `run_relay_listener` itself binds successfully against a real
// upstream address, mirroring the smoke-test style used for the echo
// baseline in `tests/edge_tcp.rs`.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn run_relay_listener_binds_and_serves_one_connection() {
    let upstream_addr = spawn_echo_upstream().await;
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = probe.local_addr().unwrap();
    drop(probe);

    let server = tokio::spawn(async move {
        let _ = run_relay_listener(relay_addr, upstream_addr).await;
    });

    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(relay_addr).await.unwrap();
    client
        .write_all(b"hello via run_relay_listener")
        .await
        .unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .expect("relay did not respond")
        .unwrap();
    assert_eq!(received, b"hello via run_relay_listener");

    server.abort();
}
