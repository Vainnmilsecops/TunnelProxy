//! `tunnelproxy-edge`
//!
//! Public ingress and live tunnel routing for TunnelProxy.
//!
//! In Session 02 this crate implements a minimal asynchronous TCP echo
//! baseline. The edge binds a TCP listener on a configurable address, and
//! each accepted connection is handled independently in its own Tokio
//! task. Bytes received from the client are echoed back unchanged until
//! the client half-closes (EOF) or the connection errors.
//!
//! This is **not** yet the TunnelProxy reverse-tunnel protocol. It exists
//! to validate the byte-stream handling, per-connection task isolation,
//! and structured-tracing baseline that later sessions will reuse. See
//! `docs/ai/DECISIONS.md` (ADR-002, ADR-005) and `docs/TECH_DEBT.md` for
//! the deliberate limitations of this baseline.

#![deny(unsafe_code)]

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, trace, warn};

/// Default development bind address.
///
/// `127.0.0.1:7000` is local-only. The edge MUST NOT bind a public address
/// in this session; doing so would conflict with the production
/// architecture and with INV-001 (only agents initiate outbound tunnels).
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:7000";

/// Size of the per-connection read buffer.
///
/// 8 KiB is a reasonable default for the byte-stream baseline. Larger
/// buffers can be tuned later without changing the public API. The
/// invariant in INV-002 (no unbounded buffering) is satisfied because the
/// buffer is a fixed allocation and is reused across reads; we never call
/// `read_to_end` on a live socket.
pub const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Bind a TCP listener and serve connections forever, echoing every byte
/// received from each client back to that client until EOF or error.
///
/// `bind_addr` is resolved by the caller. Use [`DEFAULT_BIND_ADDR`] for
/// the development binary.
///
/// Each accepted connection is handled by [`handle_connection`], spawned
/// as an independent Tokio task so that one connection's failure cannot
/// stall others. Connection-level errors are logged and swallowed;
/// listener-level fatal errors return them to the caller.
///
/// The function returns `Ok(())` only when [`TcpListener::accept`]
/// itself fails — for example when the bound socket is closed by the
/// process supervisor. Normal per-connection closes are not propagated
/// upward.
pub async fn run_listener(bind_addr: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;
    info!(addr = %local, event = "tcp_server_started", "TCP server bound");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!(
                    peer = %peer,
                    event = "tcp_connection_accepted",
                    "accepted connection"
                );
                tokio::spawn(handle_connection(stream, peer));
            }
            Err(err) => {
                error!(error = %err, event = "tcp_listener_accept_error", "accept failed");
                return Err(err);
            }
        }
    }
}

/// Drive a single accepted TCP connection: read bytes in a fixed buffer
/// and echo them back until the peer half-closes or the connection
/// errors.
///
/// Exposed as a public function so integration tests can drive a
/// pre-built `TcpStream` directly. Real listener use funnels here via
/// [`run_listener`].
///
/// This function never panics on ordinary network failures. Read errors
/// after the first byte are treated as a normal close. Write errors are
/// logged and cause the connection to be dropped so the caller can
/// reclaim the socket.
pub async fn handle_connection(mut stream: TcpStream, peer: SocketAddr) {
    let mut buf = vec![0u8; READ_BUFFER_SIZE];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                // Per TCP semantics, a zero-length read means the peer
                // closed its write half (or sent a clean FIN). This is
                // not an error — it is the canonical EOF signal.
                debug!(
                    peer = %peer,
                    event = "tcp_connection_closed",
                    "client closed connection (EOF)"
                );
                return;
            }
            Ok(n) => {
                trace!(
                    peer = %peer,
                    event = "tcp_connection_read",
                    bytes = n,
                    "received bytes"
                );
                if let Err(err) = stream.write_all(&buf[..n]).await {
                    warn!(
                        peer = %peer,
                        error = %err,
                        event = "tcp_connection_error",
                        "write failed; dropping connection"
                    );
                    return;
                }
            }
            Err(err) => {
                warn!(
                    peer = %peer,
                    error = %err,
                    event = "tcp_connection_error",
                    "read failed; dropping connection"
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test: bind on an ephemeral port, connect, send, read
    /// back, assert byte-exact equality. Uses no hardcoded port (AC-13).
    #[tokio::test]
    async fn echo_round_trip_single_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                handle_connection(stream, peer).await;
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let payload: &[u8] = b"hello tunnelproxy";
        client.write_all(payload).await.unwrap();
        // Signal half-close so the server's read returns 0 after the echo.
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.as_slice(), payload);

        let _ = server.await;
    }

    /// Integration test: multiple sequential writes from the client must
    /// be echoed back in the same order, and the server must not assume
    /// one read equals one application message (AC-04).
    #[tokio::test]
    async fn echo_round_trip_multiple_writes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                handle_connection(stream, peer).await;
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let chunks: &[&[u8]] = &[b"foo ", b"bar ", b"baz"];
        for chunk in chunks {
            client.write_all(chunk).await.unwrap();
        }
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let mut expected: Vec<u8> = Vec::new();
        for chunk in chunks {
            expected.extend_from_slice(chunk);
        }
        assert_eq!(received, expected);

        let _ = server.await;
    }

    /// Integration test: client EOF with no bytes written is a normal
    /// close, not a crash (AC-06).
    #[tokio::test]
    async fn immediate_eof_is_normal_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                handle_connection(stream, peer).await;
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());

        let _ = server.await;
    }

    /// Integration test: the listener keeps running after a recoverable
    /// client error (AC-07). We simulate this by sending bytes, dropping
    /// the client abruptly, then opening a second connection that must
    /// still succeed. The spawned server task is aborted at the end of
    /// the test — `tokio::test` cleans up automatically.
    #[tokio::test]
    async fn listener_survives_abrupt_client_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                tokio::spawn(handle_connection(stream, peer));
            }
        });

        // Connection 1: send something, then drop without shutdown.
        // This RSTs the connection; the server's read will surface as
        // an error and `handle_connection` will return without
        // affecting the listener loop.
        {
            let mut c1 = TcpStream::connect(addr).await.unwrap();
            c1.write_all(b"first").await.unwrap();
            drop(c1);
        }

        // Give the server task a chance to observe the close.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connection 2: must still be served by the same listener.
        let mut c2 = TcpStream::connect(addr).await.unwrap();
        c2.write_all(b"second").await.unwrap();
        c2.shutdown().await.unwrap();
        let mut received = Vec::new();
        c2.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.as_slice(), b"second");

        server.abort();
    }
}
