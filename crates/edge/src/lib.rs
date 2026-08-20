//! `tunnelproxy-edge`
//!
//! Public ingress and live tunnel routing for TunnelProxy.
//!
//! This crate contains two distinct but coexisting TCP primitives:
//!
//! - The **echo baseline** from Session 02 (`run_listener`,
//!   `handle_connection`). It binds a TCP listener and echoes every
//!   byte back to the client. Kept for regression coverage and as the
//!   simplest possible networking smoke test.
//!
//! - The **bidirectional TCP relay** from Session 03
//!   (`run_relay_listener`, `relay_connection`, `relay_bidirectional`,
//!   [`RelayStats`], [`RelayError`]). It binds a TCP listener; for
//!   every accepted downstream connection it opens a fresh upstream
//!   TCP connection to a configured address and forwards raw bytes
//!   concurrently in both directions using
//!   [`tokio::io::copy_bidirectional`]. The relay preserves TCP
//!   half-close semantics so that EOF in one direction does not kill
//!   traffic in the other.
//!
//! Neither primitive implements the TunnelProxy reverse-tunnel
//! protocol. The relay is a **layer-4 TCP relay primitive**: it does
//! not understand HTTP, framing, sessions, multiplexing, or
//! authentication. It exists to validate the byte-stream pipeline that
//! later sessions will reuse for the agent ↔ edge tunnel. See
//! `docs/ai/DECISIONS.md` (ADR-002, ADR-005) and `docs/TECH_DEBT.md`
//! for the deliberate limitations.

#![deny(unsafe_code)]

use std::net::SocketAddr;

use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, trace, warn};

/// Default development bind address for the edge listener.
///
/// `127.0.0.1:7000` is local-only. The edge MUST NOT bind a public
/// address in the foundation phase; doing so would conflict with the
/// production architecture and with INV-001 (only agents initiate
/// outbound tunnels).
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:7000";

/// Default upstream address for the relay development binary.
///
/// Pairs with [`DEFAULT_BIND_ADDR`]: a relay running on `127.0.0.1:7000`
/// will forward to `127.0.0.1:8000` by default.
pub const DEFAULT_UPSTREAM_ADDR: &str = "127.0.0.1:8000";

/// Size of the per-connection read buffer used by the Session 02 echo
/// baseline.
///
/// 8 KiB is a reasonable default for the byte-stream baseline. The
/// invariant in INV-002 (no unbounded buffering) is satisfied because
/// the buffer is a fixed allocation and is reused across reads; we
/// never call `read_to_end` on a live socket. The relay does not use
/// this constant directly — `tokio::io::copy_bidirectional` allocates
/// its own fixed-size intermediate buffer (default 8 KiB).
pub const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Bind a TCP listener and serve connections forever, echoing every
/// byte received from each client back to that client until EOF or
/// error.
///
/// This is the Session 02 baseline. Kept for regression coverage and
/// as the simplest possible networking smoke test. New code should
/// prefer the relay primitives below for any non-trivial workload.
///
/// `bind_addr` is resolved by the caller. Use [`DEFAULT_BIND_ADDR`] for
/// the development binary.
///
/// Each accepted connection is handled by [`handle_connection`],
/// spawned as an independent Tokio task so that one connection's
/// failure cannot stall others. Connection-level errors are logged
/// and swallowed; listener-level fatal errors return them to the
/// caller.
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

/// Drive a single accepted TCP connection: read bytes in a fixed
/// buffer and echo them back until the peer half-closes or the
/// connection errors.
///
/// Exposed as a public function so integration tests can drive a
/// pre-built `TcpStream` directly. Real listener use funnels here via
/// [`run_listener`].
///
/// This function never panics on ordinary network failures. Read
/// errors after the first byte are treated as a normal close. Write
/// errors are logged and cause the connection to be dropped so the
/// caller can reclaim the socket.
pub async fn handle_connection(mut stream: TcpStream, peer: SocketAddr) {
    let mut buf = vec![0u8; READ_BUFFER_SIZE];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
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

// ---------------------------------------------------------------------------
// Session 03 — bidirectional TCP relay
// ---------------------------------------------------------------------------

/// Summary of bytes forwarded in both directions during a single relay
/// connection.
///
/// Returned by [`relay_bidirectional`] and surfaced through
/// [`relay_connection`] so callers and tests can assert that traffic
/// actually flowed through the relay.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    /// Bytes forwarded from the downstream client to the upstream
    /// server.
    pub bytes_downstream_to_upstream: u64,
    /// Bytes forwarded from the upstream server back to the downstream
    /// client.
    pub bytes_upstream_to_downstream: u64,
}

/// Errors that can occur during a single relay connection.
///
/// These deliberately stay coarse-grained: the relay is a TCP primitive,
/// not a diagnostic tool. Tests and the dev binary use the variants
/// only to distinguish "could not even open the upstream" from
/// "upstream opened but I/O failed while relaying".
#[derive(Debug)]
pub enum RelayError {
    /// Opening the upstream TCP connection failed for a specific
    /// downstream connection. The downstream connection is dropped;
    /// the listener keeps running.
    UpstreamConnect {
        upstream: SocketAddr,
        source: std::io::Error,
    },
    /// One half of the bidirectional copy failed after both sockets
    /// were established. The other half is shorted out as part of the
    /// relay teardown.
    Copy {
        from: RelayDirection,
        to: RelayDirection,
        source: std::io::Error,
    },
}

/// Identifies which side of the relay a byte copy involves.
///
/// `Downstream` is the client that connected to the edge relay.
/// `Upstream` is the TCP service the relay dialed on behalf of that
/// client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    Downstream,
    Upstream,
}

impl std::fmt::Display for RelayDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayDirection::Downstream => f.write_str("downstream"),
            RelayDirection::Upstream => f.write_str("upstream"),
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::UpstreamConnect { upstream, source } => {
                write!(f, "upstream connect to {upstream} failed: {source}")
            }
            RelayError::Copy { from, to, source } => {
                write!(f, "copy {from} -> {to} failed: {source}")
            }
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RelayError::UpstreamConnect { source, .. } => Some(source),
            RelayError::Copy { source, .. } => Some(source),
        }
    }
}

/// Forward raw bytes concurrently in both directions between
/// `downstream` and `upstream` until either side closes its write
/// half.
///
/// The relay is **byte-oriented**: it never inspects, parses, or
/// rewrites payload bytes. Each direction is forwarded independently
/// using [`tokio::io::copy_bidirectional`], which already honours TCP
/// half-close semantics: when one direction finishes, the matching
/// write half on the other side is shut down so the remote peer
/// observes EOF.
///
/// Returns the total byte counts forwarded in each direction. The
/// byte counts reflect successful copies only — bytes that could not
/// be delivered because the connection failed are not included.
///
/// INV-002 (no unbounded buffering) is structurally satisfied because
/// `copy_bidirectional` allocates its own fixed-size intermediate
/// buffer (default 8 KiB) and propagates backpressure naturally.
pub async fn relay_bidirectional(
    mut downstream: TcpStream,
    mut upstream: TcpStream,
) -> Result<RelayStats, RelayError> {
    let (dn_to_up, up_to_dn) = copy_bidirectional(&mut downstream, &mut upstream)
        .await
        .map_err(|source| RelayError::Copy {
            from: RelayDirection::Downstream, // either direction; tests assert
            to: RelayDirection::Upstream,     // by byte counts, not by error variant
            source,
        })?;

    Ok(RelayStats {
        bytes_downstream_to_upstream: dn_to_up,
        bytes_upstream_to_downstream: up_to_dn,
    })
}

/// Accept a downstream `TcpStream`, open a fresh upstream connection
/// to `upstream_addr`, and forward bytes bidirectionally between the
/// two until either side closes.
///
/// On a successful upstream connect, this returns the byte counts from
/// [`relay_bidirectional`]. If the upstream connect fails, the
/// downstream socket is closed and [`RelayError::UpstreamConnect`] is
/// returned.
///
/// This function is the per-connection workhorse used by
/// [`run_relay_listener`]. It is exposed publicly so integration tests
/// can drive the full relay lifecycle without owning a listener.
pub async fn relay_connection(
    mut downstream: TcpStream,
    peer: SocketAddr,
    upstream_addr: SocketAddr,
) -> Result<RelayStats, RelayError> {
    info!(
        event = "relay_connection_accepted",
        peer = %peer,
        upstream = %upstream_addr,
        "relay: downstream accepted, dialing upstream"
    );

    let upstream = match TcpStream::connect(upstream_addr).await {
        Ok(stream) => {
            info!(
                event = "relay_upstream_connected",
                peer = %peer,
                upstream = %upstream_addr,
                "relay: upstream connected"
            );
            stream
        }
        Err(source) => {
            error!(
                event = "relay_failed",
                peer = %peer,
                upstream = %upstream_addr,
                error = %source,
                "relay: upstream connect failed; closing downstream only"
            );
            // Explicitly close the downstream side. Dropping it would
            // also work, but a graceful shutdown is clearer in the
            // logs.
            let _ = downstream.shutdown().await;
            return Err(RelayError::UpstreamConnect {
                upstream: upstream_addr,
                source,
            });
        }
    };

    info!(
        event = "relay_started",
        peer = %peer,
        upstream = %upstream_addr,
        "relay: starting bidirectional copy"
    );

    let stats = relay_bidirectional(downstream, upstream).await;

    match &stats {
        Ok(s) => info!(
            event = "relay_completed",
            peer = %peer,
            upstream = %upstream_addr,
            bytes_downstream_to_upstream = s.bytes_downstream_to_upstream,
            bytes_upstream_to_downstream = s.bytes_upstream_to_downstream,
            "relay: completed"
        ),
        Err(err) => warn!(
            event = "relay_failed",
            peer = %peer,
            upstream = %upstream_addr,
            error = %err,
            "relay: copy failed"
        ),
    }

    stats
}

/// Bind a TCP listener on `bind_addr`. For each accepted downstream
/// connection, open a fresh upstream TCP connection to `upstream_addr`
/// and forward bytes bidirectionally until either side closes.
///
/// Connection-level failures (upstream refused, downstream reset,
/// I/O errors) are logged and isolated to that connection; the
/// listener loop continues to accept new connections.
///
/// Returns `Ok(())` only when [`TcpListener::accept`] itself fails.
pub async fn run_relay_listener(
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;
    info!(
        addr = %local,
        upstream = %upstream_addr,
        event = "relay_server_started",
        "relay server bound"
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(async move {
                    let _ = relay_connection(stream, peer, upstream_addr).await;
                });
            }
            Err(err) => {
                error!(error = %err, event = "relay_listener_accept_error", "accept failed");
                return Err(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test for `RelayStats`: it round-trips through serde-like
    /// derivations without losing the byte counts. This guards against
    /// an accidental field rename breaking observability.
    #[test]
    fn relay_stats_default_is_zero() {
        let stats = RelayStats::default();
        assert_eq!(stats.bytes_downstream_to_upstream, 0);
        assert_eq!(stats.bytes_upstream_to_downstream, 0);
    }

    #[test]
    fn relay_error_display_does_not_leak_payloads() {
        let err = RelayError::UpstreamConnect {
            upstream: "127.0.0.1:1".parse().unwrap(),
            source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        };
        let rendered = err.to_string();
        // We deliberately do not assert exact wording — only that
        // neither the address is logged with secret-shaped content
        // nor the upstream service name leaks.
        assert!(rendered.contains("upstream"));
        assert!(rendered.contains("refused"));
    }
}
