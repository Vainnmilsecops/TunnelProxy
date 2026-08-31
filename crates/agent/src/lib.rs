//! `tunnelproxy-agent`
//!
//! Local TunnelProxy agent / CLI runtime.
//!
//! In Session 02 this crate provides a minimal asynchronous TCP client
//! that connects to a configured `SocketAddr`, writes a deterministic
//! test payload, reads the echoed response, and verifies byte-exact
//! equality. This is **not** the TunnelProxy reverse-tunnel protocol
//! yet; it exists to validate the byte-stream baseline and to give the
//! integration tests something concrete to drive.
//!
//! Session 06 adds the Agent-side transport layer (`agent_transport`):
//! outbound TCP connection to Edge, Tunnel Protocol v2 handshake
//! (HELLO → REGISTER → REGISTERED), and established session management.
//!
//! The agent NEVER accepts inbound connections from the public internet
//! (INV-001). All sockets in this crate are outbound.
//!
//! Session 07 adds Edge-initiated PING/PONG heartbeat handling. Session 08
//! adds a loopback-tested single-stream local TCP bridge, and Session 09 adds
//! bounded concurrent streams through `AgentSession::run_multiplexed`.
//! Session 12 adds the runnable single-session `AgentRuntime` and CLI, Session
//! 13 adds reconnect, Session 14 adds mutual TLS, and Session 15 binds durable
//! Agent/tunnel registration to the authenticated certificate. Session 29 adds
//! a bounded loopback operations endpoint and connection-lifecycle metrics.
//! Session 42 composes managed-hostname allocation with the runnable Agent in
//! `tunnelproxy-agent http <port>`. Session 43 adds the canonical `tunnelproxy`
//! wrapper and a shared CLI driver with strict bounded local config v1. See
//! `docs/ai/SESSION_INDEX.md` and `docs/TECH_DEBT.md` for the limitations.

mod agent_transport;
pub mod cli;
mod enrollment;
mod hostname;
mod multiplex;
mod operations;
mod public_reachability;
mod runtime;
mod tls;

pub use agent_transport::{
    connect, connect_registered_with_security, connect_with_security, development_registration,
    AgentError, AgentSession, AgentSessionCloseReason, ConnectOutcome,
};
pub use enrollment::{
    bootstrap_agent_credentials, read_token as read_enrollment_token,
    write_token as write_enrollment_token, AgentEnrollmentClient, AgentEnrollmentConfig,
    AgentEnrollmentError, AgentEnrollmentRuntime, EnrollmentClientConfig, IssuedEnrollment,
};
pub use hostname::{
    AgentHostnameClient, AgentHostnameError, HostnameAllocation, HostnameClientConfig,
    HostnameRelease,
};
pub use multiplex::{
    MultiplexedAgentConfig, MultiplexedAgentConfigError, MULTIPLEXED_DATA_PAYLOAD_SIZE,
};
pub use operations::{
    AgentOperationsConfig, AgentOperationsConfigError, AgentOperationsError,
    AgentOperationsOutcome, AgentOperationsRuntime, MAX_OPERATIONS_CONNECTIONS,
    MAX_OPERATIONS_HEADERS, MAX_OPERATIONS_HEADER_BYTES, MIN_OPERATIONS_HEADER_BYTES,
};
pub use public_reachability::{
    PublicReachabilityConfig, PublicReachabilityError, PublicReachabilityFailureClass,
    PublicReachabilityOutcome, PublicReachabilityProbe,
    DEFAULT_PUBLIC_REACHABILITY_ATTEMPT_TIMEOUT, DEFAULT_PUBLIC_REACHABILITY_RETRY_INTERVAL,
    DEFAULT_PUBLIC_REACHABILITY_TIMEOUT, MAX_PUBLIC_REACHABILITY_TIMEOUT,
};
pub use runtime::{
    AgentConnectionState, AgentRuntime, AgentRuntimeConfig, AgentRuntimeConfigError,
    AgentRuntimeControl, AgentRuntimeError, AgentRuntimeOutcome, AgentRuntimeStatus,
    AgentRuntimeStatusHandle, ReconnectConfig, ReconnectConfigError,
};
pub use tls::{
    AgentTlsConfig, AgentTlsConfigError, AgentTlsReloadBootstrapError, AgentTlsReloadConfig,
    AgentTlsReloadRuntime, AgentTransportSecurity,
};
pub use tunnelproxy_common::{RuntimeShutdownConfig, ShutdownSignal};

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

/// Default target address for the development binary.
///
/// In Session 02 this is the same address the edge binds in development
/// (`127.0.0.1:7000`). It is local-only by design.
pub const DEFAULT_TARGET_ADDR: &str = "127.0.0.1:7000";

/// Deterministic test payload sent on every connection.
///
/// Kept as bytes (not `&str`) so the network layer never assumes UTF-8
/// (AC-04). Future sessions may extend or parameterise this for real
/// handshake negotiation.
pub const TEST_PAYLOAD: &[u8] = b"hello tunnelproxy";

/// Default per-operation timeout.
///
/// Long-running network operations must have a timeout (INV-005). A
/// short deadline is appropriate for a smoke client; production tunnels
/// will use longer, configurable timeouts and a separate cancellation
/// channel.
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Outcome of a single agent run.
#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// Bytes were sent and the echoed response matched the payload.
    Success { sent: usize, received: usize },
    /// The remote closed or errored before sending back the expected
    /// bytes; we return what was received so the caller can diagnose.
    Mismatch {
        sent: usize,
        received_bytes: Vec<u8>,
        /// Human-readable reason (not a payload).
        reason: &'static str,
    },
}

/// Connect to `target`, send `payload`, read the echo back, and verify
/// equality. Honours INV-005 by wrapping the read in
/// [`DEFAULT_OPERATION_TIMEOUT`].
///
/// Exposed as a public function so integration tests can drive it from
/// in-process Tokio. Real CLI use funnels through [`run`].
pub async fn send_and_verify(target: SocketAddr, payload: &[u8], deadline: Duration) -> RunOutcome {
    debug!(target = %target, event = "tcp_client_connecting", "connecting");
    let stream = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(err) => {
            error!(
                target = %target,
                error = %err,
                event = "tcp_client_connect_error",
                "connect failed"
            );
            return RunOutcome::Mismatch {
                sent: 0,
                received_bytes: Vec::new(),
                reason: "connect_failed",
            };
        }
    };

    if let Err(err) = stream.set_nodelay(true) {
        // nodelay is an optimisation, not a correctness requirement.
        warn!(error = %err, "failed to set TCP_NODELAY");
    }

    let mut stream = stream;
    if let Err(err) = stream.write_all(payload).await {
        error!(error = %err, event = "tcp_client_write_error", "write failed");
        return RunOutcome::Mismatch {
            sent: 0,
            received_bytes: Vec::new(),
            reason: "write_failed",
        };
    }
    info!(
        event = "tcp_client_payload_sent",
        bytes = payload.len(),
        "payload sent"
    );

    // Half-close our write side so the remote's read returns 0 after
    // it has echoed the bytes we sent. This is the canonical way to
    // signal end-of-payload on a TCP byte stream.
    if let Err(err) = stream.shutdown().await {
        warn!(error = %err, event = "tcp_client_shutdown_error", "shutdown failed");
    }

    let mut received = Vec::with_capacity(payload.len());
    match timeout(deadline, stream.read_to_end(&mut received)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!(
                error = %err,
                event = "tcp_client_read_error",
                "read failed"
            );
            return RunOutcome::Mismatch {
                sent: payload.len(),
                received_bytes: received,
                reason: "read_failed",
            };
        }
        Err(_) => {
            error!(event = "tcp_client_timeout", "operation timed out");
            return RunOutcome::Mismatch {
                sent: payload.len(),
                received_bytes: received,
                reason: "timeout",
            };
        }
    }

    trace!(
        event = "tcp_client_payload_received",
        bytes = received.len(),
        "echo received"
    );

    if received.as_slice() == payload {
        RunOutcome::Success {
            sent: payload.len(),
            received: received.len(),
        }
    } else {
        RunOutcome::Mismatch {
            sent: payload.len(),
            received_bytes: received,
            reason: "payload_mismatch",
        }
    }
}

/// High-level entry point used by the development binary.
///
/// Connects to `target`, sends [`TEST_PAYLOAD`], and verifies the
/// response. Returns `Ok(())` only on full success; any other outcome
/// is mapped to a structured error.
pub async fn run(target: SocketAddr) -> Result<(), String> {
    let outcome = send_and_verify(target, TEST_PAYLOAD, DEFAULT_OPERATION_TIMEOUT).await;
    match outcome {
        RunOutcome::Success { sent, received } => {
            info!(
                sent,
                received,
                event = "tcp_client_run_success",
                "echo verified"
            );
            Ok(())
        }
        RunOutcome::Mismatch {
            sent,
            received_bytes,
            reason,
        } => {
            error!(
                sent,
                received = received_bytes.len(),
                reason,
                event = "tcp_client_run_mismatch",
                "echo did not match payload"
            );
            Err(format!("agent run failed: {reason}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tunnelproxy_edge::handle_connection;

    /// Integration test: a real listener echoes the agent's payload back
    /// byte-for-byte. Uses an ephemeral port and real Tokio sockets
    /// (AC-12, AC-13).
    #[tokio::test]
    async fn send_and_verify_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                handle_connection(stream, peer).await;
            }
        });

        let outcome = send_and_verify(addr, TEST_PAYLOAD, Duration::from_secs(2)).await;
        assert_eq!(
            outcome,
            RunOutcome::Success {
                sent: TEST_PAYLOAD.len(),
                received: TEST_PAYLOAD.len(),
            }
        );

        let _ = server.await;
    }

    /// Integration test: a server that drops the connection without
    /// responding surfaces as a `Mismatch`, not a panic (AC-07 spirit).
    #[tokio::test]
    async fn send_and_verify_detects_server_close_without_echo() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            if let Ok((mut stream, _peer)) = listener.accept().await {
                // Read the payload, but never echo anything: close.
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf).await;
                drop(stream);
            }
        });

        let outcome = send_and_verify(addr, TEST_PAYLOAD, Duration::from_secs(2)).await;
        match outcome {
            RunOutcome::Mismatch { reason, .. } => {
                // Acceptable reasons for an unspeaking server: the read
                // hits EOF (received stays empty) and the payload does
                // not match.
                assert_eq!(reason, "payload_mismatch");
            }
            RunOutcome::Success { .. } => panic!("expected mismatch, got success"),
        }

        let _ = server.await;
    }
}
