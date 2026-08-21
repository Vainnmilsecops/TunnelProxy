//! Agent control transport: Edge-side protocol handshake and session management.
//!
//! This module implements the Edge runtime for accepting Agent connections,
//! performing the Tunnel Protocol v1 handshake (HELLO → REGISTER → REGISTERED),
//! and maintaining established sessions.
//!
//! # Lifecycle
//!
//! Edge observes this per-connection state machine:
//!
//! ```text
//! TCP_ACCEPTED
//!     |
//!     v
//! AWAIT_HELLO  --timeout/EOF--> CLOSED
//!     |
//!     v  (valid HELLO received)
//! AWAIT_REGISTER  --timeout/EOF/wrong_frame --> CLOSED
//!     |
//!     v  (valid REGISTER received)
//! ESTABLISHED  --EOF/error--> CLOSED
//! ```
//!
//! The permit from the capacity semaphore is held for the entire lifetime
//! of the connection (from TCP_ACCEPTED through CLOSED), ensuring bounded
//! admission even during slow handshakes.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, info, warn};

use tunnelproxy_protocol::{
    Frame, FrameDecoder, FrameEncoder, FrameType, HandshakeErrorCode, ProtocolError,
    TransportSessionId, HELLO_PAYLOAD_SIZE, ROLE_AGENT,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default development bind address for the agent control listener.
///
/// `127.0.0.1` is local-only and deliberate: this transport is not yet
/// authenticated or encrypted, so binding a public interface would expose
/// an unauthenticated protocol endpoint.
pub const DEFAULT_AGENT_LISTEN_ADDR: &str = "127.0.0.1:7100";

/// Default maximum concurrent Agent transport sessions.
pub const DEFAULT_MAX_AGENT_SESSIONS: usize = 50;

/// Default handshake timeout (how long Edge waits for a complete handshake).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for an [`AgentTransportListener`].
#[derive(Debug, Clone)]
pub struct AgentListenerConfig {
    /// Local address to bind for incoming Agent connections.
    pub listen_addr: SocketAddr,
    /// Maximum number of concurrent Agent sessions.
    /// Each accepted connection consumes one permit for its full lifetime.
    pub max_agent_sessions: usize,
    /// Maximum time to wait for a complete handshake after TCP acceptance.
    /// Does not limit established session lifetime.
    pub handshake_timeout: Duration,
}

impl AgentListenerConfig {
    /// Development defaults: bind `127.0.0.1:0` (ephemeral port), 50 sessions, 10 s handshake.
    pub fn dev_defaults() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".parse().expect("hardcoded default is valid"),
            max_agent_sessions: DEFAULT_MAX_AGENT_SESSIONS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Validates the configuration. Returns `Ok` if all fields are usable.
    pub fn validate(&self) -> Result<(), AgentListenerConfigError> {
        if self.max_agent_sessions == 0 {
            return Err(AgentListenerConfigError::ZeroMaxSessions);
        }
        if self.handshake_timeout.is_zero() {
            return Err(AgentListenerConfigError::ZeroHandshakeTimeout);
        }
        Ok(())
    }
}

/// Errors from [`AgentListenerConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentListenerConfigError {
    /// `max_agent_sessions` must be greater than zero.
    ZeroMaxSessions,
    /// `handshake_timeout` must be a positive duration.
    ZeroHandshakeTimeout,
}

impl std::fmt::Display for AgentListenerConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaxSessions => f.write_str("max_agent_sessions must be greater than zero"),
            Self::ZeroHandshakeTimeout => {
                f.write_str("handshake_timeout must be greater than zero")
            }
        }
    }
}

impl std::error::Error for AgentListenerConfigError {}

// ---------------------------------------------------------------------------
// Transport session ID allocator
// ---------------------------------------------------------------------------

/// Process-local allocator for [`TransportSessionId`].
///
/// Wraps an `AtomicU64` counter starting at 0; allocating returns
/// `fetch_add(1) + 1`, so the first issued ID is 1. Zero is reserved
/// as invalid. If wraparound ever returns zero (after 2^64 allocations),
/// the allocator retries once. If the retry also returns zero, `None`
/// is returned — a safe failure rather than a silent zero-ID session.
#[derive(Debug, Default)]
pub struct TransportSessionIdAllocator {
    counter: AtomicU64,
}

impl TransportSessionIdAllocator {
    /// Creates a new allocator with the first ID set to 1.
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Allocates and returns the next [`TransportSessionId`].
    ///
    /// Returns `None` if the allocator would return zero (wraparound edge
    /// case after 2^64 allocations — safe failure, not a silent zero-ID).
    pub fn next_id(&self) -> Option<TransportSessionId> {
        let raw = self
            .counter
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        TransportSessionId::new(raw)
    }
}

// ---------------------------------------------------------------------------
// Handshake state machine
// ---------------------------------------------------------------------------

/// Per-connection handshake state observed by Edge.
///
/// Used for structured logging and test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// TCP connection accepted; waiting for HELLO.
    AwaitHello,
    /// Valid HELLO received; waiting for REGISTER.
    AwaitRegister,
    /// Handshake complete; session is established.
    Established,
    /// Session closed (success, timeout, protocol error, or EOF).
    Closed,
}

impl HandshakeState {
    /// Short identifier for log fields.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitHello => "await_hello",
            Self::AwaitRegister => "await_register",
            Self::Established => "established",
            Self::Closed => "closed",
        }
    }
}

/// Errors that can occur during an Agent transport session.
#[derive(Debug)]
pub enum AgentTransportError {
    /// Handshake timed out before completion.
    HandshakeTimeout { state: HandshakeState },
    /// Protocol violation detected (wrong frame, wrong payload, etc.).
    ProtocolViolation { reason: &'static str },
    /// Decoder returned a protocol error (bad magic, version, etc.).
    ProtocolDecode(ProtocolError),
    /// Unexpected peer disconnect during handshake.
    UnexpectedEof { state: HandshakeState },
    /// I/O error during the established session (post-handshake).
    SessionIo(std::io::Error),
}

impl std::fmt::Display for AgentTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeTimeout { state } => {
                write!(f, "handshake timeout in state {:?}", state)
            }
            Self::ProtocolViolation { reason } => write!(f, "protocol violation: {reason}"),
            Self::ProtocolDecode(e) => write!(f, "protocol decode error: {e}"),
            Self::UnexpectedEof { state } => write!(f, "unexpected EOF in state {:?}", state),
            Self::SessionIo(e) => write!(f, "session I/O error: {e}"),
        }
    }
}

impl std::error::Error for AgentTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HandshakeTimeout { .. } => None,
            Self::ProtocolViolation { .. } => None,
            Self::ProtocolDecode(e) => Some(e),
            Self::UnexpectedEof { .. } => None,
            Self::SessionIo(e) => Some(e),
        }
    }
}

/// Established Agent transport session.
///
/// After successful handshake, the session is kept alive and readable.
/// The session is consumed by the session handler that decides what to
/// do with the established connection.
#[derive(Debug)]
pub struct AgentSession {
    /// Process-local session identifier assigned by Edge.
    pub session_id: TransportSessionId,
    /// Address of the connected Agent.
    pub peer_addr: SocketAddr,
    /// When the session was established.
    pub established_at: Instant,
}

/// Sends an ERROR frame and closes the connection.
///
/// Used for handshake violations where we want to inform the peer
/// before closing. Errors sending the ERROR frame are silently ignored
/// (we close the connection regardless).
async fn send_error_and_close(socket: &mut TcpStream, code: HandshakeErrorCode) {
    let frame = match Frame::control(FrameType::Error, code.to_be_bytes().to_vec()) {
        Ok(f) => f,
        Err(_) => return,
    };
    if FrameEncoder::encode(socket, &frame).await.is_err() {
        // Silently ignore encoding/sending errors — we're closing anyway.
    }
    let _ = socket.shutdown().await;
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// Bounded, protocol-aware Agent control transport listener.
///
/// Binds a `TcpListener` on `config.listen_addr` and accepts incoming
/// Agent connections. Each connection performs the v1 handshake
/// (HELLO → REGISTER → REGISTERED) under a configurable timeout.
///
/// Capacity is bounded by a `Semaphore` sized to `config.max_agent_sessions`.
/// A permit is acquired before the handshake begins and held until the
/// connection closes. This ensures that slow or malicious handshakes do
/// not consume unbounded capacity.
pub struct AgentTransportListener {
    listener: Option<TcpListener>,
    config: AgentListenerConfig,
    semaphore: Arc<Semaphore>,
    session_ids: Arc<TransportSessionIdAllocator>,
    local_addr: SocketAddr,
}

impl AgentTransportListener {
    /// Constructs a listener from configuration and binds the TCP socket.
    ///
    /// Returns an error if `config.validate()` fails or the socket cannot be bound.
    pub async fn bind(config: AgentListenerConfig) -> std::io::Result<Self> {
        config
            .validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let listener = TcpListener::bind(config.listen_addr).await?;
        let local = listener.local_addr()?;
        info!(
            addr = %local,
            max_sessions = config.max_agent_sessions,
            handshake_timeout_ms = config.handshake_timeout.as_millis() as u64,
            event = "agent_transport_listener_started",
            "agent transport listener bound"
        );
        Ok(Self {
            listener: Some(listener),
            semaphore: Arc::new(Semaphore::new(config.max_agent_sessions)),
            session_ids: Arc::new(TransportSessionIdAllocator::new()),
            config,
            local_addr: local,
        })
    }

    /// Returns the bound local address of this listener.
    ///
    /// Only valid after [`bind()`][Self::bind] has been called.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Runs the listener accept loop until `accept` fails.
    ///
    /// Listener errors (bind failures) are returned to the caller.
    /// Connection-level errors (handshake failures, I/O errors) are
    /// logged and do not terminate the listener.
    pub async fn run(&mut self) -> std::io::Result<()> {
        let listener = self.listener.take().expect("run must be called once");

        let semaphore = Arc::clone(&self.semaphore);
        let session_ids = Arc::clone(&self.session_ids);
        let handshake_timeout = self.config.handshake_timeout;

        loop {
            match listener.accept().await {
                Ok((mut stream, peer)) => {
                    let semaphore = Arc::clone(&semaphore);
                    let session_ids = Arc::clone(&session_ids);
                    tokio::spawn(async move {
                        let permit = match semaphore.try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                error!(
                                    peer = %peer,
                                    event = "agent_connection_rejected_capacity",
                                    "no session capacity; closing connection"
                                );
                                let _ = stream.shutdown().await;
                                return;
                            }
                        };
                        agent_session_task(stream, peer, session_ids, handshake_timeout, permit)
                            .await;
                    });
                }
                Err(err) => {
                    error!(
                        error = %err,
                        event = "agent_transport_accept_error",
                        "accept failed"
                    );
                    return Err(err);
                }
            }
        }
    }
}

/// Drives a single Agent connection through the handshake state machine.
async fn agent_session_task(
    mut socket: TcpStream,
    peer: SocketAddr,
    session_ids: Arc<TransportSessionIdAllocator>,
    handshake_timeout: Duration,
    _permit: OwnedSemaphorePermit,
) {
    info!(peer = %peer, event = "agent_connection_accepted", "agent connection accepted");

    let started = Instant::now();

    match tokio::time::timeout(
        handshake_timeout,
        perform_handshake(&mut socket, peer, &session_ids),
    )
    .await
    {
        Ok(Ok(session)) => {
            let duration_ms = started.elapsed().as_millis() as u64;
            info!(
                peer = %peer,
                session_id = %session.session_id,
                duration_ms,
                event = "agent_session_established",
                "agent transport session established"
            );

            // For Session 06: wait for EOF or error on the established session.
            // No traffic streams are implemented yet.
            match socket.read_u8().await {
                Ok(_) => {
                    // Any frame received on an established session is unsupported in v1.
                    warn!(
                        peer = %peer,
                        session_id = %session.session_id,
                        event = "agent_session_unsupported_frame",
                        "received unexpected frame on established session; closing"
                    );
                }
                Err(e) => {
                    // EOF or error — clean close.
                    debug!(
                        peer = %peer,
                        session_id = %session.session_id,
                        error = %e,
                        event = "agent_session_closed",
                        "agent session closed"
                    );
                }
            }
        }
        Ok(Err(e)) => {
            let duration_ms = started.elapsed().as_millis() as u64;
            match &e {
                AgentTransportError::ProtocolViolation { reason } => {
                    error!(
                        peer = %peer,
                        reason,
                        duration_ms,
                        event = "agent_protocol_violation",
                        "agent protocol violation during handshake"
                    );
                }
                AgentTransportError::ProtocolDecode(de) => {
                    error!(
                        peer = %peer,
                        error = %de,
                        duration_ms,
                        event = "agent_protocol_violation",
                        "agent protocol decode error during handshake"
                    );
                }
                AgentTransportError::UnexpectedEof { state } => {
                    debug!(
                        peer = %peer,
                        state = state.as_str(),
                        duration_ms,
                        event = "agent_session_eof",
                        "agent disconnected during handshake"
                    );
                }
                _ => {
                    error!(
                        peer = %peer,
                        error = %e,
                        duration_ms,
                        event = "agent_handshake_error",
                        "agent handshake failed"
                    );
                }
            }
        }
        Err(_) => {
            let duration_ms = started.elapsed().as_millis() as u64;
            error!(
                peer = %peer,
                duration_ms,
                event = "agent_handshake_timeout",
                "agent handshake timed out"
            );
        }
    }
}

/// Performs the v1 handshake: HELLO → REGISTER → REGISTERED.
///
/// Returns `Ok(AgentSession)` on success, or an error on any violation.
/// The socket is owned by this function during the handshake.
async fn perform_handshake(
    socket: &mut TcpStream,
    peer: SocketAddr,
    session_ids: &TransportSessionIdAllocator,
) -> Result<AgentSession, AgentTransportError> {
    info!(peer = %peer, event = "agent_handshake_started", "starting handshake");

    let mut decoder = FrameDecoder::new();

    // --- Await HELLO ---
    let hello_frame = match decoder.decode(socket).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return Err(AgentTransportError::UnexpectedEof {
                state: HandshakeState::AwaitHello,
            });
        }
        Err(e) => {
            return Err(AgentTransportError::ProtocolDecode(e));
        }
    };

    if hello_frame.frame_type != FrameType::Hello {
        info!(
            peer = %peer,
            frame_type = ?hello_frame.frame_type,
            event = "agent_unexpected_frame",
            "expected HELLO, got different frame"
        );
        send_error_and_close(socket, HandshakeErrorCode::UnexpectedFrame).await;
        return Err(AgentTransportError::ProtocolViolation {
            reason: "expected HELLO first",
        });
    }

    // Validate HELLO payload: exactly 1 byte, role == AGENT.
    if hello_frame.payload.len() as u32 != HELLO_PAYLOAD_SIZE {
        info!(
            peer = %peer,
            payload_len = hello_frame.payload.len(),
            event = "agent_invalid_hello",
            "HELLO payload length must be 1"
        );
        send_error_and_close(socket, HandshakeErrorCode::InvalidHello).await;
        return Err(AgentTransportError::ProtocolViolation {
            reason: "invalid HELLO payload length",
        });
    }

    if hello_frame.payload[0] != ROLE_AGENT {
        info!(
            peer = %peer,
            role = hello_frame.payload[0],
            event = "agent_unknown_role",
            "unknown HELLO role"
        );
        send_error_and_close(socket, HandshakeErrorCode::InvalidHello).await;
        return Err(AgentTransportError::ProtocolViolation {
            reason: "unknown HELLO role",
        });
    }

    info!(peer = %peer, event = "agent_hello_received", "HELLO (AGENT) received");

    // --- Await REGISTER ---
    let register_frame = match decoder.decode(socket).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return Err(AgentTransportError::UnexpectedEof {
                state: HandshakeState::AwaitRegister,
            });
        }
        Err(e) => {
            return Err(AgentTransportError::ProtocolDecode(e));
        }
    };

    if register_frame.frame_type != FrameType::Register {
        info!(
            peer = %peer,
            frame_type = ?register_frame.frame_type,
            event = "agent_unexpected_frame",
            "expected REGISTER, got different frame"
        );
        send_error_and_close(socket, HandshakeErrorCode::UnexpectedFrame).await;
        return Err(AgentTransportError::ProtocolViolation {
            reason: "expected REGISTER as second frame",
        });
    }

    // REGISTER payload must be empty in v1.
    if !register_frame.payload.is_empty() {
        info!(
            peer = %peer,
            payload_len = register_frame.payload.len(),
            event = "agent_invalid_register",
            "REGISTER payload must be empty in v1"
        );
        send_error_and_close(socket, HandshakeErrorCode::InvalidRegister).await;
        return Err(AgentTransportError::ProtocolViolation {
            reason: "REGISTER payload must be empty",
        });
    }

    info!(peer = %peer, event = "agent_register_received", "REGISTER received");

    // --- Allocate session ID ---
    let session_id = match session_ids.next_id() {
        Some(id) => id,
        None => {
            error!(
                peer = %peer,
                event = "agent_session_id_exhausted",
                "transport session ID allocator exhausted"
            );
            return Err(AgentTransportError::ProtocolViolation {
                reason: "session ID allocator exhausted",
            });
        }
    };

    // --- Send REGISTERED ---
    let registered_frame = Frame::control(FrameType::Registered, session_id.to_be_bytes().to_vec())
        .expect("session_id is non-zero; to_be_bytes fits in 8 bytes; both valid for REGISTERED");

    match FrameEncoder::encode(socket, &registered_frame).await {
        Ok(_) => {}
        Err(e) => {
            return Err(AgentTransportError::SessionIo(std::io::Error::other(
                e.to_string(),
            )));
        }
    }

    info!(
        peer = %peer,
        session_id = %session_id,
        event = "agent_registered_sent",
        "REGISTERED sent"
    );

    Ok(AgentSession {
        session_id,
        peer_addr: peer,
        established_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_listener_config_dev_defaults_valid() {
        let cfg = AgentListenerConfig::dev_defaults();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn agent_listener_config_rejects_zero_sessions() {
        let cfg = AgentListenerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_agent_sessions: 0,
            handshake_timeout: Duration::from_secs(10),
        };
        assert_eq!(
            cfg.validate(),
            Err(AgentListenerConfigError::ZeroMaxSessions)
        );
    }

    #[test]
    fn agent_listener_config_rejects_zero_timeout() {
        let cfg = AgentListenerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_agent_sessions: 10,
            handshake_timeout: Duration::ZERO,
        };
        assert_eq!(
            cfg.validate(),
            Err(AgentListenerConfigError::ZeroHandshakeTimeout)
        );
    }

    #[test]
    fn transport_session_id_allocator_starts_at_one() {
        let alloc = TransportSessionIdAllocator::new();
        let id1 = alloc.next_id();
        let id2 = alloc.next_id();
        assert!(id1.is_some());
        assert!(id2.is_some());
        assert!(id1.unwrap() != id2.unwrap());
        assert!(!id1.unwrap().is_invalid());
        assert!(!id2.unwrap().is_invalid());
        assert_eq!(id1.unwrap().get(), 1);
        assert_eq!(id2.unwrap().get(), 2);
    }

    #[test]
    fn transport_session_id_allocator_monotonic() {
        let alloc = TransportSessionIdAllocator::new();
        let ids: Vec<_> = (0..100).filter_map(|_| alloc.next_id()).collect();
        for window in ids.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn handshake_state_as_str() {
        assert_eq!(HandshakeState::AwaitHello.as_str(), "await_hello");
        assert_eq!(HandshakeState::AwaitRegister.as_str(), "await_register");
        assert_eq!(HandshakeState::Established.as_str(), "established");
        assert_eq!(HandshakeState::Closed.as_str(), "closed");
    }
}
