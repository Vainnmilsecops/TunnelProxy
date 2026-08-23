//! Agent-side transport: outbound connection, protocol handshake, and session management.
//!
//! This module implements the Agent runtime for connecting to Edge,
//! performing the Tunnel Protocol v1 handshake (HELLO → REGISTER → REGISTERED),
//! and maintaining the established session by answering Edge-initiated
//! heartbeat PING frames with matching PONG frames. Session 08 also bridges one
//! active framed stream to a configured local TCP service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

use tunnelproxy_protocol::{
    Frame, FrameDecoder, FrameEncoder, FrameType, HeartbeatErrorCode, HeartbeatSequence,
    ProtocolError, StreamId, StreamResetCode, TransportSessionId, HEARTBEAT_PAYLOAD_SIZE,
    REGISTERED_PAYLOAD_SIZE, ROLE_AGENT, STREAM_RESET_PAYLOAD_SIZE,
};

use crate::tls::{AgentTransportSecurity, BoxedTransport};

/// Fixed application-data read buffer used by the single-stream bridge.
pub const STREAM_IO_BUFFER_SIZE: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default Edge address the Agent connects to in development.
#[allow(dead_code)]
pub const DEFAULT_EDGE_ADDR: &str = "127.0.0.1:7100";

/// Default connect timeout.
#[allow(dead_code)]
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default handshake timeout (waiting for REGISTERED after sending REGISTER).
#[allow(dead_code)]
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during an Agent transport session.
#[derive(Debug)]
pub enum AgentError {
    /// Failed to establish the underlying TCP connection.
    Connect(std::io::Error),
    /// Plaintext transport was requested for a non-loopback Edge.
    PlaintextRemoteEdge(SocketAddr),
    /// TCP connection timed out.
    ConnectTimeout,
    /// Handshake timed out before completion.
    HandshakeTimeout,
    /// TLS negotiation timed out before Protocol v1 began.
    TlsHandshakeTimeout,
    /// Transient network I/O failed while negotiating TLS.
    TlsTransport(std::io::Error),
    /// Edge identity or mutual-TLS authentication was rejected.
    TlsAuthentication(String),
    /// Protocol violation detected.
    ProtocolViolation { reason: &'static str },
    /// Protocol decode error.
    ProtocolDecode(ProtocolError),
    /// Received a frame that was not expected.
    UnexpectedFrame { frame_type: FrameType },
    /// The REGISTERED payload was invalid.
    InvalidRegisteredPayload { reason: &'static str },
    /// I/O error during the established session.
    SessionIo(std::io::Error),
    /// The connection was closed by the peer.
    ConnectionClosed,
    /// A heartbeat frame had an invalid payload.
    InvalidHeartbeatPayload { frame_type: FrameType },
    /// Edge rejected or terminated the established heartbeat session.
    HeartbeatRejected { code: Option<HeartbeatErrorCode> },
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::PlaintextRemoteEdge(addr) => {
                write!(
                    f,
                    "plaintext transport is restricted to loopback, got {addr}"
                )
            }
            Self::ConnectTimeout => write!(f, "connect timed out"),
            Self::HandshakeTimeout => write!(f, "handshake timed out"),
            Self::TlsHandshakeTimeout => write!(f, "TLS handshake timed out"),
            Self::TlsTransport(error) => write!(f, "TLS transport failed: {error}"),
            Self::TlsAuthentication(reason) => {
                write!(f, "TLS identity or authentication rejected: {reason}")
            }
            Self::ProtocolViolation { reason } => write!(f, "protocol violation: {reason}"),
            Self::ProtocolDecode(e) => write!(f, "protocol decode error: {e}"),
            Self::UnexpectedFrame { frame_type } => {
                write!(f, "unexpected frame type: {frame_type:?}")
            }
            Self::InvalidRegisteredPayload { reason } => {
                write!(f, "invalid REGISTERED payload: {reason}")
            }
            Self::SessionIo(e) => write!(f, "session I/O error: {e}"),
            Self::ConnectionClosed => write!(f, "connection closed by peer"),
            Self::InvalidHeartbeatPayload { frame_type } => {
                write!(f, "invalid {frame_type:?} heartbeat payload")
            }
            Self::HeartbeatRejected { code: Some(code) } => {
                write!(f, "heartbeat rejected by Edge: {code:?}")
            }
            Self::HeartbeatRejected { code: None } => {
                write!(f, "heartbeat rejected by Edge with an unknown error")
            }
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::TlsTransport(e) => Some(e),
            Self::ProtocolDecode(e) => Some(e),
            Self::SessionIo(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// An established Agent transport session after successful handshake.
///
/// The session owns its plaintext or TLS byte stream. Dropping the
/// session closes the connection.
pub struct AgentSession {
    /// Session identifier assigned by Edge (from the REGISTERED frame).
    pub session_id: TransportSessionId,
    /// Address of the connected Edge.
    pub edge_addr: SocketAddr,
    /// When the session was established.
    pub established_at: Instant,
    pub(crate) socket: BoxedTransport,
}

impl std::fmt::Debug for AgentSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSession")
            .field("session_id", &self.session_id)
            .field("edge_addr", &self.edge_addr)
            .field("established_at", &self.established_at)
            .field("transport", &"redacted byte stream")
            .finish()
    }
}

/// Normal reason the Agent session loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSessionCloseReason {
    /// Edge closed the TCP connection cleanly.
    PeerClosed,
    /// The Agent explicitly shut down its write side.
    LocalShutdown,
}

impl AgentSession {
    /// Reads a single frame from the established session.
    ///
    /// Returns `Ok(None)` on clean EOF. Returns `Err` on protocol decode
    /// error or I/O error.
    ///
    /// Callers that want automatic heartbeat responses should use [`run`](Self::run).
    /// This lower-level method remains available for protocol tests and future
    /// stream dispatch.
    pub async fn read_frame(&mut self) -> Result<Option<Frame>, AgentError> {
        let mut decoder = FrameDecoder::new();
        decoder
            .decode(&mut self.socket)
            .await
            .map_err(AgentError::ProtocolDecode)
    }

    /// Drives the established heartbeat loop until Edge closes the session or
    /// a protocol/I/O failure occurs.
    pub async fn run(&mut self) -> Result<AgentSessionCloseReason, AgentError> {
        loop {
            let frame = match self.read_frame().await? {
                Some(frame) => frame,
                None => return Ok(AgentSessionCloseReason::PeerClosed),
            };

            match frame.frame_type {
                FrameType::Ping => {
                    if let Err(error) = self.respond_to_ping(frame).await {
                        let _ = self.socket.shutdown().await;
                        return Err(error);
                    }
                }
                FrameType::Error => {
                    let error = decode_heartbeat_error(&frame);
                    let _ = self.socket.shutdown().await;
                    return Err(error);
                }
                frame_type => {
                    let _ = self.socket.shutdown().await;
                    return Err(AgentError::UnexpectedFrame { frame_type });
                }
            }
        }
    }

    /// Runs heartbeat plus the Session 08 single-stream reverse data path.
    ///
    /// Edge may open one stream at a time. For each accepted `OPEN_STREAM`, the
    /// Agent connects to `local_addr`, echoes `OPEN_STREAM` as acknowledgment,
    /// then relays bounded `DATA` frames until both directions send
    /// `END_STREAM` or either side resets the stream. The transport returns to
    /// idle after cleanup, allowing another stream to be opened sequentially.
    pub async fn run_with_local_target(
        &mut self,
        local_addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<AgentSessionCloseReason, AgentError> {
        if connect_timeout.is_zero() {
            return Err(AgentError::ProtocolViolation {
                reason: "local connect timeout must be greater than zero",
            });
        }

        let mut decoder = FrameDecoder::new();
        loop {
            let frame = match decoder
                .decode(&mut self.socket)
                .await
                .map_err(AgentError::ProtocolDecode)?
            {
                Some(frame) => frame,
                None => return Ok(AgentSessionCloseReason::PeerClosed),
            };

            match frame.frame_type {
                FrameType::Ping => self.respond_to_ping(frame).await?,
                FrameType::OpenStream => {
                    if !frame.payload.is_empty() {
                        self.send_stream_reset(frame.stream_id, StreamResetCode::ProtocolViolation)
                            .await?;
                        continue;
                    }
                    self.drive_local_stream(
                        &mut decoder,
                        frame.stream_id,
                        local_addr,
                        connect_timeout,
                    )
                    .await?;
                }
                FrameType::Error => {
                    let error = decode_heartbeat_error(&frame);
                    let _ = self.socket.shutdown().await;
                    return Err(error);
                }
                frame_type => {
                    let _ = self.socket.shutdown().await;
                    return Err(AgentError::UnexpectedFrame { frame_type });
                }
            }
        }
    }

    /// Gracefully closes the Agent's TCP write side.
    pub async fn close(&mut self) -> Result<AgentSessionCloseReason, AgentError> {
        self.socket
            .shutdown()
            .await
            .map_err(AgentError::SessionIo)?;
        Ok(AgentSessionCloseReason::LocalShutdown)
    }

    async fn respond_to_ping(&mut self, frame: Frame) -> Result<(), AgentError> {
        if frame.payload.len() as u32 != HEARTBEAT_PAYLOAD_SIZE {
            warn!(
                edge = %self.edge_addr,
                session_id = %self.session_id,
                payload_len = frame.payload.len(),
                event = "heartbeat_invalid_payload",
                "PING payload length is invalid"
            );
            return Err(AgentError::InvalidHeartbeatPayload {
                frame_type: FrameType::Ping,
            });
        }

        let mut bytes = [0_u8; HEARTBEAT_PAYLOAD_SIZE as usize];
        bytes.copy_from_slice(&frame.payload);
        let sequence = HeartbeatSequence::from_be_bytes(bytes).ok_or_else(|| {
            warn!(
                edge = %self.edge_addr,
                session_id = %self.session_id,
                event = "heartbeat_invalid_payload",
                "PING sequence must be non-zero"
            );
            AgentError::InvalidHeartbeatPayload {
                frame_type: FrameType::Ping,
            }
        })?;

        info!(
            edge = %self.edge_addr,
            session_id = %self.session_id,
            heartbeat_sequence = sequence.get(),
            event = "heartbeat_ping_received",
            "heartbeat PING received"
        );

        let pong = Frame::control(FrameType::Pong, sequence.to_be_bytes().to_vec())
            .expect("a heartbeat sequence is a valid control payload");
        FrameEncoder::encode(&mut self.socket, &pong)
            .await
            .map_err(|error| AgentError::SessionIo(std::io::Error::other(error.to_string())))?;
        info!(
            edge = %self.edge_addr,
            session_id = %self.session_id,
            heartbeat_sequence = sequence.get(),
            event = "heartbeat_pong_sent",
            "heartbeat PONG sent"
        );
        Ok(())
    }

    async fn drive_local_stream(
        &mut self,
        decoder: &mut FrameDecoder,
        stream_id: StreamId,
        local_addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<(), AgentError> {
        info!(
            edge = %self.edge_addr,
            session_id = %self.session_id,
            stream_id = stream_id.get(),
            local = %local_addr,
            event = "stream_open_received",
            "single-stream open request received"
        );

        let mut local = match timeout(connect_timeout, TcpStream::connect(local_addr)).await {
            Ok(Ok(socket)) => socket,
            Ok(Err(error)) => {
                warn!(
                    edge = %self.edge_addr,
                    session_id = %self.session_id,
                    stream_id = stream_id.get(),
                    error = %error,
                    event = "stream_local_connect_failed",
                    "local service connection failed"
                );
                self.send_stream_reset(stream_id, StreamResetCode::LocalConnectFailed)
                    .await?;
                return Ok(());
            }
            Err(_) => {
                warn!(
                    edge = %self.edge_addr,
                    session_id = %self.session_id,
                    stream_id = stream_id.get(),
                    event = "stream_local_connect_timeout",
                    "local service connection timed out"
                );
                self.send_stream_reset(stream_id, StreamResetCode::LocalConnectTimeout)
                    .await?;
                return Ok(());
            }
        };
        if let Err(error) = local.set_nodelay(true) {
            warn!(error = %error, stream_id = stream_id.get(), "failed to set local TCP_NODELAY");
        }

        self.send_stream_frame(stream_id, FrameType::OpenStream, Vec::new())
            .await?;
        info!(
            edge = %self.edge_addr,
            session_id = %self.session_id,
            stream_id = stream_id.get(),
            local = %local_addr,
            event = "stream_local_connected",
            "local service connected and stream acknowledged"
        );

        let mut buffer = [0_u8; STREAM_IO_BUFFER_SIZE];
        let mut edge_to_local_open = true;
        let mut local_to_edge_open = true;
        let mut bytes_edge_to_local = 0_u64;
        let mut bytes_local_to_edge = 0_u64;

        while edge_to_local_open || local_to_edge_open {
            tokio::select! {
                incoming = decoder.decode(&mut self.socket) => {
                    let frame = match incoming.map_err(AgentError::ProtocolDecode)? {
                        Some(frame) => frame,
                        None => return Err(AgentError::ConnectionClosed),
                    };
                    match frame.frame_type {
                        FrameType::Ping => self.respond_to_ping(frame).await?,
                        FrameType::Data => {
                            if frame.stream_id != stream_id || frame.payload.is_empty() || !edge_to_local_open {
                                self.send_stream_reset(frame.stream_id, StreamResetCode::ProtocolViolation).await?;
                                return Err(AgentError::ProtocolViolation {
                                    reason: "invalid DATA frame for active stream",
                                });
                            }
                            if let Err(error) = local.write_all(&frame.payload).await {
                                warn!(stream_id = stream_id.get(), error = %error, event = "stream_local_io_failed", "local stream write failed");
                                self.send_stream_reset(stream_id, StreamResetCode::IoFailure).await?;
                                return Ok(());
                            }
                            bytes_edge_to_local = bytes_edge_to_local.saturating_add(frame.payload.len() as u64);
                        }
                        FrameType::EndStream => {
                            if frame.stream_id != stream_id || !frame.payload.is_empty() || !edge_to_local_open {
                                self.send_stream_reset(frame.stream_id, StreamResetCode::ProtocolViolation).await?;
                                return Err(AgentError::ProtocolViolation {
                                    reason: "invalid END_STREAM frame for active stream",
                                });
                            }
                            if let Err(error) = local.shutdown().await {
                                warn!(stream_id = stream_id.get(), error = %error, event = "stream_local_io_failed", "local stream half-close failed");
                                self.send_stream_reset(stream_id, StreamResetCode::IoFailure).await?;
                                return Ok(());
                            }
                            edge_to_local_open = false;
                            info!(stream_id = stream_id.get(), event = "stream_half_closed", direction = "edge_to_local", "stream direction closed");
                        }
                        FrameType::ResetStream => {
                            if frame.stream_id != stream_id {
                                self.send_stream_reset(frame.stream_id, StreamResetCode::ProtocolViolation).await?;
                                return Err(AgentError::ProtocolViolation {
                                    reason: "RESET_STREAM used the wrong stream ID",
                                });
                            }
                            let Some(code) = decode_stream_reset(&frame) else {
                                self.send_stream_reset(stream_id, StreamResetCode::ProtocolViolation).await?;
                                return Err(AgentError::ProtocolViolation {
                                    reason: "RESET_STREAM payload must be a known two-byte code",
                                });
                            };
                            info!(stream_id = stream_id.get(), reset_code = ?code, event = "stream_reset_received", "stream reset by Edge");
                            return Ok(());
                        }
                        FrameType::OpenStream => {
                            self.send_stream_reset(frame.stream_id, StreamResetCode::StreamBusy).await?;
                        }
                        frame_type => {
                            self.send_stream_reset(stream_id, StreamResetCode::ProtocolViolation).await?;
                            return Err(AgentError::UnexpectedFrame { frame_type });
                        }
                    }
                }
                read = local.read(&mut buffer), if local_to_edge_open => {
                    match read {
                        Ok(0) => {
                            self.send_stream_frame(stream_id, FrameType::EndStream, Vec::new()).await?;
                            local_to_edge_open = false;
                            info!(stream_id = stream_id.get(), event = "stream_half_closed", direction = "local_to_edge", "stream direction closed");
                        }
                        Ok(read) => {
                            self.send_stream_frame(stream_id, FrameType::Data, buffer[..read].to_vec()).await?;
                            bytes_local_to_edge = bytes_local_to_edge.saturating_add(read as u64);
                        }
                        Err(error) => {
                            warn!(stream_id = stream_id.get(), error = %error, event = "stream_local_io_failed", "local stream read failed");
                            self.send_stream_reset(stream_id, StreamResetCode::IoFailure).await?;
                            return Ok(());
                        }
                    }
                }
            }
        }

        info!(
            edge = %self.edge_addr,
            session_id = %self.session_id,
            stream_id = stream_id.get(),
            bytes_edge_to_local,
            bytes_local_to_edge,
            event = "stream_closed",
            "single stream completed"
        );
        Ok(())
    }

    async fn send_stream_frame(
        &mut self,
        stream_id: StreamId,
        frame_type: FrameType,
        payload: Vec<u8>,
    ) -> Result<(), AgentError> {
        let frame =
            Frame::stream(stream_id, frame_type, payload).map_err(AgentError::ProtocolDecode)?;
        FrameEncoder::encode(&mut self.socket, &frame)
            .await
            .map(|_| ())
            .map_err(AgentError::ProtocolDecode)
    }

    async fn send_stream_reset(
        &mut self,
        stream_id: StreamId,
        code: StreamResetCode,
    ) -> Result<(), AgentError> {
        self.send_stream_frame(
            stream_id,
            FrameType::ResetStream,
            code.to_be_bytes().to_vec(),
        )
        .await
    }
}

fn decode_heartbeat_error(frame: &Frame) -> AgentError {
    let code = if frame.payload.len() == 2 {
        let bytes = [frame.payload[0], frame.payload[1]];
        HeartbeatErrorCode::from_be_bytes(bytes)
    } else {
        None
    };
    AgentError::HeartbeatRejected { code }
}

fn decode_stream_reset(frame: &Frame) -> Option<StreamResetCode> {
    if frame.payload.len() as u32 != STREAM_RESET_PAYLOAD_SIZE {
        return None;
    }
    StreamResetCode::from_be_bytes([frame.payload[0], frame.payload[1]])
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Outcome of a connection and handshake attempt.
#[derive(Debug)]
pub enum ConnectOutcome {
    /// Handshake succeeded; a live session was established.
    Established(AgentSession),
    /// Handshake failed; connection was closed.
    Failed { reason: AgentError },
}

/// Connects to `edge_addr`, performs the v1 handshake, and returns an
/// established session.
///
/// This is the primary public entry point. The session remains open
/// after return. Drop the session to close it.
///
/// # Timeouts
///
/// - TCP connect: bounded by `connect_timeout`.
/// - Full handshake: bounded by `handshake_timeout`.
///
/// Neither timeout limits the established session lifetime.
pub async fn connect(
    edge_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ConnectOutcome {
    connect_with_security(
        edge_addr,
        connect_timeout,
        handshake_timeout,
        &AgentTransportSecurity::PlaintextLoopback,
    )
    .await
}

/// Connects using the configured plaintext-loopback or mutual-TLS transport,
/// then performs the unchanged Protocol v1 handshake.
pub async fn connect_with_security(
    edge_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    security: &AgentTransportSecurity,
) -> ConnectOutcome {
    if matches!(security, AgentTransportSecurity::PlaintextLoopback)
        && !edge_addr.ip().is_loopback()
    {
        return ConnectOutcome::Failed {
            reason: AgentError::PlaintextRemoteEdge(edge_addr),
        };
    }
    info!(edge = %edge_addr, event = "agent_connecting", "connecting to edge");

    let socket = match timeout(connect_timeout, TcpStream::connect(edge_addr)).await {
        Ok(Ok(s)) => {
            info!(edge = %edge_addr, event = "agent_tcp_connected", "TCP connected");
            s
        }
        Ok(Err(e)) => {
            error!(edge = %edge_addr, error = %e, event = "agent_connect_error", "connect failed");
            return ConnectOutcome::Failed {
                reason: AgentError::Connect(e),
            };
        }
        Err(_) => {
            error!(edge = %edge_addr, event = "agent_connect_timeout", "connect timed out");
            return ConnectOutcome::Failed {
                reason: AgentError::ConnectTimeout,
            };
        }
    };

    if let Err(e) = socket.set_nodelay(true) {
        warn!(error = %e, "failed to set TCP_NODELAY");
    }

    let mut socket: BoxedTransport = match security {
        AgentTransportSecurity::PlaintextLoopback => Box::new(socket),
        AgentTransportSecurity::MutualTls(tls) => {
            let connector = TlsConnector::from(Arc::clone(&tls.client_config));
            let negotiation = connector.connect(tls.server_name.clone(), socket);
            match timeout(tls.handshake_timeout, negotiation).await {
                Ok(Ok(stream)) => {
                    info!(edge = %edge_addr, event = "agent_tls_established", "mutual TLS established");
                    Box::new(stream)
                }
                Ok(Err(error)) if is_transient_tls_error(&error) => {
                    return ConnectOutcome::Failed {
                        reason: AgentError::TlsTransport(error),
                    };
                }
                Ok(Err(error)) => {
                    return ConnectOutcome::Failed {
                        reason: AgentError::TlsAuthentication(error.to_string()),
                    };
                }
                Err(_) => {
                    return ConnectOutcome::Failed {
                        reason: AgentError::TlsHandshakeTimeout,
                    };
                }
            }
        }
    };

    match timeout(handshake_timeout, perform_handshake(&mut socket, edge_addr)).await {
        Ok(Ok(session_id)) => {
            let session = AgentSession {
                session_id,
                edge_addr,
                established_at: Instant::now(),
                socket,
            };
            info!(
                edge = %edge_addr,
                session_id = %session.session_id,
                event = "agent_session_established",
                "agent transport session established"
            );
            ConnectOutcome::Established(session)
        }
        Ok(Err(e)) => {
            let e = normalize_tls_handshake_error(e, security.is_tls());
            error!(edge = %edge_addr, error = %e, event = "agent_handshake_failed", "handshake failed");
            ConnectOutcome::Failed { reason: e }
        }
        Err(_) => {
            error!(edge = %edge_addr, event = "agent_handshake_timeout", "handshake timed out");
            ConnectOutcome::Failed {
                reason: AgentError::HandshakeTimeout,
            }
        }
    }
}

/// Performs the v1 handshake: HELLO → REGISTER → REGISTERED.
async fn perform_handshake(
    socket: &mut BoxedTransport,
    edge_addr: SocketAddr,
) -> Result<TransportSessionId, AgentError> {
    info!(edge = %edge_addr, event = "agent_handshake_started", "starting handshake");

    // --- Send HELLO ---
    let hello_frame = Frame::control(FrameType::Hello, vec![ROLE_AGENT])
        .expect("ROLE_AGENT is a valid single byte; qed");
    FrameEncoder::encode(socket, &hello_frame)
        .await
        .map_err(|e| AgentError::SessionIo(std::io::Error::other(e.to_string())))?;
    info!(edge = %edge_addr, event = "agent_hello_sent", "HELLO sent");

    // --- Send REGISTER ---
    let register_frame =
        Frame::control(FrameType::Register, vec![]).expect("empty payload is always valid");
    FrameEncoder::encode(socket, &register_frame)
        .await
        .map_err(|e| AgentError::SessionIo(std::io::Error::other(e.to_string())))?;
    info!(edge = %edge_addr, event = "agent_register_sent", "REGISTER sent");

    // --- Await REGISTERED ---
    let mut decoder = FrameDecoder::new();
    let registered_frame = match decoder.decode(socket).await {
        Ok(Some(f)) => f,
        Ok(None) => return Err(AgentError::ConnectionClosed),
        Err(e) => return Err(AgentError::ProtocolDecode(e)),
    };

    if registered_frame.frame_type != FrameType::Registered {
        return Err(AgentError::UnexpectedFrame {
            frame_type: registered_frame.frame_type,
        });
    }

    // Validate REGISTERED payload: exactly 8 bytes, non-zero ID.
    if registered_frame.payload.len() as u32 != REGISTERED_PAYLOAD_SIZE {
        return Err(AgentError::InvalidRegisteredPayload {
            reason: "REGISTERED payload must be exactly 8 bytes",
        });
    }

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&registered_frame.payload);
    let session_id = match TransportSessionId::from_be_bytes(bytes) {
        Some(id) => id,
        None => {
            return Err(AgentError::InvalidRegisteredPayload {
                reason: "REGISTERED session ID must be non-zero",
            });
        }
    };

    info!(
        edge = %edge_addr,
        session_id = %session_id,
        event = "agent_registered_received",
        "REGISTERED received"
    );

    Ok(session_id)
}

fn is_transient_tls_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::UnexpectedEof
    )
}

fn normalize_tls_handshake_error(error: AgentError, tls: bool) -> AgentError {
    if !tls {
        return error;
    }
    match error {
        AgentError::ProtocolDecode(ProtocolError::Io(error)) | AgentError::SessionIo(error)
            if error.kind() == std::io::ErrorKind::InvalidData =>
        {
            AgentError::TlsAuthentication(error.to_string())
        }
        error => error,
    }
}
