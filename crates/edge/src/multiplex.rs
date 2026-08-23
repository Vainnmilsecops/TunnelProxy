//! Session registry, routing, and bounded concurrent stream runtime.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use tunnelproxy_common::{RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal};

use tunnelproxy_protocol::{
    Frame, FrameDecoder, FrameEncoder, FrameType, HeartbeatSequence, StreamId, StreamResetCode,
    TransportSessionId, HEARTBEAT_PAYLOAD_SIZE, STREAM_RESET_PAYLOAD_SIZE,
};

use crate::agent_transport::{
    perform_handshake, AgentListenerConfig, AgentListenerConfigError, AgentTransportError,
    TransportSessionIdAllocator,
};
use crate::tls::{BoxedTransport, EdgeTransportSecurity, TUNNELPROXY_ALPN};

/// Maximum DATA payload emitted or accepted by the multiplexed runtime.
pub const MULTIPLEXED_DATA_PAYLOAD_SIZE: usize = 16 * 1024;

/// Limits for the Session 09 Edge runtime.
#[derive(Debug, Clone)]
pub struct MultiplexedEdgeConfig {
    pub agent_listener: AgentListenerConfig,
    pub security: EdgeTransportSecurity,
    pub max_streams_per_session: usize,
    pub session_command_capacity: usize,
    pub per_stream_queue_capacity: usize,
    pub control_queue_capacity: usize,
    pub data_queue_capacity: usize,
    pub stream_open_timeout: Duration,
    pub stream_idle_timeout: Duration,
}

impl MultiplexedEdgeConfig {
    /// Loopback-only development defaults with an ephemeral Agent port.
    pub fn dev_defaults() -> Self {
        Self {
            agent_listener: AgentListenerConfig::dev_defaults(),
            security: EdgeTransportSecurity::default(),
            max_streams_per_session: 32,
            session_command_capacity: 64,
            per_stream_queue_capacity: 8,
            control_queue_capacity: 32,
            data_queue_capacity: 128,
            stream_open_timeout: Duration::from_secs(5),
            stream_idle_timeout: Duration::from_secs(60),
        }
    }

    pub fn validate(&self) -> Result<(), MultiplexedEdgeConfigError> {
        self.agent_listener
            .validate()
            .map_err(MultiplexedEdgeConfigError::AgentListener)?;
        if matches!(self.security, EdgeTransportSecurity::PlaintextLoopback)
            && !self.agent_listener.listen_addr.ip().is_loopback()
        {
            return Err(MultiplexedEdgeConfigError::NonLoopbackAgentListener(
                self.agent_listener.listen_addr,
            ));
        }
        if self.max_streams_per_session == 0 {
            return Err(MultiplexedEdgeConfigError::ZeroMaxStreams);
        }
        if self.session_command_capacity == 0 {
            return Err(MultiplexedEdgeConfigError::ZeroSessionCommandQueue);
        }
        if self.per_stream_queue_capacity == 0 {
            return Err(MultiplexedEdgeConfigError::ZeroPerStreamQueue);
        }
        if self.control_queue_capacity == 0 {
            return Err(MultiplexedEdgeConfigError::ZeroControlQueue);
        }
        if self.data_queue_capacity == 0 {
            return Err(MultiplexedEdgeConfigError::ZeroDataQueue);
        }
        if self.stream_open_timeout.is_zero() {
            return Err(MultiplexedEdgeConfigError::ZeroOpenTimeout);
        }
        if self.stream_idle_timeout.is_zero() {
            return Err(MultiplexedEdgeConfigError::ZeroIdleTimeout);
        }
        Ok(())
    }
}

/// Invalid multiplexed Edge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiplexedEdgeConfigError {
    AgentListener(AgentListenerConfigError),
    NonLoopbackAgentListener(SocketAddr),
    ZeroMaxStreams,
    ZeroSessionCommandQueue,
    ZeroPerStreamQueue,
    ZeroControlQueue,
    ZeroDataQueue,
    ZeroOpenTimeout,
    ZeroIdleTimeout,
}

impl std::fmt::Display for MultiplexedEdgeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentListener(error) => write!(f, "invalid Agent listener config: {error}"),
            Self::NonLoopbackAgentListener(addr) => {
                write!(f, "Agent listener must use a loopback address, got {addr}")
            }
            Self::ZeroMaxStreams => {
                f.write_str("max_streams_per_session must be greater than zero")
            }
            Self::ZeroSessionCommandQueue => {
                f.write_str("session_command_capacity must be greater than zero")
            }
            Self::ZeroPerStreamQueue => {
                f.write_str("per_stream_queue_capacity must be greater than zero")
            }
            Self::ZeroControlQueue => {
                f.write_str("control_queue_capacity must be greater than zero")
            }
            Self::ZeroDataQueue => f.write_str("data_queue_capacity must be greater than zero"),
            Self::ZeroOpenTimeout => f.write_str("stream_open_timeout must be greater than zero"),
            Self::ZeroIdleTimeout => f.write_str("stream_idle_timeout must be greater than zero"),
        }
    }
}

impl std::error::Error for MultiplexedEdgeConfigError {}

type SessionRegistry = Arc<RwLock<HashMap<TransportSessionId, mpsc::Sender<SessionCommand>>>>;

fn sorted_session_ids(
    sessions: &HashMap<TransportSessionId, mpsc::Sender<SessionCommand>>,
) -> Vec<TransportSessionId> {
    let mut ids: Vec<_> = sessions.keys().copied().collect();
    ids.sort_unstable();
    ids
}

/// Cloneable routing handle. The registry contains only live, process-local
/// transport sessions and never acts as durable tunnel identity.
#[derive(Clone)]
pub struct EdgeSessionRouter {
    sessions: SessionRegistry,
    session_updates: watch::Sender<Arc<Vec<TransportSessionId>>>,
    accepting_streams: Arc<AtomicBool>,
}

impl EdgeSessionRouter {
    /// Returns a snapshot of currently established session IDs.
    pub async fn connected_session_ids(&self) -> Vec<TransportSessionId> {
        let mut ids: Vec<_> = self.sessions.read().await.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Returns whether one ephemeral transport session is currently live.
    pub async fn is_connected(&self, session_id: TransportSessionId) -> bool {
        self.sessions.read().await.contains_key(&session_id)
    }

    /// Subscribes to live-session snapshots for route lifecycle management.
    pub fn subscribe_session_ids(&self) -> watch::Receiver<Arc<Vec<TransportSessionId>>> {
        self.session_updates.subscribe()
    }

    /// Routes an already-accepted ingress socket to one exact Agent session.
    /// Success means the Agent acknowledged `OPEN_STREAM`.
    pub async fn open_stream(
        &self,
        session_id: TransportSessionId,
        ingress: TcpStream,
    ) -> Result<StreamId, RouteError> {
        Ok(self
            .open_stream_tracked(session_id, ingress)
            .await?
            .stream_id)
    }

    /// Opens a logical stream and returns a completion handle used by ingress
    /// owners to track drain lifecycle without retaining the TCP socket.
    pub async fn open_stream_tracked(
        &self,
        session_id: TransportSessionId,
        ingress: TcpStream,
    ) -> Result<RoutedStream, RouteError> {
        if !self.accepting_streams.load(Ordering::Acquire) {
            return Err(RouteError::RuntimeDraining);
        }
        let sender = self.sessions.read().await.get(&session_id).cloned();
        let sender = sender.ok_or(RouteError::SessionNotFound(session_id))?;
        let (response_tx, response_rx) = oneshot::channel();
        let (completion_tx, completion_rx) = oneshot::channel();
        sender
            .try_send(SessionCommand::Open {
                ingress,
                response: response_tx,
                completion: completion_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RouteError::SessionBusy(session_id),
                mpsc::error::TrySendError::Closed(_) => RouteError::SessionClosing(session_id),
            })?;
        let stream_id = response_rx
            .await
            .unwrap_or(Err(RouteError::SessionClosing(session_id)))?;
        Ok(RoutedStream {
            session_id,
            stream_id,
            completion: completion_rx,
        })
    }
}

/// A logical stream acknowledged by Agent plus its close notification.
pub struct RoutedStream {
    pub session_id: TransportSessionId,
    pub stream_id: StreamId,
    completion: oneshot::Receiver<RoutedStreamCloseReason>,
}

impl RoutedStream {
    /// Waits until the Edge stream task releases its ingress socket.
    pub async fn wait_closed(self) -> RoutedStreamCloseReason {
        self.completion
            .await
            .unwrap_or(RoutedStreamCloseReason::SessionClosed)
    }
}

impl std::fmt::Debug for RoutedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutedStream")
            .field("session_id", &self.session_id)
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

/// Why a tracked logical stream released its ingress socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutedStreamCloseReason {
    Graceful,
    PeerReset(StreamResetCode),
    SessionClosed,
    IoFailure,
    OpenTimeout,
    IdleTimeout,
    ProtocolViolation,
}

/// Failure to route an ingress connection to a logical stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    RuntimeDraining,
    SessionNotFound(TransportSessionId),
    SessionBusy(TransportSessionId),
    SessionClosing(TransportSessionId),
    CapacityExceeded(TransportSessionId),
    StreamIdExhausted(TransportSessionId),
    StreamRejected(StreamResetCode),
    OpenTimeout(StreamId),
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeDraining => f.write_str("Edge runtime is draining"),
            Self::SessionNotFound(id) => write!(f, "transport session {id} was not found"),
            Self::SessionBusy(id) => write!(f, "transport session {id} command queue is full"),
            Self::SessionClosing(id) => write!(f, "transport session {id} is closing"),
            Self::CapacityExceeded(id) => {
                write!(f, "transport session {id} reached stream capacity")
            }
            Self::StreamIdExhausted(id) => write!(f, "transport session {id} exhausted stream IDs"),
            Self::StreamRejected(code) => write!(f, "Agent rejected stream: {code}"),
            Self::OpenTimeout(id) => write!(f, "stream {} open timed out", id.get()),
        }
    }
}

impl std::error::Error for RouteError {}

/// Accepts Agent sessions and publishes them to an [`EdgeSessionRouter`].
pub struct MultiplexedEdgeRuntime {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: MultiplexedEdgeConfig,
    sessions: SessionRegistry,
    session_ids: Arc<TransportSessionIdAllocator>,
    permits: Arc<Semaphore>,
    session_updates: watch::Sender<Arc<Vec<TransportSessionId>>>,
    accepting_streams: Arc<AtomicBool>,
}

impl MultiplexedEdgeRuntime {
    pub async fn bind(config: MultiplexedEdgeConfig) -> std::io::Result<Self> {
        config
            .validate()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let listener = TcpListener::bind(config.agent_listener.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let permits = Arc::new(Semaphore::new(config.agent_listener.max_agent_sessions));
        let (session_updates, _) = watch::channel(Arc::new(Vec::new()));
        Ok(Self {
            listener,
            local_addr,
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_ids: Arc::new(TransportSessionIdAllocator::new()),
            permits,
            session_updates,
            accepting_streams: Arc::new(AtomicBool::new(true)),
        })
    }

    pub const fn agent_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn router(&self) -> EdgeSessionRouter {
        EdgeSessionRouter {
            sessions: Arc::clone(&self.sessions),
            session_updates: self.session_updates.clone(),
            accepting_streams: Arc::clone(&self.accepting_streams),
        }
    }

    /// Runs until the listener fails or the task is cancelled.
    pub async fn run(self) -> std::io::Result<()> {
        info!(addr = %self.local_addr, event = "multiplexed_edge_started");
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (socket, peer) = accepted?;
                    spawn_accepted_session(
                        &mut tasks,
                        socket,
                        peer,
                        Arc::clone(&self.permits),
                        self.config.clone(),
                        Arc::clone(&self.sessions),
                        Arc::clone(&self.session_ids),
                        self.session_updates.clone(),
                    );
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }

    /// Stops Agent and stream admission, drains sessions, then force-closes
    /// any task still alive at the configured deadline.
    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
        shutdown: RuntimeShutdownConfig,
    ) -> std::io::Result<RuntimeShutdownOutcome> {
        crate::validate_shutdown(shutdown)?;
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (socket, peer) = accepted?;
                    spawn_accepted_session(
                        &mut tasks,
                        socket,
                        peer,
                        Arc::clone(&self.permits),
                        self.config.clone(),
                        Arc::clone(&self.sessions),
                        Arc::clone(&self.session_ids),
                        self.session_updates.clone(),
                    );
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        self.accepting_streams.store(false, Ordering::Release);
        let senders: Vec<_> = self.sessions.read().await.values().cloned().collect();
        for sender in senders {
            let _ = sender.try_send(SessionCommand::BeginDrain);
        }
        drop(self.listener);
        let outcome = crate::drain_tasks(tasks, shutdown.drain_timeout).await;
        self.sessions.write().await.clear();
        self.session_updates.send_replace(Arc::new(Vec::new()));
        Ok(outcome)
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_accepted_session(
    tasks: &mut JoinSet<()>,
    socket: TcpStream,
    peer: SocketAddr,
    permits: Arc<Semaphore>,
    config: MultiplexedEdgeConfig,
    sessions: SessionRegistry,
    session_ids: Arc<TransportSessionIdAllocator>,
    session_updates: watch::Sender<Arc<Vec<TransportSessionId>>>,
) {
    let permit = match permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            warn!(peer = %peer, event = "agent_capacity_rejected");
            drop(socket);
            return;
        }
    };
    tasks.spawn(run_accepted_session(
        socket,
        peer,
        permit,
        config,
        sessions,
        session_ids,
        session_updates,
    ));
}

enum SessionCommand {
    Open {
        ingress: TcpStream,
        response: oneshot::Sender<Result<StreamId, RouteError>>,
        completion: oneshot::Sender<RoutedStreamCloseReason>,
    },
    BeginDrain,
}

enum StreamEvent {
    Closed(StreamId),
}

async fn run_accepted_session(
    socket: TcpStream,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
    config: MultiplexedEdgeConfig,
    sessions: SessionRegistry,
    session_ids: Arc<TransportSessionIdAllocator>,
    session_updates: watch::Sender<Arc<Vec<TransportSessionId>>>,
) {
    let mut socket: BoxedTransport = match &config.security {
        EdgeTransportSecurity::PlaintextLoopback => Box::new(socket),
        EdgeTransportSecurity::MutualTls(tls) => {
            let acceptor = TlsAcceptor::from(Arc::clone(&tls.server_config));
            match tokio::time::timeout(tls.handshake_timeout, acceptor.accept(socket)).await {
                Ok(Ok(stream)) if stream.get_ref().1.alpn_protocol() == Some(TUNNELPROXY_ALPN) => {
                    info!(peer = %peer, event = "edge_tls_established", "mutual TLS established");
                    Box::new(stream)
                }
                Ok(Ok(_)) => {
                    warn!(peer = %peer, event = "edge_tls_alpn_rejected", "Agent did not negotiate TunnelProxy ALPN");
                    return;
                }
                Ok(Err(_)) => {
                    warn!(peer = %peer, event = "edge_tls_authentication_rejected", "Agent TLS authentication failed");
                    return;
                }
                Err(_) => {
                    warn!(peer = %peer, event = "edge_tls_handshake_timeout", "Agent TLS handshake timed out");
                    return;
                }
            }
        }
    };
    let handshake = tokio::time::timeout(
        config.agent_listener.handshake_timeout,
        perform_handshake(&mut socket, peer, &session_ids),
    )
    .await;
    let session = match handshake {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            warn!(peer = %peer, error = %error, event = "multiplexed_handshake_failed");
            return;
        }
        Err(_) => {
            warn!(peer = %peer, event = "multiplexed_handshake_timeout");
            return;
        }
    };

    let session_id = session.session_id;
    let (command_tx, command_rx) = mpsc::channel(config.session_command_capacity);
    let snapshot = {
        let mut sessions = sessions.write().await;
        sessions.insert(session_id, command_tx);
        sorted_session_ids(&sessions)
    };
    session_updates.send_replace(Arc::new(snapshot));
    info!(%session_id, peer = %peer, event = "multiplexed_session_registered");

    if let Err(error) = run_edge_session(socket, session_id, config, command_rx).await {
        warn!(%session_id, error = %error, event = "multiplexed_session_failed");
    }
    let snapshot = {
        let mut sessions = sessions.write().await;
        sessions.remove(&session_id);
        sorted_session_ids(&sessions)
    };
    session_updates.send_replace(Arc::new(snapshot));
    info!(%session_id, event = "multiplexed_session_removed");
}

async fn run_edge_session(
    socket: BoxedTransport,
    session_id: TransportSessionId,
    config: MultiplexedEdgeConfig,
    mut command_rx: mpsc::Receiver<SessionCommand>,
) -> Result<(), AgentTransportError> {
    let (mut reader, writer) = tokio::io::split(socket);
    let (control_tx, control_rx) = mpsc::channel(config.control_queue_capacity);
    let (data_tx, data_rx) = mpsc::channel(config.data_queue_capacity);
    let mut writer_task = tokio::spawn(writer_actor(writer, control_rx, data_rx));
    let (event_tx, mut event_rx) = mpsc::channel(config.max_streams_per_session);
    let mut streams: HashMap<StreamId, mpsc::Sender<Frame>> = HashMap::new();
    let mut next_stream_id = 1_u32;
    let mut decoder = FrameDecoder::new();
    let mut heartbeat_sequence = HeartbeatSequence::FIRST;
    let mut pending_heartbeat: Option<HeartbeatSequence> = None;
    let mut draining = false;
    let heartbeat_timer = tokio::time::sleep(config.agent_listener.heartbeat_interval);
    tokio::pin!(heartbeat_timer);

    loop {
        tokio::select! {
            decoded = decoder.decode(&mut reader) => {
                let frame = match decoded.map_err(AgentTransportError::ProtocolDecode)? {
                    Some(frame) => frame,
                    None => break,
                };
                match frame.frame_type {
                    FrameType::Pong => {
                        let got = decode_heartbeat(&frame).ok_or(
                            AgentTransportError::InvalidHeartbeatPayload { frame_type: FrameType::Pong }
                        )?;
                        let expected = pending_heartbeat.ok_or(AgentTransportError::ProtocolViolation {
                            reason: "unsolicited PONG",
                        })?;
                        if got != expected {
                            return Err(AgentTransportError::HeartbeatSequenceMismatch { expected, got });
                        }
                        pending_heartbeat = None;
                        heartbeat_timer.as_mut().reset(
                            tokio::time::Instant::now() + config.agent_listener.heartbeat_interval
                        );
                    }
                    FrameType::OpenStream | FrameType::Data | FrameType::EndStream | FrameType::ResetStream => {
                        if frame.frame_type == FrameType::Data
                            && frame.payload.len() > MULTIPLEXED_DATA_PAYLOAD_SIZE
                        {
                            streams.remove(&frame.stream_id);
                            send_reset(&control_tx, frame.stream_id, StreamResetCode::FlowControlExceeded).await?;
                            continue;
                        }
                        match streams.get(&frame.stream_id) {
                            Some(sender) => match sender.try_send(frame) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(frame)) => {
                                    streams.remove(&frame.stream_id);
                                    send_reset(&control_tx, frame.stream_id, StreamResetCode::FlowControlExceeded).await?;
                                }
                                Err(mpsc::error::TrySendError::Closed(frame)) => {
                                    streams.remove(&frame.stream_id);
                                    if frame.frame_type != FrameType::ResetStream {
                                        send_reset(&control_tx, frame.stream_id, StreamResetCode::UnknownStream).await?;
                                    }
                                }
                            },
                            None => {
                                if frame.frame_type != FrameType::ResetStream {
                                    send_reset(&control_tx, frame.stream_id, StreamResetCode::UnknownStream).await?;
                                }
                            }
                        }
                    }
                    FrameType::Error => return Err(AgentTransportError::ProtocolViolation { reason: "Agent sent ERROR" }),
                    _ => return Err(AgentTransportError::ProtocolViolation { reason: "unexpected established-session frame" }),
                }
            }
            command = command_rx.recv() => {
                let Some(command) = command else { break };
                let SessionCommand::Open { ingress, response, completion } = command else {
                    draining = true;
                    if streams.is_empty() {
                        break;
                    }
                    continue;
                };
                if draining {
                    let _ = response.send(Err(RouteError::RuntimeDraining));
                    drop(completion);
                    continue;
                }
                if streams.len() >= config.max_streams_per_session {
                    let _ = response.send(Err(RouteError::CapacityExceeded(session_id)));
                    continue;
                }
                let stream_id = match StreamId::new(next_stream_id) {
                    Some(id) => id,
                    None => {
                        let _ = response.send(Err(RouteError::StreamIdExhausted(session_id)));
                        continue;
                    }
                };
                next_stream_id = next_stream_id.checked_add(1).unwrap_or_default();
                let (stream_tx, stream_rx) = mpsc::channel(config.per_stream_queue_capacity);
                streams.insert(stream_id, stream_tx);
                tokio::spawn(run_ingress_stream(
                    session_id,
                    stream_id,
                    ingress,
                    response,
                    completion,
                    config.clone(),
                    stream_rx,
                    control_tx.clone(),
                    data_tx.clone(),
                    event_tx.clone(),
                ));
            }
            event = event_rx.recv() => {
                if let Some(StreamEvent::Closed(stream_id)) = event {
                    streams.remove(&stream_id);
                    if draining && streams.is_empty() {
                        break;
                    }
                }
            }
            () = &mut heartbeat_timer => {
                if let Some(sequence) = pending_heartbeat {
                    return Err(AgentTransportError::HeartbeatTimeout { sequence });
                }
                send_control(&control_tx, FrameType::Ping, heartbeat_sequence.to_be_bytes().to_vec()).await?;
                pending_heartbeat = Some(heartbeat_sequence);
                heartbeat_sequence = heartbeat_sequence
                    .checked_next()
                    .ok_or(AgentTransportError::HeartbeatSequenceExhausted)?;
                heartbeat_timer.as_mut().reset(
                    tokio::time::Instant::now() + config.agent_listener.pong_timeout
                );
            }
            result = &mut writer_task => return writer_result(result),
        }
    }

    streams.clear();
    drop(control_tx);
    drop(data_tx);
    match writer_task.await {
        Ok(result) => result,
        Err(error) => Err(join_error(error)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_ingress_stream(
    session_id: TransportSessionId,
    stream_id: StreamId,
    mut ingress: TcpStream,
    response: oneshot::Sender<Result<StreamId, RouteError>>,
    completion: oneshot::Sender<RoutedStreamCloseReason>,
    config: MultiplexedEdgeConfig,
    mut inbound: mpsc::Receiver<Frame>,
    control_tx: mpsc::Sender<Frame>,
    data_tx: mpsc::Sender<Frame>,
    event_tx: mpsc::Sender<StreamEvent>,
) {
    if send_stream(&control_tx, FrameType::OpenStream, stream_id, Vec::new())
        .await
        .is_err()
    {
        let _ = response.send(Err(RouteError::SessionClosing(session_id)));
        let _ = completion.send(RoutedStreamCloseReason::SessionClosed);
        let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
        return;
    }

    let opened = tokio::time::timeout(config.stream_open_timeout, inbound.recv()).await;
    match opened {
        Ok(Some(frame))
            if frame.frame_type == FrameType::OpenStream && frame.payload.is_empty() =>
        {
            let _ = response.send(Ok(stream_id));
        }
        Ok(Some(frame)) if frame.frame_type == FrameType::ResetStream => {
            let code = decode_reset(&frame).unwrap_or(StreamResetCode::ProtocolViolation);
            let _ = response.send(Err(RouteError::StreamRejected(code)));
            let _ = completion.send(RoutedStreamCloseReason::PeerReset(code));
            let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
            return;
        }
        Ok(None) => {
            let _ = response.send(Err(RouteError::SessionClosing(session_id)));
            let _ = completion.send(RoutedStreamCloseReason::SessionClosed);
            let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
            return;
        }
        Ok(Some(_)) => {
            let _ = response.send(Err(RouteError::StreamRejected(
                StreamResetCode::ProtocolViolation,
            )));
            let _ = send_reset(&control_tx, stream_id, StreamResetCode::ProtocolViolation).await;
            let _ = completion.send(RoutedStreamCloseReason::ProtocolViolation);
            let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
            return;
        }
        Err(_) => {
            let _ = response.send(Err(RouteError::OpenTimeout(stream_id)));
            let _ = send_reset(&control_tx, stream_id, StreamResetCode::OpenTimeout).await;
            let _ = completion.send(RoutedStreamCloseReason::OpenTimeout);
            let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
            return;
        }
    }

    let mut buffer = vec![0_u8; MULTIPLEXED_DATA_PAYLOAD_SIZE];
    let mut ingress_ended = false;
    let mut agent_ended = false;
    let idle = tokio::time::sleep(config.stream_idle_timeout);
    tokio::pin!(idle);
    let mut close_reason = RoutedStreamCloseReason::Graceful;
    loop {
        if ingress_ended && agent_ended {
            break;
        }
        tokio::select! {
            frame = inbound.recv() => {
                let Some(frame) = frame else {
                    close_reason = RoutedStreamCloseReason::SessionClosed;
                    break;
                };
                idle.as_mut().reset(tokio::time::Instant::now() + config.stream_idle_timeout);
                match frame.frame_type {
                    FrameType::Data if !agent_ended => {
                        if ingress.write_all(&frame.payload).await.is_err() {
                            let _ = send_reset(&control_tx, stream_id, StreamResetCode::IoFailure).await;
                            close_reason = RoutedStreamCloseReason::IoFailure;
                            break;
                        }
                    }
                    FrameType::EndStream if frame.payload.is_empty() && !agent_ended => {
                        agent_ended = true;
                        if ingress.shutdown().await.is_err() {
                            let _ = send_reset(&control_tx, stream_id, StreamResetCode::IoFailure).await;
                            close_reason = RoutedStreamCloseReason::IoFailure;
                            break;
                        }
                    }
                    FrameType::ResetStream if decode_reset(&frame).is_some() => {
                        close_reason = RoutedStreamCloseReason::PeerReset(
                            decode_reset(&frame).expect("guard validated reset payload")
                        );
                        break;
                    }
                    _ => {
                        let _ = send_reset(&control_tx, stream_id, StreamResetCode::ProtocolViolation).await;
                        close_reason = RoutedStreamCloseReason::ProtocolViolation;
                        break;
                    }
                }
            }
            read = ingress.read(&mut buffer), if !ingress_ended => {
                match read {
                    Ok(0) => {
                        ingress_ended = true;
                        if send_stream(&data_tx, FrameType::EndStream, stream_id, Vec::new()).await.is_err() {
                            close_reason = RoutedStreamCloseReason::SessionClosed;
                            break;
                        }
                    }
                    Ok(count) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + config.stream_idle_timeout);
                        if send_stream(&data_tx, FrameType::Data, stream_id, buffer[..count].to_vec()).await.is_err() {
                            close_reason = RoutedStreamCloseReason::SessionClosed;
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = send_reset(&control_tx, stream_id, StreamResetCode::IoFailure).await;
                        close_reason = RoutedStreamCloseReason::IoFailure;
                        break;
                    }
                }
            }
            () = &mut idle => {
                let _ = send_reset(&control_tx, stream_id, StreamResetCode::IdleTimeout).await;
                close_reason = RoutedStreamCloseReason::IdleTimeout;
                break;
            }
        }
    }
    let _ = completion.send(close_reason);
    let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
}

async fn writer_actor(
    mut writer: tokio::io::WriteHalf<BoxedTransport>,
    mut control_rx: mpsc::Receiver<Frame>,
    mut data_rx: mpsc::Receiver<Frame>,
) -> Result<(), AgentTransportError> {
    let mut control_open = true;
    let mut data_open = true;
    while control_open || data_open {
        let frame = tokio::select! {
            biased;
            frame = control_rx.recv(), if control_open => {
                match frame { Some(frame) => Some(frame), None => { control_open = false; None } }
            }
            frame = data_rx.recv(), if data_open => {
                match frame { Some(frame) => Some(frame), None => { data_open = false; None } }
            }
        };
        if let Some(frame) = frame {
            FrameEncoder::encode(&mut writer, &frame)
                .await
                .map_err(AgentTransportError::ProtocolDecode)?;
        }
    }
    writer
        .shutdown()
        .await
        .map_err(AgentTransportError::SessionIo)
}

async fn send_control(
    sender: &mpsc::Sender<Frame>,
    frame_type: FrameType,
    payload: Vec<u8>,
) -> Result<(), AgentTransportError> {
    let frame = Frame::control(frame_type, payload).map_err(AgentTransportError::ProtocolDecode)?;
    sender.send(frame).await.map_err(|_| closed_writer())
}

async fn send_stream(
    sender: &mpsc::Sender<Frame>,
    frame_type: FrameType,
    stream_id: StreamId,
    payload: Vec<u8>,
) -> Result<(), AgentTransportError> {
    let frame = Frame::stream(stream_id, frame_type, payload)
        .map_err(AgentTransportError::ProtocolDecode)?;
    sender.send(frame).await.map_err(|_| closed_writer())
}

async fn send_reset(
    sender: &mpsc::Sender<Frame>,
    stream_id: StreamId,
    code: StreamResetCode,
) -> Result<(), AgentTransportError> {
    send_stream(
        sender,
        FrameType::ResetStream,
        stream_id,
        code.to_be_bytes().to_vec(),
    )
    .await
}

fn decode_heartbeat(frame: &Frame) -> Option<HeartbeatSequence> {
    if frame.payload.len() as u32 != HEARTBEAT_PAYLOAD_SIZE {
        return None;
    }
    HeartbeatSequence::from_be_bytes(frame.payload.as_slice().try_into().ok()?)
}

fn decode_reset(frame: &Frame) -> Option<StreamResetCode> {
    if frame.payload.len() as u32 != STREAM_RESET_PAYLOAD_SIZE {
        return None;
    }
    StreamResetCode::from_be_bytes([frame.payload[0], frame.payload[1]])
}

fn closed_writer() -> AgentTransportError {
    AgentTransportError::SessionIo(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "session writer closed",
    ))
}

fn join_error(error: tokio::task::JoinError) -> AgentTransportError {
    AgentTransportError::SessionIo(std::io::Error::other(format!(
        "writer task failed: {error}"
    )))
}

fn writer_result(
    result: Result<Result<(), AgentTransportError>, tokio::task::JoinError>,
) -> Result<(), AgentTransportError> {
    match result {
        Ok(result) => result,
        Err(error) => Err(join_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded_and_valid() {
        let config = MultiplexedEdgeConfig::dev_defaults();
        assert!(config.validate().is_ok());
        assert!(config.data_queue_capacity * MULTIPLEXED_DATA_PAYLOAD_SIZE < 4 * 1024 * 1024);
    }

    #[test]
    fn public_listener_is_rejected() {
        let mut config = MultiplexedEdgeConfig::dev_defaults();
        config.agent_listener.listen_addr = "0.0.0.0:7100".parse().unwrap();
        assert!(matches!(
            config.validate(),
            Err(MultiplexedEdgeConfigError::NonLoopbackAgentListener(_))
        ));
    }
}
