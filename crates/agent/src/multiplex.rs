//! Bounded concurrent stream dispatch for an established Agent session.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use tunnelproxy_protocol::{
    Frame, FrameDecoder, FrameEncoder, FrameType, HeartbeatErrorCode, HeartbeatSequence, StreamId,
    StreamResetCode, HEARTBEAT_PAYLOAD_SIZE, STREAM_RESET_PAYLOAD_SIZE,
};

use crate::agent_transport::{AgentError, AgentSession, AgentSessionCloseReason};

/// Maximum DATA payload emitted or accepted by the multiplexed runtime.
pub const MULTIPLEXED_DATA_PAYLOAD_SIZE: usize = 16 * 1024;

/// Agent-side limits for one multiplexed transport session.
#[derive(Debug, Clone)]
pub struct MultiplexedAgentConfig {
    /// Local service reached by every logical stream.
    pub local_addr: SocketAddr,
    /// Deadline for connecting a new logical stream to `local_addr`.
    pub connect_timeout: Duration,
    /// Maximum number of active logical streams.
    pub max_concurrent_streams: usize,
    /// Frames buffered from the session reader for each stream.
    pub per_stream_queue_capacity: usize,
    /// High-priority heartbeat and lifecycle frame capacity.
    pub control_queue_capacity: usize,
    /// Shared DATA frame capacity. This is the session-wide byte bound when
    /// multiplied by [`MULTIPLEXED_DATA_PAYLOAD_SIZE`].
    pub data_queue_capacity: usize,
    /// Maximum time a logical stream may make no data progress.
    pub stream_idle_timeout: Duration,
}

impl MultiplexedAgentConfig {
    /// Conservative defaults suitable for development and tests.
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            connect_timeout: Duration::from_secs(5),
            max_concurrent_streams: 32,
            per_stream_queue_capacity: 8,
            control_queue_capacity: 32,
            data_queue_capacity: 128,
            stream_idle_timeout: Duration::from_secs(60),
        }
    }

    /// Validates all bounds and deadlines.
    pub fn validate(&self) -> Result<(), MultiplexedAgentConfigError> {
        if self.connect_timeout.is_zero() {
            return Err(MultiplexedAgentConfigError::ZeroConnectTimeout);
        }
        if self.max_concurrent_streams == 0 {
            return Err(MultiplexedAgentConfigError::ZeroMaxStreams);
        }
        if self.per_stream_queue_capacity == 0 {
            return Err(MultiplexedAgentConfigError::ZeroPerStreamQueue);
        }
        if self.control_queue_capacity == 0 {
            return Err(MultiplexedAgentConfigError::ZeroControlQueue);
        }
        if self.data_queue_capacity == 0 {
            return Err(MultiplexedAgentConfigError::ZeroDataQueue);
        }
        if self.stream_idle_timeout.is_zero() {
            return Err(MultiplexedAgentConfigError::ZeroIdleTimeout);
        }
        Ok(())
    }
}

/// Invalid multiplexed Agent configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplexedAgentConfigError {
    ZeroConnectTimeout,
    ZeroMaxStreams,
    ZeroPerStreamQueue,
    ZeroControlQueue,
    ZeroDataQueue,
    ZeroIdleTimeout,
}

impl std::fmt::Display for MultiplexedAgentConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self {
            Self::ZeroConnectTimeout => "connect_timeout",
            Self::ZeroMaxStreams => "max_concurrent_streams",
            Self::ZeroPerStreamQueue => "per_stream_queue_capacity",
            Self::ZeroControlQueue => "control_queue_capacity",
            Self::ZeroDataQueue => "data_queue_capacity",
            Self::ZeroIdleTimeout => "stream_idle_timeout",
        };
        write!(f, "{field} must be greater than zero")
    }
}

impl std::error::Error for MultiplexedAgentConfigError {}

enum StreamEvent {
    Closed(StreamId),
}

impl AgentSession {
    /// Consumes the established session and concurrently bridges bounded
    /// logical streams to the configured local TCP service.
    pub async fn run_multiplexed(
        self,
        config: MultiplexedAgentConfig,
    ) -> Result<AgentSessionCloseReason, AgentError> {
        config
            .validate()
            .map_err(|error| AgentError::ProtocolViolation {
                reason: match error {
                    MultiplexedAgentConfigError::ZeroConnectTimeout => "zero connect timeout",
                    MultiplexedAgentConfigError::ZeroMaxStreams => "zero max streams",
                    MultiplexedAgentConfigError::ZeroPerStreamQueue => "zero per-stream queue",
                    MultiplexedAgentConfigError::ZeroControlQueue => "zero control queue",
                    MultiplexedAgentConfigError::ZeroDataQueue => "zero data queue",
                    MultiplexedAgentConfigError::ZeroIdleTimeout => "zero idle timeout",
                },
            })?;

        let (mut reader, writer) = self.socket.into_split();
        let (control_tx, control_rx) = mpsc::channel(config.control_queue_capacity);
        let (data_tx, data_rx) = mpsc::channel(config.data_queue_capacity);
        let mut writer_task = tokio::spawn(writer_actor(writer, control_rx, data_rx));
        let (event_tx, mut event_rx) = mpsc::channel(config.max_concurrent_streams);
        let mut streams: HashMap<StreamId, mpsc::Sender<Frame>> = HashMap::new();
        let mut decoder = FrameDecoder::new();

        loop {
            tokio::select! {
                decoded = decoder.decode(&mut reader) => {
                    let frame = match decoded.map_err(AgentError::ProtocolDecode)? {
                        Some(frame) => frame,
                        None => break,
                    };
                    match frame.frame_type {
                        FrameType::Ping => {
                            let sequence = decode_heartbeat(&frame).ok_or(
                                AgentError::InvalidHeartbeatPayload { frame_type: FrameType::Ping }
                            )?;
                            send_control(&control_tx, FrameType::Pong, sequence.to_be_bytes().to_vec()).await?;
                        }
                        FrameType::OpenStream => {
                            if !frame.payload.is_empty() || streams.contains_key(&frame.stream_id) {
                                send_reset(&control_tx, frame.stream_id, StreamResetCode::ProtocolViolation).await?;
                                continue;
                            }
                            if streams.len() >= config.max_concurrent_streams {
                                send_reset(&control_tx, frame.stream_id, StreamResetCode::CapacityExceeded).await?;
                                continue;
                            }
                            let (stream_tx, stream_rx) = mpsc::channel(config.per_stream_queue_capacity);
                            streams.insert(frame.stream_id, stream_tx);
                            tokio::spawn(run_local_stream(
                                frame.stream_id,
                                config.clone(),
                                stream_rx,
                                control_tx.clone(),
                                data_tx.clone(),
                                event_tx.clone(),
                            ));
                        }
                        FrameType::Data | FrameType::EndStream | FrameType::ResetStream => {
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
                        FrameType::Error => {
                            return Err(decode_heartbeat_error(&frame));
                        }
                        frame_type => {
                            return Err(AgentError::UnexpectedFrame { frame_type });
                        }
                    }
                }
                event = event_rx.recv() => {
                    if let Some(StreamEvent::Closed(stream_id)) = event {
                        streams.remove(&stream_id);
                    }
                }
                result = &mut writer_task => {
                    return writer_result(result);
                }
            }
        }

        streams.clear();
        drop(control_tx);
        drop(data_tx);
        match writer_task.await {
            Ok(Ok(())) => Ok(AgentSessionCloseReason::PeerClosed),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(join_error(error)),
        }
    }
}

async fn run_local_stream(
    stream_id: StreamId,
    config: MultiplexedAgentConfig,
    mut inbound: mpsc::Receiver<Frame>,
    control_tx: mpsc::Sender<Frame>,
    data_tx: mpsc::Sender<Frame>,
    event_tx: mpsc::Sender<StreamEvent>,
) {
    let connect = tokio::time::timeout(
        config.connect_timeout,
        TcpStream::connect(config.local_addr),
    );
    tokio::pin!(connect);
    let connected = tokio::select! {
        result = &mut connect => result,
        frame = inbound.recv() => {
            if let Some(frame) = frame {
                if frame.frame_type != FrameType::ResetStream || decode_reset(&frame).is_none() {
                    let _ = send_reset(&control_tx, stream_id, StreamResetCode::ProtocolViolation).await;
                }
            }
            let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
            return;
        }
    };
    let mut local = match connected {
        Ok(Ok(socket)) => socket,
        Ok(Err(_)) => {
            let _ = send_reset(&control_tx, stream_id, StreamResetCode::LocalConnectFailed).await;
            let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
            return;
        }
        Err(_) => {
            let _ = send_reset(&control_tx, stream_id, StreamResetCode::LocalConnectTimeout).await;
            let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
            return;
        }
    };

    if send_stream(&control_tx, FrameType::OpenStream, stream_id, Vec::new())
        .await
        .is_err()
    {
        let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
        return;
    }

    let mut buffer = vec![0_u8; MULTIPLEXED_DATA_PAYLOAD_SIZE];
    let mut local_ended = false;
    let mut peer_ended = false;
    let idle = tokio::time::sleep(config.stream_idle_timeout);
    tokio::pin!(idle);

    loop {
        if local_ended && peer_ended {
            break;
        }
        tokio::select! {
            frame = inbound.recv() => {
                let Some(frame) = frame else { break };
                idle.as_mut().reset(tokio::time::Instant::now() + config.stream_idle_timeout);
                match frame.frame_type {
                    FrameType::Data if !peer_ended => {
                        if local.write_all(&frame.payload).await.is_err() {
                            let _ = send_reset(&control_tx, stream_id, StreamResetCode::IoFailure).await;
                            break;
                        }
                    }
                    FrameType::EndStream if frame.payload.is_empty() && !peer_ended => {
                        peer_ended = true;
                        if local.shutdown().await.is_err() {
                            let _ = send_reset(&control_tx, stream_id, StreamResetCode::IoFailure).await;
                            break;
                        }
                    }
                    FrameType::ResetStream if decode_reset(&frame).is_some() => break,
                    _ => {
                        let _ = send_reset(&control_tx, stream_id, StreamResetCode::ProtocolViolation).await;
                        break;
                    }
                }
            }
            read = local.read(&mut buffer), if !local_ended => {
                match read {
                    Ok(0) => {
                        local_ended = true;
                        if send_stream(&data_tx, FrameType::EndStream, stream_id, Vec::new()).await.is_err() {
                            break;
                        }
                    }
                    Ok(count) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + config.stream_idle_timeout);
                        if send_stream(&data_tx, FrameType::Data, stream_id, buffer[..count].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = send_reset(&control_tx, stream_id, StreamResetCode::IoFailure).await;
                        break;
                    }
                }
            }
            () = &mut idle => {
                let _ = send_reset(&control_tx, stream_id, StreamResetCode::IdleTimeout).await;
                break;
            }
        }
    }

    let _ = event_tx.send(StreamEvent::Closed(stream_id)).await;
}

async fn writer_actor(
    mut writer: OwnedWriteHalf,
    mut control_rx: mpsc::Receiver<Frame>,
    mut data_rx: mpsc::Receiver<Frame>,
) -> Result<(), AgentError> {
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
                .map_err(AgentError::ProtocolDecode)?;
        }
    }
    writer.shutdown().await.map_err(AgentError::SessionIo)
}

async fn send_control(
    sender: &mpsc::Sender<Frame>,
    frame_type: FrameType,
    payload: Vec<u8>,
) -> Result<(), AgentError> {
    let frame = Frame::control(frame_type, payload).map_err(AgentError::ProtocolDecode)?;
    sender
        .send(frame)
        .await
        .map_err(|_| AgentError::ConnectionClosed)
}

async fn send_stream(
    sender: &mpsc::Sender<Frame>,
    frame_type: FrameType,
    stream_id: StreamId,
    payload: Vec<u8>,
) -> Result<(), AgentError> {
    let frame =
        Frame::stream(stream_id, frame_type, payload).map_err(AgentError::ProtocolDecode)?;
    sender
        .send(frame)
        .await
        .map_err(|_| AgentError::ConnectionClosed)
}

async fn send_reset(
    sender: &mpsc::Sender<Frame>,
    stream_id: StreamId,
    code: StreamResetCode,
) -> Result<(), AgentError> {
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
    let bytes: [u8; 8] = frame.payload.as_slice().try_into().ok()?;
    HeartbeatSequence::from_be_bytes(bytes)
}

fn decode_reset(frame: &Frame) -> Option<StreamResetCode> {
    if frame.payload.len() as u32 != STREAM_RESET_PAYLOAD_SIZE {
        return None;
    }
    StreamResetCode::from_be_bytes([frame.payload[0], frame.payload[1]])
}

fn decode_heartbeat_error(frame: &Frame) -> AgentError {
    let code = if frame.payload.len() == 2 {
        HeartbeatErrorCode::from_be_bytes([frame.payload[0], frame.payload[1]])
    } else {
        None
    };
    AgentError::HeartbeatRejected { code }
}

fn writer_result(
    result: Result<Result<(), AgentError>, tokio::task::JoinError>,
) -> Result<AgentSessionCloseReason, AgentError> {
    match result {
        Ok(Ok(())) => Ok(AgentSessionCloseReason::LocalShutdown),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(join_error(error)),
    }
}

fn join_error(error: tokio::task::JoinError) -> AgentError {
    AgentError::SessionIo(std::io::Error::other(format!(
        "writer task failed: {error}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded_and_valid() {
        let config = MultiplexedAgentConfig::new("127.0.0.1:3000".parse().unwrap());
        assert!(config.validate().is_ok());
        assert!(config.max_concurrent_streams > 1);
        assert!(config.data_queue_capacity * MULTIPLEXED_DATA_PAYLOAD_SIZE < 4 * 1024 * 1024);
    }

    #[test]
    fn zero_bounds_are_rejected() {
        let mut config = MultiplexedAgentConfig::new("127.0.0.1:3000".parse().unwrap());
        config.per_stream_queue_capacity = 0;
        assert_eq!(
            config.validate(),
            Err(MultiplexedAgentConfigError::ZeroPerStreamQueue)
        );
    }
}
