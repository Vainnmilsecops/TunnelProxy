//! Session 08 real-TCP integration coverage for the single-stream reverse path.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use tunnelproxy_agent::{connect, ConnectOutcome};
use tunnelproxy_edge::agent_transport::{SingleStreamEdgeConfig, SingleStreamEdgeRuntime};
use tunnelproxy_protocol::{
    Frame, FrameDecoder, FrameEncoder, FrameType, StreamId, StreamResetCode, TransportSessionId,
    ROLE_AGENT,
};

struct Harness {
    ingress_addr: SocketAddr,
    edge:
        tokio::task::JoinHandle<Result<(), tunnelproxy_edge::agent_transport::AgentTransportError>>,
    agent: tokio::task::JoinHandle<
        Result<tunnelproxy_agent::AgentSessionCloseReason, tunnelproxy_agent::AgentError>,
    >,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.edge.abort();
        self.agent.abort();
    }
}

fn fast_config() -> SingleStreamEdgeConfig {
    let mut config = SingleStreamEdgeConfig::dev_defaults();
    config.agent_listener.handshake_timeout = Duration::from_secs(1);
    config.agent_listener.heartbeat_interval = Duration::from_millis(40);
    config.agent_listener.pong_timeout = Duration::from_millis(100);
    config.stream_open_timeout = Duration::from_secs(1);
    config
}

async fn spawn_harness(local_addr: SocketAddr) -> Harness {
    spawn_harness_with_config(local_addr, fast_config()).await
}

async fn spawn_harness_with_config(
    local_addr: SocketAddr,
    config: SingleStreamEdgeConfig,
) -> Harness {
    let runtime = SingleStreamEdgeRuntime::bind(config).await.unwrap();
    let agent_addr = runtime.agent_addr();
    let ingress_addr = runtime.ingress_addr();
    let edge = tokio::spawn(runtime.run());

    let outcome = connect(agent_addr, Duration::from_secs(1), Duration::from_secs(1)).await;
    let mut session = match outcome {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("Agent handshake failed: {reason}"),
    };
    let agent = tokio::spawn(async move {
        session
            .run_with_local_target(local_addr, Duration::from_millis(500))
            .await
    });

    Harness {
        ingress_addr,
        edge,
        agent,
    }
}

async fn spawn_echo_service(connection_count: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut handlers = Vec::with_capacity(connection_count);
        for _ in 0..connection_count {
            let (mut socket, _) = listener.accept().await.unwrap();
            handlers.push(tokio::spawn(async move {
                let mut buffer = [0_u8; 8192];
                loop {
                    let read = socket.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        socket.shutdown().await.unwrap();
                        break;
                    }
                    socket.write_all(&buffer[..read]).await.unwrap();
                }
            }));
        }
        for handler in handlers {
            handler.await.unwrap();
        }
    });
    (addr, task)
}

async fn round_trip_and_close(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let socket = TcpStream::connect(addr).await.unwrap();
    let (mut reader, mut writer) = socket.into_split();
    let outbound = payload.to_vec();
    let write = tokio::spawn(async move {
        writer.write_all(&outbound).await.unwrap();
        writer.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    timeout(Duration::from_secs(3), reader.read_to_end(&mut received))
        .await
        .expect("reverse stream timed out")
        .unwrap();
    write.await.unwrap();
    received
}

#[tokio::test]
async fn single_stream_golden_path_is_byte_exact() {
    let (local_addr, local) = spawn_echo_service(1).await;
    let harness = spawn_harness(local_addr).await;
    let payload = b"session-08\0binary\xffpayload";

    let received = round_trip_and_close(harness.ingress_addr, payload).await;
    assert_eq!(received, payload);
    timeout(Duration::from_secs(1), local)
        .await
        .unwrap()
        .unwrap();
    assert!(!harness.edge.is_finished());
    assert!(!harness.agent.is_finished());
}

#[tokio::test]
async fn large_payload_is_split_across_bounded_data_frames() {
    let (local_addr, local) = spawn_echo_service(1).await;
    let harness = spawn_harness(local_addr).await;
    let payload: Vec<u8> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();

    let received = round_trip_and_close(harness.ingress_addr, &payload).await;
    assert_eq!(received, payload);
    timeout(Duration::from_secs(2), local)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn client_half_close_still_allows_local_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let local = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request-after-half-close");
        socket
            .write_all(b"response-after-half-close")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });
    let harness = spawn_harness(local_addr).await;

    let mut client = TcpStream::connect(harness.ingress_addr).await.unwrap();
    client.write_all(b"request-after-half-close").await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"response-after-half-close");
    local.await.unwrap();
}

#[tokio::test]
async fn established_agent_supports_sequential_streams() {
    let (local_addr, local) = spawn_echo_service(2).await;
    let harness = spawn_harness(local_addr).await;

    assert_eq!(
        round_trip_and_close(harness.ingress_addr, b"first").await,
        b"first"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        round_trip_and_close(harness.ingress_addr, b"second").await,
        b"second"
    );
    timeout(Duration::from_secs(2), local)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn local_connect_failure_resets_only_the_stream() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = unused.local_addr().unwrap();
    drop(unused);
    let harness = spawn_harness(local_addr).await;

    for _ in 0..2 {
        let mut client = TcpStream::connect(harness.ingress_addr).await.unwrap();
        let mut byte = [0_u8; 1];
        let result = timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("reset stream did not close ingress");
        assert!(matches!(result, Ok(0) | Err(_)));
    }
    assert!(!harness.edge.is_finished());
    assert!(!harness.agent.is_finished());
}

#[tokio::test]
async fn second_concurrent_ingress_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let local = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        accepted_tx.send(()).unwrap();
        release_rx.await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let harness = spawn_harness(local_addr).await;

    let first = TcpStream::connect(harness.ingress_addr).await.unwrap();
    timeout(Duration::from_secs(1), accepted_rx)
        .await
        .unwrap()
        .unwrap();
    let mut second = TcpStream::connect(harness.ingress_addr).await.unwrap();
    let mut byte = [0_u8; 1];
    let result = timeout(Duration::from_secs(1), second.read(&mut byte))
        .await
        .expect("busy ingress was not rejected");
    assert!(matches!(result, Ok(0) | Err(_)));

    drop(first);
    release_tx.send(()).unwrap();
    local.await.unwrap();
}

#[tokio::test]
async fn heartbeat_remains_live_during_active_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let local = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4];
        socket.read_exact(&mut request).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        socket.write_all(&request).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let harness = spawn_harness(local_addr).await;

    let mut client = TcpStream::connect(harness.ingress_addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut response = [0_u8; 4];
    timeout(Duration::from_secs(2), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"ping");
    assert!(!harness.edge.is_finished());
    assert!(!harness.agent.is_finished());
    drop(client);
    local.await.unwrap();
}

#[tokio::test]
async fn idle_stream_timeout_resets_only_the_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let local = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut byte = [0_u8; 1];
        let result = timeout(Duration::from_secs(1), socket.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    });
    let mut config = fast_config();
    config.stream_idle_timeout = Duration::from_millis(150);
    let harness = spawn_harness_with_config(local_addr, config).await;

    let mut client = TcpStream::connect(harness.ingress_addr).await.unwrap();
    let mut byte = [0_u8; 1];
    let result = timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("idle stream was not reset");
    assert!(matches!(result, Ok(0) | Err(_)));
    timeout(Duration::from_secs(1), local)
        .await
        .unwrap()
        .unwrap();
    assert!(!harness.edge.is_finished());
    assert!(!harness.agent.is_finished());
}

#[tokio::test]
async fn data_before_open_is_reset_without_killing_agent_session() {
    let runtime = SingleStreamEdgeRuntime::bind({
        let mut config = fast_config();
        config.agent_listener.heartbeat_interval = Duration::from_secs(5);
        config
    })
    .await
    .unwrap();
    let agent_addr = runtime.agent_addr();
    let edge = tokio::spawn(runtime.run());

    let mut socket = TcpStream::connect(agent_addr).await.unwrap();
    let hello = Frame::control(FrameType::Hello, vec![ROLE_AGENT]).unwrap();
    FrameEncoder::encode(&mut socket, &hello).await.unwrap();
    let register = Frame::control(FrameType::Register, Vec::new()).unwrap();
    FrameEncoder::encode(&mut socket, &register).await.unwrap();
    let mut decoder = FrameDecoder::new();
    let registered = decoder.decode(&mut socket).await.unwrap().unwrap();
    let mut registered_bytes = [0_u8; 8];
    registered_bytes.copy_from_slice(&registered.payload);
    assert!(TransportSessionId::from_be_bytes(registered_bytes).is_some());

    let stream_id = StreamId::new(1).unwrap();
    let data = Frame::stream(stream_id, FrameType::Data, b"too-early".to_vec()).unwrap();
    FrameEncoder::encode(&mut socket, &data).await.unwrap();
    let reset = timeout(Duration::from_secs(1), decoder.decode(&mut socket))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(reset.frame_type, FrameType::ResetStream);
    assert_eq!(reset.stream_id, stream_id);
    assert_eq!(
        StreamResetCode::from_be_bytes([reset.payload[0], reset.payload[1]]),
        Some(StreamResetCode::ProtocolViolation)
    );
    assert!(!edge.is_finished());
    edge.abort();
}

#[tokio::test]
async fn sequential_stream_ids_are_monotonic() {
    let runtime = SingleStreamEdgeRuntime::bind({
        let mut config = fast_config();
        config.agent_listener.heartbeat_interval = Duration::from_secs(5);
        config
    })
    .await
    .unwrap();
    let agent_addr = runtime.agent_addr();
    let ingress_addr = runtime.ingress_addr();
    let edge = tokio::spawn(runtime.run());

    let mut agent = TcpStream::connect(agent_addr).await.unwrap();
    FrameEncoder::encode(
        &mut agent,
        &Frame::control(FrameType::Hello, vec![ROLE_AGENT]).unwrap(),
    )
    .await
    .unwrap();
    FrameEncoder::encode(
        &mut agent,
        &Frame::control(FrameType::Register, Vec::new()).unwrap(),
    )
    .await
    .unwrap();
    let mut decoder = FrameDecoder::new();
    assert_eq!(
        decoder
            .decode(&mut agent)
            .await
            .unwrap()
            .unwrap()
            .frame_type,
        FrameType::Registered
    );

    for expected in 1..=2 {
        let ingress = TcpStream::connect(ingress_addr).await.unwrap();
        let open = timeout(Duration::from_secs(1), decoder.decode(&mut agent))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(open.frame_type, FrameType::OpenStream);
        assert_eq!(open.stream_id.get(), expected);
        FrameEncoder::encode(
            &mut agent,
            &Frame::stream(open.stream_id, FrameType::OpenStream, Vec::new()).unwrap(),
        )
        .await
        .unwrap();

        drop(ingress);
        let end = timeout(Duration::from_secs(1), decoder.decode(&mut agent))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(end.frame_type, FrameType::EndStream);
        assert_eq!(end.stream_id, open.stream_id);
        FrameEncoder::encode(
            &mut agent,
            &Frame::stream(open.stream_id, FrameType::EndStream, Vec::new()).unwrap(),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(!edge.is_finished());
    edge.abort();
}
