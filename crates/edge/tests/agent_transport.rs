//! Integration tests for the Agent ↔ Edge transport handshake and heartbeat.
//!
//! All tests use real loopback TCP (`127.0.0.1:0` ephemeral ports) and
//! deterministic protocol interactions.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use tunnelproxy_agent::{connect, development_registration, AgentError, ConnectOutcome};
use tunnelproxy_edge::agent_transport::{
    AgentListenerConfig, AgentTransportListener, TransportSessionIdAllocator,
};
use tunnelproxy_protocol::{
    Frame, FrameDecoder, FrameEncoder, FrameType, HeartbeatErrorCode, HeartbeatSequence,
    TransportSessionId, HEARTBEAT_PAYLOAD_SIZE, ROLE_AGENT,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawns an AgentTransportListener bound to an ephemeral port.
async fn spawn_listener(config: AgentListenerConfig) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut listener = AgentTransportListener::bind(config).await.unwrap();
    let addr = listener.local_addr();
    let handle = tokio::spawn(async move {
        let _ = listener.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

/// Spawns an AgentTransportListener with dev_defaults.
async fn spawn_default_listener() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_listener(AgentListenerConfig::dev_defaults()).await
}

fn heartbeat_config(max_agent_sessions: usize) -> AgentListenerConfig {
    AgentListenerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        max_agent_sessions,
        handshake_timeout: Duration::from_secs(1),
        heartbeat_interval: Duration::from_millis(40),
        pong_timeout: Duration::from_millis(60),
    }
}

async fn raw_handshake(addr: SocketAddr) -> (TcpStream, TransportSessionId) {
    let mut socket = TcpStream::connect(addr).await.unwrap();
    let hello = Frame::control(FrameType::Hello, vec![ROLE_AGENT]).unwrap();
    FrameEncoder::encode(&mut socket, &hello).await.unwrap();
    let register =
        Frame::control(FrameType::Register, development_registration().encode()).unwrap();
    FrameEncoder::encode(&mut socket, &register).await.unwrap();

    let mut decoder = FrameDecoder::new();
    let registered = timeout(Duration::from_secs(1), decoder.decode(&mut socket))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(registered.frame_type, FrameType::Registered);
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&registered.payload);
    let session_id = TransportSessionId::from_be_bytes(bytes).unwrap();
    (socket, session_id)
}

async fn read_frame(socket: &mut TcpStream) -> Frame {
    let mut decoder = FrameDecoder::new();
    timeout(Duration::from_secs(1), decoder.decode(socket))
        .await
        .expect("frame read timed out")
        .expect("frame decode failed")
        .expect("peer closed before sending frame")
}

fn heartbeat_sequence(frame: &Frame) -> HeartbeatSequence {
    assert_eq!(frame.payload.len(), HEARTBEAT_PAYLOAD_SIZE as usize);
    let mut bytes = [0_u8; HEARTBEAT_PAYLOAD_SIZE as usize];
    bytes.copy_from_slice(&frame.payload);
    HeartbeatSequence::from_be_bytes(bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Test 1 — Valid handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_handshake_establishes_session() {
    let (addr, handle) = spawn_default_listener().await;

    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();

    match outcome {
        tunnelproxy_agent::ConnectOutcome::Established(session) => {
            assert!(!session.session_id.is_invalid());
        }
        tunnelproxy_agent::ConnectOutcome::Failed { reason } => {
            panic!("expected established session, got failure: {reason}");
        }
    }

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 2 — Invalid first frame: REGISTER before HELLO
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_first_frame_register_before_hello() {
    let (addr, handle) = spawn_default_listener().await;

    // Send REGISTER first — Edge should reject.
    let mut socket = TcpStream::connect(addr).await.unwrap();
    let register = Frame::control(FrameType::Register, vec![]).unwrap();
    FrameEncoder::encode(&mut socket, &register).await.unwrap();
    drop(socket);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Listener survived — valid handshake must work.
    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 3 — Invalid second frame: DATA instead of REGISTER
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_second_frame_data_instead_of_register() {
    let (addr, handle) = spawn_default_listener().await;

    // Custom client: HELLO + DATA (wrong frame type).
    let mut socket = TcpStream::connect(addr).await.unwrap();
    let hello = Frame::control(FrameType::Hello, vec![ROLE_AGENT]).unwrap();
    FrameEncoder::encode(&mut socket, &hello).await.unwrap();
    let data = Frame::stream(
        tunnelproxy_protocol::StreamId::new(1).unwrap(),
        FrameType::Data,
        vec![1, 2, 3],
    )
    .unwrap();
    FrameEncoder::encode(&mut socket, &data).await.unwrap();
    drop(socket);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 4 — Invalid HELLO payload: empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_hello_empty_payload() {
    let (addr, handle) = spawn_default_listener().await;

    let mut socket = TcpStream::connect(addr).await.unwrap();
    // Empty payload (wrong size).
    let hello = Frame::control(FrameType::Hello, vec![]).unwrap();
    FrameEncoder::encode(&mut socket, &hello).await.unwrap();
    let register = Frame::control(FrameType::Register, vec![]).unwrap();
    FrameEncoder::encode(&mut socket, &register).await.unwrap();
    drop(socket);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 4b — Invalid HELLO payload: unknown role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_hello_unknown_role() {
    let (addr, handle) = spawn_default_listener().await;

    let mut socket = TcpStream::connect(addr).await.unwrap();
    // Role 0x99 is not defined.
    let hello = Frame::control(FrameType::Hello, vec![0x99]).unwrap();
    FrameEncoder::encode(&mut socket, &hello).await.unwrap();
    let register = Frame::control(FrameType::Register, vec![]).unwrap();
    FrameEncoder::encode(&mut socket, &register).await.unwrap();
    drop(socket);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 5 — Invalid REGISTER payload: non-empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_register_non_empty_payload() {
    let (addr, handle) = spawn_default_listener().await;

    let mut socket = TcpStream::connect(addr).await.unwrap();
    let hello = Frame::control(FrameType::Hello, vec![ROLE_AGENT]).unwrap();
    FrameEncoder::encode(&mut socket, &hello).await.unwrap();
    // Non-empty REGISTER payload.
    let register = Frame::control(FrameType::Register, vec![1, 2, 3]).unwrap();
    FrameEncoder::encode(&mut socket, &register).await.unwrap();
    drop(socket);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 6 — Handshake timeout: no HELLO
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_timeout_no_hello() {
    let config = AgentListenerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        max_agent_sessions: 10,
        handshake_timeout: Duration::from_millis(200),
        ..AgentListenerConfig::dev_defaults()
    };
    let (addr, handle) = spawn_listener(config).await;

    // Connect but send nothing.
    let _socket = TcpStream::connect(addr).await.unwrap();

    // Wait for timeout + margin.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Listener survived — new connection works.
    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 7 — Timeout releases capacity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn timeout_releases_capacity() {
    let config = AgentListenerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        max_agent_sessions: 1,
        handshake_timeout: Duration::from_millis(300),
        ..AgentListenerConfig::dev_defaults()
    };
    let (addr, handle) = spawn_listener(config).await;

    // Client A: connects but never sends HELLO.
    let _socket_a = TcpStream::connect(addr).await.unwrap();

    // Wait for timeout.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Client B: valid handshake must succeed.
    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 8 — Peer disconnect cleans up session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn peer_disconnect_cleans_up_session() {
    let config = AgentListenerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        max_agent_sessions: 1,
        handshake_timeout: Duration::from_secs(5),
        ..AgentListenerConfig::dev_defaults()
    };
    let (addr, handle) = spawn_listener(config).await;

    // First agent establishes session.
    let outcome1 = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    let _session = match outcome1 {
        tunnelproxy_agent::ConnectOutcome::Established(s) => s,
        tunnelproxy_agent::ConnectOutcome::Failed { reason } => {
            panic!("first agent failed: {reason}")
        }
    };

    // Drop the session (closes socket).
    drop(_session);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second agent must succeed (permit was released).
    let outcome2 = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome2,
        tunnelproxy_agent::ConnectOutcome::Established(_)
    ));

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 9 — Session ID uniqueness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_id_uniqueness() {
    let (addr, handle) = spawn_default_listener().await;

    let outcome1 = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    let session1 = match outcome1 {
        tunnelproxy_agent::ConnectOutcome::Established(s) => s,
        tunnelproxy_agent::ConnectOutcome::Failed { reason } => {
            panic!("first agent failed: {reason}")
        }
    };

    let id1 = session1.session_id;
    drop(session1);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let outcome2 = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();
    let session2 = match outcome2 {
        tunnelproxy_agent::ConnectOutcome::Established(s) => s,
        tunnelproxy_agent::ConnectOutcome::Failed { reason } => {
            panic!("second agent failed: {reason}")
        }
    };

    let id2 = session2.session_id;
    assert!(!id1.is_invalid());
    assert!(!id2.is_invalid());
    assert_ne!(id1, id2, "session IDs must be unique");

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test 10 — TransportSessionIdAllocator regression
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transport_session_id_allocator_regression() {
    let alloc = TransportSessionIdAllocator::new();
    let id1 = alloc.next_id().expect("first ID must not be zero");
    let id2 = alloc.next_id().expect("second ID must not be zero");
    assert!(id1 < id2);
}

// ---------------------------------------------------------------------------
// Test 11 — Session remains open after handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_remains_open_after_handshake() {
    let (addr, handle) = spawn_default_listener().await;

    let outcome = timeout(
        Duration::from_secs(5),
        connect(addr, Duration::from_secs(5), Duration::from_secs(5)),
    )
    .await
    .unwrap();

    let mut session = match outcome {
        tunnelproxy_agent::ConnectOutcome::Established(s) => s,
        tunnelproxy_agent::ConnectOutcome::Failed { reason } => {
            panic!("expected established session, got: {reason}")
        }
    };

    // Session is open — try to read with a short timeout.
    // In Session 06, no frames are expected, so the read should timeout (not return EOF immediately).
    let read_result = tokio::time::timeout(Duration::from_millis(100), session.read_frame()).await;
    // Timeout means no data/EOF arrived immediately — session is still alive.
    assert!(
        read_result.is_err(),
        "read should timeout; immediate EOF means connection was closed"
    );

    drop(session);
    handle.abort();
}

// ---------------------------------------------------------------------------
// Session 07 heartbeat and liveness coverage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heartbeat_ping_pong_keeps_session_alive() {
    let (addr, listener) = spawn_listener(heartbeat_config(2)).await;
    let outcome = connect(addr, Duration::from_secs(1), Duration::from_secs(1)).await;
    let mut session = match outcome {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("handshake failed: {reason}"),
    };

    let agent = tokio::spawn(async move { session.run().await });
    tokio::time::sleep(Duration::from_millis(240)).await;
    assert!(
        !agent.is_finished(),
        "matching PONG responses should keep the session alive"
    );

    agent.abort();
    listener.abort();
}

#[tokio::test]
async fn heartbeat_timeout_releases_capacity() {
    let (addr, listener) = spawn_listener(heartbeat_config(1)).await;
    let silent = connect(addr, Duration::from_secs(1), Duration::from_secs(1)).await;
    let silent_session = match silent {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("first handshake failed: {reason}"),
    };

    // The Agent deliberately does not run its heartbeat loop.
    // Allow ample scheduling margin beyond the 40 ms interval + 60 ms timeout.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let replacement = connect(addr, Duration::from_secs(1), Duration::from_secs(1)).await;
    assert!(
        matches!(replacement, ConnectOutcome::Established(_)),
        "heartbeat timeout must release the only capacity permit"
    );

    drop(silent_session);
    listener.abort();
}

#[tokio::test]
async fn edge_heartbeat_sequence_is_monotonic() {
    let (addr, listener) = spawn_listener(heartbeat_config(1)).await;
    let (mut socket, _) = raw_handshake(addr).await;

    for expected in 1_u64..=3 {
        let ping = read_frame(&mut socket).await;
        assert_eq!(ping.frame_type, FrameType::Ping);
        let sequence = heartbeat_sequence(&ping);
        assert_eq!(sequence.get(), expected);
        let pong = Frame::control(FrameType::Pong, sequence.to_be_bytes().to_vec()).unwrap();
        FrameEncoder::encode(&mut socket, &pong).await.unwrap();
    }

    drop(socket);
    listener.abort();
}

#[tokio::test]
async fn mismatched_pong_closes_session_with_error() {
    let (addr, listener) = spawn_listener(heartbeat_config(1)).await;
    let (mut socket, _) = raw_handshake(addr).await;

    let ping = read_frame(&mut socket).await;
    let expected = heartbeat_sequence(&ping);
    let wrong = expected.checked_next().unwrap();
    let pong = Frame::control(FrameType::Pong, wrong.to_be_bytes().to_vec()).unwrap();
    FrameEncoder::encode(&mut socket, &pong).await.unwrap();

    let error = read_frame(&mut socket).await;
    assert_eq!(error.frame_type, FrameType::Error);
    assert_eq!(
        HeartbeatErrorCode::from_be_bytes([error.payload[0], error.payload[1]]),
        Some(HeartbeatErrorCode::HeartbeatSequenceMismatch)
    );

    listener.abort();
}

#[tokio::test]
async fn malformed_pong_payload_is_rejected() {
    let (addr, listener) = spawn_listener(heartbeat_config(1)).await;
    let (mut socket, _) = raw_handshake(addr).await;

    let ping = read_frame(&mut socket).await;
    assert_eq!(ping.frame_type, FrameType::Ping);
    let pong = Frame::control(FrameType::Pong, vec![1, 2, 3]).unwrap();
    FrameEncoder::encode(&mut socket, &pong).await.unwrap();

    let error = read_frame(&mut socket).await;
    assert_eq!(
        HeartbeatErrorCode::from_be_bytes([error.payload[0], error.payload[1]]),
        Some(HeartbeatErrorCode::InvalidHeartbeatPayload)
    );

    listener.abort();
}

#[tokio::test]
async fn unsolicited_pong_is_rejected() {
    let mut config = heartbeat_config(1);
    config.heartbeat_interval = Duration::from_secs(1);
    let (addr, listener) = spawn_listener(config).await;
    let (mut socket, _) = raw_handshake(addr).await;

    let pong = Frame::control(
        FrameType::Pong,
        HeartbeatSequence::FIRST.to_be_bytes().to_vec(),
    )
    .unwrap();
    FrameEncoder::encode(&mut socket, &pong).await.unwrap();

    let error = read_frame(&mut socket).await;
    assert_eq!(
        HeartbeatErrorCode::from_be_bytes([error.payload[0], error.payload[1]]),
        Some(HeartbeatErrorCode::UnsolicitedPong)
    );

    listener.abort();
}

#[tokio::test]
async fn agent_ping_is_rejected_for_edge_initiated_heartbeat() {
    let mut config = heartbeat_config(1);
    config.heartbeat_interval = Duration::from_secs(1);
    let (addr, listener) = spawn_listener(config).await;
    let (mut socket, _) = raw_handshake(addr).await;

    let ping = Frame::control(
        FrameType::Ping,
        HeartbeatSequence::FIRST.to_be_bytes().to_vec(),
    )
    .unwrap();
    FrameEncoder::encode(&mut socket, &ping).await.unwrap();

    let error = read_frame(&mut socket).await;
    assert_eq!(
        HeartbeatErrorCode::from_be_bytes([error.payload[0], error.payload[1]]),
        Some(HeartbeatErrorCode::AgentPingNotSupported)
    );

    listener.abort();
}

#[tokio::test]
async fn agent_rejects_malformed_edge_ping() {
    let edge = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = edge.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = edge.accept().await.unwrap();
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decoder
                .decode(&mut socket)
                .await
                .unwrap()
                .unwrap()
                .frame_type,
            FrameType::Hello
        );
        assert_eq!(
            decoder
                .decode(&mut socket)
                .await
                .unwrap()
                .unwrap()
                .frame_type,
            FrameType::Register
        );
        let registered = Frame::control(
            FrameType::Registered,
            TransportSessionId::new(1).unwrap().to_be_bytes().to_vec(),
        )
        .unwrap();
        FrameEncoder::encode(&mut socket, &registered)
            .await
            .unwrap();
        let malformed_ping = Frame::control(FrameType::Ping, vec![1, 2, 3]).unwrap();
        FrameEncoder::encode(&mut socket, &malformed_ping)
            .await
            .unwrap();
    });

    let outcome = connect(addr, Duration::from_secs(1), Duration::from_secs(1)).await;
    let mut session = match outcome {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("handshake failed: {reason}"),
    };
    let result = session.run().await;
    assert!(matches!(
        result,
        Err(AgentError::InvalidHeartbeatPayload {
            frame_type: FrameType::Ping
        })
    ));

    server.await.unwrap();
}
