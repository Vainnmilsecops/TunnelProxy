//! Integration tests for the Agent ↔ Edge transport handshake.
//!
//! All tests use real loopback TCP (`127.0.0.1:0` ephemeral ports) and
//! deterministic protocol interactions.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use tunnelproxy_agent::connect;
use tunnelproxy_edge::agent_transport::{
    AgentListenerConfig, AgentTransportListener, TransportSessionIdAllocator,
};
use tunnelproxy_protocol::{Frame, FrameEncoder, FrameType, ROLE_AGENT};

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
