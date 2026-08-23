//! Session 13 real-TCP coverage for process-level Edge/Agent recovery.

use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use tunnelproxy_agent::{
    AgentError, AgentRuntime, AgentRuntimeConfig, AgentRuntimeError, AgentRuntimeOutcome,
    AgentTlsConfig, AgentTransportSecurity, RuntimeShutdownConfig,
};
use tunnelproxy_edge::{
    shutdown_channel, EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeError, EdgeTlsConfig,
    EdgeTransportSecurity, RuntimeShutdownOutcome,
};
use tunnelproxy_protocol::{Frame, FrameEncoder, FrameType, ROLE_AGENT};

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

struct TestPki {
    authority_pem: String,
    server: TestIdentity,
    client: TestIdentity,
}

fn test_pki(server_name: &str) -> TestPki {
    let mut authority_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let authority_key = KeyPair::generate().unwrap();
    let authority = authority_params.self_signed(&authority_key).unwrap();
    let server = signed_identity(
        server_name,
        ExtendedKeyUsagePurpose::ServerAuth,
        &authority,
        &authority_key,
    );
    let client = signed_identity(
        "agent.test",
        ExtendedKeyUsagePurpose::ClientAuth,
        &authority,
        &authority_key,
    );
    TestPki {
        authority_pem: authority.pem(),
        server,
        client,
    }
}

fn signed_identity(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    authority: &Certificate,
    authority_key: &KeyPair,
) -> TestIdentity {
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, authority, authority_key).unwrap();
    TestIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
    }
}

fn mutual_tls_security() -> (EdgeTransportSecurity, AgentTransportSecurity) {
    let pki = test_pki("edge.test");
    let edge = edge_tls_security(&pki, Duration::from_secs(1));
    let agent = agent_tls_security(&pki.authority_pem, &pki.client, "edge.test");
    (edge, agent)
}

fn edge_tls_security(pki: &TestPki, timeout: Duration) -> EdgeTransportSecurity {
    EdgeTransportSecurity::MutualTls(
        EdgeTlsConfig::from_pem(
            pki.server.certificate_pem.as_bytes(),
            pki.server.private_key_pem.as_bytes(),
            pki.authority_pem.as_bytes(),
            timeout,
        )
        .unwrap(),
    )
}

fn agent_tls_security(
    server_ca_pem: &str,
    client: &TestIdentity,
    server_name: &str,
) -> AgentTransportSecurity {
    AgentTransportSecurity::MutualTls(
        AgentTlsConfig::from_pem(
            server_ca_pem.as_bytes(),
            client.certificate_pem.as_bytes(),
            client.private_key_pem.as_bytes(),
            server_name,
            Duration::from_secs(1),
        )
        .unwrap(),
    )
}

fn raw_tls_client_config(
    authority_pem: &str,
    identity: Option<&TestIdentity>,
    advertise_alpn: bool,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(Cursor::new(authority_pem.as_bytes()));
    for certificate in rustls_pemfile::certs(&mut reader) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let mut config = match identity {
        Some(identity) => {
            let mut certificates = BufReader::new(Cursor::new(identity.certificate_pem.as_bytes()));
            let certificates: Vec<_> = rustls_pemfile::certs(&mut certificates)
                .collect::<Result<_, _>>()
                .unwrap();
            let mut key = BufReader::new(Cursor::new(identity.private_key_pem.as_bytes()));
            let key = rustls_pemfile::private_key(&mut key).unwrap().unwrap();
            builder.with_client_auth_cert(certificates, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    if advertise_alpn {
        config.alpn_protocols = vec![b"tunnelproxy/1".to_vec()];
    }
    Arc::new(config)
}

async fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn edge_config(raw_addr: SocketAddr) -> EdgeRuntimeConfig {
    let mut config = EdgeRuntimeConfig::dev_defaults();
    config.multiplex.agent_listener.listen_addr = "127.0.0.1:0".parse().unwrap();
    config.multiplex.agent_listener.handshake_timeout = Duration::from_secs(1);
    config.multiplex.agent_listener.heartbeat_interval = Duration::from_millis(25);
    config.multiplex.agent_listener.pong_timeout = Duration::from_millis(100);
    config.multiplex.stream_open_timeout = Duration::from_secs(1);
    config.multiplex.stream_idle_timeout = Duration::from_secs(2);
    config.raw_listen_addr = raw_addr;
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    config
}

fn agent_runtime(edge_addr: SocketAddr, local_addr: SocketAddr) -> AgentRuntime {
    let mut config = AgentRuntimeConfig::new(edge_addr, local_addr);
    config.connect_timeout = Duration::from_secs(1);
    config.handshake_timeout = Duration::from_secs(1);
    config.multiplex.connect_timeout = Duration::from_secs(1);
    config.multiplex.stream_idle_timeout = Duration::from_secs(2);
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    config.reconnect.initial_delay = Duration::from_millis(10);
    config.reconnect.max_delay = Duration::from_millis(40);
    config.reconnect.jitter_percent = 0;
    config.reconnect.stable_session_reset_after = Duration::from_secs(1);
    AgentRuntime::new(config).unwrap()
}

async fn connect_eventually(addr: SocketAddr) -> TcpStream {
    timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect(addr).await {
                Ok(socket) => break socket,
                Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
            }
        }
    })
    .await
    .expect("raw route was not bound")
}

async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_echo_connections(1).await
}

async fn spawn_echo_connections(
    connection_count: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..connection_count {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = socket.read(&mut buffer).await.unwrap();
                if count == 0 {
                    let _ = socket.shutdown().await;
                    break;
                }
                socket.write_all(&buffer[..count]).await.unwrap();
            }
        }
    });
    (addr, task)
}

async fn round_trip(raw_addr: SocketAddr, payload: &[u8]) {
    let mut client = connect_eventually(raw_addr).await;
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
    let mut end = Vec::new();
    client.read_to_end(&mut end).await.unwrap();
}

async fn wait_until_bindable(addr: SocketAddr) {
    timeout(Duration::from_secs(2), async {
        loop {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    drop(listener);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
            }
        }
    })
    .await
    .expect("listener was not released");
}

#[tokio::test]
async fn edge_shutdown_before_agent_releases_transport_listener() {
    let raw_addr = unused_addr().await;
    let runtime = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let agent_addr = runtime.agent_addr();
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();

    let outcome = runtime.run_until_shutdown(signal).await.unwrap();
    assert_eq!(outcome.raw_addr, None);
    assert_eq!(
        outcome.raw_routes,
        RuntimeShutdownOutcome::Drained { completed_tasks: 0 }
    );
    assert!(!outcome.was_forced());
    TcpListener::bind(agent_addr).await.unwrap();
}

#[tokio::test]
async fn composed_runtimes_forward_bytes_and_shutdown_cleanly() {
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let edge = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));

    round_trip(raw_addr, b"session-13-runtime").await;

    edge_trigger.shutdown();
    agent_trigger.shutdown();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(edge_outcome.raw_addr, Some(raw_addr));
    assert!(!edge_outcome.was_forced());
    let agent_outcome = agent_task.await.unwrap().unwrap();
    assert!(agent_outcome.established_sessions >= 1);
    local_task.await.unwrap();
    TcpListener::bind(edge_addr).await.unwrap();
    TcpListener::bind(raw_addr).await.unwrap();
}

#[tokio::test]
async fn raw_bind_failure_rolls_back_the_agent_listener() {
    let occupied_raw = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw_addr = occupied_raw.local_addr().unwrap();
    let edge = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (_edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(
        agent_runtime(edge_addr, unused_addr().await).run_until_shutdown(agent_signal),
    );

    assert!(matches!(
        edge_task.await.unwrap(),
        Err(EdgeRuntimeError::RouteStartup(_))
    ));
    agent_trigger.shutdown();
    let _ = agent_task.await.unwrap();
    TcpListener::bind(edge_addr)
        .await
        .expect("startup rollback must release Agent listener");
}

#[tokio::test]
async fn agent_shutdown_interrupts_a_long_reconnect_backoff() {
    let mut config = AgentRuntimeConfig::new(unused_addr().await, unused_addr().await);
    config.connect_timeout = Duration::from_millis(100);
    config.reconnect.initial_delay = Duration::from_secs(5);
    config.reconnect.max_delay = Duration::from_secs(5);
    config.reconnect.jitter_percent = 0;
    let runtime = AgentRuntime::new(config).unwrap();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(runtime.run_until_shutdown(signal));

    tokio::time::sleep(Duration::from_millis(50)).await;
    trigger.shutdown();
    let outcome = timeout(Duration::from_millis(250), task)
        .await
        .expect("shutdown did not interrupt reconnect sleep")
        .unwrap()
        .unwrap();
    assert_eq!(outcome.connection_attempts, 1);
    assert_eq!(outcome.established_sessions, 0);
}

#[tokio::test]
async fn reconnect_budget_exhaustion_is_typed() {
    let mut config = AgentRuntimeConfig::new(unused_addr().await, unused_addr().await);
    config.connect_timeout = Duration::from_millis(100);
    config.reconnect.initial_delay = Duration::from_millis(5);
    config.reconnect.max_delay = Duration::from_millis(5);
    config.reconnect.jitter_percent = 0;
    config.reconnect.max_attempts = Some(2);
    let runtime = AgentRuntime::new(config).unwrap();
    let (_trigger, signal) = shutdown_channel();

    let error = timeout(Duration::from_secs(1), runtime.run_until_shutdown(signal))
        .await
        .expect("reconnect budget was not exhausted")
        .unwrap_err();
    assert!(matches!(
        error,
        AgentRuntimeError::ReconnectExhausted {
            consecutive_failures: 2,
            ..
        }
    ));
}

#[tokio::test]
async fn edge_rebinds_the_same_raw_address_to_a_replacement_agent() {
    let (local_addr, local_task) = spawn_echo_connections(2).await;
    let raw_addr = unused_addr().await;
    let edge = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let (_agent_one_trigger, agent_one_signal) = shutdown_channel();
    let agent_one_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_one_signal));
    round_trip(raw_addr, b"first-agent").await;

    agent_one_task.abort();
    let _ = agent_one_task.await;
    wait_until_bindable(raw_addr).await;

    let (agent_two_trigger, agent_two_signal) = shutdown_channel();
    let agent_two_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_two_signal));
    round_trip(raw_addr, b"replacement-agent").await;

    agent_two_trigger.shutdown();
    edge_trigger.shutdown();
    let agent_outcome = agent_two_task.await.unwrap().unwrap();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(agent_outcome.established_sessions, 1);
    assert_eq!(edge_outcome.raw_addr, Some(raw_addr));
    assert_eq!(edge_outcome.agent_sessions_seen, 2);
    assert_eq!(edge_outcome.route_generations, 2);
    assert_eq!(edge_outcome.successful_recoveries, 1);
    local_task.await.unwrap();
}

#[tokio::test]
async fn agent_reconnects_after_edge_restart() {
    let (local_addr, local_task) = spawn_echo_connections(2).await;
    let agent_addr = unused_addr().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.agent_listener.listen_addr = agent_addr;

    let edge_one = EdgeRuntime::bind(config.clone()).await.unwrap();
    let (edge_one_trigger, edge_one_signal) = shutdown_channel();
    let edge_one_task = tokio::spawn(edge_one.run_until_shutdown(edge_one_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(agent_addr, local_addr).run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"before-edge-restart").await;

    edge_one_trigger.shutdown();
    edge_one_task.await.unwrap().unwrap();
    let edge_two = timeout(Duration::from_secs(1), EdgeRuntime::bind(config))
        .await
        .expect("second Edge bind timed out")
        .expect("second Edge could not reuse listener addresses");
    let (edge_two_trigger, edge_two_signal) = shutdown_channel();
    let edge_two_task = tokio::spawn(edge_two.run_until_shutdown(edge_two_signal));
    round_trip(raw_addr, b"after-edge-restart").await;

    agent_trigger.shutdown();
    edge_two_trigger.shutdown();
    let agent_outcome = agent_task.await.unwrap().unwrap();
    let edge_outcome = edge_two_task.await.unwrap().unwrap();
    assert!(agent_outcome.connection_attempts >= 2);
    assert!(agent_outcome.established_sessions >= 2);
    assert!(agent_outcome.successful_reconnects >= 1);
    assert_eq!(edge_outcome.raw_addr, Some(raw_addr));
    local_task.await.unwrap();
}

#[tokio::test]
async fn agent_shutdown_before_connect_skips_network_startup() {
    let runtime = agent_runtime(unused_addr().await, unused_addr().await);
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();
    assert_eq!(
        runtime.run_until_shutdown(signal).await.unwrap(),
        AgentRuntimeOutcome {
            connection_attempts: 0,
            established_sessions: 0,
            successful_reconnects: 0,
            last_session_id: None,
        }
    );
}

#[tokio::test]
async fn mutual_tls_runtimes_authenticate_and_forward_bytes() {
    let (edge_security, agent_security) = mutual_tls_security();
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_security;
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let mut config = AgentRuntimeConfig::new(edge_addr, local_addr);
    config.security = agent_security;
    config.connect_timeout = Duration::from_secs(1);
    config.handshake_timeout = Duration::from_secs(1);
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    let agent = AgentRuntime::new(config).unwrap();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));

    round_trip(raw_addr, b"mutual-tls-runtime").await;
    agent_trigger.shutdown();
    edge_trigger.shutdown();

    let agent_outcome = agent_task.await.unwrap().unwrap();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(agent_outcome.established_sessions, 1);
    assert_eq!(edge_outcome.route_generations, 1);
    local_task.await.unwrap();
}

#[tokio::test]
async fn wrong_tls_server_name_is_terminal_and_never_becomes_routable() {
    let pki = test_pki("edge.test");
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let mut config = AgentRuntimeConfig::new(edge_addr, unused_addr().await);
    config.security = agent_tls_security(&pki.authority_pem, &pki.client, "wrong.test");
    let agent = AgentRuntime::new(config).unwrap();
    let (_trigger, signal) = shutdown_channel();
    let error = timeout(Duration::from_secs(1), agent.run_until_shutdown(signal))
        .await
        .expect("invalid server identity did not fail promptly")
        .unwrap_err();
    assert!(matches!(
        error,
        AgentRuntimeError::Terminal(AgentError::TlsAuthentication(_))
    ));

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(outcome.agent_sessions_seen, 0);
    wait_until_bindable(raw_addr).await;
}

#[tokio::test]
async fn untrusted_edge_ca_is_terminal() {
    let trusted = test_pki("edge.test");
    let untrusted = test_pki("other-edge.test");
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&trusted, Duration::from_secs(1));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let mut config = AgentRuntimeConfig::new(edge_addr, unused_addr().await);
    config.security = agent_tls_security(&untrusted.authority_pem, &trusted.client, "edge.test");
    let agent = AgentRuntime::new(config).unwrap();
    let (_trigger, signal) = shutdown_channel();
    let error = timeout(Duration::from_secs(1), agent.run_until_shutdown(signal))
        .await
        .expect("untrusted Edge CA did not fail promptly")
        .unwrap_err();
    assert!(matches!(
        error,
        AgentRuntimeError::Terminal(AgentError::TlsAuthentication(_))
    ));

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(outcome.agent_sessions_seen, 0);
}

#[tokio::test]
async fn untrusted_client_certificate_is_isolated_and_releases_capacity() {
    let trusted = test_pki("edge.test");
    let untrusted = test_pki("untrusted.test");
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.agent_listener.max_agent_sessions = 1;
    config.multiplex.security = edge_tls_security(&trusted, Duration::from_secs(1));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let mut bad_config = AgentRuntimeConfig::new(edge_addr, local_addr);
    bad_config.security =
        agent_tls_security(&trusted.authority_pem, &untrusted.client, "edge.test");
    bad_config.reconnect.max_attempts = Some(1);
    let bad_agent = AgentRuntime::new(bad_config).unwrap();
    let (_bad_trigger, bad_signal) = shutdown_channel();
    let error = timeout(
        Duration::from_secs(1),
        bad_agent.run_until_shutdown(bad_signal),
    )
    .await
    .expect("untrusted client certificate did not fail promptly")
    .unwrap_err();
    assert!(
        matches!(
            error,
            AgentRuntimeError::Terminal(AgentError::TlsAuthentication(_))
        ),
        "unexpected untrusted-client error: {error:?}"
    );

    let mut good_config = AgentRuntimeConfig::new(edge_addr, local_addr);
    good_config.security = agent_tls_security(&trusted.authority_pem, &trusted.client, "edge.test");
    let good_agent = AgentRuntime::new(good_config).unwrap();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(good_agent.run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"trusted-agent-after-rejection").await;

    agent_trigger.shutdown();
    edge_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(edge_outcome.agent_sessions_seen, 1);
    local_task.await.unwrap();
}

#[tokio::test]
async fn missing_client_certificate_is_rejected_before_protocol_registration() {
    let pki = test_pki("edge.test");
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.agent_listener.max_agent_sessions = 1;
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let socket = TcpStream::connect(edge_addr).await.unwrap();
    let connector = TlsConnector::from(raw_tls_client_config(&pki.authority_pem, None, true));
    let server_name = ServerName::try_from("edge.test").unwrap().to_owned();
    if let Ok(mut stream) = connector.connect(server_name, socket).await {
        let _ = stream.write_all(b"not-a-protocol-frame").await;
        let mut byte = [0_u8; 1];
        let _ = timeout(Duration::from_millis(100), stream.read(&mut byte)).await;
    }

    let mut config = AgentRuntimeConfig::new(edge_addr, local_addr);
    config.security = agent_tls_security(&pki.authority_pem, &pki.client, "edge.test");
    let agent = AgentRuntime::new(config).unwrap();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"authenticated-after-missing-cert").await;

    agent_trigger.shutdown();
    edge_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    let edge_outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(edge_outcome.agent_sessions_seen, 1);
    local_task.await.unwrap();
}

#[tokio::test]
async fn missing_tunnelproxy_alpn_is_rejected_before_protocol_registration() {
    let pki = test_pki("edge.test");
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let socket = TcpStream::connect(edge_addr).await.unwrap();
    let connector = TlsConnector::from(raw_tls_client_config(
        &pki.authority_pem,
        Some(&pki.client),
        false,
    ));
    let server_name = ServerName::try_from("edge.test").unwrap().to_owned();
    if let Ok(mut stream) = connector.connect(server_name, socket).await {
        let hello = Frame::control(FrameType::Hello, vec![ROLE_AGENT]).unwrap();
        let register = Frame::control(FrameType::Register, Vec::new()).unwrap();
        let _ = FrameEncoder::encode(&mut stream, &hello).await;
        let _ = FrameEncoder::encode(&mut stream, &register).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(outcome.agent_sessions_seen, 0);
    wait_until_bindable(raw_addr).await;
}

#[tokio::test]
async fn stalled_tls_handshake_times_out_and_releases_capacity() {
    let pki = test_pki("edge.test");
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.agent_listener.max_agent_sessions = 1;
    config.multiplex.security = edge_tls_security(&pki, Duration::from_millis(50));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let stalled = TcpStream::connect(edge_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut config = AgentRuntimeConfig::new(edge_addr, local_addr);
    config.security = agent_tls_security(&pki.authority_pem, &pki.client, "edge.test");
    let agent = AgentRuntime::new(config).unwrap();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"after-stalled-tls-handshake").await;
    drop(stalled);

    agent_trigger.shutdown();
    edge_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    edge_task.await.unwrap().unwrap();
    local_task.await.unwrap();
}

#[tokio::test]
async fn agent_shutdown_cancels_an_in_progress_tls_handshake() {
    let pki = test_pki("edge.test");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });

    let mut config = AgentRuntimeConfig::new(edge_addr, unused_addr().await);
    let tls = AgentTlsConfig::from_pem(
        pki.authority_pem.as_bytes(),
        pki.client.certificate_pem.as_bytes(),
        pki.client.private_key_pem.as_bytes(),
        "edge.test",
        Duration::from_secs(5),
    )
    .unwrap();
    config.security = AgentTransportSecurity::MutualTls(tls);
    let agent = AgentRuntime::new(config).unwrap();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(agent.run_until_shutdown(signal));

    tokio::time::sleep(Duration::from_millis(50)).await;
    trigger.shutdown();
    let outcome = timeout(Duration::from_millis(250), task)
        .await
        .expect("shutdown did not cancel TLS handshake")
        .unwrap()
        .unwrap();
    assert_eq!(outcome.established_sessions, 0);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn agent_performs_a_fresh_mutual_tls_handshake_after_edge_restart() {
    let pki = test_pki("edge.test");
    let edge_security = edge_tls_security(&pki, Duration::from_secs(1));
    let agent_security = agent_tls_security(&pki.authority_pem, &pki.client, "edge.test");
    let (local_addr, local_task) = spawn_echo_connections(2).await;
    let agent_addr = unused_addr().await;
    let raw_addr = unused_addr().await;
    let mut edge_config = edge_config(raw_addr);
    edge_config.multiplex.agent_listener.listen_addr = agent_addr;
    edge_config.multiplex.security = edge_security;

    let edge_one = EdgeRuntime::bind(edge_config.clone()).await.unwrap();
    let (edge_one_trigger, edge_one_signal) = shutdown_channel();
    let edge_one_task = tokio::spawn(edge_one.run_until_shutdown(edge_one_signal));
    let mut agent_config = AgentRuntimeConfig::new(agent_addr, local_addr);
    agent_config.security = agent_security;
    agent_config.reconnect.initial_delay = Duration::from_millis(10);
    agent_config.reconnect.max_delay = Duration::from_millis(40);
    agent_config.reconnect.jitter_percent = 0;
    let agent = AgentRuntime::new(agent_config).unwrap();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"secure-before-restart").await;

    edge_one_trigger.shutdown();
    edge_one_task.await.unwrap().unwrap();
    let edge_two = timeout(Duration::from_secs(1), EdgeRuntime::bind(edge_config))
        .await
        .expect("secure Edge restart bind timed out")
        .unwrap();
    let (edge_two_trigger, edge_two_signal) = shutdown_channel();
    let edge_two_task = tokio::spawn(edge_two.run_until_shutdown(edge_two_signal));
    round_trip(raw_addr, b"secure-after-restart").await;

    agent_trigger.shutdown();
    edge_two_trigger.shutdown();
    let agent_outcome = agent_task.await.unwrap().unwrap();
    edge_two_task.await.unwrap().unwrap();
    assert!(agent_outcome.established_sessions >= 2);
    assert!(agent_outcome.successful_reconnects >= 1);
    local_task.await.unwrap();
}

#[test]
fn tls_allows_a_non_loopback_agent_listener_but_plaintext_does_not() {
    let pki = test_pki("edge.test");
    let raw_addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
    let mut config = edge_config(raw_addr);
    config.multiplex.agent_listener.listen_addr = "0.0.0.0:7100".parse().unwrap();
    assert!(config.validate().is_err());
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    assert!(config.validate().is_ok());
}

#[test]
fn tls_configuration_debug_output_omits_certificate_and_private_key_pem() {
    let pki = test_pki("edge.test");
    let edge = edge_tls_security(&pki, Duration::from_secs(1));
    let agent = agent_tls_security(&pki.authority_pem, &pki.client, "edge.test");
    let debug = format!("{edge:?} {agent:?}");
    assert!(!debug.contains("BEGIN CERTIFICATE"));
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(!debug.contains(&pki.client.private_key_pem));
    assert!(!debug.contains(&pki.server.private_key_pem));
}
