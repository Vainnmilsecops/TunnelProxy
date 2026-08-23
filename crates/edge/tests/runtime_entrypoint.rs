//! Session 13 real-TCP coverage for process-level Edge/Agent recovery.

use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
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
use tunnelproxy_common::{AgentId, TunnelId};
use tunnelproxy_control_plane::{
    authorization_snapshot_channel, AgentGrant, AuthorizationSnapshot, CertificateFingerprint,
    ControlPlaneRuntime, ControlPlaneRuntimeConfig, SnapshotBootstrapSource, SnapshotCacheConfig,
    SnapshotClientConfig, SnapshotClientError, SnapshotRepository, SnapshotServerConfig,
    SnapshotServerTlsConfig, SnapshotVersion, SqliteSnapshotRepository, TunnelGrant, TunnelStatus,
    VersionedAuthorizationSnapshot,
};
use tunnelproxy_edge::{
    shutdown_channel, AuthorizationSourceStatus, EdgeRegistrationPolicy, EdgeRuntime,
    EdgeRuntimeConfig, EdgeRuntimeError, EdgeSessionRouter, EdgeTlsConfig, EdgeTransportSecurity,
    RuntimeShutdownOutcome, SnapshotAwareEdgeRuntime, SnapshotAwareEdgeRuntimeError,
};
use tunnelproxy_protocol::{
    Frame, FrameEncoder, FrameType, HandshakeErrorCode, RegistrationRequest, ROLE_AGENT,
};

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

static NEXT_SNAPSHOT_TEMP: AtomicU64 = AtomicU64::new(1);

fn snapshot_temp_database() -> (PathBuf, PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "tunnelproxy-edge-snapshot-{}-{}",
        std::process::id(),
        NEXT_SNAPSHOT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    (directory.join("snapshots.sqlite"), directory)
}

struct TestPki {
    authority_pem: String,
    server: TestIdentity,
    client: TestIdentity,
    other_client: TestIdentity,
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
    let other_client = signed_identity(
        "other-agent.test",
        ExtendedKeyUsagePurpose::ClientAuth,
        &authority,
        &authority_key,
    );
    TestPki {
        authority_pem: authority.pem(),
        server,
        client,
        other_client,
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

fn mutual_tls_security() -> (
    EdgeTransportSecurity,
    EdgeRegistrationPolicy,
    AgentTransportSecurity,
) {
    let pki = test_pki("edge.test");
    let edge = edge_tls_security(&pki, Duration::from_secs(1));
    let registration = edge_tls_registration(&pki);
    let agent = agent_tls_security(&pki.authority_pem, &pki.client, "edge.test");
    (edge, registration, agent)
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

fn edge_tls_registration(pki: &TestPki) -> EdgeRegistrationPolicy {
    EdgeRegistrationPolicy::mutual_tls_from_client_cert_pem(
        AgentId::new("agent-dev").unwrap(),
        TunnelId::new("tunnel-dev").unwrap(),
        pki.client.certificate_pem.as_bytes(),
    )
    .unwrap()
}

fn client_fingerprint(identity: &TestIdentity) -> CertificateFingerprint {
    let mut certificates = BufReader::new(Cursor::new(identity.certificate_pem.as_bytes()));
    let leaf = rustls_pemfile::certs(&mut certificates)
        .next()
        .unwrap()
        .unwrap();
    CertificateFingerprint::from_certificate_der(leaf.as_ref())
}

fn versioned_snapshot(
    pki: &TestPki,
    version: u64,
    status: TunnelStatus,
    include_unrelated: bool,
) -> VersionedAuthorizationSnapshot {
    let mut grants = vec![AgentGrant::new(
        client_fingerprint(&pki.client),
        AgentId::new("agent-dev").unwrap(),
        vec![TunnelGrant::new(
            TunnelId::new("tunnel-dev").unwrap(),
            status,
        )],
    )];
    if include_unrelated {
        grants.push(AgentGrant::new(
            client_fingerprint(&pki.other_client),
            AgentId::new("agent-other").unwrap(),
            vec![TunnelGrant::new(
                TunnelId::new("tunnel-other").unwrap(),
                TunnelStatus::Enabled,
            )],
        ));
    }
    VersionedAuthorizationSnapshot::new(
        SnapshotVersion::new(version).unwrap(),
        AuthorizationSnapshot::new(grants).unwrap(),
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
        config.alpn_protocols = vec![b"tunnelproxy/2".to_vec()];
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

fn secure_agent_runtime(
    edge_addr: SocketAddr,
    local_addr: SocketAddr,
    pki: &TestPki,
) -> AgentRuntime {
    let mut config = AgentRuntimeConfig::new(edge_addr, local_addr);
    config.security = agent_tls_security(&pki.authority_pem, &pki.client, "edge.test");
    config.connect_timeout = Duration::from_secs(1);
    config.handshake_timeout = Duration::from_secs(1);
    config.multiplex.connect_timeout = Duration::from_secs(1);
    config.multiplex.stream_idle_timeout = Duration::from_secs(2);
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    config.reconnect.initial_delay = Duration::from_millis(10);
    config.reconnect.max_delay = Duration::from_millis(40);
    config.reconnect.jitter_percent = 0;
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
    timeout(Duration::from_secs(2), async {
        loop {
            let mut client = connect_eventually(raw_addr).await;
            if client.write_all(payload).await.is_err() {
                continue;
            }
            let mut echoed = vec![0_u8; payload.len()];
            if client.read_exact(&mut echoed).await.is_ok() && echoed == payload {
                client.shutdown().await.unwrap();
                let mut end = Vec::new();
                client.read_to_end(&mut end).await.unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("tunnel did not become routable");
}

async fn registration_rejection(
    edge_addr: SocketAddr,
    local_addr: SocketAddr,
    security: AgentTransportSecurity,
    registration: RegistrationRequest,
) -> HandshakeErrorCode {
    let mut config = AgentRuntimeConfig::new(edge_addr, local_addr);
    config.security = security;
    config.registration = registration;
    config.connect_timeout = Duration::from_secs(1);
    config.handshake_timeout = Duration::from_secs(1);
    let runtime = AgentRuntime::new(config).unwrap();
    let (_trigger, signal) = shutdown_channel();
    let error = timeout(Duration::from_secs(1), runtime.run_until_shutdown(signal))
        .await
        .expect("registration rejection was not terminal")
        .unwrap_err();
    match error {
        AgentRuntimeError::Terminal(AgentError::RegistrationRejected { code: Some(code) }) => code,
        other => panic!("unexpected registration result: {other:?}"),
    }
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

async fn wait_for_authorization_status(
    router: &EdgeSessionRouter,
    version: u64,
    source: AuthorizationSourceStatus,
) {
    timeout(Duration::from_secs(2), async {
        loop {
            let status = router.authorization_status();
            if status.version == SnapshotVersion::new(version) && status.source == source {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("authorization status did not converge");
}

#[tokio::test]
async fn edge_shutdown_before_agent_releases_transport_listener() {
    let raw_addr = unused_addr().await;
    let runtime = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let agent_addr = runtime.agent_addr();
    let (trigger, signal) = shutdown_channel();
    trigger.shutdown();

    let outcome = runtime.run_until_shutdown(signal).await.unwrap();
    assert_eq!(outcome.raw_addr, Some(raw_addr));
    assert_eq!(
        outcome.raw_routes,
        RuntimeShutdownOutcome::Drained { completed_tasks: 1 }
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
    assert!(TcpListener::bind(raw_addr).await.is_err());

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
    assert_eq!(edge_outcome.route_generations, 1);
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
    let (edge_security, edge_registration, agent_security) = mutual_tls_security();
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_security;
    config.multiplex.registration = edge_registration;
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
async fn durable_raw_listener_fails_closed_offline_then_routes_after_registration() {
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let edge = EdgeRuntime::bind(edge_config(raw_addr)).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let mut offline = connect_eventually(raw_addr).await;
    offline.write_all(b"offline").await.unwrap();
    let mut byte = [0_u8; 1];
    let offline_result = timeout(Duration::from_secs(1), offline.read(&mut byte))
        .await
        .expect("offline ingress was not closed");
    assert!(matches!(offline_result, Ok(0) | Err(_)));
    assert!(TcpListener::bind(raw_addr).await.is_err());

    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"online-after-registration").await;

    agent_trigger.shutdown();
    edge_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    edge_task.await.unwrap().unwrap();
    local_task.await.unwrap();
}

#[tokio::test]
async fn live_snapshot_updates_revoke_and_restore_tunnel_without_rebinding_ingress() {
    let pki = test_pki("edge.test");
    let (publisher, subscription) =
        authorization_snapshot_channel(versioned_snapshot(&pki, 1, TunnelStatus::Enabled, false));
    let (local_addr, local_task) = spawn_echo_connections(5).await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls_updates(subscription);
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let (agent_one_trigger, agent_one_signal) = shutdown_channel();
    let agent_one_task = tokio::spawn(
        secure_agent_runtime(edge_addr, local_addr, &pki).run_until_shutdown(agent_one_signal),
    );
    round_trip(raw_addr, b"snapshot-v1").await;

    publisher
        .publish(versioned_snapshot(&pki, 2, TunnelStatus::Enabled, true))
        .unwrap();
    wait_for_authorization_status(&router, 2, AuthorizationSourceStatus::Live).await;
    round_trip(raw_addr, b"unrelated-update-keeps-session").await;

    let mut active = connect_eventually(raw_addr).await;
    active.write_all(b"active-before-revoke").await.unwrap();
    let mut echoed = vec![0_u8; b"active-before-revoke".len()];
    active.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"active-before-revoke");

    publisher
        .publish(versioned_snapshot(&pki, 3, TunnelStatus::Disabled, true))
        .unwrap();
    wait_for_authorization_status(&router, 3, AuthorizationSourceStatus::Live).await;
    assert!(router.connected_tunnels().await.is_empty());
    assert_eq!(router.authorization_status().revoked_sessions, 1);
    let mut byte = [0_u8; 1];
    let revoked_read = timeout(Duration::from_secs(2), active.read(&mut byte))
        .await
        .expect("revoked active stream stayed open");
    assert!(matches!(revoked_read, Ok(0) | Err(_)));
    let mut offline = connect_eventually(raw_addr).await;
    offline.write_all(b"offline-after-revoke").await.unwrap();
    let offline_read = timeout(Duration::from_secs(1), offline.read(&mut byte))
        .await
        .expect("offline ingress stayed open");
    assert!(matches!(offline_read, Ok(0) | Err(_)));
    assert!(TcpListener::bind(raw_addr).await.is_err());

    agent_one_trigger.shutdown();
    let _ = timeout(Duration::from_secs(2), agent_one_task)
        .await
        .expect("revoked Agent did not stop");

    publisher
        .publish(versioned_snapshot(&pki, 4, TunnelStatus::Enabled, false))
        .unwrap();
    wait_for_authorization_status(&router, 4, AuthorizationSourceStatus::Live).await;
    let (agent_two_trigger, agent_two_signal) = shutdown_channel();
    let agent_two_task = tokio::spawn(
        secure_agent_runtime(edge_addr, local_addr, &pki).run_until_shutdown(agent_two_signal),
    );
    round_trip(raw_addr, b"snapshot-v4-reenabled").await;

    drop(publisher);
    wait_for_authorization_status(&router, 4, AuthorizationSourceStatus::Stale).await;
    round_trip(raw_addr, b"cached-snapshot-after-source-close").await;

    agent_two_trigger.shutdown();
    edge_trigger.shutdown();
    agent_two_task.await.unwrap().unwrap();
    let outcome = edge_task.await.unwrap().unwrap();
    assert!(outcome.agent_sessions_seen >= 2);
    assert_eq!(outcome.route_generations, 1);
    local_task.await.unwrap();
}

#[tokio::test]
async fn live_snapshot_add_authorizes_tunnel_without_edge_restart() {
    let pki = test_pki("edge.test");
    let (publisher, subscription) =
        authorization_snapshot_channel(VersionedAuthorizationSnapshot::new(
            SnapshotVersion::FIRST,
            AuthorizationSnapshot::default(),
        ));
    let (local_addr, local_task) = spawn_echo().await;
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls_updates(subscription);
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let mut offline = connect_eventually(raw_addr).await;
    offline.write_all(b"before-grant").await.unwrap();
    let mut byte = [0_u8; 1];
    let offline_read = timeout(Duration::from_secs(1), offline.read(&mut byte))
        .await
        .expect("ungranted tunnel ingress stayed open");
    assert!(matches!(offline_read, Ok(0) | Err(_)));

    publisher
        .publish(versioned_snapshot(&pki, 2, TunnelStatus::Enabled, false))
        .unwrap();
    wait_for_authorization_status(&router, 2, AuthorizationSourceStatus::Live).await;
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(
        secure_agent_runtime(edge_addr, local_addr, &pki).run_until_shutdown(agent_signal),
    );
    round_trip(raw_addr, b"after-live-grant").await;

    agent_trigger.shutdown();
    edge_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    edge_task.await.unwrap().unwrap();
    local_task.await.unwrap();
}

#[tokio::test]
async fn certificate_binding_rejects_same_ca_peer_and_false_identity_claims() {
    let pki = test_pki("edge.test");
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = edge_tls_registration(&pki);
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let local_addr = unused_addr().await;

    let unknown_certificate = registration_rejection(
        edge_addr,
        local_addr,
        agent_tls_security(&pki.authority_pem, &pki.other_client, "edge.test"),
        RegistrationRequest::new(
            AgentId::new("agent-dev").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
    )
    .await;
    assert_eq!(unknown_certificate, HandshakeErrorCode::UnauthorizedAgent);

    let wrong_agent = registration_rejection(
        edge_addr,
        local_addr,
        agent_tls_security(&pki.authority_pem, &pki.client, "edge.test"),
        RegistrationRequest::new(
            AgentId::new("agent-impostor").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
    )
    .await;
    assert_eq!(wrong_agent, HandshakeErrorCode::UnauthorizedAgent);

    let wrong_tunnel = registration_rejection(
        edge_addr,
        local_addr,
        agent_tls_security(&pki.authority_pem, &pki.client, "edge.test"),
        RegistrationRequest::new(
            AgentId::new("agent-dev").unwrap(),
            TunnelId::new("tunnel-other").unwrap(),
        ),
    )
    .await;
    assert_eq!(wrong_tunnel, HandshakeErrorCode::UnauthorizedTunnel);

    edge_trigger.shutdown();
    edge_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn disabled_tunnel_is_rejected_before_session_publication() {
    let pki = test_pki("edge.test");
    let mut certificates = BufReader::new(Cursor::new(pki.client.certificate_pem.as_bytes()));
    let leaf = rustls_pemfile::certs(&mut certificates)
        .next()
        .unwrap()
        .unwrap();
    let snapshot = AuthorizationSnapshot::new(vec![AgentGrant::new(
        CertificateFingerprint::from_certificate_der(leaf.as_ref()),
        AgentId::new("agent-dev").unwrap(),
        vec![TunnelGrant::new(
            TunnelId::new("tunnel-dev").unwrap(),
            TunnelStatus::Disabled,
        )],
    )])
    .unwrap();
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls(snapshot);
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let rejection = registration_rejection(
        edge_addr,
        unused_addr().await,
        agent_tls_security(&pki.authority_pem, &pki.client, "edge.test"),
        RegistrationRequest::new(
            AgentId::new("agent-dev").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
    )
    .await;
    assert_eq!(rejection, HandshakeErrorCode::TunnelDisabled);

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(outcome.agent_sessions_seen, 0);
}

#[tokio::test]
async fn wrong_tls_server_name_is_terminal_and_never_becomes_routable() {
    let pki = test_pki("edge.test");
    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = edge_tls_registration(&pki);
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
    config.multiplex.registration = edge_tls_registration(&trusted);
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
    config.multiplex.registration = edge_tls_registration(&trusted);
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
    config.multiplex.registration = edge_tls_registration(&pki);
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
    config.multiplex.registration = edge_tls_registration(&pki);
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
    config.multiplex.registration = edge_tls_registration(&pki);
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
    edge_config.multiplex.registration = edge_tls_registration(&pki);

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
    config.multiplex.registration = edge_tls_registration(&pki);
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

#[tokio::test]
async fn snapshot_aware_edge_routes_and_survives_control_plane_restart() {
    let agent_pki = test_pki("edge.test");
    let snapshot_pki = test_pki("control-plane.test");
    let (database, directory) = snapshot_temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    repository
        .commit(&versioned_snapshot(
            &agent_pki,
            1,
            TunnelStatus::Enabled,
            false,
        ))
        .unwrap();

    let snapshot_tls = SnapshotServerTlsConfig::from_pem(
        snapshot_pki.server.certificate_pem.as_bytes(),
        snapshot_pki.server.private_key_pem.as_bytes(),
        snapshot_pki.authority_pem.as_bytes(),
        Duration::from_secs(1),
    )
    .unwrap();
    let server_config = |listen_addr| SnapshotServerConfig {
        listen_addr,
        max_edge_clients: 4,
        request_timeout: Duration::from_secs(1),
        tls: snapshot_tls.clone(),
    };
    let control_plane = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database.clone(),
        refresh_interval: Duration::from_millis(20),
        snapshot_server: server_config("127.0.0.1:0".parse().unwrap()),
    })
    .await
    .unwrap();
    let snapshot_addr = control_plane.local_addr();
    let (control_trigger, control_signal) = shutdown_channel();
    let control_task = tokio::spawn(control_plane.run_until_shutdown(control_signal));

    let raw_addr = unused_addr().await;
    let mut edge_config = edge_config(raw_addr);
    edge_config.multiplex.security = edge_tls_security(&agent_pki, Duration::from_secs(1));
    let mut snapshot_client = SnapshotClientConfig::from_pem(
        snapshot_addr,
        snapshot_pki.authority_pem.as_bytes(),
        snapshot_pki.client.certificate_pem.as_bytes(),
        snapshot_pki.client.private_key_pem.as_bytes(),
        "control-plane.test",
    )
    .unwrap();
    snapshot_client.connect_timeout = Duration::from_secs(1);
    snapshot_client.handshake_timeout = Duration::from_secs(1);
    snapshot_client.subscribe_timeout = Duration::from_secs(1);
    snapshot_client.reconnect_initial_delay = Duration::from_millis(20);
    snapshot_client.reconnect_max_delay = Duration::from_millis(100);
    let edge = SnapshotAwareEdgeRuntime::bind(edge_config, snapshot_client)
        .await
        .unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let (local_addr, local_task) = spawn_echo().await;
    let agent = secure_agent_runtime(edge_addr, local_addr, &agent_pki);
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"snapshot-aware-edge").await;

    repository
        .commit(&versioned_snapshot(
            &agent_pki,
            2,
            TunnelStatus::Enabled,
            true,
        ))
        .unwrap();
    wait_for_authorization_status(&router, 2, AuthorizationSourceStatus::Live).await;

    control_trigger.shutdown();
    control_task.await.unwrap().unwrap();
    wait_for_authorization_status(&router, 2, AuthorizationSourceStatus::Stale).await;

    let restarted = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database,
        refresh_interval: Duration::from_millis(20),
        snapshot_server: server_config(snapshot_addr),
    })
    .await
    .unwrap();
    let (restarted_trigger, restarted_signal) = shutdown_channel();
    let restarted_task = tokio::spawn(restarted.run_until_shutdown(restarted_signal));
    wait_for_authorization_status(&router, 2, AuthorizationSourceStatus::Live).await;

    agent_trigger.shutdown();
    edge_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    edge_task.await.unwrap().unwrap();
    restarted_trigger.shutdown();
    restarted_task.await.unwrap().unwrap();
    local_task.await.unwrap();
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn snapshot_bootstrap_failure_does_not_bind_edge_listeners() {
    let agent_pki = test_pki("edge.test");
    let snapshot_pki = test_pki("control-plane.test");
    let agent_addr = unused_addr().await;
    let raw_addr = unused_addr().await;
    let unavailable_snapshot = unused_addr().await;
    let mut edge_config = edge_config(raw_addr);
    edge_config.multiplex.agent_listener.listen_addr = agent_addr;
    edge_config.multiplex.security = edge_tls_security(&agent_pki, Duration::from_secs(1));
    let mut snapshot_client = SnapshotClientConfig::from_pem(
        unavailable_snapshot,
        snapshot_pki.authority_pem.as_bytes(),
        snapshot_pki.client.certificate_pem.as_bytes(),
        snapshot_pki.client.private_key_pem.as_bytes(),
        "control-plane.test",
    )
    .unwrap();
    snapshot_client.connect_timeout = Duration::from_millis(100);

    assert!(SnapshotAwareEdgeRuntime::bind(edge_config, snapshot_client)
        .await
        .is_err());
    let agent_listener = TcpListener::bind(agent_addr).await.unwrap();
    let raw_listener = TcpListener::bind(raw_addr).await.unwrap();
    drop(agent_listener);
    drop(raw_listener);
}

#[tokio::test]
async fn snapshot_cache_cold_start_routes_then_expiry_releases_edge_listeners() {
    let agent_pki = test_pki("edge.test");
    let snapshot_pki = test_pki("control-plane.test");
    let (database, directory) = snapshot_temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    repository
        .commit(&versioned_snapshot(
            &agent_pki,
            1,
            TunnelStatus::Enabled,
            false,
        ))
        .unwrap();
    let snapshot_tls = SnapshotServerTlsConfig::from_pem(
        snapshot_pki.server.certificate_pem.as_bytes(),
        snapshot_pki.server.private_key_pem.as_bytes(),
        snapshot_pki.authority_pem.as_bytes(),
        Duration::from_secs(1),
    )
    .unwrap();
    let control_plane = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database,
        refresh_interval: Duration::from_millis(20),
        snapshot_server: SnapshotServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_edge_clients: 4,
            request_timeout: Duration::from_secs(1),
            tls: snapshot_tls,
        },
    })
    .await
    .unwrap();
    let snapshot_addr = control_plane.local_addr();
    let (control_trigger, control_signal) = shutdown_channel();
    let control_task = tokio::spawn(control_plane.run_until_shutdown(control_signal));

    let agent_addr = unused_addr().await;
    let raw_addr = unused_addr().await;
    let mut edge_config = edge_config(raw_addr);
    edge_config.multiplex.agent_listener.listen_addr = agent_addr;
    edge_config.multiplex.security = edge_tls_security(&agent_pki, Duration::from_secs(1));
    let mut snapshot_client = SnapshotClientConfig::from_pem(
        snapshot_addr,
        snapshot_pki.authority_pem.as_bytes(),
        snapshot_pki.client.certificate_pem.as_bytes(),
        snapshot_pki.client.private_key_pem.as_bytes(),
        "control-plane.test",
    )
    .unwrap();
    snapshot_client.connect_timeout = Duration::from_millis(100);
    snapshot_client.handshake_timeout = Duration::from_secs(1);
    snapshot_client.subscribe_timeout = Duration::from_secs(1);
    snapshot_client.reconnect_initial_delay = Duration::from_millis(20);
    snapshot_client.reconnect_max_delay = Duration::from_millis(50);
    let cache = SnapshotCacheConfig {
        directory: directory.join("edge-cache"),
        max_stale_age: Duration::from_secs(2),
    };

    let online = SnapshotAwareEdgeRuntime::bind_with_cache(
        edge_config.clone(),
        snapshot_client.clone(),
        cache.clone(),
    )
    .await
    .unwrap();
    assert_eq!(online.bootstrap_source(), SnapshotBootstrapSource::Online);
    let (online_trigger, online_signal) = shutdown_channel();
    online_trigger.shutdown();
    online.run_until_shutdown(online_signal).await.unwrap();
    control_trigger.shutdown();
    control_task.await.unwrap().unwrap();

    let offline = SnapshotAwareEdgeRuntime::bind_with_cache(edge_config, snapshot_client, cache)
        .await
        .unwrap();
    assert_eq!(
        offline.bootstrap_source(),
        SnapshotBootstrapSource::DiskCache
    );
    let (offline_trigger, offline_signal) = shutdown_channel();
    let offline_task = tokio::spawn(offline.run_until_shutdown(offline_signal));
    let (local_addr, local_task) = spawn_echo().await;
    let agent = secure_agent_runtime(agent_addr, local_addr, &agent_pki);
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    round_trip(raw_addr, b"cold-start-cache").await;

    let expired = timeout(Duration::from_secs(3), offline_task)
        .await
        .expect("stale Edge did not stop at the cache deadline")
        .unwrap();
    assert!(matches!(
        expired,
        Err(SnapshotAwareEdgeRuntimeError::Snapshot(
            SnapshotClientError::CacheExpired
        ))
    ));
    offline_trigger.shutdown();
    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    local_task.await.unwrap();
    let agent_listener = TcpListener::bind(agent_addr).await.unwrap();
    let raw_listener = TcpListener::bind(raw_addr).await.unwrap();
    drop(agent_listener);
    drop(raw_listener);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}
