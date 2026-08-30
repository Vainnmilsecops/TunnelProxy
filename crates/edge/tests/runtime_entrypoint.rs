//! Session 13 real-TCP coverage for process-level Edge/Agent recovery.

use std::io::{BufReader, Cursor};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::header::{CONNECTION, HOST};
use hyper::{Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use tunnelproxy_agent::{
    connect_registered_with_security, AgentError, AgentHostnameClient, AgentOperationsConfig,
    AgentOperationsRuntime, AgentRuntime, AgentRuntimeConfig, AgentRuntimeError,
    AgentRuntimeOutcome, AgentTlsConfig, AgentTlsReloadConfig, AgentTlsReloadRuntime,
    AgentTransportSecurity, ConnectOutcome, HostnameClientConfig, RuntimeShutdownConfig,
};
use tunnelproxy_common::{AgentId, TlsConfigHealth, TunnelId};
use tunnelproxy_control_plane::{
    authorization_snapshot_channel, enrollment_token_hash, AgentGrant, AuthorizationSnapshot,
    CertificateFingerprint, ControlPlaneRuntime, ControlPlaneRuntimeConfig, EnrollmentRepository,
    HostnameServer, HostnameServerConfig, HostnameServerTlsConfig, HttpsRouteRepository,
    IssuanceCandidate, ManagedHostnameBaseDomain, PersistentHttpsRouteCatalog,
    PersistentSnapshotAuthority, SnapshotBootstrapSource, SnapshotCacheConfig,
    SnapshotClientConfig, SnapshotClientError, SnapshotRepository, SnapshotServerConfig,
    SnapshotServerTlsConfig, SnapshotVersion, SqliteSnapshotRepository, TunnelGrant, TunnelStatus,
    VersionedAuthorizationSnapshot,
};
use tunnelproxy_edge::{
    shutdown_channel, AuthorizationSourceStatus, EdgeOperationsConfig, EdgeRegistrationPolicy,
    EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeError, EdgeSessionRouter, EdgeTlsConfig,
    EdgeTlsReloadConfig, EdgeTlsReloadRuntime, EdgeTransportSecurity, Http2IngressConfig,
    HttpHostRoutes, HttpHostname, HttpIngressConfig, HttpIngressExposurePolicy,
    HttpRequestRateLimitConfig, PublicHttpProtocolPolicy, PublicTlsConfig, PublicTlsReloadConfig,
    PublicTlsReloadRuntime, RawIngressExposurePolicy, RuntimeShutdownOutcome,
    SnapshotAwareEdgeRuntime, SnapshotAwareEdgeRuntimeError, WebSocketIngressConfig,
};
use tunnelproxy_protocol::{
    EnrollmentRequestId, Frame, FrameEncoder, FrameType, HandshakeErrorCode, ProtocolError,
    RegistrationRequest, ROLE_AGENT,
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

fn write_reload_manifest(path: &PathBuf, generation: u64, files: &[(&str, &PathBuf)]) {
    let entries = files
        .iter()
        .map(|(name, path)| {
            let digest = Sha256::digest(std::fs::read(path).unwrap());
            let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            format!(r#""{name}":"{digest}""#)
        })
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(
        path,
        format!(r#"{{"generation":{generation},"files":{{{entries}}}}}"#),
    )
    .unwrap();
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

fn public_tls_client_config(authority_pem: &str, alpn: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(Cursor::new(authority_pem.as_bytes()));
    for certificate in rustls_pemfile::certs(&mut reader) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
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

async fn read_http_head<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    timeout(Duration::from_secs(2), async {
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
    })
    .await
    .expect("HTTP head timed out");
    response
}

async fn wait_for_tunnel(router: &EdgeSessionRouter, tunnel_id: &str) {
    let tunnel_id = TunnelId::new(tunnel_id).unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if router.resolve_tunnel(&tunnel_id).await.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Agent did not become routable");
}

async fn operations_request(addr: SocketAddr, method: &str, path: &str) -> String {
    try_operations_request(addr, method, path)
        .await
        .expect("operations endpoint closed without a response")
}

async fn try_operations_request(addr: SocketAddr, method: &str, path: &str) -> Option<String> {
    let mut socket = connect_eventually(addr).await;
    if socket
        .write_all(
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .is_err()
    {
        return None;
    }
    let mut response = Vec::new();
    if socket.read_to_end(&mut response).await.is_err() && response.is_empty() {
        return None;
    }
    String::from_utf8(response)
        .ok()
        .filter(|value| !value.is_empty())
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

async fn spawn_concurrent_echo(
    connection_count: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut handlers = Vec::with_capacity(connection_count);
        for _ in 0..connection_count {
            let (mut socket, _) = listener.accept().await.unwrap();
            handlers.push(tokio::spawn(async move {
                let mut buffer = [0_u8; 8192];
                loop {
                    let count = socket.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        let _ = socket.shutdown().await;
                        break;
                    }
                    socket.write_all(&buffer[..count]).await.unwrap();
                }
            }));
        }
        for handler in handlers {
            handler.await.unwrap();
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
async fn operations_endpoint_tracks_raw_readiness_metrics_and_lifecycle() {
    let raw_addr = unused_addr().await;
    let operations_addr = unused_addr().await;
    let (local_addr, local_task) = spawn_echo().await;
    let mut config = edge_config(raw_addr);
    config.operations = Some(EdgeOperationsConfig::loopback(operations_addr));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let health = operations_request(operations_addr, "GET", "/healthz").await;
    assert!(health.starts_with("HTTP/1.1 200 OK"));
    assert!(health.ends_with("ok\n"));
    assert_eq!(
        operations_request(operations_addr, "GET", "/readyz")
            .await
            .split("\r\n")
            .next(),
        Some("HTTP/1.1 503 Service Unavailable")
    );
    assert!(operations_request(operations_addr, "POST", "/metrics")
        .await
        .starts_with("HTTP/1.1 405 Method Not Allowed"));
    assert!(operations_request(operations_addr, "GET", "/missing")
        .await
        .starts_with("HTTP/1.1 404 Not Found"));

    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    timeout(Duration::from_secs(2), async {
        while router
            .resolve_tunnel(&TunnelId::new("tunnel-dev").unwrap())
            .await
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Agent did not become routable");
    assert!(operations_request(operations_addr, "GET", "/readyz")
        .await
        .starts_with("HTTP/1.1 200 OK"));
    round_trip(raw_addr, b"operations-metrics").await;

    let metrics = operations_request(operations_addr, "GET", "/metrics").await;
    assert!(metrics.starts_with("HTTP/1.1 200 OK"));
    assert!(metrics.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(metrics.contains("tunnelproxy_edge_ready 1\n"));
    assert!(metrics.contains("tunnelproxy_edge_ingress_mode_raw 1\n"));
    assert!(metrics.contains("tunnelproxy_edge_raw_accepted_connections_total 1\n"));
    assert!(metrics.contains("tunnelproxy_edge_authorization_source{source=\"static\"} 1\n"));
    assert!(!metrics.contains("tunnel-dev"));
    assert!(!metrics.contains("127.0.0.1"));
    assert!(!metrics.contains("agent-dev"));

    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            let ready = operations_request(operations_addr, "GET", "/readyz").await;
            if ready.starts_with("HTTP/1.1 503 Service Unavailable") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operations readiness did not observe Agent disconnect");

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let operations = outcome.operations.expect("operations outcome");
    assert!(!operations.was_forced());
    assert!(operations.accepted_connections >= 7);
    assert_eq!(operations.rejected_requests, 2);
    local_task.await.unwrap();
    wait_until_bindable(raw_addr).await;
    wait_until_bindable(operations_addr).await;
}

#[tokio::test]
async fn concurrent_transport_load_is_visible_without_identity_or_payload_labels() {
    let stream_count = 4_usize;
    let payload_size = 256 * 1024;
    let expected_bytes = stream_count * payload_size;
    let (local_addr, local_task) = spawn_concurrent_echo(stream_count).await;
    let raw_addr = unused_addr().await;
    let edge_operations_addr = unused_addr().await;
    let mut edge_config = edge_config(raw_addr);
    edge_config.multiplex.data_queue_capacity = 2;
    edge_config.multiplex.per_stream_queue_capacity = 64;
    edge_config.operations = Some(EdgeOperationsConfig::loopback(edge_operations_addr));
    let edge = EdgeRuntime::bind(edge_config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let mut agent_config = AgentRuntimeConfig::new(edge_addr, local_addr);
    agent_config.connect_timeout = Duration::from_secs(1);
    agent_config.handshake_timeout = Duration::from_secs(1);
    agent_config.multiplex.connect_timeout = Duration::from_secs(1);
    agent_config.multiplex.stream_idle_timeout = Duration::from_secs(5);
    agent_config.multiplex.data_queue_capacity = 2;
    agent_config.multiplex.per_stream_queue_capacity = 64;
    agent_config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    agent_config.reconnect.initial_delay = Duration::from_millis(10);
    agent_config.reconnect.max_delay = Duration::from_millis(40);
    agent_config.reconnect.jitter_percent = 0;
    let agent = AgentRuntime::new(agent_config).unwrap();
    let agent_operations = AgentOperationsRuntime::bind(
        AgentOperationsConfig::loopback("127.0.0.1:0".parse().unwrap()),
        agent.status_handle(),
    )
    .await
    .unwrap();
    let agent_operations_addr = agent_operations.local_addr();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let (agent_operations_trigger, agent_operations_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    let agent_operations_task =
        tokio::spawn(agent_operations.run_until_shutdown(agent_operations_signal));

    wait_for_tunnel(&router, "tunnel-dev").await;
    let mut streams = Vec::with_capacity(stream_count);
    for index in 0..stream_count {
        let payload: Vec<u8> = (0..payload_size)
            .map(|offset| ((offset + index * 31) % 251) as u8)
            .collect();
        streams.push(tokio::spawn(async move {
            round_trip(raw_addr, &payload).await;
        }));
    }
    for stream in streams {
        stream.await.unwrap();
    }
    local_task.await.unwrap();

    let edge_metrics = operations_request(edge_operations_addr, "GET", "/metrics").await;
    let agent_metrics = operations_request(agent_operations_addr, "GET", "/metrics").await;
    let expected_bytes = expected_bytes.to_string();
    for (metrics, prefix) in [
        (&edge_metrics, "tunnelproxy_edge_transport"),
        (&agent_metrics, "tunnelproxy_agent_transport"),
    ] {
        assert!(metrics.contains(&format!(
            "{prefix}_data_bytes_total{{direction=\"sent\"}} {expected_bytes}"
        )));
        assert!(metrics.contains(&format!(
            "{prefix}_data_bytes_total{{direction=\"received\"}} {expected_bytes}"
        )));
        assert!(metrics.contains(&format!("{prefix}_data_frames_total")));
        assert!(metrics.contains(&format!("{prefix}_peak_data_pipeline_frames")));
        assert!(metrics.contains(&format!("{prefix}_data_pipeline_frames 0")));
        assert!(metrics.contains(&format!("{prefix}_data_pipeline_capacity_frames 2")));
        assert!(metrics.contains(&format!("{prefix}_data_admission_waits_total")));
        assert!(!metrics.contains("agent-dev"));
        assert!(!metrics.contains("tunnel-dev"));
        assert!(!metrics.contains("session36-secret-payload"));
    }

    agent_trigger.shutdown();
    agent_operations_trigger.shutdown();
    edge_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    agent_operations_task.await.unwrap().unwrap();
    edge_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn operations_connection_capacity_rejects_then_releases_with_raii() {
    let raw_addr = unused_addr().await;
    let operations_addr = unused_addr().await;
    let mut operations = EdgeOperationsConfig::loopback(operations_addr);
    operations.max_concurrent_connections = 1;
    let mut config = edge_config(raw_addr);
    config.operations = Some(operations);
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let held = connect_eventually(operations_addr).await;
    let mut rejected = TcpStream::connect(operations_addr).await.unwrap();
    rejected
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = rejected.read_to_end(&mut response).await;
    assert!(response.is_empty());

    drop(held);
    timeout(Duration::from_secs(2), async {
        loop {
            let response = try_operations_request(operations_addr, "GET", "/healthz").await;
            if response.is_some_and(|value| value.starts_with("HTTP/1.1 200 OK")) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operations connection permit was not released");

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let operations = outcome.operations.unwrap();
    assert!(operations.capacity_rejections >= 1);
    assert_eq!(operations.accepted_connections, 2);
    wait_until_bindable(raw_addr).await;
    wait_until_bindable(operations_addr).await;
}

#[tokio::test]
async fn operations_readiness_turns_false_and_remains_observable_during_raw_drain() {
    let raw_addr = unused_addr().await;
    let operations_addr = unused_addr().await;
    let (local_addr, local_task) = spawn_echo().await;
    let mut config = edge_config(raw_addr);
    config.operations = Some(EdgeOperationsConfig::loopback(operations_addr));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    timeout(Duration::from_secs(2), async {
        while router
            .resolve_tunnel(&TunnelId::new("tunnel-dev").unwrap())
            .await
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Agent did not become routable");

    let mut raw = connect_eventually(raw_addr).await;
    raw.write_all(b"x").await.unwrap();
    let mut echoed = [0_u8; 1];
    raw.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"x");
    assert!(operations_request(operations_addr, "GET", "/readyz")
        .await
        .starts_with("HTTP/1.1 200 OK"));

    edge_trigger.shutdown();
    timeout(Duration::from_secs(1), async {
        loop {
            if let Some(response) = try_operations_request(operations_addr, "GET", "/readyz").await
            {
                if response.starts_with("HTTP/1.1 503 Service Unavailable") {
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operations endpoint did not remain observable during ingress drain");

    drop(raw);
    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    let outcome = edge_task.await.unwrap().unwrap();
    assert!(!outcome.was_forced());
    assert!(outcome.operations.is_some());
    local_task.await.unwrap();
    wait_until_bindable(raw_addr).await;
    wait_until_bindable(operations_addr).await;
}

#[tokio::test]
async fn operations_bind_failure_rolls_back_raw_and_agent_listeners() {
    let raw_addr = unused_addr().await;
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let operations_addr = blocker.local_addr().unwrap();
    let mut config = edge_config(raw_addr);
    config.operations = Some(EdgeOperationsConfig::loopback(operations_addr));
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let agent_addr = edge.agent_addr();
    let (_, signal) = shutdown_channel();
    assert!(matches!(
        edge.run_until_shutdown(signal).await,
        Err(EdgeRuntimeError::OperationsStartup(_))
    ));
    drop(blocker);
    wait_until_bindable(raw_addr).await;
    wait_until_bindable(agent_addr).await;
}

#[tokio::test]
async fn https_ingress_routes_exact_host_and_replaces_spoofed_forwarding_headers() {
    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    let local_task = tokio::spawn(async move {
        let (mut socket, _) = local_listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let count = socket.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = captured_tx.send(String::from_utf8(request).unwrap());
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024 * 1024,
        max_requests_per_connection: 1,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(3),
        duplex_capacity: 64 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let agent = agent_runtime(edge_addr, local_addr);
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    timeout(Duration::from_secs(2), async {
        loop {
            if router
                .resolve_tunnel(&TunnelId::new("tunnel-dev").unwrap())
                .await
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Agent did not become routable");

    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));
    let tcp = connect_eventually(https_addr).await;
    let mut tls = connector
        .connect(ServerName::try_from("demo.example.test").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        b"GET /hello HTTP/1.1\r\nHost: demo.example.test\r\nForwarded: for=spoofed\r\nX-Forwarded-For: spoofed\r\nX-Forwarded-Proto: http\r\nConnection: x-remove\r\nX-Remove: secret\r\n\r\n",
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("\r\n\r\nok"));

    let captured = captured_rx.await.unwrap().to_ascii_lowercase();
    assert!(captured.starts_with("get /hello http/1.1\r\n"));
    assert!(captured.contains("host: demo.example.test\r\n"));
    assert!(captured.contains("x-forwarded-for: 127.0.0.1\r\n"));
    assert!(captured.contains("x-forwarded-proto: https\r\n"));
    assert!(captured.contains("x-forwarded-host: demo.example.test\r\n"));
    assert!(!captured.contains("spoofed"));
    assert!(!captured.contains("x-remove"));

    agent_trigger.shutdown();
    let _ = agent_task.await.unwrap().unwrap();
    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    assert_eq!(outcome.raw_addr, None);
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.completed_requests, 1);
    assert_eq!(https.rejected_requests, 0);
    local_task.await.unwrap();
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn http2_multiplexes_bounded_streams_and_rejects_authority_fronting() {
    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let (captured_tx, mut captured_rx) = tokio::sync::mpsc::channel(5);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let local_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..5 {
            let (mut socket, _) = local_listener.accept().await.unwrap();
            let captured_tx = captured_tx.clone();
            let barrier = Arc::clone(&barrier);
            tasks.spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let count = socket.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                captured_tx
                    .send(String::from_utf8(request.clone()).unwrap())
                    .await
                    .unwrap();
                if index < 2 {
                    barrier.wait().await;
                }
                if request.windows(9).any(|window| window == b"GET /slow") {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = socket.shutdown().await;
            });
        }
        while tasks.join_next().await.is_some() {}
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem_with_protocols(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
            PublicHttpProtocolPolicy::Http1AndHttp2,
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 2,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 1,
        http2: Some(Http2IngressConfig {
            max_concurrent_streams: 2,
            keep_alive_interval: Duration::from_secs(1),
            keep_alive_timeout: Duration::from_secs(1),
        }),
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_millis(200),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let agent = agent_runtime(edge_addr, local_addr);
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(public_tls_client_config(&public_pki.authority_pem, b"h2"));
    let tcp = connect_eventually(https_addr).await;
    let tls = connector
        .connect(ServerName::try_from("demo.example.test").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let request = |path: &'static str, host: Option<&'static str>| {
        let builder = Request::builder().uri(format!("https://demo.example.test{path}"));
        let builder = match host {
            Some(host) => builder.header(HOST, host),
            None => builder,
        };
        builder.body(Full::new(Bytes::new())).unwrap()
    };
    let mut second_sender = sender.clone();
    let (first, second) = tokio::join!(
        sender.send_request(request("/one", None)),
        second_sender.send_request(request("/two", Some("demo.example.test"))),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(first.into_body().collect().await.unwrap().to_bytes(), "ok");
    assert_eq!(second.into_body().collect().await.unwrap().to_bytes(), "ok");

    let oversized = sender
        .send_request(
            Request::builder()
                .uri("https://demo.example.test/oversized")
                .header(HOST, "demo.example.test")
                .body(Full::new(Bytes::from(vec![0_u8; 1025])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let _ = oversized.into_body().collect().await.unwrap();

    let mut fast_sender = sender.clone();
    let (slow, fast) = tokio::join!(
        sender.send_request(request("/slow", Some("demo.example.test"))),
        fast_sender.send_request(request("/fast", Some("demo.example.test"))),
    );
    let slow = slow.unwrap();
    let fast = fast.unwrap();
    assert_eq!(slow.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(fast.status(), StatusCode::OK);
    let _ = slow.into_body().collect().await.unwrap();
    assert_eq!(fast.into_body().collect().await.unwrap().to_bytes(), "ok");

    let fronted = sender
        .send_request(request("/fronted", Some("other.example.test")))
        .await
        .unwrap();
    assert_eq!(fronted.status(), StatusCode::MISDIRECTED_REQUEST);
    let _ = fronted.into_body().collect().await.unwrap();
    drop(sender);
    drop(second_sender);
    drop(fast_sender);
    connection_task.await.unwrap().unwrap();

    let connector = TlsConnector::from(public_tls_client_config(
        &public_pki.authority_pem,
        b"http/1.1",
    ));
    let tls = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            connect_eventually(https_addr).await,
        )
        .await
        .unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    let (mut fallback, fallback_connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let fallback_task = tokio::spawn(fallback_connection);
    let response = fallback
        .send_request(
            Request::builder()
                .uri("/fallback")
                .header(HOST, "demo.example.test")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "ok"
    );
    fallback_task.await.unwrap().unwrap();

    let connector = TlsConnector::from(public_tls_client_config(&public_pki.authority_pem, b"h2"));
    let idle_tls = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            connect_eventually(https_addr).await,
        )
        .await
        .unwrap();
    let (idle_sender, idle_connection): (hyper::client::conn::http2::SendRequest<Empty<Bytes>>, _) =
        hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(idle_tls))
            .await
            .unwrap();
    let idle_connection_task = tokio::spawn(idle_connection);

    let mut captured = Vec::new();
    for _ in 0..5 {
        captured.push(captured_rx.recv().await.unwrap().to_ascii_lowercase());
    }
    captured.sort();
    assert!(captured[0].starts_with("get /fallback http/1.1\r\n"));
    assert!(captured[1].starts_with("get /fast http/1.1\r\n"));
    assert!(captured[2].starts_with("get /one http/1.1\r\n"));
    assert!(captured[3].starts_with("get /slow http/1.1\r\n"));
    assert!(captured[4].starts_with("get /two http/1.1\r\n"));
    assert!(captured
        .iter()
        .all(|request| request.contains("host: demo.example.test\r\n")));

    local_task.await.unwrap();
    agent_trigger.shutdown();
    let _ = agent_task.await.unwrap().unwrap();
    edge_trigger.shutdown();
    timeout(Duration::from_millis(500), idle_connection_task)
        .await
        .expect("idle HTTP/2 connection did not receive graceful shutdown")
        .unwrap()
        .unwrap();
    drop(idle_sender);
    let outcome = edge_task.await.unwrap().unwrap();
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.http1_connections, 1);
    assert_eq!(https.http2_connections, 2);
    assert!(https.peak_active_http2_streams >= 2);
    assert_eq!(https.completed_requests, 4);
    assert_eq!(https.rejected_requests, 3);
    assert_eq!(https.request_timeouts, 1);
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn websocket_upgrade_relays_frames_and_releases_bounded_capacity() {
    const REQUEST: &[u8] = b"GET /socket HTTP/1.1\r\nHost: demo.example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nForwarded: for=spoofed\r\nX-Forwarded-For: spoofed\r\n\r\n";
    const FRONTED_REQUEST: &[u8] = b"GET /socket HTTP/1.1\r\nHost: other.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    const INVALID_REQUEST: &[u8] = b"GET /socket HTTP/1.1\r\nHost: demo.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: not-a-valid-key\r\n\r\n";
    const SWITCHING: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\n\r\n";
    const INVALID_SWITCHING: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: invalid\r\nSec-WebSocket-Protocol: chat\r\n\r\n";
    const CLIENT_TEXT_FRAME: &[u8] = &[0x81, 0x85, 1, 2, 3, 4, 105, 103, 111, 104, 110];
    const SERVER_FRAMES: &[u8] = &[0x82, 0x02, b'o', b'k', 0x89, 0x00];

    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_task = tokio::spawn(async move {
        let mut captured = Vec::new();
        for index in 0..3 {
            let (mut socket, _) = local_listener.accept().await.unwrap();
            let request = read_http_head(&mut socket).await;
            captured.push(String::from_utf8(request).unwrap());
            socket
                .write_all(if index == 1 {
                    INVALID_SWITCHING
                } else {
                    SWITCHING
                })
                .await
                .unwrap();
            if index == 0 {
                let mut frame = [0_u8; CLIENT_TEXT_FRAME.len()];
                socket.read_exact(&mut frame).await.unwrap();
                assert_eq!(&frame, CLIENT_TEXT_FRAME);
                socket.write_all(SERVER_FRAMES).await.unwrap();
            }
            let mut trailing = Vec::new();
            let _ = socket.read_to_end(&mut trailing).await;
            assert!(trailing.is_empty());
        }
        captured
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 2,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 1,
        http2: None,
        websocket: Some(WebSocketIngressConfig {
            max_concurrent_sessions: 1,
            idle_timeout: Duration::from_secs(2),
        }),
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let agent = agent_runtime(edge_addr, local_addr);
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(public_tls_client_config(
        &public_pki.authority_pem,
        b"http/1.1",
    ));
    let connect = || async {
        connector
            .connect(
                ServerName::try_from("demo.example.test").unwrap(),
                connect_eventually(https_addr).await,
            )
            .await
            .unwrap()
    };

    let mut first = connect().await;
    first.write_all(REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut first).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    assert!(response.contains("sec-websocket-protocol: chat\r\n"));
    first.write_all(CLIENT_TEXT_FRAME).await.unwrap();
    let mut server_frames = [0_u8; SERVER_FRAMES.len()];
    first.read_exact(&mut server_frames).await.unwrap();
    assert_eq!(&server_frames, SERVER_FRAMES);

    let mut capacity_rejected = connect().await;
    capacity_rejected.write_all(REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut capacity_rejected).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    drop(capacity_rejected);

    let mut malformed = connect().await;
    malformed.write_all(INVALID_REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut malformed).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    drop(malformed);

    let mut fronted = connect().await;
    fronted.write_all(FRONTED_REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut fronted).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 421 Misdirected Request\r\n"));
    drop(fronted);

    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut invalid_local = connect().await;
    invalid_local.write_all(REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut invalid_local).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    drop(invalid_local);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let mut replacement = connect().await;
    replacement.write_all(REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut replacement).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    drop(replacement);

    let captured = local_task.await.unwrap();
    assert_eq!(captured.len(), 3);
    for request in captured {
        let request = request.to_ascii_lowercase();
        assert!(request.starts_with("get /socket http/1.1\r\n"));
        assert!(request.contains("host: demo.example.test\r\n"));
        assert!(request.contains("connection: upgrade\r\n"));
        assert!(request.contains("upgrade: websocket\r\n"));
        assert!(request.contains("sec-websocket-protocol: chat, superchat\r\n"));
        assert!(request.contains("x-forwarded-for: 127.0.0.1\r\n"));
        assert!(!request.contains("spoofed"));
    }

    agent_trigger.shutdown();
    let _ = agent_task.await.unwrap().unwrap();
    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.accepted_websocket_upgrades, 2);
    assert_eq!(https.rejected_websocket_upgrades, 4);
    assert_eq!(https.peak_active_websocket_sessions, 1);
    assert_eq!(https.websocket_idle_timeouts, 0);
    assert_eq!(https.completed_requests, 2);
    assert_eq!(https.rejected_requests, 4);
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn websocket_idle_timeout_and_forced_shutdown_are_bounded() {
    const REQUEST: &[u8] = b"GET /socket HTTP/1.1\r\nHost: demo.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    const SWITCHING: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = local_listener.accept().await.unwrap();
            let _ = read_http_head(&mut socket).await;
            socket.write_all(SWITCHING).await.unwrap();
            let mut trailing = Vec::new();
            let _ = socket.read_to_end(&mut trailing).await;
            assert!(trailing.is_empty());
        }
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_millis(30));
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 1,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 1,
        http2: None,
        websocket: Some(WebSocketIngressConfig {
            max_concurrent_sessions: 1,
            idle_timeout: Duration::from_millis(500),
        }),
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_millis(30)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let agent = agent_runtime(edge_addr, local_addr);
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(public_tls_client_config(
        &public_pki.authority_pem,
        b"http/1.1",
    ));
    let connect = || async {
        connector
            .connect(
                ServerName::try_from("demo.example.test").unwrap(),
                connect_eventually(https_addr).await,
            )
            .await
            .unwrap()
    };
    let mut idle = connect().await;
    idle.write_all(REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut idle).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    let mut byte = [0_u8; 1];
    let idle_closed = timeout(Duration::from_secs(1), idle.read(&mut byte))
        .await
        .expect("idle WebSocket was not closed");
    assert!(matches!(idle_closed, Ok(0) | Err(_)));
    drop(idle);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let mut active = connect().await;
    active.write_all(REQUEST).await.unwrap();
    let response = String::from_utf8(read_http_head(&mut active).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    edge_trigger.shutdown();
    let outcome = timeout(Duration::from_secs(1), edge_task)
        .await
        .expect("Edge WebSocket drain exceeded its bound")
        .unwrap()
        .unwrap();
    let forced_closed = timeout(Duration::from_millis(500), active.read(&mut byte))
        .await
        .expect("forced WebSocket was not closed");
    assert!(matches!(forced_closed, Ok(0) | Err(_)));
    drop(active);

    agent_trigger.shutdown();
    let _ = agent_task.await.unwrap().unwrap();
    local_task.await.unwrap();
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.accepted_websocket_upgrades, 2);
    assert_eq!(https.rejected_websocket_upgrades, 0);
    assert_eq!(https.peak_active_websocket_sessions, 1);
    assert_eq!(https.websocket_idle_timeouts, 1);
    assert!(matches!(
        https.shutdown,
        RuntimeShutdownOutcome::Forced {
            aborted_tasks: 1,
            ..
        }
    ));
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn managed_hostname_allocation_activates_end_to_end_https_without_auto_release() {
    let agent_pki = test_pki("edge.test");
    let public_pki = test_pki("*.agents.example.test");
    let versioned = versioned_snapshot(&agent_pki, 1, TunnelStatus::Enabled, false);
    let (_authorization_publisher, authorization) = authorization_snapshot_channel(versioned);
    let (database, directory) = snapshot_temp_database();
    let routes = PersistentHttpsRouteCatalog::open(HttpsRouteRepository::open(&database).unwrap())
        .await
        .unwrap();
    let dynamic_routes = routes.subscribe();

    let hostname_server = HostnameServer::bind(
        HostnameServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_clients: 4,
            request_timeout: Duration::from_secs(2),
            base_domain: ManagedHostnameBaseDomain::new("agents.example.test").unwrap(),
            tls: HostnameServerTlsConfig::from_pem(
                agent_pki.server.certificate_pem.as_bytes(),
                agent_pki.server.private_key_pem.as_bytes(),
                agent_pki.authority_pem.as_bytes(),
                Duration::from_secs(1),
            )
            .unwrap(),
        },
        authorization.clone(),
        routes.clone(),
    )
    .await
    .unwrap();
    let hostname_addr = hostname_server.local_addr();
    let (hostname_trigger, hostname_signal) = shutdown_channel();
    let hostname_task = tokio::spawn(hostname_server.run_until_shutdown(hostname_signal));

    let https_addr = unused_addr().await;
    let mut edge_config = edge_config(unused_addr().await);
    edge_config.multiplex.security = edge_tls_security(&agent_pki, Duration::from_secs(1));
    edge_config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls_updates(authorization);
    edge_config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::dynamic(dynamic_routes),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 1,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(3),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(edge_config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));

    let hostname_client = AgentHostnameClient::new(HostnameClientConfig {
        server_addr: hostname_addr,
        server_name: "edge.test".to_owned(),
        server_ca_pem: agent_pki.authority_pem.as_bytes().to_vec(),
        client_cert_pem: agent_pki.client.certificate_pem.as_bytes().to_vec(),
        client_key_pem: agent_pki.client.private_key_pem.as_bytes().to_vec(),
        connect_timeout: Duration::from_secs(1),
        handshake_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
    })
    .unwrap();
    let allocated = hostname_client
        .allocate(
            AgentId::new("agent-dev").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        )
        .await
        .unwrap();
    assert!(allocated.changed);
    assert!(allocated
        .hostname
        .as_str()
        .ends_with(".agents.example.test"));

    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_task = tokio::spawn(async move {
        let (mut socket, _) = local_listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let count = socket.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8(request)
            .unwrap()
            .starts_with("GET /managed HTTP/1.1\r\n"));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmanaged")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });

    let mut agent_config = AgentRuntimeConfig::new(edge_addr, local_addr);
    agent_config.security =
        agent_tls_security(&agent_pki.authority_pem, &agent_pki.client, "edge.test");
    agent_config.connect_timeout = Duration::from_secs(1);
    agent_config.handshake_timeout = Duration::from_secs(1);
    agent_config.shutdown = RuntimeShutdownConfig::new(Duration::from_secs(1));
    let agent = AgentRuntime::new(agent_config).unwrap();
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(agent.run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));
    let tcp = connect_eventually(https_addr).await;
    let server_name = ServerName::try_from(allocated.hostname.as_str().to_owned()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(
        format!(
            "GET /managed HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            allocated.hostname
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("\r\n\r\nmanaged"));

    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    let repeated = hostname_client
        .allocate(
            AgentId::new("agent-dev").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        )
        .await
        .unwrap();
    assert!(!repeated.changed);
    assert_eq!(repeated.hostname, allocated.hostname);
    assert_eq!(repeated.catalog_version, allocated.catalog_version);
    let durable = HttpsRouteRepository::open(&database)
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(durable.routes().len(), 1);
    assert_eq!(durable.routes()[0].hostname, allocated.hostname);

    edge_trigger.shutdown();
    edge_task.await.unwrap().unwrap();
    hostname_trigger.shutdown();
    hostname_task.await.unwrap().unwrap();
    local_task.await.unwrap();
    drop(routes);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn https_keep_alive_reuses_one_tls_connection_until_the_request_cap() {
    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_task = tokio::spawn(async move {
        for response_body in [b"one".as_slice(), b"two".as_slice()] {
            let (mut socket, _) = local_listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let count = socket.read(&mut chunk).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(response_body).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 2,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));
    let tls = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            connect_eventually(https_addr).await,
        )
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);

    let first = sender
        .send_request(
            Request::builder()
                .uri("/one")
                .header(HOST, "demo.example.test")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert!(first.headers().get(CONNECTION).is_none());
    assert_eq!(first.into_body().collect().await.unwrap().to_bytes(), "one");

    let second = sender
        .send_request(
            Request::builder()
                .uri("/two")
                .header(HOST, "demo.example.test")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(second.headers().get(CONNECTION).unwrap(), "close");
    assert_eq!(
        second.into_body().collect().await.unwrap().to_bytes(),
        "two"
    );
    connection_task.await.unwrap().unwrap();

    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.accepted_connections, 1);
    assert_eq!(https.completed_requests, 2);
    assert_eq!(https.reused_requests, 1);
    assert_eq!(https.request_timeouts, 0);
    local_task.await.unwrap();
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn https_request_deadline_returns_504_and_closes_the_reused_connection() {
    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_task = tokio::spawn(async move {
        let (mut socket, _) = local_listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 4,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_millis(100),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));
    let tls = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            connect_eventually(https_addr).await,
        )
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::builder()
                .uri("/slow")
                .header(HOST, "demo.example.test")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
    response.into_body().collect().await.unwrap();
    connection_task.await.unwrap().unwrap();

    local_task.await.unwrap();
    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.accepted_connections, 1);
    assert_eq!(https.admitted_requests, 1);
    assert_eq!(https.completed_requests, 0);
    assert_eq!(https.rejected_requests, 1);
    assert_eq!(https.request_timeouts, 1);
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn https_shutdown_gracefully_closes_an_idle_keep_alive_connection() {
    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_task = tokio::spawn(async move {
        let (mut socket, _) = local_listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 4,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(2),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));
    let tls = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            connect_eventually(https_addr).await,
        )
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::builder()
                .uri("/one")
                .header(HOST, "demo.example.test")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(CONNECTION).is_none());
    response.into_body().collect().await.unwrap();
    local_task.await.unwrap();

    edge_trigger.shutdown();
    timeout(Duration::from_millis(500), connection_task)
        .await
        .expect("idle keep-alive connection did not drain")
        .unwrap()
        .unwrap();
    let outcome = edge_task.await.unwrap().unwrap();
    assert!(!outcome.was_forced());
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.accepted_connections, 1);
    assert_eq!(https.completed_requests, 1);
    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn https_shutdown_forces_an_active_keep_alive_request_after_the_deadline() {
    let public_pki = test_pki("demo.example.test");
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let local_task = tokio::spawn(async move {
        let (mut socket, _) = local_listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        let _ = accepted_tx.send(());
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.shutdown = RuntimeShutdownConfig::new(Duration::from_millis(50));
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 4,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_millis(50)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    wait_for_tunnel(&router, "tunnel-dev").await;

    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));
    let tls = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            connect_eventually(https_addr).await,
        )
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let request_task = tokio::spawn(async move {
        sender
            .send_request(
                Request::builder()
                    .uri("/blocked")
                    .header(HOST, "demo.example.test")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
    });
    accepted_rx.await.unwrap();

    edge_trigger.shutdown();
    let outcome = timeout(Duration::from_secs(2), edge_task)
        .await
        .expect("Edge did not enforce the keep-alive drain deadline")
        .unwrap()
        .unwrap();
    assert!(outcome.was_forced());
    assert!(outcome.https_ingress.unwrap().was_forced());
    let _ = request_task.await;
    let _ = connection_task.await;
    agent_trigger.shutdown();
    match agent_task.await.unwrap() {
        Ok(_) => {}
        Err(AgentRuntimeError::Terminal(AgentError::ProtocolDecode(
            ProtocolError::TruncatedHeader { .. } | ProtocolError::TruncatedPayload { .. },
        ))) => {}
        Err(error) => panic!("unexpected Agent shutdown failure: {error}"),
    }
    local_task.abort();
    let _ = local_task.await;
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn https_request_rate_limit_returns_429_before_local_service_and_refills() {
    let public_pki = test_pki("demo.example.test");
    let operations_addr = unused_addr().await;
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_requests = Arc::new(AtomicUsize::new(0));
    let local_requests_for_task = Arc::clone(&local_requests);
    let local_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = local_listener.accept().await.unwrap();
            local_requests_for_task.fetch_add(1, Ordering::Relaxed);
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let count = socket.read(&mut chunk).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        }
    });

    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.operations = Some(EdgeOperationsConfig::loopback(operations_addr));
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 4,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig {
            global_requests_per_second: 2,
            global_burst: 2,
            per_ip_requests_per_second: 1,
            per_ip_burst: 1,
            max_tracked_ips: 2,
            peer_idle_ttl: Duration::from_secs(5),
        },
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(3),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task =
        tokio::spawn(agent_runtime(edge_addr, local_addr).run_until_shutdown(agent_signal));
    timeout(Duration::from_secs(2), async {
        loop {
            if router
                .resolve_tunnel(&TunnelId::new("tunnel-dev").unwrap())
                .await
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Agent did not become routable");

    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));
    let tls = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            connect_eventually(https_addr).await,
        )
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let first = sender
        .send_request(
            Request::builder()
                .uri("/limited")
                .header(HOST, "demo.example.test")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert!(first.headers().get(CONNECTION).is_none());
    first.into_body().collect().await.unwrap();
    let limited = sender
        .send_request(
            Request::builder()
                .uri("/limited")
                .header(HOST, "demo.example.test")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers().get(CONNECTION).unwrap(), "close");
    assert_eq!(limited.headers().get("retry-after").unwrap(), "1");
    limited.into_body().collect().await.unwrap();
    connection_task.await.unwrap().unwrap();

    let request = || {
        let connector = connector.clone();
        async move {
            let tcp = connect_eventually(https_addr).await;
            let mut tls = connector
                .connect(ServerName::try_from("demo.example.test").unwrap(), tcp)
                .await
                .unwrap();
            tls.write_all(
                b"GET /limited HTTP/1.1\r\nHost: demo.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut response = Vec::new();
            tls.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap()
        }
    };

    assert_eq!(local_requests.load(Ordering::Relaxed), 1);

    let mut invalid_tls = connect_eventually(https_addr).await;
    invalid_tls.write_all(b"not tls").await.unwrap();
    invalid_tls.shutdown().await.unwrap();
    let metrics = timeout(Duration::from_secs(2), async {
        loop {
            let metrics = operations_request(operations_addr, "GET", "/metrics").await;
            if metrics.contains("tunnelproxy_edge_https_tls_rejections_total 1\n") {
                break metrics;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operations metrics did not observe TLS rejection");
    assert!(metrics.contains("tunnelproxy_edge_ingress_mode_https 1\n"));
    assert!(metrics.contains("tunnelproxy_edge_https_admitted_requests_total 1\n"));
    assert!(metrics.contains("tunnelproxy_edge_https_per_ip_rate_limit_rejections_total 1\n"));
    assert!(metrics.contains("tunnelproxy_edge_https_reused_requests_total 1\n"));
    assert!(metrics.contains("tunnelproxy_edge_https_request_timeouts_total 0\n"));
    assert!(metrics.contains("tunnelproxy_edge_https_tracked_rate_limit_peers 1\n"));
    assert!(!metrics.contains("demo.example.test"));
    assert!(!metrics.contains("tunnel-dev"));

    tokio::time::sleep(Duration::from_millis(1_050)).await;
    assert!(request().await.starts_with("HTTP/1.1 200 OK"));

    agent_trigger.shutdown();
    agent_task.await.unwrap().unwrap();
    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.admitted_requests, 2);
    assert_eq!(https.completed_requests, 2);
    assert_eq!(https.rejected_requests, 1);
    assert_eq!(https.global_rate_limit_rejections, 0);
    assert_eq!(https.per_ip_rate_limit_rejections, 1);
    assert_eq!(https.rate_limit_peer_capacity_rejections, 0);
    assert_eq!(https.reused_requests, 1);
    assert_eq!(https.tracked_rate_limit_peers, 1);
    assert_eq!(https.peak_tracked_rate_limit_peers, 1);
    assert!(outcome.operations.unwrap().completed_requests >= 1);
    local_task.await.unwrap();
    wait_until_bindable(https_addr).await;
    wait_until_bindable(operations_addr).await;
}

#[tokio::test]
async fn https_ingress_rejects_host_fronting_and_fails_closed_while_offline() {
    let public_pki = test_pki("demo.example.test");
    let https_addr = unused_addr().await;
    let mut config = edge_config(unused_addr().await);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: https_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::LoopbackOnly,
        max_concurrent_connections: 4,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 1,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));

    let send = |host: &'static str| {
        let connector = connector.clone();
        async move {
            let tcp = connect_eventually(https_addr).await;
            let mut tls = connector
                .connect(ServerName::try_from("demo.example.test").unwrap(), tcp)
                .await
                .unwrap();
            tls.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = Vec::new();
            tls.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap()
        }
    };
    assert!(send("demo.example.test")
        .await
        .starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(send("other.example.test")
        .await
        .starts_with("HTTP/1.1 421 Misdirected Request"));

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let https = outcome.https_ingress.unwrap();
    assert_eq!(https.completed_requests, 0);
    assert_eq!(https.rejected_requests, 2);
    wait_until_bindable(https_addr).await;
}

#[tokio::test]
async fn public_https_per_ip_admission_releases_after_connection_close() {
    let agent_pki = test_pki("edge.test");
    let public_pki = test_pki("demo.example.test");
    let https_addr = unused_addr().await;
    let public_listen_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, https_addr.port()));
    let (_publisher, subscription) = authorization_snapshot_channel(versioned_snapshot(
        &agent_pki,
        1,
        TunnelStatus::Enabled,
        false,
    ));
    let mut config = edge_config(unused_addr().await);
    config.multiplex.security = edge_tls_security(&agent_pki, Duration::from_secs(1));
    config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls_updates(subscription);
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: public_listen_addr,
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::Public {
            max_connections_per_ip: 1,
        },
        max_concurrent_connections: 2,
        max_header_bytes: 16 * 1024,
        max_headers: 32,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 1,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(3),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let connector = TlsConnector::from(raw_tls_client_config(
        &public_pki.authority_pem,
        None,
        false,
    ));

    let first_tcp = connect_eventually(https_addr).await;
    let first = connector
        .connect(
            ServerName::try_from("demo.example.test").unwrap(),
            first_tcp,
        )
        .await
        .unwrap();
    let mut rejected = connect_eventually(https_addr).await;
    let mut byte = [0_u8; 1];
    let rejected_read = timeout(Duration::from_secs(1), rejected.read(&mut byte))
        .await
        .expect("same-IP excess HTTPS connection stayed open");
    assert!(matches!(rejected_read, Ok(0) | Err(_)));
    drop(first);

    let mut replacement = timeout(Duration::from_secs(2), async {
        loop {
            let tcp = connect_eventually(https_addr).await;
            match connector
                .connect(ServerName::try_from("demo.example.test").unwrap(), tcp)
                .await
            {
                Ok(tls) => break tls,
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .expect("per-IP permit was not released");
    replacement
        .write_all(b"GET / HTTP/1.1\r\nHost: demo.example.test\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    replacement.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8(response)
        .unwrap()
        .starts_with("HTTP/1.1 503 Service Unavailable"));

    edge_trigger.shutdown();
    let outcome = edge_task.await.unwrap().unwrap();
    let https = outcome.https_ingress.unwrap();
    assert!(https.per_ip_capacity_rejections >= 1);
    assert_eq!(https.rejected_requests, 1);
    wait_until_bindable(https_addr).await;
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
async fn durable_emergency_revoke_closes_the_exact_live_public_mtls_agent_session() {
    let pki = test_pki("edge.test");
    let (database, directory) = snapshot_temp_database();
    let snapshots = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    snapshots
        .commit(&VersionedAuthorizationSnapshot::new(
            SnapshotVersion::FIRST,
            AuthorizationSnapshot::default(),
        ))
        .unwrap();
    let credentials = EnrollmentRepository::open(&database).unwrap();
    let agent_id = AgentId::new("agent-dev").unwrap();
    let tunnel_id = TunnelId::new("tunnel-dev").unwrap();
    let bootstrap = [61; 32];
    let renewal = [62; 32];
    credentials
        .create_bootstrap_token(
            enrollment_token_hash(&bootstrap),
            &agent_id,
            &tunnel_id,
            1_000,
        )
        .unwrap();
    let issuance = IssuanceCandidate {
        request_id: EnrollmentRequestId::from_bytes([63; 16]),
        presented_token_hash: enrollment_token_hash(&bootstrap),
        next_token_hash: enrollment_token_hash(&renewal),
        agent_id: agent_id.clone(),
        tunnel_id: tunnel_id.clone(),
        csr_digest: [64; 32],
        certificate_pem: pki.client.certificate_pem.as_bytes().to_vec(),
        fingerprint: client_fingerprint(&pki.client),
        not_after_unix: 10_000,
        activation_deadline_unix: 9_000,
    };
    credentials.commit_issuance(&issuance, 100).unwrap();
    credentials
        .activate(
            issuance.request_id,
            enrollment_token_hash(&renewal),
            issuance.fingerprint,
            110,
        )
        .unwrap();
    let authority = PersistentSnapshotAuthority::open(snapshots.clone())
        .await
        .unwrap();

    let (local_addr, local_task) = spawn_echo_connections(2).await;
    let raw_addr = unused_addr().await;
    let public_listen_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, raw_addr.port()));
    let mut config = edge_config(public_listen_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration =
        EdgeRegistrationPolicy::mutual_tls_updates(authority.subscribe());
    config.raw_exposure = RawIngressExposurePolicy::Public {
        max_connections_per_ip: 4,
    };
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let router = edge.router();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (agent_trigger, agent_signal) = shutdown_channel();
    let agent_task = tokio::spawn(
        secure_agent_runtime(edge_addr, local_addr, &pki).run_until_shutdown(agent_signal),
    );
    round_trip(raw_addr, b"before-durable-revoke").await;

    let mut active = connect_eventually(raw_addr).await;
    active.write_all(b"active-durable-revoke").await.unwrap();
    let mut echoed = vec![0_u8; b"active-durable-revoke".len()];
    active.read_exact(&mut echoed).await.unwrap();
    credentials
        .revoke_agent(&agent_id, &tunnel_id, 120)
        .unwrap();
    authority.refresh_from_repository().await.unwrap();
    wait_for_authorization_status(&router, 3, AuthorizationSourceStatus::Live).await;
    assert!(router.connected_tunnels().await.is_empty());
    let mut byte = [0_u8; 1];
    let closed = timeout(Duration::from_secs(2), active.read(&mut byte))
        .await
        .expect("durably revoked active stream stayed open");
    assert!(matches!(closed, Ok(0) | Err(_)));

    agent_trigger.shutdown();
    edge_trigger.shutdown();
    let _ = agent_task.await;
    edge_task.await.unwrap().unwrap();
    local_task.await.unwrap();
    drop(credentials);
    drop(authority);
    drop(snapshots);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn public_raw_config_rejects_static_mtls_and_accepts_dynamic_authorization() {
    let pki = test_pki("edge.test");
    let mut config = edge_config("0.0.0.0:7000".parse().unwrap());
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = edge_tls_registration(&pki);
    config.raw_exposure = RawIngressExposurePolicy::Public {
        max_connections_per_ip: 4,
    };
    assert!(matches!(
        config.validate(),
        Err(tunnelproxy_edge::EdgeRuntimeConfigError::PublicRawRequiresLiveAuthorization)
    ));

    let (_publisher, subscription) =
        authorization_snapshot_channel(versioned_snapshot(&pki, 1, TunnelStatus::Enabled, false));
    config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls_updates(subscription);
    assert!(config.validate().is_ok());
}

#[test]
fn public_https_config_requires_agent_mtls_and_dynamic_authorization() {
    let pki = test_pki("edge.test");
    let public_pki = test_pki("demo.example.test");
    let mut config = edge_config("127.0.0.1:7000".parse().unwrap());
    config.https_ingress = Some(HttpIngressConfig {
        listen_addr: "0.0.0.0:7443".parse().unwrap(),
        routes: HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        ),
        tls: PublicTlsConfig::from_pem(
            public_pki.server.certificate_pem.as_bytes(),
            public_pki.server.private_key_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
        exposure: HttpIngressExposurePolicy::Public {
            max_connections_per_ip: 4,
        },
        max_concurrent_connections: 8,
        max_header_bytes: 16 * 1024,
        max_headers: 64,
        max_request_body_bytes: 1024,
        max_requests_per_connection: 1,
        http2: None,
        websocket: None,
        request_rate_limit: HttpRequestRateLimitConfig::default(),
        header_read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        duplex_capacity: 16 * 1024,
        shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
    });
    assert!(matches!(
        config.validate(),
        Err(tunnelproxy_edge::EdgeRuntimeConfigError::PublicHttpsRequiresMutualTls)
    ));

    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = edge_tls_registration(&pki);
    assert!(matches!(
        config.validate(),
        Err(tunnelproxy_edge::EdgeRuntimeConfigError::PublicHttpsRequiresLiveAuthorization)
    ));

    let (_publisher, subscription) =
        authorization_snapshot_channel(versioned_snapshot(&pki, 1, TunnelStatus::Enabled, false));
    config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls_updates(subscription);
    assert!(config.validate().is_ok());
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
    let public_listen_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, raw_addr.port()));
    let mut config = edge_config(public_listen_addr);
    config.multiplex.security = edge_tls_security(&pki, Duration::from_secs(1));
    config.multiplex.registration = EdgeRegistrationPolicy::mutual_tls_updates(subscription);
    config.raw_exposure = RawIngressExposurePolicy::Public {
        max_connections_per_ip: 4,
    };
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
        https_route_server: None,
        operations: None,
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
        https_route_server: None,
        operations: None,
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
        https_route_server: None,
        operations: None,
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

#[tokio::test]
async fn public_tls_generation_reload_is_atomic() {
    let first = test_pki("demo.example.test");
    let second = test_pki("demo.example.test");
    let (_unused_database, directory) = snapshot_temp_database();
    let certificate = directory.join("public.pem");
    let private_key = directory.join("public-key.pem");
    let manifest = directory.join("public-manifest.json");
    std::fs::write(&certificate, &first.server.certificate_pem).unwrap();
    std::fs::write(&private_key, &first.server.private_key_pem).unwrap();
    write_reload_manifest(
        &manifest,
        1,
        &[
            ("public_server_certificate", &certificate),
            ("public_server_private_key", &private_key),
        ],
    );
    let (tls, runtime) = PublicTlsReloadRuntime::bootstrap_with_protocols(
        PublicTlsReloadConfig {
            manifest_path: manifest.clone(),
            server_certificate_path: certificate.clone(),
            server_private_key_path: private_key.clone(),
            poll_interval: Duration::from_millis(10),
            expiry_warning: Duration::from_secs(60),
        },
        Duration::from_secs(1),
        PublicHttpProtocolPolicy::Http1AndHttp2,
    )
    .await
    .unwrap();
    assert_eq!(tls.reload_status(Duration::from_secs(60)).generation, 1);
    assert_eq!(tls.protocols(), PublicHttpProtocolPolicy::Http1AndHttp2);
    let status = tls.clone();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(runtime.run_until_shutdown(signal));

    std::fs::write(&certificate, &second.server.certificate_pem).unwrap();
    std::fs::write(&private_key, &second.server.private_key_pem).unwrap();
    write_reload_manifest(
        &manifest,
        2,
        &[
            ("public_server_certificate", &certificate),
            ("public_server_private_key", &private_key),
        ],
    );
    timeout(Duration::from_secs(2), async {
        while status.reload_status(Duration::from_secs(60)).generation != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("public TLS generation did not reload");
    assert_eq!(status.protocols(), PublicHttpProtocolPolicy::Http1AndHttp2);

    trigger.shutdown();
    task.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn tls_generation_rotation_is_atomic_and_invalid_candidate_keeps_last_good() {
    let generation_one = test_pki("edge.test");
    let generation_two = test_pki("edge.test");
    let (_, directory) = snapshot_temp_database();
    let edge_certificate = directory.join("edge.pem");
    let edge_key = directory.join("edge-key.pem");
    let agent_ca = directory.join("agent-ca.pem");
    let agent_certificate = directory.join("agent.pem");
    let agent_key = directory.join("agent-key.pem");
    let edge_ca = directory.join("edge-ca.pem");
    let edge_manifest = directory.join("edge-reload.json");
    let agent_manifest = directory.join("agent-reload.json");

    let write_generation = |pki: &TestPki| {
        std::fs::write(&edge_certificate, &pki.server.certificate_pem).unwrap();
        std::fs::write(&edge_key, &pki.server.private_key_pem).unwrap();
        std::fs::write(&agent_ca, &pki.authority_pem).unwrap();
        std::fs::write(&agent_certificate, &pki.client.certificate_pem).unwrap();
        std::fs::write(&agent_key, &pki.client.private_key_pem).unwrap();
        std::fs::write(&edge_ca, &pki.authority_pem).unwrap();
    };
    write_generation(&generation_one);
    write_reload_manifest(
        &edge_manifest,
        1,
        &[
            ("server_certificate", &edge_certificate),
            ("server_private_key", &edge_key),
            ("client_ca", &agent_ca),
            ("authorized_client_certificate", &agent_certificate),
        ],
    );
    write_reload_manifest(
        &agent_manifest,
        1,
        &[
            ("server_ca", &edge_ca),
            ("client_certificate", &agent_certificate),
            ("client_private_key", &agent_key),
        ],
    );

    let (edge_tls, registration_policy, edge_reloader) =
        EdgeTlsReloadRuntime::bootstrap_with_static_authorization(
            EdgeTlsReloadConfig {
                manifest_path: edge_manifest.clone(),
                server_certificate_path: edge_certificate.clone(),
                server_private_key_path: edge_key.clone(),
                client_ca_path: agent_ca.clone(),
                poll_interval: Duration::from_millis(20),
                expiry_warning: Duration::from_secs(60),
            },
            agent_certificate.clone(),
            Duration::from_secs(1),
            AgentId::new("agent-dev").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        )
        .await
        .unwrap();
    let (agent_tls, agent_reloader) = AgentTlsReloadRuntime::bootstrap(
        AgentTlsReloadConfig {
            manifest_path: agent_manifest.clone(),
            server_ca_path: edge_ca.clone(),
            client_certificate_path: agent_certificate.clone(),
            client_private_key_path: agent_key.clone(),
            poll_interval: Duration::from_millis(20),
            expiry_warning: Duration::from_secs(60),
        },
        "edge.test",
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let edge_status = edge_tls.clone();
    let agent_status = agent_tls.clone();

    let raw_addr = unused_addr().await;
    let mut config = edge_config(raw_addr);
    config.multiplex.security = EdgeTransportSecurity::MutualTls(edge_tls);
    config.multiplex.registration = registration_policy;
    let edge = EdgeRuntime::bind(config).await.unwrap();
    let edge_addr = edge.agent_addr();
    let (edge_trigger, edge_signal) = shutdown_channel();
    let edge_task = tokio::spawn(edge.run_until_shutdown(edge_signal));
    let (edge_reload_trigger, edge_reload_signal) = shutdown_channel();
    let edge_reload_task = tokio::spawn(edge_reloader.run_until_shutdown(edge_reload_signal));
    let (agent_reload_trigger, agent_reload_signal) = shutdown_channel();
    let agent_reload_task = tokio::spawn(agent_reloader.run_until_shutdown(agent_reload_signal));
    let registration = RegistrationRequest::new(
        AgentId::new("agent-dev").unwrap(),
        TunnelId::new("tunnel-dev").unwrap(),
    );
    let security = AgentTransportSecurity::MutualTls(agent_tls);
    let mut session = match connect_registered_with_security(
        edge_addr,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &security,
        &registration,
    )
    .await
    {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("generation one failed: {reason}"),
    };
    session.close().await.unwrap();

    write_generation(&generation_two);
    write_reload_manifest(
        &edge_manifest,
        2,
        &[
            ("server_certificate", &edge_certificate),
            ("server_private_key", &edge_key),
            ("client_ca", &agent_ca),
            ("authorized_client_certificate", &agent_certificate),
        ],
    );
    write_reload_manifest(
        &agent_manifest,
        2,
        &[
            ("server_ca", &edge_ca),
            ("client_certificate", &agent_certificate),
            ("client_private_key", &agent_key),
        ],
    );
    timeout(Duration::from_secs(2), async {
        loop {
            if edge_status.reload_status(Duration::from_secs(1)).generation == 2
                && agent_status
                    .reload_status(Duration::from_secs(1))
                    .generation
                    == 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TLS generation two was not published");

    let mut session = match connect_registered_with_security(
        edge_addr,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &security,
        &registration,
    )
    .await
    {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("generation two failed: {reason}"),
    };
    session.close().await.unwrap();

    let old_security = AgentTransportSecurity::MutualTls(
        AgentTlsConfig::from_pem(
            generation_one.authority_pem.as_bytes(),
            generation_one.client.certificate_pem.as_bytes(),
            generation_one.client.private_key_pem.as_bytes(),
            "edge.test",
            Duration::from_secs(1),
        )
        .unwrap(),
    );
    assert!(matches!(
        connect_registered_with_security(
            edge_addr,
            Duration::from_secs(1),
            Duration::from_secs(1),
            &old_security,
            &registration,
        )
        .await,
        ConnectOutcome::Failed { .. }
    ));

    std::fs::write(&edge_key, b"invalid private key").unwrap();
    write_reload_manifest(
        &edge_manifest,
        3,
        &[
            ("server_certificate", &edge_certificate),
            ("server_private_key", &edge_key),
            ("client_ca", &agent_ca),
            ("authorized_client_certificate", &agent_certificate),
        ],
    );
    timeout(Duration::from_secs(2), async {
        loop {
            let status = edge_status.reload_status(Duration::from_secs(1));
            if status.health == TlsConfigHealth::ReloadFailed {
                assert_eq!(status.generation, 2);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("invalid generation was not reported");
    let mut session = match connect_registered_with_security(
        edge_addr,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &security,
        &registration,
    )
    .await
    {
        ConnectOutcome::Established(session) => session,
        ConnectOutcome::Failed { reason } => panic!("last-good generation failed: {reason}"),
    };
    session.close().await.unwrap();

    edge_trigger.shutdown();
    edge_reload_trigger.shutdown();
    agent_reload_trigger.shutdown();
    edge_task.await.unwrap().unwrap();
    edge_reload_task.await.unwrap().unwrap();
    agent_reload_task.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
