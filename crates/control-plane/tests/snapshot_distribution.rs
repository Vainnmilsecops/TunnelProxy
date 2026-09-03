use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};
use tunnelproxy_common::{shutdown_channel, AgentId, ShutdownTrigger, TlsConfigHealth, TunnelId};
use tunnelproxy_control_plane::{
    AgentGrant, AuthorizationSnapshot, AuthorizationSnapshotSubscription, CertificateFingerprint,
    ControlPlaneOperationsConfig, ControlPlaneRuntime, ControlPlaneRuntimeConfig,
    ControlPlaneRuntimeError, PersistentSnapshotAuthority, PersistentSnapshotAuthorityError,
    SnapshotBootstrapClient, SnapshotBootstrapSource, SnapshotCacheConfig, SnapshotCacheError,
    SnapshotClientConfig, SnapshotClientError, SnapshotClientTlsReloadConfig,
    SnapshotClientTlsReloadRuntime, SnapshotDistributionServer, SnapshotRepository,
    SnapshotServerConfig, SnapshotServerTlsConfig, SnapshotServerTlsReloadConfig,
    SnapshotServerTlsReloadRuntime, SnapshotSourceHealth, SnapshotVersion,
    SqliteSnapshotRepository, TunnelGrant, TunnelStatus, VersionedAuthorizationSnapshot,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

struct TestPki {
    authority_pem: String,
    server: TestIdentity,
    edge: TestIdentity,
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
    TestPki {
        authority_pem: authority.pem(),
        server: signed_identity(
            server_name,
            ExtendedKeyUsagePurpose::ServerAuth,
            &authority,
            &authority_key,
        ),
        edge: signed_identity(
            "edge.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            &authority,
            &authority_key,
        ),
    }
}

fn signed_identity(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    authority: &Certificate,
    authority_key: &KeyPair,
) -> TestIdentity {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, authority, authority_key).unwrap();
    TestIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
    }
}

fn snapshot(version: u64, status: TunnelStatus) -> VersionedAuthorizationSnapshot {
    VersionedAuthorizationSnapshot::new(
        SnapshotVersion::new(version).unwrap(),
        AuthorizationSnapshot::new(vec![AgentGrant::new(
            CertificateFingerprint::from_bytes([version as u8; 32]),
            AgentId::new("agent-snapshot").unwrap(),
            vec![TunnelGrant::new(
                TunnelId::new("tunnel-snapshot").unwrap(),
                status,
            )],
        )])
        .unwrap(),
    )
}

fn temp_database() -> (PathBuf, PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "tunnelproxy-snapshot-integration-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
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

fn server_config(
    listen_addr: SocketAddr,
    pki: &TestPki,
) -> tunnelproxy_control_plane::SnapshotServerConfig {
    SnapshotServerConfig {
        listen_addr,
        max_edge_clients: 8,
        request_timeout: Duration::from_secs(1),
        tls: SnapshotServerTlsConfig::from_pem(
            pki.server.certificate_pem.as_bytes(),
            pki.server.private_key_pem.as_bytes(),
            pki.authority_pem.as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap(),
    }
}

fn client_config(
    server_addr: SocketAddr,
    pki: &TestPki,
    server_name: &str,
) -> SnapshotClientConfig {
    let mut config = SnapshotClientConfig::from_pem(
        server_addr,
        pki.authority_pem.as_bytes(),
        pki.edge.certificate_pem.as_bytes(),
        pki.edge.private_key_pem.as_bytes(),
        server_name,
    )
    .unwrap();
    config.connect_timeout = Duration::from_secs(1);
    config.handshake_timeout = Duration::from_secs(1);
    config.subscribe_timeout = Duration::from_secs(1);
    config.reconnect_initial_delay = Duration::from_millis(20);
    config.reconnect_max_delay = Duration::from_millis(100);
    config
}

async fn start_server(
    listen_addr: SocketAddr,
    pki: &TestPki,
    authority: &PersistentSnapshotAuthority,
) -> (
    SocketAddr,
    ShutdownTrigger,
    JoinHandle<Result<(), tunnelproxy_control_plane::SnapshotServerError>>,
) {
    let server =
        SnapshotDistributionServer::bind(server_config(listen_addr, pki), authority.subscribe())
            .await
            .unwrap();
    let address = server.local_addr();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(server.run_until_shutdown(signal));
    (address, trigger, task)
}

async fn wait_for_version(subscription: &mut AuthorizationSnapshotSubscription, version: u64) {
    timeout(Duration::from_secs(3), async {
        while subscription.current().version().get() != version {
            subscription.changed().await.unwrap();
        }
    })
    .await
    .expect("snapshot version was not delivered");
}

async fn wait_for_health(
    subscription: &mut AuthorizationSnapshotSubscription,
    health: SnapshotSourceHealth,
) {
    timeout(Duration::from_secs(3), async {
        while subscription.source_health() != health {
            subscription.changed().await.unwrap();
        }
    })
    .await
    .expect("snapshot source health did not change");
}

async fn wait_for_operations_active(addr: SocketAddr, expected: usize) {
    let metric = format!("tunnelproxy_control_plane_operations_active_connections {expected}\n");
    timeout(Duration::from_secs(3), async {
        loop {
            let response = operations_request(addr, "GET", "/metrics").await;
            if response.contains(&metric) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operations connection was not admitted");
}

#[tokio::test]
async fn sqlite_authority_bootstraps_pushes_and_recovers_snapshot_stream() {
    let (database, directory) = temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    let first = snapshot(1, TunnelStatus::Enabled);
    repository.commit(&first).unwrap();
    let authority = PersistentSnapshotAuthority::open(repository.clone())
        .await
        .unwrap();
    assert_eq!(authority.current().as_ref(), &first);

    let pki = test_pki("control-plane.test");
    let (server_addr, server_trigger, server_task) =
        start_server("127.0.0.1:0".parse().unwrap(), &pki, &authority).await;

    let (mut edge_snapshots, runtime) =
        SnapshotBootstrapClient::bootstrap(client_config(server_addr, &pki, "control-plane.test"))
            .await
            .unwrap();
    assert_eq!(edge_snapshots.current().as_ref(), &first);
    assert_eq!(edge_snapshots.source_health(), SnapshotSourceHealth::Live);
    let (client_trigger, client_signal) = shutdown_channel();
    let client_task = tokio::spawn(runtime.run_until_shutdown(client_signal));

    let second = snapshot(2, TunnelStatus::Disabled);
    authority.commit(second.clone()).await.unwrap();
    wait_for_version(&mut edge_snapshots, 2).await;
    assert_eq!(edge_snapshots.current().as_ref(), &second);

    server_trigger.shutdown();
    server_task.await.unwrap().unwrap();
    wait_for_health(&mut edge_snapshots, SnapshotSourceHealth::Stale).await;
    assert_eq!(edge_snapshots.current().as_ref(), &second);

    let (_, restarted_trigger, restarted_task) = start_server(server_addr, &pki, &authority).await;
    wait_for_health(&mut edge_snapshots, SnapshotSourceHealth::Live).await;

    let third = snapshot(3, TunnelStatus::Enabled);
    authority.commit(third.clone()).await.unwrap();
    wait_for_version(&mut edge_snapshots, 3).await;
    assert_eq!(edge_snapshots.current().as_ref(), &third);

    let invalid_name = SnapshotBootstrapClient::bootstrap(client_config(
        server_addr,
        &pki,
        "wrong-control-plane.test",
    ))
    .await;
    assert!(matches!(
        invalid_name,
        Err(SnapshotClientError::TlsAuthentication)
    ));

    client_trigger.shutdown();
    client_task.await.unwrap().unwrap();
    restarted_trigger.shutdown();
    restarted_task.await.unwrap().unwrap();
    drop(authority);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn reconnect_attempt_is_cancelled_without_waiting_for_network_timeouts() {
    let pki = test_pki("control-plane.test");
    let (database, directory) = temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(database).unwrap());
    repository
        .commit(&snapshot(1, TunnelStatus::Enabled))
        .unwrap();
    let authority = PersistentSnapshotAuthority::open(repository.clone())
        .await
        .unwrap();
    let (server_addr, server_trigger, server_task) =
        start_server("127.0.0.1:0".parse().unwrap(), &pki, &authority).await;
    let mut config = client_config(server_addr, &pki, "control-plane.test");
    config.reconnect_initial_delay = Duration::from_secs(10);
    config.reconnect_max_delay = Duration::from_secs(10);
    let (_, runtime) = SnapshotBootstrapClient::bootstrap(config).await.unwrap();
    server_trigger.shutdown();
    server_task.await.unwrap().unwrap();

    let (client_trigger, client_signal) = shutdown_channel();
    let task = tokio::spawn(runtime.run_until_shutdown(client_signal));
    tokio::time::sleep(Duration::from_millis(30)).await;
    client_trigger.shutdown();
    timeout(Duration::from_millis(250), task)
        .await
        .expect("shutdown waited for reconnect timeouts")
        .unwrap()
        .unwrap();
    drop(authority);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn control_plane_runtime_refreshes_imports_and_survives_process_restart() {
    let (database, directory) = temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    repository
        .commit(&snapshot(1, TunnelStatus::Enabled))
        .unwrap();
    let pki = test_pki("control-plane.test");
    let runtime = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database.clone(),
        refresh_interval: Duration::from_millis(20),
        snapshot_server: server_config("127.0.0.1:0".parse().unwrap(), &pki),
        https_route_server: None,
        operations: Some(ControlPlaneOperationsConfig::loopback(
            "127.0.0.1:0".parse().unwrap(),
        )),
    })
    .await
    .unwrap();
    let server_addr = runtime.local_addr();
    let operations_addr = runtime.operations_addr().unwrap();
    let (server_trigger, server_signal) = shutdown_channel();
    let server_task = tokio::spawn(runtime.run_until_shutdown(server_signal));
    let (mut edge_snapshots, client) =
        SnapshotBootstrapClient::bootstrap(client_config(server_addr, &pki, "control-plane.test"))
            .await
            .unwrap();
    let (client_trigger, client_signal) = shutdown_channel();
    let client_task = tokio::spawn(client.run_until_shutdown(client_signal));

    let ready = operations_request(operations_addr, "GET", "/readyz").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"));
    let head = operations_request(operations_addr, "HEAD", "/healthz").await;
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.ends_with("\r\n\r\n"));
    assert!(operations_request(operations_addr, "POST", "/metrics")
        .await
        .starts_with("HTTP/1.1 405 Method Not Allowed"));
    assert!(operations_request(operations_addr, "GET", "/missing")
        .await
        .starts_with("HTTP/1.1 404 Not Found"));
    let metrics = operations_request(operations_addr, "GET", "/metrics").await;
    assert!(metrics.contains("tunnelproxy_control_plane_ready 1\n"));
    assert!(metrics.contains("tunnelproxy_control_plane_snapshot_version 1\n"));
    assert!(metrics.contains("tunnelproxy_control_plane_snapshot_accepted_connections_total 1\n"));
    assert!(metrics.contains("tunnelproxy_control_plane_snapshot_subscriptions_total 1\n"));
    assert!(!metrics.contains("agent-snapshot"));
    assert!(!metrics.contains("tunnel-snapshot"));

    repository
        .commit(&snapshot(2, TunnelStatus::Disabled))
        .unwrap();
    wait_for_version(&mut edge_snapshots, 2).await;

    let mut drain_probe = TcpStream::connect(operations_addr).await.unwrap();
    // The metrics request itself is active while rendered, so observing two
    // active connections proves the header-stalled drain probe was accepted.
    wait_for_operations_active(operations_addr, 2).await;
    server_trigger.shutdown();
    // Source staleness is the observable acknowledgement that the runtime has
    // consumed shutdown, marked readiness false, and drained snapshot service
    // before stopping operations last. A fixed sleep races that scheduling on
    // loaded CI hosts.
    wait_for_health(&mut edge_snapshots, SnapshotSourceHealth::Stale).await;
    drain_probe
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut draining_response = Vec::new();
    drain_probe
        .read_to_end(&mut draining_response)
        .await
        .unwrap();
    assert!(String::from_utf8(draining_response)
        .unwrap()
        .starts_with("HTTP/1.1 503 Service Unavailable"));
    let outcome = server_task.await.unwrap().unwrap();
    assert_eq!(outcome.applied_refreshes, 1);
    assert_eq!(outcome.operations_addr, Some(operations_addr));
    assert!(outcome.operations.is_some());
    assert!(TcpStream::connect(operations_addr).await.is_err());

    let restarted = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database.clone(),
        refresh_interval: Duration::from_millis(20),
        snapshot_server: server_config(server_addr, &pki),
        https_route_server: None,
        operations: None,
    })
    .await
    .unwrap();
    assert_eq!(restarted.current_version().get(), 2);
    let (restarted_trigger, restarted_signal) = shutdown_channel();
    let restarted_task = tokio::spawn(restarted.run_until_shutdown(restarted_signal));
    wait_for_health(&mut edge_snapshots, SnapshotSourceHealth::Live).await;

    client_trigger.shutdown();
    client_task.await.unwrap().unwrap();
    restarted_trigger.shutdown();
    restarted_task.await.unwrap().unwrap();
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

async fn operations_request(addr: SocketAddr, method: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn operations_bind_failure_releases_the_snapshot_listener() {
    let (database, directory) = temp_database();
    let repository = SqliteSnapshotRepository::open(&database).unwrap();
    repository
        .commit(&snapshot(1, TunnelStatus::Enabled))
        .unwrap();
    drop(repository);
    let pki = test_pki("control-plane.test");
    let snapshot_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let snapshot_addr = snapshot_probe.local_addr().unwrap();
    drop(snapshot_probe);
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let operations_addr = occupied.local_addr().unwrap();
    let result = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database,
        refresh_interval: Duration::from_millis(20),
        snapshot_server: server_config(snapshot_addr, &pki),
        https_route_server: None,
        operations: Some(ControlPlaneOperationsConfig::loopback(operations_addr)),
    })
    .await;
    assert!(matches!(
        result,
        Err(ControlPlaneRuntimeError::Operations(_))
    ));
    let rebound = tokio::net::TcpListener::bind(snapshot_addr).await.unwrap();
    drop(rebound);
    drop(occupied);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn operations_capacity_rejection_releases_after_stalled_connection_closes() {
    let (database, directory) = temp_database();
    let repository = SqliteSnapshotRepository::open(&database).unwrap();
    repository
        .commit(&snapshot(1, TunnelStatus::Enabled))
        .unwrap();
    drop(repository);
    let pki = test_pki("control-plane.test");
    let mut operations = ControlPlaneOperationsConfig::loopback("127.0.0.1:0".parse().unwrap());
    operations.max_concurrent_connections = 1;
    operations.header_read_timeout = Duration::from_secs(1);
    let runtime = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database,
        refresh_interval: Duration::from_secs(1),
        snapshot_server: server_config("127.0.0.1:0".parse().unwrap(), &pki),
        https_route_server: None,
        operations: Some(operations),
    })
    .await
    .unwrap();
    let addr = runtime.operations_addr().unwrap();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(runtime.run_until_shutdown(signal));

    let held = TcpStream::connect(addr).await.unwrap();
    sleep(Duration::from_millis(20)).await;
    let mut rejected = TcpStream::connect(addr).await.unwrap();
    let _ = rejected
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await;
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(1), rejected.read_to_end(&mut bytes)).await;
    assert!(bytes.is_empty());

    drop(held);
    let deadline = Instant::now() + Duration::from_secs(2);
    let metrics = loop {
        if let Ok(response) = try_operations_request(addr, "GET", "/metrics").await {
            if response.starts_with("HTTP/1.1 200") {
                break response;
            }
        }
        assert!(
            Instant::now() < deadline,
            "capacity permit was not released"
        );
        sleep(Duration::from_millis(10)).await;
    };
    assert!(metrics.contains("tunnelproxy_control_plane_operations_capacity_rejections_total 1\n"));

    trigger.shutdown();
    let outcome = task.await.unwrap().unwrap();
    assert!(!outcome.operations.unwrap().was_forced());
    std::fs::remove_dir_all(directory).unwrap();
}

async fn try_operations_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    String::from_utf8(response)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[tokio::test]
async fn control_plane_runtime_refuses_an_uninitialized_repository() {
    let (database, directory) = temp_database();
    let pki = test_pki("control-plane.test");
    let mut config = ControlPlaneRuntimeConfig {
        database_path: database.clone(),
        refresh_interval: Duration::from_millis(20),
        snapshot_server: server_config("127.0.0.1:0".parse().unwrap(), &pki),
        https_route_server: None,
        operations: None,
    };
    config.operations = Some(ControlPlaneOperationsConfig::loopback(
        "0.0.0.0:9092".parse().unwrap(),
    ));
    assert!(matches!(
        ControlPlaneRuntime::bind(config.clone()).await,
        Err(ControlPlaneRuntimeError::InvalidConfig)
    ));
    assert!(!database.exists());
    config.operations = None;
    config.refresh_interval = Duration::ZERO;
    assert!(matches!(
        ControlPlaneRuntime::bind(config.clone()).await,
        Err(ControlPlaneRuntimeError::InvalidConfig)
    ));
    config.refresh_interval = Duration::from_millis(20);
    let result = ControlPlaneRuntime::bind(config).await;
    assert!(matches!(
        result,
        Err(ControlPlaneRuntimeError::Authority(
            PersistentSnapshotAuthorityError::Uninitialized
        ))
    ));
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn edge_cache_cold_starts_offline_and_reconciles_after_reconnect() {
    let (database, directory) = temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    let first = snapshot(1, TunnelStatus::Enabled);
    repository.commit(&first).unwrap();
    let authority = PersistentSnapshotAuthority::open(repository.clone())
        .await
        .unwrap();
    let pki = test_pki("control-plane.test");
    let (server_addr, server_trigger, server_task) =
        start_server("127.0.0.1:0".parse().unwrap(), &pki, &authority).await;
    let cache = SnapshotCacheConfig {
        directory: directory.join("edge-cache"),
        max_stale_age: Duration::from_secs(5),
    };

    let (online, online_runtime, source) = SnapshotBootstrapClient::bootstrap_with_cache(
        client_config(server_addr, &pki, "control-plane.test"),
        cache.clone(),
    )
    .await
    .unwrap();
    assert_eq!(source, SnapshotBootstrapSource::Online);
    assert_eq!(online.current().as_ref(), &first);
    drop(online_runtime);
    server_trigger.shutdown();
    server_task.await.unwrap().unwrap();

    let (mut offline, offline_runtime, source) = SnapshotBootstrapClient::bootstrap_with_cache(
        client_config(server_addr, &pki, "control-plane.test"),
        cache,
    )
    .await
    .unwrap();
    assert_eq!(source, SnapshotBootstrapSource::DiskCache);
    assert_eq!(offline.source_health(), SnapshotSourceHealth::Stale);
    assert_eq!(offline.current().as_ref(), &first);
    let (client_trigger, client_signal) = shutdown_channel();
    let client_task = tokio::spawn(offline_runtime.run_until_shutdown(client_signal));

    let (_, restarted_trigger, restarted_task) = start_server(server_addr, &pki, &authority).await;
    wait_for_health(&mut offline, SnapshotSourceHealth::Live).await;
    let second = snapshot(2, TunnelStatus::Disabled);
    authority.commit(second.clone()).await.unwrap();
    wait_for_version(&mut offline, 2).await;
    assert_eq!(offline.current().as_ref(), &second);

    client_trigger.shutdown();
    client_task.await.unwrap().unwrap();
    restarted_trigger.shutdown();
    restarted_task.await.unwrap().unwrap();
    drop(authority);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn cache_expiry_is_terminal_and_tls_authentication_never_falls_back() {
    let (database, directory) = temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    repository
        .commit(&snapshot(1, TunnelStatus::Enabled))
        .unwrap();
    let authority = PersistentSnapshotAuthority::open(repository.clone())
        .await
        .unwrap();
    let pki = test_pki("control-plane.test");
    let (server_addr, server_trigger, server_task) =
        start_server("127.0.0.1:0".parse().unwrap(), &pki, &authority).await;
    let cache = SnapshotCacheConfig {
        directory: directory.join("edge-cache"),
        max_stale_age: Duration::from_secs(2),
    };
    let (_, online_runtime, _) = SnapshotBootstrapClient::bootstrap_with_cache(
        client_config(server_addr, &pki, "control-plane.test"),
        cache.clone(),
    )
    .await
    .unwrap();
    drop(online_runtime);

    let wrong_name = SnapshotBootstrapClient::bootstrap_with_cache(
        client_config(server_addr, &pki, "wrong-control-plane.test"),
        cache.clone(),
    )
    .await;
    assert!(matches!(
        wrong_name,
        Err(SnapshotClientError::TlsAuthentication)
    ));

    server_trigger.shutdown();
    server_task.await.unwrap().unwrap();
    let (_, stale_runtime, source) = SnapshotBootstrapClient::bootstrap_with_cache(
        client_config(server_addr, &pki, "control-plane.test"),
        cache.clone(),
    )
    .await
    .unwrap();
    assert_eq!(source, SnapshotBootstrapSource::DiskCache);
    let (_trigger, signal) = shutdown_channel();
    assert!(matches!(
        timeout(
            Duration::from_secs(3),
            stale_runtime.run_until_shutdown(signal)
        )
        .await,
        Ok(Err(SnapshotClientError::CacheExpired))
    ));

    let expired = SnapshotBootstrapClient::bootstrap_with_cache(
        client_config(server_addr, &pki, "control-plane.test"),
        cache,
    )
    .await;
    assert!(matches!(
        expired,
        Err(SnapshotClientError::Cache(SnapshotCacheError::Expired))
    ));
    drop(authority);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn cache_write_failure_never_publishes_the_new_snapshot() {
    let (database, directory) = temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    repository
        .commit(&snapshot(1, TunnelStatus::Enabled))
        .unwrap();
    let authority = PersistentSnapshotAuthority::open(repository.clone())
        .await
        .unwrap();
    let pki = test_pki("control-plane.test");
    let (server_addr, server_trigger, server_task) =
        start_server("127.0.0.1:0".parse().unwrap(), &pki, &authority).await;
    let cache_directory = directory.join("edge-cache");
    let cache = SnapshotCacheConfig {
        directory: cache_directory.clone(),
        max_stale_age: Duration::from_secs(5),
    };
    let (edge_snapshots, runtime, _) = SnapshotBootstrapClient::bootstrap_with_cache(
        client_config(server_addr, &pki, "control-plane.test"),
        cache,
    )
    .await
    .unwrap();
    let (_client_trigger, client_signal) = shutdown_channel();
    let client_task = tokio::spawn(runtime.run_until_shutdown(client_signal));

    std::fs::remove_dir_all(&cache_directory).unwrap();
    std::fs::write(&cache_directory, b"blocks cache directory creation").unwrap();
    authority
        .commit(snapshot(2, TunnelStatus::Disabled))
        .await
        .unwrap();
    let failure = timeout(Duration::from_secs(1), client_task)
        .await
        .expect("cache write failure did not stop the snapshot client")
        .unwrap();
    assert!(matches!(
        failure,
        Err(SnapshotClientError::Cache(SnapshotCacheError::Io(_)))
    ));
    assert_eq!(edge_snapshots.current().version().get(), 1);
    assert_eq!(edge_snapshots.source_health(), SnapshotSourceHealth::Stale);

    server_trigger.shutdown();
    server_task.await.unwrap().unwrap();
    drop(authority);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn snapshot_tls_server_and_client_rotate_without_process_restart() {
    let first_pki = test_pki("control-plane.test");
    let second_pki = test_pki("control-plane.test");
    let (database, directory) = temp_database();
    let repository = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    repository
        .commit(&snapshot(1, TunnelStatus::Enabled))
        .unwrap();
    let authority = PersistentSnapshotAuthority::open(repository.clone())
        .await
        .unwrap();

    let server_certificate = directory.join("control.pem");
    let server_key = directory.join("control-key.pem");
    let edge_ca = directory.join("edge-ca.pem");
    let server_ca = directory.join("control-ca.pem");
    let client_certificate = directory.join("edge.pem");
    let client_key = directory.join("edge-key.pem");
    let server_manifest = directory.join("server-reload.json");
    let client_manifest = directory.join("client-reload.json");
    let write_generation = |pki: &TestPki| {
        std::fs::write(&server_certificate, &pki.server.certificate_pem).unwrap();
        std::fs::write(&server_key, &pki.server.private_key_pem).unwrap();
        std::fs::write(&edge_ca, &pki.authority_pem).unwrap();
        std::fs::write(&server_ca, &pki.authority_pem).unwrap();
        std::fs::write(&client_certificate, &pki.edge.certificate_pem).unwrap();
        std::fs::write(&client_key, &pki.edge.private_key_pem).unwrap();
    };
    write_generation(&first_pki);
    write_reload_manifest(
        &server_manifest,
        1,
        &[
            ("server_certificate", &server_certificate),
            ("server_private_key", &server_key),
            ("client_ca", &edge_ca),
        ],
    );
    write_reload_manifest(
        &client_manifest,
        1,
        &[
            ("server_ca", &server_ca),
            ("client_certificate", &client_certificate),
            ("client_private_key", &client_key),
        ],
    );

    let (server_tls, server_reloader) = SnapshotServerTlsReloadRuntime::bootstrap(
        SnapshotServerTlsReloadConfig {
            manifest_path: server_manifest.clone(),
            server_certificate_path: server_certificate.clone(),
            server_private_key_path: server_key.clone(),
            client_ca_path: edge_ca.clone(),
            poll_interval: Duration::from_millis(20),
            expiry_warning: Duration::from_secs(60),
        },
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let server_status = server_tls.clone();
    let server = SnapshotDistributionServer::bind(
        SnapshotServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_edge_clients: 8,
            request_timeout: Duration::from_secs(1),
            tls: server_tls,
        },
        authority.subscribe(),
    )
    .await
    .unwrap();
    let server_addr = server.local_addr();
    let (server_trigger, server_signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run_until_shutdown(server_signal));
    let (server_reload_trigger, server_reload_signal) = shutdown_channel();
    let server_reload_task = tokio::spawn(server_reloader.run_until_shutdown(server_reload_signal));

    let (mut client, client_reloader) = SnapshotClientTlsReloadRuntime::bootstrap(
        server_addr,
        "control-plane.test",
        SnapshotClientTlsReloadConfig {
            manifest_path: client_manifest.clone(),
            server_ca_path: server_ca.clone(),
            client_certificate_path: client_certificate.clone(),
            client_private_key_path: client_key.clone(),
            poll_interval: Duration::from_millis(20),
            expiry_warning: Duration::from_secs(60),
        },
    )
    .await
    .unwrap();
    client.connect_timeout = Duration::from_secs(1);
    client.handshake_timeout = Duration::from_secs(1);
    client.subscribe_timeout = Duration::from_secs(1);
    let client_status = client.clone();
    let (_, initial_runtime) = SnapshotBootstrapClient::bootstrap(client.clone())
        .await
        .unwrap();
    drop(initial_runtime);
    let (client_reload_trigger, client_reload_signal) = shutdown_channel();
    let client_reload_task = tokio::spawn(client_reloader.run_until_shutdown(client_reload_signal));

    write_generation(&second_pki);
    write_reload_manifest(
        &server_manifest,
        2,
        &[
            ("server_certificate", &server_certificate),
            ("server_private_key", &server_key),
            ("client_ca", &edge_ca),
        ],
    );
    write_reload_manifest(
        &client_manifest,
        2,
        &[
            ("server_ca", &server_ca),
            ("client_certificate", &client_certificate),
            ("client_private_key", &client_key),
        ],
    );
    timeout(Duration::from_secs(2), async {
        loop {
            if server_status
                .reload_status(Duration::from_secs(1))
                .generation
                == 2
                && client_status
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
    .expect("snapshot TLS generation two was not published");
    let (_, rotated_runtime) = SnapshotBootstrapClient::bootstrap(client.clone())
        .await
        .unwrap();
    drop(rotated_runtime);

    let old_client = client_config(server_addr, &first_pki, "control-plane.test");
    assert!(matches!(
        SnapshotBootstrapClient::bootstrap(old_client).await,
        Err(SnapshotClientError::TlsAuthentication)
    ));

    std::fs::write(&client_key, b"invalid private key").unwrap();
    write_reload_manifest(
        &client_manifest,
        3,
        &[
            ("server_ca", &server_ca),
            ("client_certificate", &client_certificate),
            ("client_private_key", &client_key),
        ],
    );
    timeout(Duration::from_secs(2), async {
        loop {
            let status = client_status.reload_status(Duration::from_secs(1));
            if status.health == TlsConfigHealth::ReloadFailed {
                assert_eq!(status.generation, 2);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("invalid snapshot client generation was not reported");
    let (_, last_good_runtime) = SnapshotBootstrapClient::bootstrap(client).await.unwrap();
    drop(last_good_runtime);

    client_reload_trigger.shutdown();
    server_reload_trigger.shutdown();
    server_trigger.shutdown();
    client_reload_task.await.unwrap().unwrap();
    server_reload_task.await.unwrap().unwrap();
    server_task.await.unwrap().unwrap();
    drop(authority);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}
