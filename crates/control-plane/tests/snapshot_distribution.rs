use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tunnelproxy_common::{shutdown_channel, AgentId, ShutdownTrigger, TunnelId};
use tunnelproxy_control_plane::{
    AgentGrant, AuthorizationSnapshot, AuthorizationSnapshotSubscription, CertificateFingerprint,
    PersistentSnapshotAuthority, SnapshotBootstrapClient, SnapshotClientConfig,
    SnapshotClientError, SnapshotDistributionServer, SnapshotRepository, SnapshotServerConfig,
    SnapshotServerTlsConfig, SnapshotSourceHealth, SnapshotVersion, SqliteSnapshotRepository,
    TunnelGrant, TunnelStatus, VersionedAuthorizationSnapshot,
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
