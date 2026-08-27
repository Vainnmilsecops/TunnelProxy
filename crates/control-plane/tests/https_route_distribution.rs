use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tunnelproxy_common::{shutdown_channel, PublicHostname, ShutdownTrigger, TunnelId};
use tunnelproxy_control_plane::{
    AuthorizationSnapshot, ControlPlaneRuntime, ControlPlaneRuntimeConfig,
    HttpsRouteBootstrapClient, HttpsRouteCatalogSubscription, HttpsRouteClientConfig,
    HttpsRouteDistributionServer, HttpsRouteRecord, HttpsRouteRepository, HttpsRouteServerConfig,
    HttpsRouteServerError, HttpsRouteServerTlsConfig, HttpsRouteSourceHealth, HttpsRouteStatus,
    PersistentHttpsRouteCatalog, SnapshotRepository, SnapshotServerConfig, SnapshotServerTlsConfig,
    SnapshotVersion, SqliteSnapshotRepository, VersionedAuthorizationSnapshot,
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

fn temp_database() -> (PathBuf, PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "tunnelproxy-route-distribution-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    (directory.join("state.sqlite"), directory)
}

fn route(tunnel: &str, status: HttpsRouteStatus) -> HttpsRouteRecord {
    HttpsRouteRecord::new(
        PublicHostname::new("demo.example.test").unwrap(),
        TunnelId::new(tunnel).unwrap(),
        status,
    )
}

async fn start_server(
    listen_addr: std::net::SocketAddr,
    pki: &TestPki,
    authority: &PersistentHttpsRouteCatalog,
) -> (
    std::net::SocketAddr,
    ShutdownTrigger,
    JoinHandle<Result<(), HttpsRouteServerError>>,
) {
    let server = HttpsRouteDistributionServer::bind(
        HttpsRouteServerConfig {
            listen_addr,
            max_edge_clients: 4,
            request_timeout: Duration::from_secs(1),
            tls: HttpsRouteServerTlsConfig::from_pem(
                pki.server.certificate_pem.as_bytes(),
                pki.server.private_key_pem.as_bytes(),
                pki.authority_pem.as_bytes(),
                Duration::from_secs(1),
            )
            .unwrap(),
        },
        authority.subscribe(),
    )
    .await
    .unwrap();
    let address = server.local_addr();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(server.run_until_shutdown(signal));
    (address, trigger, task)
}

fn client_config(
    server_addr: std::net::SocketAddr,
    pki: &TestPki,
    max_stale_age: Duration,
) -> HttpsRouteClientConfig {
    HttpsRouteClientConfig::from_pem(
        server_addr,
        pki.authority_pem.as_bytes(),
        pki.edge.certificate_pem.as_bytes(),
        pki.edge.private_key_pem.as_bytes(),
        "control-plane.test",
        max_stale_age,
    )
    .unwrap()
}

async fn wait_for_version(subscription: &mut HttpsRouteCatalogSubscription, version: u64) {
    timeout(Duration::from_secs(3), async {
        while subscription.current().version().get() != version {
            subscription.changed().await.unwrap();
        }
    })
    .await
    .expect("route catalog version was not delivered");
}

async fn wait_for_health(
    subscription: &mut HttpsRouteCatalogSubscription,
    health: HttpsRouteSourceHealth,
) {
    timeout(Duration::from_secs(3), async {
        while subscription.source_health() != health {
            subscription.changed().await.unwrap();
        }
    })
    .await
    .expect("route source health did not change");
}

#[tokio::test]
async fn mtls_route_stream_updates_expires_and_recovers_without_disk_cache() {
    let (database, directory) = temp_database();
    let repository = HttpsRouteRepository::open(&database).unwrap();
    repository
        .upsert(&route("tunnel-a", HttpsRouteStatus::Enabled))
        .unwrap();
    let authority = PersistentHttpsRouteCatalog::open(repository.clone())
        .await
        .unwrap();
    let pki = test_pki("control-plane.test");
    let (server_addr, server_trigger, server_task) =
        start_server("127.0.0.1:0".parse().unwrap(), &pki, &authority).await;

    let (mut routes, runtime) = HttpsRouteBootstrapClient::bootstrap(client_config(
        server_addr,
        &pki,
        Duration::from_millis(150),
    ))
    .await
    .unwrap();
    assert_eq!(
        routes.current().routes(),
        &[route("tunnel-a", HttpsRouteStatus::Enabled)]
    );
    let (client_trigger, client_signal) = shutdown_channel();
    let client_task = tokio::spawn(runtime.run_until_shutdown(client_signal));

    repository
        .upsert(&route("tunnel-b", HttpsRouteStatus::Disabled))
        .unwrap();
    authority.refresh_from_repository().await.unwrap();
    wait_for_version(&mut routes, 3).await;
    assert_eq!(
        routes.current().routes(),
        &[route("tunnel-b", HttpsRouteStatus::Disabled)]
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    server_trigger.shutdown();
    server_task.await.unwrap().unwrap();
    wait_for_health(&mut routes, HttpsRouteSourceHealth::Stale).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(routes.source_health(), HttpsRouteSourceHealth::Stale);
    wait_for_health(&mut routes, HttpsRouteSourceHealth::Expired).await;

    let (_, restarted_trigger, restarted_task) = start_server(server_addr, &pki, &authority).await;
    wait_for_health(&mut routes, HttpsRouteSourceHealth::Live).await;

    client_trigger.shutdown();
    client_task.await.unwrap().unwrap();
    restarted_trigger.shutdown();
    restarted_task.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn control_plane_runtime_refreshes_and_supervises_route_distribution() {
    let (database, directory) = temp_database();
    let snapshots = SqliteSnapshotRepository::open(&database).unwrap();
    snapshots
        .commit(&VersionedAuthorizationSnapshot::new(
            SnapshotVersion::FIRST,
            AuthorizationSnapshot::default(),
        ))
        .unwrap();
    let repository = HttpsRouteRepository::open(&database).unwrap();
    repository
        .upsert(&route("tunnel-a", HttpsRouteStatus::Enabled))
        .unwrap();
    let pki = test_pki("control-plane.test");
    let server_tls = SnapshotServerTlsConfig::from_pem(
        pki.server.certificate_pem.as_bytes(),
        pki.server.private_key_pem.as_bytes(),
        pki.authority_pem.as_bytes(),
        Duration::from_secs(1),
    )
    .unwrap();
    let route_tls = HttpsRouteServerTlsConfig::from_pem(
        pki.server.certificate_pem.as_bytes(),
        pki.server.private_key_pem.as_bytes(),
        pki.authority_pem.as_bytes(),
        Duration::from_secs(1),
    )
    .unwrap();
    let runtime = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: database,
        refresh_interval: Duration::from_millis(20),
        snapshot_server: SnapshotServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_edge_clients: 4,
            request_timeout: Duration::from_secs(1),
            tls: server_tls,
        },
        https_route_server: Some(HttpsRouteServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_edge_clients: 4,
            request_timeout: Duration::from_secs(1),
            tls: route_tls,
        }),
        operations: None,
    })
    .await
    .unwrap();
    let route_addr = runtime.https_route_addr().unwrap();
    let (server_trigger, server_signal) = shutdown_channel();
    let server_task = tokio::spawn(runtime.run_until_shutdown(server_signal));
    let (mut routes, client) = HttpsRouteBootstrapClient::bootstrap(client_config(
        route_addr,
        &pki,
        Duration::from_secs(1),
    ))
    .await
    .unwrap();
    let (client_trigger, client_signal) = shutdown_channel();
    let client_task = tokio::spawn(client.run_until_shutdown(client_signal));

    repository
        .upsert(&route("tunnel-b", HttpsRouteStatus::Enabled))
        .unwrap();
    wait_for_version(&mut routes, 3).await;

    server_trigger.shutdown();
    let outcome = server_task.await.unwrap().unwrap();
    assert_eq!(outcome.https_route_addr, Some(route_addr));
    assert_eq!(outcome.applied_route_refreshes, 1);
    client_trigger.shutdown();
    client_task.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
