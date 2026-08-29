use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tunnelproxy_agent::{AgentHostnameClient, AgentHostnameError, HostnameClientConfig};
use tunnelproxy_common::{shutdown_channel, AgentId, TunnelId};
use tunnelproxy_control_plane::{
    authorization_snapshot_channel, AgentGrant, AuthorizationSnapshot, CertificateFingerprint,
    ControlPlaneRuntime, ControlPlaneRuntimeConfig, HostnameServer, HostnameServerConfig,
    HostnameServerTlsConfig, HttpsRouteRepository, HttpsRouteServerConfig,
    HttpsRouteServerTlsConfig, ManagedHostnameBaseDomain, PersistentHttpsRouteCatalog,
    SnapshotRepository, SnapshotServerConfig, SnapshotServerTlsConfig, SnapshotVersion,
    SqliteSnapshotRepository, TunnelGrant, TunnelStatus, VersionedAuthorizationSnapshot,
};
use tunnelproxy_protocol::HostnameErrorCode;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct Identity {
    certificate_pem: String,
    private_key_pem: String,
    fingerprint: CertificateFingerprint,
}

struct TestPki {
    authority_pem: String,
    server: Identity,
    agent: Identity,
    unknown_agent: Identity,
}

fn test_pki(server_name: &str) -> TestPki {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let authority_key = KeyPair::generate().unwrap();
    let authority = params.self_signed(&authority_key).unwrap();
    TestPki {
        authority_pem: authority.pem(),
        server: signed_identity(
            server_name,
            ExtendedKeyUsagePurpose::ServerAuth,
            &authority,
            &authority_key,
        ),
        agent: signed_identity(
            "agent.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            &authority,
            &authority_key,
        ),
        unknown_agent: signed_identity(
            "unknown-agent.test",
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
) -> Identity {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, authority, authority_key).unwrap();
    Identity {
        fingerprint: CertificateFingerprint::from_certificate_der(certificate.der().as_ref()),
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
    }
}

fn temp_database() -> (PathBuf, PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "tunnelproxy-hostname-service-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    (directory.join("state.sqlite"), directory)
}

fn authorized_snapshot(pki: &TestPki) -> (VersionedAuthorizationSnapshot, AgentId, TunnelId) {
    let agent_id = AgentId::new("agent-hostname").unwrap();
    let tunnel_id = TunnelId::new("tunnel-hostname").unwrap();
    let snapshot = VersionedAuthorizationSnapshot::new(
        SnapshotVersion::new(1).unwrap(),
        AuthorizationSnapshot::new(vec![AgentGrant::new(
            pki.agent.fingerprint,
            agent_id.clone(),
            vec![TunnelGrant::new(tunnel_id.clone(), TunnelStatus::Enabled)],
        )])
        .unwrap(),
    );
    (snapshot, agent_id, tunnel_id)
}

fn hostname_client(
    addr: std::net::SocketAddr,
    pki: &TestPki,
    identity: &Identity,
) -> AgentHostnameClient {
    AgentHostnameClient::new(HostnameClientConfig {
        server_addr: addr,
        server_name: "control.test".to_owned(),
        server_ca_pem: pki.authority_pem.as_bytes().to_vec(),
        client_cert_pem: identity.certificate_pem.as_bytes().to_vec(),
        client_key_pem: identity.private_key_pem.as_bytes().to_vec(),
        connect_timeout: Duration::from_secs(2),
        handshake_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
    })
    .unwrap()
}

#[tokio::test]
async fn authenticated_agent_allocates_publishes_and_releases_managed_hostname() {
    let pki = test_pki("control.test");
    let (versioned, agent_id, tunnel_id) = authorized_snapshot(&pki);
    let (_publisher, subscription) = authorization_snapshot_channel(versioned);
    let (database, directory) = temp_database();
    let routes = PersistentHttpsRouteCatalog::open(HttpsRouteRepository::open(&database).unwrap())
        .await
        .unwrap();
    let mut route_updates = routes.subscribe();
    let server = HostnameServer::bind(
        HostnameServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_clients: 4,
            request_timeout: Duration::from_secs(2),
            base_domain: ManagedHostnameBaseDomain::new("agents.example.test").unwrap(),
            tls: HostnameServerTlsConfig::from_pem(
                pki.server.certificate_pem.as_bytes(),
                pki.server.private_key_pem.as_bytes(),
                pki.authority_pem.as_bytes(),
                Duration::from_secs(2),
            )
            .unwrap(),
        },
        subscription,
        routes.clone(),
    )
    .await
    .unwrap();
    let addr = server.local_addr();
    let (shutdown, signal) = shutdown_channel();
    let task = tokio::spawn(server.run_until_shutdown(signal));
    let client = hostname_client(addr, &pki, &pki.agent);

    let allocated = client
        .allocate(agent_id.clone(), tunnel_id.clone())
        .await
        .unwrap();
    assert!(allocated.changed);
    assert!(allocated
        .hostname
        .as_str()
        .ends_with(".agents.example.test"));
    let published = route_updates.changed().await.unwrap();
    assert_eq!(published.version().get(), allocated.catalog_version);
    assert_eq!(published.routes()[0].hostname, allocated.hostname);

    let existing = client
        .allocate(agent_id.clone(), tunnel_id.clone())
        .await
        .unwrap();
    assert!(!existing.changed);
    assert_eq!(existing.hostname, allocated.hostname);
    assert_eq!(existing.catalog_version, allocated.catalog_version);

    let wrong_binding = client
        .allocate(AgentId::new("another-agent").unwrap(), tunnel_id.clone())
        .await;
    assert!(matches!(
        wrong_binding,
        Err(AgentHostnameError::Rejected(
            HostnameErrorCode::Unauthorized
        ))
    ));
    let unknown_identity = hostname_client(addr, &pki, &pki.unknown_agent)
        .allocate(agent_id.clone(), tunnel_id.clone())
        .await;
    assert!(matches!(
        unknown_identity,
        Err(AgentHostnameError::Rejected(
            HostnameErrorCode::Unauthorized
        ))
    ));
    let untrusted_pki = test_pki("untrusted-control.test");
    assert!(hostname_client(addr, &pki, &untrusted_pki.agent)
        .allocate(agent_id.clone(), tunnel_id.clone())
        .await
        .is_err());

    let released = client.release(agent_id, tunnel_id).await.unwrap();
    assert!(released.changed);
    assert_eq!(released.hostname, Some(allocated.hostname));
    let published = route_updates.changed().await.unwrap();
    assert!(published.routes().is_empty());
    assert_eq!(published.version().get(), released.catalog_version);

    shutdown.shutdown();
    task.await.unwrap().unwrap();
    drop(route_updates);
    drop(routes);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn control_plane_runtime_supervises_hostname_service_through_shutdown() {
    let pki = test_pki("control.test");
    let (snapshot, agent_id, tunnel_id) = authorized_snapshot(&pki);
    let (database, directory) = temp_database();
    let repository = SqliteSnapshotRepository::open(&database).unwrap();
    repository.commit(&snapshot).unwrap();
    drop(repository);
    let server_tls = || {
        SnapshotServerTlsConfig::from_pem(
            pki.server.certificate_pem.as_bytes(),
            pki.server.private_key_pem.as_bytes(),
            pki.authority_pem.as_bytes(),
            Duration::from_secs(2),
        )
        .unwrap()
    };
    let runtime = ControlPlaneRuntime::bind_with_hostname(
        ControlPlaneRuntimeConfig {
            database_path: database.clone(),
            refresh_interval: Duration::from_millis(50),
            snapshot_server: SnapshotServerConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                max_edge_clients: 2,
                request_timeout: Duration::from_secs(2),
                tls: server_tls(),
            },
            https_route_server: Some(HttpsRouteServerConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                max_edge_clients: 2,
                request_timeout: Duration::from_secs(2),
                tls: HttpsRouteServerTlsConfig::from_pem(
                    pki.server.certificate_pem.as_bytes(),
                    pki.server.private_key_pem.as_bytes(),
                    pki.authority_pem.as_bytes(),
                    Duration::from_secs(2),
                )
                .unwrap(),
            }),
            operations: None,
        },
        HostnameServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_clients: 2,
            request_timeout: Duration::from_secs(2),
            base_domain: ManagedHostnameBaseDomain::new("agents.example.test").unwrap(),
            tls: HostnameServerTlsConfig::from_pem(
                pki.server.certificate_pem.as_bytes(),
                pki.server.private_key_pem.as_bytes(),
                pki.authority_pem.as_bytes(),
                Duration::from_secs(2),
            )
            .unwrap(),
        },
    )
    .await
    .unwrap();
    let hostname_addr = runtime.hostname_addr().unwrap();
    let (shutdown, signal) = shutdown_channel();
    let task = tokio::spawn(runtime.run_until_shutdown(signal));
    let allocated = hostname_client(hostname_addr, &pki, &pki.agent)
        .allocate(agent_id, tunnel_id)
        .await
        .unwrap();
    assert!(allocated.changed);
    let durable = HttpsRouteRepository::open(&database)
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(durable.version().get(), allocated.catalog_version);

    shutdown.shutdown();
    let outcome = task.await.unwrap().unwrap();
    assert_eq!(outcome.hostname_addr, Some(hostname_addr));
    std::fs::remove_dir_all(directory).unwrap();
}
