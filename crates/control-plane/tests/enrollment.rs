use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use tunnelproxy_agent::{
    bootstrap_agent_credentials, read_enrollment_token, write_enrollment_token,
    AgentEnrollmentConfig, AgentEnrollmentError, EnrollmentClientConfig,
};
use tunnelproxy_common::{shutdown_channel, AgentCredentialPaths, AgentId, TunnelId};
use tunnelproxy_control_plane::{
    AgentCertificateIssuer, AuthorizationError, AuthorizationSnapshot, EnrollmentRepository,
    EnrollmentServer, EnrollmentServerConfig, EnrollmentServerTlsConfig, IssuanceCandidate,
    PersistentSnapshotAuthority, SnapshotRepository, SnapshotVersion, SqliteSnapshotRepository,
    VersionedAuthorizationSnapshot,
};
use tunnelproxy_protocol::{EnrollmentErrorCode, EnrollmentRequestId, EnrollmentToken};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

struct TestAuthority {
    certificate: Certificate,
    certificate_pem: String,
    private_key: KeyPair,
}

fn authority() -> TestAuthority {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let private_key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&private_key).unwrap();
    TestAuthority {
        certificate_pem: certificate.pem(),
        certificate,
        private_key,
    }
}

fn server_identity(name: &str, authority: &TestAuthority) -> TestIdentity {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let private_key = KeyPair::generate().unwrap();
    let certificate = params
        .signed_by(&private_key, &authority.certificate, &authority.private_key)
        .unwrap();
    TestIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: private_key.serialize_pem(),
    }
}

fn temp_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tunnelproxy-enrollment-integration-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

fn certificate_fingerprint(path: &PathBuf) -> tunnelproxy_control_plane::CertificateFingerprint {
    let pem = std::fs::read(path).unwrap();
    let mut reader = BufReader::new(Cursor::new(pem));
    let der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
    tunnelproxy_control_plane::CertificateFingerprint::from_bytes(
        Sha256::digest(der.as_ref()).into(),
    )
}

#[tokio::test]
async fn real_tls_bootstrap_and_renewal_publish_and_activate_credentials() {
    let directory = temp_directory();
    let database = directory.join("control-plane.sqlite");
    let snapshots = Arc::new(SqliteSnapshotRepository::open(&database).unwrap());
    snapshots
        .commit(&VersionedAuthorizationSnapshot::new(
            SnapshotVersion::FIRST,
            AuthorizationSnapshot::default(),
        ))
        .unwrap();
    let authority_runtime = PersistentSnapshotAuthority::open(snapshots.clone())
        .await
        .unwrap();

    let enrollment_ca = authority();
    let enrollment_server = server_identity("enrollment.test", &enrollment_ca);
    let agent_issuer = authority();
    let edge_server_ca = authority();
    let issuer = AgentCertificateIssuer::from_pem(
        agent_issuer.certificate_pem.as_bytes(),
        agent_issuer.private_key.serialize_pem().as_bytes(),
        Duration::from_secs(24 * 60 * 60),
    )
    .unwrap();
    let server = EnrollmentServer::bind(
        EnrollmentServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_clients: 4,
            request_timeout: Duration::from_secs(3),
            activation_grace: Duration::from_secs(60),
            reconcile_interval: Duration::from_millis(20),
            database_path: database.clone(),
            tls: EnrollmentServerTlsConfig::from_pem(
                enrollment_server.certificate_pem.as_bytes(),
                enrollment_server.private_key_pem.as_bytes(),
                Duration::from_secs(3),
            )
            .unwrap(),
            issuer,
            agent_server_ca_pem: edge_server_ca.certificate_pem.as_bytes().to_vec(),
        },
        authority_runtime.clone(),
    )
    .await
    .unwrap();
    let server_addr = server.local_addr();
    let (shutdown, signal) = shutdown_channel();
    let task = tokio::spawn(server.run_until_shutdown(signal));

    let agent_id = AgentId::new("agent-e2e").unwrap();
    let tunnel_id = TunnelId::new("tunnel-e2e").unwrap();
    let bootstrap = EnrollmentToken::from_bytes([7; 32]);
    EnrollmentRepository::open(&database)
        .unwrap()
        .create_bootstrap_token(
            tunnelproxy_control_plane::enrollment_token_hash(bootstrap.as_bytes()),
            &agent_id,
            &tunnel_id,
            tunnelproxy_control_plane::unix_time_now().unwrap() + 60,
        )
        .unwrap();
    let token_path = directory.join("renewal.token");
    write_enrollment_token(&token_path, bootstrap).unwrap();
    let certificate_path = directory.join("agent.pem");
    let config = AgentEnrollmentConfig {
        client: EnrollmentClientConfig {
            server_addr,
            server_name: "enrollment.test".to_owned(),
            server_ca_pem: enrollment_ca.certificate_pem.as_bytes().to_vec(),
            connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(3),
        },
        agent_id: agent_id.clone(),
        tunnel_id: tunnel_id.clone(),
        token_path: token_path.clone(),
        pending_path: directory.join("enrollment.pending"),
        credentials: AgentCredentialPaths {
            server_ca: directory.join("edge-ca.pem"),
            client_certificate: certificate_path.clone(),
            client_private_key: directory.join("agent-key.pem"),
            reload_manifest: directory.join("agent-tls.json"),
        },
        edge_server_name: "edge.test".to_owned(),
        edge_tls_handshake_timeout: Duration::from_secs(2),
        renew_before: Duration::from_secs(60),
        poll_interval: Duration::from_secs(60),
        activation_timeout: Duration::from_secs(2),
    };

    assert_eq!(bootstrap_agent_credentials(&config).await.unwrap(), 2);
    let first_token = read_enrollment_token(&token_path).unwrap();
    assert_ne!(first_token, bootstrap);
    let first_fingerprint = certificate_fingerprint(&certificate_path);
    assert!(authority_runtime
        .current()
        .snapshot()
        .authorize(&first_fingerprint, &agent_id, &tunnel_id)
        .is_ok());
    assert!(!config.pending_path.exists());
    assert!(config.credentials.reload_manifest.exists());

    assert_eq!(bootstrap_agent_credentials(&config).await.unwrap(), 3);
    let second_token = read_enrollment_token(&token_path).unwrap();
    assert_ne!(second_token, first_token);
    let second_fingerprint = certificate_fingerprint(&certificate_path);
    assert_ne!(second_fingerprint, first_fingerprint);
    let current = authority_runtime.current();
    assert_eq!(current.version().get(), 4);
    assert_eq!(current.snapshot().certificate_count(), 1);
    assert_eq!(
        current
            .snapshot()
            .authorize(&first_fingerprint, &agent_id, &tunnel_id),
        Err(AuthorizationError::UnknownCertificate)
    );
    assert!(current
        .snapshot()
        .authorize(&second_fingerprint, &agent_id, &tunnel_id)
        .is_ok());

    let now = tunnelproxy_control_plane::unix_time_now().unwrap();
    let abandoned_fingerprint =
        tunnelproxy_control_plane::CertificateFingerprint::from_bytes([91; 32]);
    EnrollmentRepository::open(&database)
        .unwrap()
        .commit_issuance(
            &IssuanceCandidate {
                request_id: EnrollmentRequestId::from_bytes([92; 16]),
                presented_token_hash: tunnelproxy_control_plane::enrollment_token_hash(
                    second_token.as_bytes(),
                ),
                next_token_hash: tunnelproxy_control_plane::enrollment_token_hash(&[93; 32]),
                agent_id: agent_id.clone(),
                tunnel_id: tunnel_id.clone(),
                csr_digest: [94; 32],
                certificate_pem: b"abandoned-certificate".to_vec(),
                fingerprint: abandoned_fingerprint,
                not_after_unix: now + 120,
                activation_deadline_unix: now + 1,
            },
            now,
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if authority_runtime.current().version().get() >= 6 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let reconciled = authority_runtime.current();
    assert!(reconciled
        .snapshot()
        .authorize(&second_fingerprint, &agent_id, &tunnel_id)
        .is_ok());
    assert_eq!(
        reconciled
            .snapshot()
            .authorize(&abandoned_fingerprint, &agent_id, &tunnel_id),
        Err(AuthorizationError::UnknownCertificate)
    );

    let revoked = EnrollmentRepository::open(&database)
        .unwrap()
        .revoke_agent(
            &agent_id,
            &tunnel_id,
            tunnelproxy_control_plane::unix_time_now().unwrap(),
        )
        .unwrap();
    assert!(revoked.snapshot_changed);
    authority_runtime.refresh_from_repository().await.unwrap();
    assert_eq!(
        authority_runtime.current().snapshot().authorize(
            &second_fingerprint,
            &agent_id,
            &tunnel_id
        ),
        Err(AuthorizationError::UnknownCertificate)
    );
    assert!(matches!(
        bootstrap_agent_credentials(&config).await,
        Err(AgentEnrollmentError::Rejected(
            EnrollmentErrorCode::CredentialRevoked
        ))
    ));

    shutdown.shutdown();
    task.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
