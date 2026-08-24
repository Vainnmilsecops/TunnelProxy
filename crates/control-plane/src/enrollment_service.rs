use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tunnelproxy_common::ShutdownSignal;
use tunnelproxy_protocol::{
    read_enrollment_message, write_enrollment_message, EnrollmentErrorCode, EnrollmentMessage,
    EnrollmentProtocolError, ENROLLMENT_PROTOCOL_ALPN,
};

use crate::{
    enrollment_token_hash, unix_time_now, AgentCertificateIssuer, CertificateFingerprint,
    CertificateIssuerError, EnrollmentRepository, EnrollmentRepositoryError, IssuanceCandidate,
    PersistentSnapshotAuthority,
};

#[derive(Clone)]
pub struct EnrollmentServerTlsConfig {
    server_config: Arc<ServerConfig>,
    handshake_timeout: Duration,
}

impl EnrollmentServerTlsConfig {
    pub fn from_pem(
        server_certificate_pem: &[u8],
        server_private_key_pem: &[u8],
        handshake_timeout: Duration,
    ) -> Result<Self, EnrollmentTlsConfigError> {
        if handshake_timeout.is_zero() {
            return Err(EnrollmentTlsConfigError::InvalidTimeout);
        }
        let certificates = parse_certificates(server_certificate_pem)?;
        let private_key = parse_private_key(server_private_key_pem)?;
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|_| EnrollmentTlsConfigError::InvalidIdentity)?;
        server_config.alpn_protocols = vec![ENROLLMENT_PROTOCOL_ALPN.to_vec()];
        Ok(Self {
            server_config: Arc::new(server_config),
            handshake_timeout,
        })
    }
}

impl std::fmt::Debug for EnrollmentServerTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentServerTlsConfig")
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct EnrollmentServerConfig {
    pub listen_addr: SocketAddr,
    pub max_clients: usize,
    pub request_timeout: Duration,
    pub activation_grace: Duration,
    pub reconcile_interval: Duration,
    pub database_path: PathBuf,
    pub tls: EnrollmentServerTlsConfig,
    pub issuer: AgentCertificateIssuer,
    /// Edge server trust returned to Agent and included in its Session 20
    /// client bundle. This is public certificate material, never a key.
    pub agent_server_ca_pem: Vec<u8>,
}

impl EnrollmentServerConfig {
    pub fn validate(&self) -> Result<(), EnrollmentServerError> {
        if self.max_clients == 0
            || self.request_timeout.is_zero()
            || self.activation_grace.is_zero()
            || self.activation_grace.as_secs() == 0
            || self.reconcile_interval.is_zero()
            || self.activation_grace > self.issuer.validity()
            || self.database_path.as_os_str().is_empty()
            || self.agent_server_ca_pem.is_empty()
        {
            return Err(EnrollmentServerError::InvalidConfig);
        }
        parse_certificates(&self.agent_server_ca_pem)
            .map_err(|_| EnrollmentServerError::InvalidConfig)?;
        Ok(())
    }
}

pub struct EnrollmentServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: EnrollmentServerConfig,
    repository: EnrollmentRepository,
    authority: PersistentSnapshotAuthority,
    permits: Arc<Semaphore>,
    mutation_gate: Arc<Mutex<()>>,
}

impl EnrollmentServer {
    pub async fn bind(
        config: EnrollmentServerConfig,
        authority: PersistentSnapshotAuthority,
    ) -> Result<Self, EnrollmentServerError> {
        config.validate()?;
        let database_path = config.database_path.clone();
        let repository =
            tokio::task::spawn_blocking(move || EnrollmentRepository::open(database_path))
                .await
                .map_err(|_| EnrollmentServerError::StorageTask)?
                .map_err(EnrollmentServerError::Repository)?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(EnrollmentServerError::Bind)?;
        let local_addr = listener.local_addr().map_err(EnrollmentServerError::Bind)?;
        let max_clients = config.max_clients;
        Ok(Self {
            listener,
            local_addr,
            config,
            repository,
            authority,
            permits: Arc::new(Semaphore::new(max_clients)),
            mutation_gate: Arc::new(Mutex::new(())),
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), EnrollmentServerError> {
        info!(addr = %self.local_addr, event = "enrollment_server_started");
        let mut tasks = JoinSet::new();
        let mut reconcile = tokio::time::interval_at(
            Instant::now() + self.config.reconcile_interval,
            self.config.reconcile_interval,
        );
        reconcile.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                _ = reconcile.tick() => {
                    let _guard = self.mutation_gate.lock().await;
                    let repository = self.repository.clone();
                    let outcome = tokio::task::spawn_blocking(move || {
                        repository.reconcile_expired(unix_time_now()?)
                    })
                    .await
                    .map_err(|_| EnrollmentServerError::StorageTask)?
                    .map_err(EnrollmentServerError::Repository)?;
                    if outcome.snapshot_changed {
                        self.authority
                            .refresh_from_repository()
                            .await
                            .map_err(|_| EnrollmentServerError::Authority)?;
                    }
                    if outcome.affected_credentials != 0 {
                        info!(
                            affected_credentials = outcome.affected_credentials,
                            snapshot_version = outcome.snapshot_version.get(),
                            event = "pending_credential_expired"
                        );
                        info!(
                            affected_credentials = outcome.affected_credentials,
                            snapshot_version = outcome.snapshot_version.get(),
                            event = "credential_reconciliation_completed"
                        );
                    }
                }
                accepted = self.listener.accept() => {
                    let (socket, peer) = accepted.map_err(EnrollmentServerError::Accept)?;
                    let permit = match Arc::clone(&self.permits).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(%peer, event = "enrollment_capacity_rejected");
                            continue;
                        }
                    };
                    tasks.spawn(serve_connection(
                        socket,
                        peer,
                        permit,
                        self.config.clone(),
                        self.repository.clone(),
                        self.authority.clone(),
                        Arc::clone(&self.mutation_gate),
                    ));
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

async fn serve_connection(
    socket: TcpStream,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
    config: EnrollmentServerConfig,
    repository: EnrollmentRepository,
    authority: PersistentSnapshotAuthority,
    mutation_gate: Arc<Mutex<()>>,
) {
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls.server_config));
    let mut stream = match timeout(config.tls.handshake_timeout, acceptor.accept(socket)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            warn!(%peer, event = "enrollment_tls_rejected");
            return;
        }
    };
    if stream.get_ref().1.alpn_protocol() != Some(ENROLLMENT_PROTOCOL_ALPN) {
        warn!(%peer, event = "enrollment_alpn_rejected");
        return;
    }
    let request = match timeout(config.request_timeout, read_enrollment_message(&mut stream)).await
    {
        Ok(Ok(Some(request))) => request,
        _ => {
            let _ = write_error(&mut stream, EnrollmentErrorCode::InvalidRequest).await;
            return;
        }
    };
    let response = match request {
        EnrollmentMessage::Enroll {
            request_id,
            token,
            next_renewal_token,
            agent_id,
            tunnel_id,
            csr_der,
        } => {
            let _guard = mutation_gate.lock().await;
            let presented_token_hash = enrollment_token_hash(token.as_bytes());
            let next_token_hash = enrollment_token_hash(next_renewal_token.as_bytes());
            let csr_digest: [u8; 32] = Sha256::digest(&csr_der).into();
            let preflight_repository = repository.clone();
            let preflight_agent = agent_id.clone();
            let preflight_tunnel = tunnel_id.clone();
            let preflight = match tokio::task::spawn_blocking(move || {
                let now = unix_time_now()?;
                preflight_repository.preflight_issuance(
                    request_id,
                    presented_token_hash,
                    next_token_hash,
                    &preflight_agent,
                    &preflight_tunnel,
                    csr_digest,
                    now,
                )
            })
            .await
            {
                Ok(Ok(existing)) => existing,
                Ok(Err(error)) => {
                    let _ = write_error(&mut stream, repository_error_code(error)).await;
                    return;
                }
                Err(_) => {
                    let _ = write_error(&mut stream, EnrollmentErrorCode::Internal).await;
                    return;
                }
            };
            let durable = if let Some(existing) = preflight {
                existing
            } else {
                let issuer = config.issuer.clone();
                let issue_agent = agent_id.clone();
                let issue_tunnel = tunnel_id.clone();
                let issue_csr = csr_der.clone();
                let issued = match tokio::task::spawn_blocking(move || {
                    issuer.issue(request_id, &issue_agent, &issue_tunnel, &issue_csr)
                })
                .await
                {
                    Ok(Ok(issued)) => issued,
                    _ => {
                        let _ = write_error(&mut stream, EnrollmentErrorCode::InvalidCsr).await;
                        return;
                    }
                };
                let activation_deadline_unix = match unix_time_now().and_then(|now| {
                    now.checked_add(config.activation_grace.as_secs())
                        .ok_or(EnrollmentRepositoryError::InvalidTime)
                }) {
                    Ok(deadline) => deadline,
                    Err(_) => {
                        let _ = write_error(&mut stream, EnrollmentErrorCode::Internal).await;
                        return;
                    }
                };
                let candidate = IssuanceCandidate {
                    request_id,
                    presented_token_hash,
                    next_token_hash,
                    agent_id: agent_id.clone(),
                    tunnel_id: tunnel_id.clone(),
                    csr_digest,
                    certificate_pem: issued.certificate_pem,
                    fingerprint: issued.fingerprint,
                    not_after_unix: issued.not_after_unix,
                    activation_deadline_unix,
                };
                let commit_repository = repository.clone();
                match tokio::task::spawn_blocking(move || {
                    let now = unix_time_now()?;
                    commit_repository.commit_issuance(&candidate, now)
                })
                .await
                {
                    Ok(Ok(durable)) => durable,
                    Ok(Err(error)) => {
                        let _ = write_error(&mut stream, repository_error_code(error)).await;
                        return;
                    }
                    Err(_) => {
                        let _ = write_error(&mut stream, EnrollmentErrorCode::Internal).await;
                        return;
                    }
                }
            };
            if authority.refresh_from_repository().await.is_err() {
                let _ = write_error(&mut stream, EnrollmentErrorCode::Internal).await;
                return;
            }
            info!(
                %agent_id,
                %tunnel_id,
                generation = durable.generation.get(),
                fingerprint = %durable.fingerprint,
                event = "agent_certificate_issued"
            );
            EnrollmentMessage::Issued {
                request_id,
                generation: durable.generation.get(),
                not_after_unix: durable.not_after_unix,
                certificate_pem: durable.certificate_pem,
                server_ca_pem: config.agent_server_ca_pem,
                fingerprint: *durable.fingerprint.as_bytes(),
            }
        }
        EnrollmentMessage::Activate {
            request_id,
            renewal_token,
            fingerprint,
        } => {
            let _guard = mutation_gate.lock().await;
            let activate_repository = repository.clone();
            let version = match tokio::task::spawn_blocking(move || {
                let now = unix_time_now()?;
                activate_repository.activate(
                    request_id,
                    enrollment_token_hash(renewal_token.as_bytes()),
                    CertificateFingerprint::from_bytes(fingerprint),
                    now,
                )
            })
            .await
            {
                Ok(Ok(version)) => version,
                Ok(Err(error)) => {
                    if error == EnrollmentRepositoryError::RequestExpired
                        && authority.refresh_from_repository().await.is_err()
                    {
                        let _ = write_error(&mut stream, EnrollmentErrorCode::Internal).await;
                        return;
                    }
                    let _ = write_error(&mut stream, repository_error_code(error)).await;
                    return;
                }
                Err(_) => {
                    let _ = write_error(&mut stream, EnrollmentErrorCode::Internal).await;
                    return;
                }
            };
            if authority.refresh_from_repository().await.is_err() {
                let _ = write_error(&mut stream, EnrollmentErrorCode::Internal).await;
                return;
            }
            info!(
                snapshot_version = version.get(),
                fingerprint = %CertificateFingerprint::from_bytes(fingerprint),
                event = "agent_certificate_activated"
            );
            EnrollmentMessage::Activated {
                snapshot_version: version.get(),
            }
        }
        _ => EnrollmentMessage::Error {
            code: EnrollmentErrorCode::InvalidRequest,
        },
    };
    let _ = timeout(
        config.request_timeout,
        write_enrollment_message(&mut stream, &response),
    )
    .await;
}

async fn write_error(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    code: EnrollmentErrorCode,
) -> Result<(), EnrollmentProtocolError> {
    write_enrollment_message(stream, &EnrollmentMessage::Error { code }).await
}

fn repository_error_code(error: EnrollmentRepositoryError) -> EnrollmentErrorCode {
    match error {
        EnrollmentRepositoryError::Unauthorized => EnrollmentErrorCode::Unauthorized,
        EnrollmentRepositoryError::TokenExpired => EnrollmentErrorCode::TokenExpired,
        EnrollmentRepositoryError::CredentialRevoked => EnrollmentErrorCode::CredentialRevoked,
        EnrollmentRepositoryError::RequestExpired => EnrollmentErrorCode::RequestExpired,
        EnrollmentRepositoryError::IdentityMismatch => EnrollmentErrorCode::IdentityMismatch,
        EnrollmentRepositoryError::Conflict => EnrollmentErrorCode::Conflict,
        EnrollmentRepositoryError::Storage
        | EnrollmentRepositoryError::Uninitialized
        | EnrollmentRepositoryError::Corrupt
        | EnrollmentRepositoryError::InvalidTime
        | EnrollmentRepositoryError::VersionExhausted
        | EnrollmentRepositoryError::Random
        | EnrollmentRepositoryError::TokenOutput
        | EnrollmentRepositoryError::ResourceLimit => EnrollmentErrorCode::Internal,
    }
}

fn parse_certificates(
    pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>, EnrollmentTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certificates = certificates.map_err(|_| EnrollmentTlsConfigError::InvalidCertificate)?;
    if certificates.is_empty() {
        return Err(EnrollmentTlsConfigError::InvalidCertificate);
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, EnrollmentTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| EnrollmentTlsConfigError::InvalidPrivateKey)?
        .ok_or(EnrollmentTlsConfigError::InvalidPrivateKey)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentTlsConfigError {
    InvalidTimeout,
    InvalidCertificate,
    InvalidPrivateKey,
    InvalidIdentity,
}

impl std::fmt::Display for EnrollmentTlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidTimeout => "enrollment TLS handshake timeout is invalid",
            Self::InvalidCertificate => "enrollment TLS certificate is invalid",
            Self::InvalidPrivateKey => "enrollment TLS private key is invalid",
            Self::InvalidIdentity => "enrollment TLS certificate and private key do not match",
        };
        f.write_str(message)
    }
}

impl std::error::Error for EnrollmentTlsConfigError {}

#[derive(Debug)]
pub enum EnrollmentServerError {
    InvalidConfig,
    Bind(std::io::Error),
    Accept(std::io::Error),
    Repository(EnrollmentRepositoryError),
    StorageTask,
    Authority,
}

impl std::fmt::Display for EnrollmentServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidConfig => "enrollment server configuration is invalid",
            Self::Bind(_) => "enrollment server bind failed",
            Self::Accept(_) => "enrollment server accept failed",
            Self::Repository(_) => "enrollment repository initialization failed",
            Self::StorageTask => "enrollment repository worker stopped unexpectedly",
            Self::Authority => "enrollment snapshot publication failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for EnrollmentServerError {}

impl From<CertificateIssuerError> for EnrollmentServerError {
    fn from(_: CertificateIssuerError) -> Self {
        Self::InvalidConfig
    }
}
