//! Edge-side mutual-TLS configuration for Agent transports.

use std::fmt;
use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tunnelproxy_common::{
    certificate_validity, load_tls_reload_generation, ReloadableConfig, ShutdownSignal,
    TlsConfigStatus, TlsGenerationError, TlsReloadCandidate, TlsReloadFile, TlsReloadGeneration,
    TlsReloadRuntime, TlsReloadRuntimeConfig, TlsReloadRuntimeError,
};
use tunnelproxy_common::{AgentId, TunnelId};
use tunnelproxy_control_plane::{
    authorization_snapshot_channel, AgentGrant, AuthorizationError, AuthorizationSnapshot,
    AuthorizationSnapshotPublisher, AuthorizationSnapshotSubscription, CertificateFingerprint,
    SnapshotBootstrapClient, SnapshotClientConfig, SnapshotClientError, SnapshotClientRuntime,
    SnapshotError, SnapshotSourceHealth, SnapshotVersion, TunnelGrant, TunnelStatus,
    VersionedAuthorizationSnapshot,
};
use tunnelproxy_protocol::{HandshakeErrorCode, RegistrationRequest};

pub const TUNNELPROXY_ALPN: &[u8] = b"tunnelproxy/2";

pub(crate) trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TransportIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type BoxedTransport = Box<dyn TransportIo>;

/// Registration authorization applied after Protocol v2 REGISTER decoding.
#[derive(Clone)]
pub struct EdgeRegistrationPolicy {
    mode: EdgeRegistrationMode,
}

#[derive(Clone)]
enum EdgeRegistrationMode {
    LoopbackDevelopment {
        registrations: Arc<Vec<RegistrationRequest>>,
    },
    MutualTls {
        snapshots: AuthorizationSnapshotSubscription,
        /// Static policies retain their producer so the source does not look
        /// stale. Dynamic policies leave ownership with the control plane.
        static_source: Option<AuthorizationSnapshotPublisher>,
        /// Reloadable local policies consume their retained publisher just
        /// like a remote snapshot source so removed certificates revoke live
        /// sessions.
        local_updates: bool,
    },
}

/// Exact identity established by certificate-bound registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedRegistration {
    pub certificate: Option<CertificateFingerprint>,
    pub agent_id: AgentId,
    pub tunnel_id: TunnelId,
    pub snapshot_version: Option<SnapshotVersion>,
}

impl EdgeRegistrationPolicy {
    pub fn loopback_development(agent_id: AgentId, tunnel_id: TunnelId) -> Self {
        Self {
            mode: EdgeRegistrationMode::LoopbackDevelopment {
                registrations: Arc::new(vec![RegistrationRequest::new(agent_id, tunnel_id)]),
            },
        }
    }

    pub fn loopback_allowlist(registrations: Vec<RegistrationRequest>) -> Self {
        Self {
            mode: EdgeRegistrationMode::LoopbackDevelopment {
                registrations: Arc::new(registrations),
            },
        }
    }

    pub fn mutual_tls(snapshot: AuthorizationSnapshot) -> Self {
        let initial = VersionedAuthorizationSnapshot::new(SnapshotVersion::FIRST, snapshot);
        let (publisher, snapshots) = authorization_snapshot_channel(initial);
        Self {
            mode: EdgeRegistrationMode::MutualTls {
                snapshots,
                static_source: Some(publisher),
                local_updates: false,
            },
        }
    }

    /// Uses a live, versioned authorization source owned by the control plane.
    pub fn mutual_tls_updates(snapshots: AuthorizationSnapshotSubscription) -> Self {
        Self {
            mode: EdgeRegistrationMode::MutualTls {
                snapshots,
                static_source: None,
                local_updates: false,
            },
        }
    }

    /// Builds a one-Agent/one-Tunnel snapshot from the exact public client
    /// certificate authorized by the current single-tunnel CLI.
    pub fn mutual_tls_from_client_cert_pem(
        agent_id: AgentId,
        tunnel_id: TunnelId,
        client_certificate_pem: &[u8],
    ) -> Result<Self, EdgeRegistrationPolicyError> {
        let snapshot = static_authorization_snapshot(agent_id, tunnel_id, client_certificate_pem)?;
        Ok(Self::mutual_tls(snapshot))
    }

    fn mutual_tls_reloadable(
        initial: VersionedAuthorizationSnapshot,
    ) -> (Self, AuthorizationSnapshotPublisher) {
        let (publisher, snapshots) = authorization_snapshot_channel(initial);
        (
            Self {
                mode: EdgeRegistrationMode::MutualTls {
                    snapshots,
                    static_source: Some(publisher.clone()),
                    local_updates: true,
                },
            },
            publisher,
        )
    }

    pub const fn is_mutual_tls(&self) -> bool {
        matches!(self.mode, EdgeRegistrationMode::MutualTls { .. })
    }

    pub fn contains_tunnel(&self, tunnel_id: &TunnelId) -> bool {
        match &self.mode {
            EdgeRegistrationMode::LoopbackDevelopment { registrations } => registrations
                .iter()
                .any(|registration| &registration.tunnel_id == tunnel_id),
            EdgeRegistrationMode::MutualTls { snapshots, .. } => {
                snapshots.current().snapshot().contains_tunnel(tunnel_id)
            }
        }
    }

    pub(crate) fn authorize(
        &self,
        peer_certificate: Option<&CertificateFingerprint>,
        request: &RegistrationRequest,
    ) -> Result<AuthorizedRegistration, HandshakeErrorCode> {
        match &self.mode {
            EdgeRegistrationMode::LoopbackDevelopment { registrations }
                if registrations.iter().any(|allowed| allowed == request) =>
            {
                Ok(AuthorizedRegistration {
                    certificate: None,
                    agent_id: request.agent_id.clone(),
                    tunnel_id: request.tunnel_id.clone(),
                    snapshot_version: None,
                })
            }
            EdgeRegistrationMode::LoopbackDevelopment { registrations }
                if registrations
                    .iter()
                    .any(|allowed| allowed.agent_id == request.agent_id) =>
            {
                Err(HandshakeErrorCode::UnauthorizedTunnel)
            }
            EdgeRegistrationMode::LoopbackDevelopment { .. } => {
                Err(HandshakeErrorCode::UnauthorizedAgent)
            }
            EdgeRegistrationMode::MutualTls { snapshots, .. } => {
                let certificate = peer_certificate.ok_or(HandshakeErrorCode::UnauthorizedAgent)?;
                let current = snapshots.current();
                current
                    .snapshot()
                    .authorize(certificate, &request.agent_id, &request.tunnel_id)
                    .map_err(|error| match error {
                        AuthorizationError::UnknownCertificate
                        | AuthorizationError::AgentMismatch => {
                            HandshakeErrorCode::UnauthorizedAgent
                        }
                        AuthorizationError::TunnelNotAuthorized => {
                            HandshakeErrorCode::UnauthorizedTunnel
                        }
                        AuthorizationError::TunnelDisabled => HandshakeErrorCode::TunnelDisabled,
                    })?;
                Ok(AuthorizedRegistration {
                    certificate: Some(*certificate),
                    agent_id: request.agent_id.clone(),
                    tunnel_id: request.tunnel_id.clone(),
                    snapshot_version: Some(current.version()),
                })
            }
        }
    }

    pub(crate) fn reauthorize(&self, principal: &AuthorizedRegistration) -> bool {
        let request =
            RegistrationRequest::new(principal.agent_id.clone(), principal.tunnel_id.clone());
        self.authorize(principal.certificate.as_ref(), &request)
            .is_ok()
    }

    pub(crate) fn snapshot_subscription(&self) -> Option<AuthorizationSnapshotSubscription> {
        match &self.mode {
            EdgeRegistrationMode::MutualTls {
                snapshots,
                static_source,
                local_updates,
            } if static_source.is_none() || *local_updates => Some(snapshots.clone()),
            EdgeRegistrationMode::LoopbackDevelopment { .. }
            | EdgeRegistrationMode::MutualTls { .. } => None,
        }
    }

    pub fn snapshot_version(&self) -> Option<SnapshotVersion> {
        match &self.mode {
            EdgeRegistrationMode::LoopbackDevelopment { .. } => None,
            EdgeRegistrationMode::MutualTls { snapshots, .. } => {
                Some(snapshots.current().version())
            }
        }
    }

    pub(crate) fn snapshot_source_health(&self) -> Option<SnapshotSourceHealth> {
        match &self.mode {
            EdgeRegistrationMode::LoopbackDevelopment { .. } => None,
            EdgeRegistrationMode::MutualTls { snapshots, .. } => Some(snapshots.source_health()),
        }
    }

    /// Dynamic policies may authorize a configured raw tunnel in a later full
    /// snapshot, so Edge can bind ingress before the grant exists.
    pub fn has_live_updates(&self) -> bool {
        match &self.mode {
            EdgeRegistrationMode::MutualTls {
                static_source,
                local_updates,
                ..
            } => static_source.is_none() || *local_updates,
            EdgeRegistrationMode::LoopbackDevelopment { .. } => false,
        }
    }
}

/// Bootstraps the first durable authorization snapshot over the dedicated mTLS
/// control-plane channel, then returns the reconnecting client runtime that
/// feeds later versions into the same Edge policy.
pub async fn bootstrap_registration_from_snapshot_service(
    config: SnapshotClientConfig,
) -> Result<(EdgeRegistrationPolicy, SnapshotClientRuntime), SnapshotClientError> {
    let (subscription, runtime) = SnapshotBootstrapClient::bootstrap(config).await?;
    Ok((
        EdgeRegistrationPolicy::mutual_tls_updates(subscription),
        runtime,
    ))
}

impl Default for EdgeRegistrationPolicy {
    fn default() -> Self {
        Self::loopback_development(
            AgentId::new("agent-dev").expect("hardcoded AgentId is valid"),
            TunnelId::new("tunnel-dev").expect("hardcoded TunnelId is valid"),
        )
    }
}

impl fmt::Debug for EdgeRegistrationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            EdgeRegistrationMode::LoopbackDevelopment { registrations } => f
                .debug_struct("LoopbackDevelopment")
                .field("registration_count", &registrations.len())
                .finish(),
            EdgeRegistrationMode::MutualTls {
                snapshots,
                static_source,
                local_updates,
            } => f
                .debug_struct("MutualTlsAuthorization")
                .field("version", &snapshots.current().version())
                .field(
                    "certificate_count",
                    &snapshots.current().snapshot().certificate_count(),
                )
                .field("dynamic", &(static_source.is_none() || *local_updates))
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug)]
pub enum EdgeRegistrationPolicyError {
    MissingClientCertificate,
    InvalidClientCertificate,
    Snapshot(SnapshotError),
}

impl fmt::Display for EdgeRegistrationPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClientCertificate => {
                f.write_str("authorized client certificate bundle is empty")
            }
            Self::InvalidClientCertificate => {
                f.write_str("authorized client certificate bundle is invalid")
            }
            Self::Snapshot(error) => write!(f, "invalid authorization snapshot: {error}"),
        }
    }
}

impl std::error::Error for EdgeRegistrationPolicyError {}

fn static_authorization_snapshot(
    agent_id: AgentId,
    tunnel_id: TunnelId,
    client_certificate_pem: &[u8],
) -> Result<AuthorizationSnapshot, EdgeRegistrationPolicyError> {
    let certificates = parse_registration_certificates(client_certificate_pem)?;
    let fingerprint = CertificateFingerprint::from_certificate_der(certificates[0].as_ref());
    AuthorizationSnapshot::new(vec![AgentGrant::new(
        fingerprint,
        agent_id,
        vec![TunnelGrant::new(tunnel_id, TunnelStatus::Enabled)],
    )])
    .map_err(EdgeRegistrationPolicyError::Snapshot)
}

/// Security applied before Edge accepts a Protocol v2 Agent handshake.
#[derive(Clone, Default)]
pub enum EdgeTransportSecurity {
    /// Development-only mode restricted to a loopback Agent listener.
    #[default]
    PlaintextLoopback,
    /// Mutual TLS requiring a client certificate signed by the configured CA.
    MutualTls(EdgeTlsConfig),
}

impl EdgeTransportSecurity {
    pub const fn is_tls(&self) -> bool {
        matches!(self, Self::MutualTls(_))
    }
}

impl fmt::Debug for EdgeTransportSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextLoopback => f.write_str("PlaintextLoopback"),
            Self::MutualTls(config) => f
                .debug_struct("MutualTls")
                .field("handshake_timeout", &config.handshake_timeout)
                .finish_non_exhaustive(),
        }
    }
}

/// Parsed server TLS configuration. Private-key material is never included in
/// its debug representation or error values.
#[derive(Clone)]
pub struct EdgeTlsConfig {
    pub(crate) server_config: ReloadableConfig<ServerConfig>,
    pub(crate) handshake_timeout: Duration,
}

impl EdgeTlsConfig {
    pub fn from_pem(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        client_ca_pem: &[u8],
        handshake_timeout: Duration,
    ) -> Result<Self, EdgeTlsConfigError> {
        if handshake_timeout.is_zero() {
            return Err(EdgeTlsConfigError::ZeroHandshakeTimeout);
        }
        let candidate = build_server_config(server_cert_pem, server_key_pem, client_ca_pem)?;
        Ok(Self {
            server_config: ReloadableConfig::new(1, [0; 32], candidate.config, candidate.validity)
                .map_err(|_| EdgeTlsConfigError::InvalidCertificateValidity)?,
            handshake_timeout,
        })
    }

    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn reload_status(&self, expiry_warning: Duration) -> TlsConfigStatus {
        self.server_config
            .status(std::time::SystemTime::now(), expiry_warning)
    }
}

impl fmt::Debug for EdgeTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdgeTlsConfig")
            .field("handshake_timeout", &self.handshake_timeout)
            .field("generation", &self.server_config.generation())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeTlsConfigError {
    ZeroHandshakeTimeout,
    MissingServerCertificate,
    InvalidServerCertificate,
    MissingServerPrivateKey,
    InvalidServerPrivateKey,
    InvalidServerIdentity,
    MissingClientAuthorityCertificate,
    InvalidClientAuthorityCertificate,
    InvalidCertificateValidity,
}

impl fmt::Display for EdgeTlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroHandshakeTimeout => "TLS handshake timeout must be greater than zero",
            Self::MissingServerCertificate => "TLS server certificate bundle is empty",
            Self::InvalidServerCertificate => "TLS server certificate bundle is invalid",
            Self::MissingServerPrivateKey => "TLS server private key is missing",
            Self::InvalidServerPrivateKey => "TLS server private key is invalid",
            Self::InvalidServerIdentity => {
                "TLS server certificate and private key are incompatible"
            }
            Self::MissingClientAuthorityCertificate => {
                "TLS client CA bundle contains no certificate"
            }
            Self::InvalidClientAuthorityCertificate => {
                "TLS client CA bundle contains an invalid certificate"
            }
            Self::InvalidCertificateValidity => {
                "TLS server certificate validity is invalid or not currently active"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for EdgeTlsConfigError {}

#[derive(Clone, Copy)]
enum CertificateKind {
    Server,
    Authority,
}

fn parse_certificates(
    pem: &[u8],
    kind: CertificateKind,
) -> Result<Vec<CertificateDer<'static>>, EdgeTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certificates = certificates.map_err(|_| match kind {
        CertificateKind::Server => EdgeTlsConfigError::InvalidServerCertificate,
        CertificateKind::Authority => EdgeTlsConfigError::InvalidClientAuthorityCertificate,
    })?;
    if certificates.is_empty() {
        return Err(match kind {
            CertificateKind::Server => EdgeTlsConfigError::MissingServerCertificate,
            CertificateKind::Authority => EdgeTlsConfigError::MissingClientAuthorityCertificate,
        });
    }
    Ok(certificates)
}

fn parse_registration_certificates(
    pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>, EdgeRegistrationPolicyError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certificates =
        certificates.map_err(|_| EdgeRegistrationPolicyError::InvalidClientCertificate)?;
    if certificates.is_empty() {
        return Err(EdgeRegistrationPolicyError::MissingClientCertificate);
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, EdgeTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| EdgeTlsConfigError::InvalidServerPrivateKey)?
        .ok_or(EdgeTlsConfigError::MissingServerPrivateKey)
}

fn build_server_config(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<TlsReloadCandidate<ServerConfig>, EdgeTlsConfigError> {
    let server_certificates = parse_certificates(server_cert_pem, CertificateKind::Server)?;
    let validity = certificate_validity(server_certificates[0].as_ref())
        .map_err(|_| EdgeTlsConfigError::InvalidCertificateValidity)?;
    let server_key = parse_private_key(server_key_pem)?;
    let client_ca_certificates = parse_certificates(client_ca_pem, CertificateKind::Authority)?;
    let mut client_roots = RootCertStore::empty();
    for certificate in client_ca_certificates {
        client_roots
            .add(certificate)
            .map_err(|_| EdgeTlsConfigError::InvalidClientAuthorityCertificate)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|_| EdgeTlsConfigError::InvalidClientAuthorityCertificate)?;
    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certificates, server_key)
        .map_err(|_| EdgeTlsConfigError::InvalidServerIdentity)?;
    server_config.alpn_protocols = vec![TUNNELPROXY_ALPN.to_vec()];
    Ok(TlsReloadCandidate {
        config: server_config,
        validity,
    })
}

const RELOAD_SERVER_CERTIFICATE: &str = "server_certificate";
const RELOAD_SERVER_PRIVATE_KEY: &str = "server_private_key";
const RELOAD_CLIENT_CA: &str = "client_ca";
const RELOAD_AUTHORIZED_CLIENT_CERTIFICATE: &str = "authorized_client_certificate";

#[derive(Debug, Clone)]
pub struct EdgeTlsReloadConfig {
    pub manifest_path: std::path::PathBuf,
    pub server_certificate_path: std::path::PathBuf,
    pub server_private_key_path: std::path::PathBuf,
    pub client_ca_path: std::path::PathBuf,
    pub poll_interval: Duration,
    pub expiry_warning: Duration,
}

impl EdgeTlsReloadConfig {
    fn runtime_config(&self) -> TlsReloadRuntimeConfig {
        TlsReloadRuntimeConfig {
            manifest_path: self.manifest_path.clone(),
            files: vec![
                TlsReloadFile::new(
                    RELOAD_SERVER_CERTIFICATE,
                    self.server_certificate_path.clone(),
                ),
                TlsReloadFile::new(
                    RELOAD_SERVER_PRIVATE_KEY,
                    self.server_private_key_path.clone(),
                ),
                TlsReloadFile::new(RELOAD_CLIENT_CA, self.client_ca_path.clone()),
            ],
            poll_interval: self.poll_interval,
            expiry_warning: self.expiry_warning,
        }
    }

    fn runtime_config_with_static_authorization(
        &self,
        authorized_client_certificate_path: std::path::PathBuf,
    ) -> TlsReloadRuntimeConfig {
        let mut config = self.runtime_config();
        config.files.push(TlsReloadFile::new(
            RELOAD_AUTHORIZED_CLIENT_CERTIFICATE,
            authorized_client_certificate_path,
        ));
        config
    }
}

type EdgeBuild =
    Box<dyn Fn(&TlsReloadGeneration) -> Result<TlsReloadCandidate<ServerConfig>, ()> + Send + Sync>;

pub struct EdgeTlsReloadRuntime {
    inner: TlsReloadRuntime<ServerConfig, EdgeBuild>,
}

impl EdgeTlsReloadRuntime {
    pub async fn bootstrap(
        reload: EdgeTlsReloadConfig,
        handshake_timeout: Duration,
    ) -> Result<(EdgeTlsConfig, Self), EdgeTlsReloadBootstrapError> {
        if handshake_timeout.is_zero() {
            return Err(EdgeTlsReloadBootstrapError::Tls(
                EdgeTlsConfigError::ZeroHandshakeTimeout,
            ));
        }
        let runtime_config = reload.runtime_config();
        runtime_config
            .validate()
            .map_err(EdgeTlsReloadBootstrapError::Runtime)?;
        let generation = load_tls_reload_generation(
            runtime_config.manifest_path.clone(),
            runtime_config.files.clone(),
        )
        .await
        .map_err(EdgeTlsReloadBootstrapError::Load)?;
        let candidate = build_reload_generation(&generation)
            .map_err(|()| EdgeTlsReloadBootstrapError::Candidate)?;
        let server_config = ReloadableConfig::new(
            generation.generation(),
            generation.manifest_digest(),
            candidate.config,
            candidate.validity,
        )
        .map_err(EdgeTlsReloadBootstrapError::Generation)?;
        let tls = EdgeTlsConfig {
            server_config: server_config.clone(),
            handshake_timeout,
        };
        let inner = TlsReloadRuntime::new(
            runtime_config,
            server_config,
            Box::new(build_reload_generation) as EdgeBuild,
        )
        .map_err(EdgeTlsReloadBootstrapError::Runtime)?;
        Ok((tls, Self { inner }))
    }

    /// Bootstraps the Agent-facing TLS identity and the exact static Agent
    /// authorization from one manifest generation. Later generations publish
    /// authorization before TLS so a removed certificate is denied before the
    /// newly trusted transport identity becomes active.
    pub async fn bootstrap_with_static_authorization(
        reload: EdgeTlsReloadConfig,
        authorized_client_certificate_path: std::path::PathBuf,
        handshake_timeout: Duration,
        agent_id: AgentId,
        tunnel_id: TunnelId,
    ) -> Result<(EdgeTlsConfig, EdgeRegistrationPolicy, Self), EdgeTlsReloadBootstrapError> {
        if handshake_timeout.is_zero() {
            return Err(EdgeTlsReloadBootstrapError::Tls(
                EdgeTlsConfigError::ZeroHandshakeTimeout,
            ));
        }
        let runtime_config =
            reload.runtime_config_with_static_authorization(authorized_client_certificate_path);
        runtime_config
            .validate()
            .map_err(EdgeTlsReloadBootstrapError::Runtime)?;
        let generation = load_tls_reload_generation(
            runtime_config.manifest_path.clone(),
            runtime_config.files.clone(),
        )
        .await
        .map_err(EdgeTlsReloadBootstrapError::Load)?;
        let candidate = build_reload_generation(&generation)
            .map_err(|()| EdgeTlsReloadBootstrapError::Candidate)?;
        let snapshot = static_authorization_snapshot(
            agent_id.clone(),
            tunnel_id.clone(),
            generation
                .file(RELOAD_AUTHORIZED_CLIENT_CERTIFICATE)
                .map_err(EdgeTlsReloadBootstrapError::Load)?,
        )
        .map_err(EdgeTlsReloadBootstrapError::Authorization)?;
        let version = SnapshotVersion::new(generation.generation())
            .ok_or(EdgeTlsReloadBootstrapError::Candidate)?;
        let (registration, publisher) = EdgeRegistrationPolicy::mutual_tls_reloadable(
            VersionedAuthorizationSnapshot::new(version, snapshot),
        );
        let server_config = ReloadableConfig::new(
            generation.generation(),
            generation.manifest_digest(),
            candidate.config,
            candidate.validity,
        )
        .map_err(EdgeTlsReloadBootstrapError::Generation)?;
        let tls = EdgeTlsConfig {
            server_config: server_config.clone(),
            handshake_timeout,
        };
        let build_agent_id = agent_id;
        let build_tunnel_id = tunnel_id;
        let build = Box::new(move |generation: &TlsReloadGeneration| {
            let candidate = build_reload_generation(generation)?;
            let snapshot = static_authorization_snapshot(
                build_agent_id.clone(),
                build_tunnel_id.clone(),
                generation
                    .file(RELOAD_AUTHORIZED_CLIENT_CERTIFICATE)
                    .map_err(|_| ())?,
            )
            .map_err(|_| ())?;
            let version = SnapshotVersion::new(generation.generation()).ok_or(())?;
            publisher
                .publish(VersionedAuthorizationSnapshot::new(version, snapshot))
                .map_err(|_| ())?;
            Ok(candidate)
        }) as EdgeBuild;
        let inner = TlsReloadRuntime::new(runtime_config, server_config, build)
            .map_err(EdgeTlsReloadBootstrapError::Runtime)?;
        Ok((tls, registration, Self { inner }))
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), TlsReloadRuntimeError> {
        self.inner.run_until_shutdown(signal).await
    }
}

fn build_reload_generation(
    generation: &TlsReloadGeneration,
) -> Result<TlsReloadCandidate<ServerConfig>, ()> {
    build_server_config(
        generation.file(RELOAD_SERVER_CERTIFICATE).map_err(|_| ())?,
        generation.file(RELOAD_SERVER_PRIVATE_KEY).map_err(|_| ())?,
        generation.file(RELOAD_CLIENT_CA).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

#[derive(Debug)]
pub enum EdgeTlsReloadBootstrapError {
    Load(tunnelproxy_common::TlsReloadLoadError),
    Tls(EdgeTlsConfigError),
    Generation(TlsGenerationError),
    Runtime(TlsReloadRuntimeError),
    Authorization(EdgeRegistrationPolicyError),
    Candidate,
}

impl std::fmt::Display for EdgeTlsReloadBootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(error) => error.fmt(f),
            Self::Tls(error) => error.fmt(f),
            Self::Generation(error) => error.fmt(f),
            Self::Runtime(error) => error.fmt(f),
            Self::Authorization(error) => error.fmt(f),
            Self::Candidate => f.write_str("TLS reload generation contains invalid credentials"),
        }
    }
}

impl std::error::Error for EdgeTlsReloadBootstrapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pem_inputs_are_typed() {
        assert_eq!(
            EdgeTlsConfig::from_pem(b"", b"", b"", Duration::from_secs(1)).unwrap_err(),
            EdgeTlsConfigError::MissingServerCertificate
        );
    }

    #[test]
    fn debug_output_contains_no_key_material() {
        let security = EdgeTransportSecurity::PlaintextLoopback;
        assert_eq!(format!("{security:?}"), "PlaintextLoopback");
    }

    #[test]
    fn loopback_policy_requires_exact_identity() {
        let policy = EdgeRegistrationPolicy::default();
        let valid = RegistrationRequest::new(
            AgentId::new("agent-dev").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        );
        assert!(policy.authorize(None, &valid).is_ok());
        let wrong = RegistrationRequest::new(
            AgentId::new("other-agent").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        );
        assert_eq!(
            policy.authorize(None, &wrong),
            Err(HandshakeErrorCode::UnauthorizedAgent)
        );
    }

    #[test]
    fn live_policy_revalidation_closes_authorize_before_publication_race() {
        let certificate = CertificateFingerprint::from_bytes([3; 32]);
        let agent_id = AgentId::new("agent-live").unwrap();
        let tunnel_id = TunnelId::new("tunnel-live").unwrap();
        let enabled = AuthorizationSnapshot::new(vec![AgentGrant::new(
            certificate,
            agent_id.clone(),
            vec![TunnelGrant::new(tunnel_id.clone(), TunnelStatus::Enabled)],
        )])
        .unwrap();
        let (publisher, subscription) = authorization_snapshot_channel(
            VersionedAuthorizationSnapshot::new(SnapshotVersion::FIRST, enabled),
        );
        let policy = EdgeRegistrationPolicy::mutual_tls_updates(subscription);
        let request = RegistrationRequest::new(agent_id.clone(), tunnel_id.clone());
        let principal = policy.authorize(Some(&certificate), &request).unwrap();

        let disabled = AuthorizationSnapshot::new(vec![AgentGrant::new(
            certificate,
            agent_id,
            vec![TunnelGrant::new(tunnel_id, TunnelStatus::Disabled)],
        )])
        .unwrap();
        publisher
            .publish(VersionedAuthorizationSnapshot::new(
                SnapshotVersion::new(2).unwrap(),
                disabled,
            ))
            .unwrap();

        assert!(!policy.reauthorize(&principal));
    }
}
