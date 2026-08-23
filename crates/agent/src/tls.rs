//! Agent-side transport security configuration.

use std::fmt;
use std::io::{BufReader, Cursor};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tunnelproxy_common::{
    certificate_validity, load_tls_reload_generation, ReloadableConfig, ShutdownSignal,
    TlsConfigStatus, TlsGenerationError, TlsReloadCandidate, TlsReloadFile, TlsReloadGeneration,
    TlsReloadRuntime, TlsReloadRuntimeConfig, TlsReloadRuntimeError,
};

pub const TUNNELPROXY_ALPN: &[u8] = b"tunnelproxy/2";

pub(crate) trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TransportIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type BoxedTransport = Box<dyn TransportIo>;

/// Security applied before the Tunnel Protocol v2 handshake.
#[derive(Clone, Default)]
pub enum AgentTransportSecurity {
    /// Development-only transport. Runtime validation restricts this mode to
    /// loopback Edge addresses.
    #[default]
    PlaintextLoopback,
    /// TLS with server verification and an Agent client certificate.
    MutualTls(AgentTlsConfig),
}

impl fmt::Debug for AgentTransportSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextLoopback => f.write_str("PlaintextLoopback"),
            Self::MutualTls(config) => f
                .debug_struct("MutualTls")
                .field("server_name", &config.server_name)
                .field("handshake_timeout", &config.handshake_timeout)
                .finish_non_exhaustive(),
        }
    }
}

impl AgentTransportSecurity {
    pub const fn is_tls(&self) -> bool {
        matches!(self, Self::MutualTls(_))
    }
}

/// Parsed client TLS configuration. Private-key material is retained only by
/// rustls and is deliberately omitted from `Debug` output.
#[derive(Clone)]
pub struct AgentTlsConfig {
    pub(crate) client_config: ReloadableConfig<ClientConfig>,
    pub(crate) server_name: ServerName<'static>,
    pub(crate) handshake_timeout: Duration,
}

impl AgentTlsConfig {
    pub fn from_pem(
        ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        server_name: &str,
        handshake_timeout: Duration,
    ) -> Result<Self, AgentTlsConfigError> {
        if handshake_timeout.is_zero() {
            return Err(AgentTlsConfigError::ZeroHandshakeTimeout);
        }
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| AgentTlsConfigError::InvalidServerName)?;
        let candidate = build_client_config(ca_pem, client_cert_pem, client_key_pem)?;
        Ok(Self {
            client_config: ReloadableConfig::new(1, [0; 32], candidate.config, candidate.validity)
                .map_err(|_| AgentTlsConfigError::InvalidCertificateValidity)?,
            server_name,
            handshake_timeout,
        })
    }

    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn server_name(&self) -> &ServerName<'static> {
        &self.server_name
    }

    pub fn reload_status(&self, expiry_warning: Duration) -> TlsConfigStatus {
        self.client_config
            .status(std::time::SystemTime::now(), expiry_warning)
    }
}

impl fmt::Debug for AgentTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentTlsConfig")
            .field("server_name", &self.server_name)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("generation", &self.client_config.generation())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTlsConfigError {
    ZeroHandshakeTimeout,
    InvalidServerName,
    MissingAuthorityCertificate,
    InvalidAuthorityCertificate,
    MissingClientCertificate,
    InvalidClientCertificate,
    MissingPrivateKey,
    InvalidPrivateKey,
    InvalidClientIdentity,
    InvalidCertificateValidity,
}

impl fmt::Display for AgentTlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroHandshakeTimeout => "TLS handshake timeout must be greater than zero",
            Self::InvalidServerName => "TLS server name is invalid",
            Self::MissingAuthorityCertificate => "TLS CA bundle contains no certificate",
            Self::InvalidAuthorityCertificate => "TLS CA bundle contains an invalid certificate",
            Self::MissingClientCertificate => "TLS client certificate bundle is empty",
            Self::InvalidClientCertificate => "TLS client certificate bundle is invalid",
            Self::MissingPrivateKey => "TLS client private key is missing",
            Self::InvalidPrivateKey => "TLS client private key is invalid",
            Self::InvalidClientIdentity => {
                "TLS client certificate and private key are incompatible"
            }
            Self::InvalidCertificateValidity => {
                "TLS client certificate validity is invalid or not currently active"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for AgentTlsConfigError {}

#[derive(Clone, Copy)]
enum CertificateKind {
    Authority,
    Client,
}

fn parse_certificates(
    pem: &[u8],
    kind: CertificateKind,
) -> Result<Vec<CertificateDer<'static>>, AgentTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certificates = certificates.map_err(|_| match kind {
        CertificateKind::Authority => AgentTlsConfigError::InvalidAuthorityCertificate,
        CertificateKind::Client => AgentTlsConfigError::InvalidClientCertificate,
    })?;
    if certificates.is_empty() {
        return Err(match kind {
            CertificateKind::Authority => AgentTlsConfigError::MissingAuthorityCertificate,
            CertificateKind::Client => AgentTlsConfigError::MissingClientCertificate,
        });
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, AgentTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| AgentTlsConfigError::InvalidPrivateKey)?
        .ok_or(AgentTlsConfigError::MissingPrivateKey)
}

fn build_client_config(
    ca_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
) -> Result<TlsReloadCandidate<ClientConfig>, AgentTlsConfigError> {
    let ca_certificates = parse_certificates(ca_pem, CertificateKind::Authority)?;
    let client_certificates = parse_certificates(client_cert_pem, CertificateKind::Client)?;
    let validity = certificate_validity(client_certificates[0].as_ref())
        .map_err(|_| AgentTlsConfigError::InvalidCertificateValidity)?;
    let client_key = parse_private_key(client_key_pem)?;
    let mut roots = RootCertStore::empty();
    for certificate in ca_certificates {
        roots
            .add(certificate)
            .map_err(|_| AgentTlsConfigError::InvalidAuthorityCertificate)?;
    }
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certificates, client_key)
        .map_err(|_| AgentTlsConfigError::InvalidClientIdentity)?;
    client_config.alpn_protocols = vec![TUNNELPROXY_ALPN.to_vec()];
    Ok(TlsReloadCandidate {
        config: client_config,
        validity,
    })
}

const RELOAD_SERVER_CA: &str = "server_ca";
const RELOAD_CLIENT_CERTIFICATE: &str = "client_certificate";
const RELOAD_CLIENT_PRIVATE_KEY: &str = "client_private_key";

#[derive(Debug, Clone)]
pub struct AgentTlsReloadConfig {
    pub manifest_path: std::path::PathBuf,
    pub server_ca_path: std::path::PathBuf,
    pub client_certificate_path: std::path::PathBuf,
    pub client_private_key_path: std::path::PathBuf,
    pub poll_interval: Duration,
    pub expiry_warning: Duration,
}

impl AgentTlsReloadConfig {
    fn runtime_config(&self) -> TlsReloadRuntimeConfig {
        TlsReloadRuntimeConfig {
            manifest_path: self.manifest_path.clone(),
            files: vec![
                TlsReloadFile::new(RELOAD_SERVER_CA, self.server_ca_path.clone()),
                TlsReloadFile::new(
                    RELOAD_CLIENT_CERTIFICATE,
                    self.client_certificate_path.clone(),
                ),
                TlsReloadFile::new(
                    RELOAD_CLIENT_PRIVATE_KEY,
                    self.client_private_key_path.clone(),
                ),
            ],
            poll_interval: self.poll_interval,
            expiry_warning: self.expiry_warning,
        }
    }
}

type AgentBuild = fn(&TlsReloadGeneration) -> Result<TlsReloadCandidate<ClientConfig>, ()>;

pub struct AgentTlsReloadRuntime {
    inner: TlsReloadRuntime<ClientConfig, AgentBuild>,
}

impl AgentTlsReloadRuntime {
    pub async fn bootstrap(
        reload: AgentTlsReloadConfig,
        server_name: &str,
        handshake_timeout: Duration,
    ) -> Result<(AgentTlsConfig, Self), AgentTlsReloadBootstrapError> {
        if handshake_timeout.is_zero() {
            return Err(AgentTlsReloadBootstrapError::Tls(
                AgentTlsConfigError::ZeroHandshakeTimeout,
            ));
        }
        let server_name = ServerName::try_from(server_name.to_owned()).map_err(|_| {
            AgentTlsReloadBootstrapError::Tls(AgentTlsConfigError::InvalidServerName)
        })?;
        let runtime_config = reload.runtime_config();
        runtime_config
            .validate()
            .map_err(AgentTlsReloadBootstrapError::Runtime)?;
        let generation = load_tls_reload_generation(
            runtime_config.manifest_path.clone(),
            runtime_config.files.clone(),
        )
        .await
        .map_err(AgentTlsReloadBootstrapError::Load)?;
        let candidate = build_reload_generation(&generation)
            .map_err(|()| AgentTlsReloadBootstrapError::Candidate)?;
        let client_config = ReloadableConfig::new(
            generation.generation(),
            generation.manifest_digest(),
            candidate.config,
            candidate.validity,
        )
        .map_err(AgentTlsReloadBootstrapError::Generation)?;
        let tls = AgentTlsConfig {
            client_config: client_config.clone(),
            server_name,
            handshake_timeout,
        };
        let inner = TlsReloadRuntime::new(
            runtime_config,
            client_config,
            build_reload_generation as AgentBuild,
        )
        .map_err(AgentTlsReloadBootstrapError::Runtime)?;
        Ok((tls, Self { inner }))
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
) -> Result<TlsReloadCandidate<ClientConfig>, ()> {
    build_client_config(
        generation.file(RELOAD_SERVER_CA).map_err(|_| ())?,
        generation.file(RELOAD_CLIENT_CERTIFICATE).map_err(|_| ())?,
        generation.file(RELOAD_CLIENT_PRIVATE_KEY).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

#[derive(Debug)]
pub enum AgentTlsReloadBootstrapError {
    Load(tunnelproxy_common::TlsReloadLoadError),
    Tls(AgentTlsConfigError),
    Generation(TlsGenerationError),
    Runtime(TlsReloadRuntimeError),
    Candidate,
}

impl std::fmt::Display for AgentTlsReloadBootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(error) => error.fmt(f),
            Self::Tls(error) => error.fmt(f),
            Self::Generation(error) => error.fmt(f),
            Self::Runtime(error) => error.fmt(f),
            Self::Candidate => f.write_str("TLS reload generation contains invalid credentials"),
        }
    }
}

impl std::error::Error for AgentTlsReloadBootstrapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_contains_no_key_material() {
        let security = AgentTransportSecurity::PlaintextLoopback;
        assert_eq!(format!("{security:?}"), "PlaintextLoopback");
    }

    #[test]
    fn empty_pem_inputs_are_typed() {
        assert_eq!(
            AgentTlsConfig::from_pem(b"", b"", b"", "edge.test", Duration::from_secs(1))
                .unwrap_err(),
            AgentTlsConfigError::MissingAuthorityCertificate
        );
    }
}
