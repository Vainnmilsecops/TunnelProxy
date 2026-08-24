//! Public-client TLS termination for the HTTPS ingress.

use std::fmt;
use std::io::{BufReader, Cursor};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tunnelproxy_common::{
    certificate_validity, load_tls_reload_generation, ReloadableConfig, ShutdownSignal,
    TlsConfigStatus, TlsGenerationError, TlsReloadCandidate, TlsReloadFile, TlsReloadGeneration,
    TlsReloadRuntime, TlsReloadRuntimeConfig, TlsReloadRuntimeError,
};

pub const PUBLIC_HTTP1_ALPN: &[u8] = b"http/1.1";

#[derive(Clone)]
pub struct PublicTlsConfig {
    pub(crate) server_config: ReloadableConfig<ServerConfig>,
    pub(crate) handshake_timeout: Duration,
}

impl PublicTlsConfig {
    pub fn from_pem(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        handshake_timeout: Duration,
    ) -> Result<Self, PublicTlsConfigError> {
        if handshake_timeout.is_zero() {
            return Err(PublicTlsConfigError::ZeroHandshakeTimeout);
        }
        let candidate = build_server_config(server_cert_pem, server_key_pem)?;
        Ok(Self {
            server_config: ReloadableConfig::new(1, [0; 32], candidate.config, candidate.validity)
                .map_err(|_| PublicTlsConfigError::InvalidCertificateValidity)?,
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

impl fmt::Debug for PublicTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicTlsConfig")
            .field("handshake_timeout", &self.handshake_timeout)
            .field("generation", &self.server_config.generation())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicTlsConfigError {
    ZeroHandshakeTimeout,
    MissingServerCertificate,
    InvalidServerCertificate,
    MissingServerPrivateKey,
    InvalidServerPrivateKey,
    InvalidServerIdentity,
    InvalidCertificateValidity,
}

impl fmt::Display for PublicTlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroHandshakeTimeout => "public TLS handshake timeout must be greater than zero",
            Self::MissingServerCertificate => "public TLS certificate bundle is empty",
            Self::InvalidServerCertificate => "public TLS certificate bundle is invalid",
            Self::MissingServerPrivateKey => "public TLS private key is missing",
            Self::InvalidServerPrivateKey => "public TLS private key is invalid",
            Self::InvalidServerIdentity => {
                "public TLS server certificate and private key are incompatible"
            }
            Self::InvalidCertificateValidity => {
                "public TLS server certificate validity is invalid or not currently active"
            }
        })
    }
}

impl std::error::Error for PublicTlsConfigError {}

fn parse_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, PublicTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certificates = certificates.map_err(|_| PublicTlsConfigError::InvalidServerCertificate)?;
    if certificates.is_empty() {
        return Err(PublicTlsConfigError::MissingServerCertificate);
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, PublicTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| PublicTlsConfigError::InvalidServerPrivateKey)?
        .ok_or(PublicTlsConfigError::MissingServerPrivateKey)
}

fn build_server_config(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
) -> Result<TlsReloadCandidate<ServerConfig>, PublicTlsConfigError> {
    let certificates = parse_certificates(server_cert_pem)?;
    let validity = certificate_validity(certificates[0].as_ref())
        .map_err(|_| PublicTlsConfigError::InvalidCertificateValidity)?;
    let private_key = parse_private_key(server_key_pem)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| PublicTlsConfigError::InvalidServerIdentity)?;
    config.alpn_protocols = vec![PUBLIC_HTTP1_ALPN.to_vec()];
    Ok(TlsReloadCandidate { config, validity })
}

const RELOAD_PUBLIC_CERTIFICATE: &str = "public_server_certificate";
const RELOAD_PUBLIC_PRIVATE_KEY: &str = "public_server_private_key";

#[derive(Debug, Clone)]
pub struct PublicTlsReloadConfig {
    pub manifest_path: std::path::PathBuf,
    pub server_certificate_path: std::path::PathBuf,
    pub server_private_key_path: std::path::PathBuf,
    pub poll_interval: Duration,
    pub expiry_warning: Duration,
}

impl PublicTlsReloadConfig {
    fn runtime_config(&self) -> TlsReloadRuntimeConfig {
        TlsReloadRuntimeConfig {
            manifest_path: self.manifest_path.clone(),
            files: vec![
                TlsReloadFile::new(
                    RELOAD_PUBLIC_CERTIFICATE,
                    self.server_certificate_path.clone(),
                ),
                TlsReloadFile::new(
                    RELOAD_PUBLIC_PRIVATE_KEY,
                    self.server_private_key_path.clone(),
                ),
            ],
            poll_interval: self.poll_interval,
            expiry_warning: self.expiry_warning,
        }
    }
}

type PublicTlsBuild =
    Box<dyn Fn(&TlsReloadGeneration) -> Result<TlsReloadCandidate<ServerConfig>, ()> + Send + Sync>;

pub struct PublicTlsReloadRuntime {
    inner: TlsReloadRuntime<ServerConfig, PublicTlsBuild>,
}

impl PublicTlsReloadRuntime {
    pub async fn bootstrap(
        reload: PublicTlsReloadConfig,
        handshake_timeout: Duration,
    ) -> Result<(PublicTlsConfig, Self), PublicTlsReloadBootstrapError> {
        if handshake_timeout.is_zero() {
            return Err(PublicTlsReloadBootstrapError::Tls(
                PublicTlsConfigError::ZeroHandshakeTimeout,
            ));
        }
        let runtime_config = reload.runtime_config();
        runtime_config
            .validate()
            .map_err(PublicTlsReloadBootstrapError::Runtime)?;
        let generation = load_tls_reload_generation(
            runtime_config.manifest_path.clone(),
            runtime_config.files.clone(),
        )
        .await
        .map_err(PublicTlsReloadBootstrapError::Load)?;
        let candidate = build_reload_generation(&generation)
            .map_err(|()| PublicTlsReloadBootstrapError::Candidate)?;
        let server_config = ReloadableConfig::new(
            generation.generation(),
            generation.manifest_digest(),
            candidate.config,
            candidate.validity,
        )
        .map_err(PublicTlsReloadBootstrapError::Generation)?;
        let tls = PublicTlsConfig {
            server_config: server_config.clone(),
            handshake_timeout,
        };
        let inner = TlsReloadRuntime::new(
            runtime_config,
            server_config,
            Box::new(build_reload_generation) as PublicTlsBuild,
        )
        .map_err(PublicTlsReloadBootstrapError::Runtime)?;
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
) -> Result<TlsReloadCandidate<ServerConfig>, ()> {
    build_server_config(
        generation.file(RELOAD_PUBLIC_CERTIFICATE).map_err(|_| ())?,
        generation.file(RELOAD_PUBLIC_PRIVATE_KEY).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

#[derive(Debug)]
pub enum PublicTlsReloadBootstrapError {
    Load(tunnelproxy_common::TlsReloadLoadError),
    Tls(PublicTlsConfigError),
    Generation(TlsGenerationError),
    Runtime(TlsReloadRuntimeError),
    Candidate,
}

impl fmt::Display for PublicTlsReloadBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(error) => error.fmt(f),
            Self::Tls(error) => error.fmt(f),
            Self::Generation(error) => error.fmt(f),
            Self::Runtime(error) => error.fmt(f),
            Self::Candidate => {
                f.write_str("public TLS reload generation contains invalid credentials")
            }
        }
    }
}

impl std::error::Error for PublicTlsReloadBootstrapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inputs_are_typed_and_debug_is_secret_safe() {
        assert_eq!(
            PublicTlsConfig::from_pem(b"", b"", Duration::from_secs(1)).unwrap_err(),
            PublicTlsConfigError::MissingServerCertificate
        );
        let error =
            PublicTlsConfig::from_pem(b"certificate", b"secret-key", Duration::ZERO).unwrap_err();
        let debug = format!("{error:?}");
        assert!(!debug.contains("secret-key"));
    }
}
