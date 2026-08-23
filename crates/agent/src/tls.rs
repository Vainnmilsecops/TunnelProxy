//! Agent-side transport security configuration.

use std::fmt;
use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};

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
    pub(crate) client_config: Arc<ClientConfig>,
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
        let ca_certificates = parse_certificates(ca_pem, CertificateKind::Authority)?;
        let client_certificates = parse_certificates(client_cert_pem, CertificateKind::Client)?;
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
        Ok(Self {
            client_config: Arc::new(client_config),
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
}

impl fmt::Debug for AgentTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentTlsConfig")
            .field("server_name", &self.server_name)
            .field("handshake_timeout", &self.handshake_timeout)
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
