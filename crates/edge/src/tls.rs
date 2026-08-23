//! Edge-side mutual-TLS configuration for Agent transports.

use std::fmt;
use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};

pub const TUNNELPROXY_ALPN: &[u8] = b"tunnelproxy/1";

pub(crate) trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TransportIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type BoxedTransport = Box<dyn TransportIo>;

/// Security applied before Edge accepts a Protocol v1 Agent handshake.
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
    pub(crate) server_config: Arc<ServerConfig>,
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
        let server_certificates = parse_certificates(server_cert_pem, CertificateKind::Server)?;
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
        Ok(Self {
            server_config: Arc::new(server_config),
            handshake_timeout,
        })
    }

    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }
}

impl fmt::Debug for EdgeTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdgeTlsConfig")
            .field("handshake_timeout", &self.handshake_timeout)
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

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, EdgeTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| EdgeTlsConfigError::InvalidServerPrivateKey)?
        .ok_or(EdgeTlsConfigError::MissingServerPrivateKey)
}

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
}
