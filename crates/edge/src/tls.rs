//! Edge-side mutual-TLS configuration for Agent transports.

use std::fmt;
use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tunnelproxy_common::{AgentId, TunnelId};
use tunnelproxy_control_plane::{
    AgentGrant, AuthorizationError, AuthorizationSnapshot, CertificateFingerprint, SnapshotError,
    TunnelGrant, TunnelStatus,
};
use tunnelproxy_protocol::{HandshakeErrorCode, RegistrationRequest};

pub const TUNNELPROXY_ALPN: &[u8] = b"tunnelproxy/2";

pub(crate) trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TransportIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type BoxedTransport = Box<dyn TransportIo>;

/// Registration authorization applied after Protocol v2 REGISTER decoding.
#[derive(Clone)]
pub enum EdgeRegistrationPolicy {
    /// Explicit non-cryptographic policy for loopback development only.
    LoopbackDevelopment {
        registrations: Arc<Vec<RegistrationRequest>>,
    },
    /// Immutable certificate-bound authorization pushed from the control plane.
    MutualTls(Arc<AuthorizationSnapshot>),
}

impl EdgeRegistrationPolicy {
    pub fn loopback_development(agent_id: AgentId, tunnel_id: TunnelId) -> Self {
        Self::LoopbackDevelopment {
            registrations: Arc::new(vec![RegistrationRequest::new(agent_id, tunnel_id)]),
        }
    }

    pub fn loopback_allowlist(registrations: Vec<RegistrationRequest>) -> Self {
        Self::LoopbackDevelopment {
            registrations: Arc::new(registrations),
        }
    }

    pub fn mutual_tls(snapshot: AuthorizationSnapshot) -> Self {
        Self::MutualTls(Arc::new(snapshot))
    }

    /// Builds a one-Agent/one-Tunnel snapshot from the exact public client
    /// certificate authorized by the current single-tunnel CLI.
    pub fn mutual_tls_from_client_cert_pem(
        agent_id: AgentId,
        tunnel_id: TunnelId,
        client_certificate_pem: &[u8],
    ) -> Result<Self, EdgeRegistrationPolicyError> {
        let certificates = parse_registration_certificates(client_certificate_pem)?;
        let fingerprint = CertificateFingerprint::from_certificate_der(certificates[0].as_ref());
        let snapshot = AuthorizationSnapshot::new(vec![AgentGrant::new(
            fingerprint,
            agent_id,
            vec![TunnelGrant::new(tunnel_id, TunnelStatus::Registered)],
        )])
        .map_err(EdgeRegistrationPolicyError::Snapshot)?;
        Ok(Self::mutual_tls(snapshot))
    }

    pub const fn is_mutual_tls(&self) -> bool {
        matches!(self, Self::MutualTls(_))
    }

    pub fn contains_tunnel(&self, tunnel_id: &TunnelId) -> bool {
        match self {
            Self::LoopbackDevelopment { registrations } => registrations
                .iter()
                .any(|registration| &registration.tunnel_id == tunnel_id),
            Self::MutualTls(snapshot) => snapshot.contains_tunnel(tunnel_id),
        }
    }

    pub(crate) fn authorize(
        &self,
        peer_certificate: Option<&CertificateFingerprint>,
        request: &RegistrationRequest,
    ) -> Result<(), HandshakeErrorCode> {
        match self {
            Self::LoopbackDevelopment { registrations }
                if registrations.iter().any(|allowed| allowed == request) =>
            {
                Ok(())
            }
            Self::LoopbackDevelopment { registrations }
                if registrations
                    .iter()
                    .any(|allowed| allowed.agent_id == request.agent_id) =>
            {
                Err(HandshakeErrorCode::UnauthorizedTunnel)
            }
            Self::LoopbackDevelopment { .. } => Err(HandshakeErrorCode::UnauthorizedAgent),
            Self::MutualTls(snapshot) => {
                let certificate = peer_certificate.ok_or(HandshakeErrorCode::UnauthorizedAgent)?;
                snapshot
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
                    })
            }
        }
    }
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
        match self {
            Self::LoopbackDevelopment { registrations } => f
                .debug_struct("LoopbackDevelopment")
                .field("registration_count", &registrations.len())
                .finish(),
            Self::MutualTls(snapshot) => f
                .debug_struct("MutualTlsAuthorization")
                .field("certificate_count", &snapshot.certificate_count())
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
        assert_eq!(policy.authorize(None, &valid), Ok(()));
        let wrong = RegistrationRequest::new(
            AgentId::new("other-agent").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        );
        assert_eq!(
            policy.authorize(None, &wrong),
            Err(HandshakeErrorCode::UnauthorizedAgent)
        );
    }
}
