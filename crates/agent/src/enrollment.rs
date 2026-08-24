use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};
use tunnelproxy_common::{
    publish_agent_credential_bundle, replace_secret_file, AgentCredentialPaths, AgentId,
    CredentialBundleError, ShutdownSignal, TlsConfigHealth, TunnelId,
};
use tunnelproxy_protocol::{
    read_enrollment_message, write_enrollment_message, EnrollmentErrorCode, EnrollmentMessage,
    EnrollmentProtocolError, EnrollmentRequestId, EnrollmentToken, ENROLLMENT_PROTOCOL_ALPN,
};

use crate::{AgentTlsConfig, AgentTlsConfigError};

#[derive(Debug, Clone)]
pub struct EnrollmentClientConfig {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub server_ca_pem: Vec<u8>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub request_timeout: Duration,
}

impl EnrollmentClientConfig {
    fn build_tls(&self) -> Result<(Arc<ClientConfig>, ServerName<'static>), AgentEnrollmentError> {
        if self.connect_timeout.is_zero()
            || self.handshake_timeout.is_zero()
            || self.request_timeout.is_zero()
        {
            return Err(AgentEnrollmentError::InvalidConfig);
        }
        let mut roots = RootCertStore::empty();
        let mut reader = BufReader::new(Cursor::new(&self.server_ca_pem));
        let certificates: Result<Vec<CertificateDer<'static>>, _> =
            rustls_pemfile::certs(&mut reader).collect();
        let certificates = certificates.map_err(|_| AgentEnrollmentError::InvalidServerCa)?;
        if certificates.is_empty() {
            return Err(AgentEnrollmentError::InvalidServerCa);
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| AgentEnrollmentError::InvalidServerCa)?;
        }
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ENROLLMENT_PROTOCOL_ALPN.to_vec()];
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| AgentEnrollmentError::InvalidServerName)?;
        Ok((Arc::new(config), server_name))
    }
}

#[derive(Debug, Clone)]
pub struct AgentEnrollmentConfig {
    pub client: EnrollmentClientConfig,
    pub agent_id: AgentId,
    pub tunnel_id: TunnelId,
    pub token_path: PathBuf,
    pub pending_path: PathBuf,
    pub credentials: AgentCredentialPaths,
    pub edge_server_name: String,
    pub edge_tls_handshake_timeout: Duration,
    pub renew_before: Duration,
    pub poll_interval: Duration,
    pub activation_timeout: Duration,
}

impl AgentEnrollmentConfig {
    pub fn validate(&self) -> Result<(), AgentEnrollmentError> {
        self.client.build_tls()?;
        self.credentials
            .validate()
            .map_err(AgentEnrollmentError::Publish)?;
        if self.token_path.as_os_str().is_empty()
            || self.pending_path.as_os_str().is_empty()
            || self.edge_server_name.is_empty()
            || self.edge_tls_handshake_timeout.is_zero()
            || self.renew_before.is_zero()
            || self.poll_interval.is_zero()
            || self.activation_timeout.is_zero()
        {
            return Err(AgentEnrollmentError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct AgentEnrollmentClient {
    config: EnrollmentClientConfig,
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl AgentEnrollmentClient {
    pub fn new(config: EnrollmentClientConfig) -> Result<Self, AgentEnrollmentError> {
        let (tls, server_name) = config.build_tls()?;
        Ok(Self {
            config,
            tls,
            server_name,
        })
    }

    pub async fn issue(
        &self,
        request_id: EnrollmentRequestId,
        token: EnrollmentToken,
        next_renewal_token: EnrollmentToken,
        agent_id: AgentId,
        tunnel_id: TunnelId,
        csr_der: Vec<u8>,
    ) -> Result<IssuedEnrollment, AgentEnrollmentError> {
        let response = self
            .exchange(EnrollmentMessage::Enroll {
                request_id,
                token,
                next_renewal_token,
                agent_id,
                tunnel_id,
                csr_der,
            })
            .await?;
        match response {
            EnrollmentMessage::Issued {
                request_id: response_id,
                generation,
                not_after_unix,
                certificate_pem,
                server_ca_pem,
                fingerprint,
            } if response_id == request_id && generation != 0 => Ok(IssuedEnrollment {
                request_id,
                generation,
                not_after_unix,
                certificate_pem,
                server_ca_pem,
                fingerprint,
            }),
            EnrollmentMessage::Error { code } => Err(AgentEnrollmentError::Rejected(code)),
            _ => Err(AgentEnrollmentError::UnexpectedResponse),
        }
    }

    pub async fn activate(
        &self,
        request_id: EnrollmentRequestId,
        renewal_token: EnrollmentToken,
        fingerprint: [u8; 32],
    ) -> Result<u64, AgentEnrollmentError> {
        match self
            .exchange(EnrollmentMessage::Activate {
                request_id,
                renewal_token,
                fingerprint,
            })
            .await?
        {
            EnrollmentMessage::Activated { snapshot_version } if snapshot_version != 0 => {
                Ok(snapshot_version)
            }
            EnrollmentMessage::Error { code } => Err(AgentEnrollmentError::Rejected(code)),
            _ => Err(AgentEnrollmentError::UnexpectedResponse),
        }
    }

    async fn exchange(
        &self,
        request: EnrollmentMessage,
    ) -> Result<EnrollmentMessage, AgentEnrollmentError> {
        let socket = timeout(
            self.config.connect_timeout,
            TcpStream::connect(self.config.server_addr),
        )
        .await
        .map_err(|_| AgentEnrollmentError::ConnectTimeout)?
        .map_err(|_| AgentEnrollmentError::Connect)?;
        let connector = TlsConnector::from(Arc::clone(&self.tls));
        let mut stream = timeout(
            self.config.handshake_timeout,
            connector.connect(self.server_name.clone(), socket),
        )
        .await
        .map_err(|_| AgentEnrollmentError::HandshakeTimeout)?
        .map_err(|_| AgentEnrollmentError::Tls)?;
        if stream.get_ref().1.alpn_protocol() != Some(ENROLLMENT_PROTOCOL_ALPN) {
            return Err(AgentEnrollmentError::Alpn);
        }
        timeout(
            self.config.request_timeout,
            write_enrollment_message(&mut stream, &request),
        )
        .await
        .map_err(|_| AgentEnrollmentError::RequestTimeout)?
        .map_err(AgentEnrollmentError::Protocol)?;
        timeout(
            self.config.request_timeout,
            read_enrollment_message(&mut stream),
        )
        .await
        .map_err(|_| AgentEnrollmentError::RequestTimeout)?
        .map_err(AgentEnrollmentError::Protocol)?
        .ok_or(AgentEnrollmentError::UnexpectedResponse)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedEnrollment {
    pub request_id: EnrollmentRequestId,
    pub generation: u64,
    pub not_after_unix: u64,
    pub certificate_pem: Vec<u8>,
    pub server_ca_pem: Vec<u8>,
    pub fingerprint: [u8; 32],
}

pub struct AgentEnrollmentRuntime {
    config: AgentEnrollmentConfig,
    client: AgentEnrollmentClient,
    tls: AgentTlsConfig,
}

impl AgentEnrollmentRuntime {
    pub fn new(
        config: AgentEnrollmentConfig,
        tls: AgentTlsConfig,
    ) -> Result<Self, AgentEnrollmentError> {
        config.validate()?;
        let client = AgentEnrollmentClient::new(config.client.clone())?;
        Ok(Self {
            config,
            client,
            tls,
        })
    }

    pub async fn rotate_once(&self) -> Result<u64, AgentEnrollmentError> {
        rotate(&self.config, &self.client, Some(&self.tls)).await
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), AgentEnrollmentError> {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => return Ok(()),
                _ = interval.tick() => {}
            }
            let status = self.tls.reload_status(self.config.renew_before);
            if self.config.pending_path.exists() || status.health == TlsConfigHealth::Expiring {
                if let Err(error) = self.rotate_once().await {
                    warn!(%error, generation = status.generation, event = "agent_renewal_failed");
                }
            }
        }
    }
}

pub async fn bootstrap_agent_credentials(
    config: &AgentEnrollmentConfig,
) -> Result<u64, AgentEnrollmentError> {
    config.validate()?;
    let client = AgentEnrollmentClient::new(config.client.clone())?;
    rotate(config, &client, None).await
}

async fn rotate(
    config: &AgentEnrollmentConfig,
    client: &AgentEnrollmentClient,
    tls: Option<&AgentTlsConfig>,
) -> Result<u64, AgentEnrollmentError> {
    let token_path = config.token_path.clone();
    let token = tokio::task::spawn_blocking(move || read_token(&token_path))
        .await
        .map_err(|_| AgentEnrollmentError::StorageTask)??;
    let pending_path = config.pending_path.clone();
    let pending_agent = config.agent_id.clone();
    let pending_tunnel = config.tunnel_id.clone();
    let pending = tokio::task::spawn_blocking(move || {
        load_or_create_pending(&pending_path, &pending_agent, &pending_tunnel)
    })
    .await
    .map_err(|_| AgentEnrollmentError::StorageTask)??;
    // The token file is published before the pending record is removed. If the
    // process stopped in that narrow window, the rotation already completed;
    // clear the stale journal instead of trying to authenticate it with the
    // newly rotated token.
    if token == pending.next_token {
        let completed_pending = config.pending_path.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::remove_file(completed_pending).map_err(|_| AgentEnrollmentError::Storage)
        })
        .await
        .map_err(|_| AgentEnrollmentError::StorageTask)??;
        return Ok(tls
            .map(|active| active.reload_status(Duration::from_secs(1)).generation)
            .unwrap_or(1));
    }
    let issued = client
        .issue(
            pending.request_id,
            token,
            pending.next_token,
            config.agent_id.clone(),
            config.tunnel_id.clone(),
            pending.csr_der.clone(),
        )
        .await?;
    verify_issued_fingerprint(&issued.certificate_pem, issued.fingerprint)?;
    AgentTlsConfig::from_pem(
        &issued.server_ca_pem,
        &issued.certificate_pem,
        pending.private_key_pem.as_bytes(),
        &config.edge_server_name,
        config.edge_tls_handshake_timeout,
    )
    .map_err(AgentEnrollmentError::IssuedCredential)?;
    let paths = config.credentials.clone();
    let certificate = issued.certificate_pem.clone();
    let server_ca = issued.server_ca_pem.clone();
    let private_key = pending.private_key_pem.clone();
    let generation = issued.generation;
    tokio::task::spawn_blocking(move || {
        publish_agent_credential_bundle(
            &paths,
            generation,
            &server_ca,
            &certificate,
            private_key.as_bytes(),
        )
    })
    .await
    .map_err(|_| AgentEnrollmentError::StorageTask)?
    .map_err(AgentEnrollmentError::Publish)?;
    if let Some(tls) = tls {
        timeout(config.activation_timeout, async {
            loop {
                let status = tls.reload_status(Duration::from_secs(1));
                if status.generation == issued.generation
                    && status.health != TlsConfigHealth::ReloadFailed
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| AgentEnrollmentError::ActivationTimeout)?;
    }
    let snapshot_version = client
        .activate(issued.request_id, pending.next_token, issued.fingerprint)
        .await?;
    let next_token_path = config.token_path.clone();
    let next_token = pending.next_token;
    let completed_pending = config.pending_path.clone();
    tokio::task::spawn_blocking(move || {
        write_token(&next_token_path, next_token)?;
        std::fs::remove_file(completed_pending).map_err(|_| AgentEnrollmentError::Storage)
    })
    .await
    .map_err(|_| AgentEnrollmentError::StorageTask)??;
    info!(
        generation = issued.generation,
        snapshot_version,
        not_after_unix = issued.not_after_unix,
        event = "agent_credential_rotation_completed"
    );
    Ok(issued.generation)
}

fn verify_issued_fingerprint(
    certificate_pem: &[u8],
    expected: [u8; 32],
) -> Result<(), AgentEnrollmentError> {
    let mut reader = BufReader::new(Cursor::new(certificate_pem));
    let certificate = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .map_err(|_| AgentEnrollmentError::IssuedFingerprint)?
        .ok_or(AgentEnrollmentError::IssuedFingerprint)?;
    let actual: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
    if actual != expected {
        return Err(AgentEnrollmentError::IssuedFingerprint);
    }
    Ok(())
}

struct PendingEnrollment {
    request_id: EnrollmentRequestId,
    next_token: EnrollmentToken,
    private_key_pem: String,
    csr_der: Vec<u8>,
}

fn load_or_create_pending(
    path: &Path,
    agent_id: &AgentId,
    tunnel_id: &TunnelId,
) -> Result<PendingEnrollment, AgentEnrollmentError> {
    if path.exists() {
        return decode_pending(&std::fs::read(path).map_err(|_| AgentEnrollmentError::Storage)?);
    }
    let mut request_id = [0_u8; 16];
    let mut next_token = [0_u8; 32];
    getrandom::getrandom(&mut request_id).map_err(|_| AgentEnrollmentError::Random)?;
    getrandom::getrandom(&mut next_token).map_err(|_| AgentEnrollmentError::Random)?;
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|_| AgentEnrollmentError::KeyGeneration)?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|_| AgentEnrollmentError::KeyGeneration)?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, agent_id.as_str());
    name.push(DnType::OrganizationalUnitName, tunnel_id.as_str());
    params.distinguished_name = name;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|_| AgentEnrollmentError::KeyGeneration)?;
    let pending = PendingEnrollment {
        request_id: EnrollmentRequestId::from_bytes(request_id),
        next_token: EnrollmentToken::from_bytes(next_token),
        private_key_pem: key_pair.serialize_pem(),
        csr_der: csr.der().as_ref().to_vec(),
    };
    replace_secret_file(path, &encode_pending(&pending)).map_err(AgentEnrollmentError::Publish)?;
    Ok(pending)
}

fn encode_pending(pending: &PendingEnrollment) -> Vec<u8> {
    let key = pending.private_key_pem.as_bytes();
    let mut bytes = Vec::with_capacity(6 + 16 + 32 + 8 + key.len() + pending.csr_der.len());
    bytes.extend_from_slice(b"TPENP1");
    bytes.extend_from_slice(pending.request_id.as_bytes());
    bytes.extend_from_slice(pending.next_token.as_bytes());
    bytes.extend_from_slice(&(key.len() as u32).to_be_bytes());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(&(pending.csr_der.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&pending.csr_der);
    bytes
}

fn decode_pending(bytes: &[u8]) -> Result<PendingEnrollment, AgentEnrollmentError> {
    if bytes.len() > 128 * 1024 || bytes.get(..6) != Some(b"TPENP1") {
        return Err(AgentEnrollmentError::PendingState);
    }
    let mut offset = 6;
    let request_id = take_array::<16>(bytes, &mut offset)?;
    let next_token = take_array::<32>(bytes, &mut offset)?;
    let key_len = u32::from_be_bytes(take_array(bytes, &mut offset)?) as usize;
    let key = take(bytes, &mut offset, key_len)?;
    let csr_len = u32::from_be_bytes(take_array(bytes, &mut offset)?) as usize;
    let csr = take(bytes, &mut offset, csr_len)?;
    if offset != bytes.len() {
        return Err(AgentEnrollmentError::PendingState);
    }
    Ok(PendingEnrollment {
        request_id: EnrollmentRequestId::from_bytes(request_id),
        next_token: EnrollmentToken::from_bytes(next_token),
        private_key_pem: std::str::from_utf8(key)
            .map_err(|_| AgentEnrollmentError::PendingState)?
            .to_owned(),
        csr_der: csr.to_vec(),
    })
}

fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], AgentEnrollmentError> {
    let end = offset
        .checked_add(length)
        .ok_or(AgentEnrollmentError::PendingState)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(AgentEnrollmentError::PendingState)?;
    *offset = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], AgentEnrollmentError> {
    take(bytes, offset, N)?
        .try_into()
        .map_err(|_| AgentEnrollmentError::PendingState)
}

pub fn read_token(path: &Path) -> Result<EnrollmentToken, AgentEnrollmentError> {
    let text = std::fs::read_to_string(path).map_err(|_| AgentEnrollmentError::Storage)?;
    let text = text.trim();
    if text.len() != 64 {
        return Err(AgentEnrollmentError::InvalidToken);
    }
    let mut token = [0_u8; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| AgentEnrollmentError::InvalidToken)?;
    }
    Ok(EnrollmentToken::from_bytes(token))
}

pub fn write_token(path: &Path, token: EnrollmentToken) -> Result<(), AgentEnrollmentError> {
    let value: String = token
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    replace_secret_file(path, format!("{value}\n").as_bytes())
        .map_err(AgentEnrollmentError::Publish)
}

#[derive(Debug)]
pub enum AgentEnrollmentError {
    InvalidConfig,
    InvalidServerCa,
    InvalidServerName,
    InvalidToken,
    ConnectTimeout,
    Connect,
    HandshakeTimeout,
    Tls,
    Alpn,
    RequestTimeout,
    Protocol(EnrollmentProtocolError),
    Rejected(EnrollmentErrorCode),
    UnexpectedResponse,
    Random,
    KeyGeneration,
    PendingState,
    IssuedCredential(AgentTlsConfigError),
    IssuedFingerprint,
    Publish(CredentialBundleError),
    ActivationTimeout,
    Storage,
    StorageTask,
}

impl std::fmt::Display for AgentEnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(f),
            Self::Rejected(code) => write!(f, "enrollment request was rejected: {code:?}"),
            Self::IssuedCredential(error) => write!(f, "issued credential is invalid: {error}"),
            Self::Publish(error) => error.fmt(f),
            other => f.write_str(match other {
                Self::InvalidConfig => "Agent enrollment configuration is invalid",
                Self::InvalidServerCa => "enrollment server CA is invalid",
                Self::InvalidServerName => "enrollment server name is invalid",
                Self::InvalidToken => "enrollment token file is invalid",
                Self::ConnectTimeout => "enrollment connection timed out",
                Self::Connect => "enrollment connection failed",
                Self::HandshakeTimeout => "enrollment TLS handshake timed out",
                Self::Tls => "enrollment TLS authentication failed",
                Self::Alpn => "enrollment ALPN negotiation failed",
                Self::RequestTimeout => "enrollment request timed out",
                Self::UnexpectedResponse => "enrollment server returned an unexpected response",
                Self::Random => "secure random generation failed",
                Self::KeyGeneration => "Agent key or CSR generation failed",
                Self::PendingState => "pending enrollment state is invalid",
                Self::IssuedFingerprint => "issued certificate fingerprint does not match",
                Self::ActivationTimeout => "new Agent TLS generation did not activate in time",
                Self::Storage => "Agent enrollment state could not be read or written",
                Self::StorageTask => "Agent enrollment storage worker stopped unexpectedly",
                Self::Protocol(_)
                | Self::Rejected(_)
                | Self::IssuedCredential(_)
                | Self::Publish(_) => {
                    unreachable!()
                }
            }),
        }
    }
}

impl std::error::Error for AgentEnrollmentError {}
