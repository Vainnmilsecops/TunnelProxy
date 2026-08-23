use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};
use tunnelproxy_common::ShutdownSignal;

use crate::{
    authorization_snapshot_channel, read_snapshot_message, write_snapshot_message,
    AuthorizationSnapshotPublisher, AuthorizationSnapshotSubscription, SnapshotMessage,
    SnapshotProtocolError, SnapshotServiceErrorCode, SnapshotSourceHealth, SNAPSHOT_PROTOCOL_ALPN,
};

#[derive(Clone)]
pub struct SnapshotServerTlsConfig {
    server_config: Arc<ServerConfig>,
    handshake_timeout: Duration,
}

impl SnapshotServerTlsConfig {
    pub fn from_pem(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        edge_client_ca_pem: &[u8],
        handshake_timeout: Duration,
    ) -> Result<Self, SnapshotTlsConfigError> {
        if handshake_timeout.is_zero() {
            return Err(SnapshotTlsConfigError::ZeroHandshakeTimeout);
        }
        let server_certificates = parse_certificates(server_cert_pem, CertificateKind::Identity)?;
        let server_key = parse_private_key(server_key_pem)?;
        let client_authorities =
            parse_certificates(edge_client_ca_pem, CertificateKind::Authority)?;
        let mut client_roots = RootCertStore::empty();
        for certificate in client_authorities {
            client_roots
                .add(certificate)
                .map_err(|_| SnapshotTlsConfigError::InvalidAuthorityCertificate)?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|_| SnapshotTlsConfigError::InvalidAuthorityCertificate)?;
        let mut server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certificates, server_key)
            .map_err(|_| SnapshotTlsConfigError::InvalidIdentity)?;
        server_config.alpn_protocols = vec![SNAPSHOT_PROTOCOL_ALPN.to_vec()];
        Ok(Self {
            server_config: Arc::new(server_config),
            handshake_timeout,
        })
    }
}

impl std::fmt::Debug for SnapshotServerTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotServerTlsConfig")
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct SnapshotClientConfig {
    pub server_addr: SocketAddr,
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub subscribe_timeout: Duration,
    pub reconnect_initial_delay: Duration,
    pub reconnect_max_delay: Duration,
}

impl SnapshotClientConfig {
    pub fn from_pem(
        server_addr: SocketAddr,
        control_plane_ca_pem: &[u8],
        edge_client_cert_pem: &[u8],
        edge_client_key_pem: &[u8],
        server_name: &str,
    ) -> Result<Self, SnapshotTlsConfigError> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| SnapshotTlsConfigError::InvalidServerName)?;
        let authorities = parse_certificates(control_plane_ca_pem, CertificateKind::Authority)?;
        let identity = parse_certificates(edge_client_cert_pem, CertificateKind::Identity)?;
        let key = parse_private_key(edge_client_key_pem)?;
        let mut roots = RootCertStore::empty();
        for certificate in authorities {
            roots
                .add(certificate)
                .map_err(|_| SnapshotTlsConfigError::InvalidAuthorityCertificate)?;
        }
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(identity, key)
            .map_err(|_| SnapshotTlsConfigError::InvalidIdentity)?;
        client_config.alpn_protocols = vec![SNAPSHOT_PROTOCOL_ALPN.to_vec()];
        Ok(Self {
            server_addr,
            client_config: Arc::new(client_config),
            server_name,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
            subscribe_timeout: Duration::from_secs(5),
            reconnect_initial_delay: Duration::from_millis(250),
            reconnect_max_delay: Duration::from_secs(30),
        })
    }

    pub fn validate(&self) -> Result<(), SnapshotClientError> {
        if self.connect_timeout.is_zero()
            || self.handshake_timeout.is_zero()
            || self.subscribe_timeout.is_zero()
            || self.reconnect_initial_delay.is_zero()
            || self.reconnect_max_delay < self.reconnect_initial_delay
        {
            return Err(SnapshotClientError::InvalidConfig);
        }
        Ok(())
    }
}

impl std::fmt::Debug for SnapshotClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotClientConfig")
            .field("server_addr", &self.server_addr)
            .field("server_name", &self.server_name)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("subscribe_timeout", &self.subscribe_timeout)
            .field("reconnect_initial_delay", &self.reconnect_initial_delay)
            .field("reconnect_max_delay", &self.reconnect_max_delay)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotServerConfig {
    pub listen_addr: SocketAddr,
    pub max_edge_clients: usize,
    pub request_timeout: Duration,
    pub tls: SnapshotServerTlsConfig,
}

impl SnapshotServerConfig {
    pub fn validate(&self) -> Result<(), SnapshotServerError> {
        if self.max_edge_clients == 0 || self.request_timeout.is_zero() {
            return Err(SnapshotServerError::InvalidConfig);
        }
        Ok(())
    }
}

pub struct SnapshotDistributionServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: SnapshotServerConfig,
    snapshots: AuthorizationSnapshotSubscription,
}

impl SnapshotDistributionServer {
    pub async fn bind(
        config: SnapshotServerConfig,
        snapshots: AuthorizationSnapshotSubscription,
    ) -> Result<Self, SnapshotServerError> {
        config.validate()?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(SnapshotServerError::Bind)?;
        let local_addr = listener.local_addr().map_err(SnapshotServerError::Bind)?;
        Ok(Self {
            listener,
            local_addr,
            config,
            snapshots,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), SnapshotServerError> {
        let permits = Arc::new(Semaphore::new(self.config.max_edge_clients));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (socket, peer) = accepted.map_err(SnapshotServerError::Accept)?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        warn!(%peer, event = "snapshot_client_capacity_rejected");
                        continue;
                    };
                    tasks.spawn(serve_edge(
                        socket,
                        peer,
                        permit,
                        self.config.clone(),
                        self.snapshots.clone(),
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

async fn serve_edge(
    socket: TcpStream,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
    config: SnapshotServerConfig,
    mut snapshots: AuthorizationSnapshotSubscription,
) {
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls.server_config));
    let mut stream =
        match tokio::time::timeout(config.tls.handshake_timeout, acceptor.accept(socket)).await {
            Ok(Ok(stream))
                if stream.get_ref().1.alpn_protocol() == Some(SNAPSHOT_PROTOCOL_ALPN) =>
            {
                stream
            }
            _ => {
                warn!(%peer, event = "snapshot_tls_rejected");
                return;
            }
        };
    let request = match tokio::time::timeout(
        config.request_timeout,
        read_snapshot_message(&mut stream),
    )
    .await
    {
        Ok(Ok(SnapshotMessage::Subscribe {
            last_applied_version,
        })) => last_applied_version,
        _ => {
            let _ = tokio::time::timeout(
                config.request_timeout,
                write_snapshot_message(
                    &mut stream,
                    &SnapshotMessage::Error(SnapshotServiceErrorCode::InvalidRequest),
                ),
            )
            .await;
            return;
        }
    };
    let current = snapshots.current();
    let response = if request == current.version().get() {
        SnapshotMessage::UpToDate(current.version())
    } else if request < current.version().get() {
        SnapshotMessage::Snapshot((*current).clone())
    } else {
        SnapshotMessage::Error(SnapshotServiceErrorCode::ClientAhead)
    };
    if !matches!(
        tokio::time::timeout(
            config.request_timeout,
            write_snapshot_message(&mut stream, &response),
        )
        .await,
        Ok(Ok(()))
    ) {
        return;
    }
    if matches!(response, SnapshotMessage::Error(_)) {
        return;
    }
    info!(%peer, snapshot_version = current.version().get(), event = "snapshot_edge_subscribed");
    while snapshots.changed().await.is_ok() {
        let next = snapshots.current();
        if !matches!(
            tokio::time::timeout(
                config.request_timeout,
                write_snapshot_message(&mut stream, &SnapshotMessage::Snapshot((*next).clone())),
            )
            .await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
}

type SnapshotTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

pub struct SnapshotBootstrapClient;

impl SnapshotBootstrapClient {
    pub async fn bootstrap(
        config: SnapshotClientConfig,
    ) -> Result<(AuthorizationSnapshotSubscription, SnapshotClientRuntime), SnapshotClientError>
    {
        config.validate()?;
        let (stream, response) = connect_and_subscribe(&config, 0).await?;
        let SnapshotMessage::Snapshot(initial) = response else {
            return Err(match response {
                SnapshotMessage::Error(code) => SnapshotClientError::Server(code),
                _ => SnapshotClientError::BootstrapResponse,
            });
        };
        let (publisher, subscription) = authorization_snapshot_channel(initial);
        Ok((
            subscription,
            SnapshotClientRuntime {
                config,
                publisher,
                stream: Some(stream),
            },
        ))
    }
}

pub struct SnapshotClientRuntime {
    config: SnapshotClientConfig,
    publisher: AuthorizationSnapshotPublisher,
    stream: Option<SnapshotTlsStream>,
}

impl SnapshotClientRuntime {
    pub async fn run_until_shutdown(
        mut self,
        signal: ShutdownSignal,
    ) -> Result<(), SnapshotClientError> {
        let mut delay = self.config.reconnect_initial_delay;
        loop {
            if let Some(stream) = self.stream.as_mut() {
                tokio::select! {
                    biased;
                    () = signal.cancelled() => return Ok(()),
                    message = read_snapshot_message(stream) => {
                        match message {
                            Ok(SnapshotMessage::Snapshot(snapshot)) => {
                                if let Err(error) = self.publisher.publish(snapshot) {
                                    self.publisher.set_source_health(SnapshotSourceHealth::Stale);
                                    return Err(SnapshotClientError::Update(error));
                                }
                                continue;
                            }
                            Ok(SnapshotMessage::UpToDate(_))
                            | Ok(SnapshotMessage::Subscribe { .. }) => {
                                self.publisher.set_source_health(SnapshotSourceHealth::Stale);
                                return Err(SnapshotClientError::UnexpectedMessage);
                            }
                            Ok(SnapshotMessage::Error(code)) => {
                                self.publisher.set_source_health(SnapshotSourceHealth::Stale);
                                return Err(SnapshotClientError::Server(code));
                            }
                            Err(_) => {
                                self.stream = None;
                                self.publisher.set_source_health(SnapshotSourceHealth::Stale);
                            }
                        }
                    }
                }
            }

            tokio::select! {
                biased;
                () = signal.cancelled() => return Ok(()),
                () = tokio::time::sleep(delay) => {}
            }
            let reconnect =
                connect_and_subscribe(&self.config, self.publisher.current().version().get());
            let reconnect_result = tokio::select! {
                biased;
                () = signal.cancelled() => return Ok(()),
                result = reconnect => result,
            };
            match reconnect_result {
                Ok((stream, SnapshotMessage::Snapshot(snapshot))) => {
                    self.publisher
                        .publish(snapshot)
                        .map_err(SnapshotClientError::Update)?;
                    self.publisher.set_source_health(SnapshotSourceHealth::Live);
                    self.stream = Some(stream);
                    delay = self.config.reconnect_initial_delay;
                }
                Ok((stream, SnapshotMessage::UpToDate(version))) => {
                    if version != self.publisher.current().version() {
                        return Err(SnapshotClientError::UnexpectedMessage);
                    }
                    self.publisher.set_source_health(SnapshotSourceHealth::Live);
                    self.stream = Some(stream);
                    delay = self.config.reconnect_initial_delay;
                }
                Ok((_, SnapshotMessage::Error(code))) => {
                    return Err(SnapshotClientError::Server(code))
                }
                Ok(_) => return Err(SnapshotClientError::UnexpectedMessage),
                Err(_) => {
                    delay = delay
                        .checked_mul(2)
                        .unwrap_or(self.config.reconnect_max_delay)
                        .min(self.config.reconnect_max_delay);
                }
            }
        }
    }
}

async fn connect_and_subscribe(
    config: &SnapshotClientConfig,
    last_applied_version: u64,
) -> Result<(SnapshotTlsStream, SnapshotMessage), SnapshotClientError> {
    let socket = tokio::time::timeout(
        config.connect_timeout,
        TcpStream::connect(config.server_addr),
    )
    .await
    .map_err(|_| SnapshotClientError::ConnectTimeout)?
    .map_err(SnapshotClientError::Connect)?;
    let connector = TlsConnector::from(Arc::clone(&config.client_config));
    let mut stream = tokio::time::timeout(
        config.handshake_timeout,
        connector.connect(config.server_name.clone(), socket),
    )
    .await
    .map_err(|_| SnapshotClientError::TlsTimeout)?
    .map_err(|_| SnapshotClientError::TlsAuthentication)?;
    if stream.get_ref().1.alpn_protocol() != Some(SNAPSHOT_PROTOCOL_ALPN) {
        return Err(SnapshotClientError::Alpn);
    }
    tokio::time::timeout(
        config.subscribe_timeout,
        write_snapshot_message(
            &mut stream,
            &SnapshotMessage::Subscribe {
                last_applied_version,
            },
        ),
    )
    .await
    .map_err(|_| SnapshotClientError::SubscribeTimeout)?
    .map_err(SnapshotClientError::Protocol)?;
    let response =
        tokio::time::timeout(config.subscribe_timeout, read_snapshot_message(&mut stream))
            .await
            .map_err(|_| SnapshotClientError::SubscribeTimeout)?
            .map_err(SnapshotClientError::Protocol)?;
    Ok((stream, response))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotTlsConfigError {
    ZeroHandshakeTimeout,
    InvalidServerName,
    MissingAuthorityCertificate,
    InvalidAuthorityCertificate,
    MissingIdentityCertificate,
    InvalidIdentityCertificate,
    MissingPrivateKey,
    InvalidPrivateKey,
    InvalidIdentity,
}

impl std::fmt::Display for SnapshotTlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ZeroHandshakeTimeout => "TLS handshake timeout must be greater than zero",
            Self::InvalidServerName => "TLS server name is invalid",
            Self::MissingAuthorityCertificate => "TLS CA bundle is empty",
            Self::InvalidAuthorityCertificate => "TLS CA bundle is invalid",
            Self::MissingIdentityCertificate => "TLS identity certificate bundle is empty",
            Self::InvalidIdentityCertificate => "TLS identity certificate bundle is invalid",
            Self::MissingPrivateKey => "TLS private key is missing",
            Self::InvalidPrivateKey => "TLS private key is invalid",
            Self::InvalidIdentity => "TLS certificate and private key are incompatible",
        })
    }
}

impl std::error::Error for SnapshotTlsConfigError {}

#[derive(Clone, Copy)]
enum CertificateKind {
    Authority,
    Identity,
}

fn parse_certificates(
    pem: &[u8],
    kind: CertificateKind,
) -> Result<Vec<CertificateDer<'static>>, SnapshotTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certificates = certificates.map_err(|_| match kind {
        CertificateKind::Authority => SnapshotTlsConfigError::InvalidAuthorityCertificate,
        CertificateKind::Identity => SnapshotTlsConfigError::InvalidIdentityCertificate,
    })?;
    if certificates.is_empty() {
        return Err(match kind {
            CertificateKind::Authority => SnapshotTlsConfigError::MissingAuthorityCertificate,
            CertificateKind::Identity => SnapshotTlsConfigError::MissingIdentityCertificate,
        });
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, SnapshotTlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| SnapshotTlsConfigError::InvalidPrivateKey)?
        .ok_or(SnapshotTlsConfigError::MissingPrivateKey)
}

#[derive(Debug)]
pub enum SnapshotServerError {
    InvalidConfig,
    Bind(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for SnapshotServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("snapshot server configuration is invalid"),
            Self::Bind(_) => f.write_str("snapshot server bind failed"),
            Self::Accept(_) => f.write_str("snapshot server accept failed"),
        }
    }
}

impl std::error::Error for SnapshotServerError {}

#[derive(Debug)]
pub enum SnapshotClientError {
    InvalidConfig,
    Connect(std::io::Error),
    ConnectTimeout,
    TlsTimeout,
    TlsAuthentication,
    Alpn,
    SubscribeTimeout,
    Protocol(SnapshotProtocolError),
    Server(SnapshotServiceErrorCode),
    BootstrapResponse,
    UnexpectedMessage,
    Update(crate::SnapshotUpdateError),
}

impl std::fmt::Display for SnapshotClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("snapshot client configuration is invalid"),
            Self::Connect(_) => f.write_str("snapshot service connection failed"),
            Self::ConnectTimeout => f.write_str("snapshot service connection timed out"),
            Self::TlsTimeout => f.write_str("snapshot service TLS handshake timed out"),
            Self::TlsAuthentication => f.write_str("snapshot service TLS authentication failed"),
            Self::Alpn => f.write_str("snapshot service ALPN was not negotiated"),
            Self::SubscribeTimeout => f.write_str("snapshot subscription timed out"),
            Self::Protocol(error) => error.fmt(f),
            Self::Server(code) => write!(f, "snapshot service rejected subscription: {code:?}"),
            Self::BootstrapResponse => f.write_str("snapshot bootstrap returned no snapshot"),
            Self::UnexpectedMessage => f.write_str("snapshot service sent an unexpected message"),
            Self::Update(error) => write!(f, "snapshot update was rejected: {error}"),
        }
    }
}

impl std::error::Error for SnapshotClientError {}
