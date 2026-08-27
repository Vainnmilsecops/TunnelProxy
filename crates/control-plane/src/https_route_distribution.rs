//! Latest-value HTTPS route publication and authenticated Edge distribution.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::{client::TlsStream, TlsAcceptor};
use tracing::{info, warn};
use tunnelproxy_common::ShutdownSignal;

use crate::{
    read_https_route_message, write_https_route_message, HttpsRouteCatalog,
    HttpsRouteCatalogVersion, HttpsRouteMessage, HttpsRouteProtocolError, HttpsRouteRepository,
    HttpsRouteRepositoryError, HttpsRouteServiceErrorCode, SnapshotClientConfig,
    SnapshotServerTlsConfig, SnapshotTlsConfigError, HTTPS_ROUTE_PROTOCOL_ALPN,
};

#[derive(Debug)]
struct PublisherState {
    current: Arc<HttpsRouteCatalog>,
    updates: watch::Sender<Arc<HttpsRouteCatalog>>,
    health: Arc<AtomicU8>,
}

#[derive(Clone)]
pub struct HttpsRouteCatalogPublisher {
    state: Arc<Mutex<PublisherState>>,
}

impl HttpsRouteCatalogPublisher {
    pub fn current(&self) -> Arc<HttpsRouteCatalog> {
        Arc::clone(
            &self
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .current,
        )
    }

    pub fn publish(
        &self,
        candidate: HttpsRouteCatalog,
    ) -> Result<HttpsRoutePublishOutcome, HttpsRouteUpdateError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if candidate.version() < state.current.version() {
            return Err(HttpsRouteUpdateError::StaleVersion {
                current: state.current.version(),
                received: candidate.version(),
            });
        }
        if candidate.version() == state.current.version() {
            if candidate == *state.current {
                return Ok(HttpsRoutePublishOutcome::Unchanged {
                    version: state.current.version(),
                });
            }
            return Err(HttpsRouteUpdateError::ConflictingVersion {
                version: state.current.version(),
            });
        }
        let previous = state.current.version();
        let candidate = Arc::new(candidate);
        state.current = Arc::clone(&candidate);
        state.updates.send_replace(candidate);
        Ok(HttpsRoutePublishOutcome::Applied {
            previous,
            current: state.current.version(),
        })
    }

    pub fn set_source_health(&self, health: HttpsRouteSourceHealth) {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.health.store(health as u8, Ordering::Release);
        state.updates.send_replace(Arc::clone(&state.current));
    }

    pub fn subscribe(&self) -> HttpsRouteCatalogSubscription {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        HttpsRouteCatalogSubscription {
            updates: state.updates.subscribe(),
            health: Arc::clone(&state.health),
        }
    }
}

impl std::fmt::Debug for HttpsRouteCatalogPublisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpsRouteCatalogPublisher")
            .field("version", &self.current().version())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct HttpsRouteCatalogSubscription {
    updates: watch::Receiver<Arc<HttpsRouteCatalog>>,
    health: Arc<AtomicU8>,
}

impl HttpsRouteCatalogSubscription {
    pub fn current(&self) -> Arc<HttpsRouteCatalog> {
        Arc::clone(&self.updates.borrow())
    }

    pub fn source_health(&self) -> HttpsRouteSourceHealth {
        HttpsRouteSourceHealth::from_raw(self.health.load(Ordering::Acquire))
    }

    pub async fn changed(&mut self) -> Result<Arc<HttpsRouteCatalog>, HttpsRouteSourceClosed> {
        self.updates
            .changed()
            .await
            .map_err(|_| HttpsRouteSourceClosed)?;
        Ok(self.current())
    }
}

pub fn https_route_catalog_channel(
    initial: HttpsRouteCatalog,
) -> (HttpsRouteCatalogPublisher, HttpsRouteCatalogSubscription) {
    let initial = Arc::new(initial);
    let (updates, receiver) = watch::channel(Arc::clone(&initial));
    let health = Arc::new(AtomicU8::new(HttpsRouteSourceHealth::Live as u8));
    (
        HttpsRouteCatalogPublisher {
            state: Arc::new(Mutex::new(PublisherState {
                current: initial,
                updates,
                health: Arc::clone(&health),
            })),
        },
        HttpsRouteCatalogSubscription {
            updates: receiver,
            health,
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HttpsRouteSourceHealth {
    Live = 1,
    Stale = 2,
    Expired = 3,
}

impl HttpsRouteSourceHealth {
    const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Live,
            2 => Self::Stale,
            _ => Self::Expired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsRoutePublishOutcome {
    Applied {
        previous: HttpsRouteCatalogVersion,
        current: HttpsRouteCatalogVersion,
    },
    Unchanged {
        version: HttpsRouteCatalogVersion,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsRouteUpdateError {
    StaleVersion {
        current: HttpsRouteCatalogVersion,
        received: HttpsRouteCatalogVersion,
    },
    ConflictingVersion {
        version: HttpsRouteCatalogVersion,
    },
}

impl std::fmt::Display for HttpsRouteUpdateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleVersion { current, received } => write!(
                formatter,
                "HTTPS route catalog version {received} is stale; current version is {current}"
            ),
            Self::ConflictingVersion { version } => write!(
                formatter,
                "HTTPS route catalog version {version} conflicts with current content"
            ),
        }
    }
}

impl std::error::Error for HttpsRouteUpdateError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpsRouteSourceClosed;

impl std::fmt::Display for HttpsRouteSourceClosed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HTTPS route catalog source closed")
    }
}

impl std::error::Error for HttpsRouteSourceClosed {}

#[derive(Clone)]
pub struct PersistentHttpsRouteCatalog {
    repository: HttpsRouteRepository,
    publisher: HttpsRouteCatalogPublisher,
    refresh_gate: Arc<tokio::sync::Mutex<()>>,
}

impl PersistentHttpsRouteCatalog {
    pub async fn open(repository: HttpsRouteRepository) -> Result<Self, HttpsRouteAuthorityError> {
        let loader = repository.clone();
        let catalog = tokio::task::spawn_blocking(move || loader.load())
            .await
            .map_err(|_| HttpsRouteAuthorityError::StorageTask)?
            .map_err(HttpsRouteAuthorityError::Repository)?;
        let (publisher, _) = https_route_catalog_channel(catalog);
        Ok(Self {
            repository,
            publisher,
            refresh_gate: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn current(&self) -> Arc<HttpsRouteCatalog> {
        self.publisher.current()
    }

    pub fn subscribe(&self) -> HttpsRouteCatalogSubscription {
        self.publisher.subscribe()
    }

    pub async fn refresh_from_repository(
        &self,
    ) -> Result<HttpsRoutePublishOutcome, HttpsRouteAuthorityError> {
        let _guard = self.refresh_gate.lock().await;
        let loader = self.repository.clone();
        let catalog = tokio::task::spawn_blocking(move || loader.load())
            .await
            .map_err(|_| HttpsRouteAuthorityError::StorageTask)?
            .map_err(HttpsRouteAuthorityError::Repository)?;
        self.publisher
            .publish(catalog)
            .map_err(|_| HttpsRouteAuthorityError::PublishInvariant)
    }
}

#[derive(Debug)]
pub enum HttpsRouteAuthorityError {
    Repository(HttpsRouteRepositoryError),
    StorageTask,
    PublishInvariant,
}

impl std::fmt::Display for HttpsRouteAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => error.fmt(formatter),
            Self::StorageTask => {
                formatter.write_str("HTTPS route storage worker stopped unexpectedly")
            }
            Self::PublishInvariant => {
                formatter.write_str("durable and live HTTPS route catalogs became inconsistent")
            }
        }
    }
}

impl std::error::Error for HttpsRouteAuthorityError {}

#[derive(Clone)]
pub struct HttpsRouteServerTlsConfig(SnapshotServerTlsConfig);

impl HttpsRouteServerTlsConfig {
    pub fn from_pem(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        edge_client_ca_pem: &[u8],
        handshake_timeout: Duration,
    ) -> Result<Self, SnapshotTlsConfigError> {
        SnapshotServerTlsConfig::from_pem_with_alpn(
            server_cert_pem,
            server_key_pem,
            edge_client_ca_pem,
            handshake_timeout,
            HTTPS_ROUTE_PROTOCOL_ALPN,
        )
        .map(Self)
    }
}

impl std::fmt::Debug for HttpsRouteServerTlsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpsRouteServerTlsConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct HttpsRouteServerConfig {
    pub listen_addr: SocketAddr,
    pub max_edge_clients: usize,
    pub request_timeout: Duration,
    pub tls: HttpsRouteServerTlsConfig,
}

impl HttpsRouteServerConfig {
    pub fn validate(&self) -> Result<(), HttpsRouteServerError> {
        if self.max_edge_clients == 0 || self.request_timeout.is_zero() {
            return Err(HttpsRouteServerError::InvalidConfig);
        }
        Ok(())
    }
}

pub struct HttpsRouteDistributionServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: HttpsRouteServerConfig,
    catalogs: HttpsRouteCatalogSubscription,
}

impl HttpsRouteDistributionServer {
    pub async fn bind(
        config: HttpsRouteServerConfig,
        catalogs: HttpsRouteCatalogSubscription,
    ) -> Result<Self, HttpsRouteServerError> {
        config.validate()?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(HttpsRouteServerError::Bind)?;
        let local_addr = listener.local_addr().map_err(HttpsRouteServerError::Bind)?;
        Ok(Self {
            listener,
            local_addr,
            config,
            catalogs,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), HttpsRouteServerError> {
        let permits = Arc::new(Semaphore::new(self.config.max_edge_clients));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (socket, peer) = accepted.map_err(HttpsRouteServerError::Accept)?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        warn!(%peer, event = "https_route_client_capacity_rejected");
                        continue;
                    };
                    tasks.spawn(serve_edge(socket, peer, permit, self.config.clone(), self.catalogs.clone()));
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
    config: HttpsRouteServerConfig,
    mut catalogs: HttpsRouteCatalogSubscription,
) {
    let acceptor: TlsAcceptor = config.tls.0.acceptor();
    let mut stream =
        match tokio::time::timeout(config.tls.0.handshake_timeout(), acceptor.accept(socket)).await
        {
            Ok(Ok(stream))
                if stream.get_ref().1.alpn_protocol() == Some(HTTPS_ROUTE_PROTOCOL_ALPN) =>
            {
                stream
            }
            _ => return,
        };
    let request = match tokio::time::timeout(
        config.request_timeout,
        read_https_route_message(&mut stream),
    )
    .await
    {
        Ok(Ok(HttpsRouteMessage::Subscribe {
            last_applied_version,
        })) => last_applied_version,
        _ => {
            let _ = write_https_route_message(
                &mut stream,
                &HttpsRouteMessage::Error(HttpsRouteServiceErrorCode::InvalidRequest),
            )
            .await;
            return;
        }
    };
    let current = catalogs.current();
    let response = if request == current.version().get() {
        HttpsRouteMessage::UpToDate(current.version())
    } else if request < current.version().get() {
        HttpsRouteMessage::Catalog((*current).clone())
    } else {
        HttpsRouteMessage::Error(HttpsRouteServiceErrorCode::ClientAhead)
    };
    if !matches!(
        tokio::time::timeout(
            config.request_timeout,
            write_https_route_message(&mut stream, &response)
        )
        .await,
        Ok(Ok(()))
    ) || matches!(response, HttpsRouteMessage::Error(_))
    {
        return;
    }
    info!(%peer, catalog_version = current.version().get(), event = "https_route_edge_subscribed");
    loop {
        let changed = tokio::select! {
            changed = catalogs.changed() => changed.is_ok(),
            disconnected = stream.read_u8() => {
                let _ = disconnected;
                false
            }
        };
        if !changed {
            return;
        }
        let next = catalogs.current();
        if !matches!(
            tokio::time::timeout(
                config.request_timeout,
                write_https_route_message(
                    &mut stream,
                    &HttpsRouteMessage::Catalog((*next).clone())
                ),
            )
            .await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}

#[derive(Debug)]
pub enum HttpsRouteServerError {
    InvalidConfig,
    Bind(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for HttpsRouteServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => {
                formatter.write_str("HTTPS route server configuration is invalid")
            }
            Self::Bind(_) => formatter.write_str("HTTPS route server bind failed"),
            Self::Accept(_) => formatter.write_str("HTTPS route server accept failed"),
        }
    }
}

impl std::error::Error for HttpsRouteServerError {}

#[derive(Clone)]
pub struct HttpsRouteClientConfig {
    inner: SnapshotClientConfig,
    pub max_stale_age: Duration,
}

impl HttpsRouteClientConfig {
    pub fn from_pem(
        server_addr: SocketAddr,
        control_plane_ca_pem: &[u8],
        edge_client_cert_pem: &[u8],
        edge_client_key_pem: &[u8],
        server_name: &str,
        max_stale_age: Duration,
    ) -> Result<Self, SnapshotTlsConfigError> {
        SnapshotClientConfig::from_pem_with_alpn(
            server_addr,
            control_plane_ca_pem,
            edge_client_cert_pem,
            edge_client_key_pem,
            server_name,
            HTTPS_ROUTE_PROTOCOL_ALPN,
        )
        .map(|inner| Self {
            inner,
            max_stale_age,
        })
    }

    pub fn validate(&self) -> Result<(), HttpsRouteClientError> {
        if self.max_stale_age.is_zero() || self.inner.validate().is_err() {
            return Err(HttpsRouteClientError::InvalidConfig);
        }
        Ok(())
    }
}

impl std::fmt::Debug for HttpsRouteClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpsRouteClientConfig")
            .field("server_addr", &self.inner.server_addr)
            .field("max_stale_age", &self.max_stale_age)
            .finish_non_exhaustive()
    }
}

pub struct HttpsRouteBootstrapClient;

impl HttpsRouteBootstrapClient {
    pub async fn bootstrap(
        config: HttpsRouteClientConfig,
    ) -> Result<(HttpsRouteCatalogSubscription, HttpsRouteClientRuntime), HttpsRouteClientError>
    {
        config.validate()?;
        let (stream, response) = connect_and_subscribe(&config, 0).await?;
        let HttpsRouteMessage::Catalog(initial) = response else {
            return Err(match response {
                HttpsRouteMessage::Error(code) => HttpsRouteClientError::Server(code),
                _ => HttpsRouteClientError::BootstrapResponse,
            });
        };
        let (publisher, subscription) = https_route_catalog_channel(initial);
        Ok((
            subscription,
            HttpsRouteClientRuntime {
                config,
                publisher,
                stream: Some(stream),
                authenticated_at: Instant::now(),
            },
        ))
    }
}

type RouteTlsStream = TlsStream<TcpStream>;

pub struct HttpsRouteClientRuntime {
    config: HttpsRouteClientConfig,
    publisher: HttpsRouteCatalogPublisher,
    stream: Option<RouteTlsStream>,
    authenticated_at: Instant,
}

impl HttpsRouteClientRuntime {
    pub async fn run_until_shutdown(
        mut self,
        signal: ShutdownSignal,
    ) -> Result<(), HttpsRouteClientError> {
        let mut delay = self.config.inner.reconnect_initial_delay;
        loop {
            if let Some(mut stream) = self.stream.take() {
                tokio::select! {
                    biased;
                    () = signal.cancelled() => return Ok(()),
                    message = read_https_route_message(&mut stream) => {
                        match message {
                            Ok(HttpsRouteMessage::Catalog(catalog)) => {
                                self.publisher.publish(catalog).map_err(HttpsRouteClientError::Update)?;
                                self.publisher.set_source_health(HttpsRouteSourceHealth::Live);
                                self.authenticated_at = Instant::now();
                                self.stream = Some(stream);
                                delay = self.config.inner.reconnect_initial_delay;
                                continue;
                            }
                            Ok(_) => return Err(HttpsRouteClientError::UnexpectedMessage),
                            Err(_) => {
                                self.authenticated_at = Instant::now();
                                self.publisher.set_source_health(HttpsRouteSourceHealth::Stale);
                            }
                        }
                    }
                }
            }

            let expires_at = self.authenticated_at + self.config.max_stale_age;
            let expiry_enabled =
                self.publisher.subscribe().source_health() != HttpsRouteSourceHealth::Expired;
            tokio::select! {
                biased;
                () = signal.cancelled() => return Ok(()),
                () = tokio::time::sleep_until(expires_at), if expiry_enabled => {
                    self.publisher.set_source_health(HttpsRouteSourceHealth::Expired);
                }
                () = tokio::time::sleep(delay) => {
                    let reconnect = connect_and_subscribe(
                        &self.config,
                        self.publisher.current().version().get(),
                    );
                    let result = tokio::select! {
                        biased;
                        () = signal.cancelled() => return Ok(()),
                        () = tokio::time::sleep_until(expires_at), if expiry_enabled => {
                            self.publisher.set_source_health(HttpsRouteSourceHealth::Expired);
                            continue;
                        }
                        result = reconnect => result,
                    };
                    match result {
                        Ok((stream, HttpsRouteMessage::Catalog(catalog))) => {
                            self.publisher.publish(catalog).map_err(HttpsRouteClientError::Update)?;
                            self.publisher.set_source_health(HttpsRouteSourceHealth::Live);
                            self.authenticated_at = Instant::now();
                            self.stream = Some(stream);
                            delay = self.config.inner.reconnect_initial_delay;
                        }
                        Ok((stream, HttpsRouteMessage::UpToDate(version)))
                            if version == self.publisher.current().version() =>
                        {
                            self.publisher.set_source_health(HttpsRouteSourceHealth::Live);
                            self.authenticated_at = Instant::now();
                            self.stream = Some(stream);
                            delay = self.config.inner.reconnect_initial_delay;
                        }
                        Ok((_, HttpsRouteMessage::Error(code))) => return Err(HttpsRouteClientError::Server(code)),
                        Ok(_) => return Err(HttpsRouteClientError::UnexpectedMessage),
                        Err(error) if error.allows_retry() => {
                            delay = delay.saturating_mul(2).min(self.config.inner.reconnect_max_delay);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
}

async fn connect_and_subscribe(
    config: &HttpsRouteClientConfig,
    last_applied_version: u64,
) -> Result<(RouteTlsStream, HttpsRouteMessage), HttpsRouteClientError> {
    let socket = tokio::time::timeout(
        config.inner.connect_timeout,
        TcpStream::connect(config.inner.server_addr),
    )
    .await
    .map_err(|_| HttpsRouteClientError::ConnectTimeout)?
    .map_err(HttpsRouteClientError::Connect)?;
    let mut stream = tokio::time::timeout(
        config.inner.handshake_timeout,
        config
            .inner
            .connector()
            .connect(config.inner.server_name(), socket),
    )
    .await
    .map_err(|_| HttpsRouteClientError::TlsTimeout)?
    .map_err(|_| HttpsRouteClientError::TlsAuthentication)?;
    if stream.get_ref().1.alpn_protocol() != Some(HTTPS_ROUTE_PROTOCOL_ALPN) {
        return Err(HttpsRouteClientError::Alpn);
    }
    tokio::time::timeout(
        config.inner.subscribe_timeout,
        write_https_route_message(
            &mut stream,
            &HttpsRouteMessage::Subscribe {
                last_applied_version,
            },
        ),
    )
    .await
    .map_err(|_| HttpsRouteClientError::SubscribeTimeout)?
    .map_err(HttpsRouteClientError::Protocol)?;
    let response = tokio::time::timeout(
        config.inner.subscribe_timeout,
        read_https_route_message(&mut stream),
    )
    .await
    .map_err(|_| HttpsRouteClientError::SubscribeTimeout)?
    .map_err(HttpsRouteClientError::Protocol)?;
    Ok((stream, response))
}

#[derive(Debug)]
pub enum HttpsRouteClientError {
    InvalidConfig,
    ConnectTimeout,
    Connect(std::io::Error),
    TlsTimeout,
    TlsAuthentication,
    Alpn,
    SubscribeTimeout,
    Protocol(HttpsRouteProtocolError),
    Server(HttpsRouteServiceErrorCode),
    BootstrapResponse,
    UnexpectedMessage,
    Update(HttpsRouteUpdateError),
}

impl HttpsRouteClientError {
    const fn allows_retry(&self) -> bool {
        matches!(
            self,
            Self::ConnectTimeout | Self::Connect(_) | Self::TlsTimeout
        )
    }
}

impl std::fmt::Display for HttpsRouteClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "HTTPS route client configuration is invalid",
            Self::ConnectTimeout => "HTTPS route client connect timed out",
            Self::Connect(_) => "HTTPS route client connect failed",
            Self::TlsTimeout => "HTTPS route client TLS handshake timed out",
            Self::TlsAuthentication => "HTTPS route client TLS authentication failed",
            Self::Alpn => "HTTPS route client ALPN negotiation failed",
            Self::SubscribeTimeout => "HTTPS route client subscribe timed out",
            Self::Protocol(_) => "HTTPS route protocol failed",
            Self::Server(_) => "HTTPS route server rejected the client",
            Self::BootstrapResponse => "HTTPS route bootstrap response is invalid",
            Self::UnexpectedMessage => "HTTPS route server sent an unexpected message",
            Self::Update(_) => "HTTPS route catalog update was rejected",
        })
    }
}

impl std::error::Error for HttpsRouteClientError {}

#[cfg(test)]
mod tests {
    use tunnelproxy_common::{PublicHostname, TunnelId};

    use super::*;
    use crate::{HttpsRouteRecord, HttpsRouteStatus};

    fn catalog(version: u64, tunnel: &str) -> HttpsRouteCatalog {
        HttpsRouteCatalog::new(
            HttpsRouteCatalogVersion::new(version).unwrap(),
            vec![HttpsRouteRecord::new(
                PublicHostname::new("demo.example.test").unwrap(),
                TunnelId::new(tunnel).unwrap(),
                HttpsRouteStatus::Enabled,
            )],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn latest_value_ordering_and_health_are_bounded() {
        let (publisher, mut subscription) = https_route_catalog_channel(catalog(1, "tunnel-a"));
        assert!(matches!(
            publisher.publish(catalog(2, "tunnel-b")),
            Ok(HttpsRoutePublishOutcome::Applied { .. })
        ));
        assert_eq!(subscription.changed().await.unwrap().version().get(), 2);
        assert!(matches!(
            publisher.publish(catalog(1, "tunnel-a")),
            Err(HttpsRouteUpdateError::StaleVersion { .. })
        ));
        assert!(matches!(
            publisher.publish(catalog(2, "tunnel-c")),
            Err(HttpsRouteUpdateError::ConflictingVersion { .. })
        ));
        publisher.set_source_health(HttpsRouteSourceHealth::Expired);
        subscription.changed().await.unwrap();
        assert_eq!(
            subscription.source_health(),
            HttpsRouteSourceHealth::Expired
        );
    }
}
