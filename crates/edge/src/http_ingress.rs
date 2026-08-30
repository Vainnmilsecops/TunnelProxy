//! Bounded HTTPS/HTTP/1.1 ingress with exact cached hostname routing.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper::header::{
    HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, RETRY_AFTER, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::http::uri::Authority;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tunnelproxy_common::{RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal, TunnelId};
use tunnelproxy_control_plane::{
    HttpsRouteCatalogSubscription, HttpsRouteSourceHealth, HttpsRouteStatus,
};

pub use tunnelproxy_common::{
    PublicHostname as HttpHostname, PublicHostnameError as HttpHostnameError,
};

use crate::admission::{PeerAdmission, PeerAdmissionPermit};
use crate::http_rate_limit::{
    HttpRateLimitRejection, HttpRequestRateLimitConfig, HttpRequestRateLimitConfigError,
    HttpRequestRateLimiter,
};
use crate::http_tls::{
    PublicHttpProtocolPolicy, PublicTlsConfig, PUBLIC_HTTP1_ALPN, PUBLIC_HTTP2_ALPN,
};
use crate::multiplex::{EdgeSessionRouter, RouteError};

pub const MIN_HTTP_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_HTTP_HEADER_BYTES: usize = 1024 * 1024;
pub const MAX_HTTP_HOST_ROUTES: usize = 64;
pub const MAX_HTTP_REQUESTS_PER_CONNECTION: usize = 1024;
pub const MAX_HTTP2_CONCURRENT_STREAMS: u32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2IngressConfig {
    pub max_concurrent_streams: u32,
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,
}

impl Default for Http2IngressConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 32,
            keep_alive_interval: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(10),
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

fn normalize_authority(value: &str) -> Result<HttpHostname, HttpHostnameError> {
    let authority: Authority = value.parse().map_err(|_| HttpHostnameError::InvalidLabel)?;
    HttpHostname::new(authority.host())
}

#[derive(Debug, Clone)]
pub struct HttpHostRoutes {
    source: HttpHostRouteSource,
}

#[derive(Debug, Clone)]
enum HttpHostRouteSource {
    Static(Arc<HashMap<HttpHostname, TunnelId>>),
    Dynamic(HttpsRouteCatalogSubscription),
}

impl HttpHostRoutes {
    pub fn new(routes: Vec<(HttpHostname, TunnelId)>) -> Result<Self, HttpHostRoutesError> {
        if routes.is_empty() {
            return Err(HttpHostRoutesError::Empty);
        }
        if routes.len() > MAX_HTTP_HOST_ROUTES {
            return Err(HttpHostRoutesError::TooManyRoutes);
        }
        let mut indexed = HashMap::with_capacity(routes.len());
        for (hostname, tunnel_id) in routes {
            if indexed.insert(hostname.clone(), tunnel_id).is_some() {
                return Err(HttpHostRoutesError::DuplicateHostname(hostname));
            }
        }
        Ok(Self {
            source: HttpHostRouteSource::Static(Arc::new(indexed)),
        })
    }

    pub fn dynamic(subscription: HttpsRouteCatalogSubscription) -> Self {
        Self {
            source: HttpHostRouteSource::Dynamic(subscription),
        }
    }

    pub fn dynamic_unavailable() -> Self {
        use tunnelproxy_control_plane::{
            https_route_catalog_channel, HttpsRouteCatalog, HttpsRouteCatalogVersion,
        };

        let catalog = HttpsRouteCatalog::new(HttpsRouteCatalogVersion::FIRST, Vec::new())
            .expect("an empty route catalog is valid");
        let (publisher, subscription) = https_route_catalog_channel(catalog);
        publisher.set_source_health(HttpsRouteSourceHealth::Expired);
        Self::dynamic(subscription)
    }

    pub fn single(hostname: HttpHostname, tunnel_id: TunnelId) -> Self {
        Self::new(vec![(hostname, tunnel_id)]).expect("one route is always valid")
    }

    pub fn resolve(&self, hostname: &HttpHostname) -> Option<TunnelId> {
        match &self.source {
            HttpHostRouteSource::Static(routes) => routes.get(hostname).cloned(),
            HttpHostRouteSource::Dynamic(subscription)
                if subscription.source_health() != HttpsRouteSourceHealth::Expired =>
            {
                subscription
                    .current()
                    .routes()
                    .iter()
                    .find(|route| {
                        route.status == HttpsRouteStatus::Enabled && &route.hostname == hostname
                    })
                    .map(|route| route.tunnel_id.clone())
            }
            HttpHostRouteSource::Dynamic(_) => None,
        }
    }

    pub fn contains_tunnel(&self, tunnel_id: &TunnelId) -> bool {
        match &self.source {
            HttpHostRouteSource::Static(routes) => {
                routes.values().any(|candidate| candidate == tunnel_id)
            }
            HttpHostRouteSource::Dynamic(subscription)
                if subscription.source_health() != HttpsRouteSourceHealth::Expired =>
            {
                subscription.current().routes().iter().any(|route| {
                    route.status == HttpsRouteStatus::Enabled && &route.tunnel_id == tunnel_id
                })
            }
            HttpHostRouteSource::Dynamic(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        match &self.source {
            HttpHostRouteSource::Static(routes) => routes.len(),
            HttpHostRouteSource::Dynamic(subscription)
                if subscription.source_health() != HttpsRouteSourceHealth::Expired =>
            {
                subscription
                    .current()
                    .routes()
                    .iter()
                    .filter(|route| route.status == HttpsRouteStatus::Enabled)
                    .count()
            }
            HttpHostRouteSource::Dynamic(_) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub const fn is_dynamic(&self) -> bool {
        matches!(&self.source, HttpHostRouteSource::Dynamic(_))
    }

    pub fn dynamic_source_health(&self) -> Option<HttpsRouteSourceHealth> {
        match &self.source {
            HttpHostRouteSource::Static(_) => None,
            HttpHostRouteSource::Dynamic(subscription) => Some(subscription.source_health()),
        }
    }

    pub fn dynamic_catalog_version(&self) -> Option<u64> {
        match &self.source {
            HttpHostRouteSource::Static(_) => None,
            HttpHostRouteSource::Dynamic(subscription) => {
                Some(subscription.current().version().get())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpHostRoutesError {
    Empty,
    TooManyRoutes,
    DuplicateHostname(HttpHostname),
}

impl std::fmt::Display for HttpHostRoutesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("at least one HTTP hostname route is required"),
            Self::TooManyRoutes => write!(f, "HTTP hostname routes exceed {MAX_HTTP_HOST_ROUTES}"),
            Self::DuplicateHostname(hostname) => {
                write!(f, "duplicate HTTP hostname route {hostname}")
            }
        }
    }
}

impl std::error::Error for HttpHostRoutesError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HttpIngressExposurePolicy {
    #[default]
    LoopbackOnly,
    Public {
        max_connections_per_ip: usize,
    },
}

#[derive(Debug, Clone)]
pub struct HttpIngressConfig {
    pub listen_addr: SocketAddr,
    pub routes: HttpHostRoutes,
    pub tls: PublicTlsConfig,
    pub exposure: HttpIngressExposurePolicy,
    pub max_concurrent_connections: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_request_body_bytes: usize,
    pub max_requests_per_connection: usize,
    pub http2: Option<Http2IngressConfig>,
    pub request_rate_limit: HttpRequestRateLimitConfig,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
    pub duplex_capacity: usize,
    pub shutdown: RuntimeShutdownConfig,
}

impl HttpIngressConfig {
    pub fn validate(&self) -> Result<(), HttpIngressConfigError> {
        if self.max_concurrent_connections == 0 {
            return Err(HttpIngressConfigError::ZeroConnections);
        }
        if self.max_concurrent_connections > u32::MAX as usize {
            return Err(HttpIngressConfigError::ConnectionLimitTooLarge);
        }
        match self.exposure {
            HttpIngressExposurePolicy::LoopbackOnly if !self.listen_addr.ip().is_loopback() => {
                return Err(HttpIngressConfigError::NonLoopbackListener(
                    self.listen_addr,
                ));
            }
            HttpIngressExposurePolicy::Public {
                max_connections_per_ip: 0,
            } => return Err(HttpIngressConfigError::ZeroConnectionsPerIp),
            HttpIngressExposurePolicy::Public {
                max_connections_per_ip,
            } if max_connections_per_ip > self.max_concurrent_connections => {
                return Err(HttpIngressConfigError::PerIpExceedsGlobal);
            }
            HttpIngressExposurePolicy::LoopbackOnly | HttpIngressExposurePolicy::Public { .. } => {}
        }
        if !(MIN_HTTP_HEADER_BYTES..=MAX_HTTP_HEADER_BYTES).contains(&self.max_header_bytes) {
            return Err(HttpIngressConfigError::InvalidHeaderBytes);
        }
        if self.max_headers == 0 || self.max_headers > 1024 {
            return Err(HttpIngressConfigError::InvalidHeaderCount);
        }
        if self.max_request_body_bytes == 0 {
            return Err(HttpIngressConfigError::ZeroRequestBodyBytes);
        }
        if !(1..=MAX_HTTP_REQUESTS_PER_CONNECTION).contains(&self.max_requests_per_connection) {
            return Err(HttpIngressConfigError::InvalidRequestsPerConnection);
        }
        match (self.http2, self.tls.protocols()) {
            (None, PublicHttpProtocolPolicy::Http1Only) => {}
            (Some(http2), PublicHttpProtocolPolicy::Http1AndHttp2) => {
                if http2.max_concurrent_streams == 0
                    || http2.max_concurrent_streams > MAX_HTTP2_CONCURRENT_STREAMS
                {
                    return Err(HttpIngressConfigError::InvalidHttp2ConcurrentStreams);
                }
                if http2.keep_alive_interval.is_zero() {
                    return Err(HttpIngressConfigError::ZeroHttp2KeepAliveInterval);
                }
                if http2.keep_alive_timeout.is_zero() {
                    return Err(HttpIngressConfigError::ZeroHttp2KeepAliveTimeout);
                }
            }
            _ => return Err(HttpIngressConfigError::Http2TlsPolicyMismatch),
        }
        self.request_rate_limit
            .validate()
            .map_err(HttpIngressConfigError::InvalidRequestRateLimit)?;
        if self.duplex_capacity == 0 || self.duplex_capacity > 1024 * 1024 {
            return Err(HttpIngressConfigError::InvalidDuplexCapacity);
        }
        if self.header_read_timeout.is_zero() {
            return Err(HttpIngressConfigError::ZeroHeaderTimeout);
        }
        if self.request_timeout.is_zero() {
            return Err(HttpIngressConfigError::ZeroRequestTimeout);
        }
        self.shutdown
            .validate()
            .map_err(|_| HttpIngressConfigError::ZeroDrainTimeout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpIngressConfigError {
    NonLoopbackListener(SocketAddr),
    ZeroConnections,
    ConnectionLimitTooLarge,
    ZeroConnectionsPerIp,
    PerIpExceedsGlobal,
    InvalidHeaderBytes,
    InvalidHeaderCount,
    ZeroRequestBodyBytes,
    InvalidRequestsPerConnection,
    InvalidHttp2ConcurrentStreams,
    ZeroHttp2KeepAliveInterval,
    ZeroHttp2KeepAliveTimeout,
    Http2TlsPolicyMismatch,
    InvalidRequestRateLimit(HttpRequestRateLimitConfigError),
    InvalidDuplexCapacity,
    ZeroHeaderTimeout,
    ZeroRequestTimeout,
    ZeroDrainTimeout,
}

impl std::fmt::Display for HttpIngressConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLoopbackListener(addr) => {
                write!(f, "HTTPS ingress listener must be loopback, got {addr}")
            }
            Self::ZeroConnections => f.write_str("max HTTP connections must be greater than zero"),
            Self::ConnectionLimitTooLarge => {
                f.write_str("max HTTP connections must fit in u32")
            }
            Self::ZeroConnectionsPerIp => {
                f.write_str("max HTTP connections per IP must be greater than zero")
            }
            Self::PerIpExceedsGlobal => {
                f.write_str("max HTTP connections per IP cannot exceed the global limit")
            }
            Self::InvalidHeaderBytes => write!(
                f,
                "max HTTP header bytes must be between {MIN_HTTP_HEADER_BYTES} and {MAX_HTTP_HEADER_BYTES}"
            ),
            Self::InvalidHeaderCount => {
                f.write_str("max HTTP headers must be between 1 and 1024")
            }
            Self::ZeroRequestBodyBytes => {
                f.write_str("max HTTP request body bytes must be greater than zero")
            }
            Self::InvalidRequestsPerConnection => write!(
                f,
                "max HTTP requests per connection must be between 1 and {MAX_HTTP_REQUESTS_PER_CONNECTION}"
            ),
            Self::InvalidHttp2ConcurrentStreams => write!(
                f,
                "max HTTP/2 concurrent streams must be between 1 and {MAX_HTTP2_CONCURRENT_STREAMS}"
            ),
            Self::ZeroHttp2KeepAliveInterval => {
                f.write_str("HTTP/2 keep-alive interval must be greater than zero")
            }
            Self::ZeroHttp2KeepAliveTimeout => {
                f.write_str("HTTP/2 keep-alive timeout must be greater than zero")
            }
            Self::Http2TlsPolicyMismatch => {
                f.write_str("HTTP/2 ingress and public TLS protocol policies must match")
            }
            Self::InvalidRequestRateLimit(error) => {
                write!(f, "invalid HTTP request rate limit: {error}")
            }
            Self::InvalidDuplexCapacity => {
                f.write_str("HTTP duplex capacity must be between 1 and 1048576 bytes")
            }
            Self::ZeroHeaderTimeout => {
                f.write_str("HTTP header timeout must be greater than zero")
            }
            Self::ZeroRequestTimeout => {
                f.write_str("HTTP request timeout must be greater than zero")
            }
            Self::ZeroDrainTimeout => f.write_str("HTTP drain timeout must be greater than zero"),
        }
    }
}

impl std::error::Error for HttpIngressConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpIngressOutcome {
    pub local_addr: SocketAddr,
    pub accepted_connections: u64,
    pub completed_requests: u64,
    pub admitted_requests: u64,
    pub rejected_requests: u64,
    pub global_capacity_rejections: u64,
    pub per_ip_capacity_rejections: u64,
    pub tls_rejections: u64,
    pub http1_connections: u64,
    pub http2_connections: u64,
    pub peak_active_http2_streams: usize,
    pub reused_requests: u64,
    pub request_timeouts: u64,
    pub global_rate_limit_rejections: u64,
    pub per_ip_rate_limit_rejections: u64,
    pub rate_limit_peer_capacity_rejections: u64,
    pub tracked_rate_limit_peers: usize,
    pub peak_tracked_rate_limit_peers: usize,
    pub shutdown: RuntimeShutdownOutcome,
}

impl HttpIngressOutcome {
    pub const fn was_forced(self) -> bool {
        matches!(self.shutdown, RuntimeShutdownOutcome::Forced { .. })
    }
}

#[derive(Debug)]
pub enum HttpIngressError {
    InvalidConfig(HttpIngressConfigError),
    Bind(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for HttpIngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid HTTPS ingress config: {error}"),
            Self::Bind(error) => write!(f, "HTTPS ingress bind failed: {error}"),
            Self::Accept(error) => write!(f, "HTTPS ingress accept failed: {error}"),
        }
    }
}

impl std::error::Error for HttpIngressError {}

#[derive(Default)]
struct HttpIngressCounters {
    active_connections: AtomicUsize,
    accepted_connections: AtomicU64,
    completed_requests: AtomicU64,
    admitted_requests: AtomicU64,
    rejected_requests: AtomicU64,
    global_capacity_rejections: AtomicU64,
    per_ip_capacity_rejections: AtomicU64,
    tls_rejections: AtomicU64,
    http1_connections: AtomicU64,
    http2_connections: AtomicU64,
    active_http2_streams: AtomicUsize,
    peak_active_http2_streams: AtomicUsize,
    reused_requests: AtomicU64,
    request_timeouts: AtomicU64,
    global_rate_limit_rejections: AtomicU64,
    per_ip_rate_limit_rejections: AtomicU64,
    rate_limit_peer_capacity_rejections: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpIngressStatus {
    pub active_connections: usize,
    pub accepted_connections: u64,
    pub completed_requests: u64,
    pub admitted_requests: u64,
    pub rejected_requests: u64,
    pub global_capacity_rejections: u64,
    pub per_ip_capacity_rejections: u64,
    pub tls_rejections: u64,
    pub http1_connections: u64,
    pub http2_connections: u64,
    pub active_http2_streams: usize,
    pub peak_active_http2_streams: usize,
    pub reused_requests: u64,
    pub request_timeouts: u64,
    pub global_rate_limit_rejections: u64,
    pub per_ip_rate_limit_rejections: u64,
    pub rate_limit_peer_capacity_rejections: u64,
    pub tracked_rate_limit_peers: usize,
    pub peak_tracked_rate_limit_peers: usize,
}

#[derive(Clone)]
pub struct HttpIngressStatusHandle {
    counters: Arc<HttpIngressCounters>,
    rate_limiter: HttpRequestRateLimiter,
}

impl HttpIngressStatusHandle {
    pub fn snapshot(&self) -> HttpIngressStatus {
        let rate = self.rate_limiter.status();
        HttpIngressStatus {
            active_connections: self.counters.active_connections.load(Ordering::Relaxed),
            accepted_connections: self.counters.accepted_connections.load(Ordering::Relaxed),
            completed_requests: self.counters.completed_requests.load(Ordering::Relaxed),
            admitted_requests: self.counters.admitted_requests.load(Ordering::Relaxed),
            rejected_requests: self.counters.rejected_requests.load(Ordering::Relaxed),
            global_capacity_rejections: self
                .counters
                .global_capacity_rejections
                .load(Ordering::Relaxed),
            per_ip_capacity_rejections: self
                .counters
                .per_ip_capacity_rejections
                .load(Ordering::Relaxed),
            tls_rejections: self.counters.tls_rejections.load(Ordering::Relaxed),
            http1_connections: self.counters.http1_connections.load(Ordering::Relaxed),
            http2_connections: self.counters.http2_connections.load(Ordering::Relaxed),
            active_http2_streams: self.counters.active_http2_streams.load(Ordering::Relaxed),
            peak_active_http2_streams: self
                .counters
                .peak_active_http2_streams
                .load(Ordering::Relaxed),
            reused_requests: self.counters.reused_requests.load(Ordering::Relaxed),
            request_timeouts: self.counters.request_timeouts.load(Ordering::Relaxed),
            global_rate_limit_rejections: self
                .counters
                .global_rate_limit_rejections
                .load(Ordering::Relaxed),
            per_ip_rate_limit_rejections: self
                .counters
                .per_ip_rate_limit_rejections
                .load(Ordering::Relaxed),
            rate_limit_peer_capacity_rejections: self
                .counters
                .rate_limit_peer_capacity_rejections
                .load(Ordering::Relaxed),
            tracked_rate_limit_peers: rate.tracked_peer_ips,
            peak_tracked_rate_limit_peers: rate.peak_tracked_peer_ips,
        }
    }
}

pub struct HttpIngressRuntime {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: HttpIngressConfig,
    router: EdgeSessionRouter,
    status: HttpIngressStatusHandle,
}

impl HttpIngressRuntime {
    pub async fn bind(
        config: HttpIngressConfig,
        router: EdgeSessionRouter,
    ) -> Result<Self, HttpIngressError> {
        config.validate().map_err(HttpIngressError::InvalidConfig)?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(HttpIngressError::Bind)?;
        let local_addr = listener.local_addr().map_err(HttpIngressError::Bind)?;
        let status = HttpIngressStatusHandle {
            counters: Arc::new(HttpIngressCounters::default()),
            rate_limiter: HttpRequestRateLimiter::new(config.request_rate_limit),
        };
        Ok(Self {
            listener,
            local_addr,
            config,
            router,
            status,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn status_handle(&self) -> HttpIngressStatusHandle {
        self.status.clone()
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<HttpIngressOutcome, HttpIngressError> {
        let permits = Arc::new(Semaphore::new(self.config.max_concurrent_connections));
        let peer_admission = match self.config.exposure {
            HttpIngressExposurePolicy::LoopbackOnly => None,
            HttpIngressExposurePolicy::Public {
                max_connections_per_ip,
            } => Some(Arc::new(PeerAdmission::new(max_connections_per_ip))),
        };
        let counters = Arc::clone(&self.status.counters);
        let rate_limiter = self.status.rate_limiter.clone();
        let mut connections = JoinSet::new();
        let mut terminal_error = None;

        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (socket, peer) = match accepted {
                        Ok(value) => value,
                        Err(error) => {
                            terminal_error = Some(HttpIngressError::Accept(error));
                            break;
                        }
                    };
                    let global_permit = match Arc::clone(&permits).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            counters.global_capacity_rejections.fetch_add(1, Ordering::Relaxed);
                            warn!(%peer, event = "https_global_capacity_rejected");
                            drop(socket);
                            continue;
                        }
                    };
                    let peer_permit = match &peer_admission {
                        Some(admission) => match admission.try_acquire(peer.ip()) {
                            Some(permit) => Some(permit),
                            None => {
                                counters.per_ip_capacity_rejections.fetch_add(1, Ordering::Relaxed);
                                warn!(%peer, event = "https_per_ip_capacity_rejected");
                                drop(global_permit);
                                drop(socket);
                                continue;
                            }
                        },
                        None => None,
                    };
                    counters.accepted_connections.fetch_add(1, Ordering::Relaxed);
                    let active_connection = ActiveConnectionGuard::new(Arc::clone(&counters));
                    connections.spawn(run_connection(
                        socket,
                        peer,
                        self.config.clone(),
                        self.router.clone(),
                        Arc::clone(&counters),
                        rate_limiter.clone(),
                        global_permit,
                        peer_permit,
                        active_connection,
                        signal.clone(),
                    ));
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        drop(self.listener);
        let task_count = connections.len();
        let drained = tokio::time::timeout(self.config.shutdown.drain_timeout, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        let shutdown = if drained.is_ok() {
            RuntimeShutdownOutcome::Drained {
                completed_tasks: task_count,
            }
        } else {
            let aborted_tasks = connections.len();
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            RuntimeShutdownOutcome::Forced {
                completed_tasks: task_count.saturating_sub(aborted_tasks),
                aborted_tasks,
            }
        };
        if let Some(error) = terminal_error {
            return Err(error);
        }
        let status = self.status.snapshot();
        Ok(HttpIngressOutcome {
            local_addr: self.local_addr,
            accepted_connections: counters.accepted_connections.load(Ordering::Relaxed),
            completed_requests: counters.completed_requests.load(Ordering::Relaxed),
            admitted_requests: counters.admitted_requests.load(Ordering::Relaxed),
            rejected_requests: counters.rejected_requests.load(Ordering::Relaxed),
            global_capacity_rejections: counters.global_capacity_rejections.load(Ordering::Relaxed),
            per_ip_capacity_rejections: counters.per_ip_capacity_rejections.load(Ordering::Relaxed),
            tls_rejections: counters.tls_rejections.load(Ordering::Relaxed),
            http1_connections: counters.http1_connections.load(Ordering::Relaxed),
            http2_connections: counters.http2_connections.load(Ordering::Relaxed),
            peak_active_http2_streams: counters.peak_active_http2_streams.load(Ordering::Relaxed),
            reused_requests: counters.reused_requests.load(Ordering::Relaxed),
            request_timeouts: counters.request_timeouts.load(Ordering::Relaxed),
            global_rate_limit_rejections: status.global_rate_limit_rejections,
            per_ip_rate_limit_rejections: status.per_ip_rate_limit_rejections,
            rate_limit_peer_capacity_rejections: status.rate_limit_peer_capacity_rejections,
            tracked_rate_limit_peers: status.tracked_rate_limit_peers,
            peak_tracked_rate_limit_peers: status.peak_tracked_rate_limit_peers,
            shutdown,
        })
    }
}

struct ActiveConnectionGuard {
    counters: Arc<HttpIngressCounters>,
}

impl ActiveConnectionGuard {
    fn new(counters: Arc<HttpIngressCounters>) -> Self {
        counters.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { counters }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.counters
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    socket: TcpStream,
    peer: SocketAddr,
    config: HttpIngressConfig,
    router: EdgeSessionRouter,
    counters: Arc<HttpIngressCounters>,
    rate_limiter: HttpRequestRateLimiter,
    _global_permit: OwnedSemaphorePermit,
    _peer_permit: Option<PeerAdmissionPermit>,
    _active_connection: ActiveConnectionGuard,
    signal: ShutdownSignal,
) {
    let acceptor = TlsAcceptor::from(config.tls.server_config.current());
    let tls =
        match tokio::time::timeout(config.tls.handshake_timeout, acceptor.accept(socket)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(_)) | Err(_) => {
                counters.tls_rejections.fetch_add(1, Ordering::Relaxed);
                warn!(%peer, event = "https_tls_rejected");
                return;
            }
        };
    let protocol = match tls.get_ref().1.alpn_protocol() {
        None | Some(PUBLIC_HTTP1_ALPN) => NegotiatedHttpProtocol::Http1,
        Some(PUBLIC_HTTP2_ALPN) if config.http2.is_some() => NegotiatedHttpProtocol::Http2,
        Some(_) => {
            counters.tls_rejections.fetch_add(1, Ordering::Relaxed);
            warn!(%peer, event = "https_alpn_rejected");
            return;
        }
    };
    match protocol {
        NegotiatedHttpProtocol::Http1 => {
            counters.http1_connections.fetch_add(1, Ordering::Relaxed);
        }
        NegotiatedHttpProtocol::Http2 => {
            counters.http2_connections.fetch_add(1, Ordering::Relaxed);
        }
    }
    let server_name = tls
        .get_ref()
        .1
        .server_name()
        .and_then(|name| HttpHostname::new(name).ok());
    let request_count = Arc::new(AtomicUsize::new(0));
    let service_config = config.clone();
    let service = hyper::service::service_fn(move |request| {
        handle_ingress_request(
            request,
            peer,
            server_name.clone(),
            service_config.clone(),
            router.clone(),
            Arc::clone(&counters),
            rate_limiter.clone(),
            Arc::clone(&request_count),
            protocol,
        )
    });
    match protocol {
        NegotiatedHttpProtocol::Http1 => serve_http1(tls, service, peer, &config, signal).await,
        NegotiatedHttpProtocol::Http2 => serve_http2(tls, service, peer, &config, signal).await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NegotiatedHttpProtocol {
    Http1,
    Http2,
}

#[allow(clippy::too_many_arguments)]
async fn handle_ingress_request(
    request: Request<Incoming>,
    peer: SocketAddr,
    server_name: Option<HttpHostname>,
    config: HttpIngressConfig,
    router: EdgeSessionRouter,
    counters: Arc<HttpIngressCounters>,
    rate_limiter: HttpRequestRateLimiter,
    request_count: Arc<AtomicUsize>,
    protocol: NegotiatedHttpProtocol,
) -> Result<Response<ProxyBody>, Infallible> {
    let request_number = if protocol == NegotiatedHttpProtocol::Http1 {
        request_count
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    } else {
        0
    };
    let stream_guard = (protocol == NegotiatedHttpProtocol::Http2)
        .then(|| ActiveHttp2StreamGuard::new(Arc::clone(&counters)));
    if protocol == NegotiatedHttpProtocol::Http1
        && request_number > config.max_requests_per_connection
    {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        return Ok(finish_protocol_response(
            error_response(StatusCode::SERVICE_UNAVAILABLE),
            protocol,
            stream_guard,
        ));
    }
    if protocol == NegotiatedHttpProtocol::Http1 && request_number > 1 {
        counters.reused_requests.fetch_add(1, Ordering::Relaxed);
    }
    let close_after = protocol == NegotiatedHttpProtocol::Http1
        && request_number == config.max_requests_per_connection;
    let deadline = tokio::time::Instant::now() + config.request_timeout;
    let response = tokio::time::timeout_at(
        deadline,
        proxy_request(
            request,
            HttpRequestContext {
                peer,
                server_name,
                config,
                router,
                counters: Arc::clone(&counters),
                rate_limiter,
            },
            deadline,
        ),
    )
    .await;
    let mut response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(infallible)) => match infallible {},
        Err(_) => {
            counters.request_timeouts.fetch_add(1, Ordering::Relaxed);
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            warn!(%peer, event = "https_request_timeout");
            error_response(StatusCode::GATEWAY_TIMEOUT)
        }
    };
    if close_after {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(finish_protocol_response(response, protocol, stream_guard))
}

async fn serve_http1<S>(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    service: S,
    peer: SocketAddr,
    config: &HttpIngressConfig,
    signal: ShutdownSignal,
) where
    S: hyper::service::Service<
            Request<Incoming>,
            Response = Response<ProxyBody>,
            Error = Infallible,
        > + 'static,
    S::Future: 'static,
{
    let mut http = hyper::server::conn::http1::Builder::new();
    http.keep_alive(config.max_requests_per_connection > 1)
        .half_close(false)
        .max_buf_size(config.max_header_bytes)
        .max_headers(config.max_headers)
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_read_timeout);
    let mut served = Box::pin(http.serve_connection(TokioIo::new(tls), service));
    tokio::select! {
        result = &mut served => match result {
            Ok(()) => info!(%peer, event = "https_connection_completed"),
            Err(error) => warn!(%peer, %error, event = "https_connection_failed"),
        },
        () = signal.cancelled() => {
            served.as_mut().graceful_shutdown();
            match served.await {
                Ok(()) => info!(%peer, event = "https_connection_drained"),
                Err(error) => warn!(%peer, %error, event = "https_connection_drain_failed"),
            }
        }
    }
}

async fn serve_http2<S>(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    service: S,
    peer: SocketAddr,
    config: &HttpIngressConfig,
    signal: ShutdownSignal,
) where
    S: hyper::service::Service<
            Request<Incoming>,
            Response = Response<ProxyBody>,
            Error = Infallible,
        > + 'static,
    S::Future: Send + 'static,
{
    let http2 = config
        .http2
        .expect("HTTP/2 is validated before protocol negotiation");
    let reset_limit = http2.max_concurrent_streams as usize;
    let stream_window = (config.duplex_capacity.min(64 * 1024)) as u32;
    let connection_window = stream_window.saturating_mul(http2.max_concurrent_streams);
    let mut http = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    http.max_concurrent_streams(http2.max_concurrent_streams)
        .max_pending_accept_reset_streams(reset_limit)
        .max_local_error_reset_streams(reset_limit)
        .max_header_list_size(config.max_header_bytes as u32)
        .max_send_buf_size(stream_window as usize)
        .initial_stream_window_size(stream_window)
        .initial_connection_window_size(connection_window)
        .keep_alive_interval(http2.keep_alive_interval)
        .keep_alive_timeout(http2.keep_alive_timeout)
        .timer(TokioTimer::new());
    let mut served = Box::pin(http.serve_connection(TokioIo::new(tls), service));
    tokio::select! {
        result = &mut served => match result {
            Ok(()) => info!(%peer, protocol = "http2", event = "https_connection_completed"),
            Err(error) => warn!(%peer, %error, protocol = "http2", event = "https_connection_failed"),
        },
        () = signal.cancelled() => {
            served.as_mut().graceful_shutdown();
            match served.await {
                Ok(()) => info!(%peer, protocol = "http2", event = "https_connection_drained"),
                Err(error) => warn!(%peer, %error, protocol = "http2", event = "https_connection_drain_failed"),
            }
        }
    }
}

struct ActiveHttp2StreamGuard {
    counters: Arc<HttpIngressCounters>,
}

impl ActiveHttp2StreamGuard {
    fn new(counters: Arc<HttpIngressCounters>) -> Self {
        let active = counters
            .active_http2_streams
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        counters
            .peak_active_http2_streams
            .fetch_max(active, Ordering::Relaxed);
        Self { counters }
    }
}

impl Drop for ActiveHttp2StreamGuard {
    fn drop(&mut self) {
        self.counters
            .active_http2_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct Http2TrackedBody {
    inner: Pin<Box<ProxyBody>>,
    _stream: ActiveHttp2StreamGuard,
}

impl Body for Http2TrackedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.get_mut().inner.as_mut().poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

fn finish_protocol_response(
    mut response: Response<ProxyBody>,
    protocol: NegotiatedHttpProtocol,
    stream: Option<ActiveHttp2StreamGuard>,
) -> Response<ProxyBody> {
    if protocol == NegotiatedHttpProtocol::Http2 {
        response.headers_mut().remove(CONNECTION);
        let (parts, body) = response.into_parts();
        let body = Http2TrackedBody {
            inner: Box::pin(body),
            _stream: stream.expect("HTTP/2 responses own a stream guard"),
        }
        .boxed_unsync();
        Response::from_parts(parts, body)
    } else {
        response
    }
}

struct HttpRequestContext {
    peer: SocketAddr,
    server_name: Option<HttpHostname>,
    config: HttpIngressConfig,
    router: EdgeSessionRouter,
    counters: Arc<HttpIngressCounters>,
    rate_limiter: HttpRequestRateLimiter,
}

async fn proxy_request(
    mut request: Request<Incoming>,
    context: HttpRequestContext,
    deadline: tokio::time::Instant,
) -> Result<Response<ProxyBody>, Infallible> {
    let HttpRequestContext {
        peer,
        server_name,
        config,
        router,
        counters,
        rate_limiter,
    } = context;
    let outcome = prepare_request(&mut request, peer, server_name.as_ref(), &config);
    let (hostname, tunnel_id) = match outcome {
        Ok(value) => value,
        Err(rejection) => {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            warn!(reason = rejection.reason, event = "https_request_rejected");
            return Ok(error_response(rejection.status));
        }
    };

    if let Err(rejection) = rate_limiter.try_admit(peer.ip()) {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        match rejection {
            HttpRateLimitRejection::Global { .. } => {
                counters
                    .global_rate_limit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                warn!(%peer, %hostname, event = "https_global_rate_limited");
            }
            HttpRateLimitRejection::PerIp { .. } => {
                counters
                    .per_ip_rate_limit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                warn!(%peer, %hostname, event = "https_per_ip_rate_limited");
            }
            HttpRateLimitRejection::PeerTableFull { .. } => {
                counters
                    .rate_limit_peer_capacity_rejections
                    .fetch_add(1, Ordering::Relaxed);
                warn!(%peer, %hostname, event = "https_rate_limit_peer_capacity_rejected");
            }
        }
        return Ok(rate_limited_response(rejection.retry_after()));
    }
    counters.admitted_requests.fetch_add(1, Ordering::Relaxed);

    let (parts, body) = request.into_parts();
    if body
        .size_hint()
        .upper()
        .is_some_and(|length| length > config.max_request_body_bytes as u64)
    {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
    }
    let body = Limited::new(body, config.max_request_body_bytes).boxed_unsync();
    let request = Request::from_parts(parts, body);
    let (edge_io, tunnel_io) = tokio::io::duplex(config.duplex_capacity);
    let routed = match router.open_tunnel_io_tracked(&tunnel_id, tunnel_io).await {
        Ok(stream) => stream,
        Err(error) => {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            warn!(%hostname, %error, event = "https_tunnel_unavailable");
            return Ok(error_response(route_error_status(&error)));
        }
    };
    let (mut sender, connection) = match hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(edge_io))
        .await
    {
        Ok(parts) => parts,
        Err(_) => {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
    };
    tokio::spawn(async move {
        let _ = connection.await;
        let _ = routed.wait_closed().await;
    });
    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(_) => {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
    };
    Ok(sanitize_response(response, deadline, counters))
}

struct RequestRejection {
    status: StatusCode,
    reason: &'static str,
}

fn prepare_request(
    request: &mut Request<Incoming>,
    peer: SocketAddr,
    server_name: Option<&HttpHostname>,
    config: &HttpIngressConfig,
) -> Result<(HttpHostname, TunnelId), RequestRejection> {
    if request.method() == Method::CONNECT || request.headers().contains_key(UPGRADE) {
        return Err(RequestRejection {
            status: StatusCode::NOT_IMPLEMENTED,
            reason: "unsupported_method_or_upgrade",
        });
    }
    if request.headers().len() > config.max_headers {
        return Err(RequestRejection {
            status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            reason: "too_many_headers",
        });
    }
    let header_bytes = request
        .headers()
        .iter()
        .fold(0usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
        });
    if header_bytes > config.max_header_bytes {
        return Err(RequestRejection {
            status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            reason: "headers_too_large",
        });
    }
    let host_values = request.headers().get_all(HOST);
    let mut hosts = host_values.iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "duplicate_host",
        });
    }
    let host_hostname = host
        .map(|host| {
            host.to_str()
                .ok()
                .and_then(|value| normalize_authority(value).ok())
                .ok_or(RequestRejection {
                    status: StatusCode::BAD_REQUEST,
                    reason: "invalid_host",
                })
        })
        .transpose()?;
    let uri_hostname = request
        .uri()
        .authority()
        .map(|authority| {
            normalize_authority(authority.as_str()).map_err(|_| RequestRejection {
                status: StatusCode::BAD_REQUEST,
                reason: "invalid_uri_authority",
            })
        })
        .transpose()?;
    if request.version() != Version::HTTP_2 && host_hostname.is_none() {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "missing_host",
        });
    }
    let hostname = match (host_hostname, uri_hostname) {
        (Some(host), Some(authority)) if host != authority => {
            return Err(RequestRejection {
                status: StatusCode::MISDIRECTED_REQUEST,
                reason: "host_authority_mismatch",
            })
        }
        (Some(host), _) => host,
        (None, Some(authority)) => authority,
        (None, None) => {
            return Err(RequestRejection {
                status: StatusCode::BAD_REQUEST,
                reason: "missing_authority",
            })
        }
    };
    let server_name = server_name.ok_or(RequestRejection {
        status: StatusCode::MISDIRECTED_REQUEST,
        reason: "missing_sni",
    })?;
    if &hostname != server_name {
        return Err(RequestRejection {
            status: StatusCode::MISDIRECTED_REQUEST,
            reason: "sni_host_mismatch",
        });
    }
    let tunnel_id = config.routes.resolve(&hostname).ok_or(RequestRejection {
        status: StatusCode::NOT_FOUND,
        reason: "unknown_host",
    })?;
    sanitize_request_headers(request, peer.ip(), &hostname)?;
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    *request.uri_mut() =
        Uri::builder()
            .path_and_query(path)
            .build()
            .map_err(|_| RequestRejection {
                status: StatusCode::BAD_REQUEST,
                reason: "invalid_request_target",
            })?;
    *request.version_mut() = Version::HTTP_11;
    Ok((hostname, tunnel_id))
}

fn sanitize_request_headers(
    request: &mut Request<Incoming>,
    peer_ip: IpAddr,
    hostname: &HttpHostname,
) -> Result<(), RequestRejection> {
    remove_hop_by_hop(request.headers_mut());
    let forwarded_names: Vec<_> = request
        .headers()
        .keys()
        .filter(|name| name.as_str() == "forwarded" || name.as_str().starts_with("x-forwarded-"))
        .cloned()
        .collect();
    for name in forwarded_names {
        request.headers_mut().remove(name);
    }
    let peer = HeaderValue::from_str(&peer_ip.to_string()).map_err(|_| RequestRejection {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid_peer_address",
    })?;
    let host = HeaderValue::from_str(hostname.as_str()).map_err(|_| RequestRejection {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid_canonical_host",
    })?;
    request
        .headers_mut()
        .insert(HeaderName::from_static("x-forwarded-for"), peer);
    request.headers_mut().insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    request
        .headers_mut()
        .insert(HeaderName::from_static("x-forwarded-host"), host.clone());
    request.headers_mut().insert(HOST, host);
    request
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    Ok(())
}

fn remove_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let connection_names: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect();
    for name in connection_names {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
}

fn sanitize_response(
    mut response: Response<Incoming>,
    deadline: tokio::time::Instant,
    counters: Arc<HttpIngressCounters>,
) -> Response<ProxyBody> {
    remove_hop_by_hop(response.headers_mut());
    let (parts, body) = response.into_parts();
    let body = body
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync();
    let body = RequestDeadlineBody::new(body, deadline, counters).boxed_unsync();
    Response::from_parts(parts, body)
}

struct RequestDeadlineBody {
    inner: Pin<Box<ProxyBody>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    counters: Arc<HttpIngressCounters>,
    timeout_recorded: bool,
    completion_recorded: bool,
}

impl RequestDeadlineBody {
    fn new(
        inner: ProxyBody,
        deadline: tokio::time::Instant,
        counters: Arc<HttpIngressCounters>,
    ) -> Self {
        let completion_recorded = inner.is_end_stream();
        if completion_recorded {
            counters.completed_requests.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            inner: Box::pin(inner),
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            counters,
            timeout_recorded: false,
            completion_recorded,
        }
    }
}

impl Body for RequestDeadlineBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.timeout_recorded {
            return Poll::Ready(None);
        }
        if let Poll::Ready(frame) = this.inner.as_mut().poll_frame(context) {
            let completed = match &frame {
                None => true,
                Some(Ok(_)) => this.inner.is_end_stream(),
                Some(Err(_)) => false,
            };
            if completed && !this.completion_recorded {
                this.counters
                    .completed_requests
                    .fetch_add(1, Ordering::Relaxed);
                this.completion_recorded = true;
            }
            return Poll::Ready(frame);
        }
        if this.deadline.as_mut().poll(context).is_ready() {
            if !this.timeout_recorded {
                this.counters
                    .request_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                this.timeout_recorded = true;
            }
            let error = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTPS response body deadline exceeded",
            );
            return Poll::Ready(Some(Err(Box::new(error))));
        }
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

fn route_error_status(error: &RouteError) -> StatusCode {
    match error {
        RouteError::OpenTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
        RouteError::RuntimeDraining
        | RouteError::SessionNotFound(_)
        | RouteError::TunnelNotConnected(_)
        | RouteError::SessionBusy(_)
        | RouteError::SessionClosing(_)
        | RouteError::CapacityExceeded(_)
        | RouteError::StreamIdExhausted(_)
        | RouteError::StreamRejected(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn error_response(status: StatusCode) -> Response<ProxyBody> {
    let message = status.canonical_reason().unwrap_or("request rejected");
    let body = Full::new(Bytes::copy_from_slice(message.as_bytes()))
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    Response::builder()
        .status(status)
        .header(CONNECTION, "close")
        .header(CONTENT_LENGTH, message.len())
        .body(body)
        .expect("static error response is valid")
}

fn rate_limited_response(retry_after: Duration) -> Response<ProxyBody> {
    let status = StatusCode::TOO_MANY_REQUESTS;
    let message = status.canonical_reason().unwrap_or("request rejected");
    let retry_after_seconds = retry_after
        .as_secs()
        .saturating_add(u64::from(retry_after.subsec_nanos() > 0))
        .max(1);
    let retry_after = HeaderValue::from_str(&retry_after_seconds.to_string())
        .expect("integer Retry-After is a valid header value");
    let body = Full::new(Bytes::copy_from_slice(message.as_bytes()))
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    Response::builder()
        .status(status)
        .header(CONNECTION, "close")
        .header(CONTENT_LENGTH, message.len())
        .header(RETRY_AFTER, retry_after)
        .body(body)
        .expect("static rate-limited response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    #[test]
    fn hostname_normalization_is_exact_and_bounded() {
        assert_eq!(
            HttpHostname::new("Demo.Example.COM.").unwrap().as_str(),
            "demo.example.com"
        );
        assert_eq!(
            HttpHostname::new("127.0.0.1").unwrap_err(),
            HttpHostnameError::IpAddress
        );
        assert_eq!(
            HttpHostname::new("bad_label.example").unwrap_err(),
            HttpHostnameError::InvalidLabel
        );
        assert_eq!(
            HttpHostname::new("example.com:443").unwrap_err(),
            HttpHostnameError::PortNotAllowed
        );
    }

    #[test]
    fn route_table_rejects_duplicates_and_resolves_exactly() {
        let hostname = HttpHostname::new("demo.example.com").unwrap();
        let tunnel = TunnelId::new("tunnel-a").unwrap();
        let routes = HttpHostRoutes::single(hostname.clone(), tunnel.clone());
        assert_eq!(routes.resolve(&hostname), Some(tunnel.clone()));
        assert!(routes
            .resolve(&HttpHostname::new("other.example.com").unwrap())
            .is_none());
        assert!(matches!(
            HttpHostRoutes::new(vec![
                (hostname.clone(), tunnel.clone()),
                (hostname.clone(), tunnel)
            ]),
            Err(HttpHostRoutesError::DuplicateHostname(value)) if value == hostname
        ));
    }

    #[test]
    fn dynamic_routes_apply_complete_catalogs_and_expire_fail_closed() {
        use tunnelproxy_control_plane::{
            https_route_catalog_channel, HttpsRouteCatalog, HttpsRouteCatalogVersion,
            HttpsRouteRecord,
        };

        let hostname = HttpHostname::new("demo.example.test").unwrap();
        let first = TunnelId::new("tunnel-a").unwrap();
        let second = TunnelId::new("tunnel-b").unwrap();
        let initial = HttpsRouteCatalog::new(
            HttpsRouteCatalogVersion::FIRST,
            vec![HttpsRouteRecord::new(
                hostname.clone(),
                first.clone(),
                HttpsRouteStatus::Enabled,
            )],
        )
        .unwrap();
        let (publisher, subscription) = https_route_catalog_channel(initial);
        let routes = HttpHostRoutes::dynamic(subscription);
        let connection_routes = routes.clone();
        assert_eq!(routes.resolve(&hostname), Some(first));
        publisher
            .publish(
                HttpsRouteCatalog::new(
                    HttpsRouteCatalogVersion::new(2).unwrap(),
                    vec![HttpsRouteRecord::new(
                        hostname.clone(),
                        second.clone(),
                        HttpsRouteStatus::Enabled,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(routes.resolve(&hostname), Some(second.clone()));
        assert_eq!(connection_routes.resolve(&hostname), Some(second.clone()));
        publisher.set_source_health(HttpsRouteSourceHealth::Expired);
        assert_eq!(routes.resolve(&hostname), None);
        assert_eq!(connection_routes.resolve(&hostname), None);
        assert!(routes.is_empty());
    }

    #[test]
    fn status_snapshot_is_live_bounded_and_active_guard_is_raii() {
        let counters = Arc::new(HttpIngressCounters::default());
        let rate_limiter = HttpRequestRateLimiter::new(HttpRequestRateLimitConfig::default());
        let status = HttpIngressStatusHandle {
            counters: Arc::clone(&counters),
            rate_limiter: rate_limiter.clone(),
        };
        counters.accepted_connections.store(3, Ordering::Relaxed);
        counters.admitted_requests.store(2, Ordering::Relaxed);
        counters.reused_requests.store(1, Ordering::Relaxed);
        counters.request_timeouts.store(4, Ordering::Relaxed);
        counters.http1_connections.store(5, Ordering::Relaxed);
        counters.http2_connections.store(6, Ordering::Relaxed);
        rate_limiter
            .try_admit(IpAddr::from([127, 0, 0, 1]))
            .unwrap();
        let active = ActiveConnectionGuard::new(Arc::clone(&counters));
        let active_http2 = ActiveHttp2StreamGuard::new(Arc::clone(&counters));
        let snapshot = status.snapshot();
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.accepted_connections, 3);
        assert_eq!(snapshot.admitted_requests, 2);
        assert_eq!(snapshot.reused_requests, 1);
        assert_eq!(snapshot.request_timeouts, 4);
        assert_eq!(snapshot.http1_connections, 5);
        assert_eq!(snapshot.http2_connections, 6);
        assert_eq!(snapshot.active_http2_streams, 1);
        assert_eq!(snapshot.peak_active_http2_streams, 1);
        assert_eq!(snapshot.tracked_rate_limit_peers, 1);
        assert_eq!(snapshot.peak_tracked_rate_limit_peers, 1);
        drop(active);
        drop(active_http2);
        assert_eq!(status.snapshot().active_connections, 0);
        assert_eq!(status.snapshot().active_http2_streams, 0);
    }

    #[test]
    fn rate_limited_response_rounds_retry_after_up_to_seconds() {
        let response = rate_limited_response(Duration::from_millis(1));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
        assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
    }

    #[test]
    fn http_protocol_limits_are_strictly_bounded() {
        let routes = HttpHostRoutes::single(
            HttpHostname::new("demo.example.test").unwrap(),
            TunnelId::new("tunnel-dev").unwrap(),
        );
        let pki = rcgen::generate_simple_self_signed(vec!["demo.example.test".to_owned()]).unwrap();
        let mut config = HttpIngressConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            routes,
            tls: PublicTlsConfig::from_pem(
                pki.cert.pem().as_bytes(),
                pki.key_pair.serialize_pem().as_bytes(),
                Duration::from_secs(1),
            )
            .unwrap(),
            exposure: HttpIngressExposurePolicy::LoopbackOnly,
            max_concurrent_connections: 1,
            max_header_bytes: MIN_HTTP_HEADER_BYTES,
            max_headers: 8,
            max_request_body_bytes: 1,
            max_requests_per_connection: 1,
            http2: None,
            request_rate_limit: HttpRequestRateLimitConfig::default(),
            header_read_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
            duplex_capacity: 1,
            shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
        };
        assert!(config.validate().is_ok());
        config.max_requests_per_connection = 0;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::InvalidRequestsPerConnection)
        );
        config.max_requests_per_connection = MAX_HTTP_REQUESTS_PER_CONNECTION + 1;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::InvalidRequestsPerConnection)
        );
        config.max_requests_per_connection = 1;
        config.http2 = Some(Http2IngressConfig::default());
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::Http2TlsPolicyMismatch)
        );
        config.tls = PublicTlsConfig::from_pem_with_protocols(
            pki.cert.pem().as_bytes(),
            pki.key_pair.serialize_pem().as_bytes(),
            Duration::from_secs(1),
            PublicHttpProtocolPolicy::Http1AndHttp2,
        )
        .unwrap();
        assert!(config.validate().is_ok());
        config.http2.as_mut().unwrap().max_concurrent_streams = 0;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::InvalidHttp2ConcurrentStreams)
        );
        let http2 = config.http2.as_mut().unwrap();
        http2.max_concurrent_streams = 1;
        http2.keep_alive_interval = Duration::ZERO;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::ZeroHttp2KeepAliveInterval)
        );
        let http2 = config.http2.as_mut().unwrap();
        http2.keep_alive_interval = Duration::from_secs(1);
        http2.keep_alive_timeout = Duration::ZERO;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::ZeroHttp2KeepAliveTimeout)
        );
    }

    #[tokio::test]
    async fn response_body_deadline_is_enforced_and_observable() {
        let counters = Arc::new(HttpIngressCounters::default());
        let body = PendingBody.boxed_unsync();
        let result = RequestDeadlineBody::new(
            body,
            tokio::time::Instant::now() + Duration::from_millis(10),
            Arc::clone(&counters),
        )
        .collect()
        .await;
        assert!(result.is_err());
        assert_eq!(counters.request_timeouts.load(Ordering::Relaxed), 1);
        assert_eq!(counters.completed_requests.load(Ordering::Relaxed), 0);
    }
}
