//! Bounded HTTPS/HTTP/1.1 ingress with exact cached hostname routing.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
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
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tunnelproxy_common::{RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal, TunnelId};

pub use tunnelproxy_common::{
    PublicHostname as HttpHostname, PublicHostnameError as HttpHostnameError,
};

use crate::admission::{PeerAdmission, PeerAdmissionPermit};
use crate::http_rate_limit::{
    HttpRateLimitRejection, HttpRequestRateLimitConfig, HttpRequestRateLimitConfigError,
    HttpRequestRateLimiter,
};
use crate::http_tls::{PublicTlsConfig, PUBLIC_HTTP1_ALPN};
use crate::multiplex::{EdgeSessionRouter, RouteError};

pub const MIN_HTTP_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_HTTP_HEADER_BYTES: usize = 1024 * 1024;
pub const MAX_HTTP_HOST_ROUTES: usize = 64;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

fn normalize_authority(value: &str) -> Result<HttpHostname, HttpHostnameError> {
    let authority: Authority = value.parse().map_err(|_| HttpHostnameError::InvalidLabel)?;
    HttpHostname::new(authority.host())
}

#[derive(Debug, Clone)]
pub struct HttpHostRoutes {
    routes: Arc<HashMap<HttpHostname, TunnelId>>,
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
            routes: Arc::new(indexed),
        })
    }

    pub fn single(hostname: HttpHostname, tunnel_id: TunnelId) -> Self {
        Self::new(vec![(hostname, tunnel_id)]).expect("one route is always valid")
    }

    pub fn resolve(&self, hostname: &HttpHostname) -> Option<&TunnelId> {
        self.routes.get(hostname)
    }

    pub fn contains_tunnel(&self, tunnel_id: &TunnelId) -> bool {
        self.routes.values().any(|candidate| candidate == tunnel_id)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
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
    global_rate_limit_rejections: AtomicU64,
    per_ip_rate_limit_rejections: AtomicU64,
    rate_limit_peer_capacity_rejections: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpIngressStatus {
    pub active_connections: usize,
    pub accepted_connections: u64,
    pub completed_requests: u64,
    pub admitted_requests: u64,
    pub rejected_requests: u64,
    pub global_capacity_rejections: u64,
    pub per_ip_capacity_rejections: u64,
    pub tls_rejections: u64,
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
    if !matches!(
        tls.get_ref().1.alpn_protocol(),
        None | Some(PUBLIC_HTTP1_ALPN)
    ) {
        counters.tls_rejections.fetch_add(1, Ordering::Relaxed);
        warn!(%peer, event = "https_alpn_rejected");
        return;
    }
    let server_name = tls
        .get_ref()
        .1
        .server_name()
        .and_then(|name| HttpHostname::new(name).ok());
    let service_config = config.clone();
    let service_counters = Arc::clone(&counters);
    let service = hyper::service::service_fn(move |request| {
        proxy_request(
            request,
            peer,
            server_name.clone(),
            service_config.clone(),
            router.clone(),
            Arc::clone(&service_counters),
            rate_limiter.clone(),
        )
    });
    let mut http = hyper::server::conn::http1::Builder::new();
    http.keep_alive(false)
        .half_close(false)
        .max_buf_size(config.max_header_bytes)
        .max_headers(config.max_headers)
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_read_timeout);
    let served = tokio::time::timeout(
        config.request_timeout,
        http.serve_connection(TokioIo::new(tls), service),
    )
    .await;
    match served {
        Ok(Ok(())) => info!(%peer, event = "https_connection_completed"),
        Ok(Err(error)) => warn!(%peer, %error, event = "https_connection_failed"),
        Err(_) => warn!(%peer, event = "https_request_timeout"),
    }
}

async fn proxy_request(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    server_name: Option<HttpHostname>,
    config: HttpIngressConfig,
    router: EdgeSessionRouter,
    counters: Arc<HttpIngressCounters>,
    rate_limiter: HttpRequestRateLimiter,
) -> Result<Response<ProxyBody>, Infallible> {
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
    counters.completed_requests.fetch_add(1, Ordering::Relaxed);
    Ok(sanitize_response(response))
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
    let host_values = request.headers().get_all(HOST);
    let mut hosts = host_values.iter();
    let host = hosts.next().ok_or(RequestRejection {
        status: StatusCode::BAD_REQUEST,
        reason: "missing_host",
    })?;
    if hosts.next().is_some() {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "duplicate_host",
        });
    }
    let hostname = host
        .to_str()
        .ok()
        .and_then(|value| normalize_authority(value).ok())
        .ok_or(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_host",
        })?;
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
    if let Some(authority) = request.uri().authority() {
        let absolute_hostname =
            normalize_authority(authority.as_str()).map_err(|_| RequestRejection {
                status: StatusCode::BAD_REQUEST,
                reason: "invalid_absolute_uri",
            })?;
        if absolute_hostname != hostname {
            return Err(RequestRejection {
                status: StatusCode::MISDIRECTED_REQUEST,
                reason: "uri_host_mismatch",
            });
        }
    }
    let tunnel_id = config
        .routes
        .resolve(&hostname)
        .cloned()
        .ok_or(RequestRejection {
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

fn sanitize_response(mut response: Response<Incoming>) -> Response<ProxyBody> {
    remove_hop_by_hop(response.headers_mut());
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    let (parts, body) = response.into_parts();
    let body = body
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync();
    Response::from_parts(parts, body)
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
        assert_eq!(routes.resolve(&hostname), Some(&tunnel));
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
    fn status_snapshot_is_live_bounded_and_active_guard_is_raii() {
        let counters = Arc::new(HttpIngressCounters::default());
        let rate_limiter = HttpRequestRateLimiter::new(HttpRequestRateLimitConfig::default());
        let status = HttpIngressStatusHandle {
            counters: Arc::clone(&counters),
            rate_limiter: rate_limiter.clone(),
        };
        counters.accepted_connections.store(3, Ordering::Relaxed);
        counters.admitted_requests.store(2, Ordering::Relaxed);
        rate_limiter
            .try_admit(IpAddr::from([127, 0, 0, 1]))
            .unwrap();
        let active = ActiveConnectionGuard::new(Arc::clone(&counters));
        let snapshot = status.snapshot();
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.accepted_connections, 3);
        assert_eq!(snapshot.admitted_requests, 2);
        assert_eq!(snapshot.tracked_rate_limit_peers, 1);
        assert_eq!(snapshot.peak_tracked_rate_limit_peers, 1);
        drop(active);
        assert_eq!(status.snapshot().active_connections, 0);
    }

    #[test]
    fn rate_limited_response_rounds_retry_after_up_to_seconds() {
        let response = rate_limited_response(Duration::from_millis(1));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
        assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
    }
}
