//! Bounded HTTPS/HTTP/1.1 ingress with exact cached hostname routing.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
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
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tunnelproxy_common::{
    PublicReachabilityChallenge, RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal,
    SignedAccessError, SignedAccessKeyRing, TunnelId, PUBLIC_REACHABILITY_CHALLENGE_HEADER,
    PUBLIC_REACHABILITY_PATH, PUBLIC_REACHABILITY_PROOF_HEADER, SIGNED_ACCESS_QUERY_PARAMETER,
};
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
pub const MAX_WEBSOCKET_SESSIONS: usize = 1024;
pub const MAX_CONNECT_SESSIONS: usize = 1024;
pub const MAX_SIGNED_ACCESS_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_SIGNED_ACCESS_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
const UPGRADED_BUFFER_BYTES: usize = 16 * 1024;
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketIngressConfig {
    pub enable_http1: bool,
    pub enable_http2: bool,
    pub max_concurrent_sessions: usize,
    pub idle_timeout: Duration,
}

impl Default for WebSocketIngressConfig {
    fn default() -> Self {
        Self {
            enable_http1: true,
            enable_http2: false,
            max_concurrent_sessions: 32,
            idle_timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectIngressConfig {
    pub enable_http1: bool,
    pub enable_http2: bool,
    pub max_concurrent_sessions: usize,
    pub idle_timeout: Duration,
    pub authority_port: u16,
}

#[derive(Debug, Clone)]
pub struct SignedAccessIngressConfig {
    pub key_ring: SignedAccessKeyRing,
    pub maximum_ttl: Duration,
    pub clock_skew: Duration,
}

impl Default for ConnectIngressConfig {
    fn default() -> Self {
        Self {
            enable_http1: true,
            enable_http2: false,
            max_concurrent_sessions: 32,
            idle_timeout: Duration::from_secs(60),
            authority_port: 443,
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type OpaqueRelay = Pin<Box<dyn Future<Output = ()> + Send>>;

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
    pub websocket: Option<WebSocketIngressConfig>,
    pub connect: Option<ConnectIngressConfig>,
    pub signed_access: Option<SignedAccessIngressConfig>,
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
        if let Some(websocket) = self.websocket {
            if !websocket.enable_http1 && !websocket.enable_http2 {
                return Err(HttpIngressConfigError::WebSocketProtocolsDisabled);
            }
            if websocket.enable_http2 && self.http2.is_none() {
                return Err(HttpIngressConfigError::Http2WebSocketWithoutHttp2);
            }
            if websocket.max_concurrent_sessions == 0
                || websocket.max_concurrent_sessions > MAX_WEBSOCKET_SESSIONS
            {
                return Err(HttpIngressConfigError::InvalidWebSocketSessionLimit);
            }
            if websocket.max_concurrent_sessions > self.max_concurrent_connections {
                return Err(HttpIngressConfigError::WebSocketSessionsExceedConnections);
            }
            if websocket.idle_timeout.is_zero() {
                return Err(HttpIngressConfigError::ZeroWebSocketIdleTimeout);
            }
        }
        if let Some(connect) = self.connect {
            if !connect.enable_http1 && !connect.enable_http2 {
                return Err(HttpIngressConfigError::ConnectProtocolsDisabled);
            }
            if connect.enable_http2 && self.http2.is_none() {
                return Err(HttpIngressConfigError::Http2ConnectWithoutHttp2);
            }
            if connect.max_concurrent_sessions == 0
                || connect.max_concurrent_sessions > MAX_CONNECT_SESSIONS
            {
                return Err(HttpIngressConfigError::InvalidConnectSessionLimit);
            }
            if connect.max_concurrent_sessions > self.max_concurrent_connections {
                return Err(HttpIngressConfigError::ConnectSessionsExceedConnections);
            }
            if connect.idle_timeout.is_zero() {
                return Err(HttpIngressConfigError::ZeroConnectIdleTimeout);
            }
            if connect.authority_port == 0 {
                return Err(HttpIngressConfigError::ZeroConnectAuthorityPort);
            }
        }
        if let Some(signed_access) = &self.signed_access {
            if signed_access.key_ring.is_empty() {
                return Err(HttpIngressConfigError::EmptySignedAccessKeyRing);
            }
            if signed_access.maximum_ttl.is_zero() {
                return Err(HttpIngressConfigError::ZeroSignedAccessMaximumTtl);
            }
            if signed_access.maximum_ttl > MAX_SIGNED_ACCESS_TTL {
                return Err(HttpIngressConfigError::SignedAccessMaximumTtlTooLarge);
            }
            if signed_access.clock_skew > MAX_SIGNED_ACCESS_CLOCK_SKEW {
                return Err(HttpIngressConfigError::SignedAccessClockSkewTooLarge);
            }
            if signed_access.maximum_ttl.subsec_nanos() != 0
                || signed_access.clock_skew.subsec_nanos() != 0
            {
                return Err(HttpIngressConfigError::SubsecondSignedAccessPolicy);
            }
            if self.connect.is_some() {
                return Err(HttpIngressConfigError::SignedAccessWithConnect);
            }
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
    WebSocketProtocolsDisabled,
    Http2WebSocketWithoutHttp2,
    InvalidWebSocketSessionLimit,
    WebSocketSessionsExceedConnections,
    ZeroWebSocketIdleTimeout,
    ConnectProtocolsDisabled,
    Http2ConnectWithoutHttp2,
    InvalidConnectSessionLimit,
    ConnectSessionsExceedConnections,
    ZeroConnectIdleTimeout,
    ZeroConnectAuthorityPort,
    EmptySignedAccessKeyRing,
    ZeroSignedAccessMaximumTtl,
    SignedAccessMaximumTtlTooLarge,
    SignedAccessClockSkewTooLarge,
    SubsecondSignedAccessPolicy,
    SignedAccessWithConnect,
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
            Self::WebSocketProtocolsDisabled => {
                f.write_str("WebSocket ingress must enable HTTP/1.1 or HTTP/2")
            }
            Self::Http2WebSocketWithoutHttp2 => {
                f.write_str("HTTP/2 WebSocket requires HTTP/2 ingress")
            }
            Self::InvalidWebSocketSessionLimit => write!(
                f,
                "max WebSocket sessions must be between 1 and {MAX_WEBSOCKET_SESSIONS}"
            ),
            Self::WebSocketSessionsExceedConnections => {
                f.write_str("max WebSocket sessions cannot exceed max HTTP connections")
            }
            Self::ZeroWebSocketIdleTimeout => {
                f.write_str("WebSocket idle timeout must be greater than zero")
            }
            Self::ConnectProtocolsDisabled => {
                f.write_str("CONNECT ingress must enable HTTP/1.1 or HTTP/2")
            }
            Self::Http2ConnectWithoutHttp2 => {
                f.write_str("HTTP/2 CONNECT requires HTTP/2 ingress")
            }
            Self::InvalidConnectSessionLimit => write!(
                f,
                "max CONNECT sessions must be between 1 and {MAX_CONNECT_SESSIONS}"
            ),
            Self::ConnectSessionsExceedConnections => {
                f.write_str("max CONNECT sessions cannot exceed max HTTP connections")
            }
            Self::ZeroConnectIdleTimeout => {
                f.write_str("CONNECT idle timeout must be greater than zero")
            }
            Self::ZeroConnectAuthorityPort => {
                f.write_str("CONNECT authority port must be greater than zero")
            }
            Self::EmptySignedAccessKeyRing => {
                f.write_str("signed-access public-key ring must not be empty")
            }
            Self::ZeroSignedAccessMaximumTtl => {
                f.write_str("signed-access maximum TTL must be greater than zero")
            }
            Self::SignedAccessMaximumTtlTooLarge => {
                f.write_str("signed-access maximum TTL cannot exceed seven days")
            }
            Self::SignedAccessClockSkewTooLarge => {
                f.write_str("signed-access clock skew cannot exceed five minutes")
            }
            Self::SubsecondSignedAccessPolicy => {
                f.write_str("signed-access TTL and clock skew must use whole seconds")
            }
            Self::SignedAccessWithConnect => {
                f.write_str("signed-access URLs cannot be combined with CONNECT ingress")
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
    pub accepted_websocket_upgrades: u64,
    pub rejected_websocket_upgrades: u64,
    pub peak_active_websocket_sessions: usize,
    pub websocket_idle_timeouts: u64,
    pub accepted_http2_websocket_sessions: u64,
    pub rejected_http2_websocket_sessions: u64,
    pub peak_active_http2_websocket_sessions: usize,
    pub http2_websocket_idle_timeouts: u64,
    pub accepted_connect_sessions: u64,
    pub rejected_connect_sessions: u64,
    pub peak_active_connect_sessions: usize,
    pub connect_idle_timeouts: u64,
    pub accepted_http2_connect_sessions: u64,
    pub rejected_http2_connect_sessions: u64,
    pub peak_active_http2_connect_sessions: usize,
    pub http2_connect_idle_timeouts: u64,
    pub global_rate_limit_rejections: u64,
    pub per_ip_rate_limit_rejections: u64,
    pub rate_limit_peer_capacity_rejections: u64,
    pub accepted_signed_access_requests: u64,
    pub missing_signed_access_rejections: u64,
    pub invalid_signed_access_rejections: u64,
    pub expired_signed_access_rejections: u64,
    pub reachability_probe_requests: u64,
    pub successful_reachability_probes: u64,
    pub failed_reachability_probes: u64,
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
    accepted_websocket_upgrades: AtomicU64,
    rejected_websocket_upgrades: AtomicU64,
    active_websocket_sessions: AtomicUsize,
    peak_active_websocket_sessions: AtomicUsize,
    websocket_idle_timeouts: AtomicU64,
    accepted_http2_websocket_sessions: AtomicU64,
    rejected_http2_websocket_sessions: AtomicU64,
    active_http2_websocket_sessions: AtomicUsize,
    peak_active_http2_websocket_sessions: AtomicUsize,
    http2_websocket_idle_timeouts: AtomicU64,
    accepted_connect_sessions: AtomicU64,
    rejected_connect_sessions: AtomicU64,
    active_connect_sessions: AtomicUsize,
    peak_active_connect_sessions: AtomicUsize,
    connect_idle_timeouts: AtomicU64,
    accepted_http2_connect_sessions: AtomicU64,
    rejected_http2_connect_sessions: AtomicU64,
    active_http2_connect_sessions: AtomicUsize,
    peak_active_http2_connect_sessions: AtomicUsize,
    http2_connect_idle_timeouts: AtomicU64,
    global_rate_limit_rejections: AtomicU64,
    per_ip_rate_limit_rejections: AtomicU64,
    rate_limit_peer_capacity_rejections: AtomicU64,
    accepted_signed_access_requests: AtomicU64,
    missing_signed_access_rejections: AtomicU64,
    invalid_signed_access_rejections: AtomicU64,
    expired_signed_access_rejections: AtomicU64,
    reachability_probe_requests: AtomicU64,
    successful_reachability_probes: AtomicU64,
    failed_reachability_probes: AtomicU64,
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
    pub accepted_websocket_upgrades: u64,
    pub rejected_websocket_upgrades: u64,
    pub active_websocket_sessions: usize,
    pub peak_active_websocket_sessions: usize,
    pub websocket_idle_timeouts: u64,
    pub accepted_http2_websocket_sessions: u64,
    pub rejected_http2_websocket_sessions: u64,
    pub active_http2_websocket_sessions: usize,
    pub peak_active_http2_websocket_sessions: usize,
    pub http2_websocket_idle_timeouts: u64,
    pub accepted_connect_sessions: u64,
    pub rejected_connect_sessions: u64,
    pub active_connect_sessions: usize,
    pub peak_active_connect_sessions: usize,
    pub connect_idle_timeouts: u64,
    pub accepted_http2_connect_sessions: u64,
    pub rejected_http2_connect_sessions: u64,
    pub active_http2_connect_sessions: usize,
    pub peak_active_http2_connect_sessions: usize,
    pub http2_connect_idle_timeouts: u64,
    pub global_rate_limit_rejections: u64,
    pub per_ip_rate_limit_rejections: u64,
    pub rate_limit_peer_capacity_rejections: u64,
    pub accepted_signed_access_requests: u64,
    pub missing_signed_access_rejections: u64,
    pub invalid_signed_access_rejections: u64,
    pub expired_signed_access_rejections: u64,
    pub reachability_probe_requests: u64,
    pub successful_reachability_probes: u64,
    pub failed_reachability_probes: u64,
    pub signed_access_keyring_generation: u64,
    pub signed_access_keyring_reload_failed: bool,
    pub signed_access_keyring_reload_successes: u64,
    pub signed_access_keyring_reload_failures: u64,
    pub tracked_rate_limit_peers: usize,
    pub peak_tracked_rate_limit_peers: usize,
}

#[derive(Clone)]
pub struct HttpIngressStatusHandle {
    counters: Arc<HttpIngressCounters>,
    rate_limiter: HttpRequestRateLimiter,
    signed_access_key_ring: Option<SignedAccessKeyRing>,
}

impl HttpIngressStatusHandle {
    pub fn snapshot(&self) -> HttpIngressStatus {
        let rate = self.rate_limiter.status();
        let reload = self
            .signed_access_key_ring
            .as_ref()
            .and_then(SignedAccessKeyRing::reload_status);
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
            accepted_websocket_upgrades: self
                .counters
                .accepted_websocket_upgrades
                .load(Ordering::Relaxed),
            rejected_websocket_upgrades: self
                .counters
                .rejected_websocket_upgrades
                .load(Ordering::Relaxed),
            active_websocket_sessions: self
                .counters
                .active_websocket_sessions
                .load(Ordering::Relaxed),
            peak_active_websocket_sessions: self
                .counters
                .peak_active_websocket_sessions
                .load(Ordering::Relaxed),
            websocket_idle_timeouts: self
                .counters
                .websocket_idle_timeouts
                .load(Ordering::Relaxed),
            accepted_http2_websocket_sessions: self
                .counters
                .accepted_http2_websocket_sessions
                .load(Ordering::Relaxed),
            rejected_http2_websocket_sessions: self
                .counters
                .rejected_http2_websocket_sessions
                .load(Ordering::Relaxed),
            active_http2_websocket_sessions: self
                .counters
                .active_http2_websocket_sessions
                .load(Ordering::Relaxed),
            peak_active_http2_websocket_sessions: self
                .counters
                .peak_active_http2_websocket_sessions
                .load(Ordering::Relaxed),
            http2_websocket_idle_timeouts: self
                .counters
                .http2_websocket_idle_timeouts
                .load(Ordering::Relaxed),
            accepted_connect_sessions: self
                .counters
                .accepted_connect_sessions
                .load(Ordering::Relaxed),
            rejected_connect_sessions: self
                .counters
                .rejected_connect_sessions
                .load(Ordering::Relaxed),
            active_connect_sessions: self
                .counters
                .active_connect_sessions
                .load(Ordering::Relaxed),
            peak_active_connect_sessions: self
                .counters
                .peak_active_connect_sessions
                .load(Ordering::Relaxed),
            connect_idle_timeouts: self.counters.connect_idle_timeouts.load(Ordering::Relaxed),
            accepted_http2_connect_sessions: self
                .counters
                .accepted_http2_connect_sessions
                .load(Ordering::Relaxed),
            rejected_http2_connect_sessions: self
                .counters
                .rejected_http2_connect_sessions
                .load(Ordering::Relaxed),
            active_http2_connect_sessions: self
                .counters
                .active_http2_connect_sessions
                .load(Ordering::Relaxed),
            peak_active_http2_connect_sessions: self
                .counters
                .peak_active_http2_connect_sessions
                .load(Ordering::Relaxed),
            http2_connect_idle_timeouts: self
                .counters
                .http2_connect_idle_timeouts
                .load(Ordering::Relaxed),
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
            accepted_signed_access_requests: self
                .counters
                .accepted_signed_access_requests
                .load(Ordering::Relaxed),
            missing_signed_access_rejections: self
                .counters
                .missing_signed_access_rejections
                .load(Ordering::Relaxed),
            invalid_signed_access_rejections: self
                .counters
                .invalid_signed_access_rejections
                .load(Ordering::Relaxed),
            expired_signed_access_rejections: self
                .counters
                .expired_signed_access_rejections
                .load(Ordering::Relaxed),
            reachability_probe_requests: self
                .counters
                .reachability_probe_requests
                .load(Ordering::Relaxed),
            successful_reachability_probes: self
                .counters
                .successful_reachability_probes
                .load(Ordering::Relaxed),
            failed_reachability_probes: self
                .counters
                .failed_reachability_probes
                .load(Ordering::Relaxed),
            signed_access_keyring_generation: reload.map_or(0, |status| status.generation),
            signed_access_keyring_reload_failed: reload.is_some_and(|status| status.reload_failed),
            signed_access_keyring_reload_successes: reload
                .map_or(0, |status| status.successful_reloads),
            signed_access_keyring_reload_failures: reload.map_or(0, |status| status.failed_reloads),
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
            signed_access_key_ring: config
                .signed_access
                .as_ref()
                .map(|signed_access| signed_access.key_ring.clone()),
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
        let websocket_permits = self
            .config
            .websocket
            .map(|websocket| Arc::new(Semaphore::new(websocket.max_concurrent_sessions)));
        let connect_permits = self
            .config
            .connect
            .map(|connect| Arc::new(Semaphore::new(connect.max_concurrent_sessions)));
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
                        websocket_permits.clone(),
                        connect_permits.clone(),
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
            accepted_websocket_upgrades: status.accepted_websocket_upgrades,
            rejected_websocket_upgrades: status.rejected_websocket_upgrades,
            peak_active_websocket_sessions: status.peak_active_websocket_sessions,
            websocket_idle_timeouts: status.websocket_idle_timeouts,
            accepted_http2_websocket_sessions: status.accepted_http2_websocket_sessions,
            rejected_http2_websocket_sessions: status.rejected_http2_websocket_sessions,
            peak_active_http2_websocket_sessions: status.peak_active_http2_websocket_sessions,
            http2_websocket_idle_timeouts: status.http2_websocket_idle_timeouts,
            accepted_connect_sessions: status.accepted_connect_sessions,
            rejected_connect_sessions: status.rejected_connect_sessions,
            peak_active_connect_sessions: status.peak_active_connect_sessions,
            connect_idle_timeouts: status.connect_idle_timeouts,
            accepted_http2_connect_sessions: status.accepted_http2_connect_sessions,
            rejected_http2_connect_sessions: status.rejected_http2_connect_sessions,
            peak_active_http2_connect_sessions: status.peak_active_http2_connect_sessions,
            http2_connect_idle_timeouts: status.http2_connect_idle_timeouts,
            global_rate_limit_rejections: status.global_rate_limit_rejections,
            per_ip_rate_limit_rejections: status.per_ip_rate_limit_rejections,
            rate_limit_peer_capacity_rejections: status.rate_limit_peer_capacity_rejections,
            accepted_signed_access_requests: status.accepted_signed_access_requests,
            missing_signed_access_rejections: status.missing_signed_access_rejections,
            invalid_signed_access_rejections: status.invalid_signed_access_rejections,
            expired_signed_access_rejections: status.expired_signed_access_rejections,
            reachability_probe_requests: status.reachability_probe_requests,
            successful_reachability_probes: status.successful_reachability_probes,
            failed_reachability_probes: status.failed_reachability_probes,
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
    websocket_permits: Option<Arc<Semaphore>>,
    connect_permits: Option<Arc<Semaphore>>,
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
    let opaque_relay_capacity = match protocol {
        NegotiatedHttpProtocol::Http1 => 1,
        NegotiatedHttpProtocol::Http2 => config
            .http2
            .map_or(1, |http2| http2.max_concurrent_streams as usize),
    };
    let (opaque_relay_tx, opaque_relay_rx) = mpsc::channel(opaque_relay_capacity);
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
            websocket_permits.clone(),
            connect_permits.clone(),
            Some(opaque_relay_tx.clone()),
            Arc::clone(&request_count),
            protocol,
        )
    });
    match protocol {
        NegotiatedHttpProtocol::Http1 => {
            serve_http1(tls, service, opaque_relay_rx, peer, &config, signal).await
        }
        NegotiatedHttpProtocol::Http2 => {
            serve_http2(tls, service, opaque_relay_rx, peer, &config, signal).await
        }
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
    websocket_permits: Option<Arc<Semaphore>>,
    connect_permits: Option<Arc<Semaphore>>,
    opaque_relay_tx: Option<mpsc::Sender<OpaqueRelay>>,
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
                websocket_permits,
                connect_permits,
                opaque_relay_tx,
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
    if close_after
        && response.status() != StatusCode::SWITCHING_PROTOCOLS
        && response.extensions().get::<ConnectResponse>().is_none()
    {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(finish_protocol_response(response, protocol, stream_guard))
}

async fn serve_http1<S>(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    service: S,
    mut opaque_relay_rx: mpsc::Receiver<OpaqueRelay>,
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
    http.keep_alive(
        config.max_requests_per_connection > 1
            || config.connect.is_some_and(|connect| connect.enable_http1),
    )
    .half_close(false)
    .max_buf_size(config.max_header_bytes)
    .max_headers(config.max_headers)
    .timer(TokioTimer::new())
    .header_read_timeout(config.header_read_timeout);
    let mut served = Box::pin(
        http.serve_connection(TokioIo::new(tls), service)
            .with_upgrades(),
    );
    tokio::select! {
        result = &mut served => {
            if let Ok(relay) = opaque_relay_rx.try_recv() {
                relay.await;
                info!(%peer, event = "https_opaque_session_completed");
            } else {
                match result {
                    Ok(()) => info!(%peer, event = "https_connection_completed"),
                    Err(error) => warn!(%peer, %error, event = "https_connection_failed"),
                }
            }
        },
        () = signal.cancelled() => {
            served.as_mut().graceful_shutdown();
            tokio::select! {
                result = &mut served => {
                    if let Ok(relay) = opaque_relay_rx.try_recv() {
                        relay.await;
                        info!(%peer, event = "https_opaque_session_drained");
                    } else {
                        match result {
                            Ok(()) => info!(%peer, event = "https_connection_drained"),
                            Err(error) => warn!(%peer, %error, event = "https_connection_drain_failed"),
                        }
                    }
                },
                relay = opaque_relay_rx.recv() => {
                    if let Some(relay) = relay {
                        let (result, ()) = tokio::join!(&mut served, relay);
                        match result {
                            Ok(()) => info!(%peer, event = "https_opaque_session_drained"),
                            Err(error) => warn!(%peer, %error, event = "https_opaque_session_drain_failed"),
                        }
                    }
                }
            }
        },
        relay = opaque_relay_rx.recv() => {
            if let Some(relay) = relay {
                let (result, ()) = tokio::join!(&mut served, relay);
                match result {
                    Ok(()) => info!(%peer, event = "https_opaque_session_completed"),
                    Err(error) => warn!(%peer, %error, event = "https_opaque_session_connection_failed"),
                }
            }
        }
    }
}

async fn serve_http2<S>(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    service: S,
    mut opaque_relay_rx: mpsc::Receiver<OpaqueRelay>,
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
    if config
        .websocket
        .is_some_and(|websocket| websocket.enable_http2)
    {
        http.enable_connect_protocol();
    }
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
    let mut relays = JoinSet::new();
    let mut draining = false;
    let result = loop {
        tokio::select! {
            result = &mut served => break result,
            relay = opaque_relay_rx.recv() => {
                if let Some(relay) = relay {
                    relays.spawn(relay);
                }
            }
            _ = relays.join_next(), if !relays.is_empty() => {}
            () = signal.cancelled(), if !draining => {
                draining = true;
                served.as_mut().graceful_shutdown();
            }
        }
    };
    while relays.join_next().await.is_some() {}
    match (draining, result) {
        (false, Ok(())) => info!(%peer, protocol = "http2", event = "https_connection_completed"),
        (false, Err(error)) => {
            warn!(%peer, %error, protocol = "http2", event = "https_connection_failed")
        }
        (true, Ok(())) => info!(%peer, protocol = "http2", event = "https_connection_drained"),
        (true, Err(error)) => {
            warn!(%peer, %error, protocol = "http2", event = "https_connection_drain_failed")
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
    websocket_permits: Option<Arc<Semaphore>>,
    connect_permits: Option<Arc<Semaphore>>,
    opaque_relay_tx: Option<mpsc::Sender<OpaqueRelay>>,
}

#[derive(Debug, Clone)]
struct ConnectResponse;

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
        websocket_permits,
        connect_permits,
        opaque_relay_tx,
    } = context;
    let reachability_intent = request.uri().path() == PUBLIC_REACHABILITY_PATH;
    let http2_websocket_intent = request.version() == Version::HTTP_2
        && request
            .extensions()
            .get::<hyper::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"));
    let websocket_intent = has_websocket_intent(request.headers()) || http2_websocket_intent;
    let connect_intent = request.method() == Method::CONNECT
        && request.extensions().get::<hyper::ext::Protocol>().is_none();
    let http2_connect_intent = connect_intent && request.version() == Version::HTTP_2;
    let outcome = prepare_request(&mut request, server_name.as_ref(), &config);
    let PreparedRequest {
        hostname,
        tunnel_id,
        kind,
    } = match outcome {
        Ok(value) => value,
        Err(rejection) => {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            if reachability_intent {
                counters
                    .reachability_probe_requests
                    .fetch_add(1, Ordering::Relaxed);
                counters
                    .failed_reachability_probes
                    .fetch_add(1, Ordering::Relaxed);
            }
            if websocket_intent {
                counters
                    .rejected_websocket_upgrades
                    .fetch_add(1, Ordering::Relaxed);
                if http2_websocket_intent {
                    counters
                        .rejected_http2_websocket_sessions
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            if connect_intent {
                counters
                    .rejected_connect_sessions
                    .fetch_add(1, Ordering::Relaxed);
            }
            if http2_connect_intent {
                counters
                    .rejected_http2_connect_sessions
                    .fetch_add(1, Ordering::Relaxed);
            }
            warn!(reason = rejection.reason, event = "https_request_rejected");
            return Ok(error_response(rejection.status));
        }
    };

    if let Err(rejection) = rate_limiter.try_admit(peer.ip()) {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        if reachability_intent {
            counters
                .reachability_probe_requests
                .fetch_add(1, Ordering::Relaxed);
            counters
                .failed_reachability_probes
                .fetch_add(1, Ordering::Relaxed);
        }
        if matches!(&kind, PreparedRequestKind::WebSocket(_)) {
            counters
                .rejected_websocket_upgrades
                .fetch_add(1, Ordering::Relaxed);
            if is_http2_websocket(&kind) {
                counters
                    .rejected_http2_websocket_sessions
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        if matches!(&kind, PreparedRequestKind::Connect(_)) {
            counters
                .rejected_connect_sessions
                .fetch_add(1, Ordering::Relaxed);
        }
        if matches!(
            &kind,
            PreparedRequestKind::Connect(NegotiatedHttpProtocol::Http2)
        ) {
            counters
                .rejected_http2_connect_sessions
                .fetch_add(1, Ordering::Relaxed);
        }
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
    if let PreparedRequestKind::ReachabilityProbe(proof) = &kind {
        counters
            .reachability_probe_requests
            .fetch_add(1, Ordering::Relaxed);
        if router.resolve_tunnel(&tunnel_id).await.is_none() {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            counters
                .failed_reachability_probes
                .fetch_add(1, Ordering::Relaxed);
            warn!(%peer, %hostname, event = "https_reachability_probe_route_unavailable");
            return Ok(no_store_error_response(StatusCode::SERVICE_UNAVAILABLE));
        }
        counters.admitted_requests.fetch_add(1, Ordering::Relaxed);
        counters.completed_requests.fetch_add(1, Ordering::Relaxed);
        counters
            .successful_reachability_probes
            .fetch_add(1, Ordering::Relaxed);
        info!(%peer, %hostname, event = "https_reachability_probe_succeeded");
        return Ok(reachability_probe_response(proof));
    }
    if let Some(signed_access) = &config.signed_access {
        if let Err(rejection) = authorize_signed_access(&mut request, &hostname, signed_access) {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            match rejection.reason {
                "signed_access_missing" => &counters.missing_signed_access_rejections,
                "signed_access_expired" => &counters.expired_signed_access_rejections,
                _ => &counters.invalid_signed_access_rejections,
            }
            .fetch_add(1, Ordering::Relaxed);
            record_protocol_rejection(&counters, &kind);
            warn!(%peer, %hostname, reason = rejection.reason, event = "https_signed_access_rejected");
            return Ok(unauthorized_response());
        }
        counters
            .accepted_signed_access_requests
            .fetch_add(1, Ordering::Relaxed);
    }
    if let Err(rejection) = finalize_request(&mut request, peer, &hostname, &kind) {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        record_protocol_rejection(&counters, &kind);
        warn!(%peer, %hostname, reason = rejection.reason, event = "https_request_rejected");
        return Ok(error_response(rejection.status));
    }
    counters.admitted_requests.fetch_add(1, Ordering::Relaxed);

    let websocket_guard = if matches!(&kind, PreparedRequestKind::WebSocket(_)) {
        let permits = websocket_permits
            .expect("WebSocket permits exist when validated WebSocket ingress is enabled");
        match permits.try_acquire_owned() {
            Ok(permit) => Some(WebSocketSessionGuard::new(
                Arc::clone(&counters),
                permit,
                websocket_protocol(&kind),
            )),
            Err(_) => {
                counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                counters
                    .rejected_websocket_upgrades
                    .fetch_add(1, Ordering::Relaxed);
                if is_http2_websocket(&kind) {
                    counters
                        .rejected_http2_websocket_sessions
                        .fetch_add(1, Ordering::Relaxed);
                }
                warn!(%peer, %hostname, event = "https_websocket_capacity_rejected");
                return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE));
            }
        }
    } else {
        None
    };

    let connect_guard = if let PreparedRequestKind::Connect(protocol) = &kind {
        let permits = connect_permits
            .expect("CONNECT permits exist when validated CONNECT ingress is enabled");
        match permits.try_acquire_owned() {
            Ok(permit) => Some(ConnectSessionGuard::new(
                Arc::clone(&counters),
                permit,
                *protocol,
            )),
            Err(_) => {
                counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                counters
                    .rejected_connect_sessions
                    .fetch_add(1, Ordering::Relaxed);
                if *protocol == NegotiatedHttpProtocol::Http2 {
                    counters
                        .rejected_http2_connect_sessions
                        .fetch_add(1, Ordering::Relaxed);
                }
                warn!(%peer, %hostname, event = "https_connect_capacity_rejected");
                return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE));
            }
        }
    } else {
        None
    };

    let client_upgrade = matches!(
        &kind,
        PreparedRequestKind::WebSocket(_) | PreparedRequestKind::Connect(_)
    )
    .then(|| hyper::upgrade::on(&mut request));

    let (parts, incoming_body) = request.into_parts();
    if incoming_body
        .size_hint()
        .upper()
        .is_some_and(|length| length > config.max_request_body_bytes as u64)
    {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
    }
    let (edge_io, tunnel_io) = tokio::io::duplex(config.duplex_capacity);
    let routed = match router.open_tunnel_io_tracked(&tunnel_id, tunnel_io).await {
        Ok(stream) => stream,
        Err(error) => {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            if matches!(&kind, PreparedRequestKind::WebSocket(_)) {
                counters
                    .rejected_websocket_upgrades
                    .fetch_add(1, Ordering::Relaxed);
                if is_http2_websocket(&kind) {
                    counters
                        .rejected_http2_websocket_sessions
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            if matches!(&kind, PreparedRequestKind::Connect(_)) {
                counters
                    .rejected_connect_sessions
                    .fetch_add(1, Ordering::Relaxed);
            }
            if matches!(
                &kind,
                PreparedRequestKind::Connect(NegotiatedHttpProtocol::Http2)
            ) {
                counters
                    .rejected_http2_connect_sessions
                    .fetch_add(1, Ordering::Relaxed);
            }
            warn!(%hostname, %error, event = "https_tunnel_unavailable");
            return Ok(error_response(route_error_status(&error)));
        }
    };
    if matches!(
        &kind,
        PreparedRequestKind::Connect(NegotiatedHttpProtocol::Http1)
    ) {
        let relay_tx = opaque_relay_tx.expect("HTTP/1.1 CONNECT requests have a relay owner");
        let connect = config.connect.expect("validated CONNECT config exists");
        let counters_for_relay = Arc::clone(&counters);
        let relay: OpaqueRelay = Box::pin(async move {
            let _session = connect_guard.expect("CONNECT admission owns a guard");
            match tokio::time::timeout(
                config.request_timeout,
                client_upgrade.expect("CONNECT request captured public upgrade"),
            )
            .await
            {
                Ok(Ok(client)) => {
                    if relay_upgraded_io(TokioIo::new(client), edge_io, connect.idle_timeout).await
                        == OpaqueRelayOutcome::IdleTimeout
                    {
                        counters_for_relay
                            .connect_idle_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Err(_)) | Err(_) => warn!(event = "https_connect_upgrade_failed"),
            }
            let _ = routed.wait_closed().await;
            counters_for_relay
                .completed_requests
                .fetch_add(1, Ordering::Relaxed);
        });
        if relay_tx.try_send(relay).is_err() {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            counters
                .rejected_connect_sessions
                .fetch_add(1, Ordering::Relaxed);
            return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE));
        }
        counters
            .accepted_connect_sessions
            .fetch_add(1, Ordering::Relaxed);
        info!(%peer, %hostname, event = "https_connect_established");
        let body = Full::new(Bytes::new())
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        let mut response = Response::new(body);
        *response.status_mut() = StatusCode::OK;
        response.extensions_mut().insert(ConnectResponse);
        return Ok(response);
    }
    if matches!(
        &kind,
        PreparedRequestKind::Connect(NegotiatedHttpProtocol::Http2)
    ) {
        let relay_tx = opaque_relay_tx.expect("HTTP/2 CONNECT requests have a relay owner");
        let connect = config.connect.expect("validated CONNECT config exists");
        let counters_for_relay = Arc::clone(&counters);
        let relay: OpaqueRelay = Box::pin(async move {
            let _session = connect_guard.expect("CONNECT admission owns a guard");
            match tokio::time::timeout(
                config.request_timeout,
                client_upgrade.expect("CONNECT request captured public upgrade"),
            )
            .await
            {
                Ok(Ok(client)) => {
                    if relay_upgraded_io(TokioIo::new(client), edge_io, connect.idle_timeout).await
                        == OpaqueRelayOutcome::IdleTimeout
                    {
                        counters_for_relay
                            .connect_idle_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                        counters_for_relay
                            .http2_connect_idle_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    warn!(protocol = "http2", event = "https_connect_upgrade_failed")
                }
            }
            let _ = routed.wait_closed().await;
            counters_for_relay
                .completed_requests
                .fetch_add(1, Ordering::Relaxed);
        });
        if relay_tx.try_send(relay).is_err() {
            counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
            counters
                .rejected_connect_sessions
                .fetch_add(1, Ordering::Relaxed);
            counters
                .rejected_http2_connect_sessions
                .fetch_add(1, Ordering::Relaxed);
            return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE));
        }
        counters
            .accepted_connect_sessions
            .fetch_add(1, Ordering::Relaxed);
        counters
            .accepted_http2_connect_sessions
            .fetch_add(1, Ordering::Relaxed);
        info!(%peer, %hostname, protocol = "http2", event = "https_connect_established");
        let body = Full::new(Bytes::new())
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        let mut response = Response::new(body);
        *response.status_mut() = StatusCode::OK;
        response.extensions_mut().insert(ConnectResponse);
        return Ok(response);
    }
    let body = if is_http2_websocket(&kind) {
        Full::new(Bytes::new())
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync()
    } else {
        Limited::new(incoming_body, config.max_request_body_bytes).boxed_unsync()
    };
    let request = Request::from_parts(parts, body);
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
    match kind {
        PreparedRequestKind::ReachabilityProbe(_) => {
            unreachable!("reachability probes return before tunnel opening")
        }
        PreparedRequestKind::Regular => {
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
        PreparedRequestKind::WebSocket(handshake) => {
            let http2_websocket = handshake.protocol == NegotiatedHttpProtocol::Http2;
            let driver = AbortOnDropTask::new(tokio::spawn(async move {
                let _ = connection.with_upgrades().await;
            }));
            let mut response = match sender.send_request(request).await {
                Ok(response) => response,
                Err(_) => {
                    counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                    counters
                        .rejected_websocket_upgrades
                        .fetch_add(1, Ordering::Relaxed);
                    if http2_websocket {
                        counters
                            .rejected_http2_websocket_sessions
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    return Ok(error_response(StatusCode::BAD_GATEWAY));
                }
            };
            if response.status() != StatusCode::SWITCHING_PROTOCOLS {
                counters
                    .rejected_websocket_upgrades
                    .fetch_add(1, Ordering::Relaxed);
                if http2_websocket {
                    counters
                        .rejected_http2_websocket_sessions
                        .fetch_add(1, Ordering::Relaxed);
                }
                tokio::spawn(async move {
                    driver.join().await;
                    let _ = routed.wait_closed().await;
                });
                return Ok(sanitize_response(response, deadline, counters));
            }
            let local_upgrade = hyper::upgrade::on(&mut response);
            let response = match sanitize_websocket_response(response, &handshake) {
                Ok(response) => response,
                Err(reason) => {
                    counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                    counters
                        .rejected_websocket_upgrades
                        .fetch_add(1, Ordering::Relaxed);
                    if http2_websocket {
                        counters
                            .rejected_http2_websocket_sessions
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    warn!(%peer, reason, event = "https_websocket_response_rejected");
                    return Ok(error_response(StatusCode::BAD_GATEWAY));
                }
            };
            let relay_tx = opaque_relay_tx.expect("HTTP/1.1 WebSocket requests have a relay owner");
            let idle_timeout = config
                .websocket
                .expect("validated WebSocket config exists")
                .idle_timeout;
            let upgrade_timeout = config.request_timeout;
            let counters_for_relay = Arc::clone(&counters);
            let relay: OpaqueRelay = Box::pin(async move {
                let _session = websocket_guard.expect("WebSocket admission owns a guard");
                let upgraded = tokio::time::timeout(upgrade_timeout, async {
                    let (client, local) = tokio::join!(
                        client_upgrade.expect("WebSocket request captured public upgrade"),
                        local_upgrade
                    );
                    match (client, local) {
                        (Ok(client), Ok(local)) => Some((client, local)),
                        _ => None,
                    }
                })
                .await
                .ok()
                .flatten();
                if let Some((client, local)) = upgraded {
                    if relay_upgraded_io(TokioIo::new(client), TokioIo::new(local), idle_timeout)
                        .await
                        == OpaqueRelayOutcome::IdleTimeout
                    {
                        counters_for_relay
                            .websocket_idle_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                        if http2_websocket {
                            counters_for_relay
                                .http2_websocket_idle_timeouts
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    warn!(event = "https_websocket_upgrade_failed");
                }
                driver.join().await;
                let _ = routed.wait_closed().await;
                counters_for_relay
                    .completed_requests
                    .fetch_add(1, Ordering::Relaxed);
            });
            if relay_tx.try_send(relay).is_err() {
                counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                counters
                    .rejected_websocket_upgrades
                    .fetch_add(1, Ordering::Relaxed);
                if http2_websocket {
                    counters
                        .rejected_http2_websocket_sessions
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE));
            }
            counters
                .accepted_websocket_upgrades
                .fetch_add(1, Ordering::Relaxed);
            if http2_websocket {
                counters
                    .accepted_http2_websocket_sessions
                    .fetch_add(1, Ordering::Relaxed);
            }
            info!(%peer, %hostname, protocol = if http2_websocket { "http2" } else { "http1" }, event = "https_websocket_upgraded");
            Ok(response)
        }
        PreparedRequestKind::Connect(_) => {
            unreachable!("CONNECT returns before the local HTTP handshake")
        }
    }
}

struct WebSocketSessionGuard {
    counters: Arc<HttpIngressCounters>,
    _permit: OwnedSemaphorePermit,
    protocol: NegotiatedHttpProtocol,
}

impl WebSocketSessionGuard {
    fn new(
        counters: Arc<HttpIngressCounters>,
        permit: OwnedSemaphorePermit,
        protocol: NegotiatedHttpProtocol,
    ) -> Self {
        let active = counters
            .active_websocket_sessions
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        counters
            .peak_active_websocket_sessions
            .fetch_max(active, Ordering::Relaxed);
        if protocol == NegotiatedHttpProtocol::Http2 {
            let active = counters
                .active_http2_websocket_sessions
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            counters
                .peak_active_http2_websocket_sessions
                .fetch_max(active, Ordering::Relaxed);
        }
        Self {
            counters,
            _permit: permit,
            protocol,
        }
    }
}

impl Drop for WebSocketSessionGuard {
    fn drop(&mut self) {
        self.counters
            .active_websocket_sessions
            .fetch_sub(1, Ordering::Relaxed);
        if self.protocol == NegotiatedHttpProtocol::Http2 {
            self.counters
                .active_http2_websocket_sessions
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct ConnectSessionGuard {
    counters: Arc<HttpIngressCounters>,
    _permit: OwnedSemaphorePermit,
    protocol: NegotiatedHttpProtocol,
}

impl ConnectSessionGuard {
    fn new(
        counters: Arc<HttpIngressCounters>,
        permit: OwnedSemaphorePermit,
        protocol: NegotiatedHttpProtocol,
    ) -> Self {
        let active = counters
            .active_connect_sessions
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        counters
            .peak_active_connect_sessions
            .fetch_max(active, Ordering::Relaxed);
        if protocol == NegotiatedHttpProtocol::Http2 {
            let active = counters
                .active_http2_connect_sessions
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            counters
                .peak_active_http2_connect_sessions
                .fetch_max(active, Ordering::Relaxed);
        }
        Self {
            counters,
            _permit: permit,
            protocol,
        }
    }
}

impl Drop for ConnectSessionGuard {
    fn drop(&mut self) {
        self.counters
            .active_connect_sessions
            .fetch_sub(1, Ordering::Relaxed);
        if self.protocol == NegotiatedHttpProtocol::Http2 {
            self.counters
                .active_http2_connect_sessions
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct AbortOnDropTask {
    handle: Option<JoinHandle<()>>,
}

impl AbortOnDropTask {
    fn new(handle: JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    async fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for AbortOnDropTask {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

fn sanitize_websocket_response(
    response: Response<Incoming>,
    handshake: &WebSocketHandshake,
) -> Result<Response<ProxyBody>, &'static str> {
    if response.version() != Version::HTTP_11 {
        return Err("invalid_websocket_http_version");
    }
    let headers = response.headers();
    if !header_has_token(headers, CONNECTION, "upgrade") {
        return Err("missing_connection_upgrade");
    }
    let upgrade = exact_header(headers, UPGRADE).ok_or("invalid_upgrade_header")?;
    if upgrade
        .to_str()
        .ok()
        .map_or(true, |value| !value.eq_ignore_ascii_case("websocket"))
    {
        return Err("invalid_upgrade_header");
    }
    let accept_name = HeaderName::from_static("sec-websocket-accept");
    if exact_header(headers, accept_name.clone()) != Some(&handshake.expected_accept) {
        return Err("invalid_websocket_accept");
    }
    if headers.contains_key("sec-websocket-extensions") {
        return Err("websocket_extensions_not_supported");
    }
    let protocol_name = HeaderName::from_static("sec-websocket-protocol");
    let selected_protocol = match exact_header(headers, protocol_name.clone()) {
        Some(value) => {
            let value = value.to_str().map_err(|_| "invalid_websocket_protocol")?;
            if !is_http_token(value)
                || !handshake
                    .offered_protocols
                    .iter()
                    .any(|offered| offered == value)
            {
                return Err("invalid_websocket_protocol");
            }
            Some(HeaderValue::from_str(value).map_err(|_| "invalid_websocket_protocol")?)
        }
        None if headers.contains_key(&protocol_name) => return Err("invalid_websocket_protocol"),
        None => None,
    };
    let (mut parts, _body) = response.into_parts();
    remove_hop_by_hop(&mut parts.headers);
    for name in [
        "sec-websocket-accept",
        "sec-websocket-key",
        "sec-websocket-protocol",
        "sec-websocket-version",
        "sec-websocket-extensions",
    ] {
        parts.headers.remove(name);
    }
    parts.headers.remove(CONTENT_LENGTH);
    match handshake.protocol {
        NegotiatedHttpProtocol::Http1 => {
            parts.status = StatusCode::SWITCHING_PROTOCOLS;
            parts.version = Version::HTTP_11;
            parts
                .headers
                .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
            parts
                .headers
                .insert(UPGRADE, HeaderValue::from_static("websocket"));
            parts
                .headers
                .insert(accept_name, handshake.expected_accept.clone());
        }
        NegotiatedHttpProtocol::Http2 => {
            parts.status = StatusCode::OK;
            parts.version = Version::HTTP_2;
        }
    }
    if let Some(protocol) = selected_protocol {
        parts.headers.insert(protocol_name, protocol);
    }
    let body = Full::new(Bytes::new())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    Ok(Response::from_parts(parts, body))
}

fn exact_header(headers: &hyper::HeaderMap, name: HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        None
    } else {
        value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpaqueRelayOutcome {
    Completed,
    IdleTimeout,
    IoError,
}

async fn relay_upgraded_io<C, L>(client: C, local: L, idle_timeout: Duration) -> OpaqueRelayOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let mut client_open = true;
    let mut local_open = true;
    let mut client_buffer = [0u8; UPGRADED_BUFFER_BYTES];
    let mut local_buffer = [0u8; UPGRADED_BUFFER_BYTES];
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    while client_open || local_open {
        tokio::select! {
            read = client_read.read(&mut client_buffer), if client_open => {
                match read {
                    Ok(0) => {
                        client_open = false;
                        if tokio::time::timeout(idle_timeout, local_write.shutdown()).await.is_err() {
                            return OpaqueRelayOutcome::IdleTimeout;
                        }
                    }
                    Ok(read) => {
                        match tokio::time::timeout(
                            idle_timeout,
                            local_write.write_all(&client_buffer[..read]),
                        ).await {
                            Ok(Ok(())) => idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout),
                            Ok(Err(_)) => return OpaqueRelayOutcome::IoError,
                            Err(_) => return OpaqueRelayOutcome::IdleTimeout,
                        }
                    }
                    Err(_) => return OpaqueRelayOutcome::IoError,
                }
            }
            read = local_read.read(&mut local_buffer), if local_open => {
                match read {
                    Ok(0) => {
                        local_open = false;
                        if tokio::time::timeout(idle_timeout, client_write.shutdown()).await.is_err() {
                            return OpaqueRelayOutcome::IdleTimeout;
                        }
                    }
                    Ok(read) => {
                        match tokio::time::timeout(
                            idle_timeout,
                            client_write.write_all(&local_buffer[..read]),
                        ).await {
                            Ok(Ok(())) => idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout),
                            Ok(Err(_)) => return OpaqueRelayOutcome::IoError,
                            Err(_) => return OpaqueRelayOutcome::IdleTimeout,
                        }
                    }
                    Err(_) => return OpaqueRelayOutcome::IoError,
                }
            }
            () = &mut idle => return OpaqueRelayOutcome::IdleTimeout,
        }
    }
    OpaqueRelayOutcome::Completed
}

#[derive(Debug)]
struct RequestRejection {
    status: StatusCode,
    reason: &'static str,
}

enum PreparedRequestKind {
    Regular,
    ReachabilityProbe(String),
    WebSocket(WebSocketHandshake),
    Connect(NegotiatedHttpProtocol),
}

fn websocket_protocol(kind: &PreparedRequestKind) -> NegotiatedHttpProtocol {
    match kind {
        PreparedRequestKind::WebSocket(handshake) => handshake.protocol,
        _ => unreachable!("only WebSocket requests have a WebSocket protocol"),
    }
}

fn is_http2_websocket(kind: &PreparedRequestKind) -> bool {
    matches!(
        kind,
        PreparedRequestKind::WebSocket(WebSocketHandshake {
            protocol: NegotiatedHttpProtocol::Http2,
            ..
        })
    )
}

struct WebSocketHandshake {
    protocol: NegotiatedHttpProtocol,
    key: HeaderValue,
    expected_accept: HeaderValue,
    offered_protocols: Vec<String>,
}

struct PreparedRequest {
    hostname: HttpHostname,
    tunnel_id: TunnelId,
    kind: PreparedRequestKind,
}

fn prepare_request(
    request: &mut Request<Incoming>,
    server_name: Option<&HttpHostname>,
    config: &HttpIngressConfig,
) -> Result<PreparedRequest, RequestRejection> {
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
    let kind = if request.uri().path() == PUBLIC_REACHABILITY_PATH {
        PreparedRequestKind::ReachabilityProbe(validate_reachability_probe(request)?)
    } else if request.method() == Method::CONNECT
        && request.version() == Version::HTTP_2
        && request.extensions().get::<hyper::ext::Protocol>().is_some()
    {
        PreparedRequestKind::WebSocket(validate_http2_websocket_handshake(request, config)?)
    } else if request.method() == Method::CONNECT {
        PreparedRequestKind::Connect(validate_connect_request(request, config)?)
    } else if has_websocket_intent(request.headers()) {
        PreparedRequestKind::WebSocket(validate_websocket_handshake(request, config)?)
    } else {
        PreparedRequestKind::Regular
    };
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
    if matches!(&kind, PreparedRequestKind::Connect(_)) {
        let connect = config.connect.expect("CONNECT was validated as enabled");
        let uri_authority = request.uri().authority().ok_or(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "missing_connect_authority",
        })?;
        if request.uri().scheme().is_some()
            || request.uri().path_and_query().is_some()
            || uri_authority.port_u16() != Some(connect.authority_port)
        {
            return Err(RequestRejection {
                status: StatusCode::BAD_REQUEST,
                reason: "invalid_connect_authority",
            });
        }
        if let Some(host) = host {
            let host_authority = host
                .to_str()
                .ok()
                .and_then(|value| value.parse::<Authority>().ok())
                .ok_or(RequestRejection {
                    status: StatusCode::BAD_REQUEST,
                    reason: "invalid_connect_host",
                })?;
            if host_authority.port_u16() != Some(connect.authority_port) {
                return Err(RequestRejection {
                    status: StatusCode::MISDIRECTED_REQUEST,
                    reason: "connect_host_port_mismatch",
                });
            }
        }
    }
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
    Ok(PreparedRequest {
        hostname,
        tunnel_id,
        kind,
    })
}

fn validate_reachability_probe<B>(request: &Request<B>) -> Result<String, RequestRejection> {
    if request.method() != Method::GET
        || request.uri().query().is_some()
        || request.headers().contains_key(TRANSFER_ENCODING)
    {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_reachability_probe",
        });
    }
    if let Some(length) = request.headers().get(CONTENT_LENGTH) {
        if length.as_bytes() != b"0" {
            return Err(RequestRejection {
                status: StatusCode::BAD_REQUEST,
                reason: "reachability_probe_body",
            });
        }
    }
    let mut values = request
        .headers()
        .get_all(PUBLIC_REACHABILITY_CHALLENGE_HEADER)
        .iter();
    let value = values.next().ok_or(RequestRejection {
        status: StatusCode::BAD_REQUEST,
        reason: "missing_reachability_challenge",
    })?;
    if values.next().is_some() {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "duplicate_reachability_challenge",
        });
    }
    let challenge = value
        .to_str()
        .ok()
        .and_then(|value| PublicReachabilityChallenge::parse(value).ok())
        .ok_or(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_reachability_challenge",
        })?;
    Ok(challenge.proof())
}

fn authorize_signed_access<B>(
    request: &mut Request<B>,
    hostname: &HttpHostname,
    config: &SignedAccessIngressConfig,
) -> Result<(), RequestRejection> {
    let query = request.uri().query().ok_or(RequestRejection {
        status: StatusCode::UNAUTHORIZED,
        reason: "signed_access_missing",
    })?;
    let mut token = None;
    let mut retained = Vec::new();
    for parameter in query.split('&') {
        let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if name == SIGNED_ACCESS_QUERY_PARAMETER {
            if value.is_empty() || token.replace(value).is_some() {
                return Err(RequestRejection {
                    status: StatusCode::UNAUTHORIZED,
                    reason: "signed_access_malformed",
                });
            }
        } else {
            retained.push(parameter);
        }
    }
    let token = token.ok_or(RequestRejection {
        status: StatusCode::UNAUTHORIZED,
        reason: "signed_access_missing",
    })?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RequestRejection {
            status: StatusCode::UNAUTHORIZED,
            reason: "signed_access_clock",
        })?
        .as_secs();
    config
        .key_ring
        .verify(
            token,
            hostname,
            now_unix,
            config.maximum_ttl.as_secs(),
            config.clock_skew.as_secs(),
        )
        .map_err(|error| RequestRejection {
            status: StatusCode::UNAUTHORIZED,
            reason: signed_access_rejection_reason(error),
        })?;

    let mut path_and_query = request.uri().path().to_owned();
    if !retained.is_empty() {
        path_and_query.push('?');
        path_and_query.push_str(&retained.join("&"));
    }
    let mut parts = request.uri().clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().map_err(|_| RequestRejection {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid_request_target",
    })?);
    *request.uri_mut() = Uri::from_parts(parts).map_err(|_| RequestRejection {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid_request_target",
    })?;
    Ok(())
}

fn signed_access_rejection_reason(error: SignedAccessError) -> &'static str {
    match error {
        SignedAccessError::Expired
        | SignedAccessError::NotYetValid
        | SignedAccessError::LifetimeTooLong
        | SignedAccessError::InvalidLifetime => "signed_access_expired",
        SignedAccessError::MalformedToken => "signed_access_malformed",
        _ => "signed_access_invalid",
    }
}

fn finalize_request(
    request: &mut Request<Incoming>,
    peer: SocketAddr,
    hostname: &HttpHostname,
    kind: &PreparedRequestKind,
) -> Result<(), RequestRejection> {
    if matches!(kind, PreparedRequestKind::Connect(_)) {
        return Ok(());
    }
    sanitize_request_headers(request, peer.ip(), hostname, kind)?;
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
    Ok(())
}

fn record_protocol_rejection(counters: &HttpIngressCounters, kind: &PreparedRequestKind) {
    if matches!(kind, PreparedRequestKind::WebSocket(_)) {
        counters
            .rejected_websocket_upgrades
            .fetch_add(1, Ordering::Relaxed);
        if is_http2_websocket(kind) {
            counters
                .rejected_http2_websocket_sessions
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    if matches!(kind, PreparedRequestKind::Connect(_)) {
        counters
            .rejected_connect_sessions
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn validate_connect_request(
    request: &Request<Incoming>,
    config: &HttpIngressConfig,
) -> Result<NegotiatedHttpProtocol, RequestRejection> {
    let Some(connect) = config.connect else {
        return Err(RequestRejection {
            status: StatusCode::NOT_IMPLEMENTED,
            reason: "connect_not_enabled_for_protocol",
        });
    };
    match request.version() {
        Version::HTTP_11 if connect.enable_http1 => {
            if has_websocket_intent(request.headers()) {
                return Err(RequestRejection {
                    status: StatusCode::BAD_REQUEST,
                    reason: "connect_upgrade_headers_not_allowed",
                });
            }
            let mut content_lengths = request.headers().get_all(CONTENT_LENGTH).iter();
            let content_length = content_lengths.next();
            if content_lengths.next().is_some()
                || request.headers().contains_key(TRANSFER_ENCODING)
                || content_length.is_some_and(|value| value.as_bytes() != b"0")
                || request
                    .body()
                    .size_hint()
                    .upper()
                    .is_some_and(|size| size != 0)
            {
                return Err(RequestRejection {
                    status: StatusCode::BAD_REQUEST,
                    reason: "connect_request_body_not_allowed",
                });
            }
            Ok(NegotiatedHttpProtocol::Http1)
        }
        Version::HTTP_2 if connect.enable_http2 => {
            if request.extensions().get::<hyper::ext::Protocol>().is_some() {
                return Err(RequestRejection {
                    status: StatusCode::NOT_IMPLEMENTED,
                    reason: "extended_connect_not_supported",
                });
            }
            let mut content_lengths = request.headers().get_all(CONTENT_LENGTH).iter();
            let content_length = content_lengths.next();
            if content_lengths.next().is_some()
                || content_length.is_some_and(|value| value.as_bytes() != b"0")
                || request.headers().contains_key(TRANSFER_ENCODING)
                || has_websocket_intent(request.headers())
            {
                return Err(RequestRejection {
                    status: StatusCode::BAD_REQUEST,
                    reason: "invalid_http2_connect_headers",
                });
            }
            Ok(NegotiatedHttpProtocol::Http2)
        }
        Version::HTTP_11 | Version::HTTP_2 => Err(RequestRejection {
            status: StatusCode::NOT_IMPLEMENTED,
            reason: "connect_not_enabled_for_protocol",
        }),
        _ => Err(RequestRejection {
            status: StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            reason: "connect_protocol_not_supported",
        }),
    }
}

fn has_websocket_intent(headers: &hyper::HeaderMap) -> bool {
    headers.contains_key(UPGRADE)
        || header_has_token(headers, CONNECTION, "upgrade")
        || [
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-protocol",
            "sec-websocket-extensions",
        ]
        .iter()
        .any(|name| headers.contains_key(*name))
}

fn validate_websocket_handshake(
    request: &Request<Incoming>,
    config: &HttpIngressConfig,
) -> Result<WebSocketHandshake, RequestRejection> {
    if !config
        .websocket
        .is_some_and(|websocket| websocket.enable_http1)
        || request.version() != Version::HTTP_11
    {
        return Err(RequestRejection {
            status: StatusCode::NOT_IMPLEMENTED,
            reason: "websocket_not_enabled_for_protocol",
        });
    }
    if request.method() != Method::GET {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_websocket_method",
        });
    }
    if !header_has_token(request.headers(), CONNECTION, "upgrade")
        || single_header_str(request.headers(), UPGRADE)?
            .map_or(true, |value| !value.eq_ignore_ascii_case("websocket"))
    {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_websocket_upgrade",
        });
    }
    if single_header_str(
        request.headers(),
        HeaderName::from_static("sec-websocket-version"),
    )? != Some("13")
    {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_websocket_version",
        });
    }
    let key_name = HeaderName::from_static("sec-websocket-key");
    let key =
        single_header_value(request.headers(), key_name.clone())?.ok_or(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "missing_websocket_key",
        })?;
    let key_text = key.to_str().map_err(|_| RequestRejection {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid_websocket_key",
    })?;
    let decoded = BASE64_STANDARD
        .decode(key_text)
        .map_err(|_| RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_websocket_key",
        })?;
    if decoded.len() != 16 || BASE64_STANDARD.encode(&decoded) != key_text {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_websocket_key",
        });
    }
    if request.headers().contains_key("sec-websocket-extensions") {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "websocket_extensions_not_supported",
        });
    }
    if request.headers().contains_key(TRANSFER_ENCODING)
        || single_header_str(request.headers(), CONTENT_LENGTH)?.is_some_and(|value| value != "0")
        || request
            .body()
            .size_hint()
            .upper()
            .is_some_and(|size| size != 0)
    {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "websocket_request_body_not_allowed",
        });
    }
    let offered_protocols = parse_websocket_protocols(request.headers())?;
    let mut digest = Sha1::new();
    digest.update(key_text.as_bytes());
    digest.update(WEBSOCKET_GUID);
    let expected_accept = HeaderValue::from_str(&BASE64_STANDARD.encode(digest.finalize()))
        .expect("WebSocket accept is ASCII");
    Ok(WebSocketHandshake {
        protocol: NegotiatedHttpProtocol::Http1,
        key,
        expected_accept,
        offered_protocols,
    })
}

fn validate_http2_websocket_handshake(
    request: &Request<Incoming>,
    config: &HttpIngressConfig,
) -> Result<WebSocketHandshake, RequestRejection> {
    if !config
        .websocket
        .is_some_and(|websocket| websocket.enable_http2)
    {
        return Err(RequestRejection {
            status: StatusCode::NOT_IMPLEMENTED,
            reason: "websocket_not_enabled_for_protocol",
        });
    }
    let protocol = request
        .extensions()
        .get::<hyper::ext::Protocol>()
        .ok_or(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "missing_extended_connect_protocol",
        })?;
    if !protocol.as_str().eq_ignore_ascii_case("websocket") {
        return Err(RequestRejection {
            status: StatusCode::NOT_IMPLEMENTED,
            reason: "extended_connect_protocol_not_supported",
        });
    }
    if request.uri().scheme_str() != Some("https")
        || request.uri().authority().is_none()
        || request.uri().path_and_query().is_none()
        || !request.uri().path().starts_with('/')
    {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_http2_websocket_target",
        });
    }
    if request.headers().contains_key(CONNECTION)
        || request.headers().contains_key(UPGRADE)
        || request.headers().contains_key("sec-websocket-key")
        || request.headers().contains_key("sec-websocket-accept")
        || request.headers().contains_key("sec-websocket-extensions")
        || request.headers().contains_key(CONTENT_LENGTH)
        || request.headers().contains_key(TE)
        || request.headers().contains_key(TRAILER)
        || request.headers().contains_key(TRANSFER_ENCODING)
    {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_http2_websocket_headers",
        });
    }
    if single_header_str(
        request.headers(),
        HeaderName::from_static("sec-websocket-version"),
    )? != Some("13")
    {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_websocket_version",
        });
    }
    let offered_protocols = parse_websocket_protocols(request.headers())?;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| RequestRejection {
        status: StatusCode::SERVICE_UNAVAILABLE,
        reason: "websocket_entropy_unavailable",
    })?;
    let key_text = BASE64_STANDARD.encode(nonce);
    let key = HeaderValue::from_str(&key_text).expect("base64 WebSocket key is ASCII");
    let mut digest = Sha1::new();
    digest.update(key_text.as_bytes());
    digest.update(WEBSOCKET_GUID);
    let expected_accept = HeaderValue::from_str(&BASE64_STANDARD.encode(digest.finalize()))
        .expect("WebSocket accept is ASCII");
    Ok(WebSocketHandshake {
        protocol: NegotiatedHttpProtocol::Http2,
        key,
        expected_accept,
        offered_protocols,
    })
}

fn single_header_value(
    headers: &hyper::HeaderMap,
    name: HeaderName,
) -> Result<Option<HeaderValue>, RequestRejection> {
    let mut values = headers.get_all(&name).iter();
    let value = values.next().cloned();
    if values.next().is_some() {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "duplicate_websocket_header",
        });
    }
    Ok(value)
}

fn single_header_str(
    headers: &hyper::HeaderMap,
    name: HeaderName,
) -> Result<Option<&str>, RequestRejection> {
    let mut values = headers.get_all(&name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "duplicate_websocket_header",
        });
    }
    value
        .map(|value| {
            value.to_str().map_err(|_| RequestRejection {
                status: StatusCode::BAD_REQUEST,
                reason: "invalid_websocket_header",
            })
        })
        .transpose()
}

fn parse_websocket_protocols(headers: &hyper::HeaderMap) -> Result<Vec<String>, RequestRejection> {
    let mut protocols = Vec::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value.to_str().map_err(|_| RequestRejection {
            status: StatusCode::BAD_REQUEST,
            reason: "invalid_websocket_protocol",
        })?;
        for protocol in value.split(',').map(str::trim) {
            if !is_http_token(protocol) || protocols.iter().any(|item| item == protocol) {
                return Err(RequestRejection {
                    status: StatusCode::BAD_REQUEST,
                    reason: "invalid_websocket_protocol",
                });
            }
            protocols.push(protocol.to_owned());
        }
    }
    Ok(protocols)
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn header_has_token(headers: &hyper::HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn sanitize_request_headers(
    request: &mut Request<Incoming>,
    peer_ip: IpAddr,
    hostname: &HttpHostname,
    kind: &PreparedRequestKind,
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
    for name in [
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
    ] {
        request.headers_mut().remove(name);
    }
    match kind {
        PreparedRequestKind::ReachabilityProbe(_) => {}
        PreparedRequestKind::Regular => {
            request
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
        PreparedRequestKind::WebSocket(handshake) => {
            *request.method_mut() = Method::GET;
            request
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
            request
                .headers_mut()
                .insert(UPGRADE, HeaderValue::from_static("websocket"));
            request.headers_mut().insert(
                HeaderName::from_static("sec-websocket-version"),
                HeaderValue::from_static("13"),
            );
            request.headers_mut().insert(
                HeaderName::from_static("sec-websocket-key"),
                handshake.key.clone(),
            );
            if !handshake.offered_protocols.is_empty() {
                let protocols = HeaderValue::from_str(&handshake.offered_protocols.join(", "))
                    .map_err(|_| RequestRejection {
                        status: StatusCode::BAD_REQUEST,
                        reason: "invalid_websocket_protocol",
                    })?;
                request
                    .headers_mut()
                    .insert(HeaderName::from_static("sec-websocket-protocol"), protocols);
            }
        }
        PreparedRequestKind::Connect(_) => {}
    }
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

fn unauthorized_response() -> Response<ProxyBody> {
    no_store_error_response(StatusCode::UNAUTHORIZED)
}

fn no_store_error_response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = error_response(status);
    response.headers_mut().insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    response
}

fn reachability_probe_response(proof: &str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::new())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(CONNECTION, "close")
        .header(CONTENT_LENGTH, "0")
        .header("cache-control", "no-store")
        .header(PUBLIC_REACHABILITY_PROOF_HEADER, proof)
        .body(body)
        .expect("validated reachability proof is a valid response header")
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
    fn reachability_probe_is_strict_bounded_and_produces_no_store_proof() {
        let challenge = PublicReachabilityChallenge::generate().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(PUBLIC_REACHABILITY_PATH)
            .header(PUBLIC_REACHABILITY_CHALLENGE_HEADER, challenge.encoded())
            .body(())
            .unwrap();
        let proof = validate_reachability_probe(&request).unwrap();
        assert_eq!(proof, challenge.proof());
        let response = reachability_probe_response(&proof);
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["cache-control"], "no-store");

        let missing = Request::builder()
            .method(Method::GET)
            .uri(PUBLIC_REACHABILITY_PATH)
            .body(())
            .unwrap();
        assert_eq!(
            validate_reachability_probe(&missing).unwrap_err().reason,
            "missing_reachability_challenge"
        );
    }

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
            signed_access_key_ring: None,
        };
        counters.accepted_connections.store(3, Ordering::Relaxed);
        counters.admitted_requests.store(2, Ordering::Relaxed);
        counters.reused_requests.store(1, Ordering::Relaxed);
        counters.request_timeouts.store(4, Ordering::Relaxed);
        counters.http1_connections.store(5, Ordering::Relaxed);
        counters.http2_connections.store(6, Ordering::Relaxed);
        counters
            .accepted_websocket_upgrades
            .store(7, Ordering::Relaxed);
        counters
            .rejected_websocket_upgrades
            .store(8, Ordering::Relaxed);
        counters.websocket_idle_timeouts.store(9, Ordering::Relaxed);
        counters
            .accepted_http2_websocket_sessions
            .store(16, Ordering::Relaxed);
        counters
            .rejected_http2_websocket_sessions
            .store(17, Ordering::Relaxed);
        counters
            .http2_websocket_idle_timeouts
            .store(18, Ordering::Relaxed);
        counters
            .accepted_connect_sessions
            .store(10, Ordering::Relaxed);
        counters
            .rejected_connect_sessions
            .store(11, Ordering::Relaxed);
        counters.connect_idle_timeouts.store(12, Ordering::Relaxed);
        counters
            .accepted_http2_connect_sessions
            .store(13, Ordering::Relaxed);
        counters
            .rejected_http2_connect_sessions
            .store(14, Ordering::Relaxed);
        counters
            .http2_connect_idle_timeouts
            .store(15, Ordering::Relaxed);
        rate_limiter
            .try_admit(IpAddr::from([127, 0, 0, 1]))
            .unwrap();
        let active = ActiveConnectionGuard::new(Arc::clone(&counters));
        let active_http2 = ActiveHttp2StreamGuard::new(Arc::clone(&counters));
        let websocket_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let active_websocket = WebSocketSessionGuard::new(
            Arc::clone(&counters),
            websocket_permit,
            NegotiatedHttpProtocol::Http2,
        );
        let connect_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let active_connect = ConnectSessionGuard::new(
            Arc::clone(&counters),
            connect_permit,
            NegotiatedHttpProtocol::Http2,
        );
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
        assert_eq!(snapshot.accepted_websocket_upgrades, 7);
        assert_eq!(snapshot.rejected_websocket_upgrades, 8);
        assert_eq!(snapshot.active_websocket_sessions, 1);
        assert_eq!(snapshot.peak_active_websocket_sessions, 1);
        assert_eq!(snapshot.websocket_idle_timeouts, 9);
        assert_eq!(snapshot.accepted_http2_websocket_sessions, 16);
        assert_eq!(snapshot.rejected_http2_websocket_sessions, 17);
        assert_eq!(snapshot.active_http2_websocket_sessions, 1);
        assert_eq!(snapshot.peak_active_http2_websocket_sessions, 1);
        assert_eq!(snapshot.http2_websocket_idle_timeouts, 18);
        assert_eq!(snapshot.accepted_connect_sessions, 10);
        assert_eq!(snapshot.rejected_connect_sessions, 11);
        assert_eq!(snapshot.active_connect_sessions, 1);
        assert_eq!(snapshot.peak_active_connect_sessions, 1);
        assert_eq!(snapshot.connect_idle_timeouts, 12);
        assert_eq!(snapshot.accepted_http2_connect_sessions, 13);
        assert_eq!(snapshot.rejected_http2_connect_sessions, 14);
        assert_eq!(snapshot.active_http2_connect_sessions, 1);
        assert_eq!(snapshot.peak_active_http2_connect_sessions, 1);
        assert_eq!(snapshot.http2_connect_idle_timeouts, 15);
        assert_eq!(snapshot.tracked_rate_limit_peers, 1);
        assert_eq!(snapshot.peak_tracked_rate_limit_peers, 1);
        drop(active);
        drop(active_http2);
        drop(active_websocket);
        drop(active_connect);
        assert_eq!(status.snapshot().active_connections, 0);
        assert_eq!(status.snapshot().active_http2_streams, 0);
        assert_eq!(status.snapshot().active_websocket_sessions, 0);
        assert_eq!(status.snapshot().active_http2_websocket_sessions, 0);
        assert_eq!(status.snapshot().active_connect_sessions, 0);
        assert_eq!(status.snapshot().active_http2_connect_sessions, 0);
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
            websocket: None,
            connect: None,
            signed_access: None,
            request_rate_limit: HttpRequestRateLimitConfig::default(),
            header_read_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
            duplex_capacity: 1,
            shutdown: RuntimeShutdownConfig::new(Duration::from_secs(1)),
        };
        assert!(config.validate().is_ok());
        let cap_signer =
            tunnelproxy_common::SignedAccessSigner::from_private_key(2, [2; 32]).unwrap();
        config.signed_access = Some(SignedAccessIngressConfig {
            key_ring: cap_signer.public_key_ring(),
            maximum_ttl: MAX_SIGNED_ACCESS_TTL + Duration::from_secs(1),
            clock_skew: Duration::ZERO,
        });
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::SignedAccessMaximumTtlTooLarge)
        );
        let policy = config.signed_access.as_mut().unwrap();
        policy.maximum_ttl = Duration::from_secs(60);
        policy.clock_skew = MAX_SIGNED_ACCESS_CLOCK_SKEW + Duration::from_secs(1);
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::SignedAccessClockSkewTooLarge)
        );
        config.signed_access = None;
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
        config.http2.as_mut().unwrap().keep_alive_timeout = Duration::from_secs(1);
        config.websocket = Some(WebSocketIngressConfig {
            enable_http1: true,
            enable_http2: false,
            max_concurrent_sessions: 2,
            idle_timeout: Duration::from_secs(1),
        });
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::WebSocketSessionsExceedConnections)
        );
        config.websocket.as_mut().unwrap().max_concurrent_sessions = 0;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::InvalidWebSocketSessionLimit)
        );
        let websocket = config.websocket.as_mut().unwrap();
        websocket.max_concurrent_sessions = 1;
        websocket.idle_timeout = Duration::ZERO;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::ZeroWebSocketIdleTimeout)
        );
        config.websocket.as_mut().unwrap().idle_timeout = Duration::from_secs(1);
        config.websocket.as_mut().unwrap().enable_http1 = false;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::WebSocketProtocolsDisabled)
        );
        config.websocket.as_mut().unwrap().enable_http2 = true;
        config.http2 = None;
        config.tls = PublicTlsConfig::from_pem(
            pki.cert.pem().as_bytes(),
            pki.key_pair.serialize_pem().as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::Http2WebSocketWithoutHttp2)
        );
        config.http2 = Some(Http2IngressConfig::default());
        config.tls = PublicTlsConfig::from_pem_with_protocols(
            pki.cert.pem().as_bytes(),
            pki.key_pair.serialize_pem().as_bytes(),
            Duration::from_secs(1),
            PublicHttpProtocolPolicy::Http1AndHttp2,
        )
        .unwrap();
        config.websocket.as_mut().unwrap().enable_http1 = true;
        config.websocket.as_mut().unwrap().enable_http2 = false;
        config.connect = Some(ConnectIngressConfig {
            enable_http1: true,
            enable_http2: false,
            max_concurrent_sessions: 2,
            idle_timeout: Duration::from_secs(1),
            authority_port: 443,
        });
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::ConnectSessionsExceedConnections)
        );
        config.connect.as_mut().unwrap().max_concurrent_sessions = 0;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::InvalidConnectSessionLimit)
        );
        let connect = config.connect.as_mut().unwrap();
        connect.max_concurrent_sessions = 1;
        connect.idle_timeout = Duration::ZERO;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::ZeroConnectIdleTimeout)
        );
        let connect = config.connect.as_mut().unwrap();
        connect.idle_timeout = Duration::from_secs(1);
        connect.enable_http1 = false;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::ConnectProtocolsDisabled)
        );
        config.connect.as_mut().unwrap().enable_http2 = true;
        assert!(config.validate().is_ok());
        let signer = tunnelproxy_common::SignedAccessSigner::from_private_key(1, [1; 32]).unwrap();
        config.signed_access = Some(SignedAccessIngressConfig {
            key_ring: signer.public_key_ring(),
            maximum_ttl: Duration::from_secs(60),
            clock_skew: Duration::ZERO,
        });
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::SignedAccessWithConnect)
        );
        config.signed_access = None;
        config.http2 = None;
        config.tls = PublicTlsConfig::from_pem(
            pki.cert.pem().as_bytes(),
            pki.key_pair.serialize_pem().as_bytes(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::Http2ConnectWithoutHttp2)
        );
        config.tls = PublicTlsConfig::from_pem_with_protocols(
            pki.cert.pem().as_bytes(),
            pki.key_pair.serialize_pem().as_bytes(),
            Duration::from_secs(1),
            PublicHttpProtocolPolicy::Http1AndHttp2,
        )
        .unwrap();
        config.http2 = Some(Http2IngressConfig::default());
        let connect = config.connect.as_mut().unwrap();
        connect.authority_port = 0;
        assert_eq!(
            config.validate(),
            Err(HttpIngressConfigError::ZeroConnectAuthorityPort)
        );
    }

    #[tokio::test]
    async fn opaque_relay_is_bidirectional_and_idle_bounded() {
        let (proxy_client, mut public_client) = tokio::io::duplex(64);
        let (proxy_local, mut local_service) = tokio::io::duplex(64);
        let relay = tokio::spawn(relay_upgraded_io(
            proxy_client,
            proxy_local,
            Duration::from_secs(1),
        ));
        public_client.write_all(b"from-client").await.unwrap();
        let mut from_client = [0u8; 11];
        local_service.read_exact(&mut from_client).await.unwrap();
        assert_eq!(&from_client, b"from-client");
        local_service.write_all(b"from-local").await.unwrap();
        let mut from_local = [0u8; 10];
        public_client.read_exact(&mut from_local).await.unwrap();
        assert_eq!(&from_local, b"from-local");
        public_client.shutdown().await.unwrap();
        local_service.shutdown().await.unwrap();
        assert_eq!(relay.await.unwrap(), OpaqueRelayOutcome::Completed);

        let (proxy_client, _public_client) = tokio::io::duplex(1);
        let (proxy_local, _local_service) = tokio::io::duplex(1);
        assert_eq!(
            relay_upgraded_io(proxy_client, proxy_local, Duration::from_millis(10)).await,
            OpaqueRelayOutcome::IdleTimeout
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

    #[test]
    fn signed_access_verification_strips_only_its_query_parameter() {
        let signer = tunnelproxy_common::SignedAccessSigner::from_private_key(9, [17; 32]).unwrap();
        let hostname = HttpHostname::new("demo.example.test").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = signer.sign(&hostname, now - 1, now + 60).unwrap();
        let config = SignedAccessIngressConfig {
            key_ring: signer.public_key_ring(),
            maximum_ttl: Duration::from_secs(120),
            clock_skew: Duration::from_secs(1),
        };
        let mut request = Request::builder()
            .uri(format!("/resource?a=1&tp_access={token}&b=2"))
            .body(())
            .unwrap();

        authorize_signed_access(&mut request, &hostname, &config).unwrap();

        assert_eq!(request.uri().path_and_query().unwrap(), "/resource?a=1&b=2");
        assert!(!request.uri().to_string().contains(&token));
    }

    #[test]
    fn signed_access_fails_closed_for_missing_duplicate_expired_and_wrong_host_tokens() {
        let signer = tunnelproxy_common::SignedAccessSigner::from_private_key(9, [17; 32]).unwrap();
        let hostname = HttpHostname::new("demo.example.test").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid = signer.sign(&hostname, now - 1, now + 60).unwrap();
        let expired = signer.sign(&hostname, now - 120, now - 60).unwrap();
        let config = SignedAccessIngressConfig {
            key_ring: signer.public_key_ring(),
            maximum_ttl: Duration::from_secs(120),
            clock_skew: Duration::ZERO,
        };
        for (uri, reason) in [
            ("/resource".to_owned(), "signed_access_missing"),
            (
                format!("/resource?tp_access={valid}&tp_access={valid}"),
                "signed_access_malformed",
            ),
            (
                format!("/resource?tp_access={expired}"),
                "signed_access_expired",
            ),
        ] {
            let mut request = Request::builder().uri(uri).body(()).unwrap();
            assert_eq!(
                authorize_signed_access(&mut request, &hostname, &config)
                    .unwrap_err()
                    .reason,
                reason
            );
        }
        let mut wrong_host = Request::builder()
            .uri(format!("/resource?tp_access={valid}"))
            .body(())
            .unwrap();
        assert_eq!(
            authorize_signed_access(
                &mut wrong_host,
                &HttpHostname::new("other.example.test").unwrap(),
                &config,
            )
            .unwrap_err()
            .reason,
            "signed_access_invalid"
        );
    }
}
