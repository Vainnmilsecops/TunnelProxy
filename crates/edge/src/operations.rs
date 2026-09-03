//! Bounded loopback-only operational health, readiness, and metrics endpoint.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{info, warn};
use tunnelproxy_common::{
    process_logging_snapshot, MultiplexTelemetrySnapshot, ProcessLoggingSnapshot,
    RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal, TunnelId,
};
use tunnelproxy_control_plane::HttpsRouteSourceHealth;

use crate::http_ingress::{HttpHostRoutes, HttpIngressStatus, HttpIngressStatusHandle};
use crate::multiplex::{AuthorizationSourceStatus, EdgeSessionRouter};
use crate::raw_ingress::{RawIngressRouteId, RawIngressRouteManager, RawIngressRouteStatus};
use crate::request_history::{
    RequestHistory, RequestHistoryEntry, RequestHistoryOutcome, RequestHistorySnapshot,
    MAX_REQUEST_HISTORY_ENTRIES, MAX_REQUEST_HISTORY_RESPONSE_BYTES,
};

pub const MIN_OPERATIONS_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_OPERATIONS_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_OPERATIONS_HEADERS: usize = 128;
pub const MAX_OPERATIONS_CONNECTIONS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeOperationsConfig {
    pub listen_addr: SocketAddr,
    pub max_concurrent_connections: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
    pub shutdown: RuntimeShutdownConfig,
}

impl EdgeOperationsConfig {
    pub fn loopback(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            max_concurrent_connections: 8,
            max_header_bytes: MIN_OPERATIONS_HEADER_BYTES,
            max_headers: 16,
            header_read_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
            shutdown: RuntimeShutdownConfig::default(),
        }
    }

    pub fn validate(self) -> Result<(), EdgeOperationsConfigError> {
        if !self.listen_addr.ip().is_loopback() {
            return Err(EdgeOperationsConfigError::NonLoopbackListener);
        }
        if self.max_concurrent_connections == 0
            || self.max_concurrent_connections > MAX_OPERATIONS_CONNECTIONS
        {
            return Err(EdgeOperationsConfigError::InvalidConnectionLimit);
        }
        if self.max_header_bytes < MIN_OPERATIONS_HEADER_BYTES
            || self.max_header_bytes > MAX_OPERATIONS_HEADER_BYTES
        {
            return Err(EdgeOperationsConfigError::InvalidHeaderBytes);
        }
        if self.max_headers == 0 || self.max_headers > MAX_OPERATIONS_HEADERS {
            return Err(EdgeOperationsConfigError::InvalidHeaderCount);
        }
        if self.header_read_timeout.is_zero() {
            return Err(EdgeOperationsConfigError::ZeroHeaderTimeout);
        }
        if self.request_timeout.is_zero() {
            return Err(EdgeOperationsConfigError::ZeroRequestTimeout);
        }
        if self.shutdown.drain_timeout.is_zero() {
            return Err(EdgeOperationsConfigError::ZeroDrainTimeout);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeOperationsConfigError {
    NonLoopbackListener,
    InvalidConnectionLimit,
    InvalidHeaderBytes,
    InvalidHeaderCount,
    ZeroHeaderTimeout,
    ZeroRequestTimeout,
    ZeroDrainTimeout,
}

impl std::fmt::Display for EdgeOperationsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NonLoopbackListener => "operations listener must use a loopback address",
            Self::InvalidConnectionLimit => {
                "operations connection limit must be between 1 and 1024"
            }
            Self::InvalidHeaderBytes => "operations header bytes must be between 8192 and 65536",
            Self::InvalidHeaderCount => "operations header count must be between 1 and 128",
            Self::ZeroHeaderTimeout => "operations header timeout must be greater than zero",
            Self::ZeroRequestTimeout => "operations request timeout must be greater than zero",
            Self::ZeroDrainTimeout => "operations drain timeout must be greater than zero",
        })
    }
}

impl std::error::Error for EdgeOperationsConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeOperationsOutcome {
    pub local_addr: SocketAddr,
    pub accepted_connections: u64,
    pub completed_requests: u64,
    pub rejected_requests: u64,
    pub capacity_rejections: u64,
    pub shutdown: RuntimeShutdownOutcome,
}

impl EdgeOperationsOutcome {
    pub const fn was_forced(self) -> bool {
        matches!(self.shutdown, RuntimeShutdownOutcome::Forced { .. })
    }
}

#[derive(Debug)]
pub enum EdgeOperationsError {
    InvalidConfig(EdgeOperationsConfigError),
    Bind(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for EdgeOperationsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid operations config: {error}"),
            Self::Bind(error) => write!(f, "operations listener bind failed: {error}"),
            Self::Accept(error) => write!(f, "operations listener accept failed: {error}"),
        }
    }
}

impl std::error::Error for EdgeOperationsError {}

#[derive(Clone)]
pub(crate) enum EdgeIngressMetricsSource {
    Raw {
        manager: RawIngressRouteManager,
        route_id: RawIngressRouteId,
    },
    Https {
        status: HttpIngressStatusHandle,
        routes: HttpHostRoutes,
        request_history: Option<RequestHistory>,
    },
}

#[derive(Clone)]
pub(crate) struct EdgeOperationsControl {
    draining: Arc<AtomicBool>,
}

impl EdgeOperationsControl {
    pub(crate) fn begin_draining(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct EdgeOperationsCounters {
    active_connections: AtomicUsize,
    accepted_connections: AtomicU64,
    completed_requests: AtomicU64,
    rejected_requests: AtomicU64,
    capacity_rejections: AtomicU64,
}

pub(crate) struct EdgeOperationsRuntime {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: EdgeOperationsConfig,
    router: EdgeSessionRouter,
    tunnel_id: TunnelId,
    ingress: EdgeIngressMetricsSource,
    counters: Arc<EdgeOperationsCounters>,
    draining: Arc<AtomicBool>,
}

impl EdgeOperationsRuntime {
    pub(crate) async fn bind(
        config: EdgeOperationsConfig,
        router: EdgeSessionRouter,
        tunnel_id: TunnelId,
        ingress: EdgeIngressMetricsSource,
    ) -> Result<Self, EdgeOperationsError> {
        config
            .validate()
            .map_err(EdgeOperationsError::InvalidConfig)?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(EdgeOperationsError::Bind)?;
        let local_addr = listener.local_addr().map_err(EdgeOperationsError::Bind)?;
        Ok(Self {
            listener,
            local_addr,
            config,
            router,
            tunnel_id,
            ingress,
            counters: Arc::new(EdgeOperationsCounters::default()),
            draining: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn control(&self) -> EdgeOperationsControl {
        EdgeOperationsControl {
            draining: Arc::clone(&self.draining),
        }
    }

    pub(crate) async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<EdgeOperationsOutcome, EdgeOperationsError> {
        let permits = Arc::new(Semaphore::new(self.config.max_concurrent_connections));
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
                            terminal_error = Some(EdgeOperationsError::Accept(error));
                            break;
                        }
                    };
                    let permit = match Arc::clone(&permits).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            self.counters.capacity_rejections.fetch_add(1, Ordering::Relaxed);
                            warn!(%peer, event = "operations_capacity_rejected");
                            drop(socket);
                            continue;
                        }
                    };
                    self.counters.accepted_connections.fetch_add(1, Ordering::Relaxed);
                    let active = ActiveConnectionGuard::new(Arc::clone(&self.counters));
                    connections.spawn(run_connection(
                        socket,
                        peer,
                        self.config,
                        self.router.clone(),
                        self.tunnel_id.clone(),
                        self.ingress.clone(),
                        Arc::clone(&self.counters),
                        Arc::clone(&self.draining),
                        permit,
                        active,
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
        Ok(EdgeOperationsOutcome {
            local_addr: self.local_addr,
            accepted_connections: self.counters.accepted_connections.load(Ordering::Relaxed),
            completed_requests: self.counters.completed_requests.load(Ordering::Relaxed),
            rejected_requests: self.counters.rejected_requests.load(Ordering::Relaxed),
            capacity_rejections: self.counters.capacity_rejections.load(Ordering::Relaxed),
            shutdown,
        })
    }
}

struct ActiveConnectionGuard {
    counters: Arc<EdgeOperationsCounters>,
}

impl ActiveConnectionGuard {
    fn new(counters: Arc<EdgeOperationsCounters>) -> Self {
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
    config: EdgeOperationsConfig,
    router: EdgeSessionRouter,
    tunnel_id: TunnelId,
    ingress: EdgeIngressMetricsSource,
    counters: Arc<EdgeOperationsCounters>,
    draining: Arc<AtomicBool>,
    _permit: OwnedSemaphorePermit,
    _active: ActiveConnectionGuard,
) {
    let service_counters = Arc::clone(&counters);
    let service = hyper::service::service_fn(move |request| {
        serve_request(
            request,
            router.clone(),
            tunnel_id.clone(),
            ingress.clone(),
            Arc::clone(&service_counters),
            Arc::clone(&draining),
        )
    });
    let mut http = hyper::server::conn::http1::Builder::new();
    http.keep_alive(false)
        .half_close(false)
        .max_buf_size(config.max_header_bytes)
        .max_headers(config.max_headers)
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_read_timeout);
    match tokio::time::timeout(
        config.request_timeout,
        http.serve_connection(TokioIo::new(socket), service),
    )
    .await
    {
        Ok(Ok(())) => info!(%peer, event = "operations_connection_completed"),
        Ok(Err(error)) => warn!(%peer, %error, event = "operations_connection_failed"),
        Err(_) => warn!(%peer, event = "operations_request_timeout"),
    }
}

async fn serve_request(
    request: Request<Incoming>,
    router: EdgeSessionRouter,
    tunnel_id: TunnelId,
    ingress: EdgeIngressMetricsSource,
    counters: Arc<EdgeOperationsCounters>,
    draining: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let head = request.method() == Method::HEAD;
    let response = if request.method() != Method::GET && !head {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n", head)
    } else {
        match request.uri().path() {
            "/healthz" => plain_response(StatusCode::OK, "ok\n", head),
            "/readyz" => {
                let ready = ingress_ready(&router, &tunnel_id, &ingress, &draining).await;
                if ready {
                    plain_response(StatusCode::OK, "ready\n", head)
                } else {
                    plain_response(StatusCode::SERVICE_UNAVAILABLE, "not ready\n", head)
                }
            }
            "/metrics" => {
                let snapshot =
                    collect_metrics(&router, &tunnel_id, &ingress, &counters, &draining).await;
                metrics_response(&render_metrics(snapshot), head)
            }
            "/requests" => match &ingress {
                EdgeIngressMetricsSource::Https {
                    request_history: Some(history),
                    ..
                } => match RequestHistoryQuery::parse(request.uri().query()) {
                    Ok(query) => request_history_response(history, query, head),
                    Err(_) => {
                        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                        plain_response(
                            StatusCode::BAD_REQUEST,
                            "invalid request history query\n",
                            head,
                        )
                    }
                },
                EdgeIngressMetricsSource::Raw { .. }
                | EdgeIngressMetricsSource::Https {
                    request_history: None,
                    ..
                } => plain_response(StatusCode::NOT_FOUND, "not found\n", head),
            },
            _ => {
                counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                plain_response(StatusCode::NOT_FOUND, "not found\n", head)
            }
        }
    };
    counters.completed_requests.fetch_add(1, Ordering::Relaxed);
    Ok(response)
}

async fn ingress_ready(
    router: &EdgeSessionRouter,
    tunnel_id: &TunnelId,
    ingress: &EdgeIngressMetricsSource,
    draining: &AtomicBool,
) -> bool {
    if draining.load(Ordering::Relaxed) {
        return false;
    }
    match ingress {
        EdgeIngressMetricsSource::Https { routes, .. } if routes.is_dynamic() => {
            routes.dynamic_source_health() != Some(HttpsRouteSourceHealth::Expired)
        }
        EdgeIngressMetricsSource::Raw { .. } | EdgeIngressMetricsSource::Https { .. } => {
            router.resolve_tunnel(tunnel_id).await.is_some()
        }
    }
}

fn plain_response(status: StatusCode, body: &'static str, head: bool) -> Response<Full<Bytes>> {
    response(
        status,
        "text/plain; charset=utf-8",
        if head { "" } else { body },
    )
}

fn metrics_response(body: &str, head: bool) -> Response<Full<Bytes>> {
    response(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        if head { "" } else { body },
    )
}

fn request_history_response(
    history: &RequestHistory,
    query: RequestHistoryQuery,
    head: bool,
) -> Response<Full<Bytes>> {
    let body = render_request_history(history.snapshot(), query);
    response(
        StatusCode::OK,
        "application/json; charset=utf-8",
        if head { "" } else { &body },
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RequestHistoryQuery {
    before: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InvalidRequestHistoryQuery;

impl RequestHistoryQuery {
    fn parse(query: Option<&str>) -> Result<Self, InvalidRequestHistoryQuery> {
        let Some(query) = query.filter(|query| !query.is_empty()) else {
            return Ok(Self::default());
        };
        let mut parsed = Self::default();
        for parameter in query.split('&') {
            let (name, value) = parameter
                .split_once('=')
                .ok_or(InvalidRequestHistoryQuery)?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(InvalidRequestHistoryQuery);
            }
            match name {
                "before" if parsed.before.is_none() => {
                    let before = value
                        .parse::<u64>()
                        .map_err(|_| InvalidRequestHistoryQuery)?;
                    if before == 0 {
                        return Err(InvalidRequestHistoryQuery);
                    }
                    parsed.before = Some(before);
                }
                "limit" if parsed.limit.is_none() => {
                    let limit = value
                        .parse::<usize>()
                        .map_err(|_| InvalidRequestHistoryQuery)?;
                    if !(1..=MAX_REQUEST_HISTORY_ENTRIES).contains(&limit) {
                        return Err(InvalidRequestHistoryQuery);
                    }
                    parsed.limit = Some(limit);
                }
                _ => return Err(InvalidRequestHistoryQuery),
            }
        }
        Ok(parsed)
    }
}

#[derive(Serialize)]
struct RequestHistoryDocument<'a> {
    version: u8,
    capacity: usize,
    retained: usize,
    eligible: usize,
    returned: usize,
    recorded_total: u64,
    evicted_total: u64,
    sequence_exhaustions: u64,
    truncated: bool,
    has_more: bool,
    next_before: Option<u64>,
    requests: &'a [RequestHistoryEntry],
}

fn render_request_history(snapshot: RequestHistorySnapshot, query: RequestHistoryQuery) -> String {
    let start = query.before.map_or(0, |before| {
        snapshot
            .entries
            .iter()
            .position(|entry| entry.request_id < before)
            .unwrap_or(snapshot.entries.len())
    });
    let eligible = snapshot.entries.len() - start;
    let page_limit = query.limit.unwrap_or(snapshot.capacity).min(eligible);
    let mut lower = 0;
    let mut upper = page_limit;
    while lower < upper {
        let candidate = lower + (upper - lower).div_ceil(2);
        if serialize_request_history(&snapshot, start, eligible, candidate).len()
            <= MAX_REQUEST_HISTORY_RESPONSE_BYTES
        {
            lower = candidate;
        } else {
            upper = candidate - 1;
        }
    }
    let body = serialize_request_history(&snapshot, start, eligible, lower);
    assert!(body.len() <= MAX_REQUEST_HISTORY_RESPONSE_BYTES);
    body
}

fn serialize_request_history(
    snapshot: &RequestHistorySnapshot,
    start: usize,
    eligible: usize,
    returned: usize,
) -> String {
    let has_more = returned < eligible;
    let next_before = if has_more && returned > 0 {
        Some(snapshot.entries[start + returned - 1].request_id)
    } else {
        None
    };
    let document = RequestHistoryDocument {
        version: 1,
        capacity: snapshot.capacity,
        retained: snapshot.entries.len(),
        eligible,
        returned,
        recorded_total: snapshot.recorded_total,
        evicted_total: snapshot.evicted_total,
        sequence_exhaustions: snapshot.sequence_exhaustions,
        truncated: has_more,
        has_more,
        next_before,
        requests: &snapshot.entries[start..start + returned],
    };
    let mut body = serde_json::to_string(&document)
        .expect("bounded request history contains only serializable values");
    body.push('\n');
    body
}

fn response(status: StatusCode, content_type: &'static str, body: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::copy_from_slice(body.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        content_type.parse().expect("static content type"),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        "no-store".parse().expect("static cache policy"),
    );
    response.headers_mut().insert(
        CONNECTION,
        "close".parse().expect("static connection policy"),
    );
    response
}

#[derive(Clone, Copy)]
struct OperationsCounterSnapshot {
    active_connections: usize,
    accepted_connections: u64,
    completed_requests: u64,
    rejected_requests: u64,
    capacity_rejections: u64,
}

#[derive(Clone)]
enum IngressMetricSnapshot {
    Raw(Option<RawIngressRouteStatus>),
    Https {
        status: Box<HttpIngressStatus>,
        route_health: Option<HttpsRouteSourceHealth>,
        route_version: u64,
        route_count: usize,
        request_history: Option<RequestHistorySnapshot>,
    },
}

#[derive(Clone)]
struct EdgeMetricSnapshot {
    ready: bool,
    tunnel_connected: bool,
    authorization_source: AuthorizationSourceStatus,
    authorization_version: u64,
    revoked_sessions: u64,
    transport: MultiplexTelemetrySnapshot,
    operations: OperationsCounterSnapshot,
    ingress: IngressMetricSnapshot,
}

async fn collect_metrics(
    router: &EdgeSessionRouter,
    tunnel_id: &TunnelId,
    ingress: &EdgeIngressMetricsSource,
    counters: &EdgeOperationsCounters,
    draining: &AtomicBool,
) -> EdgeMetricSnapshot {
    let tunnel_connected = ingress_tunnel_connected(router, tunnel_id, ingress).await;
    let authorization = router.authorization_status();
    let ready = ingress_ready(router, tunnel_id, ingress, draining).await;
    let ingress = match ingress {
        EdgeIngressMetricsSource::Raw { manager, route_id } => {
            IngressMetricSnapshot::Raw(manager.get_route(*route_id).await.ok())
        }
        EdgeIngressMetricsSource::Https {
            status,
            routes,
            request_history,
        } => IngressMetricSnapshot::Https {
            status: Box::new(status.snapshot()),
            route_health: routes.dynamic_source_health(),
            route_version: routes.dynamic_catalog_version().unwrap_or(0),
            route_count: routes.len(),
            request_history: request_history.as_ref().map(RequestHistory::snapshot),
        },
    };
    EdgeMetricSnapshot {
        ready,
        tunnel_connected,
        authorization_source: authorization.source,
        authorization_version: authorization.version.map_or(0, |version| version.get()),
        revoked_sessions: authorization.revoked_sessions,
        transport: router.transport_telemetry(),
        operations: OperationsCounterSnapshot {
            active_connections: counters.active_connections.load(Ordering::Relaxed),
            accepted_connections: counters.accepted_connections.load(Ordering::Relaxed),
            completed_requests: counters.completed_requests.load(Ordering::Relaxed),
            rejected_requests: counters.rejected_requests.load(Ordering::Relaxed),
            capacity_rejections: counters.capacity_rejections.load(Ordering::Relaxed),
        },
        ingress,
    }
}

async fn ingress_tunnel_connected(
    router: &EdgeSessionRouter,
    tunnel_id: &TunnelId,
    ingress: &EdgeIngressMetricsSource,
) -> bool {
    match ingress {
        EdgeIngressMetricsSource::Https { routes, .. } if routes.is_dynamic() => {
            let tunnels = router.subscribe_tunnels();
            let connected = tunnels
                .borrow()
                .iter()
                .any(|(candidate, _)| routes.contains_tunnel(candidate));
            connected
        }
        EdgeIngressMetricsSource::Raw { .. } | EdgeIngressMetricsSource::Https { .. } => {
            router.resolve_tunnel(tunnel_id).await.is_some()
        }
    }
}

fn render_metrics(snapshot: EdgeMetricSnapshot) -> String {
    let mut output = String::with_capacity(4 * 1024);
    metric(&mut output, "tunnelproxy_edge_up", "gauge", 1);
    metric(
        &mut output,
        "tunnelproxy_edge_ready",
        "gauge",
        u8::from(snapshot.ready),
    );
    metric(
        &mut output,
        "tunnelproxy_edge_tunnel_connected",
        "gauge",
        u8::from(snapshot.tunnel_connected),
    );
    let _ = writeln!(output, "# TYPE tunnelproxy_edge_authorization_source gauge");
    for (source, active) in [
        (
            "static",
            snapshot.authorization_source == AuthorizationSourceStatus::Static,
        ),
        (
            "live",
            snapshot.authorization_source == AuthorizationSourceStatus::Live,
        ),
        (
            "stale",
            snapshot.authorization_source == AuthorizationSourceStatus::Stale,
        ),
    ] {
        let _ = writeln!(
            output,
            "tunnelproxy_edge_authorization_source{{source=\"{source}\"}} {}",
            u8::from(active)
        );
    }
    metric(
        &mut output,
        "tunnelproxy_edge_authorization_snapshot_version",
        "gauge",
        snapshot.authorization_version,
    );
    metric(
        &mut output,
        "tunnelproxy_edge_authorization_revoked_sessions_total",
        "counter",
        snapshot.revoked_sessions,
    );
    metric(
        &mut output,
        "tunnelproxy_edge_operations_active_connections",
        "gauge",
        snapshot.operations.active_connections,
    );
    metric(
        &mut output,
        "tunnelproxy_edge_operations_accepted_connections_total",
        "counter",
        snapshot.operations.accepted_connections,
    );
    metric(
        &mut output,
        "tunnelproxy_edge_operations_completed_requests_total",
        "counter",
        snapshot.operations.completed_requests,
    );
    metric(
        &mut output,
        "tunnelproxy_edge_operations_rejected_requests_total",
        "counter",
        snapshot.operations.rejected_requests,
    );
    metric(
        &mut output,
        "tunnelproxy_edge_operations_capacity_rejections_total",
        "counter",
        snapshot.operations.capacity_rejections,
    );
    render_logging_metrics(&mut output, process_logging_snapshot());
    render_transport_metrics(&mut output, snapshot.transport);
    match snapshot.ingress {
        IngressMetricSnapshot::Raw(status) => render_raw_metrics(&mut output, status.as_ref()),
        IngressMetricSnapshot::Https {
            status,
            route_health,
            route_version,
            route_count,
            request_history,
        } => render_https_metrics(
            &mut output,
            *status,
            route_health,
            route_version,
            route_count,
            request_history.as_ref(),
        ),
    }
    output
}

fn render_logging_metrics(output: &mut String, logging: ProcessLoggingSnapshot) {
    for (name, kind, value) in [
        (
            "tunnelproxy_edge_logging_nonblocking_enabled",
            "gauge",
            u64::from(logging.buffer_capacity_events > 0),
        ),
        (
            "tunnelproxy_edge_logging_buffer_capacity_events",
            "gauge",
            logging.buffer_capacity_events,
        ),
        (
            "tunnelproxy_edge_logging_accepted_events_total",
            "counter",
            logging.accepted_events,
        ),
        (
            "tunnelproxy_edge_logging_dropped_events_total",
            "counter",
            logging.dropped_events,
        ),
        (
            "tunnelproxy_edge_logging_oversized_events_total",
            "counter",
            logging.oversized_events,
        ),
        (
            "tunnelproxy_edge_logging_write_failures_total",
            "counter",
            logging.write_failures,
        ),
    ] {
        metric(output, name, kind, value);
    }
}

fn render_transport_metrics(output: &mut String, transport: MultiplexTelemetrySnapshot) {
    metric(
        output,
        "tunnelproxy_edge_transport_active_streams",
        "gauge",
        transport.active_streams,
    );
    metric(
        output,
        "tunnelproxy_edge_transport_peak_active_streams",
        "gauge",
        transport.peak_active_streams,
    );
    let _ = writeln!(
        output,
        "# TYPE tunnelproxy_edge_transport_data_frames_total counter"
    );
    let _ = writeln!(
        output,
        "tunnelproxy_edge_transport_data_frames_total{{direction=\"sent\"}} {}",
        transport.sent_data_frames
    );
    let _ = writeln!(
        output,
        "tunnelproxy_edge_transport_data_frames_total{{direction=\"received\"}} {}",
        transport.received_data_frames
    );
    let _ = writeln!(
        output,
        "# TYPE tunnelproxy_edge_transport_data_bytes_total counter"
    );
    let _ = writeln!(
        output,
        "tunnelproxy_edge_transport_data_bytes_total{{direction=\"sent\"}} {}",
        transport.sent_data_bytes
    );
    let _ = writeln!(
        output,
        "tunnelproxy_edge_transport_data_bytes_total{{direction=\"received\"}} {}",
        transport.received_data_bytes
    );
    for (name, kind, value) in [
        (
            "tunnelproxy_edge_transport_data_admission_waits_total",
            "counter",
            transport.data_admission_waits,
        ),
        (
            "tunnelproxy_edge_transport_data_pipeline_frames",
            "gauge",
            transport.data_pipeline_frames,
        ),
        (
            "tunnelproxy_edge_transport_data_pipeline_capacity_frames",
            "gauge",
            transport.data_pipeline_capacity_frames,
        ),
        (
            "tunnelproxy_edge_transport_peak_data_pipeline_frames",
            "gauge",
            transport.peak_data_pipeline_frames,
        ),
        (
            "tunnelproxy_edge_transport_flow_control_resets_total",
            "counter",
            transport.flow_control_resets,
        ),
        (
            "tunnelproxy_edge_transport_control_burst_yields_total",
            "counter",
            transport.control_burst_yields,
        ),
    ] {
        metric(output, name, kind, value);
    }
}

fn render_raw_metrics(output: &mut String, status: Option<&RawIngressRouteStatus>) {
    metric(output, "tunnelproxy_edge_ingress_mode_raw", "gauge", 1);
    metric(output, "tunnelproxy_edge_ingress_mode_https", "gauge", 0);
    metric(
        output,
        "tunnelproxy_edge_raw_route_present",
        "gauge",
        u8::from(status.is_some()),
    );
    metric(
        output,
        "tunnelproxy_edge_raw_active_connections",
        "gauge",
        status.map_or(0, |value| value.active_connections),
    );
    metric(
        output,
        "tunnelproxy_edge_raw_accepted_connections_total",
        "counter",
        status.map_or(0, |value| value.accepted_connections),
    );
    metric(
        output,
        "tunnelproxy_edge_raw_global_capacity_rejections_total",
        "counter",
        status.map_or(0, |value| value.global_capacity_rejections),
    );
    metric(
        output,
        "tunnelproxy_edge_raw_per_ip_capacity_rejections_total",
        "counter",
        status.map_or(0, |value| value.per_ip_capacity_rejections),
    );
    metric(
        output,
        "tunnelproxy_edge_raw_target_unavailable_rejections_total",
        "counter",
        status.map_or(0, |value| value.target_unavailable_rejections),
    );
}

fn render_https_metrics(
    output: &mut String,
    status: HttpIngressStatus,
    route_health: Option<HttpsRouteSourceHealth>,
    route_version: u64,
    route_count: usize,
    request_history: Option<&RequestHistorySnapshot>,
) {
    metric(output, "tunnelproxy_edge_ingress_mode_raw", "gauge", 0);
    metric(output, "tunnelproxy_edge_ingress_mode_https", "gauge", 1);
    let _ = writeln!(output, "# TYPE tunnelproxy_edge_https_route_source gauge");
    for (source, active) in [
        ("static", route_health.is_none()),
        ("live", route_health == Some(HttpsRouteSourceHealth::Live)),
        ("stale", route_health == Some(HttpsRouteSourceHealth::Stale)),
        (
            "expired",
            route_health == Some(HttpsRouteSourceHealth::Expired),
        ),
    ] {
        let _ = writeln!(
            output,
            "tunnelproxy_edge_https_route_source{{source=\"{source}\"}} {}",
            u8::from(active)
        );
    }
    metric(
        output,
        "tunnelproxy_edge_https_route_catalog_version",
        "gauge",
        route_version,
    );
    metric(
        output,
        "tunnelproxy_edge_https_enabled_routes",
        "gauge",
        route_count,
    );
    metric(
        output,
        "tunnelproxy_edge_https_request_history_capacity",
        "gauge",
        request_history.map_or(0, |history| history.capacity),
    );
    metric(
        output,
        "tunnelproxy_edge_https_request_history_retained",
        "gauge",
        request_history.map_or(0, |history| history.entries.len()),
    );
    metric(
        output,
        "tunnelproxy_edge_https_request_history_recorded_total",
        "counter",
        request_history.map_or(0, |history| history.recorded_total),
    );
    metric(
        output,
        "tunnelproxy_edge_https_request_history_evicted_total",
        "counter",
        request_history.map_or(0, |history| history.evicted_total),
    );
    metric(
        output,
        "tunnelproxy_edge_https_request_history_sequence_exhaustions_total",
        "counter",
        request_history.map_or(0, |history| history.sequence_exhaustions),
    );
    let _ = writeln!(
        output,
        "# TYPE tunnelproxy_edge_https_request_history_outcomes_total counter"
    );
    for outcome in RequestHistoryOutcome::ALL {
        let value = request_history.map_or(0, |history| history.outcome_count(outcome));
        let _ = writeln!(
            output,
            "tunnelproxy_edge_https_request_history_outcomes_total{{outcome=\"{}\"}} {value}",
            outcome.as_str()
        );
    }
    for (name, kind, value) in [
        (
            "tunnelproxy_edge_https_active_connections",
            "gauge",
            status.active_connections as u64,
        ),
        (
            "tunnelproxy_edge_https_accepted_connections_total",
            "counter",
            status.accepted_connections,
        ),
        (
            "tunnelproxy_edge_https_http1_connections_total",
            "counter",
            status.http1_connections,
        ),
        (
            "tunnelproxy_edge_https_http2_connections_total",
            "counter",
            status.http2_connections,
        ),
        (
            "tunnelproxy_edge_https_active_http2_streams",
            "gauge",
            status.active_http2_streams as u64,
        ),
        (
            "tunnelproxy_edge_https_peak_active_http2_streams",
            "gauge",
            status.peak_active_http2_streams as u64,
        ),
        (
            "tunnelproxy_edge_https_websocket_upgrades_total",
            "counter",
            status.accepted_websocket_upgrades,
        ),
        (
            "tunnelproxy_edge_https_websocket_rejections_total",
            "counter",
            status.rejected_websocket_upgrades,
        ),
        (
            "tunnelproxy_edge_https_active_websocket_sessions",
            "gauge",
            status.active_websocket_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_peak_active_websocket_sessions",
            "gauge",
            status.peak_active_websocket_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_websocket_idle_timeouts_total",
            "counter",
            status.websocket_idle_timeouts,
        ),
        (
            "tunnelproxy_edge_https_http2_websocket_sessions_total",
            "counter",
            status.accepted_http2_websocket_sessions,
        ),
        (
            "tunnelproxy_edge_https_http2_websocket_rejections_total",
            "counter",
            status.rejected_http2_websocket_sessions,
        ),
        (
            "tunnelproxy_edge_https_active_http2_websocket_sessions",
            "gauge",
            status.active_http2_websocket_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_peak_active_http2_websocket_sessions",
            "gauge",
            status.peak_active_http2_websocket_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_http2_websocket_idle_timeouts_total",
            "counter",
            status.http2_websocket_idle_timeouts,
        ),
        (
            "tunnelproxy_edge_https_connect_sessions_total",
            "counter",
            status.accepted_connect_sessions,
        ),
        (
            "tunnelproxy_edge_https_connect_rejections_total",
            "counter",
            status.rejected_connect_sessions,
        ),
        (
            "tunnelproxy_edge_https_active_connect_sessions",
            "gauge",
            status.active_connect_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_peak_active_connect_sessions",
            "gauge",
            status.peak_active_connect_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_connect_idle_timeouts_total",
            "counter",
            status.connect_idle_timeouts,
        ),
        (
            "tunnelproxy_edge_https_http2_connect_sessions_total",
            "counter",
            status.accepted_http2_connect_sessions,
        ),
        (
            "tunnelproxy_edge_https_http2_connect_rejections_total",
            "counter",
            status.rejected_http2_connect_sessions,
        ),
        (
            "tunnelproxy_edge_https_active_http2_connect_sessions",
            "gauge",
            status.active_http2_connect_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_peak_active_http2_connect_sessions",
            "gauge",
            status.peak_active_http2_connect_sessions as u64,
        ),
        (
            "tunnelproxy_edge_https_http2_connect_idle_timeouts_total",
            "counter",
            status.http2_connect_idle_timeouts,
        ),
        (
            "tunnelproxy_edge_https_completed_requests_total",
            "counter",
            status.completed_requests,
        ),
        (
            "tunnelproxy_edge_https_admitted_requests_total",
            "counter",
            status.admitted_requests,
        ),
        (
            "tunnelproxy_edge_https_rejected_requests_total",
            "counter",
            status.rejected_requests,
        ),
        (
            "tunnelproxy_edge_https_global_capacity_rejections_total",
            "counter",
            status.global_capacity_rejections,
        ),
        (
            "tunnelproxy_edge_https_per_ip_capacity_rejections_total",
            "counter",
            status.per_ip_capacity_rejections,
        ),
        (
            "tunnelproxy_edge_https_tls_rejections_total",
            "counter",
            status.tls_rejections,
        ),
        (
            "tunnelproxy_edge_https_reused_requests_total",
            "counter",
            status.reused_requests,
        ),
        (
            "tunnelproxy_edge_https_request_timeouts_total",
            "counter",
            status.request_timeouts,
        ),
        (
            "tunnelproxy_edge_https_global_rate_limit_rejections_total",
            "counter",
            status.global_rate_limit_rejections,
        ),
        (
            "tunnelproxy_edge_https_per_ip_rate_limit_rejections_total",
            "counter",
            status.per_ip_rate_limit_rejections,
        ),
        (
            "tunnelproxy_edge_https_rate_limit_peer_capacity_rejections_total",
            "counter",
            status.rate_limit_peer_capacity_rejections,
        ),
        (
            "tunnelproxy_edge_https_signed_access_requests_total",
            "counter",
            status.accepted_signed_access_requests,
        ),
        (
            "tunnelproxy_edge_https_signed_access_missing_rejections_total",
            "counter",
            status.missing_signed_access_rejections,
        ),
        (
            "tunnelproxy_edge_https_signed_access_invalid_rejections_total",
            "counter",
            status.invalid_signed_access_rejections,
        ),
        (
            "tunnelproxy_edge_https_signed_access_expired_rejections_total",
            "counter",
            status.expired_signed_access_rejections,
        ),
        (
            "tunnelproxy_edge_https_signed_access_keyring_generation",
            "gauge",
            status.signed_access_keyring_generation,
        ),
        (
            "tunnelproxy_edge_https_signed_access_keyring_reload_failed",
            "gauge",
            u64::from(status.signed_access_keyring_reload_failed),
        ),
        (
            "tunnelproxy_edge_https_signed_access_keyring_reload_successes_total",
            "counter",
            status.signed_access_keyring_reload_successes,
        ),
        (
            "tunnelproxy_edge_https_signed_access_keyring_reload_failures_total",
            "counter",
            status.signed_access_keyring_reload_failures,
        ),
        (
            "tunnelproxy_edge_https_reachability_probe_requests_total",
            "counter",
            status.reachability_probe_requests,
        ),
        (
            "tunnelproxy_edge_https_reachability_probe_successes_total",
            "counter",
            status.successful_reachability_probes,
        ),
        (
            "tunnelproxy_edge_https_reachability_probe_failures_total",
            "counter",
            status.failed_reachability_probes,
        ),
        (
            "tunnelproxy_edge_https_tracked_rate_limit_peers",
            "gauge",
            status.tracked_rate_limit_peers as u64,
        ),
        (
            "tunnelproxy_edge_https_peak_tracked_rate_limit_peers",
            "gauge",
            status.peak_tracked_rate_limit_peers as u64,
        ),
    ] {
        metric(output, name, kind, value);
    }
}

fn metric(output: &mut String, name: &str, kind: &str, value: impl std::fmt::Display) {
    let _ = writeln!(output, "# TYPE {name} {kind}");
    let _ = writeln!(output, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_loopback_only_and_bounded() {
        let config = EdgeOperationsConfig::loopback("127.0.0.1:0".parse().unwrap());
        assert_eq!(config.validate(), Ok(()));
        let mut candidate = config;
        candidate.listen_addr = "0.0.0.0:9090".parse().unwrap();
        assert_eq!(
            candidate.validate(),
            Err(EdgeOperationsConfigError::NonLoopbackListener)
        );
        candidate = config;
        candidate.max_concurrent_connections = 0;
        assert_eq!(
            candidate.validate(),
            Err(EdgeOperationsConfigError::InvalidConnectionLimit)
        );
        candidate = config;
        candidate.request_timeout = Duration::ZERO;
        assert_eq!(
            candidate.validate(),
            Err(EdgeOperationsConfigError::ZeroRequestTimeout)
        );
    }

    #[test]
    fn metric_rendering_uses_only_fixed_bounded_labels() {
        let rendered = render_metrics(EdgeMetricSnapshot {
            ready: true,
            tunnel_connected: true,
            authorization_source: AuthorizationSourceStatus::Live,
            authorization_version: 7,
            revoked_sessions: 2,
            transport: MultiplexTelemetrySnapshot {
                sent_data_frames: 2,
                sent_data_bytes: 17,
                received_data_frames: 3,
                received_data_bytes: 29,
                data_pipeline_capacity_frames: 256,
                ..MultiplexTelemetrySnapshot::default()
            },
            operations: OperationsCounterSnapshot {
                active_connections: 1,
                accepted_connections: 3,
                completed_requests: 2,
                rejected_requests: 1,
                capacity_rejections: 0,
            },
            ingress: IngressMetricSnapshot::Raw(None),
        });
        assert!(rendered.contains("tunnelproxy_edge_ready 1\n"));
        assert!(rendered.contains("tunnelproxy_edge_logging_nonblocking_enabled 0\n"));
        let mut logging = String::new();
        render_logging_metrics(
            &mut logging,
            ProcessLoggingSnapshot {
                buffer_capacity_events: 8,
                oversized_events: 2,
                ..ProcessLoggingSnapshot::default()
            },
        );
        assert!(logging.contains("tunnelproxy_edge_logging_nonblocking_enabled 1"));
        assert!(logging.contains("tunnelproxy_edge_logging_oversized_events_total 2"));
        assert!(rendered.contains("tunnelproxy_edge_authorization_source{source=\"live\"} 1\n"));
        assert_eq!(
            rendered
                .matches("# TYPE tunnelproxy_edge_authorization_source gauge")
                .count(),
            1
        );
        assert!(rendered.contains("tunnelproxy_edge_raw_route_present 0\n"));
        assert!(rendered
            .contains("tunnelproxy_edge_transport_data_frames_total{direction=\"received\"} 3"));
        assert!(
            rendered.contains("tunnelproxy_edge_transport_data_bytes_total{direction=\"sent\"} 17")
        );
        assert!(rendered.contains("tunnelproxy_edge_transport_data_pipeline_capacity_frames 256"));
        assert!(!rendered.contains("TunnelId"));
        assert!(!rendered.contains("127.0.0.1"));

        let mut https = String::new();
        render_https_metrics(
            &mut https,
            HttpIngressStatus {
                http1_connections: 3,
                http2_connections: 2,
                active_http2_streams: 4,
                peak_active_http2_streams: 7,
                accepted_websocket_upgrades: 5,
                rejected_websocket_upgrades: 6,
                active_websocket_sessions: 2,
                peak_active_websocket_sessions: 4,
                websocket_idle_timeouts: 1,
                accepted_http2_websocket_sessions: 12,
                rejected_http2_websocket_sessions: 13,
                active_http2_websocket_sessions: 1,
                peak_active_http2_websocket_sessions: 3,
                http2_websocket_idle_timeouts: 4,
                accepted_connect_sessions: 8,
                rejected_connect_sessions: 9,
                active_connect_sessions: 3,
                peak_active_connect_sessions: 5,
                connect_idle_timeouts: 2,
                accepted_http2_connect_sessions: 10,
                rejected_http2_connect_sessions: 11,
                active_http2_connect_sessions: 1,
                peak_active_http2_connect_sessions: 2,
                http2_connect_idle_timeouts: 3,
                accepted_signed_access_requests: 14,
                missing_signed_access_rejections: 15,
                invalid_signed_access_rejections: 16,
                expired_signed_access_rejections: 17,
                signed_access_keyring_generation: 18,
                signed_access_keyring_reload_failed: true,
                signed_access_keyring_reload_successes: 19,
                signed_access_keyring_reload_failures: 20,
                reachability_probe_requests: 23,
                successful_reachability_probes: 21,
                failed_reachability_probes: 2,
                ..HttpIngressStatus::default()
            },
            None,
            0,
            1,
            None,
        );
        assert!(https.contains("tunnelproxy_edge_https_http1_connections_total 3\n"));
        assert!(https.contains("tunnelproxy_edge_https_http2_connections_total 2\n"));
        assert!(https.contains("tunnelproxy_edge_https_active_http2_streams 4\n"));
        assert!(https.contains("tunnelproxy_edge_https_peak_active_http2_streams 7\n"));
        assert!(https.contains("tunnelproxy_edge_https_websocket_upgrades_total 5\n"));
        assert!(https.contains("tunnelproxy_edge_https_websocket_rejections_total 6\n"));
        assert!(https.contains("tunnelproxy_edge_https_active_websocket_sessions 2\n"));
        assert!(https.contains("tunnelproxy_edge_https_peak_active_websocket_sessions 4\n"));
        assert!(https.contains("tunnelproxy_edge_https_websocket_idle_timeouts_total 1\n"));
        assert!(https.contains("tunnelproxy_edge_https_http2_websocket_sessions_total 12\n"));
        assert!(https.contains("tunnelproxy_edge_https_http2_websocket_rejections_total 13\n"));
        assert!(https.contains("tunnelproxy_edge_https_active_http2_websocket_sessions 1\n"));
        assert!(https.contains("tunnelproxy_edge_https_peak_active_http2_websocket_sessions 3\n"));
        assert!(https.contains("tunnelproxy_edge_https_http2_websocket_idle_timeouts_total 4\n"));
        assert!(https.contains("tunnelproxy_edge_https_connect_sessions_total 8\n"));
        assert!(https.contains("tunnelproxy_edge_https_connect_rejections_total 9\n"));
        assert!(https.contains("tunnelproxy_edge_https_active_connect_sessions 3\n"));
        assert!(https.contains("tunnelproxy_edge_https_peak_active_connect_sessions 5\n"));
        assert!(https.contains("tunnelproxy_edge_https_connect_idle_timeouts_total 2\n"));
        assert!(https.contains("tunnelproxy_edge_https_http2_connect_sessions_total 10\n"));
        assert!(https.contains("tunnelproxy_edge_https_http2_connect_rejections_total 11\n"));
        assert!(https.contains("tunnelproxy_edge_https_active_http2_connect_sessions 1\n"));
        assert!(https.contains("tunnelproxy_edge_https_peak_active_http2_connect_sessions 2\n"));
        assert!(https.contains("tunnelproxy_edge_https_http2_connect_idle_timeouts_total 3\n"));
        assert!(https.contains("tunnelproxy_edge_https_signed_access_requests_total 14\n"));
        assert!(
            https.contains("tunnelproxy_edge_https_signed_access_missing_rejections_total 15\n")
        );
        assert!(
            https.contains("tunnelproxy_edge_https_signed_access_invalid_rejections_total 16\n")
        );
        assert!(
            https.contains("tunnelproxy_edge_https_signed_access_expired_rejections_total 17\n")
        );
        assert!(https.contains("tunnelproxy_edge_https_signed_access_keyring_generation 18\n"));
        assert!(https.contains("tunnelproxy_edge_https_signed_access_keyring_reload_failed 1\n"));
        assert!(https
            .contains("tunnelproxy_edge_https_signed_access_keyring_reload_successes_total 19\n"));
        assert!(https
            .contains("tunnelproxy_edge_https_signed_access_keyring_reload_failures_total 20\n"));
        assert!(https.contains("tunnelproxy_edge_https_reachability_probe_requests_total 23\n"));
        assert!(https.contains("tunnelproxy_edge_https_reachability_probe_successes_total 21\n"));
        assert!(https.contains("tunnelproxy_edge_https_reachability_probe_failures_total 2\n"));
        assert!(https.contains("tunnelproxy_edge_https_request_history_capacity 0\n"));
        for outcome in RequestHistoryOutcome::ALL {
            assert!(https.contains(&format!(
                "tunnelproxy_edge_https_request_history_outcomes_total{{outcome=\"{}\"}} 0",
                outcome.as_str()
            )));
        }
        assert!(!https.contains("hostname"));
    }

    #[test]
    fn responses_disable_cache_and_connection_reuse() {
        let response = plain_response(StatusCode::OK, "ok\n", false);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn request_history_json_is_versioned_newest_first_and_response_bounded() {
        let history = RequestHistory::new(128).unwrap();
        for index in 0..128 {
            history
                .begin(
                    "demo.example.test",
                    "tunnel-dev",
                    "GET",
                    &format!("/{index}/{}", "x".repeat(2 * 1024)),
                    crate::request_history::RequestHistoryProtocol::Http1,
                    std::time::Instant::now(),
                )
                .finish(200);
        }
        let body = render_request_history(history.snapshot(), RequestHistoryQuery::default());
        assert!(body.len() <= MAX_REQUEST_HISTORY_RESPONSE_BYTES);
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(document["version"], 1);
        assert_eq!(document["capacity"], 128);
        assert_eq!(document["retained"], 128);
        assert_eq!(document["eligible"], 128);
        assert_eq!(document["recorded_total"], 128);
        assert_eq!(document["truncated"], true);
        assert_eq!(document["has_more"], true);
        assert!(document["next_before"].as_u64().is_some());
        assert_eq!(document["requests"][0]["request_id"], 128);

        let response = request_history_response(&history, RequestHistoryQuery::default(), false);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
    }

    #[test]
    fn request_history_query_is_strict_and_bounded() {
        assert_eq!(
            RequestHistoryQuery::parse(None),
            Ok(RequestHistoryQuery::default())
        );
        assert_eq!(
            RequestHistoryQuery::parse(Some("")),
            Ok(RequestHistoryQuery::default())
        );
        assert_eq!(
            RequestHistoryQuery::parse(Some("limit=8&before=42")),
            Ok(RequestHistoryQuery {
                before: Some(42),
                limit: Some(8),
            })
        );
        for invalid in [
            "limit=0",
            "limit=129",
            "limit=",
            "limit=one",
            "limit=+1",
            "limit=1&limit=2",
            "before=0",
            "before=",
            "before=one",
            "before=+1",
            "before=1&before=2",
            "unknown=1",
            "limit",
            "limit=1&",
            "limit=%31",
        ] {
            assert_eq!(
                RequestHistoryQuery::parse(Some(invalid)),
                Err(InvalidRequestHistoryQuery),
                "query {invalid:?} must fail closed"
            );
        }
    }

    #[test]
    fn request_history_cursor_pages_are_newest_first_without_duplicates() {
        let history = RequestHistory::new(5).unwrap();
        for index in 1..=7 {
            history
                .begin(
                    "demo.example.test",
                    "tunnel-dev",
                    "GET",
                    &format!("/{index}"),
                    crate::request_history::RequestHistoryProtocol::Http2,
                    std::time::Instant::now(),
                )
                .finish(200);
        }

        let first: serde_json::Value = serde_json::from_str(&render_request_history(
            history.snapshot(),
            RequestHistoryQuery {
                before: None,
                limit: Some(2),
            },
        ))
        .unwrap();
        assert_eq!(first["retained"], 5);
        assert_eq!(first["eligible"], 5);
        assert_eq!(first["returned"], 2);
        assert_eq!(first["has_more"], true);
        assert_eq!(first["next_before"], 6);
        assert_eq!(first["requests"][0]["request_id"], 7);
        assert_eq!(first["requests"][1]["request_id"], 6);

        let second: serde_json::Value = serde_json::from_str(&render_request_history(
            history.snapshot(),
            RequestHistoryQuery {
                before: first["next_before"].as_u64(),
                limit: Some(2),
            },
        ))
        .unwrap();
        assert_eq!(second["eligible"], 3);
        assert_eq!(second["returned"], 2);
        assert_eq!(second["next_before"], 4);
        assert_eq!(second["requests"][0]["request_id"], 5);
        assert_eq!(second["requests"][1]["request_id"], 4);

        let final_page: serde_json::Value = serde_json::from_str(&render_request_history(
            history.snapshot(),
            RequestHistoryQuery {
                before: second["next_before"].as_u64(),
                limit: Some(2),
            },
        ))
        .unwrap();
        assert_eq!(final_page["eligible"], 1);
        assert_eq!(final_page["returned"], 1);
        assert_eq!(final_page["has_more"], false);
        assert_eq!(final_page["next_before"], serde_json::Value::Null);
        assert_eq!(final_page["requests"][0]["request_id"], 3);

        let evicted_cursor: serde_json::Value = serde_json::from_str(&render_request_history(
            history.snapshot(),
            RequestHistoryQuery {
                before: Some(2),
                limit: Some(5),
            },
        ))
        .unwrap();
        assert_eq!(evicted_cursor["eligible"], 0);
        assert_eq!(evicted_cursor["returned"], 0);
        assert_eq!(evicted_cursor["has_more"], false);
    }
}
