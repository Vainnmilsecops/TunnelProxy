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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{info, warn};
use tunnelproxy_common::{
    MultiplexTelemetrySnapshot, RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal,
    TunnelId,
};
use tunnelproxy_control_plane::HttpsRouteSourceHealth;

use crate::http_ingress::{HttpHostRoutes, HttpIngressStatus, HttpIngressStatusHandle};
use crate::multiplex::{AuthorizationSourceStatus, EdgeSessionRouter};
use crate::raw_ingress::{RawIngressRouteId, RawIngressRouteManager, RawIngressRouteStatus};

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
        status: HttpIngressStatus,
        route_health: Option<HttpsRouteSourceHealth>,
        route_version: u64,
        route_count: usize,
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
        EdgeIngressMetricsSource::Https { status, routes } => IngressMetricSnapshot::Https {
            status: status.snapshot(),
            route_health: routes.dynamic_source_health(),
            route_version: routes.dynamic_catalog_version().unwrap_or(0),
            route_count: routes.len(),
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
    render_transport_metrics(&mut output, snapshot.transport);
    match snapshot.ingress {
        IngressMetricSnapshot::Raw(status) => render_raw_metrics(&mut output, status.as_ref()),
        IngressMetricSnapshot::Https {
            status,
            route_health,
            route_version,
            route_count,
        } => render_https_metrics(
            &mut output,
            status,
            route_health,
            route_version,
            route_count,
        ),
    }
    output
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
}
