//! Bounded loopback-only Control Plane health, readiness, and metrics endpoint.

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
use tunnelproxy_common::{RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal};

pub const MIN_OPERATIONS_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_OPERATIONS_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_OPERATIONS_HEADERS: usize = 128;
pub const MAX_OPERATIONS_CONNECTIONS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPlaneOperationsConfig {
    pub listen_addr: SocketAddr,
    pub max_concurrent_connections: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
    pub shutdown: RuntimeShutdownConfig,
}

impl ControlPlaneOperationsConfig {
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

    pub fn validate(self) -> Result<(), ControlPlaneOperationsConfigError> {
        if !self.listen_addr.ip().is_loopback() {
            return Err(ControlPlaneOperationsConfigError::NonLoopbackListener);
        }
        if self.max_concurrent_connections == 0
            || self.max_concurrent_connections > MAX_OPERATIONS_CONNECTIONS
        {
            return Err(ControlPlaneOperationsConfigError::InvalidConnectionLimit);
        }
        if self.max_header_bytes < MIN_OPERATIONS_HEADER_BYTES
            || self.max_header_bytes > MAX_OPERATIONS_HEADER_BYTES
        {
            return Err(ControlPlaneOperationsConfigError::InvalidHeaderBytes);
        }
        if self.max_headers == 0 || self.max_headers > MAX_OPERATIONS_HEADERS {
            return Err(ControlPlaneOperationsConfigError::InvalidHeaderCount);
        }
        if self.header_read_timeout.is_zero() {
            return Err(ControlPlaneOperationsConfigError::ZeroHeaderTimeout);
        }
        if self.request_timeout.is_zero() {
            return Err(ControlPlaneOperationsConfigError::ZeroRequestTimeout);
        }
        if self.shutdown.drain_timeout.is_zero() {
            return Err(ControlPlaneOperationsConfigError::ZeroDrainTimeout);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPlaneOperationsConfigError {
    NonLoopbackListener,
    InvalidConnectionLimit,
    InvalidHeaderBytes,
    InvalidHeaderCount,
    ZeroHeaderTimeout,
    ZeroRequestTimeout,
    ZeroDrainTimeout,
}

impl std::fmt::Display for ControlPlaneOperationsConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
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

impl std::error::Error for ControlPlaneOperationsConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPlaneOperationsOutcome {
    pub local_addr: SocketAddr,
    pub accepted_connections: u64,
    pub completed_requests: u64,
    pub rejected_requests: u64,
    pub capacity_rejections: u64,
    pub shutdown: RuntimeShutdownOutcome,
}

impl ControlPlaneOperationsOutcome {
    pub const fn was_forced(self) -> bool {
        matches!(self.shutdown, RuntimeShutdownOutcome::Forced { .. })
    }
}

#[derive(Debug)]
pub enum ControlPlaneOperationsError {
    InvalidConfig(ControlPlaneOperationsConfigError),
    Bind(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for ControlPlaneOperationsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "invalid operations config: {error}"),
            Self::Bind(error) => write!(formatter, "operations listener bind failed: {error}"),
            Self::Accept(error) => write!(formatter, "operations listener accept failed: {error}"),
        }
    }
}

impl std::error::Error for ControlPlaneOperationsError {}

#[derive(Default)]
struct TelemetryInner {
    ready: AtomicBool,
    draining: AtomicBool,
    snapshot_version: AtomicU64,
    refresh_applied: AtomicU64,
    refresh_unchanged: AtomicU64,
    refresh_failed: AtomicU64,
    snapshot_active: AtomicUsize,
    snapshot_accepted: AtomicU64,
    snapshot_capacity_rejected: AtomicU64,
    snapshot_tls_rejected: AtomicU64,
    snapshot_invalid_requests: AtomicU64,
    snapshot_subscriptions: AtomicU64,
    snapshot_updates: AtomicU64,
    enrollment_enabled: AtomicBool,
    enrollment_active: AtomicUsize,
    enrollment_accepted: AtomicU64,
    enrollment_capacity_rejected: AtomicU64,
    enrollment_tls_rejected: AtomicU64,
    enrollment_issued: AtomicU64,
    enrollment_activated: AtomicU64,
    enrollment_rejected: AtomicU64,
    enrollment_failed: AtomicU64,
    reconciliation_runs: AtomicU64,
    reconciliation_failures: AtomicU64,
    reconciliation_credentials: AtomicU64,
    operations_active: AtomicUsize,
    operations_accepted: AtomicU64,
    operations_completed: AtomicU64,
    operations_rejected: AtomicU64,
    operations_capacity_rejected: AtomicU64,
}

#[derive(Clone, Default)]
pub(crate) struct ControlPlaneTelemetry(Arc<TelemetryInner>);

impl ControlPlaneTelemetry {
    pub(crate) fn initialize(&self, version: u64, enrollment_enabled: bool) {
        self.0.snapshot_version.store(version, Ordering::Release);
        self.0
            .enrollment_enabled
            .store(enrollment_enabled, Ordering::Release);
    }

    pub(crate) fn mark_ready(&self) {
        self.0.draining.store(false, Ordering::Release);
        self.0.ready.store(true, Ordering::Release);
    }

    pub(crate) fn begin_draining(&self) {
        self.0.ready.store(false, Ordering::Release);
        self.0.draining.store(true, Ordering::Release);
    }

    pub(crate) fn record_refresh(&self, outcome: RefreshOutcome, version: Option<u64>) {
        if let Some(version) = version {
            self.0.snapshot_version.store(version, Ordering::Release);
        }
        let counter = match outcome {
            RefreshOutcome::Applied => &self.0.refresh_applied,
            RefreshOutcome::Unchanged => &self.0.refresh_unchanged,
            RefreshOutcome::Failed => &self.0.refresh_failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot_accepted(&self) -> ActiveTelemetryGuard {
        self.0.snapshot_accepted.fetch_add(1, Ordering::Relaxed);
        self.0.snapshot_active.fetch_add(1, Ordering::Relaxed);
        ActiveTelemetryGuard::new(Arc::clone(&self.0), ActiveKind::Snapshot)
    }

    pub(crate) fn snapshot_capacity_rejected(&self) {
        self.0
            .snapshot_capacity_rejected
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn snapshot_tls_rejected(&self) {
        self.0.snapshot_tls_rejected.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn snapshot_invalid_request(&self) {
        self.0
            .snapshot_invalid_requests
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn snapshot_subscribed(&self) {
        self.0
            .snapshot_subscriptions
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn snapshot_updated(&self, version: u64) {
        self.0.snapshot_version.store(version, Ordering::Release);
        self.0.snapshot_updates.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn enrollment_accepted(&self) -> ActiveTelemetryGuard {
        self.0.enrollment_accepted.fetch_add(1, Ordering::Relaxed);
        self.0.enrollment_active.fetch_add(1, Ordering::Relaxed);
        ActiveTelemetryGuard::new(Arc::clone(&self.0), ActiveKind::Enrollment)
    }
    pub(crate) fn enrollment_capacity_rejected(&self) {
        self.0
            .enrollment_capacity_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_snapshot_version(&self, version: u64) {
        self.0.snapshot_version.store(version, Ordering::Release);
    }
    pub(crate) fn enrollment_tls_rejected(&self) {
        self.0
            .enrollment_tls_rejected
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn enrollment_outcome(&self, outcome: EnrollmentRequestOutcome) {
        let counter = match outcome {
            EnrollmentRequestOutcome::Issued => &self.0.enrollment_issued,
            EnrollmentRequestOutcome::Activated => &self.0.enrollment_activated,
            EnrollmentRequestOutcome::Rejected => &self.0.enrollment_rejected,
            EnrollmentRequestOutcome::Failed => &self.0.enrollment_failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn reconciliation_completed(&self, affected: u64, version: u64) {
        self.0.reconciliation_runs.fetch_add(1, Ordering::Relaxed);
        self.0
            .reconciliation_credentials
            .fetch_add(affected, Ordering::Relaxed);
        self.0.snapshot_version.store(version, Ordering::Release);
    }
    pub(crate) fn reconciliation_failed(&self) {
        self.0
            .reconciliation_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> TelemetrySnapshot {
        let inner = &self.0;
        TelemetrySnapshot {
            ready: inner.ready.load(Ordering::Acquire),
            draining: inner.draining.load(Ordering::Acquire),
            snapshot_version: inner.snapshot_version.load(Ordering::Acquire),
            refresh_applied: inner.refresh_applied.load(Ordering::Relaxed),
            refresh_unchanged: inner.refresh_unchanged.load(Ordering::Relaxed),
            refresh_failed: inner.refresh_failed.load(Ordering::Relaxed),
            snapshot_active: inner.snapshot_active.load(Ordering::Relaxed),
            snapshot_accepted: inner.snapshot_accepted.load(Ordering::Relaxed),
            snapshot_capacity_rejected: inner.snapshot_capacity_rejected.load(Ordering::Relaxed),
            snapshot_tls_rejected: inner.snapshot_tls_rejected.load(Ordering::Relaxed),
            snapshot_invalid_requests: inner.snapshot_invalid_requests.load(Ordering::Relaxed),
            snapshot_subscriptions: inner.snapshot_subscriptions.load(Ordering::Relaxed),
            snapshot_updates: inner.snapshot_updates.load(Ordering::Relaxed),
            enrollment_enabled: inner.enrollment_enabled.load(Ordering::Acquire),
            enrollment_active: inner.enrollment_active.load(Ordering::Relaxed),
            enrollment_accepted: inner.enrollment_accepted.load(Ordering::Relaxed),
            enrollment_capacity_rejected: inner
                .enrollment_capacity_rejected
                .load(Ordering::Relaxed),
            enrollment_tls_rejected: inner.enrollment_tls_rejected.load(Ordering::Relaxed),
            enrollment_issued: inner.enrollment_issued.load(Ordering::Relaxed),
            enrollment_activated: inner.enrollment_activated.load(Ordering::Relaxed),
            enrollment_rejected: inner.enrollment_rejected.load(Ordering::Relaxed),
            enrollment_failed: inner.enrollment_failed.load(Ordering::Relaxed),
            reconciliation_runs: inner.reconciliation_runs.load(Ordering::Relaxed),
            reconciliation_failures: inner.reconciliation_failures.load(Ordering::Relaxed),
            reconciliation_credentials: inner.reconciliation_credentials.load(Ordering::Relaxed),
            operations_active: inner.operations_active.load(Ordering::Relaxed),
            operations_accepted: inner.operations_accepted.load(Ordering::Relaxed),
            operations_completed: inner.operations_completed.load(Ordering::Relaxed),
            operations_rejected: inner.operations_rejected.load(Ordering::Relaxed),
            operations_capacity_rejected: inner
                .operations_capacity_rejected
                .load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RefreshOutcome {
    Applied,
    Unchanged,
    Failed,
}
#[derive(Clone, Copy)]
pub(crate) enum EnrollmentRequestOutcome {
    Issued,
    Activated,
    Rejected,
    Failed,
}
enum ActiveKind {
    Snapshot,
    Enrollment,
    Operations,
}

pub(crate) struct ActiveTelemetryGuard {
    inner: Arc<TelemetryInner>,
    kind: ActiveKind,
}
impl ActiveTelemetryGuard {
    fn new(inner: Arc<TelemetryInner>, kind: ActiveKind) -> Self {
        Self { inner, kind }
    }
}
impl Drop for ActiveTelemetryGuard {
    fn drop(&mut self) {
        match self.kind {
            ActiveKind::Snapshot => &self.inner.snapshot_active,
            ActiveKind::Enrollment => &self.inner.enrollment_active,
            ActiveKind::Operations => &self.inner.operations_active,
        }
        .fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct ControlPlaneOperationsRuntime {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: ControlPlaneOperationsConfig,
    telemetry: ControlPlaneTelemetry,
}

impl ControlPlaneOperationsRuntime {
    pub(crate) async fn bind(
        config: ControlPlaneOperationsConfig,
        telemetry: ControlPlaneTelemetry,
    ) -> Result<Self, ControlPlaneOperationsError> {
        config
            .validate()
            .map_err(ControlPlaneOperationsError::InvalidConfig)?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(ControlPlaneOperationsError::Bind)?;
        let local_addr = listener
            .local_addr()
            .map_err(ControlPlaneOperationsError::Bind)?;
        Ok(Self {
            listener,
            local_addr,
            config,
            telemetry,
        })
    }
    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<ControlPlaneOperationsOutcome, ControlPlaneOperationsError> {
        let permits = Arc::new(Semaphore::new(self.config.max_concurrent_connections));
        let mut connections = JoinSet::new();
        let mut terminal_error = None;
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (socket, peer) = match accepted { Ok(value) => value, Err(error) => { terminal_error = Some(ControlPlaneOperationsError::Accept(error)); break; } };
                    let permit = match Arc::clone(&permits).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => { self.telemetry.0.operations_capacity_rejected.fetch_add(1, Ordering::Relaxed); warn!(%peer, event = "control_plane_operations_capacity_rejected"); drop(socket); continue; }
                    };
                    self.telemetry.0.operations_accepted.fetch_add(1, Ordering::Relaxed);
                    self.telemetry.0.operations_active.fetch_add(1, Ordering::Relaxed);
                    let active = ActiveTelemetryGuard::new(Arc::clone(&self.telemetry.0), ActiveKind::Operations);
                    connections.spawn(run_connection(socket, peer, self.config, self.telemetry.clone(), permit, active));
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
        let counters = self.telemetry.snapshot();
        Ok(ControlPlaneOperationsOutcome {
            local_addr: self.local_addr,
            accepted_connections: counters.operations_accepted,
            completed_requests: counters.operations_completed,
            rejected_requests: counters.operations_rejected,
            capacity_rejections: counters.operations_capacity_rejected,
            shutdown,
        })
    }
}

async fn run_connection(
    socket: TcpStream,
    peer: SocketAddr,
    config: ControlPlaneOperationsConfig,
    telemetry: ControlPlaneTelemetry,
    _permit: OwnedSemaphorePermit,
    _active: ActiveTelemetryGuard,
) {
    let service =
        hyper::service::service_fn(move |request| serve_request(request, telemetry.clone()));
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
        Ok(Ok(())) => info!(%peer, event = "control_plane_operations_connection_completed"),
        Ok(Err(error)) => {
            warn!(%peer, %error, event = "control_plane_operations_connection_failed")
        }
        Err(_) => warn!(%peer, event = "control_plane_operations_request_timeout"),
    }
}

async fn serve_request(
    request: Request<Incoming>,
    telemetry: ControlPlaneTelemetry,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let head = request.method() == Method::HEAD;
    let snapshot = telemetry.snapshot();
    let response = if request.method() != Method::GET && !head {
        telemetry
            .0
            .operations_rejected
            .fetch_add(1, Ordering::Relaxed);
        plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n", head)
    } else {
        match request.uri().path() {
            "/healthz" => plain_response(StatusCode::OK, "ok\n", head),
            "/readyz" if snapshot.ready => plain_response(StatusCode::OK, "ready\n", head),
            "/readyz" => plain_response(StatusCode::SERVICE_UNAVAILABLE, "not ready\n", head),
            "/metrics" => metrics_response(&render_metrics(snapshot), head),
            _ => {
                telemetry
                    .0
                    .operations_rejected
                    .fetch_add(1, Ordering::Relaxed);
                plain_response(StatusCode::NOT_FOUND, "not found\n", head)
            }
        }
    };
    telemetry
        .0
        .operations_completed
        .fetch_add(1, Ordering::Relaxed);
    Ok(response)
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
struct TelemetrySnapshot {
    ready: bool,
    draining: bool,
    snapshot_version: u64,
    refresh_applied: u64,
    refresh_unchanged: u64,
    refresh_failed: u64,
    snapshot_active: usize,
    snapshot_accepted: u64,
    snapshot_capacity_rejected: u64,
    snapshot_tls_rejected: u64,
    snapshot_invalid_requests: u64,
    snapshot_subscriptions: u64,
    snapshot_updates: u64,
    enrollment_enabled: bool,
    enrollment_active: usize,
    enrollment_accepted: u64,
    enrollment_capacity_rejected: u64,
    enrollment_tls_rejected: u64,
    enrollment_issued: u64,
    enrollment_activated: u64,
    enrollment_rejected: u64,
    enrollment_failed: u64,
    reconciliation_runs: u64,
    reconciliation_failures: u64,
    reconciliation_credentials: u64,
    operations_active: usize,
    operations_accepted: u64,
    operations_completed: u64,
    operations_rejected: u64,
    operations_capacity_rejected: u64,
}

fn render_metrics(s: TelemetrySnapshot) -> String {
    let mut output = String::with_capacity(4096);
    for (name, kind, value) in [
        ("tunnelproxy_control_plane_up", "gauge", 1),
        (
            "tunnelproxy_control_plane_ready",
            "gauge",
            u64::from(s.ready),
        ),
        (
            "tunnelproxy_control_plane_draining",
            "gauge",
            u64::from(s.draining),
        ),
        (
            "tunnelproxy_control_plane_snapshot_version",
            "gauge",
            s.snapshot_version,
        ),
        (
            "tunnelproxy_control_plane_snapshot_active_clients",
            "gauge",
            s.snapshot_active as u64,
        ),
        (
            "tunnelproxy_control_plane_snapshot_accepted_connections_total",
            "counter",
            s.snapshot_accepted,
        ),
        (
            "tunnelproxy_control_plane_snapshot_capacity_rejections_total",
            "counter",
            s.snapshot_capacity_rejected,
        ),
        (
            "tunnelproxy_control_plane_snapshot_tls_rejections_total",
            "counter",
            s.snapshot_tls_rejected,
        ),
        (
            "tunnelproxy_control_plane_snapshot_invalid_requests_total",
            "counter",
            s.snapshot_invalid_requests,
        ),
        (
            "tunnelproxy_control_plane_snapshot_subscriptions_total",
            "counter",
            s.snapshot_subscriptions,
        ),
        (
            "tunnelproxy_control_plane_snapshot_updates_total",
            "counter",
            s.snapshot_updates,
        ),
        (
            "tunnelproxy_control_plane_enrollment_enabled",
            "gauge",
            u64::from(s.enrollment_enabled),
        ),
        (
            "tunnelproxy_control_plane_enrollment_active_clients",
            "gauge",
            s.enrollment_active as u64,
        ),
        (
            "tunnelproxy_control_plane_enrollment_accepted_connections_total",
            "counter",
            s.enrollment_accepted,
        ),
        (
            "tunnelproxy_control_plane_enrollment_capacity_rejections_total",
            "counter",
            s.enrollment_capacity_rejected,
        ),
        (
            "tunnelproxy_control_plane_enrollment_tls_rejections_total",
            "counter",
            s.enrollment_tls_rejected,
        ),
        (
            "tunnelproxy_control_plane_reconciliation_runs_total",
            "counter",
            s.reconciliation_runs,
        ),
        (
            "tunnelproxy_control_plane_reconciliation_failures_total",
            "counter",
            s.reconciliation_failures,
        ),
        (
            "tunnelproxy_control_plane_reconciliation_credentials_total",
            "counter",
            s.reconciliation_credentials,
        ),
        (
            "tunnelproxy_control_plane_operations_active_connections",
            "gauge",
            s.operations_active as u64,
        ),
        (
            "tunnelproxy_control_plane_operations_accepted_connections_total",
            "counter",
            s.operations_accepted,
        ),
        (
            "tunnelproxy_control_plane_operations_completed_requests_total",
            "counter",
            s.operations_completed,
        ),
        (
            "tunnelproxy_control_plane_operations_rejected_requests_total",
            "counter",
            s.operations_rejected,
        ),
        (
            "tunnelproxy_control_plane_operations_capacity_rejections_total",
            "counter",
            s.operations_capacity_rejected,
        ),
    ] {
        metric(&mut output, name, kind, value);
    }
    labeled_metrics(
        &mut output,
        "tunnelproxy_control_plane_refresh_total",
        &[
            ("applied", s.refresh_applied),
            ("unchanged", s.refresh_unchanged),
            ("failed", s.refresh_failed),
        ],
    );
    labeled_metrics(
        &mut output,
        "tunnelproxy_control_plane_enrollment_requests_total",
        &[
            ("issued", s.enrollment_issued),
            ("activated", s.enrollment_activated),
            ("rejected", s.enrollment_rejected),
            ("failed", s.enrollment_failed),
        ],
    );
    output
}
fn metric(output: &mut String, name: &str, kind: &str, value: impl std::fmt::Display) {
    let _ = writeln!(output, "# TYPE {name} {kind}");
    let _ = writeln!(output, "{name} {value}");
}
fn labeled_metrics(output: &mut String, name: &str, values: &[(&str, u64)]) {
    let _ = writeln!(output, "# TYPE {name} counter");
    for (outcome, value) in values {
        let _ = writeln!(output, "{name}{{outcome=\"{outcome}\"}} {value}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_is_loopback_only_and_bounded() {
        let config = ControlPlaneOperationsConfig::loopback("127.0.0.1:0".parse().unwrap());
        assert_eq!(config.validate(), Ok(()));
        let mut candidate = config;
        candidate.listen_addr = "0.0.0.0:9091".parse().unwrap();
        assert_eq!(
            candidate.validate(),
            Err(ControlPlaneOperationsConfigError::NonLoopbackListener)
        );
        let mut candidate = config;
        candidate.max_concurrent_connections = 0;
        assert_eq!(
            candidate.validate(),
            Err(ControlPlaneOperationsConfigError::InvalidConnectionLimit)
        );
    }
    #[test]
    fn metrics_have_only_fixed_labels_and_no_identity_values() {
        let telemetry = ControlPlaneTelemetry::default();
        telemetry.initialize(7, true);
        telemetry.mark_ready();
        telemetry.enrollment_outcome(EnrollmentRequestOutcome::Issued);
        let rendered = render_metrics(telemetry.snapshot());
        assert!(rendered.contains("tunnelproxy_control_plane_ready 1\n"));
        assert!(rendered.contains("outcome=\"issued\""));
        assert!(!rendered.contains("agent-dev"));
        assert!(!rendered.contains("tunnel-dev"));
        assert!(!rendered.contains("127.0.0.1"));
    }
}
