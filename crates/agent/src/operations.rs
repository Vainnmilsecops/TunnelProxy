//! Bounded loopback-only Agent health, readiness, and metrics endpoint.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    process_logging_snapshot, MultiplexTelemetrySnapshot, ProcessLoggingSnapshot,
    RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal,
};

use crate::{AgentConnectionState, AgentRuntimeStatus, AgentRuntimeStatusHandle};

pub const MIN_OPERATIONS_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_OPERATIONS_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_OPERATIONS_HEADERS: usize = 128;
pub const MAX_OPERATIONS_CONNECTIONS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentOperationsConfig {
    pub listen_addr: SocketAddr,
    pub max_concurrent_connections: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
    pub shutdown: RuntimeShutdownConfig,
}

impl AgentOperationsConfig {
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

    pub fn validate(self) -> Result<(), AgentOperationsConfigError> {
        if !self.listen_addr.ip().is_loopback() {
            return Err(AgentOperationsConfigError::NonLoopbackListener);
        }
        if self.max_concurrent_connections == 0
            || self.max_concurrent_connections > MAX_OPERATIONS_CONNECTIONS
        {
            return Err(AgentOperationsConfigError::InvalidConnectionLimit);
        }
        if self.max_header_bytes < MIN_OPERATIONS_HEADER_BYTES
            || self.max_header_bytes > MAX_OPERATIONS_HEADER_BYTES
        {
            return Err(AgentOperationsConfigError::InvalidHeaderBytes);
        }
        if self.max_headers == 0 || self.max_headers > MAX_OPERATIONS_HEADERS {
            return Err(AgentOperationsConfigError::InvalidHeaderCount);
        }
        if self.header_read_timeout.is_zero() {
            return Err(AgentOperationsConfigError::ZeroHeaderTimeout);
        }
        if self.request_timeout.is_zero() {
            return Err(AgentOperationsConfigError::ZeroRequestTimeout);
        }
        if self.shutdown.drain_timeout.is_zero() {
            return Err(AgentOperationsConfigError::ZeroDrainTimeout);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentOperationsConfigError {
    NonLoopbackListener,
    InvalidConnectionLimit,
    InvalidHeaderBytes,
    InvalidHeaderCount,
    ZeroHeaderTimeout,
    ZeroRequestTimeout,
    ZeroDrainTimeout,
}

impl std::fmt::Display for AgentOperationsConfigError {
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

impl std::error::Error for AgentOperationsConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentOperationsOutcome {
    pub local_addr: SocketAddr,
    pub accepted_connections: u64,
    pub completed_requests: u64,
    pub rejected_requests: u64,
    pub capacity_rejections: u64,
    pub shutdown: RuntimeShutdownOutcome,
}

impl AgentOperationsOutcome {
    pub const fn was_forced(self) -> bool {
        matches!(self.shutdown, RuntimeShutdownOutcome::Forced { .. })
    }
}

#[derive(Debug)]
pub enum AgentOperationsError {
    InvalidConfig(AgentOperationsConfigError),
    Bind(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for AgentOperationsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "invalid operations config: {error}"),
            Self::Bind(error) => write!(formatter, "operations listener bind failed: {error}"),
            Self::Accept(error) => write!(formatter, "operations listener accept failed: {error}"),
        }
    }
}

impl std::error::Error for AgentOperationsError {}

#[derive(Default)]
struct AgentOperationsCounters {
    active_connections: AtomicUsize,
    accepted_connections: AtomicU64,
    completed_requests: AtomicU64,
    rejected_requests: AtomicU64,
    capacity_rejections: AtomicU64,
}

pub struct AgentOperationsRuntime {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: AgentOperationsConfig,
    status: AgentRuntimeStatusHandle,
    counters: Arc<AgentOperationsCounters>,
}

impl AgentOperationsRuntime {
    pub async fn bind(
        config: AgentOperationsConfig,
        status: AgentRuntimeStatusHandle,
    ) -> Result<Self, AgentOperationsError> {
        config
            .validate()
            .map_err(AgentOperationsError::InvalidConfig)?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(AgentOperationsError::Bind)?;
        let local_addr = listener.local_addr().map_err(AgentOperationsError::Bind)?;
        Ok(Self {
            listener,
            local_addr,
            config,
            status,
            counters: Arc::new(AgentOperationsCounters::default()),
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<AgentOperationsOutcome, AgentOperationsError> {
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
                            terminal_error = Some(AgentOperationsError::Accept(error));
                            break;
                        }
                    };
                    let permit = match Arc::clone(&permits).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            self.counters.capacity_rejections.fetch_add(1, Ordering::Relaxed);
                            warn!(%peer, event = "agent_operations_capacity_rejected");
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
                        self.status.clone(),
                        Arc::clone(&self.counters),
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
        Ok(AgentOperationsOutcome {
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
    counters: Arc<AgentOperationsCounters>,
}

impl ActiveConnectionGuard {
    fn new(counters: Arc<AgentOperationsCounters>) -> Self {
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

async fn run_connection(
    socket: TcpStream,
    peer: SocketAddr,
    config: AgentOperationsConfig,
    status: AgentRuntimeStatusHandle,
    counters: Arc<AgentOperationsCounters>,
    _permit: OwnedSemaphorePermit,
    _active: ActiveConnectionGuard,
) {
    let service_counters = Arc::clone(&counters);
    let service = hyper::service::service_fn(move |request| {
        serve_request(request, status.clone(), Arc::clone(&service_counters))
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
        Ok(Ok(())) => info!(%peer, event = "agent_operations_connection_completed"),
        Ok(Err(error)) => warn!(%peer, %error, event = "agent_operations_connection_failed"),
        Err(_) => warn!(%peer, event = "agent_operations_request_timeout"),
    }
}

async fn serve_request(
    request: Request<Incoming>,
    status: AgentRuntimeStatusHandle,
    counters: Arc<AgentOperationsCounters>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let head = request.method() == Method::HEAD;
    let response = if request.method() != Method::GET && !head {
        counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
        plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n", head)
    } else {
        match request.uri().path() {
            "/healthz" => plain_response(StatusCode::OK, "ok\n", head),
            "/readyz" => {
                if status.snapshot().is_ready() {
                    plain_response(StatusCode::OK, "ready\n", head)
                } else {
                    plain_response(StatusCode::SERVICE_UNAVAILABLE, "not ready\n", head)
                }
            }
            "/metrics" => metrics_response(
                &render_metrics(
                    status.snapshot(),
                    status.transport_telemetry(),
                    counters.snapshot(),
                ),
                head,
            ),
            _ => {
                counters.rejected_requests.fetch_add(1, Ordering::Relaxed);
                plain_response(StatusCode::NOT_FOUND, "not found\n", head)
            }
        }
    };
    counters.completed_requests.fetch_add(1, Ordering::Relaxed);
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
struct OperationsCounterSnapshot {
    active_connections: usize,
    accepted_connections: u64,
    completed_requests: u64,
    rejected_requests: u64,
    capacity_rejections: u64,
}

impl AgentOperationsCounters {
    fn snapshot(&self) -> OperationsCounterSnapshot {
        OperationsCounterSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            completed_requests: self.completed_requests.load(Ordering::Relaxed),
            rejected_requests: self.rejected_requests.load(Ordering::Relaxed),
            capacity_rejections: self.capacity_rejections.load(Ordering::Relaxed),
        }
    }
}

fn render_metrics(
    status: AgentRuntimeStatus,
    transport: MultiplexTelemetrySnapshot,
    operations: OperationsCounterSnapshot,
) -> String {
    let mut output = String::with_capacity(2 * 1024);
    metric(&mut output, "tunnelproxy_agent_up", "gauge", 1);
    metric(
        &mut output,
        "tunnelproxy_agent_ready",
        "gauge",
        u8::from(status.is_ready()),
    );
    let _ = writeln!(output, "# TYPE tunnelproxy_agent_connection_state gauge");
    for state in AgentConnectionState::ALL {
        let _ = writeln!(
            output,
            "tunnelproxy_agent_connection_state{{state=\"{}\"}} {}",
            state.as_str(),
            u8::from(status.state == state)
        );
    }
    let _ = writeln!(
        output,
        "# TYPE tunnelproxy_agent_public_reachability_state gauge"
    );
    for state in crate::PublicReachabilityState::ALL {
        let _ = writeln!(
            output,
            "tunnelproxy_agent_public_reachability_state{{state=\"{}\"}} {}",
            state.as_str(),
            u8::from(status.public_reachability_state == state)
        );
    }
    for (name, kind, value) in [
        (
            "tunnelproxy_agent_connection_attempts_total",
            "counter",
            status.connection_attempts,
        ),
        (
            "tunnelproxy_agent_sessions_established_total",
            "counter",
            status.established_sessions,
        ),
        (
            "tunnelproxy_agent_reconnects_total",
            "counter",
            status.successful_reconnects,
        ),
        (
            "tunnelproxy_agent_disconnects_total",
            "counter",
            status.disconnects,
        ),
        (
            "tunnelproxy_agent_connection_failures_total",
            "counter",
            status.connection_failures,
        ),
        (
            "tunnelproxy_agent_consecutive_failures",
            "gauge",
            status.consecutive_failures,
        ),
        (
            "tunnelproxy_agent_public_reachability_attempts_total",
            "counter",
            status.public_reachability_attempts,
        ),
        (
            "tunnelproxy_agent_public_reachability_successes_total",
            "counter",
            status.public_reachability_successes,
        ),
        (
            "tunnelproxy_agent_public_reachability_timeouts_total",
            "counter",
            status.public_reachability_timeouts,
        ),
        (
            "tunnelproxy_agent_public_reachability_cancellations_total",
            "counter",
            status.public_reachability_cancellations,
        ),
        (
            "tunnelproxy_agent_public_reachability_tls_failures_total",
            "counter",
            status.public_reachability_tls_failures,
        ),
        (
            "tunnelproxy_agent_public_reachability_connect_failures_total",
            "counter",
            status.public_reachability_connect_failures,
        ),
        (
            "tunnelproxy_agent_public_reachability_route_failures_total",
            "counter",
            status.public_reachability_route_failures,
        ),
        (
            "tunnelproxy_agent_public_reachability_protocol_failures_total",
            "counter",
            status.public_reachability_protocol_failures,
        ),
        (
            "tunnelproxy_agent_public_reachability_monitor_cycles_total",
            "counter",
            status.public_reachability_monitor_cycles,
        ),
        (
            "tunnelproxy_agent_public_reachability_monitor_failures_total",
            "counter",
            status.public_reachability_monitor_failures,
        ),
        (
            "tunnelproxy_agent_public_reachability_consecutive_failures",
            "gauge",
            status.public_reachability_consecutive_failures,
        ),
        (
            "tunnelproxy_agent_public_reachability_unhealthy_transitions_total",
            "counter",
            status.public_reachability_unhealthy_transitions,
        ),
        (
            "tunnelproxy_agent_public_reachability_recoveries_total",
            "counter",
            status.public_reachability_recoveries,
        ),
        (
            "tunnelproxy_agent_operations_active_connections",
            "gauge",
            operations.active_connections as u64,
        ),
        (
            "tunnelproxy_agent_operations_accepted_connections_total",
            "counter",
            operations.accepted_connections,
        ),
        (
            "tunnelproxy_agent_operations_completed_requests_total",
            "counter",
            operations.completed_requests,
        ),
        (
            "tunnelproxy_agent_operations_rejected_requests_total",
            "counter",
            operations.rejected_requests,
        ),
        (
            "tunnelproxy_agent_operations_capacity_rejections_total",
            "counter",
            operations.capacity_rejections,
        ),
    ] {
        metric(&mut output, name, kind, value);
    }
    render_logging_metrics(&mut output, process_logging_snapshot());
    render_transport_metrics(&mut output, transport);
    output
}

fn render_logging_metrics(output: &mut String, logging: ProcessLoggingSnapshot) {
    for (name, kind, value) in [
        (
            "tunnelproxy_agent_logging_nonblocking_enabled",
            "gauge",
            u64::from(logging.buffer_capacity_events > 0),
        ),
        (
            "tunnelproxy_agent_logging_buffer_capacity_events",
            "gauge",
            logging.buffer_capacity_events,
        ),
        (
            "tunnelproxy_agent_logging_accepted_events_total",
            "counter",
            logging.accepted_events,
        ),
        (
            "tunnelproxy_agent_logging_dropped_events_total",
            "counter",
            logging.dropped_events,
        ),
        (
            "tunnelproxy_agent_logging_oversized_events_total",
            "counter",
            logging.oversized_events,
        ),
        (
            "tunnelproxy_agent_logging_write_failures_total",
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
        "tunnelproxy_agent_transport_active_streams",
        "gauge",
        transport.active_streams,
    );
    metric(
        output,
        "tunnelproxy_agent_transport_peak_active_streams",
        "gauge",
        transport.peak_active_streams,
    );
    let _ = writeln!(
        output,
        "# TYPE tunnelproxy_agent_transport_data_frames_total counter"
    );
    let _ = writeln!(
        output,
        "tunnelproxy_agent_transport_data_frames_total{{direction=\"sent\"}} {}",
        transport.sent_data_frames
    );
    let _ = writeln!(
        output,
        "tunnelproxy_agent_transport_data_frames_total{{direction=\"received\"}} {}",
        transport.received_data_frames
    );
    let _ = writeln!(
        output,
        "# TYPE tunnelproxy_agent_transport_data_bytes_total counter"
    );
    let _ = writeln!(
        output,
        "tunnelproxy_agent_transport_data_bytes_total{{direction=\"sent\"}} {}",
        transport.sent_data_bytes
    );
    let _ = writeln!(
        output,
        "tunnelproxy_agent_transport_data_bytes_total{{direction=\"received\"}} {}",
        transport.received_data_bytes
    );
    for (name, kind, value) in [
        (
            "tunnelproxy_agent_transport_data_admission_waits_total",
            "counter",
            transport.data_admission_waits,
        ),
        (
            "tunnelproxy_agent_transport_data_pipeline_frames",
            "gauge",
            transport.data_pipeline_frames,
        ),
        (
            "tunnelproxy_agent_transport_data_pipeline_capacity_frames",
            "gauge",
            transport.data_pipeline_capacity_frames,
        ),
        (
            "tunnelproxy_agent_transport_peak_data_pipeline_frames",
            "gauge",
            transport.peak_data_pipeline_frames,
        ),
        (
            "tunnelproxy_agent_transport_flow_control_resets_total",
            "counter",
            transport.flow_control_resets,
        ),
        (
            "tunnelproxy_agent_transport_control_burst_yields_total",
            "counter",
            transport.control_burst_yields,
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
    use crate::AgentRuntime;

    fn status() -> AgentRuntimeStatusHandle {
        AgentRuntime::new(crate::AgentRuntimeConfig::new(
            "127.0.0.1:7100".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        ))
        .unwrap()
        .status_handle()
    }

    #[test]
    fn configuration_is_loopback_only_and_bounded() {
        let config = AgentOperationsConfig::loopback("127.0.0.1:0".parse().unwrap());
        assert_eq!(config.validate(), Ok(()));
        let mut candidate = config;
        candidate.listen_addr = "0.0.0.0:9091".parse().unwrap();
        assert_eq!(
            candidate.validate(),
            Err(AgentOperationsConfigError::NonLoopbackListener)
        );
        let mut candidate = config;
        candidate.max_concurrent_connections = 0;
        assert_eq!(
            candidate.validate(),
            Err(AgentOperationsConfigError::InvalidConnectionLimit)
        );
        let mut candidate = config;
        candidate.request_timeout = Duration::ZERO;
        assert_eq!(
            candidate.validate(),
            Err(AgentOperationsConfigError::ZeroRequestTimeout)
        );
    }

    #[test]
    fn metric_rendering_has_fixed_state_labels_and_no_identity_values() {
        let status = status();
        status.record_public_reachability_success(3);
        status.record_public_reachability_failure(
            2,
            Some(crate::PublicReachabilityFailureClass::Tls),
            false,
        );
        status.record_public_reachability_failure(0, None, true);
        status.record_public_reachability_monitor_failure(
            crate::PublicReachabilityFailureClass::RouteUnavailable,
            1,
        );
        status.record_public_reachability_monitor_success();
        let rendered = render_metrics(
            status.snapshot(),
            MultiplexTelemetrySnapshot {
                sent_data_frames: 2,
                sent_data_bytes: 17,
                received_data_frames: 3,
                received_data_bytes: 29,
                data_pipeline_capacity_frames: 128,
                ..MultiplexTelemetrySnapshot::default()
            },
            OperationsCounterSnapshot {
                active_connections: 1,
                accepted_connections: 2,
                completed_requests: 3,
                rejected_requests: 4,
                capacity_rejections: 5,
            },
        );
        for state in AgentConnectionState::ALL {
            assert!(rendered.contains(&format!("state=\"{}\"", state.as_str())));
        }
        for state in crate::PublicReachabilityState::ALL {
            assert!(rendered.contains(&format!(
                "tunnelproxy_agent_public_reachability_state{{state=\"{}\"}}",
                state.as_str()
            )));
        }
        assert!(rendered.contains("tunnelproxy_agent_ready 0"));
        assert!(rendered.contains("tunnelproxy_agent_logging_nonblocking_enabled 0"));
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_attempts_total 7"));
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_successes_total 2"));
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_timeouts_total 1"));
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_cancellations_total 1"));
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_tls_failures_total 1"));
        assert!(
            rendered.contains("tunnelproxy_agent_public_reachability_state{state=\"healthy\"} 1")
        );
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_monitor_cycles_total 2"));
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_monitor_failures_total 1"));
        assert!(rendered
            .contains("tunnelproxy_agent_public_reachability_unhealthy_transitions_total 1"));
        assert!(rendered.contains("tunnelproxy_agent_public_reachability_recoveries_total 1"));
        let mut logging = String::new();
        render_logging_metrics(
            &mut logging,
            ProcessLoggingSnapshot {
                buffer_capacity_events: 8,
                dropped_events: 3,
                ..ProcessLoggingSnapshot::default()
            },
        );
        assert!(logging.contains("tunnelproxy_agent_logging_nonblocking_enabled 1"));
        assert!(logging.contains("tunnelproxy_agent_logging_dropped_events_total 3"));
        assert!(rendered
            .contains("tunnelproxy_agent_transport_data_frames_total{direction=\"sent\"} 2"));
        assert!(rendered
            .contains("tunnelproxy_agent_transport_data_bytes_total{direction=\"received\"} 29"));
        assert!(rendered.contains("tunnelproxy_agent_transport_data_pipeline_capacity_frames 128"));
        assert!(!rendered.contains("agent-dev"));
        assert!(!rendered.contains("tunnel-dev"));
        assert!(!rendered.contains("127.0.0.1"));
    }
}
