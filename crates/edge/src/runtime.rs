//! Process-level composition for one durable raw tunnel and one Agent.

use std::net::SocketAddr;

use tokio::task::JoinHandle;
use tracing::{info, warn};
use tunnelproxy_common::{
    shutdown_channel, RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal,
    ShutdownTrigger, TunnelId,
};

use crate::operations::{EdgeIngressMetricsSource, EdgeOperationsControl, EdgeOperationsRuntime};
use crate::{
    EdgeOperationsConfig, EdgeOperationsConfigError, EdgeOperationsError, EdgeOperationsOutcome,
    EdgeSessionRouter, HttpIngressConfig, HttpIngressConfigError, HttpIngressError,
    HttpIngressExposurePolicy, HttpIngressOutcome, HttpIngressRuntime, MultiplexedEdgeConfig,
    MultiplexedEdgeConfigError, MultiplexedEdgeRuntime, RawIngressExposurePolicy,
    RawIngressManagerConfig, RawIngressRouteConfig, RawIngressRouteError, RawIngressRouteManager,
};

/// Complete configuration for the runnable single-tunnel Edge process.
#[derive(Debug, Clone)]
pub struct EdgeRuntimeConfig {
    pub multiplex: MultiplexedEdgeConfig,
    pub raw_listen_addr: SocketAddr,
    pub tunnel_id: TunnelId,
    pub max_raw_connections: usize,
    pub raw_exposure: RawIngressExposurePolicy,
    /// When present, HTTPS replaces the raw listener for this process.
    pub https_ingress: Option<HttpIngressConfig>,
    /// Optional loopback-only health, readiness, and Prometheus endpoint.
    pub operations: Option<EdgeOperationsConfig>,
    pub shutdown: RuntimeShutdownConfig,
}

impl EdgeRuntimeConfig {
    pub fn dev_defaults() -> Self {
        let mut multiplex = MultiplexedEdgeConfig::dev_defaults();
        multiplex.agent_listener.max_agent_sessions = 1;
        Self {
            multiplex,
            raw_listen_addr: "127.0.0.1:7000"
                .parse()
                .expect("hardcoded raw listener is valid"),
            tunnel_id: TunnelId::new("tunnel-dev").expect("hardcoded TunnelId is valid"),
            max_raw_connections: 32,
            raw_exposure: RawIngressExposurePolicy::LoopbackOnly,
            https_ingress: None,
            operations: None,
            shutdown: RuntimeShutdownConfig::default(),
        }
    }

    pub fn validate(&self) -> Result<(), EdgeRuntimeConfigError> {
        self.multiplex
            .validate()
            .map_err(EdgeRuntimeConfigError::Multiplex)?;
        if self.multiplex.agent_listener.max_agent_sessions != 1 {
            return Err(EdgeRuntimeConfigError::AgentCapacityMustBeOne);
        }
        if let Some(https) = &self.https_ingress {
            https.validate().map_err(EdgeRuntimeConfigError::Https)?;
            if !https.routes.contains_tunnel(&self.tunnel_id) {
                return Err(EdgeRuntimeConfigError::HttpsTunnelNotConfigured(
                    self.tunnel_id.clone(),
                ));
            }
            if matches!(https.exposure, HttpIngressExposurePolicy::Public { .. }) {
                if !self.multiplex.security.is_tls() {
                    return Err(EdgeRuntimeConfigError::PublicHttpsRequiresMutualTls);
                }
                if !self
                    .multiplex
                    .registration
                    .is_dynamic_snapshot_authorization()
                {
                    return Err(EdgeRuntimeConfigError::PublicHttpsRequiresLiveAuthorization);
                }
            }
        } else if self.max_raw_connections == 0 {
            return Err(EdgeRuntimeConfigError::ZeroRawConnections);
        } else if self.max_raw_connections > u32::MAX as usize {
            return Err(EdgeRuntimeConfigError::RawConnectionLimitTooLarge);
        } else {
            match self.raw_exposure {
                RawIngressExposurePolicy::LoopbackOnly => {
                    if !self.raw_listen_addr.ip().is_loopback() {
                        return Err(EdgeRuntimeConfigError::NonLoopbackRawListener(
                            self.raw_listen_addr,
                        ));
                    }
                }
                RawIngressExposurePolicy::Public {
                    max_connections_per_ip,
                } => {
                    if max_connections_per_ip == 0 {
                        return Err(EdgeRuntimeConfigError::ZeroRawConnectionsPerIp);
                    }
                    if max_connections_per_ip > self.max_raw_connections {
                        return Err(EdgeRuntimeConfigError::RawConnectionsPerIpExceedGlobal);
                    }
                    if !self.multiplex.security.is_tls() {
                        return Err(EdgeRuntimeConfigError::PublicRawRequiresMutualTls);
                    }
                    if !self
                        .multiplex
                        .registration
                        .is_dynamic_snapshot_authorization()
                    {
                        return Err(EdgeRuntimeConfigError::PublicRawRequiresLiveAuthorization);
                    }
                }
            }
        }
        if !self.multiplex.registration.contains_tunnel(&self.tunnel_id)
            && !self.multiplex.registration.has_live_updates()
        {
            return Err(EdgeRuntimeConfigError::RawTunnelNotAuthorized(
                self.tunnel_id.clone(),
            ));
        }
        if let Some(operations) = self.operations {
            operations
                .validate()
                .map_err(EdgeRuntimeConfigError::Operations)?;
        }
        self.shutdown
            .validate()
            .map_err(|_| EdgeRuntimeConfigError::ZeroDrainTimeout)
    }
}

/// Invalid process-level Edge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeRuntimeConfigError {
    Multiplex(MultiplexedEdgeConfigError),
    AgentCapacityMustBeOne,
    NonLoopbackRawListener(SocketAddr),
    ZeroRawConnections,
    RawConnectionLimitTooLarge,
    ZeroRawConnectionsPerIp,
    RawConnectionsPerIpExceedGlobal,
    PublicRawRequiresMutualTls,
    PublicRawRequiresLiveAuthorization,
    Https(HttpIngressConfigError),
    HttpsTunnelNotConfigured(TunnelId),
    PublicHttpsRequiresMutualTls,
    PublicHttpsRequiresLiveAuthorization,
    Operations(EdgeOperationsConfigError),
    RawTunnelNotAuthorized(TunnelId),
    ZeroDrainTimeout,
}

impl std::fmt::Display for EdgeRuntimeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Multiplex(error) => write!(f, "invalid multiplex config: {error}"),
            Self::AgentCapacityMustBeOne => {
                f.write_str("single-tunnel Edge requires max_agent_sessions = 1")
            }
            Self::NonLoopbackRawListener(addr) => {
                write!(f, "raw listener must use a loopback address, got {addr}")
            }
            Self::ZeroRawConnections => {
                f.write_str("max_raw_connections must be greater than zero")
            }
            Self::RawConnectionLimitTooLarge => f.write_str("max_raw_connections must fit in u32"),
            Self::ZeroRawConnectionsPerIp => {
                f.write_str("max_raw_connections_per_ip must be greater than zero")
            }
            Self::RawConnectionsPerIpExceedGlobal => {
                f.write_str("max_raw_connections_per_ip cannot exceed max_raw_connections")
            }
            Self::PublicRawRequiresMutualTls => {
                f.write_str("public raw ingress requires mutual TLS for Agent transport")
            }
            Self::PublicRawRequiresLiveAuthorization => {
                f.write_str("public raw ingress requires dynamic snapshot authorization")
            }
            Self::Https(error) => write!(f, "invalid HTTPS ingress: {error}"),
            Self::HttpsTunnelNotConfigured(tunnel_id) => write!(
                f,
                "HTTPS routes do not contain the configured TunnelId {tunnel_id}"
            ),
            Self::PublicHttpsRequiresMutualTls => {
                f.write_str("public HTTPS ingress requires mutual TLS for Agent transport")
            }
            Self::PublicHttpsRequiresLiveAuthorization => {
                f.write_str("public HTTPS ingress requires dynamic snapshot authorization")
            }
            Self::Operations(error) => write!(f, "invalid operations endpoint: {error}"),
            Self::RawTunnelNotAuthorized(tunnel_id) => write!(
                f,
                "raw TunnelId {tunnel_id} is absent from the registration policy"
            ),
            Self::ZeroDrainTimeout => f.write_str("drain_timeout must be greater than zero"),
        }
    }
}

impl std::error::Error for EdgeRuntimeConfigError {}

/// Ordered shutdown result from the Edge process supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeRuntimeOutcome {
    pub agent_addr: SocketAddr,
    pub raw_addr: Option<SocketAddr>,
    pub agent_sessions_seen: u64,
    pub route_generations: u64,
    pub successful_recoveries: u64,
    pub raw_routes: RuntimeShutdownOutcome,
    pub https_ingress: Option<HttpIngressOutcome>,
    pub operations: Option<EdgeOperationsOutcome>,
    pub agent_sessions: RuntimeShutdownOutcome,
}

impl EdgeRuntimeOutcome {
    pub fn was_forced(self) -> bool {
        matches!(self.raw_routes, RuntimeShutdownOutcome::Forced { .. })
            || self
                .https_ingress
                .is_some_and(HttpIngressOutcome::was_forced)
            || self
                .operations
                .is_some_and(EdgeOperationsOutcome::was_forced)
            || matches!(self.agent_sessions, RuntimeShutdownOutcome::Forced { .. })
    }
}

/// Failure to start, supervise, or roll back the Edge process runtime.
#[derive(Debug)]
pub enum EdgeRuntimeError {
    InvalidConfig(EdgeRuntimeConfigError),
    Bind(std::io::Error),
    RouteStartup(RawIngressRouteError),
    RouteRecovery(RawIngressRouteError),
    Transport(std::io::Error),
    TransportTask(String),
    TransportStopped,
    RouteShutdown(RawIngressRouteError),
    HttpsStartup(HttpIngressError),
    Https(HttpIngressError),
    HttpsTask(String),
    HttpsStopped,
    OperationsStartup(EdgeOperationsError),
    Operations(EdgeOperationsError),
    OperationsTask(String),
    OperationsStopped,
    OperationsStartupRollback {
        startup: EdgeOperationsError,
        cleanup: RawIngressRouteError,
    },
    StartupRollback {
        startup: RawIngressRouteError,
        cleanup: Box<EdgeRuntimeError>,
    },
}

impl std::fmt::Display for EdgeRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid Edge runtime config: {error}"),
            Self::Bind(error) => write!(f, "Edge listener bind failed: {error}"),
            Self::RouteStartup(error) => write!(f, "raw route startup failed: {error}"),
            Self::RouteRecovery(error) => write!(f, "raw route recovery failed: {error}"),
            Self::Transport(error) => write!(f, "Edge transport failed: {error}"),
            Self::TransportTask(error) => write!(f, "Edge transport task failed: {error}"),
            Self::TransportStopped => f.write_str("Edge transport stopped unexpectedly"),
            Self::RouteShutdown(error) => write!(f, "raw route shutdown failed: {error}"),
            Self::HttpsStartup(error) => write!(f, "HTTPS ingress startup failed: {error}"),
            Self::Https(error) => write!(f, "HTTPS ingress failed: {error}"),
            Self::HttpsTask(error) => write!(f, "HTTPS ingress task failed: {error}"),
            Self::HttpsStopped => f.write_str("HTTPS ingress stopped unexpectedly"),
            Self::OperationsStartup(error) => {
                write!(f, "operations endpoint startup failed: {error}")
            }
            Self::Operations(error) => write!(f, "operations endpoint failed: {error}"),
            Self::OperationsTask(error) => write!(f, "operations endpoint task failed: {error}"),
            Self::OperationsStopped => f.write_str("operations endpoint stopped unexpectedly"),
            Self::OperationsStartupRollback { startup, cleanup } => write!(
                f,
                "operations endpoint startup failed ({startup}) and raw-route rollback also failed ({cleanup})"
            ),
            Self::StartupRollback { startup, cleanup } => write!(
                f,
                "raw route startup failed ({startup}) and rollback also failed ({cleanup})"
            ),
        }
    }
}

impl std::error::Error for EdgeRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
            Self::Bind(error) | Self::Transport(error) => Some(error),
            Self::RouteStartup(error) | Self::RouteRecovery(error) | Self::RouteShutdown(error) => {
                Some(error)
            }
            Self::HttpsStartup(error) | Self::Https(error) => Some(error),
            Self::OperationsStartup(error) | Self::Operations(error) => Some(error),
            Self::OperationsStartupRollback { startup, .. } => Some(startup),
            Self::StartupRollback { startup, .. } => Some(startup),
            Self::TransportTask(_)
            | Self::TransportStopped
            | Self::HttpsTask(_)
            | Self::HttpsStopped
            | Self::OperationsTask(_)
            | Self::OperationsStopped => None,
        }
    }
}

/// Bound Edge runtime ready to accept one Agent transport.
pub struct EdgeRuntime {
    config: EdgeRuntimeConfig,
    transport: MultiplexedEdgeRuntime,
    agent_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, Default)]
struct RuntimeProgress {
    raw_addr: Option<SocketAddr>,
    agent_sessions_seen: u64,
    route_generations: u64,
}

struct RunningOperations {
    control: EdgeOperationsControl,
    trigger: ShutdownTrigger,
    task: JoinHandle<Result<EdgeOperationsOutcome, EdgeOperationsError>>,
}

fn spawn_operations(runtime: EdgeOperationsRuntime) -> RunningOperations {
    let local_addr = runtime.local_addr();
    let control = runtime.control();
    let (trigger, signal) = shutdown_channel();
    let task = tokio::spawn(runtime.run_until_shutdown(signal));
    info!(%local_addr, event = "operations_endpoint_bound");
    RunningOperations {
        control,
        trigger,
        task,
    }
}

fn mark_operations_draining(operations: &Option<RunningOperations>) {
    if let Some(operations) = operations {
        operations.control.begin_draining();
    }
}

async fn poll_operations(
    operations: &mut Option<RunningOperations>,
) -> Result<Result<EdgeOperationsOutcome, EdgeOperationsError>, tokio::task::JoinError> {
    match operations {
        Some(operations) => (&mut operations.task).await,
        None => std::future::pending().await,
    }
}

impl EdgeRuntime {
    pub async fn bind(config: EdgeRuntimeConfig) -> Result<Self, EdgeRuntimeError> {
        config.validate().map_err(EdgeRuntimeError::InvalidConfig)?;
        let transport = MultiplexedEdgeRuntime::bind(config.multiplex.clone())
            .await
            .map_err(EdgeRuntimeError::Bind)?;
        let agent_addr = transport.agent_addr();
        Ok(Self {
            config,
            transport,
            agent_addr,
        })
    }

    pub const fn agent_addr(&self) -> SocketAddr {
        self.agent_addr
    }

    /// Returns a cached-state routing and authorization observation handle.
    pub fn router(&self) -> EdgeSessionRouter {
        self.transport.router()
    }

    /// Keeps one durable raw route bound while its authenticated Agent session
    /// disconnects and reconnects with fresh ephemeral session IDs.
    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<EdgeRuntimeOutcome, EdgeRuntimeError> {
        if let Some(https) = self.config.https_ingress.clone() {
            return self.run_https_until_shutdown(https, signal).await;
        }
        let router = self.transport.router();
        let manager =
            RawIngressRouteManager::new(router.clone(), RawIngressManagerConfig { max_routes: 1 })
                .map_err(EdgeRuntimeError::RouteStartup)?;
        let shutdown = self.config.shutdown;
        let mut route_config = RawIngressRouteConfig::for_tunnel(
            self.config.raw_listen_addr,
            self.config.tunnel_id.clone(),
        );
        route_config.max_concurrent_connections = self.config.max_raw_connections;
        route_config.exposure = self.config.raw_exposure;
        route_config.drain_timeout = shutdown.drain_timeout;
        let route = manager
            .add_route(route_config)
            .await
            .map_err(EdgeRuntimeError::RouteStartup)?;
        let operations_runtime = match self.config.operations {
            Some(mut operations_config) => {
                operations_config.shutdown = shutdown;
                match EdgeOperationsRuntime::bind(
                    operations_config,
                    router.clone(),
                    self.config.tunnel_id.clone(),
                    EdgeIngressMetricsSource::Raw {
                        manager: manager.clone(),
                        route_id: route.route_id,
                    },
                )
                .await
                {
                    Ok(runtime) => Some(runtime),
                    Err(startup) => {
                        return match manager.shutdown(shutdown).await {
                            Ok(_) => Err(EdgeRuntimeError::OperationsStartup(startup)),
                            Err(cleanup) => Err(EdgeRuntimeError::OperationsStartupRollback {
                                startup,
                                cleanup,
                            }),
                        };
                    }
                }
            }
            None => None,
        };
        let (transport_trigger, transport_signal) = shutdown_channel();
        let mut transport_task = tokio::spawn(
            self.transport
                .run_until_shutdown(transport_signal, shutdown),
        );
        let mut operations = operations_runtime.map(spawn_operations);
        let mut tunnels = router.subscribe_tunnels();
        let mut current_session = None;
        let mut progress = RuntimeProgress {
            raw_addr: Some(route.local_addr),
            agent_sessions_seen: 0,
            route_generations: 1,
        };
        info!(
            tunnel_id = %self.config.tunnel_id,
            raw_addr = %route.local_addr,
            event = "durable_raw_route_bound",
            "raw route bound before Agent availability"
        );
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => {
                    mark_operations_draining(&operations);
                    return shutdown_components(
                        manager,
                        operations,
                        transport_trigger,
                        transport_task,
                        shutdown,
                        self.agent_addr,
                        progress,
                    ).await;
                }
                result = &mut transport_task => {
                    let transport_error = unexpected_transport_result(result);
                    mark_operations_draining(&operations);
                    let route_shutdown = manager
                        .shutdown(shutdown)
                        .await
                        .map_err(EdgeRuntimeError::RouteShutdown);
                    let operations_shutdown = shutdown_operations(operations).await;
                    route_shutdown?;
                    operations_shutdown?;
                    return Err(transport_error);
                }
                result = poll_operations(&mut operations) => {
                    let operations_error = unexpected_operations_result(result);
                    let route_shutdown = manager
                        .shutdown(shutdown)
                        .await
                        .map_err(EdgeRuntimeError::RouteShutdown);
                    transport_trigger.shutdown();
                    let _ = await_transport(transport_task).await;
                    route_shutdown?;
                    return Err(operations_error);
                }
                changed = tunnels.changed() => {
                    if changed.is_err() {
                        return Err(EdgeRuntimeError::TransportStopped);
                    }
                    let next_session = tunnels
                        .borrow()
                        .iter()
                        .find(|(tunnel_id, _)| tunnel_id == &self.config.tunnel_id)
                        .map(|(_, session_id)| *session_id);
                    if next_session != current_session {
                        match next_session {
                            Some(session_id) => {
                                progress.agent_sessions_seen = progress.agent_sessions_seen.saturating_add(1);
                                info!(
                                    %session_id,
                                    tunnel_id = %self.config.tunnel_id,
                                    event = "durable_tunnel_connected",
                                    "durable tunnel now resolves to a live session"
                                );
                            }
                            None => warn!(
                                tunnel_id = %self.config.tunnel_id,
                                event = "durable_tunnel_disconnected",
                                "raw listener remains bound while tunnel is unavailable"
                            ),
                        }
                        current_session = next_session;
                    }
                }
            }
        }
    }

    async fn run_https_until_shutdown(
        self,
        mut https_config: HttpIngressConfig,
        signal: ShutdownSignal,
    ) -> Result<EdgeRuntimeOutcome, EdgeRuntimeError> {
        let router = self.transport.router();
        let shutdown = self.config.shutdown;
        https_config.shutdown = shutdown;
        let ingress = HttpIngressRuntime::bind(https_config, router.clone())
            .await
            .map_err(EdgeRuntimeError::HttpsStartup)?;
        let https_addr = ingress.local_addr();
        let https_status = ingress.status_handle();
        let operations_runtime = match self.config.operations {
            Some(mut operations_config) => {
                operations_config.shutdown = shutdown;
                Some(
                    EdgeOperationsRuntime::bind(
                        operations_config,
                        router.clone(),
                        self.config.tunnel_id.clone(),
                        EdgeIngressMetricsSource::Https(https_status),
                    )
                    .await
                    .map_err(EdgeRuntimeError::OperationsStartup)?,
                )
            }
            None => None,
        };
        let (transport_trigger, transport_signal) = shutdown_channel();
        let (https_trigger, https_signal) = shutdown_channel();
        let mut transport_task = tokio::spawn(
            self.transport
                .run_until_shutdown(transport_signal, shutdown),
        );
        let mut https_task = tokio::spawn(ingress.run_until_shutdown(https_signal));
        let mut operations = operations_runtime.map(spawn_operations);
        let mut tunnels = router.subscribe_tunnels();
        let mut current_session = None;
        let mut sessions_seen = 0_u64;
        info!(%https_addr, tunnel_id = %self.config.tunnel_id, event = "https_ingress_bound");

        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => {
                    mark_operations_draining(&operations);
                    https_trigger.shutdown();
                    let https = await_https(https_task).await;
                    let operations = shutdown_operations(operations).await;
                    transport_trigger.shutdown();
                    let agent_sessions = await_transport(transport_task).await;
                    return Ok(EdgeRuntimeOutcome {
                        agent_addr: self.agent_addr,
                        raw_addr: None,
                        agent_sessions_seen: sessions_seen,
                        route_generations: 1,
                        successful_recoveries: sessions_seen.saturating_sub(1),
                        raw_routes: RuntimeShutdownOutcome::Drained { completed_tasks: 0 },
                        https_ingress: Some(https?),
                        operations: operations?,
                        agent_sessions: agent_sessions?,
                    });
                }
                result = &mut transport_task => {
                    let error = unexpected_transport_result(result);
                    mark_operations_draining(&operations);
                    https_trigger.shutdown();
                    let _ = await_https(https_task).await;
                    let _ = shutdown_operations(operations).await;
                    return Err(error);
                }
                result = &mut https_task => {
                    mark_operations_draining(&operations);
                    let _ = shutdown_operations(operations).await;
                    transport_trigger.shutdown();
                    let _ = await_transport(transport_task).await;
                    return Err(unexpected_https_result(result));
                }
                result = poll_operations(&mut operations) => {
                    let operations_error = unexpected_operations_result(result);
                    https_trigger.shutdown();
                    let _ = await_https(https_task).await;
                    transport_trigger.shutdown();
                    let _ = await_transport(transport_task).await;
                    return Err(operations_error);
                }
                changed = tunnels.changed() => {
                    if changed.is_err() {
                        return Err(EdgeRuntimeError::TransportStopped);
                    }
                    let next_session = tunnels
                        .borrow()
                        .iter()
                        .find(|(tunnel_id, _)| tunnel_id == &self.config.tunnel_id)
                        .map(|(_, session_id)| *session_id);
                    if next_session != current_session {
                        if next_session.is_some() {
                            sessions_seen = sessions_seen.saturating_add(1);
                        }
                        current_session = next_session;
                    }
                }
            }
        }
    }
}

async fn shutdown_components(
    manager: RawIngressRouteManager,
    operations: Option<RunningOperations>,
    transport_trigger: ShutdownTrigger,
    transport_task: JoinHandle<std::io::Result<RuntimeShutdownOutcome>>,
    shutdown: RuntimeShutdownConfig,
    agent_addr: SocketAddr,
    progress: RuntimeProgress,
) -> Result<EdgeRuntimeOutcome, EdgeRuntimeError> {
    let raw_routes = manager
        .shutdown(shutdown)
        .await
        .map_err(EdgeRuntimeError::RouteShutdown);
    let operations = shutdown_operations(operations).await;
    transport_trigger.shutdown();
    let agent_sessions = await_transport(transport_task).await;
    Ok(EdgeRuntimeOutcome {
        agent_addr,
        raw_addr: progress.raw_addr,
        agent_sessions_seen: progress.agent_sessions_seen,
        route_generations: progress.route_generations,
        successful_recoveries: progress.agent_sessions_seen.saturating_sub(1),
        raw_routes: raw_routes?,
        https_ingress: None,
        operations: operations?,
        agent_sessions: agent_sessions?,
    })
}

async fn shutdown_operations(
    operations: Option<RunningOperations>,
) -> Result<Option<EdgeOperationsOutcome>, EdgeRuntimeError> {
    let Some(operations) = operations else {
        return Ok(None);
    };
    operations.trigger.shutdown();
    await_operations(operations.task).await.map(Some)
}

async fn await_operations(
    task: JoinHandle<Result<EdgeOperationsOutcome, EdgeOperationsError>>,
) -> Result<EdgeOperationsOutcome, EdgeRuntimeError> {
    match task.await {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => Err(EdgeRuntimeError::Operations(error)),
        Err(error) => Err(EdgeRuntimeError::OperationsTask(error.to_string())),
    }
}

fn unexpected_operations_result(
    result: Result<Result<EdgeOperationsOutcome, EdgeOperationsError>, tokio::task::JoinError>,
) -> EdgeRuntimeError {
    match result {
        Ok(Ok(_)) => EdgeRuntimeError::OperationsStopped,
        Ok(Err(error)) => EdgeRuntimeError::Operations(error),
        Err(error) => EdgeRuntimeError::OperationsTask(error.to_string()),
    }
}

async fn await_https(
    task: JoinHandle<Result<HttpIngressOutcome, HttpIngressError>>,
) -> Result<HttpIngressOutcome, EdgeRuntimeError> {
    match task.await {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => Err(EdgeRuntimeError::Https(error)),
        Err(error) => Err(EdgeRuntimeError::HttpsTask(error.to_string())),
    }
}

fn unexpected_https_result(
    result: Result<Result<HttpIngressOutcome, HttpIngressError>, tokio::task::JoinError>,
) -> EdgeRuntimeError {
    match result {
        Ok(Ok(_)) => EdgeRuntimeError::HttpsStopped,
        Ok(Err(error)) => EdgeRuntimeError::Https(error),
        Err(error) => EdgeRuntimeError::HttpsTask(error.to_string()),
    }
}

async fn await_transport(
    task: JoinHandle<std::io::Result<RuntimeShutdownOutcome>>,
) -> Result<RuntimeShutdownOutcome, EdgeRuntimeError> {
    match task.await {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => Err(EdgeRuntimeError::Transport(error)),
        Err(error) => Err(EdgeRuntimeError::TransportTask(error.to_string())),
    }
}

fn unexpected_transport_result(
    result: Result<std::io::Result<RuntimeShutdownOutcome>, tokio::task::JoinError>,
) -> EdgeRuntimeError {
    match result {
        Ok(Ok(_)) => EdgeRuntimeError::TransportStopped,
        Ok(Err(error)) => EdgeRuntimeError::Transport(error),
        Err(error) => EdgeRuntimeError::TransportTask(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_single_agent_and_valid() {
        let config = EdgeRuntimeConfig::dev_defaults();
        assert_eq!(config.multiplex.agent_listener.max_agent_sessions, 1);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn public_raw_listener_requires_explicit_secure_dynamic_policy() {
        let mut config = EdgeRuntimeConfig::dev_defaults();
        config.raw_listen_addr = "0.0.0.0:7000".parse().unwrap();
        assert!(matches!(
            config.validate(),
            Err(EdgeRuntimeConfigError::NonLoopbackRawListener(_))
        ));
        config.raw_exposure = RawIngressExposurePolicy::Public {
            max_connections_per_ip: 1,
        };
        assert!(matches!(
            config.validate(),
            Err(EdgeRuntimeConfigError::PublicRawRequiresMutualTls)
        ));
        config.raw_exposure = RawIngressExposurePolicy::Public {
            max_connections_per_ip: 0,
        };
        assert!(matches!(
            config.validate(),
            Err(EdgeRuntimeConfigError::ZeroRawConnectionsPerIp)
        ));
        config.raw_exposure = RawIngressExposurePolicy::Public {
            max_connections_per_ip: 33,
        };
        assert!(matches!(
            config.validate(),
            Err(EdgeRuntimeConfigError::RawConnectionsPerIpExceedGlobal)
        ));
    }

    #[test]
    fn raw_tunnel_must_exist_in_registration_policy() {
        let mut config = EdgeRuntimeConfig::dev_defaults();
        config.tunnel_id = TunnelId::new("unconfigured-tunnel").unwrap();
        assert!(matches!(
            config.validate(),
            Err(EdgeRuntimeConfigError::RawTunnelNotAuthorized(_))
        ));
    }

    #[test]
    fn shutdown_report_detects_forced_stage() {
        let report = EdgeRuntimeOutcome {
            agent_addr: "127.0.0.1:7100".parse().unwrap(),
            raw_addr: None,
            agent_sessions_seen: 1,
            route_generations: 1,
            successful_recoveries: 0,
            raw_routes: RuntimeShutdownOutcome::Drained { completed_tasks: 0 },
            https_ingress: None,
            operations: None,
            agent_sessions: RuntimeShutdownOutcome::Forced {
                completed_tasks: 0,
                aborted_tasks: 1,
            },
        };
        assert!(report.was_forced());
    }
}
