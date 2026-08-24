//! Process-level composition for one durable raw tunnel and one Agent.

use std::net::SocketAddr;

use tokio::task::JoinHandle;
use tracing::{info, warn};
use tunnelproxy_common::{
    shutdown_channel, RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal,
    ShutdownTrigger, TunnelId,
};

use crate::{
    EdgeSessionRouter, MultiplexedEdgeConfig, MultiplexedEdgeConfigError, MultiplexedEdgeRuntime,
    RawIngressExposurePolicy, RawIngressManagerConfig, RawIngressRouteConfig, RawIngressRouteError,
    RawIngressRouteManager,
};

/// Complete configuration for the runnable single-tunnel Edge process.
#[derive(Debug, Clone)]
pub struct EdgeRuntimeConfig {
    pub multiplex: MultiplexedEdgeConfig,
    pub raw_listen_addr: SocketAddr,
    pub tunnel_id: TunnelId,
    pub max_raw_connections: usize,
    pub raw_exposure: RawIngressExposurePolicy,
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
        if self.max_raw_connections == 0 {
            return Err(EdgeRuntimeConfigError::ZeroRawConnections);
        }
        if self.max_raw_connections > u32::MAX as usize {
            return Err(EdgeRuntimeConfigError::RawConnectionLimitTooLarge);
        }
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
        if !self.multiplex.registration.contains_tunnel(&self.tunnel_id)
            && !self.multiplex.registration.has_live_updates()
        {
            return Err(EdgeRuntimeConfigError::RawTunnelNotAuthorized(
                self.tunnel_id.clone(),
            ));
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
    pub agent_sessions: RuntimeShutdownOutcome,
}

impl EdgeRuntimeOutcome {
    pub const fn was_forced(self) -> bool {
        matches!(self.raw_routes, RuntimeShutdownOutcome::Forced { .. })
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
            Self::StartupRollback { startup, .. } => Some(startup),
            Self::TransportTask(_) | Self::TransportStopped => None,
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
        let (transport_trigger, transport_signal) = shutdown_channel();
        let mut transport_task = tokio::spawn(
            self.transport
                .run_until_shutdown(transport_signal, shutdown),
        );
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
                    return shutdown_components(
                        manager,
                        transport_trigger,
                        transport_task,
                        shutdown,
                        self.agent_addr,
                        progress,
                    ).await;
                }
                result = &mut transport_task => {
                    let transport_error = unexpected_transport_result(result);
                    manager
                        .shutdown(shutdown)
                        .await
                        .map_err(EdgeRuntimeError::RouteShutdown)?;
                    return Err(transport_error);
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
}

async fn shutdown_components(
    manager: RawIngressRouteManager,
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
    transport_trigger.shutdown();
    let agent_sessions = await_transport(transport_task).await;
    Ok(EdgeRuntimeOutcome {
        agent_addr,
        raw_addr: progress.raw_addr,
        agent_sessions_seen: progress.agent_sessions_seen,
        route_generations: progress.route_generations,
        successful_recoveries: progress.agent_sessions_seen.saturating_sub(1),
        raw_routes: raw_routes?,
        agent_sessions: agent_sessions?,
    })
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
            agent_sessions: RuntimeShutdownOutcome::Forced {
                completed_tasks: 0,
                aborted_tasks: 1,
            },
        };
        assert!(report.was_forced());
    }
}
