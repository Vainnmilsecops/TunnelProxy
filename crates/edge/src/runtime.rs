//! Process-level composition for one loopback raw tunnel and one Agent.

use std::net::SocketAddr;

use tokio::task::JoinHandle;
use tracing::{info, warn};
use tunnelproxy_common::{
    shutdown_channel, RuntimeShutdownConfig, RuntimeShutdownOutcome, ShutdownSignal,
    ShutdownTrigger,
};

use crate::{
    MultiplexedEdgeConfig, MultiplexedEdgeConfigError, MultiplexedEdgeRuntime,
    RawIngressManagerConfig, RawIngressRouteConfig, RawIngressRouteError, RawIngressRouteManager,
};

/// Complete configuration for the runnable single-tunnel Edge process.
#[derive(Debug, Clone)]
pub struct EdgeRuntimeConfig {
    pub multiplex: MultiplexedEdgeConfig,
    pub raw_listen_addr: SocketAddr,
    pub max_raw_connections: usize,
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
            max_raw_connections: 32,
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
        if !self.raw_listen_addr.ip().is_loopback() {
            return Err(EdgeRuntimeConfigError::NonLoopbackRawListener(
                self.raw_listen_addr,
            ));
        }
        if self.max_raw_connections == 0 {
            return Err(EdgeRuntimeConfigError::ZeroRawConnections);
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

    /// Keeps the Agent listener alive across disconnects and rebinds the raw
    /// route to each replacement session until process shutdown.
    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<EdgeRuntimeOutcome, EdgeRuntimeError> {
        let router = self.transport.router();
        let manager =
            RawIngressRouteManager::new(router.clone(), RawIngressManagerConfig { max_routes: 1 })
                .map_err(EdgeRuntimeError::RouteStartup)?;
        let (transport_trigger, transport_signal) = shutdown_channel();
        let shutdown = self.config.shutdown;
        let mut transport_task = tokio::spawn(
            self.transport
                .run_until_shutdown(transport_signal, shutdown),
        );
        let mut sessions = router.subscribe_session_ids();

        let mut active = None;
        let mut progress = RuntimeProgress::default();
        loop {
            if active.is_none() {
                let available = { sessions.borrow().first().copied() };
                if let Some(session_id) = available {
                    let mut route_config =
                        RawIngressRouteConfig::new(self.config.raw_listen_addr, session_id);
                    route_config.max_concurrent_connections = self.config.max_raw_connections;
                    route_config.drain_timeout = shutdown.drain_timeout;
                    match manager.add_route(route_config).await {
                        Ok(route) => {
                            progress.agent_sessions_seen =
                                progress.agent_sessions_seen.saturating_add(1);
                            progress.route_generations =
                                progress.route_generations.saturating_add(1);
                            progress.raw_addr = Some(route.local_addr);
                            info!(
                                %session_id,
                                raw_addr = %route.local_addr,
                                generation = progress.route_generations,
                                event = "raw_route_rebound",
                                "raw route bound to live Agent session"
                            );
                            active = Some((session_id, route));
                            continue;
                        }
                        Err(RawIngressRouteError::TargetSessionNotConnected(_)) => {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        Err(route_error) => {
                            let startup = progress.route_generations == 0;
                            let cleanup = shutdown_components(
                                manager,
                                transport_trigger,
                                transport_task,
                                shutdown,
                                self.agent_addr,
                                progress,
                            )
                            .await;
                            return match (startup, cleanup) {
                                (true, Ok(_)) => Err(EdgeRuntimeError::RouteStartup(route_error)),
                                (true, Err(cleanup)) => Err(EdgeRuntimeError::StartupRollback {
                                    startup: route_error,
                                    cleanup: Box::new(cleanup),
                                }),
                                (false, Ok(_)) => Err(EdgeRuntimeError::RouteRecovery(route_error)),
                                (false, Err(cleanup)) => Err(cleanup),
                            };
                        }
                    }
                }

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
                    result = &mut transport_task => return Err(unexpected_transport_result(result)),
                    changed = sessions.changed() => {
                        if changed.is_err() {
                            let cleanup = shutdown_components(
                                manager,
                                transport_trigger,
                                transport_task,
                                shutdown,
                                self.agent_addr,
                                progress,
                            ).await;
                            return match cleanup {
                                Ok(_) => Err(EdgeRuntimeError::TransportStopped),
                                Err(error) => Err(error),
                            };
                        }
                    }
                }
                continue;
            }

            let (session_id, route) = active.expect("active route checked above");
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
                changed = sessions.changed() => {
                    let connected = changed.is_ok()
                        && sessions.borrow().contains(&session_id);
                    if !connected {
                        warn!(
                            %session_id,
                            generation = progress.route_generations,
                            event = "route_recovery_started",
                            "Agent disconnected; waiting for replacement"
                        );
                        let removal_manager = manager.clone();
                        let removed = async move {
                            removal_manager.wait_until_removed(route.route_id).await
                        };
                        tokio::pin!(removed);
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
                                manager.shutdown(shutdown).await
                                    .map_err(EdgeRuntimeError::RouteShutdown)?;
                                return Err(transport_error);
                            }
                            result = &mut removed => {
                                result.map_err(EdgeRuntimeError::RouteRecovery)?;
                            }
                        }
                        active = None;
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
        successful_recoveries: progress.route_generations.saturating_sub(1),
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
    fn public_raw_listener_is_rejected() {
        let mut config = EdgeRuntimeConfig::dev_defaults();
        config.raw_listen_addr = "0.0.0.0:7000".parse().unwrap();
        assert!(matches!(
            config.validate(),
            Err(EdgeRuntimeConfigError::NonLoopbackRawListener(_))
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
