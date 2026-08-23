//! Loopback raw-ingress listeners with explicit route and drain lifecycle.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{info, warn};

use tunnelproxy_common::{RuntimeShutdownConfig, RuntimeShutdownOutcome};
use tunnelproxy_protocol::TransportSessionId;

use crate::multiplex::{EdgeSessionRouter, RouteError};

/// Process-local identifier for one raw ingress listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawIngressRouteId(u64);

impl RawIngressRouteId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RawIngressRouteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "raw-route#{}", self.0)
    }
}

/// Global bounds for a [`RawIngressRouteManager`].
#[derive(Debug, Clone, Copy)]
pub struct RawIngressManagerConfig {
    pub max_routes: usize,
}

impl Default for RawIngressManagerConfig {
    fn default() -> Self {
        Self { max_routes: 32 }
    }
}

impl RawIngressManagerConfig {
    pub fn validate(self) -> Result<(), RawIngressConfigError> {
        if self.max_routes == 0 {
            return Err(RawIngressConfigError::ZeroMaxRoutes);
        }
        Ok(())
    }
}

/// Configuration for one ephemeral loopback ingress route.
#[derive(Debug, Clone, Copy)]
pub struct RawIngressRouteConfig {
    pub listen_addr: SocketAddr,
    pub target_session_id: TransportSessionId,
    pub max_concurrent_connections: usize,
    pub drain_timeout: Duration,
}

impl RawIngressRouteConfig {
    pub fn new(listen_addr: SocketAddr, target_session_id: TransportSessionId) -> Self {
        Self {
            listen_addr,
            target_session_id,
            max_concurrent_connections: 32,
            drain_timeout: Duration::from_secs(10),
        }
    }

    pub fn validate(self) -> Result<(), RawIngressConfigError> {
        if !self.listen_addr.ip().is_loopback() {
            return Err(RawIngressConfigError::NonLoopbackListener(self.listen_addr));
        }
        if self.target_session_id.is_invalid() {
            return Err(RawIngressConfigError::InvalidTargetSession);
        }
        if self.max_concurrent_connections == 0 {
            return Err(RawIngressConfigError::ZeroMaxConnections);
        }
        if self.max_concurrent_connections > u32::MAX as usize {
            return Err(RawIngressConfigError::ConnectionLimitTooLarge);
        }
        if self.drain_timeout.is_zero() {
            return Err(RawIngressConfigError::ZeroDrainTimeout);
        }
        Ok(())
    }
}

/// Invalid raw-ingress manager or route configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawIngressConfigError {
    ZeroMaxRoutes,
    NonLoopbackListener(SocketAddr),
    InvalidTargetSession,
    ZeroMaxConnections,
    ConnectionLimitTooLarge,
    ZeroDrainTimeout,
}

impl std::fmt::Display for RawIngressConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaxRoutes => f.write_str("max_routes must be greater than zero"),
            Self::NonLoopbackListener(addr) => {
                write!(f, "raw ingress listener must be loopback, got {addr}")
            }
            Self::InvalidTargetSession => f.write_str("target_session_id must be non-zero"),
            Self::ZeroMaxConnections => {
                f.write_str("max_concurrent_connections must be greater than zero")
            }
            Self::ConnectionLimitTooLarge => {
                f.write_str("max_concurrent_connections must fit in u32")
            }
            Self::ZeroDrainTimeout => f.write_str("drain_timeout must be greater than zero"),
        }
    }
}

impl std::error::Error for RawIngressConfigError {}

/// Observable route lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawIngressRouteState {
    Active,
    Draining,
    TargetDisconnected,
    Removed,
}

/// Immutable route identity and its current counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawIngressRouteStatus {
    pub route_id: RawIngressRouteId,
    pub local_addr: SocketAddr,
    pub target_session_id: TransportSessionId,
    pub state: RawIngressRouteState,
    pub active_connections: usize,
}

/// Handle returned when a route listener is successfully bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawIngressRoute {
    pub route_id: RawIngressRouteId,
    pub local_addr: SocketAddr,
    pub target_session_id: TransportSessionId,
}

/// Raw route lifecycle operation failure.
#[derive(Debug)]
pub enum RawIngressRouteError {
    InvalidConfig(RawIngressConfigError),
    Bind(std::io::Error),
    RouteCapacityExceeded,
    RouteIdExhausted,
    TargetSessionNotConnected(TransportSessionId),
    RouteNotFound(RawIngressRouteId),
    DrainTimeout(RawIngressRouteId),
    RouteTaskStopped(RawIngressRouteId),
    ManagerShuttingDown,
}

impl std::fmt::Display for RawIngressRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid raw ingress config: {error}"),
            Self::Bind(error) => write!(f, "raw ingress bind failed: {error}"),
            Self::RouteCapacityExceeded => f.write_str("raw ingress route capacity exceeded"),
            Self::RouteIdExhausted => f.write_str("raw ingress route ID exhausted"),
            Self::TargetSessionNotConnected(id) => {
                write!(f, "target transport session {id} is not connected")
            }
            Self::RouteNotFound(id) => write!(f, "raw ingress route {id} was not found"),
            Self::DrainTimeout(id) => write!(f, "raw ingress route {id} drain timed out"),
            Self::RouteTaskStopped(id) => {
                write!(f, "raw ingress route {id} stopped before removal")
            }
            Self::ManagerShuttingDown => f.write_str("raw ingress route manager is shutting down"),
        }
    }
}

impl std::error::Error for RawIngressRouteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
            Self::Bind(error) => Some(error),
            _ => None,
        }
    }
}

struct RouteControl {
    stop: watch::Sender<bool>,
    status: watch::Receiver<RawIngressRouteStatus>,
    drain_timeout: Duration,
    task: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct ManagerState {
    routes: HashMap<RawIngressRouteId, RouteControl>,
    shutting_down: bool,
}

/// Creates, observes, and drains bounded loopback ingress routes.
#[derive(Clone)]
pub struct RawIngressRouteManager {
    router: EdgeSessionRouter,
    config: RawIngressManagerConfig,
    state: Arc<Mutex<ManagerState>>,
    route_ids: Arc<AtomicU64>,
}

impl RawIngressRouteManager {
    pub fn new(
        router: EdgeSessionRouter,
        config: RawIngressManagerConfig,
    ) -> Result<Self, RawIngressRouteError> {
        config
            .validate()
            .map_err(RawIngressRouteError::InvalidConfig)?;
        Ok(Self {
            router,
            config,
            state: Arc::new(Mutex::new(ManagerState::default())),
            route_ids: Arc::new(AtomicU64::new(0)),
        })
    }

    pub async fn add_route(
        &self,
        config: RawIngressRouteConfig,
    ) -> Result<RawIngressRoute, RawIngressRouteError> {
        config
            .validate()
            .map_err(RawIngressRouteError::InvalidConfig)?;
        if self.state.lock().await.shutting_down {
            return Err(RawIngressRouteError::ManagerShuttingDown);
        }
        if !self.router.is_connected(config.target_session_id).await {
            return Err(RawIngressRouteError::TargetSessionNotConnected(
                config.target_session_id,
            ));
        }
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(RawIngressRouteError::Bind)?;
        let local_addr = listener.local_addr().map_err(RawIngressRouteError::Bind)?;
        let route_id = self.next_route_id()?;
        let initial_status = RawIngressRouteStatus {
            route_id,
            local_addr,
            target_session_id: config.target_session_id,
            state: RawIngressRouteState::Active,
            active_connections: 0,
        };
        let (stop, stop_rx) = watch::channel(false);
        let (status_tx, status) = watch::channel(initial_status);

        {
            let mut state = self.state.lock().await;
            if state.shutting_down {
                return Err(RawIngressRouteError::ManagerShuttingDown);
            }
            if state.routes.len() >= self.config.max_routes {
                return Err(RawIngressRouteError::RouteCapacityExceeded);
            }
            state.routes.insert(
                route_id,
                RouteControl {
                    stop,
                    status,
                    drain_timeout: config.drain_timeout,
                    task: None,
                },
            );
        }

        let route_task = tokio::spawn(run_route(
            route_id,
            listener,
            config,
            self.router.clone(),
            stop_rx,
            status_tx,
            Arc::downgrade(&self.state),
        ));
        if let Some(route) = self.state.lock().await.routes.get_mut(&route_id) {
            route.task = Some(route_task);
        }
        info!(%route_id, %local_addr, target = %config.target_session_id, event = "raw_route_added");
        Ok(RawIngressRoute {
            route_id,
            local_addr,
            target_session_id: config.target_session_id,
        })
    }

    pub async fn get_route(
        &self,
        route_id: RawIngressRouteId,
    ) -> Result<RawIngressRouteStatus, RawIngressRouteError> {
        self.state
            .lock()
            .await
            .routes
            .get(&route_id)
            .map(|route| *route.status.borrow())
            .ok_or(RawIngressRouteError::RouteNotFound(route_id))
    }

    pub async fn list_routes(&self) -> Vec<RawIngressRouteStatus> {
        let state = self.state.lock().await;
        let mut routes: Vec<_> = state
            .routes
            .values()
            .map(|route| *route.status.borrow())
            .collect();
        routes.sort_unstable_by_key(|route| route.route_id);
        routes
    }

    /// Stops accepting immediately. Existing streams continue until close.
    pub async fn remove_route(
        &self,
        route_id: RawIngressRouteId,
    ) -> Result<(), RawIngressRouteError> {
        let stop = self
            .state
            .lock()
            .await
            .routes
            .get(&route_id)
            .map(|route| route.stop.clone())
            .ok_or(RawIngressRouteError::RouteNotFound(route_id))?;
        stop.send_replace(true);
        Ok(())
    }

    /// Stops accepting and waits for all routed streams under the configured
    /// route drain deadline.
    pub async fn drain_route(
        &self,
        route_id: RawIngressRouteId,
    ) -> Result<(), RawIngressRouteError> {
        let (stop, mut status, drain_timeout) = {
            let state = self.state.lock().await;
            let route = state
                .routes
                .get(&route_id)
                .ok_or(RawIngressRouteError::RouteNotFound(route_id))?;
            (
                route.stop.clone(),
                route.status.clone(),
                route.drain_timeout,
            )
        };
        stop.send_replace(true);
        let drained = async {
            loop {
                if status.borrow().state == RawIngressRouteState::Removed {
                    return Ok(());
                }
                if status.changed().await.is_err() {
                    return Err(RawIngressRouteError::RouteTaskStopped(route_id));
                }
            }
        };
        tokio::time::timeout(drain_timeout, drained)
            .await
            .map_err(|_| RawIngressRouteError::DrainTimeout(route_id))?
    }

    /// Waits until a route task has released its listener and removed itself.
    /// An already-removed route is considered complete.
    pub async fn wait_until_removed(
        &self,
        route_id: RawIngressRouteId,
    ) -> Result<(), RawIngressRouteError> {
        let mut status = match self.state.lock().await.routes.get(&route_id) {
            Some(route) => route.status.clone(),
            None => return Ok(()),
        };
        loop {
            if status.borrow().state == RawIngressRouteState::Removed {
                return Ok(());
            }
            if status.changed().await.is_err() {
                return if self.state.lock().await.routes.contains_key(&route_id) {
                    Err(RawIngressRouteError::RouteTaskStopped(route_id))
                } else {
                    Ok(())
                };
            }
        }
    }

    /// Stops all listeners and drains every routed connection under one
    /// process-level deadline. The manager cannot be reused after this call.
    pub async fn shutdown(
        &self,
        shutdown: RuntimeShutdownConfig,
    ) -> Result<RuntimeShutdownOutcome, RawIngressRouteError> {
        shutdown.validate().map_err(|_| {
            RawIngressRouteError::InvalidConfig(RawIngressConfigError::ZeroDrainTimeout)
        })?;
        let route_count = {
            let mut state = self.state.lock().await;
            state.shutting_down = true;
            for route in state.routes.values() {
                route.stop.send_replace(true);
            }
            state.routes.len()
        };

        let drained = async {
            loop {
                if self.state.lock().await.routes.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        };
        if tokio::time::timeout(shutdown.drain_timeout, drained)
            .await
            .is_ok()
        {
            return Ok(RuntimeShutdownOutcome::Drained {
                completed_tasks: route_count,
            });
        }

        let (remaining, tasks) = {
            let mut state = self.state.lock().await;
            let remaining = state.routes.len();
            let tasks = state
                .routes
                .drain()
                .filter_map(|(_, mut route)| route.task.take())
                .collect::<Vec<_>>();
            (remaining, tasks)
        };
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        Ok(RuntimeShutdownOutcome::Forced {
            completed_tasks: route_count.saturating_sub(remaining),
            aborted_tasks: remaining,
        })
    }

    fn next_route_id(&self) -> Result<RawIngressRouteId, RawIngressRouteError> {
        let previous = self
            .route_ids
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RawIngressRouteError::RouteIdExhausted)?;
        previous
            .checked_add(1)
            .map(RawIngressRouteId)
            .ok_or(RawIngressRouteError::RouteIdExhausted)
    }
}

async fn run_route(
    route_id: RawIngressRouteId,
    listener: TcpListener,
    config: RawIngressRouteConfig,
    router: EdgeSessionRouter,
    mut stop: watch::Receiver<bool>,
    status: watch::Sender<RawIngressRouteStatus>,
    manager: Weak<Mutex<ManagerState>>,
) {
    let permits = Arc::new(Semaphore::new(config.max_concurrent_connections));
    let mut connections = JoinSet::new();
    let mut session_ids = router.subscribe_session_ids();
    if !session_ids.borrow().contains(&config.target_session_id) {
        status.send_modify(|route| route.state = RawIngressRouteState::TargetDisconnected);
    }
    loop {
        if status.borrow().state == RawIngressRouteState::TargetDisconnected {
            break;
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    status.send_modify(|route| route.state = RawIngressRouteState::Draining);
                    break;
                }
            }
            changed = session_ids.changed() => {
                let connected = changed.is_ok()
                    && session_ids.borrow().contains(&config.target_session_id);
                if !connected {
                    status.send_modify(|route| route.state = RawIngressRouteState::TargetDisconnected);
                    break;
                }
            }
            accepted = listener.accept() => {
                let (ingress, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        warn!(%route_id, error = %error, event = "raw_route_accept_failed");
                        break;
                    }
                };
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%route_id, %peer, event = "raw_route_capacity_rejected");
                        drop(ingress);
                        continue;
                    }
                };
                status.send_modify(|route| route.active_connections += 1);
                spawn_routed_connection(
                    &mut connections,
                    route_id,
                    config.target_session_id,
                    ingress,
                    router.clone(),
                    permit,
                    status.clone(),
                );
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }

    drop(listener);
    while connections.join_next().await.is_some() {}
    status.send_modify(|route| route.state = RawIngressRouteState::Removed);
    if let Some(manager) = manager.upgrade() {
        manager.lock().await.routes.remove(&route_id);
    }
    info!(%route_id, event = "raw_route_removed");
}

fn spawn_routed_connection(
    connections: &mut JoinSet<()>,
    route_id: RawIngressRouteId,
    session_id: TransportSessionId,
    ingress: tokio::net::TcpStream,
    router: EdgeSessionRouter,
    permit: OwnedSemaphorePermit,
    status: watch::Sender<RawIngressRouteStatus>,
) {
    connections.spawn(async move {
        match router.open_stream_tracked(session_id, ingress).await {
            Ok(stream) => {
                let reason = stream.wait_closed().await;
                info!(%route_id, %session_id, ?reason, event = "raw_route_stream_closed");
            }
            Err(error) => {
                log_route_open_failure(route_id, session_id, error);
            }
        }
        status.send_modify(|route| {
            route.active_connections = route.active_connections.saturating_sub(1);
        });
        drop(permit);
    });
}

fn log_route_open_failure(
    route_id: RawIngressRouteId,
    session_id: TransportSessionId,
    error: RouteError,
) {
    warn!(%route_id, %session_id, %error, event = "raw_route_stream_open_failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_config_defaults_are_valid() {
        let config = RawIngressRouteConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            TransportSessionId::new(1).unwrap(),
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn public_route_listener_is_rejected() {
        let config = RawIngressRouteConfig::new(
            "0.0.0.0:7000".parse().unwrap(),
            TransportSessionId::new(1).unwrap(),
        );
        assert!(matches!(
            config.validate(),
            Err(RawIngressConfigError::NonLoopbackListener(_))
        ));
    }

    #[test]
    fn zero_route_bounds_are_rejected() {
        assert!(matches!(
            RawIngressManagerConfig { max_routes: 0 }.validate(),
            Err(RawIngressConfigError::ZeroMaxRoutes)
        ));
        let mut config = RawIngressRouteConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            TransportSessionId::new(1).unwrap(),
        );
        config.max_concurrent_connections = 0;
        assert!(matches!(
            config.validate(),
            Err(RawIngressConfigError::ZeroMaxConnections)
        ));
        config.max_concurrent_connections = 1;
        config.drain_timeout = Duration::ZERO;
        assert!(matches!(
            config.validate(),
            Err(RawIngressConfigError::ZeroDrainTimeout)
        ));
        config.drain_timeout = Duration::from_secs(1);
        config.target_session_id = TransportSessionId::INVALID;
        assert!(matches!(
            config.validate(),
            Err(RawIngressConfigError::InvalidTargetSession)
        ));
    }
}
