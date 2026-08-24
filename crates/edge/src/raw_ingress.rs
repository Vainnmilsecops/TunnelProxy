//! Raw-ingress listeners with explicit exposure, admission, and drain lifecycle.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{info, warn};

use tunnelproxy_common::{RuntimeShutdownConfig, RuntimeShutdownOutcome, TunnelId};
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

/// Target resolved for each accepted raw ingress connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawIngressRouteTarget {
    /// Compatibility route pinned to one ephemeral transport session.
    TransportSession(TransportSessionId),
    /// Durable route resolved from Edge's cached live-tunnel snapshot.
    Tunnel(TunnelId),
}

/// Explicit network exposure policy for one raw ingress listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RawIngressExposurePolicy {
    /// Development-safe default. The listener must bind a loopback address.
    #[default]
    LoopbackOnly,
    /// Allows a non-loopback listener with a bounded active connection count
    /// for each source IP address.
    Public { max_connections_per_ip: usize },
}

impl std::fmt::Display for RawIngressExposurePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoopbackOnly => f.write_str("loopback"),
            Self::Public { .. } => f.write_str("public"),
        }
    }
}

impl std::fmt::Display for RawIngressRouteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransportSession(session_id) => write!(f, "{session_id}"),
            Self::Tunnel(tunnel_id) => write!(f, "tunnel:{tunnel_id}"),
        }
    }
}

/// Configuration for one raw ingress route. Loopback-only is the default.
#[derive(Debug, Clone)]
pub struct RawIngressRouteConfig {
    pub listen_addr: SocketAddr,
    pub target: RawIngressRouteTarget,
    pub max_concurrent_connections: usize,
    pub exposure: RawIngressExposurePolicy,
    pub drain_timeout: Duration,
}

impl RawIngressRouteConfig {
    pub fn new(listen_addr: SocketAddr, target_session_id: TransportSessionId) -> Self {
        Self {
            listen_addr,
            target: RawIngressRouteTarget::TransportSession(target_session_id),
            max_concurrent_connections: 32,
            exposure: RawIngressExposurePolicy::LoopbackOnly,
            drain_timeout: Duration::from_secs(10),
        }
    }

    pub fn for_tunnel(listen_addr: SocketAddr, tunnel_id: TunnelId) -> Self {
        Self {
            listen_addr,
            target: RawIngressRouteTarget::Tunnel(tunnel_id),
            max_concurrent_connections: 32,
            exposure: RawIngressExposurePolicy::LoopbackOnly,
            drain_timeout: Duration::from_secs(10),
        }
    }

    pub fn validate(&self) -> Result<(), RawIngressConfigError> {
        match self.exposure {
            RawIngressExposurePolicy::LoopbackOnly if !self.listen_addr.ip().is_loopback() => {
                return Err(RawIngressConfigError::NonLoopbackListener(self.listen_addr));
            }
            RawIngressExposurePolicy::Public {
                max_connections_per_ip: 0,
            } => return Err(RawIngressConfigError::ZeroMaxConnectionsPerIp),
            RawIngressExposurePolicy::Public {
                max_connections_per_ip,
            } if max_connections_per_ip > self.max_concurrent_connections => {
                return Err(RawIngressConfigError::PerIpLimitExceedsGlobal);
            }
            RawIngressExposurePolicy::LoopbackOnly | RawIngressExposurePolicy::Public { .. } => {}
        }
        if matches!(
            self.target,
            RawIngressRouteTarget::TransportSession(session_id) if session_id.is_invalid()
        ) {
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
    ZeroMaxConnectionsPerIp,
    PerIpLimitExceedsGlobal,
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
            Self::ZeroMaxConnectionsPerIp => {
                f.write_str("max_connections_per_ip must be greater than zero")
            }
            Self::PerIpLimitExceedsGlobal => {
                f.write_str("max_connections_per_ip cannot exceed the global connection limit")
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIngressRouteStatus {
    pub route_id: RawIngressRouteId,
    pub local_addr: SocketAddr,
    pub target: RawIngressRouteTarget,
    pub state: RawIngressRouteState,
    pub active_connections: usize,
    pub accepted_connections: u64,
    pub global_capacity_rejections: u64,
    pub per_ip_capacity_rejections: u64,
    pub target_unavailable_rejections: u64,
}

/// Handle returned when a route listener is successfully bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIngressRoute {
    pub route_id: RawIngressRouteId,
    pub local_addr: SocketAddr,
    pub target: RawIngressRouteTarget,
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

/// Creates, observes, and drains bounded raw ingress routes.
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
        if let RawIngressRouteTarget::TransportSession(session_id) = &config.target {
            if !self.router.is_connected(*session_id).await {
                return Err(RawIngressRouteError::TargetSessionNotConnected(*session_id));
            }
        }
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(RawIngressRouteError::Bind)?;
        let local_addr = listener.local_addr().map_err(RawIngressRouteError::Bind)?;
        let route_id = self.next_route_id()?;
        let initial_status = RawIngressRouteStatus {
            route_id,
            local_addr,
            target: config.target.clone(),
            state: RawIngressRouteState::Active,
            active_connections: 0,
            accepted_connections: 0,
            global_capacity_rejections: 0,
            per_ip_capacity_rejections: 0,
            target_unavailable_rejections: 0,
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

        let target = config.target.clone();
        let exposure = config.exposure;
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
        info!(
            %route_id,
            %local_addr,
            target = %target,
            exposure = %exposure,
            event = "raw_route_added"
        );
        Ok(RawIngressRoute {
            route_id,
            local_addr,
            target,
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
            .map(|route| route.status.borrow().clone())
            .ok_or(RawIngressRouteError::RouteNotFound(route_id))
    }

    pub async fn list_routes(&self) -> Vec<RawIngressRouteStatus> {
        let state = self.state.lock().await;
        let mut routes: Vec<_> = state
            .routes
            .values()
            .map(|route| route.status.borrow().clone())
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
    let peer_admission = match config.exposure {
        RawIngressExposurePolicy::LoopbackOnly => None,
        RawIngressExposurePolicy::Public {
            max_connections_per_ip,
        } => Some(Arc::new(PeerAdmission::new(max_connections_per_ip))),
    };
    let mut connections = JoinSet::new();
    let mut session_ids = router.subscribe_session_ids();
    let target_session_id = match &config.target {
        RawIngressRouteTarget::TransportSession(session_id) => Some(*session_id),
        RawIngressRouteTarget::Tunnel(_) => None,
    };
    if target_session_id.is_some_and(|session_id| !session_ids.borrow().contains(&session_id)) {
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
            changed = session_ids.changed(), if target_session_id.is_some() => {
                let connected = changed.is_ok()
                    && target_session_id.is_some_and(|session_id| session_ids.borrow().contains(&session_id));
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
                        status.send_modify(|route| {
                            route.global_capacity_rejections =
                                route.global_capacity_rejections.saturating_add(1);
                        });
                        warn!(%route_id, %peer, event = "raw_route_capacity_rejected");
                        drop(ingress);
                        continue;
                    }
                };
                let peer_permit = match &peer_admission {
                    Some(admission) => match admission.try_acquire(peer.ip()) {
                        Some(permit) => Some(permit),
                        None => {
                            status.send_modify(|route| {
                                route.per_ip_capacity_rejections =
                                    route.per_ip_capacity_rejections.saturating_add(1);
                            });
                            warn!(%route_id, %peer, event = "raw_route_per_ip_capacity_rejected");
                            drop(permit);
                            drop(ingress);
                            continue;
                        }
                    },
                    None => None,
                };
                status.send_modify(|route| {
                    route.active_connections += 1;
                    route.accepted_connections = route.accepted_connections.saturating_add(1);
                });
                info!(
                    %route_id,
                    %peer,
                    exposure = %config.exposure,
                    event = "raw_route_connection_accepted"
                );
                spawn_routed_connection(
                    &mut connections,
                    RoutedConnectionTask {
                        route_id,
                        target: config.target.clone(),
                        ingress,
                        router: router.clone(),
                        global_permit: permit,
                        peer_permit,
                        peer,
                        status: status.clone(),
                    },
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

struct RoutedConnectionTask {
    route_id: RawIngressRouteId,
    target: RawIngressRouteTarget,
    ingress: tokio::net::TcpStream,
    router: EdgeSessionRouter,
    global_permit: OwnedSemaphorePermit,
    peer_permit: Option<PeerAdmissionPermit>,
    peer: SocketAddr,
    status: watch::Sender<RawIngressRouteStatus>,
}

fn spawn_routed_connection(connections: &mut JoinSet<()>, task: RoutedConnectionTask) {
    connections.spawn(async move {
        let RoutedConnectionTask {
            route_id,
            target,
            ingress,
            router,
            global_permit,
            peer_permit,
            peer,
            status,
        } = task;
        let opened = match &target {
            RawIngressRouteTarget::TransportSession(session_id) => {
                router.open_stream_tracked(*session_id, ingress).await
            }
            RawIngressRouteTarget::Tunnel(tunnel_id) => {
                router.open_tunnel_stream_tracked(tunnel_id, ingress).await
            }
        };
        match opened {
            Ok(stream) => {
                let reason = stream.wait_closed().await;
                info!(%route_id, %target, ?reason, event = "raw_route_stream_closed");
            }
            Err(error) => {
                if matches!(
                    error,
                    RouteError::SessionNotFound(_) | RouteError::TunnelNotConnected(_)
                ) {
                    status.send_modify(|route| {
                        route.target_unavailable_rejections =
                            route.target_unavailable_rejections.saturating_add(1);
                    });
                }
                log_route_open_failure(route_id, &target, error);
            }
        }
        status.send_modify(|route| {
            route.active_connections = route.active_connections.saturating_sub(1);
        });
        info!(%route_id, %peer, event = "raw_route_connection_released");
        drop(peer_permit);
        drop(global_permit);
    });
}

#[derive(Debug)]
struct PeerAdmission {
    max_connections_per_ip: usize,
    active: StdMutex<HashMap<IpAddr, usize>>,
}

impl PeerAdmission {
    fn new(max_connections_per_ip: usize) -> Self {
        Self {
            max_connections_per_ip,
            active: StdMutex::new(HashMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, peer: IpAddr) -> Option<PeerAdmissionPermit> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active.get(&peer).copied().unwrap_or(0) >= self.max_connections_per_ip {
            return None;
        }
        *active.entry(peer).or_default() += 1;
        Some(PeerAdmissionPermit {
            admission: Arc::clone(self),
            peer,
        })
    }
}

#[derive(Debug)]
struct PeerAdmissionPermit {
    admission: Arc<PeerAdmission>,
    peer: IpAddr,
}

impl Drop for PeerAdmissionPermit {
    fn drop(&mut self) {
        let mut active = self
            .admission
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(count) = active.get_mut(&self.peer) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(&self.peer);
        }
    }
}

fn log_route_open_failure(
    route_id: RawIngressRouteId,
    target: &RawIngressRouteTarget,
    error: RouteError,
) {
    warn!(%route_id, %target, %error, event = "raw_route_stream_open_failed");
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
        let mut config = RawIngressRouteConfig::new(
            "0.0.0.0:7000".parse().unwrap(),
            TransportSessionId::new(1).unwrap(),
        );
        assert!(matches!(
            config.validate(),
            Err(RawIngressConfigError::NonLoopbackListener(_))
        ));
        config.exposure = RawIngressExposurePolicy::Public {
            max_connections_per_ip: 4,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn public_route_per_ip_limit_is_bounded_by_the_global_limit() {
        let mut config = RawIngressRouteConfig::new(
            "0.0.0.0:7000".parse().unwrap(),
            TransportSessionId::new(1).unwrap(),
        );
        config.max_concurrent_connections = 4;
        config.exposure = RawIngressExposurePolicy::Public {
            max_connections_per_ip: 0,
        };
        assert_eq!(
            config.validate(),
            Err(RawIngressConfigError::ZeroMaxConnectionsPerIp)
        );
        config.exposure = RawIngressExposurePolicy::Public {
            max_connections_per_ip: 5,
        };
        assert_eq!(
            config.validate(),
            Err(RawIngressConfigError::PerIpLimitExceedsGlobal)
        );
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
        config.target = RawIngressRouteTarget::TransportSession(TransportSessionId::INVALID);
        assert!(matches!(
            config.validate(),
            Err(RawIngressConfigError::InvalidTargetSession)
        ));
    }
}
