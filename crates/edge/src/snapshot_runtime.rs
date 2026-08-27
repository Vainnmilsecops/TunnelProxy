//! Supervision for an Edge data plane backed by the external snapshot service.

use tokio::task::JoinHandle;
use tunnelproxy_common::{shutdown_channel, ShutdownSignal};
use tunnelproxy_control_plane::{
    HttpsRouteBootstrapClient, HttpsRouteClientConfig, HttpsRouteClientError,
    HttpsRouteClientRuntime, SnapshotBootstrapClient, SnapshotBootstrapSource, SnapshotCacheConfig,
    SnapshotClientConfig, SnapshotClientError, SnapshotClientRuntime,
};

use crate::{
    bootstrap_registration_from_snapshot_service, EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeError,
    EdgeRuntimeOutcome, EdgeSessionRouter,
};

pub struct SnapshotAwareEdgeRuntime {
    edge: EdgeRuntime,
    snapshots: SnapshotClientRuntime,
    https_routes: Option<HttpsRouteClientRuntime>,
    bootstrap_source: SnapshotBootstrapSource,
}

impl SnapshotAwareEdgeRuntime {
    pub async fn bind(
        mut edge_config: EdgeRuntimeConfig,
        snapshot_config: SnapshotClientConfig,
    ) -> Result<Self, SnapshotAwareEdgeRuntimeError> {
        let (registration, snapshots) =
            bootstrap_registration_from_snapshot_service(snapshot_config)
                .await
                .map_err(SnapshotAwareEdgeRuntimeError::Bootstrap)?;
        edge_config.multiplex.registration = registration;
        let edge = EdgeRuntime::bind(edge_config)
            .await
            .map_err(SnapshotAwareEdgeRuntimeError::Edge)?;
        Ok(Self {
            edge,
            snapshots,
            https_routes: None,
            bootstrap_source: SnapshotBootstrapSource::Online,
        })
    }

    pub async fn bind_with_cache(
        mut edge_config: EdgeRuntimeConfig,
        snapshot_config: SnapshotClientConfig,
        cache_config: SnapshotCacheConfig,
    ) -> Result<Self, SnapshotAwareEdgeRuntimeError> {
        let (subscription, snapshots, bootstrap_source) =
            SnapshotBootstrapClient::bootstrap_with_cache(snapshot_config, cache_config)
                .await
                .map_err(SnapshotAwareEdgeRuntimeError::Bootstrap)?;
        edge_config.multiplex.registration =
            crate::EdgeRegistrationPolicy::mutual_tls_updates(subscription);
        let edge = EdgeRuntime::bind(edge_config)
            .await
            .map_err(SnapshotAwareEdgeRuntimeError::Edge)?;
        Ok(Self {
            edge,
            snapshots,
            https_routes: None,
            bootstrap_source,
        })
    }

    pub async fn bind_with_https_routes(
        mut edge_config: EdgeRuntimeConfig,
        snapshot_config: SnapshotClientConfig,
        route_config: HttpsRouteClientConfig,
    ) -> Result<Self, SnapshotAwareEdgeRuntimeError> {
        let (registration, snapshots) =
            bootstrap_registration_from_snapshot_service(snapshot_config)
                .await
                .map_err(SnapshotAwareEdgeRuntimeError::Bootstrap)?;
        let (routes, route_client) = HttpsRouteBootstrapClient::bootstrap(route_config)
            .await
            .map_err(SnapshotAwareEdgeRuntimeError::HttpsRouteBootstrap)?;
        let https = edge_config
            .https_ingress
            .as_mut()
            .ok_or(SnapshotAwareEdgeRuntimeError::MissingHttpsIngress)?;
        https.routes = crate::HttpHostRoutes::dynamic(routes);
        edge_config.multiplex.registration = registration;
        let edge = EdgeRuntime::bind(edge_config)
            .await
            .map_err(SnapshotAwareEdgeRuntimeError::Edge)?;
        Ok(Self {
            edge,
            snapshots,
            https_routes: Some(route_client),
            bootstrap_source: SnapshotBootstrapSource::Online,
        })
    }

    pub async fn bind_with_cache_and_https_routes(
        mut edge_config: EdgeRuntimeConfig,
        snapshot_config: SnapshotClientConfig,
        cache_config: SnapshotCacheConfig,
        route_config: HttpsRouteClientConfig,
    ) -> Result<Self, SnapshotAwareEdgeRuntimeError> {
        let (subscription, snapshots, bootstrap_source) =
            SnapshotBootstrapClient::bootstrap_with_cache(snapshot_config, cache_config)
                .await
                .map_err(SnapshotAwareEdgeRuntimeError::Bootstrap)?;
        let (routes, route_client) = HttpsRouteBootstrapClient::bootstrap(route_config)
            .await
            .map_err(SnapshotAwareEdgeRuntimeError::HttpsRouteBootstrap)?;
        let https = edge_config
            .https_ingress
            .as_mut()
            .ok_or(SnapshotAwareEdgeRuntimeError::MissingHttpsIngress)?;
        https.routes = crate::HttpHostRoutes::dynamic(routes);
        edge_config.multiplex.registration =
            crate::EdgeRegistrationPolicy::mutual_tls_updates(subscription);
        let edge = EdgeRuntime::bind(edge_config)
            .await
            .map_err(SnapshotAwareEdgeRuntimeError::Edge)?;
        Ok(Self {
            edge,
            snapshots,
            https_routes: Some(route_client),
            bootstrap_source,
        })
    }

    pub const fn agent_addr(&self) -> std::net::SocketAddr {
        self.edge.agent_addr()
    }

    pub fn router(&self) -> EdgeSessionRouter {
        self.edge.router()
    }

    pub const fn bootstrap_source(&self) -> SnapshotBootstrapSource {
        self.bootstrap_source
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<SnapshotAwareEdgeRuntimeOutcome, SnapshotAwareEdgeRuntimeError> {
        let (trigger, internal_signal) = shutdown_channel();
        let mut edge_task = tokio::spawn(self.edge.run_until_shutdown(internal_signal.clone()));
        let mut snapshot_task =
            tokio::spawn(self.snapshots.run_until_shutdown(internal_signal.clone()));
        let mut route_task = self
            .https_routes
            .map(|runtime| tokio::spawn(runtime.run_until_shutdown(internal_signal)));
        tokio::select! {
            biased;
            () = signal.cancelled() => {
                trigger.shutdown();
                let edge = await_edge(edge_task).await?;
                await_snapshot(snapshot_task).await?;
                await_routes(&mut route_task).await?;
                Ok(SnapshotAwareEdgeRuntimeOutcome { edge })
            }
            result = &mut edge_task => {
                trigger.shutdown();
                let _ = await_snapshot(snapshot_task).await;
                let _ = await_routes(&mut route_task).await;
                match result {
                    Ok(Ok(edge)) => Ok(SnapshotAwareEdgeRuntimeOutcome { edge }),
                    Ok(Err(error)) => Err(SnapshotAwareEdgeRuntimeError::Edge(error)),
                    Err(_) => Err(SnapshotAwareEdgeRuntimeError::EdgeTask),
                }
            }
            result = &mut snapshot_task => {
                trigger.shutdown();
                let edge_result = await_edge(edge_task).await;
                match result {
                    Ok(Ok(())) => {
                        edge_result?;
                        Err(SnapshotAwareEdgeRuntimeError::SnapshotStopped)
                    }
                    Ok(Err(error)) => {
                        let _ = edge_result?;
                        Err(SnapshotAwareEdgeRuntimeError::Snapshot(error))
                    }
                    Err(_) => {
                        let _ = edge_result?;
                        Err(SnapshotAwareEdgeRuntimeError::SnapshotTask)
                    }
                }
            }
            result = next_routes(&mut route_task), if route_task.is_some() => {
                trigger.shutdown();
                let _ = await_edge(edge_task).await;
                let _ = await_snapshot(snapshot_task).await;
                match result {
                    Some(Ok(Ok(()))) => Err(SnapshotAwareEdgeRuntimeError::HttpsRouteStopped),
                    Some(Ok(Err(error))) => Err(SnapshotAwareEdgeRuntimeError::HttpsRoute(error)),
                    Some(Err(_)) | None => Err(SnapshotAwareEdgeRuntimeError::HttpsRouteTask),
                }
            }
        }
    }
}

async fn next_routes(
    task: &mut Option<JoinHandle<Result<(), HttpsRouteClientError>>>,
) -> Option<Result<Result<(), HttpsRouteClientError>, tokio::task::JoinError>> {
    match task {
        Some(task) => Some(task.await),
        None => std::future::pending().await,
    }
}

async fn await_routes(
    task: &mut Option<JoinHandle<Result<(), HttpsRouteClientError>>>,
) -> Result<(), SnapshotAwareEdgeRuntimeError> {
    let Some(task) = task.take() else {
        return Ok(());
    };
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(SnapshotAwareEdgeRuntimeError::HttpsRoute(error)),
        Err(_) => Err(SnapshotAwareEdgeRuntimeError::HttpsRouteTask),
    }
}

async fn await_edge(
    task: JoinHandle<Result<EdgeRuntimeOutcome, EdgeRuntimeError>>,
) -> Result<EdgeRuntimeOutcome, SnapshotAwareEdgeRuntimeError> {
    match task.await {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => Err(SnapshotAwareEdgeRuntimeError::Edge(error)),
        Err(_) => Err(SnapshotAwareEdgeRuntimeError::EdgeTask),
    }
}

async fn await_snapshot(
    task: JoinHandle<Result<(), SnapshotClientError>>,
) -> Result<(), SnapshotAwareEdgeRuntimeError> {
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(SnapshotAwareEdgeRuntimeError::Snapshot(error)),
        Err(_) => Err(SnapshotAwareEdgeRuntimeError::SnapshotTask),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotAwareEdgeRuntimeOutcome {
    pub edge: EdgeRuntimeOutcome,
}

impl SnapshotAwareEdgeRuntimeOutcome {
    pub fn was_forced(self) -> bool {
        self.edge.was_forced()
    }
}

#[derive(Debug)]
pub enum SnapshotAwareEdgeRuntimeError {
    Bootstrap(SnapshotClientError),
    Edge(EdgeRuntimeError),
    Snapshot(SnapshotClientError),
    HttpsRouteBootstrap(HttpsRouteClientError),
    HttpsRoute(HttpsRouteClientError),
    MissingHttpsIngress,
    EdgeTask,
    SnapshotTask,
    SnapshotStopped,
    HttpsRouteTask,
    HttpsRouteStopped,
}

impl std::fmt::Display for SnapshotAwareEdgeRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap(error) => write!(f, "Edge snapshot bootstrap failed: {error}"),
            Self::Edge(error) => error.fmt(f),
            Self::Snapshot(error) => write!(f, "Edge snapshot runtime failed: {error}"),
            Self::HttpsRouteBootstrap(error) => {
                write!(f, "Edge HTTPS route bootstrap failed: {error}")
            }
            Self::HttpsRoute(error) => write!(f, "Edge HTTPS route runtime failed: {error}"),
            Self::MissingHttpsIngress => {
                f.write_str("dynamic HTTPS routes require HTTPS ingress configuration")
            }
            Self::EdgeTask => f.write_str("Edge runtime task stopped unexpectedly"),
            Self::SnapshotTask => f.write_str("Edge snapshot task stopped unexpectedly"),
            Self::SnapshotStopped => f.write_str("Edge snapshot runtime stopped unexpectedly"),
            Self::HttpsRouteTask => f.write_str("Edge HTTPS route task stopped unexpectedly"),
            Self::HttpsRouteStopped => f.write_str("Edge HTTPS route runtime stopped unexpectedly"),
        }
    }
}

impl std::error::Error for SnapshotAwareEdgeRuntimeError {}
