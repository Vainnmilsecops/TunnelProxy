//! Supervision for an Edge data plane backed by the external snapshot service.

use tokio::task::JoinHandle;
use tunnelproxy_common::{shutdown_channel, ShutdownSignal};
use tunnelproxy_control_plane::{SnapshotClientConfig, SnapshotClientError, SnapshotClientRuntime};

use crate::{
    bootstrap_registration_from_snapshot_service, EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeError,
    EdgeRuntimeOutcome, EdgeSessionRouter,
};

pub struct SnapshotAwareEdgeRuntime {
    edge: EdgeRuntime,
    snapshots: SnapshotClientRuntime,
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
        Ok(Self { edge, snapshots })
    }

    pub const fn agent_addr(&self) -> std::net::SocketAddr {
        self.edge.agent_addr()
    }

    pub fn router(&self) -> EdgeSessionRouter {
        self.edge.router()
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<SnapshotAwareEdgeRuntimeOutcome, SnapshotAwareEdgeRuntimeError> {
        let (trigger, internal_signal) = shutdown_channel();
        let mut edge_task = tokio::spawn(self.edge.run_until_shutdown(internal_signal.clone()));
        let mut snapshot_task = tokio::spawn(self.snapshots.run_until_shutdown(internal_signal));
        tokio::select! {
            biased;
            () = signal.cancelled() => {
                trigger.shutdown();
                let edge = await_edge(edge_task).await?;
                await_snapshot(snapshot_task).await?;
                Ok(SnapshotAwareEdgeRuntimeOutcome { edge })
            }
            result = &mut edge_task => {
                trigger.shutdown();
                let _ = await_snapshot(snapshot_task).await;
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
        }
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
    pub const fn was_forced(self) -> bool {
        self.edge.was_forced()
    }
}

#[derive(Debug)]
pub enum SnapshotAwareEdgeRuntimeError {
    Bootstrap(SnapshotClientError),
    Edge(EdgeRuntimeError),
    Snapshot(SnapshotClientError),
    EdgeTask,
    SnapshotTask,
    SnapshotStopped,
}

impl std::fmt::Display for SnapshotAwareEdgeRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap(error) => write!(f, "Edge snapshot bootstrap failed: {error}"),
            Self::Edge(error) => error.fmt(f),
            Self::Snapshot(error) => write!(f, "Edge snapshot runtime failed: {error}"),
            Self::EdgeTask => f.write_str("Edge runtime task stopped unexpectedly"),
            Self::SnapshotTask => f.write_str("Edge snapshot task stopped unexpectedly"),
            Self::SnapshotStopped => f.write_str("Edge snapshot runtime stopped unexpectedly"),
        }
    }
}

impl std::error::Error for SnapshotAwareEdgeRuntimeError {}
