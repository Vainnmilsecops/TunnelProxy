use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tunnelproxy_common::{shutdown_channel, ShutdownSignal};

use crate::{
    PersistentSnapshotAuthority, PersistentSnapshotAuthorityError, SnapshotDistributionServer,
    SnapshotPublishOutcome, SnapshotServerConfig, SnapshotServerError, SnapshotVersion,
    SqliteSnapshotRepository,
};

#[derive(Debug, Clone)]
pub struct ControlPlaneRuntimeConfig {
    pub database_path: PathBuf,
    pub refresh_interval: Duration,
    pub snapshot_server: SnapshotServerConfig,
}

impl ControlPlaneRuntimeConfig {
    pub fn validate(&self) -> Result<(), ControlPlaneRuntimeError> {
        if self.database_path.as_os_str().is_empty() || self.refresh_interval.is_zero() {
            return Err(ControlPlaneRuntimeError::InvalidConfig);
        }
        self.snapshot_server
            .validate()
            .map_err(|error| match error {
                SnapshotServerError::InvalidConfig => ControlPlaneRuntimeError::InvalidConfig,
                other => ControlPlaneRuntimeError::Server(other),
            })
    }
}

pub struct ControlPlaneRuntime {
    authority: PersistentSnapshotAuthority,
    server: SnapshotDistributionServer,
    refresh_interval: Duration,
}

impl ControlPlaneRuntime {
    pub async fn bind(config: ControlPlaneRuntimeConfig) -> Result<Self, ControlPlaneRuntimeError> {
        config.validate()?;
        let database_path = config.database_path;
        let repository = tokio::task::spawn_blocking(move || {
            SqliteSnapshotRepository::open(database_path).map(Arc::new)
        })
        .await
        .map_err(|_| ControlPlaneRuntimeError::StorageTask)?
        .map_err(ControlPlaneRuntimeError::Repository)?;
        let authority = PersistentSnapshotAuthority::open(repository)
            .await
            .map_err(ControlPlaneRuntimeError::Authority)?;
        let server =
            SnapshotDistributionServer::bind(config.snapshot_server, authority.subscribe())
                .await
                .map_err(ControlPlaneRuntimeError::Server)?;
        Ok(Self {
            authority,
            server,
            refresh_interval: config.refresh_interval,
        })
    }

    pub const fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    pub fn current_version(&self) -> SnapshotVersion {
        self.authority.current().version()
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<ControlPlaneRuntimeOutcome, ControlPlaneRuntimeError> {
        let local_addr = self.server.local_addr();
        let (server_trigger, server_signal) = shutdown_channel();
        let mut server_task = tokio::spawn(self.server.run_until_shutdown(server_signal));
        let mut refresh = tokio::time::interval_at(
            Instant::now() + self.refresh_interval,
            self.refresh_interval,
        );
        refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut applied_refreshes = 0_u64;
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => {
                    server_trigger.shutdown();
                    await_server(server_task).await?;
                    return Ok(ControlPlaneRuntimeOutcome {
                        listen_addr: local_addr,
                        applied_refreshes,
                    });
                }
                result = &mut server_task => {
                    return match result {
                        Ok(Ok(())) => Err(ControlPlaneRuntimeError::ServerStopped),
                        Ok(Err(error)) => Err(ControlPlaneRuntimeError::Server(error)),
                        Err(error) => Err(ControlPlaneRuntimeError::ServerTask(error.to_string())),
                    };
                }
                _ = refresh.tick() => {
                    match self.authority.refresh_from_repository().await {
                        Ok(SnapshotPublishOutcome::Applied { .. }) => {
                            applied_refreshes = applied_refreshes.saturating_add(1);
                        }
                        Ok(SnapshotPublishOutcome::Unchanged { .. }) => {}
                        Err(error) => {
                            server_trigger.shutdown();
                            let _ = await_server(server_task).await;
                            return Err(ControlPlaneRuntimeError::Authority(error));
                        }
                    }
                }
            }
        }
    }
}

async fn await_server(
    task: JoinHandle<Result<(), SnapshotServerError>>,
) -> Result<(), ControlPlaneRuntimeError> {
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ControlPlaneRuntimeError::Server(error)),
        Err(error) => Err(ControlPlaneRuntimeError::ServerTask(error.to_string())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPlaneRuntimeOutcome {
    pub listen_addr: std::net::SocketAddr,
    pub applied_refreshes: u64,
}

#[derive(Debug)]
pub enum ControlPlaneRuntimeError {
    InvalidConfig,
    Repository(crate::SnapshotRepositoryError),
    Authority(PersistentSnapshotAuthorityError),
    Server(SnapshotServerError),
    StorageTask,
    ServerTask(String),
    ServerStopped,
}

impl std::fmt::Display for ControlPlaneRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("Control Plane runtime configuration is invalid"),
            Self::Repository(error) => error.fmt(f),
            Self::Authority(error) => error.fmt(f),
            Self::Server(error) => error.fmt(f),
            Self::StorageTask => f.write_str("snapshot storage worker stopped unexpectedly"),
            Self::ServerTask(_) => f.write_str("snapshot server task stopped unexpectedly"),
            Self::ServerStopped => f.write_str("snapshot server stopped unexpectedly"),
        }
    }
}

impl std::error::Error for ControlPlaneRuntimeError {}
