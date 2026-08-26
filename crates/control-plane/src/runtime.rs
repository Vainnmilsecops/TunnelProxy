use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tunnelproxy_common::{shutdown_channel, ShutdownSignal};

use crate::{
    operations::{ControlPlaneOperationsRuntime, ControlPlaneTelemetry, RefreshOutcome},
    ControlPlaneOperationsConfig, ControlPlaneOperationsError, ControlPlaneOperationsOutcome,
    EnrollmentServer, EnrollmentServerConfig, EnrollmentServerError, PersistentSnapshotAuthority,
    PersistentSnapshotAuthorityError, SnapshotDistributionServer, SnapshotPublishOutcome,
    SnapshotServerConfig, SnapshotServerError, SnapshotVersion, SqliteSnapshotRepository,
};

#[derive(Debug, Clone)]
pub struct ControlPlaneRuntimeConfig {
    pub database_path: PathBuf,
    pub refresh_interval: Duration,
    pub snapshot_server: SnapshotServerConfig,
    pub operations: Option<ControlPlaneOperationsConfig>,
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
            })?;
        if let Some(operations) = self.operations {
            operations
                .validate()
                .map_err(|_| ControlPlaneRuntimeError::InvalidConfig)?;
        }
        Ok(())
    }
}

pub struct ControlPlaneRuntime {
    authority: PersistentSnapshotAuthority,
    server: SnapshotDistributionServer,
    enrollment_server: Option<EnrollmentServer>,
    operations: Option<ControlPlaneOperationsRuntime>,
    telemetry: ControlPlaneTelemetry,
    refresh_interval: Duration,
}

impl ControlPlaneRuntime {
    pub async fn bind(config: ControlPlaneRuntimeConfig) -> Result<Self, ControlPlaneRuntimeError> {
        Self::bind_inner(config, None).await
    }

    pub async fn bind_with_enrollment(
        config: ControlPlaneRuntimeConfig,
        enrollment: EnrollmentServerConfig,
    ) -> Result<Self, ControlPlaneRuntimeError> {
        Self::bind_inner(config, Some(enrollment)).await
    }

    async fn bind_inner(
        config: ControlPlaneRuntimeConfig,
        enrollment: Option<EnrollmentServerConfig>,
    ) -> Result<Self, ControlPlaneRuntimeError> {
        config.validate()?;
        let operations_config = config.operations;
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
        let telemetry = ControlPlaneTelemetry::default();
        telemetry.initialize(authority.current().version().get(), enrollment.is_some());
        let server = SnapshotDistributionServer::bind_with_telemetry(
            config.snapshot_server,
            authority.subscribe(),
            telemetry.clone(),
        )
        .await
        .map_err(ControlPlaneRuntimeError::Server)?;
        let enrollment_server = match enrollment {
            Some(config) => Some(
                EnrollmentServer::bind_with_telemetry(config, authority.clone(), telemetry.clone())
                    .await
                    .map_err(ControlPlaneRuntimeError::Enrollment)?,
            ),
            None => None,
        };
        let operations = match operations_config {
            Some(config) => Some(
                ControlPlaneOperationsRuntime::bind(config, telemetry.clone())
                    .await
                    .map_err(ControlPlaneRuntimeError::Operations)?,
            ),
            None => None,
        };
        Ok(Self {
            authority,
            server,
            enrollment_server,
            operations,
            telemetry,
            refresh_interval: config.refresh_interval,
        })
    }

    pub const fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    pub fn current_version(&self) -> SnapshotVersion {
        self.authority.current().version()
    }

    pub fn enrollment_addr(&self) -> Option<std::net::SocketAddr> {
        self.enrollment_server
            .as_ref()
            .map(EnrollmentServer::local_addr)
    }

    pub fn operations_addr(&self) -> Option<std::net::SocketAddr> {
        self.operations
            .as_ref()
            .map(ControlPlaneOperationsRuntime::local_addr)
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<ControlPlaneRuntimeOutcome, ControlPlaneRuntimeError> {
        let local_addr = self.server.local_addr();
        let enrollment_addr = self.enrollment_addr();
        let operations_addr = self.operations_addr();
        let (server_trigger, server_signal) = shutdown_channel();
        let mut server_task = tokio::spawn(self.server.run_until_shutdown(server_signal));
        let (enrollment_trigger, enrollment_signal) = shutdown_channel();
        let mut enrollment_task = self
            .enrollment_server
            .map(|server| tokio::spawn(server.run_until_shutdown(enrollment_signal)));
        let (operations_trigger, operations_signal) = shutdown_channel();
        let mut operations_task = self
            .operations
            .map(|runtime| tokio::spawn(runtime.run_until_shutdown(operations_signal)));
        let mut refresh = tokio::time::interval_at(
            Instant::now() + self.refresh_interval,
            self.refresh_interval,
        );
        refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut applied_refreshes = 0_u64;
        self.telemetry.mark_ready();
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    enrollment_trigger.shutdown();
                    let server_result = await_server(server_task).await;
                    let enrollment_result = await_enrollment(&mut enrollment_task).await;
                    operations_trigger.shutdown();
                    let operations_result = await_operations(&mut operations_task).await;
                    server_result?;
                    enrollment_result?;
                    let operations = operations_result?;
                    return Ok(ControlPlaneRuntimeOutcome {
                        listen_addr: local_addr,
                        enrollment_addr,
                        operations_addr,
                        applied_refreshes,
                        operations,
                    });
                }
                result = &mut server_task => {
                    self.telemetry.begin_draining();
                    enrollment_trigger.shutdown();
                    let _ = await_enrollment(&mut enrollment_task).await;
                    operations_trigger.shutdown();
                    let _ = await_operations(&mut operations_task).await;
                    return match result {
                        Ok(Ok(())) => Err(ControlPlaneRuntimeError::ServerStopped),
                        Ok(Err(error)) => Err(ControlPlaneRuntimeError::Server(error)),
                        Err(error) => Err(ControlPlaneRuntimeError::ServerTask(error.to_string())),
                    };
                }
                result = next_enrollment(&mut enrollment_task), if enrollment_task.is_some() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    let _ = await_server(server_task).await;
                    operations_trigger.shutdown();
                    let _ = await_operations(&mut operations_task).await;
                    return match result {
                        Some(Ok(Ok(()))) => Err(ControlPlaneRuntimeError::EnrollmentStopped),
                        Some(Ok(Err(error))) => Err(ControlPlaneRuntimeError::Enrollment(error)),
                        Some(Err(error)) => Err(ControlPlaneRuntimeError::EnrollmentTask(error.to_string())),
                        None => Err(ControlPlaneRuntimeError::EnrollmentStopped),
                    };
                }
                result = next_operations(&mut operations_task), if operations_task.is_some() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    enrollment_trigger.shutdown();
                    let _ = await_server(server_task).await;
                    let _ = await_enrollment(&mut enrollment_task).await;
                    return match result {
                        Some(Ok(Ok(_))) => Err(ControlPlaneRuntimeError::OperationsStopped),
                        Some(Ok(Err(error))) => Err(ControlPlaneRuntimeError::Operations(error)),
                        Some(Err(error)) => Err(ControlPlaneRuntimeError::OperationsTask(error.to_string())),
                        None => Err(ControlPlaneRuntimeError::OperationsStopped),
                    };
                }
                _ = refresh.tick() => {
                    match self.authority.refresh_from_repository().await {
                        Ok(SnapshotPublishOutcome::Applied { current, .. }) => {
                            applied_refreshes = applied_refreshes.saturating_add(1);
                            self.telemetry.record_refresh(RefreshOutcome::Applied, Some(current.get()));
                        }
                        Ok(SnapshotPublishOutcome::Unchanged { version }) => {
                            self.telemetry.record_refresh(RefreshOutcome::Unchanged, Some(version.get()));
                        }
                        Err(error) => {
                            self.telemetry.record_refresh(RefreshOutcome::Failed, None);
                            self.telemetry.begin_draining();
                            server_trigger.shutdown();
                            enrollment_trigger.shutdown();
                            let _ = await_server(server_task).await;
                            let _ = await_enrollment(&mut enrollment_task).await;
                            operations_trigger.shutdown();
                            let _ = await_operations(&mut operations_task).await;
                            return Err(ControlPlaneRuntimeError::Authority(error));
                        }
                    }
                }
            }
        }
    }
}

async fn next_operations(
    task: &mut Option<
        JoinHandle<Result<ControlPlaneOperationsOutcome, ControlPlaneOperationsError>>,
    >,
) -> Option<
    Result<
        Result<ControlPlaneOperationsOutcome, ControlPlaneOperationsError>,
        tokio::task::JoinError,
    >,
> {
    match task {
        Some(task) => Some(task.await),
        None => std::future::pending().await,
    }
}

async fn await_operations(
    task: &mut Option<
        JoinHandle<Result<ControlPlaneOperationsOutcome, ControlPlaneOperationsError>>,
    >,
) -> Result<Option<ControlPlaneOperationsOutcome>, ControlPlaneRuntimeError> {
    let Some(task) = task.take() else {
        return Ok(None);
    };
    match task.await {
        Ok(Ok(outcome)) => Ok(Some(outcome)),
        Ok(Err(error)) => Err(ControlPlaneRuntimeError::Operations(error)),
        Err(error) => Err(ControlPlaneRuntimeError::OperationsTask(error.to_string())),
    }
}

async fn next_enrollment(
    task: &mut Option<JoinHandle<Result<(), EnrollmentServerError>>>,
) -> Option<Result<Result<(), EnrollmentServerError>, tokio::task::JoinError>> {
    match task {
        Some(task) => Some(task.await),
        None => std::future::pending().await,
    }
}

async fn await_enrollment(
    task: &mut Option<JoinHandle<Result<(), EnrollmentServerError>>>,
) -> Result<(), ControlPlaneRuntimeError> {
    let Some(task) = task.take() else {
        return Ok(());
    };
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ControlPlaneRuntimeError::Enrollment(error)),
        Err(error) => Err(ControlPlaneRuntimeError::EnrollmentTask(error.to_string())),
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
    pub enrollment_addr: Option<std::net::SocketAddr>,
    pub operations_addr: Option<std::net::SocketAddr>,
    pub applied_refreshes: u64,
    pub operations: Option<ControlPlaneOperationsOutcome>,
}

#[derive(Debug)]
pub enum ControlPlaneRuntimeError {
    InvalidConfig,
    Repository(crate::SnapshotRepositoryError),
    Authority(PersistentSnapshotAuthorityError),
    Server(SnapshotServerError),
    Enrollment(EnrollmentServerError),
    Operations(ControlPlaneOperationsError),
    StorageTask,
    ServerTask(String),
    ServerStopped,
    EnrollmentTask(String),
    EnrollmentStopped,
    OperationsTask(String),
    OperationsStopped,
}

impl std::fmt::Display for ControlPlaneRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("Control Plane runtime configuration is invalid"),
            Self::Repository(error) => error.fmt(f),
            Self::Authority(error) => error.fmt(f),
            Self::Server(error) => error.fmt(f),
            Self::Enrollment(error) => error.fmt(f),
            Self::Operations(error) => error.fmt(f),
            Self::StorageTask => f.write_str("snapshot storage worker stopped unexpectedly"),
            Self::ServerTask(_) => f.write_str("snapshot server task stopped unexpectedly"),
            Self::ServerStopped => f.write_str("snapshot server stopped unexpectedly"),
            Self::EnrollmentTask(_) => f.write_str("enrollment server task stopped unexpectedly"),
            Self::EnrollmentStopped => f.write_str("enrollment server stopped unexpectedly"),
            Self::OperationsTask(_) => f.write_str("operations server task stopped unexpectedly"),
            Self::OperationsStopped => f.write_str("operations server stopped unexpectedly"),
        }
    }
}

impl std::error::Error for ControlPlaneRuntimeError {}
