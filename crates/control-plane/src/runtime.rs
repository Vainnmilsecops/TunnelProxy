use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tunnelproxy_common::{shutdown_channel, ShutdownSignal};

use crate::{
    operations::{ControlPlaneOperationsRuntime, ControlPlaneTelemetry, RefreshOutcome},
    ControlPlaneOperationsConfig, ControlPlaneOperationsError, ControlPlaneOperationsOutcome,
    EnrollmentServer, EnrollmentServerConfig, EnrollmentServerError, HostnameServer,
    HostnameServerConfig, HostnameServerError, HttpsRouteAuthorityError,
    HttpsRouteDistributionServer, HttpsRoutePublishOutcome, HttpsRouteRepository,
    HttpsRouteServerConfig, HttpsRouteServerError, PersistentHttpsRouteCatalog,
    PersistentSnapshotAuthority, PersistentSnapshotAuthorityError, SnapshotDistributionServer,
    SnapshotPublishOutcome, SnapshotServerConfig, SnapshotServerError, SnapshotVersion,
    SqliteSnapshotRepository,
};

#[derive(Debug, Clone)]
pub struct ControlPlaneRuntimeConfig {
    pub database_path: PathBuf,
    pub refresh_interval: Duration,
    pub snapshot_server: SnapshotServerConfig,
    pub https_route_server: Option<HttpsRouteServerConfig>,
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
        if let Some(routes) = &self.https_route_server {
            routes
                .validate()
                .map_err(|_| ControlPlaneRuntimeError::InvalidConfig)?;
        }
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
    https_route_authority: Option<PersistentHttpsRouteCatalog>,
    https_route_server: Option<HttpsRouteDistributionServer>,
    hostname_server: Option<HostnameServer>,
    enrollment_server: Option<EnrollmentServer>,
    operations: Option<ControlPlaneOperationsRuntime>,
    telemetry: ControlPlaneTelemetry,
    refresh_interval: Duration,
}

impl ControlPlaneRuntime {
    pub async fn bind(config: ControlPlaneRuntimeConfig) -> Result<Self, ControlPlaneRuntimeError> {
        Self::bind_inner(config, None, None).await
    }

    pub async fn bind_with_enrollment(
        config: ControlPlaneRuntimeConfig,
        enrollment: EnrollmentServerConfig,
    ) -> Result<Self, ControlPlaneRuntimeError> {
        Self::bind_inner(config, Some(enrollment), None).await
    }

    pub async fn bind_with_hostname(
        config: ControlPlaneRuntimeConfig,
        hostname: HostnameServerConfig,
    ) -> Result<Self, ControlPlaneRuntimeError> {
        Self::bind_inner(config, None, Some(hostname)).await
    }

    pub async fn bind_with_enrollment_and_hostname(
        config: ControlPlaneRuntimeConfig,
        enrollment: EnrollmentServerConfig,
        hostname: HostnameServerConfig,
    ) -> Result<Self, ControlPlaneRuntimeError> {
        Self::bind_inner(config, Some(enrollment), Some(hostname)).await
    }

    async fn bind_inner(
        config: ControlPlaneRuntimeConfig,
        enrollment: Option<EnrollmentServerConfig>,
        hostname: Option<HostnameServerConfig>,
    ) -> Result<Self, ControlPlaneRuntimeError> {
        config.validate()?;
        if hostname.is_some() && config.https_route_server.is_none() {
            return Err(ControlPlaneRuntimeError::InvalidConfig);
        }
        let operations_config = config.operations;
        let https_route_server_config = config.https_route_server;
        let database_path = config.database_path;
        let route_database_path = database_path.clone();
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
        telemetry.initialize(
            authority.current().version().get(),
            enrollment.is_some(),
            hostname.is_some(),
        );
        let server = SnapshotDistributionServer::bind_with_telemetry(
            config.snapshot_server,
            authority.subscribe(),
            telemetry.clone(),
        )
        .await
        .map_err(ControlPlaneRuntimeError::Server)?;
        let (https_route_authority, https_route_server) = match https_route_server_config {
            Some(config) => {
                let repository = tokio::task::spawn_blocking(move || {
                    HttpsRouteRepository::open(route_database_path)
                })
                .await
                .map_err(|_| ControlPlaneRuntimeError::StorageTask)?
                .map_err(ControlPlaneRuntimeError::HttpsRouteRepository)?;
                let authority = PersistentHttpsRouteCatalog::open(repository)
                    .await
                    .map_err(ControlPlaneRuntimeError::HttpsRouteAuthority)?;
                let server = HttpsRouteDistributionServer::bind(config, authority.subscribe())
                    .await
                    .map_err(ControlPlaneRuntimeError::HttpsRouteServer)?;
                (Some(authority), Some(server))
            }
            None => (None, None),
        };
        let enrollment_server = match enrollment {
            Some(config) => Some(
                EnrollmentServer::bind_with_telemetry(config, authority.clone(), telemetry.clone())
                    .await
                    .map_err(ControlPlaneRuntimeError::Enrollment)?,
            ),
            None => None,
        };
        let hostname_server = match hostname {
            Some(config) => Some(
                HostnameServer::bind_with_telemetry(
                    config,
                    authority.subscribe(),
                    https_route_authority
                        .as_ref()
                        .expect("hostname service requires route authority")
                        .clone(),
                    telemetry.clone(),
                )
                .await
                .map_err(ControlPlaneRuntimeError::Hostname)?,
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
            https_route_authority,
            https_route_server,
            hostname_server,
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

    pub fn https_route_addr(&self) -> Option<std::net::SocketAddr> {
        self.https_route_server
            .as_ref()
            .map(HttpsRouteDistributionServer::local_addr)
    }

    pub fn hostname_addr(&self) -> Option<std::net::SocketAddr> {
        self.hostname_server
            .as_ref()
            .map(HostnameServer::local_addr)
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
        let https_route_addr = self.https_route_addr();
        let hostname_addr = self.hostname_addr();
        let operations_addr = self.operations_addr();
        let (server_trigger, server_signal) = shutdown_channel();
        let mut server_task = tokio::spawn(self.server.run_until_shutdown(server_signal));
        let (route_trigger, route_signal) = shutdown_channel();
        let mut route_task = self
            .https_route_server
            .map(|server| tokio::spawn(server.run_until_shutdown(route_signal)));
        let (enrollment_trigger, enrollment_signal) = shutdown_channel();
        let mut enrollment_task = self
            .enrollment_server
            .map(|server| tokio::spawn(server.run_until_shutdown(enrollment_signal)));
        let (hostname_trigger, hostname_signal) = shutdown_channel();
        let mut hostname_task = self
            .hostname_server
            .map(|server| tokio::spawn(server.run_until_shutdown(hostname_signal)));
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
        let mut applied_route_refreshes = 0_u64;
        self.telemetry.mark_ready();
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    route_trigger.shutdown();
                    enrollment_trigger.shutdown();
                    hostname_trigger.shutdown();
                    let server_result = await_server(server_task).await;
                    let route_result = await_route_server(&mut route_task).await;
                    let enrollment_result = await_enrollment(&mut enrollment_task).await;
                    let hostname_result = await_hostname(&mut hostname_task).await;
                    operations_trigger.shutdown();
                    let operations_result = await_operations(&mut operations_task).await;
                    server_result?;
                    route_result?;
                    enrollment_result?;
                    hostname_result?;
                    let operations = operations_result?;
                    return Ok(ControlPlaneRuntimeOutcome {
                        listen_addr: local_addr,
                        enrollment_addr,
                        https_route_addr,
                        hostname_addr,
                        operations_addr,
                        applied_refreshes,
                        applied_route_refreshes,
                        operations,
                    });
                }
                result = &mut server_task => {
                    self.telemetry.begin_draining();
                    enrollment_trigger.shutdown();
                    route_trigger.shutdown();
                    hostname_trigger.shutdown();
                    let _ = await_route_server(&mut route_task).await;
                    let _ = await_enrollment(&mut enrollment_task).await;
                    let _ = await_hostname(&mut hostname_task).await;
                    operations_trigger.shutdown();
                    let _ = await_operations(&mut operations_task).await;
                    return match result {
                        Ok(Ok(())) => Err(ControlPlaneRuntimeError::ServerStopped),
                        Ok(Err(error)) => Err(ControlPlaneRuntimeError::Server(error)),
                        Err(error) => Err(ControlPlaneRuntimeError::ServerTask(error.to_string())),
                    };
                }
                result = next_route_server(&mut route_task), if route_task.is_some() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    enrollment_trigger.shutdown();
                    hostname_trigger.shutdown();
                    let _ = await_server(server_task).await;
                    let _ = await_enrollment(&mut enrollment_task).await;
                    let _ = await_hostname(&mut hostname_task).await;
                    operations_trigger.shutdown();
                    let _ = await_operations(&mut operations_task).await;
                    return match result {
                        Some(Ok(Ok(()))) => Err(ControlPlaneRuntimeError::HttpsRouteServerStopped),
                        Some(Ok(Err(error))) => Err(ControlPlaneRuntimeError::HttpsRouteServer(error)),
                        Some(Err(error)) => Err(ControlPlaneRuntimeError::HttpsRouteServerTask(error.to_string())),
                        None => Err(ControlPlaneRuntimeError::HttpsRouteServerStopped),
                    };
                }
                result = next_enrollment(&mut enrollment_task), if enrollment_task.is_some() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    route_trigger.shutdown();
                    hostname_trigger.shutdown();
                    let _ = await_route_server(&mut route_task).await;
                    let _ = await_server(server_task).await;
                    let _ = await_hostname(&mut hostname_task).await;
                    operations_trigger.shutdown();
                    let _ = await_operations(&mut operations_task).await;
                    return match result {
                        Some(Ok(Ok(()))) => Err(ControlPlaneRuntimeError::EnrollmentStopped),
                        Some(Ok(Err(error))) => Err(ControlPlaneRuntimeError::Enrollment(error)),
                        Some(Err(error)) => Err(ControlPlaneRuntimeError::EnrollmentTask(error.to_string())),
                        None => Err(ControlPlaneRuntimeError::EnrollmentStopped),
                    };
                }
                result = next_hostname(&mut hostname_task), if hostname_task.is_some() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    route_trigger.shutdown();
                    enrollment_trigger.shutdown();
                    let _ = await_route_server(&mut route_task).await;
                    let _ = await_enrollment(&mut enrollment_task).await;
                    let _ = await_server(server_task).await;
                    operations_trigger.shutdown();
                    let _ = await_operations(&mut operations_task).await;
                    return match result {
                        Some(Ok(Ok(()))) => Err(ControlPlaneRuntimeError::HostnameStopped),
                        Some(Ok(Err(error))) => Err(ControlPlaneRuntimeError::Hostname(error)),
                        Some(Err(error)) => Err(ControlPlaneRuntimeError::HostnameTask(error.to_string())),
                        None => Err(ControlPlaneRuntimeError::HostnameStopped),
                    };
                }
                result = next_operations(&mut operations_task), if operations_task.is_some() => {
                    self.telemetry.begin_draining();
                    server_trigger.shutdown();
                    route_trigger.shutdown();
                    hostname_trigger.shutdown();
                    let _ = await_route_server(&mut route_task).await;
                    enrollment_trigger.shutdown();
                    let _ = await_server(server_task).await;
                    let _ = await_enrollment(&mut enrollment_task).await;
                    let _ = await_hostname(&mut hostname_task).await;
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
                            route_trigger.shutdown();
                            hostname_trigger.shutdown();
                            let _ = await_server(server_task).await;
                            let _ = await_enrollment(&mut enrollment_task).await;
                            let _ = await_route_server(&mut route_task).await;
                            let _ = await_hostname(&mut hostname_task).await;
                            operations_trigger.shutdown();
                            let _ = await_operations(&mut operations_task).await;
                            return Err(ControlPlaneRuntimeError::Authority(error));
                        }
                    }
                    if let Some(authority) = &self.https_route_authority {
                        match authority.refresh_from_repository().await {
                            Ok(HttpsRoutePublishOutcome::Applied { .. }) => {
                                applied_route_refreshes = applied_route_refreshes.saturating_add(1);
                            }
                            Ok(HttpsRoutePublishOutcome::Unchanged { .. }) => {}
                            Err(error) => {
                                self.telemetry.begin_draining();
                                server_trigger.shutdown();
                                route_trigger.shutdown();
                                enrollment_trigger.shutdown();
                                hostname_trigger.shutdown();
                                let _ = await_server(server_task).await;
                                let _ = await_route_server(&mut route_task).await;
                                let _ = await_enrollment(&mut enrollment_task).await;
                                let _ = await_hostname(&mut hostname_task).await;
                                operations_trigger.shutdown();
                                let _ = await_operations(&mut operations_task).await;
                                return Err(ControlPlaneRuntimeError::HttpsRouteAuthority(error));
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn next_route_server(
    task: &mut Option<JoinHandle<Result<(), HttpsRouteServerError>>>,
) -> Option<Result<Result<(), HttpsRouteServerError>, tokio::task::JoinError>> {
    match task {
        Some(task) => Some(task.await),
        None => std::future::pending().await,
    }
}

async fn await_route_server(
    task: &mut Option<JoinHandle<Result<(), HttpsRouteServerError>>>,
) -> Result<(), ControlPlaneRuntimeError> {
    let Some(task) = task.take() else {
        return Ok(());
    };
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ControlPlaneRuntimeError::HttpsRouteServer(error)),
        Err(error) => Err(ControlPlaneRuntimeError::HttpsRouteServerTask(
            error.to_string(),
        )),
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

async fn next_hostname(
    task: &mut Option<JoinHandle<Result<(), HostnameServerError>>>,
) -> Option<Result<Result<(), HostnameServerError>, tokio::task::JoinError>> {
    match task {
        Some(task) => Some(task.await),
        None => std::future::pending().await,
    }
}

async fn await_hostname(
    task: &mut Option<JoinHandle<Result<(), HostnameServerError>>>,
) -> Result<(), ControlPlaneRuntimeError> {
    let Some(task) = task.take() else {
        return Ok(());
    };
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ControlPlaneRuntimeError::Hostname(error)),
        Err(error) => Err(ControlPlaneRuntimeError::HostnameTask(error.to_string())),
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
    pub https_route_addr: Option<std::net::SocketAddr>,
    pub hostname_addr: Option<std::net::SocketAddr>,
    pub operations_addr: Option<std::net::SocketAddr>,
    pub applied_refreshes: u64,
    pub applied_route_refreshes: u64,
    pub operations: Option<ControlPlaneOperationsOutcome>,
}

#[derive(Debug)]
pub enum ControlPlaneRuntimeError {
    InvalidConfig,
    Repository(crate::SnapshotRepositoryError),
    Authority(PersistentSnapshotAuthorityError),
    HttpsRouteRepository(crate::HttpsRouteRepositoryError),
    HttpsRouteAuthority(HttpsRouteAuthorityError),
    HttpsRouteServer(HttpsRouteServerError),
    Server(SnapshotServerError),
    Enrollment(EnrollmentServerError),
    Hostname(HostnameServerError),
    Operations(ControlPlaneOperationsError),
    StorageTask,
    ServerTask(String),
    ServerStopped,
    HttpsRouteServerTask(String),
    HttpsRouteServerStopped,
    EnrollmentTask(String),
    EnrollmentStopped,
    HostnameTask(String),
    HostnameStopped,
    OperationsTask(String),
    OperationsStopped,
}

impl std::fmt::Display for ControlPlaneRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("Control Plane runtime configuration is invalid"),
            Self::Repository(error) => error.fmt(f),
            Self::Authority(error) => error.fmt(f),
            Self::HttpsRouteRepository(error) => error.fmt(f),
            Self::HttpsRouteAuthority(error) => error.fmt(f),
            Self::HttpsRouteServer(error) => error.fmt(f),
            Self::Server(error) => error.fmt(f),
            Self::Enrollment(error) => error.fmt(f),
            Self::Hostname(error) => error.fmt(f),
            Self::Operations(error) => error.fmt(f),
            Self::StorageTask => f.write_str("snapshot storage worker stopped unexpectedly"),
            Self::ServerTask(_) => f.write_str("snapshot server task stopped unexpectedly"),
            Self::ServerStopped => f.write_str("snapshot server stopped unexpectedly"),
            Self::HttpsRouteServerTask(_) => {
                f.write_str("HTTPS route server task stopped unexpectedly")
            }
            Self::HttpsRouteServerStopped => f.write_str("HTTPS route server stopped unexpectedly"),
            Self::EnrollmentTask(_) => f.write_str("enrollment server task stopped unexpectedly"),
            Self::EnrollmentStopped => f.write_str("enrollment server stopped unexpectedly"),
            Self::HostnameTask(_) => f.write_str("hostname server task stopped unexpectedly"),
            Self::HostnameStopped => f.write_str("hostname server stopped unexpectedly"),
            Self::OperationsTask(_) => f.write_str("operations server task stopped unexpectedly"),
            Self::OperationsStopped => f.write_str("operations server stopped unexpectedly"),
        }
    }
}

impl std::error::Error for ControlPlaneRuntimeError {}
