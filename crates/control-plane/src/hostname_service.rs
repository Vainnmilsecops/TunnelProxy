//! Authenticated Agent-facing managed-hostname lifecycle service.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{info, warn};
use tunnelproxy_common::{ShutdownSignal, TlsConfigStatus, TlsReloadRuntimeError};
use tunnelproxy_protocol::{
    read_hostname_message, write_hostname_message, HostnameErrorCode, HostnameMessage,
    HOSTNAME_PROTOCOL_ALPN,
};

use crate::snapshot_service::ProtocolServerTlsReloadRuntime;
use crate::{
    operations::{ControlPlaneTelemetry, HostnameRequestOutcome},
    AuthorizationSnapshotSubscription, CertificateFingerprint, HttpsRouteAuthorityError,
    HttpsRouteRepositoryError, ManagedHostnameAllocationOutcome, ManagedHostnameBaseDomain,
    ManagedHostnameReleaseOutcome, PersistentHttpsRouteCatalog, SnapshotServerTlsConfig,
    SnapshotServerTlsReloadConfig, SnapshotTlsConfigError, SnapshotTlsReloadBootstrapError,
};

#[derive(Clone)]
pub struct HostnameServerTlsConfig(SnapshotServerTlsConfig);

impl HostnameServerTlsConfig {
    pub fn from_pem(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        agent_client_ca_pem: &[u8],
        handshake_timeout: Duration,
    ) -> Result<Self, SnapshotTlsConfigError> {
        SnapshotServerTlsConfig::from_pem_with_alpn(
            server_cert_pem,
            server_key_pem,
            agent_client_ca_pem,
            handshake_timeout,
            HOSTNAME_PROTOCOL_ALPN,
        )
        .map(Self)
    }

    pub fn reload_status(&self, expiry_warning: Duration) -> TlsConfigStatus {
        self.0.reload_status(expiry_warning)
    }
}

impl std::fmt::Debug for HostnameServerTlsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostnameServerTlsConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct HostnameServerTlsReloadConfig {
    pub manifest_path: PathBuf,
    pub server_certificate_path: PathBuf,
    pub server_private_key_path: PathBuf,
    pub agent_client_ca_path: PathBuf,
    pub poll_interval: Duration,
    pub expiry_warning: Duration,
}

impl From<HostnameServerTlsReloadConfig> for SnapshotServerTlsReloadConfig {
    fn from(value: HostnameServerTlsReloadConfig) -> Self {
        Self {
            manifest_path: value.manifest_path,
            server_certificate_path: value.server_certificate_path,
            server_private_key_path: value.server_private_key_path,
            client_ca_path: value.agent_client_ca_path,
            poll_interval: value.poll_interval,
            expiry_warning: value.expiry_warning,
        }
    }
}

pub struct HostnameServerTlsReloadRuntime {
    inner: ProtocolServerTlsReloadRuntime,
}

impl HostnameServerTlsReloadRuntime {
    pub async fn bootstrap(
        reload: HostnameServerTlsReloadConfig,
        handshake_timeout: Duration,
    ) -> Result<(HostnameServerTlsConfig, Self), SnapshotTlsReloadBootstrapError> {
        let (tls, inner) = ProtocolServerTlsReloadRuntime::bootstrap(
            reload.into(),
            handshake_timeout,
            HOSTNAME_PROTOCOL_ALPN,
        )
        .await?;
        Ok((HostnameServerTlsConfig(tls), Self { inner }))
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), TlsReloadRuntimeError> {
        self.inner.run_until_shutdown(signal).await
    }
}

#[derive(Debug, Clone)]
pub struct HostnameServerConfig {
    pub listen_addr: SocketAddr,
    pub max_clients: usize,
    pub request_timeout: Duration,
    pub base_domain: ManagedHostnameBaseDomain,
    pub tls: HostnameServerTlsConfig,
}

impl HostnameServerConfig {
    pub fn validate(&self) -> Result<(), HostnameServerError> {
        if self.max_clients == 0 || self.request_timeout.is_zero() {
            return Err(HostnameServerError::InvalidConfig);
        }
        Ok(())
    }
}

pub struct HostnameServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: HostnameServerConfig,
    snapshots: AuthorizationSnapshotSubscription,
    routes: PersistentHttpsRouteCatalog,
    telemetry: ControlPlaneTelemetry,
}

impl HostnameServer {
    pub async fn bind(
        config: HostnameServerConfig,
        snapshots: AuthorizationSnapshotSubscription,
        routes: PersistentHttpsRouteCatalog,
    ) -> Result<Self, HostnameServerError> {
        Self::bind_with_telemetry(config, snapshots, routes, ControlPlaneTelemetry::default()).await
    }

    pub(crate) async fn bind_with_telemetry(
        config: HostnameServerConfig,
        snapshots: AuthorizationSnapshotSubscription,
        routes: PersistentHttpsRouteCatalog,
        telemetry: ControlPlaneTelemetry,
    ) -> Result<Self, HostnameServerError> {
        config.validate()?;
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(HostnameServerError::Bind)?;
        let local_addr = listener.local_addr().map_err(HostnameServerError::Bind)?;
        Ok(Self {
            listener,
            local_addr,
            config,
            snapshots,
            routes,
            telemetry,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), HostnameServerError> {
        info!(addr = %self.local_addr, event = "hostname_server_started");
        let permits = Arc::new(Semaphore::new(self.config.max_clients));
        let context = HostnameConnectionContext {
            config: self.config.clone(),
            snapshots: self.snapshots.clone(),
            routes: self.routes.clone(),
            telemetry: self.telemetry.clone(),
        };
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (socket, peer) = accepted.map_err(HostnameServerError::Accept)?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        self.telemetry.hostname_capacity_rejected();
                        warn!(%peer, event = "hostname_capacity_rejected");
                        continue;
                    };
                    let active = self.telemetry.hostname_accepted();
                    tasks.spawn(serve_agent(
                        socket,
                        peer,
                        permit,
                        context.clone(),
                        active,
                    ));
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

#[derive(Clone)]
struct HostnameConnectionContext {
    config: HostnameServerConfig,
    snapshots: AuthorizationSnapshotSubscription,
    routes: PersistentHttpsRouteCatalog,
    telemetry: ControlPlaneTelemetry,
}

async fn serve_agent(
    socket: TcpStream,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
    context: HostnameConnectionContext,
    _active: crate::operations::ActiveTelemetryGuard,
) {
    let HostnameConnectionContext {
        config,
        snapshots,
        routes,
        telemetry,
    } = context;
    let acceptor = config.tls.0.acceptor();
    let mut stream = match timeout(config.tls.0.handshake_timeout(), acceptor.accept(socket)).await
    {
        Ok(Ok(stream)) if stream.get_ref().1.alpn_protocol() == Some(HOSTNAME_PROTOCOL_ALPN) => {
            stream
        }
        _ => {
            telemetry.hostname_tls_rejected();
            warn!(%peer, event = "hostname_tls_rejected");
            return;
        }
    };
    let Some(peer_certificate) = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
    else {
        warn!(%peer, event = "hostname_tls_identity_missing");
        return;
    };
    let fingerprint = CertificateFingerprint::from_certificate_der(peer_certificate.as_ref());
    let request = match timeout(config.request_timeout, read_hostname_message(&mut stream)).await {
        Ok(Ok(Some(request @ HostnameMessage::Allocate { .. })))
        | Ok(Ok(Some(request @ HostnameMessage::Release { .. }))) => request,
        _ => {
            telemetry.hostname_invalid_request();
            write_error(
                &mut stream,
                config.request_timeout,
                HostnameErrorCode::InvalidRequest,
            )
            .await;
            return;
        }
    };
    let (agent_id, tunnel_id) = match &request {
        HostnameMessage::Allocate {
            agent_id,
            tunnel_id,
        }
        | HostnameMessage::Release {
            agent_id,
            tunnel_id,
        } => (agent_id, tunnel_id),
        _ => unreachable!("request was filtered above"),
    };
    if snapshots
        .current()
        .snapshot()
        .authorize(&fingerprint, agent_id, tunnel_id)
        .is_err()
    {
        telemetry.hostname_unauthorized();
        write_error(
            &mut stream,
            config.request_timeout,
            HostnameErrorCode::Unauthorized,
        )
        .await;
        return;
    }
    let response = match request {
        HostnameMessage::Allocate { tunnel_id, .. } => routes
            .allocate_managed_hostname(&tunnel_id, &config.base_domain)
            .await
            .map(allocation_response),
        HostnameMessage::Release { tunnel_id, .. } => routes
            .release_managed_hostname(&tunnel_id)
            .await
            .map(release_response),
        _ => unreachable!("request was filtered above"),
    };
    let response = match response {
        Ok(response) => {
            telemetry.hostname_outcome(match &response {
                HostnameMessage::Allocated { changed: true, .. } => {
                    HostnameRequestOutcome::AllocateApplied
                }
                HostnameMessage::Allocated { changed: false, .. } => {
                    HostnameRequestOutcome::AllocateUnchanged
                }
                HostnameMessage::Released { changed: true, .. } => {
                    HostnameRequestOutcome::ReleaseApplied
                }
                HostnameMessage::Released { changed: false, .. } => {
                    HostnameRequestOutcome::ReleaseUnchanged
                }
                _ => unreachable!("authority returns a hostname response"),
            });
            response
        }
        Err(error) => {
            telemetry.hostname_outcome(HostnameRequestOutcome::Failed);
            HostnameMessage::Error {
                code: authority_error_code(&error),
            }
        }
    };
    let _ = timeout(
        config.request_timeout,
        write_hostname_message(&mut stream, &response),
    )
    .await;
}

fn allocation_response(outcome: ManagedHostnameAllocationOutcome) -> HostnameMessage {
    match outcome {
        ManagedHostnameAllocationOutcome::Allocated {
            hostname, current, ..
        } => HostnameMessage::Allocated {
            hostname,
            catalog_version: current.get(),
            changed: true,
        },
        ManagedHostnameAllocationOutcome::Existing { hostname, version } => {
            HostnameMessage::Allocated {
                hostname,
                catalog_version: version.get(),
                changed: false,
            }
        }
    }
}

fn release_response(outcome: ManagedHostnameReleaseOutcome) -> HostnameMessage {
    match outcome {
        ManagedHostnameReleaseOutcome::Released {
            hostname, current, ..
        } => HostnameMessage::Released {
            hostname: Some(hostname),
            catalog_version: current.get(),
            changed: true,
        },
        ManagedHostnameReleaseOutcome::Absent { version } => HostnameMessage::Released {
            hostname: None,
            catalog_version: version.get(),
            changed: false,
        },
    }
}

fn authority_error_code(error: &HttpsRouteAuthorityError) -> HostnameErrorCode {
    match error {
        HttpsRouteAuthorityError::Repository(
            HttpsRouteRepositoryError::ManagedHostnameConflict
            | HttpsRouteRepositoryError::ManagedBaseDomainConflict,
        ) => HostnameErrorCode::Conflict,
        HttpsRouteAuthorityError::Repository(HttpsRouteRepositoryError::CapacityExceeded) => {
            HostnameErrorCode::Capacity
        }
        _ => HostnameErrorCode::Internal,
    }
}

async fn write_error(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    request_timeout: Duration,
    code: HostnameErrorCode,
) {
    let _ = timeout(
        request_timeout,
        write_hostname_message(stream, &HostnameMessage::Error { code }),
    )
    .await;
}

#[derive(Debug)]
pub enum HostnameServerError {
    InvalidConfig,
    Bind(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for HostnameServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "hostname server configuration is invalid",
            Self::Bind(_) => "hostname server bind failed",
            Self::Accept(_) => "hostname server accept failed",
        })
    }
}

impl std::error::Error for HostnameServerError {}
