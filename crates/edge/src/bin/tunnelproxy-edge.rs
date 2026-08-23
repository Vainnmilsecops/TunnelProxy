//! Runnable single-tunnel Edge process with graceful OS shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tunnelproxy_common::{shutdown_channel, wait_for_process_shutdown, AgentId, TunnelId};
use tunnelproxy_control_plane::{
    SnapshotBootstrapSource, SnapshotCacheConfig, SnapshotClientConfig,
    SnapshotClientTlsReloadConfig, SnapshotClientTlsReloadRuntime, SnapshotTlsConfigError,
    SnapshotTlsReloadBootstrapError,
};
use tunnelproxy_edge::{
    EdgeRegistrationPolicy, EdgeRegistrationPolicyError, EdgeRuntime, EdgeRuntimeConfig,
    EdgeRuntimeError, EdgeRuntimeOutcome, EdgeTlsConfig, EdgeTlsConfigError,
    EdgeTlsReloadBootstrapError, EdgeTlsReloadConfig, EdgeTlsReloadRuntime, EdgeTransportSecurity,
    RuntimeShutdownConfig, SnapshotAwareEdgeRuntime, SnapshotAwareEdgeRuntimeError,
    SnapshotAwareEdgeRuntimeOutcome,
};

const USAGE: &str = "\
Usage: tunnelproxy-edge [OPTIONS]

Options:
  --agent-listen <addr>            Agent listener (default 127.0.0.1:7100)
  --raw-listen <addr>              raw ingress   (default 127.0.0.1:7000)
  --agent-id <id>                  authorized Agent ID (default agent-dev)
  --tunnel-id <id>                 authorized Tunnel ID (default tunnel-dev)
  --max-streams <usize>            stream limit  (default 32)
  --max-raw-connections <usize>    ingress limit (default 32)
  --drain-timeout-ms <ms>          stage drain   (default 10000)
  --tls-cert <path>                Edge certificate PEM
  --tls-key <path>                 Edge private key PEM
  --tls-client-ca <path>           trusted Agent CA PEM
  --authorized-client-cert <path>  exact authorized Agent certificate PEM
  --tls-handshake-timeout-ms <ms>  TLS timeout   (default 10000)
  --tls-reload-manifest <path>     Agent-facing TLS generation manifest
  --snapshot-server <addr>         Control Plane snapshot service
  --snapshot-ca <path>             trusted Control Plane CA PEM
  --snapshot-client-cert <path>    Edge snapshot client certificate PEM
  --snapshot-client-key <path>     Edge snapshot client private key PEM
  --snapshot-server-name <name>    Control Plane TLS server name
  --snapshot-connect-timeout-ms <ms>    connect timeout (default 5000)
  --snapshot-handshake-timeout-ms <ms>  TLS timeout (default 5000)
  --snapshot-subscribe-timeout-ms <ms>  subscribe timeout (default 5000)
  --snapshot-reconnect-initial-ms <ms>  first retry delay (default 250)
  --snapshot-reconnect-max-ms <ms>      maximum retry delay (default 30000)
  --snapshot-cache-dir <path>           opt-in cold-start snapshot cache
  --snapshot-cache-max-stale-ms <ms>    maximum offline cache age
  --snapshot-tls-reload-manifest <path> snapshot-client TLS generation manifest
  --tls-reload-interval-ms <ms>         reload poll (default 1000)
  --tls-expiry-warning-ms <ms>          expiry warning (default 604800000)
  --help                           print this help and exit
";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<_> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            error!(%error, "invalid Edge CLI arguments");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if parsed.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let mut config = EdgeRuntimeConfig::dev_defaults();
    config.multiplex.agent_listener.listen_addr = parsed.agent_listen;
    config.multiplex.max_streams_per_session = parsed.max_streams;
    config.raw_listen_addr = parsed.raw_listen;
    config.tunnel_id = parsed.tunnel_id.clone();
    config.max_raw_connections = parsed.max_raw_connections;
    config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
    let authorization = match load_transport_configuration(&parsed).await {
        Ok(configuration) => configuration,
        Err(error) => {
            error!(%error, "failed to configure Edge transport authorization");
            return ExitCode::from(2);
        }
    };
    match authorization {
        LoadedAuthorization::Static {
            security,
            registration,
            reloaders,
        } => {
            config.multiplex.security = security;
            config.multiplex.registration = registration;
            run_static_edge(config, reloaders, &parsed).await
        }
        LoadedAuthorization::Snapshot {
            security,
            snapshots,
            cache,
            reloaders,
        } => {
            config.multiplex.security = security;
            run_snapshot_edge(config, snapshots, cache, reloaders, &parsed).await
        }
    }
}

async fn run_static_edge(
    config: EdgeRuntimeConfig,
    reloaders: LoadedTlsReloaders,
    parsed: &ParsedArgs,
) -> ExitCode {
    let runtime = match EdgeRuntime::bind(config).await {
        Ok(runtime) => runtime,
        Err(error) => return edge_start_error(error),
    };
    log_edge_started(runtime.agent_addr(), parsed, "static");
    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = reloaders.run_until_shutdown(signal);
    tokio::pin!(reload_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = reload_future.await;
            edge_exit_code(result)
        },
        reload = &mut reload_future => {
            trigger.shutdown();
            let _ = runtime_future.await;
            tls_reload_exit_code(reload)
        },
        observed = &mut os_signal => {
            if let Err(error) = observed {
                error!(%error, "OS shutdown listener failed");
                trigger.shutdown();
                let _ = runtime_future.await;
                return ExitCode::from(1);
            }
            trigger.shutdown();
            let result = runtime_future.await;
            let _ = reload_future.await;
            edge_exit_code(result)
        }
    }
}

async fn run_snapshot_edge(
    config: EdgeRuntimeConfig,
    snapshots: SnapshotClientConfig,
    cache: Option<SnapshotCacheConfig>,
    reloaders: LoadedTlsReloaders,
    parsed: &ParsedArgs,
) -> ExitCode {
    let bind_result = match cache {
        Some(cache) => SnapshotAwareEdgeRuntime::bind_with_cache(config, snapshots, cache).await,
        None => SnapshotAwareEdgeRuntime::bind(config, snapshots).await,
    };
    let runtime = match bind_result {
        Ok(runtime) => runtime,
        Err(error) => {
            error!(%error, "failed to bootstrap snapshot-aware Edge runtime");
            return if matches!(
                error,
                SnapshotAwareEdgeRuntimeError::Edge(EdgeRuntimeError::InvalidConfig(_))
            ) {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            };
        }
    };
    let authorization = match runtime.bootstrap_source() {
        SnapshotBootstrapSource::Online => "snapshot-live",
        SnapshotBootstrapSource::DiskCache => "snapshot-stale-cache",
    };
    log_edge_started(runtime.agent_addr(), parsed, authorization);
    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = reloaders.run_until_shutdown(signal);
    tokio::pin!(reload_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = reload_future.await;
            snapshot_edge_exit_code(result)
        },
        reload = &mut reload_future => {
            trigger.shutdown();
            let _ = runtime_future.await;
            tls_reload_exit_code(reload)
        },
        observed = &mut os_signal => {
            if let Err(error) = observed {
                error!(%error, "OS shutdown listener failed");
                trigger.shutdown();
                let _ = runtime_future.await;
                return ExitCode::from(1);
            }
            trigger.shutdown();
            let result = runtime_future.await;
            let _ = reload_future.await;
            snapshot_edge_exit_code(result)
        }
    }
}

fn tls_reload_exit_code(result: Result<(), TlsReloadSupervisorError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "Edge TLS reload runtime failed");
            ExitCode::from(1)
        }
    }
}

fn log_edge_started(agent_addr: SocketAddr, parsed: &ParsedArgs, authorization: &'static str) {
    info!(
        %agent_addr,
        raw_addr = %parsed.raw_listen,
        agent_id = %parsed.agent_id,
        tunnel_id = %parsed.tunnel_id,
        authorization,
        "Edge runtime is waiting for one Agent"
    );
}

fn edge_start_error(error: EdgeRuntimeError) -> ExitCode {
    error!(%error, "failed to start Edge runtime");
    if matches!(error, EdgeRuntimeError::InvalidConfig(_)) {
        ExitCode::from(2)
    } else {
        ExitCode::from(1)
    }
}

fn edge_exit_code(
    result: Result<EdgeRuntimeOutcome, tunnelproxy_edge::EdgeRuntimeError>,
) -> ExitCode {
    match result {
        Ok(outcome) if outcome.was_forced() => {
            warn!(?outcome, "Edge shutdown exceeded a drain deadline");
            ExitCode::from(1)
        }
        Ok(outcome) => {
            info!(?outcome, "Edge shutdown completed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            error!(%error, "Edge runtime failed");
            ExitCode::from(1)
        }
    }
}

fn snapshot_edge_exit_code(
    result: Result<SnapshotAwareEdgeRuntimeOutcome, SnapshotAwareEdgeRuntimeError>,
) -> ExitCode {
    match result {
        Ok(outcome) if outcome.was_forced() => {
            warn!(?outcome, "Edge shutdown exceeded a drain deadline");
            ExitCode::from(1)
        }
        Ok(outcome) => {
            info!(?outcome, "Edge shutdown completed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            error!(%error, "snapshot-aware Edge runtime failed");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    agent_listen: SocketAddr,
    raw_listen: SocketAddr,
    agent_id: AgentId,
    tunnel_id: TunnelId,
    max_streams: usize,
    max_raw_connections: usize,
    drain_timeout: Duration,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    authorized_client_cert: Option<PathBuf>,
    tls_handshake_timeout: Duration,
    tls_reload_manifest: Option<PathBuf>,
    snapshot_server: Option<SocketAddr>,
    snapshot_ca: Option<PathBuf>,
    snapshot_client_cert: Option<PathBuf>,
    snapshot_client_key: Option<PathBuf>,
    snapshot_server_name: Option<String>,
    snapshot_connect_timeout: Duration,
    snapshot_handshake_timeout: Duration,
    snapshot_subscribe_timeout: Duration,
    snapshot_reconnect_initial: Duration,
    snapshot_reconnect_max: Duration,
    snapshot_cache_dir: Option<PathBuf>,
    snapshot_cache_max_stale: Option<Duration>,
    snapshot_tls_reload_manifest: Option<PathBuf>,
    tls_reload_interval: Duration,
    tls_expiry_warning: Duration,
    tls_reload_options_present: bool,
    snapshot_options_present: bool,
    help: bool,
}

impl Default for ParsedArgs {
    fn default() -> Self {
        Self {
            agent_listen: "127.0.0.1:7100".parse().unwrap(),
            raw_listen: "127.0.0.1:7000".parse().unwrap(),
            agent_id: AgentId::new("agent-dev").unwrap(),
            tunnel_id: TunnelId::new("tunnel-dev").unwrap(),
            max_streams: 32,
            max_raw_connections: 32,
            drain_timeout: Duration::from_secs(10),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            authorized_client_cert: None,
            tls_handshake_timeout: Duration::from_secs(10),
            tls_reload_manifest: None,
            snapshot_server: None,
            snapshot_ca: None,
            snapshot_client_cert: None,
            snapshot_client_key: None,
            snapshot_server_name: None,
            snapshot_connect_timeout: Duration::from_secs(5),
            snapshot_handshake_timeout: Duration::from_secs(5),
            snapshot_subscribe_timeout: Duration::from_secs(5),
            snapshot_reconnect_initial: Duration::from_millis(250),
            snapshot_reconnect_max: Duration::from_secs(30),
            snapshot_cache_dir: None,
            snapshot_cache_max_stale: None,
            snapshot_tls_reload_manifest: None,
            tls_reload_interval: Duration::from_secs(1),
            tls_expiry_warning: Duration::from_secs(7 * 24 * 60 * 60),
            tls_reload_options_present: false,
            snapshot_options_present: false,
            help: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ArgError {
    MissingValue(String),
    InvalidAddress { flag: String, value: String },
    InvalidNumber { flag: String, value: String },
    InvalidIdentifier { flag: String, value: String },
    UnknownFlag(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValue(flag) => write!(f, "{flag} requires a value"),
            Self::InvalidAddress { flag, value } => {
                write!(f, "{flag}={value} is not a valid socket address")
            }
            Self::InvalidNumber { flag, value } => {
                write!(f, "{flag}={value} is not a valid integer")
            }
            Self::InvalidIdentifier { flag, value } => {
                write!(f, "{flag}={value} is not a valid durable identifier")
            }
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, ArgError> {
    let mut parsed = ParsedArgs::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--help" | "-h" => {
                parsed.help = true;
                index += 1;
            }
            "--agent-listen" => {
                parsed.agent_listen = parse_addr(args, index, flag)?;
                index += 2;
            }
            "--raw-listen" => {
                parsed.raw_listen = parse_addr(args, index, flag)?;
                index += 2;
            }
            "--agent-id" => {
                parsed.agent_id = parse_agent_id(args, index, flag)?;
                index += 2;
            }
            "--tunnel-id" => {
                parsed.tunnel_id = parse_tunnel_id(args, index, flag)?;
                index += 2;
            }
            "--max-streams" => {
                parsed.max_streams = parse_number(args, index, flag)?;
                index += 2;
            }
            "--max-raw-connections" => {
                parsed.max_raw_connections = parse_number(args, index, flag)?;
                index += 2;
            }
            "--drain-timeout-ms" => {
                parsed.drain_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--tls-cert" => {
                parsed.tls_cert = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-key" => {
                parsed.tls_key = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-client-ca" => {
                parsed.tls_client_ca = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--authorized-client-cert" => {
                parsed.authorized_client_cert = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-handshake-timeout-ms" => {
                parsed.tls_handshake_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--tls-reload-manifest" => {
                parsed.tls_reload_manifest = Some(PathBuf::from(value(args, index, flag)?));
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            "--snapshot-server" => {
                parsed.snapshot_server = Some(parse_addr(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-ca" => {
                parsed.snapshot_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-client-cert" => {
                parsed.snapshot_client_cert = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-client-key" => {
                parsed.snapshot_client_key = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-server-name" => {
                parsed.snapshot_server_name = Some(value(args, index, flag)?.to_owned());
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-connect-timeout-ms" => {
                parsed.snapshot_connect_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-handshake-timeout-ms" => {
                parsed.snapshot_handshake_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-subscribe-timeout-ms" => {
                parsed.snapshot_subscribe_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-reconnect-initial-ms" => {
                parsed.snapshot_reconnect_initial =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-reconnect-max-ms" => {
                parsed.snapshot_reconnect_max =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-cache-dir" => {
                parsed.snapshot_cache_dir = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-cache-max-stale-ms" => {
                parsed.snapshot_cache_max_stale =
                    Some(Duration::from_millis(parse_number(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-tls-reload-manifest" => {
                parsed.snapshot_tls_reload_manifest =
                    Some(PathBuf::from(value(args, index, flag)?));
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            "--tls-reload-interval-ms" => {
                parsed.tls_reload_interval =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            "--tls-expiry-warning-ms" => {
                parsed.tls_expiry_warning = Duration::from_millis(parse_number(args, index, flag)?);
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            other => return Err(ArgError::UnknownFlag(other.to_string())),
        }
    }
    Ok(parsed)
}

#[derive(Debug)]
enum TlsLoadError {
    IncompleteArguments,
    AuthorizationMode,
    IncompleteSnapshotArguments,
    Read(&'static str),
    Invalid(EdgeTlsConfigError),
    InvalidRegistration(EdgeRegistrationPolicyError),
    InvalidSnapshotTls(SnapshotTlsConfigError),
    InvalidSnapshotConfig,
    IncompleteSnapshotCacheArguments,
    InvalidSnapshotCache,
    ReloadArguments,
    EdgeReload(EdgeTlsReloadBootstrapError),
    SnapshotReload(SnapshotTlsReloadBootstrapError),
}

impl std::fmt::Display for TlsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "Agent TLS requires --tls-cert, --tls-key, and --tls-client-ca",
            ),
            Self::AuthorizationMode => f.write_str(
                "Agent TLS requires exactly one authorization source: --authorized-client-cert or the complete snapshot group",
            ),
            Self::IncompleteSnapshotArguments => f.write_str(
                "snapshot authorization requires server, CA, client certificate/key, and server name",
            ),
            Self::Read(kind) => write!(f, "failed to read TLS {kind} PEM file"),
            Self::Invalid(error) => write!(f, "invalid TLS configuration: {error}"),
            Self::InvalidRegistration(error) => {
                write!(f, "invalid registration authorization: {error}")
            }
            Self::InvalidSnapshotTls(error) => {
                write!(f, "invalid snapshot TLS configuration: {error}")
            }
            Self::InvalidSnapshotConfig => f.write_str("snapshot client configuration is invalid"),
            Self::IncompleteSnapshotCacheArguments => f.write_str(
                "snapshot cache requires both --snapshot-cache-dir and --snapshot-cache-max-stale-ms",
            ),
            Self::InvalidSnapshotCache => {
                f.write_str("snapshot cache directory and maximum stale age are invalid")
            }
            Self::ReloadArguments => f.write_str(
                "TLS reload manifests require complete matching TLS path groups and non-zero reload settings",
            ),
            Self::EdgeReload(error) => write!(f, "Agent-facing TLS reload is invalid: {error}"),
            Self::SnapshotReload(error) => {
                write!(f, "snapshot-client TLS reload is invalid: {error}")
            }
        }
    }
}

#[derive(Default)]
struct LoadedTlsReloaders {
    edge: Option<EdgeTlsReloadRuntime>,
    snapshot: Option<SnapshotClientTlsReloadRuntime>,
}

impl LoadedTlsReloaders {
    async fn run_until_shutdown(
        self,
        signal: tunnelproxy_common::ShutdownSignal,
    ) -> Result<(), TlsReloadSupervisorError> {
        let mut tasks = tokio::task::JoinSet::new();
        if let Some(runtime) = self.edge {
            let child_signal = signal.clone();
            tasks.spawn(async move {
                runtime
                    .run_until_shutdown(child_signal)
                    .await
                    .map_err(TlsReloadSupervisorError::Edge)
            });
        }
        if let Some(runtime) = self.snapshot {
            let child_signal = signal.clone();
            tasks.spawn(async move {
                runtime
                    .run_until_shutdown(child_signal)
                    .await
                    .map_err(TlsReloadSupervisorError::Snapshot)
            });
        }
        if tasks.is_empty() {
            signal.cancelled().await;
            return Ok(());
        }
        tokio::select! {
            biased;
            () = signal.cancelled() => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Ok(())
            }
            result = tasks.join_next() => match result {
                Some(Ok(result)) => result,
                Some(Err(_)) | None => Err(TlsReloadSupervisorError::Task),
            }
        }
    }
}

#[derive(Debug)]
enum TlsReloadSupervisorError {
    Edge(tunnelproxy_common::TlsReloadRuntimeError),
    Snapshot(tunnelproxy_common::TlsReloadRuntimeError),
    Task,
}

impl std::fmt::Display for TlsReloadSupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Edge(error) => write!(f, "Agent-facing TLS reload failed: {error}"),
            Self::Snapshot(error) => write!(f, "snapshot-client TLS reload failed: {error}"),
            Self::Task => f.write_str("TLS reload task stopped unexpectedly"),
        }
    }
}

enum LoadedAuthorization {
    Static {
        security: EdgeTransportSecurity,
        registration: EdgeRegistrationPolicy,
        reloaders: LoadedTlsReloaders,
    },
    Snapshot {
        security: EdgeTransportSecurity,
        snapshots: SnapshotClientConfig,
        cache: Option<SnapshotCacheConfig>,
        reloaders: LoadedTlsReloaders,
    },
}

async fn load_transport_configuration(
    parsed: &ParsedArgs,
) -> Result<LoadedAuthorization, TlsLoadError> {
    match (&parsed.tls_cert, &parsed.tls_key, &parsed.tls_client_ca) {
        (None, None, None) => {
            if parsed.authorized_client_cert.is_some()
                || has_snapshot_arguments(parsed)
                || parsed.tls_reload_options_present
            {
                return Err(TlsLoadError::AuthorizationMode);
            }
            Ok(LoadedAuthorization::Static {
                security: EdgeTransportSecurity::PlaintextLoopback,
                registration: EdgeRegistrationPolicy::loopback_development(
                    parsed.agent_id.clone(),
                    parsed.tunnel_id.clone(),
                ),
                reloaders: LoadedTlsReloaders::default(),
            })
        }
        (Some(cert), Some(key), Some(client_ca)) => {
            let snapshot_mode = match (
                &parsed.authorized_client_cert,
                has_snapshot_arguments(parsed),
            ) {
                (Some(_), true) | (None, false) => return Err(TlsLoadError::AuthorizationMode),
                (Some(_), false) => false,
                (None, true) if snapshot_arguments_complete(parsed) => true,
                (None, true) => return Err(TlsLoadError::IncompleteSnapshotArguments),
            };
            if parsed.tls_reload_options_present
                && parsed.tls_reload_manifest.is_none()
                && parsed.snapshot_tls_reload_manifest.is_none()
            {
                return Err(TlsLoadError::ReloadArguments);
            }
            if !snapshot_mode && parsed.snapshot_tls_reload_manifest.is_some() {
                return Err(TlsLoadError::ReloadArguments);
            }
            if !snapshot_mode {
                if let Some(manifest_path) = &parsed.tls_reload_manifest {
                    let Some(authorized_client_certificate_path) = &parsed.authorized_client_cert
                    else {
                        return Err(TlsLoadError::AuthorizationMode);
                    };
                    let (tls, registration, runtime) =
                        EdgeTlsReloadRuntime::bootstrap_with_static_authorization(
                            EdgeTlsReloadConfig {
                                manifest_path: manifest_path.clone(),
                                server_certificate_path: cert.clone(),
                                server_private_key_path: key.clone(),
                                client_ca_path: client_ca.clone(),
                                poll_interval: parsed.tls_reload_interval,
                                expiry_warning: parsed.tls_expiry_warning,
                            },
                            authorized_client_certificate_path.clone(),
                            parsed.tls_handshake_timeout,
                            parsed.agent_id.clone(),
                            parsed.tunnel_id.clone(),
                        )
                        .await
                        .map_err(TlsLoadError::EdgeReload)?;
                    return Ok(LoadedAuthorization::Static {
                        security: EdgeTransportSecurity::MutualTls(tls),
                        registration,
                        reloaders: LoadedTlsReloaders {
                            edge: Some(runtime),
                            snapshot: None,
                        },
                    });
                }
            }
            let (tls, edge_reloader) = if let Some(manifest_path) = &parsed.tls_reload_manifest {
                let (tls, runtime) = EdgeTlsReloadRuntime::bootstrap(
                    EdgeTlsReloadConfig {
                        manifest_path: manifest_path.clone(),
                        server_certificate_path: cert.clone(),
                        server_private_key_path: key.clone(),
                        client_ca_path: client_ca.clone(),
                        poll_interval: parsed.tls_reload_interval,
                        expiry_warning: parsed.tls_expiry_warning,
                    },
                    parsed.tls_handshake_timeout,
                )
                .await
                .map_err(TlsLoadError::EdgeReload)?;
                (tls, Some(runtime))
            } else {
                let cert = tokio::fs::read(cert)
                    .await
                    .map_err(|_| TlsLoadError::Read("server certificate"))?;
                let key = tokio::fs::read(key)
                    .await
                    .map_err(|_| TlsLoadError::Read("server private key"))?;
                let client_ca = tokio::fs::read(client_ca)
                    .await
                    .map_err(|_| TlsLoadError::Read("client CA"))?;
                let tls =
                    EdgeTlsConfig::from_pem(&cert, &key, &client_ca, parsed.tls_handshake_timeout)
                        .map_err(TlsLoadError::Invalid)?;
                (tls, None)
            };
            let security = EdgeTransportSecurity::MutualTls(tls);
            if snapshot_mode {
                load_snapshot_configuration(parsed, security, edge_reloader).await
            } else {
                let Some(authorized_client_cert) = &parsed.authorized_client_cert else {
                    return Err(TlsLoadError::AuthorizationMode);
                };
                let authorized_client_cert = tokio::fs::read(authorized_client_cert)
                    .await
                    .map_err(|_| TlsLoadError::Read("authorized client certificate"))?;
                let registration = EdgeRegistrationPolicy::mutual_tls_from_client_cert_pem(
                    parsed.agent_id.clone(),
                    parsed.tunnel_id.clone(),
                    &authorized_client_cert,
                )
                .map_err(TlsLoadError::InvalidRegistration)?;
                Ok(LoadedAuthorization::Static {
                    security,
                    registration,
                    reloaders: LoadedTlsReloaders {
                        edge: edge_reloader,
                        snapshot: None,
                    },
                })
            }
        }
        _ => Err(TlsLoadError::IncompleteArguments),
    }
}

fn has_snapshot_arguments(parsed: &ParsedArgs) -> bool {
    parsed.snapshot_options_present
}

fn snapshot_arguments_complete(parsed: &ParsedArgs) -> bool {
    parsed.snapshot_server.is_some()
        && parsed.snapshot_ca.is_some()
        && parsed.snapshot_client_cert.is_some()
        && parsed.snapshot_client_key.is_some()
        && parsed.snapshot_server_name.is_some()
}

async fn load_snapshot_configuration(
    parsed: &ParsedArgs,
    security: EdgeTransportSecurity,
    edge_reloader: Option<EdgeTlsReloadRuntime>,
) -> Result<LoadedAuthorization, TlsLoadError> {
    let cache = snapshot_cache_configuration(parsed)?;
    let (Some(server), Some(ca), Some(client_cert), Some(client_key), Some(server_name)) = (
        parsed.snapshot_server,
        parsed.snapshot_ca.as_ref(),
        parsed.snapshot_client_cert.as_ref(),
        parsed.snapshot_client_key.as_ref(),
        parsed.snapshot_server_name.as_deref(),
    ) else {
        return Err(TlsLoadError::IncompleteSnapshotArguments);
    };
    let (mut snapshots, snapshot_reloader) =
        if let Some(manifest_path) = &parsed.snapshot_tls_reload_manifest {
            let (config, runtime) = SnapshotClientTlsReloadRuntime::bootstrap(
                server,
                server_name,
                SnapshotClientTlsReloadConfig {
                    manifest_path: manifest_path.clone(),
                    server_ca_path: ca.clone(),
                    client_certificate_path: client_cert.clone(),
                    client_private_key_path: client_key.clone(),
                    poll_interval: parsed.tls_reload_interval,
                    expiry_warning: parsed.tls_expiry_warning,
                },
            )
            .await
            .map_err(TlsLoadError::SnapshotReload)?;
            (config, Some(runtime))
        } else {
            let (ca, client_cert, client_key) = tokio::try_join!(
                read_tls_file(ca, "snapshot CA"),
                read_tls_file(client_cert, "snapshot client certificate"),
                read_tls_file(client_key, "snapshot client private key"),
            )?;
            let config =
                SnapshotClientConfig::from_pem(server, &ca, &client_cert, &client_key, server_name)
                    .map_err(TlsLoadError::InvalidSnapshotTls)?;
            (config, None)
        };
    snapshots.connect_timeout = parsed.snapshot_connect_timeout;
    snapshots.handshake_timeout = parsed.snapshot_handshake_timeout;
    snapshots.subscribe_timeout = parsed.snapshot_subscribe_timeout;
    snapshots.reconnect_initial_delay = parsed.snapshot_reconnect_initial;
    snapshots.reconnect_max_delay = parsed.snapshot_reconnect_max;
    snapshots
        .validate()
        .map_err(|_| TlsLoadError::InvalidSnapshotConfig)?;
    Ok(LoadedAuthorization::Snapshot {
        security,
        snapshots,
        cache,
        reloaders: LoadedTlsReloaders {
            edge: edge_reloader,
            snapshot: snapshot_reloader,
        },
    })
}

fn snapshot_cache_configuration(
    parsed: &ParsedArgs,
) -> Result<Option<SnapshotCacheConfig>, TlsLoadError> {
    match (
        parsed.snapshot_cache_dir.clone(),
        parsed.snapshot_cache_max_stale,
    ) {
        (None, None) => Ok(None),
        (Some(directory), Some(max_stale_age)) => {
            let config = SnapshotCacheConfig {
                directory,
                max_stale_age,
            };
            config
                .validate()
                .map_err(|_| TlsLoadError::InvalidSnapshotCache)?;
            Ok(Some(config))
        }
        _ => Err(TlsLoadError::IncompleteSnapshotCacheArguments),
    }
}

async fn read_tls_file(path: &PathBuf, kind: &'static str) -> Result<Vec<u8>, TlsLoadError> {
    tokio::fs::read(path)
        .await
        .map_err(|_| TlsLoadError::Read(kind))
}

fn value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, ArgError> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| ArgError::MissingValue(flag.to_string()))
}

fn parse_addr(args: &[String], index: usize, flag: &str) -> Result<SocketAddr, ArgError> {
    let raw = value(args, index, flag)?;
    raw.parse().map_err(|_| ArgError::InvalidAddress {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

fn parse_number<T>(args: &[String], index: usize, flag: &str) -> Result<T, ArgError>
where
    T: std::str::FromStr,
{
    let raw = value(args, index, flag)?;
    raw.parse().map_err(|_| ArgError::InvalidNumber {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

fn parse_agent_id(args: &[String], index: usize, flag: &str) -> Result<AgentId, ArgError> {
    let raw = value(args, index, flag)?;
    AgentId::new(raw).map_err(|_| ArgError::InvalidIdentifier {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

fn parse_tunnel_id(args: &[String], index: usize, flag: &str) -> Result<TunnelId, ArgError> {
    let raw = value(args, index, flag)?;
    TunnelId::new(raw).map_err(|_| ArgError::InvalidIdentifier {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn defaults_are_stable() {
        assert_eq!(parse_args(&[]).unwrap(), ParsedArgs::default());
    }

    #[test]
    fn all_flags_parse() {
        let parsed = parse_args(&args(&[
            "--agent-listen",
            "127.0.0.1:17100",
            "--raw-listen",
            "127.0.0.1:17000",
            "--agent-id",
            "agent-prod",
            "--tunnel-id",
            "tunnel-prod",
            "--max-streams",
            "8",
            "--max-raw-connections",
            "9",
            "--drain-timeout-ms",
            "250",
            "--tls-cert",
            "edge.pem",
            "--tls-key",
            "edge-key.pem",
            "--tls-client-ca",
            "ca.pem",
            "--authorized-client-cert",
            "agent.pem",
            "--tls-handshake-timeout-ms",
            "350",
            "--tls-reload-manifest",
            "edge-tls.json",
            "--snapshot-server",
            "127.0.0.1:17200",
            "--snapshot-ca",
            "control-ca.pem",
            "--snapshot-client-cert",
            "edge-client.pem",
            "--snapshot-client-key",
            "edge-client-key.pem",
            "--snapshot-server-name",
            "control-plane.test",
            "--snapshot-connect-timeout-ms",
            "101",
            "--snapshot-handshake-timeout-ms",
            "102",
            "--snapshot-subscribe-timeout-ms",
            "103",
            "--snapshot-reconnect-initial-ms",
            "104",
            "--snapshot-reconnect-max-ms",
            "105",
            "--snapshot-cache-dir",
            "edge-cache",
            "--snapshot-cache-max-stale-ms",
            "60000",
            "--snapshot-tls-reload-manifest",
            "snapshot-client-tls.json",
            "--tls-reload-interval-ms",
            "106",
            "--tls-expiry-warning-ms",
            "107",
        ]))
        .unwrap();
        assert_eq!(parsed.agent_listen.port(), 17100);
        assert_eq!(parsed.raw_listen.port(), 17000);
        assert_eq!(parsed.agent_id.as_str(), "agent-prod");
        assert_eq!(parsed.tunnel_id.as_str(), "tunnel-prod");
        assert_eq!(parsed.max_streams, 8);
        assert_eq!(parsed.max_raw_connections, 9);
        assert_eq!(parsed.drain_timeout, Duration::from_millis(250));
        assert_eq!(parsed.tls_cert, Some(PathBuf::from("edge.pem")));
        assert_eq!(parsed.tls_key, Some(PathBuf::from("edge-key.pem")));
        assert_eq!(parsed.tls_client_ca, Some(PathBuf::from("ca.pem")));
        assert_eq!(
            parsed.authorized_client_cert,
            Some(PathBuf::from("agent.pem"))
        );
        assert_eq!(parsed.tls_handshake_timeout, Duration::from_millis(350));
        assert_eq!(
            parsed.tls_reload_manifest,
            Some(PathBuf::from("edge-tls.json"))
        );
        assert_eq!(parsed.snapshot_server.unwrap().port(), 17200);
        assert_eq!(parsed.snapshot_ca, Some(PathBuf::from("control-ca.pem")));
        assert_eq!(
            parsed.snapshot_server_name.as_deref(),
            Some("control-plane.test")
        );
        assert_eq!(parsed.snapshot_connect_timeout, Duration::from_millis(101));
        assert_eq!(parsed.snapshot_reconnect_max, Duration::from_millis(105));
        assert_eq!(parsed.snapshot_cache_dir, Some(PathBuf::from("edge-cache")));
        assert_eq!(
            parsed.snapshot_cache_max_stale,
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parsed.snapshot_tls_reload_manifest,
            Some(PathBuf::from("snapshot-client-tls.json"))
        );
        assert_eq!(parsed.tls_reload_interval, Duration::from_millis(106));
        assert_eq!(parsed.tls_expiry_warning, Duration::from_millis(107));
        assert!(parsed.snapshot_options_present);
    }

    #[test]
    fn invalid_and_missing_values_are_typed() {
        assert!(matches!(
            parse_args(&args(&["--raw-listen", "bad"])),
            Err(ArgError::InvalidAddress { .. })
        ));
        assert!(matches!(
            parse_args(&args(&["--max-streams"])),
            Err(ArgError::MissingValue(_))
        ));
        assert!(matches!(
            parse_args(&args(&["--unknown"])),
            Err(ArgError::UnknownFlag(_))
        ));
        assert!(matches!(
            parse_args(&args(&["--tunnel-id", "bad/id"])),
            Err(ArgError::InvalidIdentifier { .. })
        ));
    }

    #[tokio::test]
    async fn partial_tls_arguments_are_rejected() {
        let parsed = ParsedArgs {
            tls_cert: Some(PathBuf::from("edge.pem")),
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_configuration(&parsed).await,
            Err(TlsLoadError::IncompleteArguments)
        ));

        let partial_snapshot = ParsedArgs {
            tls_cert: Some(PathBuf::from("edge.pem")),
            tls_key: Some(PathBuf::from("edge-key.pem")),
            tls_client_ca: Some(PathBuf::from("agent-ca.pem")),
            snapshot_server: Some("127.0.0.1:7200".parse().unwrap()),
            snapshot_options_present: true,
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_configuration(&partial_snapshot).await,
            Err(TlsLoadError::IncompleteSnapshotArguments)
        ));

        let conflicting = ParsedArgs {
            authorized_client_cert: Some(PathBuf::from("agent.pem")),
            ..partial_snapshot
        };
        assert!(matches!(
            load_transport_configuration(&conflicting).await,
            Err(TlsLoadError::AuthorizationMode)
        ));

        let partial_cache = ParsedArgs {
            tls_cert: Some(PathBuf::from("edge.pem")),
            tls_key: Some(PathBuf::from("edge-key.pem")),
            tls_client_ca: Some(PathBuf::from("agent-ca.pem")),
            snapshot_server: Some("127.0.0.1:7200".parse().unwrap()),
            snapshot_ca: Some(PathBuf::from("control-ca.pem")),
            snapshot_client_cert: Some(PathBuf::from("edge-client.pem")),
            snapshot_client_key: Some(PathBuf::from("edge-client-key.pem")),
            snapshot_server_name: Some("control-plane.test".to_owned()),
            snapshot_cache_dir: Some(PathBuf::from("edge-cache")),
            snapshot_options_present: true,
            ..ParsedArgs::default()
        };
        assert!(matches!(
            snapshot_cache_configuration(&partial_cache),
            Err(TlsLoadError::IncompleteSnapshotCacheArguments)
        ));
    }
}
