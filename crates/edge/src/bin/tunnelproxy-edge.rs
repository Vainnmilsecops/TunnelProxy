//! Runnable single-tunnel Edge process with graceful OS shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tunnelproxy_common::{shutdown_channel, wait_for_process_shutdown, AgentId, TunnelId};
use tunnelproxy_control_plane::{
    SnapshotBootstrapSource, SnapshotCacheConfig, SnapshotClientConfig, SnapshotTlsConfigError,
};
use tunnelproxy_edge::{
    EdgeRegistrationPolicy, EdgeRegistrationPolicyError, EdgeRuntime, EdgeRuntimeConfig,
    EdgeRuntimeError, EdgeRuntimeOutcome, EdgeTlsConfig, EdgeTlsConfigError, EdgeTransportSecurity,
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
        } => {
            config.multiplex.security = security;
            config.multiplex.registration = registration;
            run_static_edge(config, &parsed).await
        }
        LoadedAuthorization::Snapshot {
            security,
            snapshots,
            cache,
        } => {
            config.multiplex.security = security;
            run_snapshot_edge(config, snapshots, cache, &parsed).await
        }
    }
}

async fn run_static_edge(config: EdgeRuntimeConfig, parsed: &ParsedArgs) -> ExitCode {
    let runtime = match EdgeRuntime::bind(config).await {
        Ok(runtime) => runtime,
        Err(error) => return edge_start_error(error),
    };
    log_edge_started(runtime.agent_addr(), parsed, "static");
    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal);
    tokio::pin!(runtime_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    let result = tokio::select! {
        result = &mut runtime_future => result,
        observed = &mut os_signal => {
            if let Err(error) = observed {
                error!(%error, "OS shutdown listener failed");
                trigger.shutdown();
                let _ = runtime_future.await;
                return ExitCode::from(1);
            }
            trigger.shutdown();
            runtime_future.await
        }
    };
    edge_exit_code(result)
}

async fn run_snapshot_edge(
    config: EdgeRuntimeConfig,
    snapshots: SnapshotClientConfig,
    cache: Option<SnapshotCacheConfig>,
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
    let runtime_future = runtime.run_until_shutdown(signal);
    tokio::pin!(runtime_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    let result = tokio::select! {
        result = &mut runtime_future => result,
        observed = &mut os_signal => {
            if let Err(error) = observed {
                error!(%error, "OS shutdown listener failed");
                trigger.shutdown();
                let _ = runtime_future.await;
                return ExitCode::from(1);
            }
            trigger.shutdown();
            runtime_future.await
        }
    };
    snapshot_edge_exit_code(result)
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
        }
    }
}

enum LoadedAuthorization {
    Static {
        security: EdgeTransportSecurity,
        registration: EdgeRegistrationPolicy,
    },
    Snapshot {
        security: EdgeTransportSecurity,
        snapshots: SnapshotClientConfig,
        cache: Option<SnapshotCacheConfig>,
    },
}

async fn load_transport_configuration(
    parsed: &ParsedArgs,
) -> Result<LoadedAuthorization, TlsLoadError> {
    match (&parsed.tls_cert, &parsed.tls_key, &parsed.tls_client_ca) {
        (None, None, None) => {
            if parsed.authorized_client_cert.is_some() || has_snapshot_arguments(parsed) {
                return Err(TlsLoadError::AuthorizationMode);
            }
            Ok(LoadedAuthorization::Static {
                security: EdgeTransportSecurity::PlaintextLoopback,
                registration: EdgeRegistrationPolicy::loopback_development(
                    parsed.agent_id.clone(),
                    parsed.tunnel_id.clone(),
                ),
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
            let cert = tokio::fs::read(cert)
                .await
                .map_err(|_| TlsLoadError::Read("server certificate"))?;
            let key = tokio::fs::read(key)
                .await
                .map_err(|_| TlsLoadError::Read("server private key"))?;
            let client_ca = tokio::fs::read(client_ca)
                .await
                .map_err(|_| TlsLoadError::Read("client CA"))?;
            let security =
                EdgeTlsConfig::from_pem(&cert, &key, &client_ca, parsed.tls_handshake_timeout)
                    .map(EdgeTransportSecurity::MutualTls)
                    .map_err(TlsLoadError::Invalid)?;
            if snapshot_mode {
                load_snapshot_configuration(parsed, security).await
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
    let (ca, client_cert, client_key) = tokio::try_join!(
        read_tls_file(ca, "snapshot CA"),
        read_tls_file(client_cert, "snapshot client certificate"),
        read_tls_file(client_key, "snapshot client private key"),
    )?;
    let mut snapshots =
        SnapshotClientConfig::from_pem(server, &ca, &client_cert, &client_key, server_name)
            .map_err(TlsLoadError::InvalidSnapshotTls)?;
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
