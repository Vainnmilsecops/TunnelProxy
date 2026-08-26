//! Runnable outbound Agent process with graceful OS shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info};
use tunnelproxy_agent::{
    bootstrap_agent_credentials, AgentEnrollmentConfig, AgentEnrollmentError,
    AgentEnrollmentRuntime, AgentRuntime, AgentRuntimeConfig, AgentRuntimeOutcome, AgentTlsConfig,
    AgentTlsConfigError, AgentTlsReloadBootstrapError, AgentTlsReloadConfig, AgentTlsReloadRuntime,
    AgentTransportSecurity, EnrollmentClientConfig, RuntimeShutdownConfig,
};
use tunnelproxy_common::{
    init_process_logging, shutdown_channel, wait_for_process_shutdown, AgentCredentialPaths,
    AgentId, ProcessLogFormat, TunnelId,
};
use tunnelproxy_protocol::RegistrationRequest;

const USAGE: &str = "\
Usage: tunnelproxy-agent [OPTIONS]

Options:
  --edge <addr>                  Edge address  (default 127.0.0.1:7100)
  --local <addr>                 local service (default 127.0.0.1:3000)
  --agent-id <id>                durable Agent ID (default agent-dev)
  --tunnel-id <id>               durable Tunnel ID (default tunnel-dev)
  --max-streams <usize>          stream limit  (default 32)
  --connect-timeout-ms <ms>      TCP timeout   (default 5000)
  --handshake-timeout-ms <ms>    handshake     (default 10000)
  --drain-timeout-ms <ms>        stream drain  (default 10000)
  --reconnect-initial-ms <ms>    first retry   (default 250)
  --reconnect-max-ms <ms>        retry ceiling (default 30000)
  --reconnect-multiplier <n>     backoff factor(default 2)
  --reconnect-jitter-percent <n> downward jitter (default 20)
  --stable-session-reset-ms <ms> reset streak  (default 30000)
  --max-reconnect-attempts <n>   failure limit (default unlimited)
  --tls-ca <path>                trusted Edge CA PEM
  --tls-client-cert <path>       Agent certificate PEM
  --tls-client-key <path>        Agent private key PEM
  --tls-server-name <name>       verified Edge DNS name
  --tls-handshake-timeout-ms <ms> TLS timeout  (default 10000)
  --tls-reload-manifest <path>   atomic TLS generation manifest
  --tls-reload-interval-ms <ms>  reload poll   (default 1000)
  --tls-expiry-warning-ms <ms>   expiry warning(default 604800000)
  --enroll-only                  enroll/renew credentials and exit
  --enrollment-server <addr>     Control Plane enrollment address
  --enrollment-ca <path>         trusted enrollment server CA PEM
  --enrollment-server-name <name> verified enrollment DNS name
  --enrollment-token <path>      bootstrap/current renewal token file
  --enrollment-pending <path>    durable enrollment journal file
  --renew-before-ms <ms>         renew before expiry (default 604800000)
  --enrollment-poll-ms <ms>      renewal poll interval (default 60000)
  --enrollment-connect-timeout-ms <ms> TCP timeout (default 5000)
  --enrollment-handshake-timeout-ms <ms> TLS timeout (default 10000)
  --enrollment-request-timeout-ms <ms> request timeout (default 30000)
  --enrollment-activation-timeout-ms <ms> reload wait (default 30000)
  --help                         print this help and exit
";

#[tokio::main]
async fn main() -> ExitCode {
    let log_format = match init_process_logging() {
        Ok(format) => format,
        Err(error) => {
            eprintln!("failed to configure logging: {error}");
            return ExitCode::from(2);
        }
    };
    let args: Vec<_> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            error!(%error, "invalid Agent CLI arguments");
            print_usage_for_error(log_format);
            return ExitCode::from(2);
        }
    };
    if parsed.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let enrollment_config = match load_enrollment_config(&parsed).await {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "failed to configure Agent enrollment");
            return ExitCode::from(2);
        }
    };
    if parsed.enroll_only {
        let Some(config) = enrollment_config.as_ref() else {
            error!("--enroll-only requires complete enrollment arguments");
            return ExitCode::from(2);
        };
        return match bootstrap_agent_credentials(config).await {
            Ok(generation) => {
                info!(generation, "Agent credential enrollment completed");
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "Agent credential enrollment failed");
                ExitCode::from(1)
            }
        };
    }

    let mut config = AgentRuntimeConfig::new(parsed.edge, parsed.local);
    config.connect_timeout = parsed.connect_timeout;
    config.handshake_timeout = parsed.handshake_timeout;
    config.multiplex.max_concurrent_streams = parsed.max_streams;
    config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
    config.reconnect.initial_delay = parsed.reconnect_initial;
    config.reconnect.max_delay = parsed.reconnect_max;
    config.reconnect.multiplier = parsed.reconnect_multiplier;
    config.reconnect.jitter_percent = parsed.reconnect_jitter_percent;
    config.reconnect.stable_session_reset_after = parsed.stable_session_reset;
    config.reconnect.max_attempts = parsed.max_reconnect_attempts;
    config.registration =
        RegistrationRequest::new(parsed.agent_id.clone(), parsed.tunnel_id.clone());
    let loaded_tls = match load_transport_security(&parsed).await {
        Ok(security) => security,
        Err(error) => {
            error!(%error, "failed to configure Agent TLS");
            return ExitCode::from(2);
        }
    };
    let enrollment_runtime = match (&enrollment_config, &loaded_tls.security) {
        (Some(enrollment), AgentTransportSecurity::MutualTls(tls)) => {
            match AgentEnrollmentRuntime::new(enrollment.clone(), tls.clone()) {
                Ok(runtime) => Some(runtime),
                Err(error) => {
                    error!(%error, "failed to configure Agent renewal runtime");
                    return ExitCode::from(2);
                }
            }
        }
        (Some(_), AgentTransportSecurity::PlaintextLoopback) => {
            error!("automatic renewal requires Agent mutual TLS");
            return ExitCode::from(2);
        }
        (None, _) => None,
    };
    config.security = loaded_tls.security;
    let runtime = match AgentRuntime::new(config) {
        Ok(runtime) => runtime,
        Err(error) => {
            error!(%error, "failed to configure Agent runtime");
            return ExitCode::from(2);
        }
    };
    info!(
        edge = %parsed.edge,
        local = %parsed.local,
        agent_id = %parsed.agent_id,
        tunnel_id = %parsed.tunnel_id,
        "Agent runtime starting"
    );

    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = run_optional_tls_reloader(loaded_tls.reloader, signal.clone());
    tokio::pin!(reload_future);
    let enrollment_future = run_optional_enrollment(enrollment_runtime, signal.clone());
    tokio::pin!(enrollment_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    return tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            agent_exit_code(result)
        },
        reload = &mut reload_future => {
            trigger.shutdown();
            let _ = runtime_future.await;
            let _ = enrollment_future.await;
            match reload {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(%error, "Agent TLS reload runtime failed");
                    ExitCode::from(1)
                }
            }
        },
        enrollment = &mut enrollment_future => {
            trigger.shutdown();
            let _ = runtime_future.await;
            let _ = reload_future.await;
            match enrollment {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(%error, "Agent enrollment runtime failed");
                    ExitCode::from(1)
                }
            }
        },
        observed = &mut os_signal => {
            match observed {
                Ok(cause) => info!(%cause, "process shutdown requested"),
                Err(error) => {
                    error!(%error, "OS shutdown listener failed");
                    trigger.shutdown();
                    let _ = runtime_future.await;
                    let _ = reload_future.await;
                    let _ = enrollment_future.await;
                    return ExitCode::from(1);
                }
            }
            trigger.shutdown();
            let result = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            agent_exit_code(result)
        }
    };
}

fn print_usage_for_error(log_format: ProcessLogFormat) {
    if log_format == ProcessLogFormat::Text {
        eprintln!("{USAGE}");
    }
}

async fn run_optional_enrollment(
    runtime: Option<AgentEnrollmentRuntime>,
    signal: tunnelproxy_common::ShutdownSignal,
) -> Result<(), AgentEnrollmentError> {
    match runtime {
        Some(runtime) => runtime.run_until_shutdown(signal).await,
        None => {
            signal.cancelled().await;
            Ok(())
        }
    }
}

async fn run_optional_tls_reloader(
    reloader: Option<AgentTlsReloadRuntime>,
    signal: tunnelproxy_common::ShutdownSignal,
) -> Result<(), tunnelproxy_common::TlsReloadRuntimeError> {
    match reloader {
        Some(reloader) => reloader.run_until_shutdown(signal).await,
        None => {
            signal.cancelled().await;
            Ok(())
        }
    }
}

fn agent_exit_code(
    result: Result<AgentRuntimeOutcome, tunnelproxy_agent::AgentRuntimeError>,
) -> ExitCode {
    match result {
        Ok(outcome) if outcome.is_graceful_shutdown() => {
            info!(?outcome, "Agent shutdown completed");
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
            error!(?outcome, "Agent stopped without a local shutdown request");
            ExitCode::from(1)
        }
        Err(error) => {
            error!(%error, "Agent runtime failed");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    edge: SocketAddr,
    local: SocketAddr,
    agent_id: AgentId,
    tunnel_id: TunnelId,
    max_streams: usize,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    drain_timeout: Duration,
    reconnect_initial: Duration,
    reconnect_max: Duration,
    reconnect_multiplier: u32,
    reconnect_jitter_percent: u8,
    stable_session_reset: Duration,
    max_reconnect_attempts: Option<u32>,
    tls_ca: Option<PathBuf>,
    tls_client_cert: Option<PathBuf>,
    tls_client_key: Option<PathBuf>,
    tls_server_name: Option<String>,
    tls_handshake_timeout: Duration,
    tls_reload_manifest: Option<PathBuf>,
    tls_reload_interval: Duration,
    tls_expiry_warning: Duration,
    tls_reload_options_present: bool,
    enroll_only: bool,
    enrollment_server: Option<SocketAddr>,
    enrollment_ca: Option<PathBuf>,
    enrollment_server_name: Option<String>,
    enrollment_token: Option<PathBuf>,
    enrollment_pending: Option<PathBuf>,
    renew_before: Duration,
    enrollment_poll: Duration,
    enrollment_connect_timeout: Duration,
    enrollment_handshake_timeout: Duration,
    enrollment_request_timeout: Duration,
    enrollment_activation_timeout: Duration,
    enrollment_options_present: bool,
    help: bool,
}

impl Default for ParsedArgs {
    fn default() -> Self {
        Self {
            edge: "127.0.0.1:7100".parse().unwrap(),
            local: "127.0.0.1:3000".parse().unwrap(),
            agent_id: AgentId::new("agent-dev").unwrap(),
            tunnel_id: TunnelId::new("tunnel-dev").unwrap(),
            max_streams: 32,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
            reconnect_initial: Duration::from_millis(250),
            reconnect_max: Duration::from_secs(30),
            reconnect_multiplier: 2,
            reconnect_jitter_percent: 20,
            stable_session_reset: Duration::from_secs(30),
            max_reconnect_attempts: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            tls_server_name: None,
            tls_handshake_timeout: Duration::from_secs(10),
            tls_reload_manifest: None,
            tls_reload_interval: Duration::from_secs(1),
            tls_expiry_warning: Duration::from_secs(7 * 24 * 60 * 60),
            tls_reload_options_present: false,
            enroll_only: false,
            enrollment_server: None,
            enrollment_ca: None,
            enrollment_server_name: None,
            enrollment_token: None,
            enrollment_pending: None,
            renew_before: Duration::from_secs(7 * 24 * 60 * 60),
            enrollment_poll: Duration::from_secs(60),
            enrollment_connect_timeout: Duration::from_secs(5),
            enrollment_handshake_timeout: Duration::from_secs(10),
            enrollment_request_timeout: Duration::from_secs(30),
            enrollment_activation_timeout: Duration::from_secs(30),
            enrollment_options_present: false,
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
            "--edge" => {
                parsed.edge = parse_addr(args, index, flag)?;
                index += 2;
            }
            "--local" => {
                parsed.local = parse_addr(args, index, flag)?;
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
            "--connect-timeout-ms" => {
                parsed.connect_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--handshake-timeout-ms" => {
                parsed.handshake_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--drain-timeout-ms" => {
                parsed.drain_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--reconnect-initial-ms" => {
                parsed.reconnect_initial = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--reconnect-max-ms" => {
                parsed.reconnect_max = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--reconnect-multiplier" => {
                parsed.reconnect_multiplier = parse_number(args, index, flag)?;
                index += 2;
            }
            "--reconnect-jitter-percent" => {
                parsed.reconnect_jitter_percent = parse_number(args, index, flag)?;
                index += 2;
            }
            "--stable-session-reset-ms" => {
                parsed.stable_session_reset =
                    Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--max-reconnect-attempts" => {
                parsed.max_reconnect_attempts = Some(parse_number(args, index, flag)?);
                index += 2;
            }
            "--tls-ca" => {
                parsed.tls_ca = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-client-cert" => {
                parsed.tls_client_cert = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-client-key" => {
                parsed.tls_client_key = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-server-name" => {
                parsed.tls_server_name = Some(value(args, index, flag)?.to_string());
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
            "--enroll-only" => {
                parsed.enroll_only = true;
                parsed.enrollment_options_present = true;
                index += 1;
            }
            "--enrollment-server" => {
                parsed.enrollment_server = Some(parse_addr(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-ca" => {
                parsed.enrollment_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-server-name" => {
                parsed.enrollment_server_name = Some(value(args, index, flag)?.to_string());
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-token" => {
                parsed.enrollment_token = Some(PathBuf::from(value(args, index, flag)?));
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-pending" => {
                parsed.enrollment_pending = Some(PathBuf::from(value(args, index, flag)?));
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--renew-before-ms" => {
                parsed.renew_before = Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-poll-ms" => {
                parsed.enrollment_poll = Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-connect-timeout-ms" => {
                parsed.enrollment_connect_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-handshake-timeout-ms" => {
                parsed.enrollment_handshake_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-request-timeout-ms" => {
                parsed.enrollment_request_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-activation-timeout-ms" => {
                parsed.enrollment_activation_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
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
    Read(&'static str),
    Invalid(AgentTlsConfigError),
    IncompleteReloadArguments,
    Reload(AgentTlsReloadBootstrapError),
}

impl std::fmt::Display for TlsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "TLS requires --tls-ca, --tls-client-cert, --tls-client-key, and --tls-server-name",
            ),
            Self::Read(kind) => write!(f, "failed to read TLS {kind} PEM file"),
            Self::Invalid(error) => write!(f, "invalid TLS configuration: {error}"),
            Self::IncompleteReloadArguments => f.write_str(
                "TLS reload options require --tls-reload-manifest and complete TLS paths",
            ),
            Self::Reload(error) => write!(f, "invalid TLS reload configuration: {error}"),
        }
    }
}

struct LoadedTransportSecurity {
    security: AgentTransportSecurity,
    reloader: Option<AgentTlsReloadRuntime>,
}

async fn load_transport_security(
    parsed: &ParsedArgs,
) -> Result<LoadedTransportSecurity, TlsLoadError> {
    match (
        &parsed.tls_ca,
        &parsed.tls_client_cert,
        &parsed.tls_client_key,
        &parsed.tls_server_name,
    ) {
        (None, None, None, None) if !parsed.tls_reload_options_present => {
            Ok(LoadedTransportSecurity {
                security: AgentTransportSecurity::PlaintextLoopback,
                reloader: None,
            })
        }
        (Some(ca), Some(cert), Some(key), Some(server_name)) => {
            if let Some(manifest_path) = &parsed.tls_reload_manifest {
                let (tls, reloader) = AgentTlsReloadRuntime::bootstrap(
                    AgentTlsReloadConfig {
                        manifest_path: manifest_path.clone(),
                        server_ca_path: ca.clone(),
                        client_certificate_path: cert.clone(),
                        client_private_key_path: key.clone(),
                        poll_interval: parsed.tls_reload_interval,
                        expiry_warning: parsed.tls_expiry_warning,
                    },
                    server_name,
                    parsed.tls_handshake_timeout,
                )
                .await
                .map_err(TlsLoadError::Reload)?;
                return Ok(LoadedTransportSecurity {
                    security: AgentTransportSecurity::MutualTls(tls),
                    reloader: Some(reloader),
                });
            }
            if parsed.tls_reload_options_present {
                return Err(TlsLoadError::IncompleteReloadArguments);
            }
            let ca = tokio::fs::read(ca)
                .await
                .map_err(|_| TlsLoadError::Read("CA"))?;
            let cert = tokio::fs::read(cert)
                .await
                .map_err(|_| TlsLoadError::Read("client certificate"))?;
            let key = tokio::fs::read(key)
                .await
                .map_err(|_| TlsLoadError::Read("client private key"))?;
            AgentTlsConfig::from_pem(&ca, &cert, &key, server_name, parsed.tls_handshake_timeout)
                .map(|tls| LoadedTransportSecurity {
                    security: AgentTransportSecurity::MutualTls(tls),
                    reloader: None,
                })
                .map_err(TlsLoadError::Invalid)
        }
        _ => Err(TlsLoadError::IncompleteArguments),
    }
}

#[derive(Debug)]
enum EnrollmentLoadError {
    IncompleteArguments,
    ReloadManifestRequired,
    ReadCa,
    Invalid(AgentEnrollmentError),
}

impl std::fmt::Display for EnrollmentLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "enrollment requires --enrollment-server, --enrollment-ca, \
                 --enrollment-server-name, --enrollment-token, --enrollment-pending, complete \
                 Agent TLS paths, --tls-server-name, and --tls-reload-manifest",
            ),
            Self::ReloadManifestRequired => {
                f.write_str("automatic enrollment requires --tls-reload-manifest")
            }
            Self::ReadCa => f.write_str("failed to read enrollment server CA PEM file"),
            Self::Invalid(error) => write!(f, "invalid enrollment configuration: {error}"),
        }
    }
}

async fn load_enrollment_config(
    parsed: &ParsedArgs,
) -> Result<Option<AgentEnrollmentConfig>, EnrollmentLoadError> {
    if !parsed.enrollment_options_present {
        return Ok(None);
    }
    let (
        Some(server_addr),
        Some(enrollment_ca),
        Some(enrollment_server_name),
        Some(token_path),
        Some(pending_path),
        Some(server_ca_path),
        Some(client_certificate_path),
        Some(client_private_key_path),
        Some(edge_server_name),
        Some(manifest_path),
    ) = (
        parsed.enrollment_server,
        parsed.enrollment_ca.as_ref(),
        parsed.enrollment_server_name.as_ref(),
        parsed.enrollment_token.as_ref(),
        parsed.enrollment_pending.as_ref(),
        parsed.tls_ca.as_ref(),
        parsed.tls_client_cert.as_ref(),
        parsed.tls_client_key.as_ref(),
        parsed.tls_server_name.as_ref(),
        parsed.tls_reload_manifest.as_ref(),
    )
    else {
        if !parsed.enroll_only && parsed.tls_reload_manifest.is_none() {
            return Err(EnrollmentLoadError::ReloadManifestRequired);
        }
        return Err(EnrollmentLoadError::IncompleteArguments);
    };
    let server_ca_pem = tokio::fs::read(enrollment_ca)
        .await
        .map_err(|_| EnrollmentLoadError::ReadCa)?;
    let config = AgentEnrollmentConfig {
        client: EnrollmentClientConfig {
            server_addr,
            server_name: enrollment_server_name.clone(),
            server_ca_pem,
            connect_timeout: parsed.enrollment_connect_timeout,
            handshake_timeout: parsed.enrollment_handshake_timeout,
            request_timeout: parsed.enrollment_request_timeout,
        },
        agent_id: parsed.agent_id.clone(),
        tunnel_id: parsed.tunnel_id.clone(),
        token_path: token_path.clone(),
        pending_path: pending_path.clone(),
        credentials: AgentCredentialPaths {
            server_ca: server_ca_path.clone(),
            client_certificate: client_certificate_path.clone(),
            client_private_key: client_private_key_path.clone(),
            reload_manifest: manifest_path.clone(),
        },
        edge_server_name: edge_server_name.clone(),
        edge_tls_handshake_timeout: parsed.tls_handshake_timeout,
        renew_before: parsed.renew_before,
        poll_interval: parsed.enrollment_poll,
        activation_timeout: parsed.enrollment_activation_timeout,
    };
    config.validate().map_err(EnrollmentLoadError::Invalid)?;
    Ok(Some(config))
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
            "--edge",
            "127.0.0.1:17100",
            "--local",
            "127.0.0.1:13000",
            "--agent-id",
            "agent-prod",
            "--tunnel-id",
            "tunnel-prod",
            "--max-streams",
            "8",
            "--connect-timeout-ms",
            "100",
            "--handshake-timeout-ms",
            "200",
            "--drain-timeout-ms",
            "300",
            "--reconnect-initial-ms",
            "10",
            "--reconnect-max-ms",
            "400",
            "--reconnect-multiplier",
            "3",
            "--reconnect-jitter-percent",
            "15",
            "--stable-session-reset-ms",
            "500",
            "--max-reconnect-attempts",
            "7",
            "--tls-ca",
            "ca.pem",
            "--tls-client-cert",
            "agent.pem",
            "--tls-client-key",
            "agent-key.pem",
            "--tls-server-name",
            "edge.test",
            "--tls-handshake-timeout-ms",
            "600",
            "--tls-reload-manifest",
            "agent-tls.json",
            "--tls-reload-interval-ms",
            "700",
            "--tls-expiry-warning-ms",
            "800",
        ]))
        .unwrap();
        assert_eq!(parsed.edge.port(), 17100);
        assert_eq!(parsed.local.port(), 13000);
        assert_eq!(parsed.agent_id.as_str(), "agent-prod");
        assert_eq!(parsed.tunnel_id.as_str(), "tunnel-prod");
        assert_eq!(parsed.max_streams, 8);
        assert_eq!(parsed.connect_timeout, Duration::from_millis(100));
        assert_eq!(parsed.handshake_timeout, Duration::from_millis(200));
        assert_eq!(parsed.drain_timeout, Duration::from_millis(300));
        assert_eq!(parsed.reconnect_initial, Duration::from_millis(10));
        assert_eq!(parsed.reconnect_max, Duration::from_millis(400));
        assert_eq!(parsed.reconnect_multiplier, 3);
        assert_eq!(parsed.reconnect_jitter_percent, 15);
        assert_eq!(parsed.stable_session_reset, Duration::from_millis(500));
        assert_eq!(parsed.max_reconnect_attempts, Some(7));
        assert_eq!(parsed.tls_ca, Some(PathBuf::from("ca.pem")));
        assert_eq!(parsed.tls_client_cert, Some(PathBuf::from("agent.pem")));
        assert_eq!(parsed.tls_client_key, Some(PathBuf::from("agent-key.pem")));
        assert_eq!(parsed.tls_server_name.as_deref(), Some("edge.test"));
        assert_eq!(parsed.tls_handshake_timeout, Duration::from_millis(600));
        assert_eq!(
            parsed.tls_reload_manifest,
            Some(PathBuf::from("agent-tls.json"))
        );
        assert_eq!(parsed.tls_reload_interval, Duration::from_millis(700));
        assert_eq!(parsed.tls_expiry_warning, Duration::from_millis(800));
    }

    #[test]
    fn invalid_and_missing_values_are_typed() {
        assert!(matches!(
            parse_args(&args(&["--edge", "bad"])),
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
            parse_args(&args(&["--agent-id", "bad/id"])),
            Err(ArgError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn enrollment_flags_parse_without_secret_values_on_command_line() {
        let parsed = parse_args(&args(&[
            "--enroll-only",
            "--enrollment-server",
            "127.0.0.1:17300",
            "--enrollment-ca",
            "enrollment-ca.pem",
            "--enrollment-server-name",
            "enrollment.test",
            "--enrollment-token",
            "renewal.token",
            "--enrollment-pending",
            "enrollment.pending",
            "--renew-before-ms",
            "100",
            "--enrollment-poll-ms",
            "200",
            "--enrollment-connect-timeout-ms",
            "300",
            "--enrollment-handshake-timeout-ms",
            "400",
            "--enrollment-request-timeout-ms",
            "500",
            "--enrollment-activation-timeout-ms",
            "600",
        ]))
        .unwrap();
        assert!(parsed.enroll_only);
        assert_eq!(parsed.enrollment_server.unwrap().port(), 17300);
        assert_eq!(
            parsed.enrollment_ca,
            Some(PathBuf::from("enrollment-ca.pem"))
        );
        assert_eq!(
            parsed.enrollment_server_name.as_deref(),
            Some("enrollment.test")
        );
        assert_eq!(parsed.renew_before, Duration::from_millis(100));
        assert_eq!(parsed.enrollment_poll, Duration::from_millis(200));
        assert_eq!(
            parsed.enrollment_activation_timeout,
            Duration::from_millis(600)
        );
    }

    #[tokio::test]
    async fn partial_tls_arguments_are_rejected() {
        let parsed = ParsedArgs {
            tls_ca: Some(PathBuf::from("ca.pem")),
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_security(&parsed).await,
            Err(TlsLoadError::IncompleteArguments)
        ));

        let reload_without_tls = ParsedArgs {
            tls_reload_manifest: Some(PathBuf::from("reload.json")),
            tls_reload_options_present: true,
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_security(&reload_without_tls).await,
            Err(TlsLoadError::IncompleteArguments)
        ));
    }
}
