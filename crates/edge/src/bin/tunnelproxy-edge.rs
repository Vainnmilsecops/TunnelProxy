//! Runnable single-tunnel Edge process with graceful OS shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tunnelproxy_common::{shutdown_channel, wait_for_process_shutdown, AgentId, TunnelId};
use tunnelproxy_edge::{
    EdgeRegistrationPolicy, EdgeRegistrationPolicyError, EdgeRuntime, EdgeRuntimeConfig,
    EdgeRuntimeError, EdgeRuntimeOutcome, EdgeTlsConfig, EdgeTlsConfigError, EdgeTransportSecurity,
    RuntimeShutdownConfig,
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
    let (security, registration) = match load_transport_configuration(&parsed).await {
        Ok(configuration) => configuration,
        Err(error) => {
            error!(%error, "failed to configure Edge transport authorization");
            return ExitCode::from(2);
        }
    };
    config.multiplex.security = security;
    config.multiplex.registration = registration;
    let runtime = match EdgeRuntime::bind(config).await {
        Ok(runtime) => runtime,
        Err(error) => {
            error!(%error, "failed to start Edge runtime");
            return if matches!(error, EdgeRuntimeError::InvalidConfig(_)) {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            };
        }
    };
    info!(
        agent_addr = %runtime.agent_addr(),
        raw_addr = %parsed.raw_listen,
        agent_id = %parsed.agent_id,
        tunnel_id = %parsed.tunnel_id,
        "Edge runtime is waiting for one Agent"
    );

    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal);
    tokio::pin!(runtime_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    let result = tokio::select! {
        result = &mut runtime_future => result,
        observed = &mut os_signal => {
            match observed {
                Ok(cause) => info!(%cause, "process shutdown requested"),
                Err(error) => {
                    error!(%error, "OS shutdown listener failed");
                    trigger.shutdown();
                    let _ = runtime_future.await;
                    return ExitCode::from(1);
                }
            }
            trigger.shutdown();
            runtime_future.await
        }
    };
    edge_exit_code(result)
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
            other => return Err(ArgError::UnknownFlag(other.to_string())),
        }
    }
    Ok(parsed)
}

#[derive(Debug)]
enum TlsLoadError {
    IncompleteArguments,
    Read(&'static str),
    Invalid(EdgeTlsConfigError),
    InvalidRegistration(EdgeRegistrationPolicyError),
}

impl std::fmt::Display for TlsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "TLS requires --tls-cert, --tls-key, --tls-client-ca, and --authorized-client-cert",
            ),
            Self::Read(kind) => write!(f, "failed to read TLS {kind} PEM file"),
            Self::Invalid(error) => write!(f, "invalid TLS configuration: {error}"),
            Self::InvalidRegistration(error) => {
                write!(f, "invalid registration authorization: {error}")
            }
        }
    }
}

async fn load_transport_configuration(
    parsed: &ParsedArgs,
) -> Result<(EdgeTransportSecurity, EdgeRegistrationPolicy), TlsLoadError> {
    match (
        &parsed.tls_cert,
        &parsed.tls_key,
        &parsed.tls_client_ca,
        &parsed.authorized_client_cert,
    ) {
        (None, None, None, None) => Ok((
            EdgeTransportSecurity::PlaintextLoopback,
            EdgeRegistrationPolicy::loopback_development(
                parsed.agent_id.clone(),
                parsed.tunnel_id.clone(),
            ),
        )),
        (Some(cert), Some(key), Some(client_ca), Some(authorized_client_cert)) => {
            let cert = tokio::fs::read(cert)
                .await
                .map_err(|_| TlsLoadError::Read("server certificate"))?;
            let key = tokio::fs::read(key)
                .await
                .map_err(|_| TlsLoadError::Read("server private key"))?;
            let client_ca = tokio::fs::read(client_ca)
                .await
                .map_err(|_| TlsLoadError::Read("client CA"))?;
            let authorized_client_cert = tokio::fs::read(authorized_client_cert)
                .await
                .map_err(|_| TlsLoadError::Read("authorized client certificate"))?;
            let security =
                EdgeTlsConfig::from_pem(&cert, &key, &client_ca, parsed.tls_handshake_timeout)
                    .map(EdgeTransportSecurity::MutualTls)
                    .map_err(TlsLoadError::Invalid)?;
            let registration = EdgeRegistrationPolicy::mutual_tls_from_client_cert_pem(
                parsed.agent_id.clone(),
                parsed.tunnel_id.clone(),
                &authorized_client_cert,
            )
            .map_err(TlsLoadError::InvalidRegistration)?;
            Ok((security, registration))
        }
        _ => Err(TlsLoadError::IncompleteArguments),
    }
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
    }
}
