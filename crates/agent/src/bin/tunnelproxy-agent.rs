//! Runnable outbound Agent process with graceful OS shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tunnelproxy_agent::{
    AgentRuntime, AgentRuntimeConfig, AgentRuntimeOutcome, AgentTlsConfig, AgentTlsConfigError,
    AgentTransportSecurity, RuntimeShutdownConfig,
};
use tunnelproxy_common::{shutdown_channel, wait_for_process_shutdown, AgentId, TunnelId};
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
  --help                         print this help and exit
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
            error!(%error, "invalid Agent CLI arguments");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if parsed.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
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
    config.security = match load_transport_security(&parsed).await {
        Ok(security) => security,
        Err(error) => {
            error!(%error, "failed to configure Agent TLS");
            return ExitCode::from(2);
        }
    };
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
    agent_exit_code(result)
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
}

impl std::fmt::Display for TlsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "TLS requires --tls-ca, --tls-client-cert, --tls-client-key, and --tls-server-name",
            ),
            Self::Read(kind) => write!(f, "failed to read TLS {kind} PEM file"),
            Self::Invalid(error) => write!(f, "invalid TLS configuration: {error}"),
        }
    }
}

async fn load_transport_security(
    parsed: &ParsedArgs,
) -> Result<AgentTransportSecurity, TlsLoadError> {
    match (
        &parsed.tls_ca,
        &parsed.tls_client_cert,
        &parsed.tls_client_key,
        &parsed.tls_server_name,
    ) {
        (None, None, None, None) => Ok(AgentTransportSecurity::PlaintextLoopback),
        (Some(ca), Some(cert), Some(key), Some(server_name)) => {
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
                .map(AgentTransportSecurity::MutualTls)
                .map_err(TlsLoadError::Invalid)
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
    }
}
