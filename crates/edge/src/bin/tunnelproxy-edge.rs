//! Runnable single-tunnel Edge process with graceful OS shutdown.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tunnelproxy_common::{shutdown_channel, wait_for_process_shutdown};
use tunnelproxy_edge::{
    EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeError, EdgeRuntimeOutcome, RuntimeShutdownConfig,
};

const USAGE: &str = "\
Usage: tunnelproxy-edge [OPTIONS]

Options:
  --agent-listen <addr>            Agent listener (default 127.0.0.1:7100)
  --raw-listen <addr>              raw ingress   (default 127.0.0.1:7000)
  --max-streams <usize>            stream limit  (default 32)
  --max-raw-connections <usize>    ingress limit (default 32)
  --drain-timeout-ms <ms>          stage drain   (default 10000)
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
    config.max_raw_connections = parsed.max_raw_connections;
    config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
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
    max_streams: usize,
    max_raw_connections: usize,
    drain_timeout: Duration,
    help: bool,
}

impl Default for ParsedArgs {
    fn default() -> Self {
        Self {
            agent_listen: "127.0.0.1:7100".parse().unwrap(),
            raw_listen: "127.0.0.1:7000".parse().unwrap(),
            max_streams: 32,
            max_raw_connections: 32,
            drain_timeout: Duration::from_secs(10),
            help: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ArgError {
    MissingValue(String),
    InvalidAddress { flag: String, value: String },
    InvalidNumber { flag: String, value: String },
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
            other => return Err(ArgError::UnknownFlag(other.to_string())),
        }
    }
    Ok(parsed)
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
            "--max-streams",
            "8",
            "--max-raw-connections",
            "9",
            "--drain-timeout-ms",
            "250",
        ]))
        .unwrap();
        assert_eq!(parsed.agent_listen.port(), 17100);
        assert_eq!(parsed.raw_listen.port(), 17000);
        assert_eq!(parsed.max_streams, 8);
        assert_eq!(parsed.max_raw_connections, 9);
        assert_eq!(parsed.drain_timeout, Duration::from_millis(250));
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
    }
}
