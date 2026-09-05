//! Development entry point for `tunnelproxy-edge`.
//!
//! In Session 04 this binary runs the **local TCP forwarder**: it
//! binds a downstream listener, enforces a bounded concurrency
//! policy, dials a fresh upstream connection per accepted downstream
//! under a bounded connect timeout, and forwards raw bytes in both
//! directions through fixed buffers under an activity-aware idle deadline.
//!
//! CLI:
//!
//! ```text
//! tunnelproxy-edge \
//!   --listen 127.0.0.1:7000 \
//!   --upstream 127.0.0.1:8000 \
//!   --max-connections 100 \
//!   --max-connections-per-ip 25 \
//!   --connect-timeout-ms 5000 \
//!   --relay-idle-timeout-ms 60000
//! ```
//!
//! Defaults (`127.0.0.1:7000` → `127.0.0.1:8000`, 100 global connections,
//! `min(25, global)` per source IP, 5 s connect timeout, 60 s relay idle
//! timeout) apply when a flag is omitted. Use `--help` to print usage.
//!
//! The binary returns a non-zero exit code on fatal bind errors or
//! invalid configuration. Per-connection errors (upstream refused,
//! upstream timed out, client reset, I/O errors, capacity exhaustion)
//! are logged via structured lifecycle events; the listener keeps
//! accepting new connections in every failure mode.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info};
use tunnelproxy_common::{init_process_logging, ProcessLogFormat};
use tunnelproxy_edge::{
    ForwardConfig, ForwardConfigError, Forwarder, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_RELAY_IDLE_TIMEOUT,
};

const USAGE: &str = "\
Usage: tunnelproxy-edge [OPTIONS]

Options:
  --listen <addr>             downstream listen address (default 127.0.0.1:7000)
  --upstream <addr>           upstream dial address       (default 127.0.0.1:8000)
  --max-connections <usize>   max concurrent relays      (default 100; must be > 0)
  --max-connections-per-ip <usize> per-source-IP relays   (default min(25, global); 1..=global)
  --connect-timeout-ms <ms>   upstream connect timeout   (default 5000; must be > 0)
  --relay-idle-timeout-ms <ms> established relay idle timeout (default 60000; 1..=3600000)
  --help                      print this help and exit
";

#[tokio::main]
async fn main() -> ExitCode {
    let logging = match init_process_logging() {
        Ok(logging) => logging,
        Err(error) => {
            eprintln!("failed to configure logging: {error}");
            return ExitCode::from(2);
        }
    };
    let log_format = logging.format();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(err) => {
            error!(error = %err, "invalid CLI arguments");
            if log_format == ProcessLogFormat::Text {
                eprintln!("{USAGE}");
            }
            return ExitCode::from(2);
        }
    };

    if parsed.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let config = ForwardConfig {
        listen_addr: parsed.listen_addr,
        upstream_addr: parsed.upstream_addr,
        max_connections: parsed.max_connections,
        connect_timeout: parsed.connect_timeout,
        relay_idle_timeout: parsed.relay_idle_timeout,
    };

    let forwarder = match parsed.max_connections_per_ip {
        Some(limit) => Forwarder::new_with_per_ip_limit(config, limit),
        None => Forwarder::new(config),
    };
    let forwarder = match forwarder {
        Ok(forwarder) => forwarder,
        Err(err) => {
            match err {
                ForwardConfigError::ZeroMaxConnections => {
                    error!("--max-connections must be greater than zero");
                }
                ForwardConfigError::ZeroConnectTimeout => {
                    error!("--connect-timeout-ms must be greater than zero");
                }
                ForwardConfigError::RelayIdleTimeoutTooSmall => {
                    error!("--relay-idle-timeout-ms must be at least 1");
                }
                ForwardConfigError::RelayIdleTimeoutTooLarge => {
                    error!("--relay-idle-timeout-ms must not exceed 3600000");
                }
                ForwardConfigError::ZeroMaxConnectionsPerIp => {
                    error!("--max-connections-per-ip must be greater than zero");
                }
                ForwardConfigError::PerIpLimitExceedsGlobal => {
                    error!("--max-connections-per-ip must not exceed --max-connections");
                }
            }
            return ExitCode::from(2);
        }
    };

    let config = forwarder.config();
    info!(
        bind = %config.listen_addr,
        upstream = %config.upstream_addr,
        max_connections = config.max_connections,
        max_connections_per_ip = forwarder.max_connections_per_ip(),
        connect_timeout_ms = config.connect_timeout.as_millis() as u64,
        relay_idle_timeout_ms = config.relay_idle_timeout.as_millis() as u64,
        "tunnelproxy-edge: starting TCP forwarder"
    );

    match forwarder.run().await {
        Ok(()) => {
            info!("tunnelproxy-edge: forwarder exited cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            error!(error = %err, "tunnelproxy-edge: forwarder exited with error");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
struct ParsedArgs {
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    max_connections: usize,
    max_connections_per_ip: Option<usize>,
    connect_timeout: Duration,
    relay_idle_timeout: Duration,
    help: bool,
}

#[derive(Debug)]
enum ArgError {
    MissingValue(&'static str),
    InvalidNumber { flag: &'static str, value: String },
    InvalidAddress { flag: &'static str, value: String },
    UnknownFlag(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgError::MissingValue(flag) => write!(f, "--{flag} requires a value"),
            ArgError::InvalidNumber { flag, value } => {
                write!(f, "--{flag}={value} is not a valid positive integer")
            }
            ArgError::InvalidAddress { flag, value } => {
                write!(f, "--{flag}={value} is not a valid socket address")
            }
            ArgError::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, ArgError> {
    let mut out = ParsedArgs {
        listen_addr: tunnelproxy_edge::DEFAULT_BIND_ADDR
            .parse()
            .expect("hardcoded default bind address is valid"),
        upstream_addr: tunnelproxy_edge::DEFAULT_UPSTREAM_ADDR
            .parse()
            .expect("hardcoded default upstream address is valid"),
        max_connections: DEFAULT_MAX_CONNECTIONS,
        max_connections_per_ip: None,
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        relay_idle_timeout: DEFAULT_RELAY_IDLE_TIMEOUT,
        help: false,
    };

    let mut i = 0;
    while i < args.len() {
        let token = &args[i];
        match token.as_str() {
            "--help" | "-h" => {
                out.help = true;
                i += 1;
            }
            "--listen" => {
                let value = take_value(args, i, "--listen")?;
                out.listen_addr = value.parse().map_err(|_| ArgError::InvalidAddress {
                    flag: "listen",
                    value: value.clone(),
                })?;
                i += 2;
            }
            "--upstream" => {
                let value = take_value(args, i, "--upstream")?;
                out.upstream_addr = value.parse().map_err(|_| ArgError::InvalidAddress {
                    flag: "upstream",
                    value: value.clone(),
                })?;
                i += 2;
            }
            "--max-connections" => {
                let value = take_value(args, i, "--max-connections")?;
                out.max_connections = value.parse().map_err(|_| ArgError::InvalidNumber {
                    flag: "max-connections",
                    value: value.clone(),
                })?;
                i += 2;
            }
            "--max-connections-per-ip" => {
                let value = take_value(args, i, "--max-connections-per-ip")?;
                out.max_connections_per_ip =
                    Some(value.parse().map_err(|_| ArgError::InvalidNumber {
                        flag: "max-connections-per-ip",
                        value: value.clone(),
                    })?);
                i += 2;
            }
            "--connect-timeout-ms" => {
                let value = take_value(args, i, "--connect-timeout-ms")?;
                let ms: u64 = value.parse().map_err(|_| ArgError::InvalidNumber {
                    flag: "connect-timeout-ms",
                    value: value.clone(),
                })?;
                out.connect_timeout = Duration::from_millis(ms);
                i += 2;
            }
            "--relay-idle-timeout-ms" => {
                let value = take_value(args, i, "--relay-idle-timeout-ms")?;
                let ms: u64 = value.parse().map_err(|_| ArgError::InvalidNumber {
                    flag: "relay-idle-timeout-ms",
                    value: value.clone(),
                })?;
                out.relay_idle_timeout = Duration::from_millis(ms);
                i += 2;
            }
            other => return Err(ArgError::UnknownFlag(other.to_string())),
        }
    }

    Ok(out)
}

fn take_value<'a>(
    args: &'a [String],
    i: usize,
    flag: &'static str,
) -> Result<&'a String, ArgError> {
    args.get(i + 1).ok_or(ArgError::MissingValue(flag))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn relay_idle_timeout_defaults_and_parses() {
        assert_eq!(
            parse_args(&[]).unwrap().relay_idle_timeout,
            DEFAULT_RELAY_IDLE_TIMEOUT
        );
        assert_eq!(
            parse_args(&args(&["--relay-idle-timeout-ms", "1250"]))
                .unwrap()
                .relay_idle_timeout,
            Duration::from_millis(1250)
        );
        assert!(USAGE.contains("--relay-idle-timeout-ms"));
    }

    #[test]
    fn relay_idle_timeout_cli_values_use_forwarder_bounds() {
        for (milliseconds, expected) in [
            (0, ForwardConfigError::RelayIdleTimeoutTooSmall),
            (3_600_001, ForwardConfigError::RelayIdleTimeoutTooLarge),
        ] {
            let parsed = parse_args(&args(&[
                "--relay-idle-timeout-ms",
                &milliseconds.to_string(),
            ]))
            .unwrap();
            let mut config = ForwardConfig::dev_defaults();
            config.relay_idle_timeout = parsed.relay_idle_timeout;
            assert_eq!(config.validate(), Err(expected));
        }
    }

    #[test]
    fn per_ip_admission_defaults_and_parses() {
        let parsed = parse_args(&[]).unwrap();
        assert_eq!(parsed.max_connections_per_ip, None);
        let forwarder = Forwarder::new(ForwardConfig::dev_defaults()).unwrap();
        assert_eq!(
            forwarder.max_connections_per_ip(),
            tunnelproxy_edge::DEFAULT_FORWARD_MAX_CONNECTIONS_PER_IP
        );

        let parsed = parse_args(&args(&["--max-connections-per-ip", "7"])).unwrap();
        assert_eq!(parsed.max_connections_per_ip, Some(7));
        assert!(USAGE.contains("--max-connections-per-ip"));
    }

    #[test]
    fn per_ip_cli_values_use_global_forwarder_bound() {
        for (limit, expected) in [
            (0, ForwardConfigError::ZeroMaxConnectionsPerIp),
            (101, ForwardConfigError::PerIpLimitExceedsGlobal),
        ] {
            let parsed =
                parse_args(&args(&["--max-connections-per-ip", &limit.to_string()])).unwrap();
            assert_eq!(
                Forwarder::new_with_per_ip_limit(
                    ForwardConfig::dev_defaults(),
                    parsed.max_connections_per_ip.unwrap(),
                )
                .err(),
                Some(expected)
            );
        }
    }
}
