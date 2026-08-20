//! Development entry point for `tunnelproxy-edge`.
//!
//! In Session 04 this binary runs the **local TCP forwarder**: it
//! binds a downstream listener, enforces a bounded concurrency
//! policy, dials a fresh upstream connection per accepted downstream
//! under a bounded connect timeout, and forwards raw bytes in both
//! directions using `tokio::io::copy_bidirectional`.
//!
//! CLI:
//!
//! ```text
//! tunnelproxy-edge \
//!   --listen 127.0.0.1:7000 \
//!   --upstream 127.0.0.1:8000 \
//!   --max-connections 100 \
//!   --connect-timeout-ms 5000
//! ```
//!
//! Defaults (`127.0.0.1:7000` → `127.0.0.1:8000`, 100 connections,
//! 5 s connect timeout) apply when a flag is omitted. Use `--help`
//! to print usage.
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
use tracing_subscriber::EnvFilter;
use tunnelproxy_edge::{
    ForwardConfig, ForwardConfigError, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_CONNECTIONS,
};

const USAGE: &str = "\
Usage: tunnelproxy-edge [OPTIONS]

Options:
  --listen <addr>             downstream listen address (default 127.0.0.1:7000)
  --upstream <addr>           upstream dial address       (default 127.0.0.1:8000)
  --max-connections <usize>   max concurrent relays      (default 100; must be > 0)
  --connect-timeout-ms <ms>   upstream connect timeout   (default 5000; must be > 0)
  --help                      print this help and exit
";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(err) => {
            error!(error = %err, "invalid CLI arguments");
            eprintln!("{USAGE}");
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
    };

    if let Err(err) = config.validate() {
        match err {
            ForwardConfigError::ZeroMaxConnections => {
                error!("--max-connections must be greater than zero");
            }
            ForwardConfigError::ZeroConnectTimeout => {
                error!("--connect-timeout-ms must be greater than zero");
            }
        }
        return ExitCode::from(2);
    }

    info!(
        bind = %config.listen_addr,
        upstream = %config.upstream_addr,
        max_connections = config.max_connections,
        connect_timeout_ms = config.connect_timeout.as_millis() as u64,
        "tunnelproxy-edge: starting TCP forwarder"
    );

    let forwarder = match tunnelproxy_edge::Forwarder::new(config) {
        Ok(f) => f,
        Err(err) => {
            error!(error = %err, "failed to construct forwarder");
            return ExitCode::from(2);
        }
    };

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
    connect_timeout: Duration,
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
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
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
            "--connect-timeout-ms" => {
                let value = take_value(args, i, "--connect-timeout-ms")?;
                let ms: u64 = value.parse().map_err(|_| ArgError::InvalidNumber {
                    flag: "connect-timeout-ms",
                    value: value.clone(),
                })?;
                out.connect_timeout = Duration::from_millis(ms);
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
