//! Development entry point for `tunnelproxy-edge`.
//!
//! In Session 03 this binary runs a **TCP relay**: it binds a
//! downstream listener and, for every accepted connection, dials a
//! fresh upstream connection to a configured address and forwards
//! raw bytes in both directions using `tokio::io::copy_bidirectional`.
//!
//! Environment variables:
//!
//! - `TUNNELPROXY_EDGE_ADDR` — downstream listen address
//!   (default `127.0.0.1:7000`).
//! - `TUNNELPROXY_EDGE_UPSTREAM` — upstream dial address
//!   (default `127.0.0.1:8000`).
//!
//! The binary returns a non-zero exit code on fatal bind/accept errors.
//! Per-connection errors (upstream refused, client reset, I/O errors)
//! are logged and isolated; the listener keeps accepting new
//! connections.

use std::net::SocketAddr;
use std::process::ExitCode;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let bind_addr = match env_addr("TUNNELPROXY_EDGE_ADDR", tunnelproxy_edge::DEFAULT_BIND_ADDR) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let upstream_addr = match env_addr(
        "TUNNELPROXY_EDGE_UPSTREAM",
        tunnelproxy_edge::DEFAULT_UPSTREAM_ADDR,
    ) {
        Ok(a) => a,
        Err(code) => return code,
    };

    info!(
        bind = %bind_addr,
        upstream = %upstream_addr,
        "tunnelproxy-edge: TCP relay starting"
    );

    match tunnelproxy_edge::run_relay_listener(bind_addr, upstream_addr).await {
        Ok(()) => {
            info!("tunnelproxy-edge: relay listener exited cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            error!(error = %err, "tunnelproxy-edge: relay listener exited with error");
            ExitCode::from(1)
        }
    }
}

fn env_addr(var: &str, default: &str) -> Result<SocketAddr, ExitCode> {
    let raw = std::env::var(var).unwrap_or_else(|_| default.to_string());
    raw.parse::<SocketAddr>().map_err(|err| {
        error!(addr = %raw, error = %err, "invalid socket address");
        ExitCode::from(2)
    })
}
