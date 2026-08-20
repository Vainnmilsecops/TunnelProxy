//! Development entry point for `tunnelproxy-edge`.
//!
//! In Session 02 this binary exists purely to give a developer something
//! to run that binds an async TCP listener and echoes bytes. Production
//! startup (config loading, structured config files, logging
//! initialisation, graceful shutdown) is out of scope for this session.

use std::net::SocketAddr;
use std::process::ExitCode;

use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let bind_addr: SocketAddr = match std::env::var("TUNNELPROXY_EDGE_ADDR") {
        Ok(raw) => match raw.parse() {
            Ok(addr) => addr,
            Err(err) => {
                error!(addr = %raw, error = %err, "invalid TUNNELPROXY_EDGE_ADDR");
                return ExitCode::from(2);
            }
        },
        Err(_) => match tunnelproxy_edge::DEFAULT_BIND_ADDR.parse() {
            Ok(addr) => addr,
            Err(err) => {
                error!(error = %err, "DEFAULT_BIND_ADDR is not a valid socket address");
                return ExitCode::from(2);
            }
        },
    };

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(addr = %bind_addr, error = %err, "bind failed");
            return ExitCode::from(1);
        }
    };
    let local = listener.local_addr().unwrap_or(bind_addr);
    info!(addr = %local, "tunnelproxy-edge: TCP server started");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!(peer = %peer, "accepted connection");
                tokio::spawn(tunnelproxy_edge::handle_connection(stream, peer));
            }
            Err(err) => {
                error!(error = %err, "accept failed");
                return ExitCode::from(1);
            }
        }
    }
}
