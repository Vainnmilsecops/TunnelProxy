//! Minimal upstream echo server used as the relay's upstream target
//! during manual smoke tests.
//!
//! Listens on `TUNNELPROXY_UPSTREAM_ADDR` (default `127.0.0.1:8000`)
//! and, for every accepted connection, reads bytes in a fixed buffer
//! and writes them back unchanged until EOF or error. This is
//! deliberately a tiny, throwaway development helper — production
//! upstream services are user-owned, not part of TunnelProxy.

use std::net::SocketAddr;
use std::process::ExitCode;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};
use tunnelproxy_common::init_process_logging;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = init_process_logging() {
        eprintln!("failed to configure logging: {error}");
        return ExitCode::from(2);
    }

    let bind_addr: SocketAddr = match std::env::var("TUNNELPROXY_UPSTREAM_ADDR") {
        Ok(raw) => match raw.parse() {
            Ok(addr) => addr,
            Err(err) => {
                error!(addr = %raw, error = %err, "invalid TUNNELPROXY_UPSTREAM_ADDR");
                return ExitCode::from(2);
            }
        },
        Err(_) => match "127.0.0.1:8000".parse() {
            Ok(addr) => addr,
            Err(err) => {
                error!(error = %err, "default upstream address is invalid");
                return ExitCode::from(2);
            }
        },
    };

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(addr = %bind_addr, error = %err, "upstream bind failed");
            return ExitCode::from(1);
        }
    };
    info!(addr = %listener.local_addr().unwrap_or(bind_addr), "upstream echo server started");

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                error!(error = %err, "upstream accept failed");
                return ExitCode::from(1);
            }
        };
        info!(peer = %peer, "upstream accepted connection");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8 * 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }
}
