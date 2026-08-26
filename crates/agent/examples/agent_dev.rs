//! Development entry point for `tunnelproxy-agent`.
//!
//! In Session 02 this binary connects to the local edge, sends the
//! deterministic test payload, verifies the echo, and exits. It is the
//! smoke-test entry point described in the Session 02 spec.

use std::net::SocketAddr;
use std::process::ExitCode;

use tracing::error;
use tunnelproxy_common::init_process_logging;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = init_process_logging() {
        eprintln!("failed to configure logging: {error}");
        return ExitCode::from(2);
    }

    let target: SocketAddr = match std::env::var("TUNNELPROXY_AGENT_TARGET") {
        Ok(raw) => match raw.parse() {
            Ok(addr) => addr,
            Err(err) => {
                error!(target = %raw, error = %err, "invalid TUNNELPROXY_AGENT_TARGET");
                return ExitCode::from(2);
            }
        },
        Err(_) => match tunnelproxy_agent::DEFAULT_TARGET_ADDR.parse() {
            Ok(addr) => addr,
            Err(err) => {
                error!(error = %err, "DEFAULT_TARGET_ADDR is not a valid socket address");
                return ExitCode::from(2);
            }
        },
    };

    match tunnelproxy_agent::run(target).await {
        Ok(()) => {
            println!("agent: echo verified");
            ExitCode::SUCCESS
        }
        Err(err) => {
            error!(error = %err, "agent run failed");
            ExitCode::from(1)
        }
    }
}
