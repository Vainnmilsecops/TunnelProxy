//! Canonical TunnelProxy developer CLI executable.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tunnelproxy_agent::cli::run("tunnelproxy").await
}
