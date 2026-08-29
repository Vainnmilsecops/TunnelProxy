//! Backwards-compatible TunnelProxy Agent executable.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tunnelproxy_agent::cli::run("tunnelproxy-agent").await
}
