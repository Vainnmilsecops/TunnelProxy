//! `tunnelproxy-agent`
//!
//! Future local TunnelProxy agent / CLI runtime.
//!
//! The agent is the binary developers run on their machine. It will:
//!   * initiate an outbound tunnel to an Edge node (INV-001),
//!   * register which local ports it wants to expose,
//!   * stream public request traffic back to the local service,
//!   * never accept inbound connections from the public internet itself.
//!
//! None of that exists yet. This crate currently exports a single library
//! function so the workspace still has a usable surface for tests, and so
//! future sessions have a non-empty crate to grow into.

#![deny(unsafe_code)]

/// Build identifier string for the agent binary.
///
/// Useful for `--version` output and for sending to Edge during future
/// handshake negotiations.
pub fn build_identifier() -> &'static str {
    concat!("tunnelproxy-agent/", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_identifier_is_non_empty() {
        assert!(!build_identifier().is_empty());
        assert!(build_identifier().starts_with("tunnelproxy-agent/"));
    }
}
