//! `tunnelproxy-control-plane`
//!
//! Future durable tunnel and account configuration plus APIs.
//!
//! The control plane owns the slow-changing state: users, agents, tunnel
//! metadata, authentication material, domain configuration, and quotas.
//! It is intentionally separated from the data plane so per-request
//! routing on the edge never depends on a database query (INV-007).
//!
//! Nothing is implemented yet. This crate exists as a placeholder so the
//! workspace has the right component boundaries from day one.

#![deny(unsafe_code)]

/// Coarse-grained status of a registered tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    /// Tunnel registered but not currently connected.
    Registered,
    /// Agent has an active connection to an edge node.
    Connected,
    /// Tunnel has been administratively disabled.
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_status_distinct_values() {
        assert_ne!(TunnelStatus::Registered, TunnelStatus::Connected);
        assert_ne!(TunnelStatus::Connected, TunnelStatus::Disabled);
        assert_ne!(TunnelStatus::Registered, TunnelStatus::Disabled);
    }
}
