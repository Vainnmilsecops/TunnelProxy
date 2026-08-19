//! `tunnelproxy-edge`
//!
//! Future public ingress and live tunnel routing.
//!
//! The edge is the component that terminates public traffic on a hostname
//! such as `https://<host>.tunnelproxy.dev` and forwards it to the correct
//! agent. None of that exists yet. This crate exists so the workspace has
//! a non-empty surface and so future sessions can grow into it without
//! restructuring the repo.

#![deny(unsafe_code)]

/// Stable identifier for an edge node.
///
/// In the future this will be used for routing, observability, and
/// multi-edge coordination. Today it is a value type only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct EdgeId(pub String);

impl EdgeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_id_roundtrips_string() {
        let id = EdgeId::new("edge-fra-1");
        assert_eq!(id.as_str(), "edge-fra-1");
    }
}
