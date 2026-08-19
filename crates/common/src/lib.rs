//! `tunnelproxy-common`
//!
//! Shared strongly-typed primitives that genuinely cross every component
//! boundary: identifiers, error sentinels, time helpers, and tiny
//! serialization-free value types.
//!
//! This crate must remain small. If a type is only useful inside one other
//! crate, it does not belong here.

#![deny(unsafe_code)]

/// Stable identifier for an `agent` registered with the control plane.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AgentId(pub String);

impl AgentId {
    /// Construct an [`AgentId`] from a checked string.
    ///
    /// The string must be non-empty. Any further validation (length, charset)
    /// is intentionally deferred to the control plane.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable identifier for a public tunnel exposed by an agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TunnelId(pub String);

impl TunnelId {
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
    fn agent_id_roundtrips_string() {
        let id = AgentId::new("agent-abc");
        assert_eq!(id.as_str(), "agent-abc");
    }

    #[test]
    fn tunnel_id_roundtrips_string() {
        let id = TunnelId::new("blue-cat");
        assert_eq!(id.as_str(), "blue-cat");
    }
}
