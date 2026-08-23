//! Durable authorization and routing snapshots shared with Edge.
//!
//! Session 15 intentionally keeps this crate storage-free. The control-plane
//! model builds immutable snapshots which Edge can consume without querying a
//! database on the ingress hot path (INV-007).

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fmt;

use sha2::{Digest, Sha256};
use tunnelproxy_common::{AgentId, TunnelId};

/// SHA-256 digest of one leaf client certificate in DER form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    pub fn from_certificate_der(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CertificateFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertificateFingerprint({self})")
    }
}

/// Administrative state of a registered tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Registered,
    Connected,
    Disabled,
}

/// One tunnel authorization entry in an Agent grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelGrant {
    pub tunnel_id: TunnelId,
    pub status: TunnelStatus,
}

impl TunnelGrant {
    pub const fn new(tunnel_id: TunnelId, status: TunnelStatus) -> Self {
        Self { tunnel_id, status }
    }
}

/// Exact durable identity authorized for one client leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrant {
    pub certificate: CertificateFingerprint,
    pub agent_id: AgentId,
    pub tunnels: Vec<TunnelGrant>,
}

impl AgentGrant {
    pub fn new(
        certificate: CertificateFingerprint,
        agent_id: AgentId,
        tunnels: Vec<TunnelGrant>,
    ) -> Self {
        Self {
            certificate,
            agent_id,
            tunnels,
        }
    }
}

#[derive(Debug, Clone)]
struct AuthorizedAgent {
    agent_id: AgentId,
    tunnels: HashMap<TunnelId, TunnelStatus>,
}

/// Immutable certificate-to-Agent-to-Tunnel authorization snapshot.
#[derive(Debug, Clone, Default)]
pub struct AuthorizationSnapshot {
    agents: HashMap<CertificateFingerprint, AuthorizedAgent>,
}

impl AuthorizationSnapshot {
    pub fn new(grants: Vec<AgentGrant>) -> Result<Self, SnapshotError> {
        let mut agents = HashMap::with_capacity(grants.len());
        for grant in grants {
            let mut tunnels = HashMap::with_capacity(grant.tunnels.len());
            for tunnel in grant.tunnels {
                if tunnels
                    .insert(tunnel.tunnel_id.clone(), tunnel.status)
                    .is_some()
                {
                    return Err(SnapshotError::DuplicateTunnel {
                        agent_id: grant.agent_id,
                        tunnel_id: tunnel.tunnel_id,
                    });
                }
            }
            let authorized = AuthorizedAgent {
                agent_id: grant.agent_id.clone(),
                tunnels,
            };
            if agents.insert(grant.certificate, authorized).is_some() {
                return Err(SnapshotError::DuplicateCertificate(grant.certificate));
            }
        }
        Ok(Self { agents })
    }

    pub fn authorize(
        &self,
        certificate: &CertificateFingerprint,
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
    ) -> Result<(), AuthorizationError> {
        let agent = self
            .agents
            .get(certificate)
            .ok_or(AuthorizationError::UnknownCertificate)?;
        if &agent.agent_id != agent_id {
            return Err(AuthorizationError::AgentMismatch);
        }
        match agent.tunnels.get(tunnel_id) {
            Some(TunnelStatus::Disabled) => Err(AuthorizationError::TunnelDisabled),
            Some(TunnelStatus::Registered | TunnelStatus::Connected) => Ok(()),
            None => Err(AuthorizationError::TunnelNotAuthorized),
        }
    }

    pub fn certificate_count(&self) -> usize {
        self.agents.len()
    }

    pub fn contains_tunnel(&self, tunnel_id: &TunnelId) -> bool {
        self.agents
            .values()
            .any(|agent| agent.tunnels.contains_key(tunnel_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    DuplicateCertificate(CertificateFingerprint),
    DuplicateTunnel {
        agent_id: AgentId,
        tunnel_id: TunnelId,
    },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCertificate(fingerprint) => {
                write!(f, "duplicate certificate fingerprint {fingerprint}")
            }
            Self::DuplicateTunnel {
                agent_id,
                tunnel_id,
            } => write!(f, "duplicate tunnel {tunnel_id} for Agent {agent_id}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    UnknownCertificate,
    AgentMismatch,
    TunnelNotAuthorized,
    TunnelDisabled,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCertificate => f.write_str("certificate is not assigned to an Agent"),
            Self::AgentMismatch => f.write_str("certificate does not match the claimed Agent"),
            Self::TunnelNotAuthorized => f.write_str("Agent is not authorized for the tunnel"),
            Self::TunnelDisabled => f.write_str("tunnel is disabled"),
        }
    }
}

impl std::error::Error for AuthorizationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_id() -> AgentId {
        AgentId::new("agent-a").unwrap()
    }

    fn tunnel_id() -> TunnelId {
        TunnelId::new("tunnel-a").unwrap()
    }

    fn snapshot(status: TunnelStatus) -> AuthorizationSnapshot {
        AuthorizationSnapshot::new(vec![AgentGrant::new(
            CertificateFingerprint::from_bytes([7; 32]),
            agent_id(),
            vec![TunnelGrant::new(tunnel_id(), status)],
        )])
        .unwrap()
    }

    #[test]
    fn exact_certificate_agent_and_tunnel_are_authorized() {
        assert_eq!(
            snapshot(TunnelStatus::Registered).authorize(
                &CertificateFingerprint::from_bytes([7; 32]),
                &agent_id(),
                &tunnel_id(),
            ),
            Ok(())
        );
    }

    #[test]
    fn authorization_fails_closed_for_each_mismatch() {
        let snapshot = snapshot(TunnelStatus::Registered);
        assert_eq!(
            snapshot.authorize(
                &CertificateFingerprint::from_bytes([8; 32]),
                &agent_id(),
                &tunnel_id(),
            ),
            Err(AuthorizationError::UnknownCertificate)
        );
        assert_eq!(
            snapshot.authorize(
                &CertificateFingerprint::from_bytes([7; 32]),
                &AgentId::new("agent-b").unwrap(),
                &tunnel_id(),
            ),
            Err(AuthorizationError::AgentMismatch)
        );
        assert_eq!(
            snapshot.authorize(
                &CertificateFingerprint::from_bytes([7; 32]),
                &agent_id(),
                &TunnelId::new("tunnel-b").unwrap(),
            ),
            Err(AuthorizationError::TunnelNotAuthorized)
        );
    }

    #[test]
    fn disabled_tunnel_is_rejected() {
        assert_eq!(
            snapshot(TunnelStatus::Disabled).authorize(
                &CertificateFingerprint::from_bytes([7; 32]),
                &agent_id(),
                &tunnel_id(),
            ),
            Err(AuthorizationError::TunnelDisabled)
        );
    }

    #[test]
    fn duplicate_certificate_or_tunnel_is_rejected() {
        let fingerprint = CertificateFingerprint::from_bytes([1; 32]);
        let grant = AgentGrant::new(
            fingerprint,
            agent_id(),
            vec![TunnelGrant::new(tunnel_id(), TunnelStatus::Registered)],
        );
        assert!(matches!(
            AuthorizationSnapshot::new(vec![grant.clone(), grant]),
            Err(SnapshotError::DuplicateCertificate(_))
        ));
        assert!(matches!(
            AuthorizationSnapshot::new(vec![AgentGrant::new(
                fingerprint,
                agent_id(),
                vec![
                    TunnelGrant::new(tunnel_id(), TunnelStatus::Registered),
                    TunnelGrant::new(tunnel_id(), TunnelStatus::Registered),
                ],
            )]),
            Err(SnapshotError::DuplicateTunnel { .. })
        ));
    }

    #[test]
    fn certificate_fingerprint_is_stable_sha256() {
        assert_eq!(
            CertificateFingerprint::from_certificate_der(b"certificate").to_string(),
            "03d66dd08835c1ca3f128cceacd1f31ac94163096b20f445ae84285bc0832d72"
        );
    }
}
