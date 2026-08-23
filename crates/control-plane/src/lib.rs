//! Durable authorization and routing snapshots shared with Edge.
//!
//! Session 16 keeps this crate storage-free while adding monotonic full-snapshot
//! versions and bounded latest-value distribution. Edge consumes immutable
//! cached snapshots without querying a database on the ingress hot path
//! (INV-007).

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::sync::watch;
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
    Enabled,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizedAgent {
    agent_id: AgentId,
    tunnels: HashMap<TunnelId, TunnelStatus>,
}

/// Immutable certificate-to-Agent-to-Tunnel authorization snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
            Some(TunnelStatus::Enabled) => Ok(()),
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

/// Monotonic version assigned by the authoritative snapshot producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotVersion(NonZeroU64);

impl SnapshotVersion {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for SnapshotVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

/// One complete, authoritative authorization snapshot.
///
/// Updates replace the previous snapshot in full. A missing grant therefore
/// revokes that grant; an empty snapshot revokes all grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedAuthorizationSnapshot {
    version: SnapshotVersion,
    snapshot: Arc<AuthorizationSnapshot>,
}

impl VersionedAuthorizationSnapshot {
    pub fn new(version: SnapshotVersion, snapshot: AuthorizationSnapshot) -> Self {
        Self {
            version,
            snapshot: Arc::new(snapshot),
        }
    }

    pub const fn version(&self) -> SnapshotVersion {
        self.version
    }

    pub fn snapshot(&self) -> &AuthorizationSnapshot {
        &self.snapshot
    }
}

#[derive(Debug)]
struct SnapshotPublisherState {
    current: Arc<VersionedAuthorizationSnapshot>,
    updates: watch::Sender<Arc<VersionedAuthorizationSnapshot>>,
}

/// Cloneable authoritative producer for latest-value snapshot distribution.
///
/// Publication is serialized under a short synchronous mutex. The mutex is
/// never held across network or async I/O, and the Tokio watch channel retains
/// only the latest complete snapshot.
#[derive(Clone)]
pub struct AuthorizationSnapshotPublisher {
    state: Arc<Mutex<SnapshotPublisherState>>,
}

impl AuthorizationSnapshotPublisher {
    pub fn current(&self) -> Arc<VersionedAuthorizationSnapshot> {
        Arc::clone(
            &self
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .current,
        )
    }

    pub fn publish(
        &self,
        candidate: VersionedAuthorizationSnapshot,
    ) -> Result<SnapshotPublishOutcome, SnapshotUpdateError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let current = &state.current;
        if candidate.version < current.version {
            return Err(SnapshotUpdateError::StaleVersion {
                current: current.version,
                received: candidate.version,
            });
        }
        if candidate.version == current.version {
            if candidate.snapshot == current.snapshot {
                return Ok(SnapshotPublishOutcome::Unchanged {
                    version: current.version,
                });
            }
            return Err(SnapshotUpdateError::ConflictingVersion {
                version: current.version,
            });
        }

        let previous = current.version;
        let candidate = Arc::new(candidate);
        state.current = Arc::clone(&candidate);
        state.updates.send_replace(candidate);
        Ok(SnapshotPublishOutcome::Applied {
            previous,
            current: state.current.version,
        })
    }
}

impl fmt::Debug for AuthorizationSnapshotPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationSnapshotPublisher")
            .field("version", &self.current().version)
            .finish_non_exhaustive()
    }
}

/// Edge-side latest-value subscription. Dropping every publisher closes the
/// source but the receiver can continue using its last cached snapshot.
#[derive(Debug, Clone)]
pub struct AuthorizationSnapshotSubscription {
    updates: watch::Receiver<Arc<VersionedAuthorizationSnapshot>>,
}

impl AuthorizationSnapshotSubscription {
    pub fn current(&self) -> Arc<VersionedAuthorizationSnapshot> {
        Arc::clone(&self.updates.borrow())
    }

    pub async fn changed(
        &mut self,
    ) -> Result<Arc<VersionedAuthorizationSnapshot>, SnapshotSourceClosed> {
        self.updates
            .changed()
            .await
            .map_err(|_| SnapshotSourceClosed)?;
        Ok(self.current())
    }
}

/// Creates a bounded latest-value distribution channel with an initial
/// authoritative snapshot available before any Edge subscription starts.
pub fn authorization_snapshot_channel(
    initial: VersionedAuthorizationSnapshot,
) -> (
    AuthorizationSnapshotPublisher,
    AuthorizationSnapshotSubscription,
) {
    let initial = Arc::new(initial);
    let (updates, receiver) = watch::channel(Arc::clone(&initial));
    (
        AuthorizationSnapshotPublisher {
            state: Arc::new(Mutex::new(SnapshotPublisherState {
                current: initial,
                updates,
            })),
        },
        AuthorizationSnapshotSubscription { updates: receiver },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotPublishOutcome {
    Applied {
        previous: SnapshotVersion,
        current: SnapshotVersion,
    },
    Unchanged {
        version: SnapshotVersion,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotUpdateError {
    StaleVersion {
        current: SnapshotVersion,
        received: SnapshotVersion,
    },
    ConflictingVersion {
        version: SnapshotVersion,
    },
}

impl fmt::Display for SnapshotUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleVersion { current, received } => write!(
                f,
                "snapshot version {received} is stale; current version is {current}"
            ),
            Self::ConflictingVersion { version } => {
                write!(
                    f,
                    "snapshot version {version} conflicts with current content"
                )
            }
        }
    }
}

impl std::error::Error for SnapshotUpdateError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotSourceClosed;

impl fmt::Display for SnapshotSourceClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authorization snapshot source closed")
    }
}

impl std::error::Error for SnapshotSourceClosed {}

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
            snapshot(TunnelStatus::Enabled).authorize(
                &CertificateFingerprint::from_bytes([7; 32]),
                &agent_id(),
                &tunnel_id(),
            ),
            Ok(())
        );
    }

    #[test]
    fn authorization_fails_closed_for_each_mismatch() {
        let snapshot = snapshot(TunnelStatus::Enabled);
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
            vec![TunnelGrant::new(tunnel_id(), TunnelStatus::Enabled)],
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
                    TunnelGrant::new(tunnel_id(), TunnelStatus::Enabled),
                    TunnelGrant::new(tunnel_id(), TunnelStatus::Enabled),
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

    fn versioned(version: u64, status: TunnelStatus) -> VersionedAuthorizationSnapshot {
        VersionedAuthorizationSnapshot::new(
            SnapshotVersion::new(version).unwrap(),
            snapshot(status),
        )
    }

    #[test]
    fn snapshot_version_rejects_zero_and_orders_monotonically() {
        assert_eq!(SnapshotVersion::new(0), None);
        assert!(SnapshotVersion::new(2).unwrap() > SnapshotVersion::FIRST);
    }

    #[tokio::test]
    async fn higher_version_is_distributed_and_gaps_are_valid() {
        let (publisher, mut subscription) =
            authorization_snapshot_channel(versioned(1, TunnelStatus::Enabled));
        assert_eq!(
            publisher.publish(versioned(4, TunnelStatus::Disabled)),
            Ok(SnapshotPublishOutcome::Applied {
                previous: SnapshotVersion::new(1).unwrap(),
                current: SnapshotVersion::new(4).unwrap(),
            })
        );
        let update = subscription.changed().await.unwrap();
        assert_eq!(update.version(), SnapshotVersion::new(4).unwrap());
        assert_eq!(
            update.snapshot().authorize(
                &CertificateFingerprint::from_bytes([7; 32]),
                &agent_id(),
                &tunnel_id(),
            ),
            Err(AuthorizationError::TunnelDisabled)
        );
    }

    #[test]
    fn duplicate_is_idempotent_but_same_version_conflict_is_rejected() {
        let initial = versioned(3, TunnelStatus::Enabled);
        let (publisher, _) = authorization_snapshot_channel(initial.clone());
        assert_eq!(
            publisher.publish(initial),
            Ok(SnapshotPublishOutcome::Unchanged {
                version: SnapshotVersion::new(3).unwrap(),
            })
        );
        assert_eq!(
            publisher.publish(versioned(3, TunnelStatus::Disabled)),
            Err(SnapshotUpdateError::ConflictingVersion {
                version: SnapshotVersion::new(3).unwrap(),
            })
        );
    }

    #[test]
    fn stale_update_never_rolls_back_current_snapshot() {
        let (publisher, _) = authorization_snapshot_channel(versioned(5, TunnelStatus::Enabled));
        assert_eq!(
            publisher.publish(versioned(4, TunnelStatus::Disabled)),
            Err(SnapshotUpdateError::StaleVersion {
                current: SnapshotVersion::new(5).unwrap(),
                received: SnapshotVersion::new(4).unwrap(),
            })
        );
        assert_eq!(
            publisher.current().version(),
            SnapshotVersion::new(5).unwrap()
        );
    }

    #[tokio::test]
    async fn latest_value_is_bounded_and_closed_source_retains_cache() {
        let (publisher, mut subscription) =
            authorization_snapshot_channel(versioned(1, TunnelStatus::Enabled));
        publisher
            .publish(versioned(2, TunnelStatus::Disabled))
            .unwrap();
        publisher
            .publish(VersionedAuthorizationSnapshot::new(
                SnapshotVersion::new(3).unwrap(),
                AuthorizationSnapshot::default(),
            ))
            .unwrap();
        assert_eq!(
            subscription.changed().await.unwrap().version(),
            SnapshotVersion::new(3).unwrap()
        );
        drop(publisher);
        assert_eq!(subscription.changed().await, Err(SnapshotSourceClosed));
        assert_eq!(
            subscription.current().version(),
            SnapshotVersion::new(3).unwrap()
        );
    }
}
