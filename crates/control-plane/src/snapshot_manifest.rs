use serde::Deserialize;
use tunnelproxy_common::{AgentId, TunnelId};

use crate::{
    AgentGrant, AuthorizationSnapshot, CertificateFingerprint, SnapshotVersion, TunnelGrant,
    TunnelStatus, VersionedAuthorizationSnapshot, MAX_AGENTS_PER_SNAPSHOT, MAX_SNAPSHOT_BYTES,
    MAX_TUNNELS_PER_AGENT,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotManifest {
    version: u64,
    agents: Vec<AgentManifest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentManifest {
    certificate_sha256: String,
    agent_id: String,
    tunnels: Vec<TunnelManifest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelManifest {
    tunnel_id: String,
    status: ManifestTunnelStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ManifestTunnelStatus {
    Enabled,
    Disabled,
}

pub fn parse_snapshot_manifest(
    bytes: &[u8],
) -> Result<VersionedAuthorizationSnapshot, SnapshotManifestError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotManifestError::TooLarge(bytes.len()));
    }
    let manifest: SnapshotManifest =
        serde_json::from_slice(bytes).map_err(|_| SnapshotManifestError::InvalidJson)?;
    let version =
        SnapshotVersion::new(manifest.version).ok_or(SnapshotManifestError::InvalidVersion)?;
    if manifest.agents.len() > MAX_AGENTS_PER_SNAPSHOT {
        return Err(SnapshotManifestError::TooManyAgents(manifest.agents.len()));
    }
    let mut grants = Vec::with_capacity(manifest.agents.len());
    for agent in manifest.agents {
        if agent.tunnels.len() > MAX_TUNNELS_PER_AGENT {
            return Err(SnapshotManifestError::TooManyTunnels(agent.tunnels.len()));
        }
        let certificate = parse_fingerprint(&agent.certificate_sha256)?;
        let agent_id =
            AgentId::new(agent.agent_id).map_err(|_| SnapshotManifestError::InvalidAgentId)?;
        let tunnels = agent
            .tunnels
            .into_iter()
            .map(|tunnel| {
                let tunnel_id = TunnelId::new(tunnel.tunnel_id)
                    .map_err(|_| SnapshotManifestError::InvalidTunnelId)?;
                let status = match tunnel.status {
                    ManifestTunnelStatus::Enabled => TunnelStatus::Enabled,
                    ManifestTunnelStatus::Disabled => TunnelStatus::Disabled,
                };
                Ok(TunnelGrant::new(tunnel_id, status))
            })
            .collect::<Result<Vec<_>, SnapshotManifestError>>()?;
        grants.push(AgentGrant::new(certificate, agent_id, tunnels));
    }
    let snapshot =
        AuthorizationSnapshot::new(grants).map_err(|_| SnapshotManifestError::DuplicateGrant)?;
    Ok(VersionedAuthorizationSnapshot::new(version, snapshot))
}

fn parse_fingerprint(value: &str) -> Result<CertificateFingerprint, SnapshotManifestError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SnapshotManifestError::InvalidFingerprint);
    }
    let mut fingerprint = [0_u8; 32];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| SnapshotManifestError::InvalidFingerprint)?;
    }
    Ok(CertificateFingerprint::from_bytes(fingerprint))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotManifestError {
    TooLarge(usize),
    InvalidJson,
    InvalidVersion,
    InvalidFingerprint,
    InvalidAgentId,
    InvalidTunnelId,
    TooManyAgents(usize),
    TooManyTunnels(usize),
    DuplicateGrant,
}

impl std::fmt::Display for SnapshotManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(size) => write!(f, "snapshot manifest is too large: {size} bytes"),
            Self::InvalidJson => f.write_str("snapshot manifest JSON is invalid"),
            Self::InvalidVersion => f.write_str("snapshot manifest version must be non-zero"),
            Self::InvalidFingerprint => f.write_str(
                "snapshot certificate fingerprint must be exactly 64 hexadecimal characters",
            ),
            Self::InvalidAgentId => f.write_str("snapshot manifest AgentId is invalid"),
            Self::InvalidTunnelId => f.write_str("snapshot manifest TunnelId is invalid"),
            Self::TooManyAgents(count) => {
                write!(f, "snapshot manifest has too many Agents: {count}")
            }
            Self::TooManyTunnels(count) => {
                write!(f, "snapshot manifest Agent has too many tunnels: {count}")
            }
            Self::DuplicateGrant => {
                f.write_str("snapshot manifest contains a duplicate certificate or tunnel")
            }
        }
    }
}

impl std::error::Error for SnapshotManifestError {}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = br#"{
        "version": 7,
        "agents": [{
            "certificate_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
            "agent_id": "agent-prod",
            "tunnels": [{"tunnel_id": "tunnel-prod", "status": "enabled"}]
        }]
    }"#;

    #[test]
    fn strict_manifest_builds_domain_snapshot() {
        let snapshot = parse_snapshot_manifest(VALID).unwrap();
        assert_eq!(snapshot.version().get(), 7);
        assert_eq!(snapshot.snapshot().certificate_count(), 1);
        assert!(snapshot
            .snapshot()
            .authorize(
                &CertificateFingerprint::from_bytes([1; 32]),
                &AgentId::new("agent-prod").unwrap(),
                &TunnelId::new("tunnel-prod").unwrap(),
            )
            .is_ok());
    }

    #[test]
    fn manifest_rejects_unknown_fields_and_invalid_values() {
        assert_eq!(
            parse_snapshot_manifest(br#"{"version":1,"agents":[],"extra":true}"#),
            Err(SnapshotManifestError::InvalidJson)
        );
        assert_eq!(
            parse_snapshot_manifest(br#"{"version":0,"agents":[]}"#),
            Err(SnapshotManifestError::InvalidVersion)
        );
        assert_eq!(
            parse_snapshot_manifest(
                br#"{"version":1,"agents":[{"certificate_sha256":"bad","agent_id":"agent","tunnels":[]}]}"#,
            ),
            Err(SnapshotManifestError::InvalidFingerprint)
        );
        assert!(matches!(
            parse_snapshot_manifest(&vec![b' '; MAX_SNAPSHOT_BYTES + 1]),
            Err(SnapshotManifestError::TooLarge(_))
        ));
    }
}
