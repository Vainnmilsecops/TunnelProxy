use sha2::{Digest, Sha256};
use tunnelproxy_common::{AgentId, TunnelId};

use crate::{
    AgentGrant, AuthorizationSnapshot, CertificateFingerprint, SnapshotError, SnapshotVersion,
    TunnelGrant, TunnelStatus, VersionedAuthorizationSnapshot,
};

pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
pub const MAX_AGENTS_PER_SNAPSHOT: usize = 4096;
pub const MAX_TUNNELS_PER_AGENT: usize = 4096;

pub fn encode_snapshot(snapshot: &AuthorizationSnapshot) -> Result<Vec<u8>, SnapshotCodecError> {
    let grants = snapshot.grants();
    if grants.len() > MAX_AGENTS_PER_SNAPSHOT {
        return Err(SnapshotCodecError::TooManyAgents(grants.len()));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&(grants.len() as u32).to_be_bytes());
    for grant in grants {
        output.extend_from_slice(grant.certificate.as_bytes());
        push_id(&mut output, grant.agent_id.as_str());
        ensure_encoded_size(&output)?;
        if grant.tunnels.len() > MAX_TUNNELS_PER_AGENT {
            return Err(SnapshotCodecError::TooManyTunnels(grant.tunnels.len()));
        }
        output.extend_from_slice(&(grant.tunnels.len() as u16).to_be_bytes());
        for tunnel in grant.tunnels {
            push_id(&mut output, tunnel.tunnel_id.as_str());
            output.push(match tunnel.status {
                TunnelStatus::Enabled => 1,
                TunnelStatus::Disabled => 2,
            });
            ensure_encoded_size(&output)?;
        }
    }
    Ok(output)
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<AuthorizationSnapshot, SnapshotCodecError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotCodecError::TooLarge(bytes.len()));
    }
    let mut input = Input::new(bytes);
    let agent_count = input.u32()? as usize;
    if agent_count > MAX_AGENTS_PER_SNAPSHOT {
        return Err(SnapshotCodecError::TooManyAgents(agent_count));
    }
    let mut grants = Vec::with_capacity(agent_count);
    for _ in 0..agent_count {
        let certificate = CertificateFingerprint::from_bytes(input.array::<32>()?);
        let agent_id = AgentId::new(input.id()?).map_err(|_| SnapshotCodecError::InvalidId)?;
        let tunnel_count = input.u16()? as usize;
        if tunnel_count > MAX_TUNNELS_PER_AGENT {
            return Err(SnapshotCodecError::TooManyTunnels(tunnel_count));
        }
        let mut tunnels = Vec::with_capacity(tunnel_count);
        for _ in 0..tunnel_count {
            let tunnel_id =
                TunnelId::new(input.id()?).map_err(|_| SnapshotCodecError::InvalidId)?;
            let status = match input.u8()? {
                1 => TunnelStatus::Enabled,
                2 => TunnelStatus::Disabled,
                _ => return Err(SnapshotCodecError::InvalidStatus),
            };
            tunnels.push(TunnelGrant::new(tunnel_id, status));
        }
        grants.push(AgentGrant::new(certificate, agent_id, tunnels));
    }
    if !input.is_empty() {
        return Err(SnapshotCodecError::TrailingBytes);
    }
    AuthorizationSnapshot::new(grants).map_err(SnapshotCodecError::InvalidSnapshot)
}

pub fn encode_versioned_snapshot(
    snapshot: &VersionedAuthorizationSnapshot,
) -> Result<Vec<u8>, SnapshotCodecError> {
    let payload = encode_snapshot(snapshot.snapshot())?;
    let total = payload
        .len()
        .checked_add(8)
        .ok_or(SnapshotCodecError::TooLarge(usize::MAX))?;
    if total > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotCodecError::TooLarge(total));
    }
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&snapshot.version().get().to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

pub fn decode_versioned_snapshot(
    bytes: &[u8],
) -> Result<VersionedAuthorizationSnapshot, SnapshotCodecError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotCodecError::TooLarge(bytes.len()));
    }
    let version_bytes: [u8; 8] = bytes
        .get(..8)
        .ok_or(SnapshotCodecError::Truncated)?
        .try_into()
        .expect("slice length checked");
    let version = SnapshotVersion::new(u64::from_be_bytes(version_bytes))
        .ok_or(SnapshotCodecError::InvalidVersion)?;
    let snapshot = decode_snapshot(&bytes[8..])?;
    Ok(VersionedAuthorizationSnapshot::new(version, snapshot))
}

pub fn snapshot_digest(snapshot: &AuthorizationSnapshot) -> Result<[u8; 32], SnapshotCodecError> {
    Ok(Sha256::digest(encode_snapshot(snapshot)?).into())
}

fn push_id(output: &mut Vec<u8>, value: &str) {
    let len = u16::try_from(value.len()).expect("validated durable ID fits u16");
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn ensure_encoded_size(output: &[u8]) -> Result<(), SnapshotCodecError> {
    if output.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotCodecError::TooLarge(output.len()));
    }
    Ok(())
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SnapshotCodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SnapshotCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SnapshotCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SnapshotCodecError> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("requested exact array size"))
    }

    fn u8(&mut self) -> Result<u8, SnapshotCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SnapshotCodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, SnapshotCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn id(&mut self) -> Result<&'a str, SnapshotCodecError> {
        let len = self.u16()? as usize;
        std::str::from_utf8(self.take(len)?).map_err(|_| SnapshotCodecError::InvalidUtf8)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotCodecError {
    TooLarge(usize),
    TooManyAgents(usize),
    TooManyTunnels(usize),
    Truncated,
    TrailingBytes,
    InvalidVersion,
    InvalidUtf8,
    InvalidId,
    InvalidStatus,
    InvalidSnapshot(SnapshotError),
}

impl std::fmt::Display for SnapshotCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(size) => write!(f, "snapshot payload is too large: {size} bytes"),
            Self::TooManyAgents(count) => write!(f, "snapshot has too many Agents: {count}"),
            Self::TooManyTunnels(count) => {
                write!(f, "Agent grant has too many tunnels: {count}")
            }
            Self::Truncated => f.write_str("snapshot payload is truncated"),
            Self::TrailingBytes => f.write_str("snapshot payload has trailing bytes"),
            Self::InvalidVersion => f.write_str("snapshot version must be non-zero"),
            Self::InvalidUtf8 => f.write_str("snapshot identifier is not valid UTF-8"),
            Self::InvalidId => f.write_str("snapshot identifier is invalid"),
            Self::InvalidStatus => f.write_str("snapshot tunnel status is invalid"),
            Self::InvalidSnapshot(error) => write!(f, "snapshot grants are invalid: {error}"),
        }
    }
}

impl std::error::Error for SnapshotCodecError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(byte: u8, agent: &str, tunnels: &[(&str, TunnelStatus)]) -> AgentGrant {
        AgentGrant::new(
            CertificateFingerprint::from_bytes([byte; 32]),
            AgentId::new(agent).unwrap(),
            tunnels
                .iter()
                .map(|(id, status)| TunnelGrant::new(TunnelId::new(*id).unwrap(), *status))
                .collect(),
        )
    }

    #[test]
    fn canonical_encoding_is_independent_of_input_order() {
        let first = AuthorizationSnapshot::new(vec![
            grant(2, "agent-b", &[("tunnel-b", TunnelStatus::Disabled)]),
            grant(
                1,
                "agent-a",
                &[
                    ("tunnel-z", TunnelStatus::Enabled),
                    ("tunnel-a", TunnelStatus::Enabled),
                ],
            ),
        ])
        .unwrap();
        let second = AuthorizationSnapshot::new(vec![
            grant(
                1,
                "agent-a",
                &[
                    ("tunnel-a", TunnelStatus::Enabled),
                    ("tunnel-z", TunnelStatus::Enabled),
                ],
            ),
            grant(2, "agent-b", &[("tunnel-b", TunnelStatus::Disabled)]),
        ])
        .unwrap();
        assert_eq!(
            encode_snapshot(&first).unwrap(),
            encode_snapshot(&second).unwrap()
        );
        assert_eq!(
            snapshot_digest(&first).unwrap(),
            snapshot_digest(&second).unwrap()
        );
    }

    #[test]
    fn versioned_snapshot_roundtrips_and_rejects_malformed_payloads() {
        let value = VersionedAuthorizationSnapshot::new(
            SnapshotVersion::new(9).unwrap(),
            AuthorizationSnapshot::new(vec![grant(
                7,
                "agent-a",
                &[("tunnel-a", TunnelStatus::Enabled)],
            )])
            .unwrap(),
        );
        let encoded = encode_versioned_snapshot(&value).unwrap();
        assert_eq!(decode_versioned_snapshot(&encoded), Ok(value));
        assert_eq!(
            decode_versioned_snapshot(&encoded[..7]),
            Err(SnapshotCodecError::Truncated)
        );
        let mut invalid_status = encoded;
        *invalid_status.last_mut().unwrap() = 99;
        assert_eq!(
            decode_versioned_snapshot(&invalid_status),
            Err(SnapshotCodecError::InvalidStatus)
        );

        let too_many_agents = AuthorizationSnapshot::new(
            (0..=MAX_AGENTS_PER_SNAPSHOT)
                .map(|index| {
                    let mut fingerprint = [0_u8; 32];
                    fingerprint[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    grant_with_fingerprint(fingerprint, Vec::new())
                })
                .collect(),
        )
        .unwrap();
        assert!(matches!(
            encode_snapshot(&too_many_agents),
            Err(SnapshotCodecError::TooManyAgents(_))
        ));

        let too_many_tunnels: Vec<_> = (0..=MAX_TUNNELS_PER_AGENT)
            .map(|index| {
                TunnelGrant::new(
                    TunnelId::new(format!("tunnel-{index}")).unwrap(),
                    TunnelStatus::Enabled,
                )
            })
            .collect();
        let too_many_tunnels =
            AuthorizationSnapshot::new(vec![grant_with_fingerprint([8; 32], too_many_tunnels)])
                .unwrap();
        assert!(matches!(
            encode_snapshot(&too_many_tunnels),
            Err(SnapshotCodecError::TooManyTunnels(_))
        ));

        let maximum_tunnels: Vec<_> = (0..MAX_TUNNELS_PER_AGENT)
            .map(|index| {
                TunnelGrant::new(
                    TunnelId::new(format!("tunnel-{index:057}")).unwrap(),
                    TunnelStatus::Enabled,
                )
            })
            .collect();
        let oversized = AuthorizationSnapshot::new(
            (10..15)
                .map(|byte| grant_with_fingerprint([byte; 32], maximum_tunnels.clone()))
                .collect(),
        )
        .unwrap();
        assert!(matches!(
            encode_snapshot(&oversized),
            Err(SnapshotCodecError::TooLarge(_))
        ));
        assert_eq!(
            decode_snapshot(&vec![0; MAX_SNAPSHOT_BYTES + 1]),
            Err(SnapshotCodecError::TooLarge(MAX_SNAPSHOT_BYTES + 1))
        );
    }

    fn grant_with_fingerprint(fingerprint: [u8; 32], tunnels: Vec<TunnelGrant>) -> AgentGrant {
        AgentGrant::new(
            CertificateFingerprint::from_bytes(fingerprint),
            AgentId::new("agent-bounds").unwrap(),
            tunnels,
        )
    }
}
