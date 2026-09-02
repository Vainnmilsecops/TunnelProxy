//! Atomic process-local target snapshots for managed tunnel generations.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tunnelproxy_common::TunnelId;

use crate::MAX_MANAGED_HTTP_TUNNELS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelTargetReloadHealth {
    Disabled,
    Healthy,
    ReloadFailed,
}

impl TunnelTargetReloadHealth {
    pub const ALL: [Self; 3] = [Self::Disabled, Self::Healthy, Self::ReloadFailed];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Healthy => "healthy",
            Self::ReloadFailed => "reload_failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelTargetReloadStatus {
    pub generation: u64,
    pub health: TunnelTargetReloadHealth,
    pub successful_reloads: u64,
    pub failed_reloads: u64,
}

#[derive(Debug)]
struct TunnelTargetState {
    generation: u64,
    manifest_digest: [u8; 32],
    targets: BTreeMap<TunnelId, SocketAddr>,
    health: TunnelTargetReloadHealth,
    successful_reloads: u64,
    failed_reloads: u64,
}

#[derive(Debug, Clone)]
pub struct TunnelTargetSet {
    state: Arc<RwLock<TunnelTargetState>>,
}

impl TunnelTargetSet {
    pub fn fixed(targets: BTreeMap<TunnelId, SocketAddr>) -> Result<Self, TunnelTargetSetError> {
        validate_targets(&targets)?;
        Ok(Self {
            state: Arc::new(RwLock::new(TunnelTargetState {
                generation: 0,
                manifest_digest: [0; 32],
                targets,
                health: TunnelTargetReloadHealth::Disabled,
                successful_reloads: 0,
                failed_reloads: 0,
            })),
        })
    }

    pub fn reloadable(
        generation: u64,
        manifest_digest: [u8; 32],
        targets: BTreeMap<TunnelId, SocketAddr>,
    ) -> Result<Self, TunnelTargetSetError> {
        if generation == 0 {
            return Err(TunnelTargetSetError::ZeroGeneration);
        }
        validate_targets(&targets)?;
        Ok(Self {
            state: Arc::new(RwLock::new(TunnelTargetState {
                generation,
                manifest_digest,
                targets,
                health: TunnelTargetReloadHealth::Healthy,
                successful_reloads: 0,
                failed_reloads: 0,
            })),
        })
    }

    pub fn target(&self, tunnel_id: &TunnelId) -> Result<TunnelTarget, TunnelTargetSetError> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fallback = state
            .targets
            .get(tunnel_id)
            .copied()
            .ok_or(TunnelTargetSetError::UnknownTunnel)?;
        Ok(TunnelTarget {
            tunnel_id: tunnel_id.clone(),
            fallback,
            set: self.clone(),
        })
    }

    pub fn apply(
        &self,
        generation: u64,
        manifest_digest: [u8; 32],
        targets: BTreeMap<TunnelId, SocketAddr>,
    ) -> Result<TunnelTargetApplyOutcome, TunnelTargetSetError> {
        if generation == 0 {
            return Err(TunnelTargetSetError::ZeroGeneration);
        }
        validate_targets(&targets)?;
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.health == TunnelTargetReloadHealth::Disabled {
            return Err(TunnelTargetSetError::ReloadDisabled);
        }
        if generation < state.generation {
            return Err(TunnelTargetSetError::StaleGeneration {
                current: state.generation,
                received: generation,
            });
        }
        if generation == state.generation {
            if manifest_digest != state.manifest_digest {
                return Err(TunnelTargetSetError::ConflictingGeneration(generation));
            }
            state.health = TunnelTargetReloadHealth::Healthy;
            return Ok(TunnelTargetApplyOutcome::Unchanged);
        }
        if state.targets.keys().ne(targets.keys()) {
            return Err(TunnelTargetSetError::TunnelSetChanged);
        }
        state.generation = generation;
        state.manifest_digest = manifest_digest;
        state.targets = targets;
        state.health = TunnelTargetReloadHealth::Healthy;
        state.successful_reloads = state.successful_reloads.saturating_add(1);
        Ok(TunnelTargetApplyOutcome::Applied)
    }

    pub fn record_reload_failure(&self) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.health != TunnelTargetReloadHealth::Disabled {
            state.health = TunnelTargetReloadHealth::ReloadFailed;
            state.failed_reloads = state.failed_reloads.saturating_add(1);
        }
    }

    pub fn status(&self) -> TunnelTargetReloadStatus {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        TunnelTargetReloadStatus {
            generation: state.generation,
            health: state.health,
            successful_reloads: state.successful_reloads,
            failed_reloads: state.failed_reloads,
        }
    }

    #[cfg(test)]
    fn snapshot(&self) -> BTreeMap<TunnelId, SocketAddr> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .targets
            .clone()
    }
}

#[derive(Debug, Clone)]
pub struct TunnelTarget {
    tunnel_id: TunnelId,
    fallback: SocketAddr,
    set: TunnelTargetSet,
}

impl TunnelTarget {
    pub fn current(&self) -> SocketAddr {
        self.set
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .targets
            .get(&self.tunnel_id)
            .copied()
            .unwrap_or(self.fallback)
    }

    pub fn set(&self) -> TunnelTargetSet {
        self.set.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelTargetApplyOutcome {
    Applied,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelTargetSetError {
    Empty,
    TooMany,
    NonLoopback,
    ZeroPort,
    ZeroGeneration,
    UnknownTunnel,
    ReloadDisabled,
    StaleGeneration { current: u64, received: u64 },
    ConflictingGeneration(u64),
    TunnelSetChanged,
}

impl std::fmt::Display for TunnelTargetSetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("managed tunnel target set must not be empty"),
            Self::TooMany => formatter.write_str("managed tunnel target set exceeds 16 entries"),
            Self::NonLoopback => formatter.write_str("managed tunnel target must use loopback"),
            Self::ZeroPort => formatter.write_str("managed tunnel target port must be non-zero"),
            Self::ZeroGeneration => {
                formatter.write_str("tunnel target generation must be non-zero")
            }
            Self::UnknownTunnel => formatter.write_str("managed tunnel target is unavailable"),
            Self::ReloadDisabled => formatter.write_str("tunnel target reload is disabled"),
            Self::StaleGeneration { current, received } => write!(
                formatter,
                "tunnel target generation {received} is stale; current is {current}"
            ),
            Self::ConflictingGeneration(generation) => write!(
                formatter,
                "tunnel target generation {generation} has conflicting content"
            ),
            Self::TunnelSetChanged => {
                formatter.write_str("tunnel target reload changed the TunnelId set")
            }
        }
    }
}

impl std::error::Error for TunnelTargetSetError {}

fn validate_targets(targets: &BTreeMap<TunnelId, SocketAddr>) -> Result<(), TunnelTargetSetError> {
    if targets.is_empty() {
        return Err(TunnelTargetSetError::Empty);
    }
    if targets.len() > MAX_MANAGED_HTTP_TUNNELS {
        return Err(TunnelTargetSetError::TooMany);
    }
    if targets.values().any(|target| !target.ip().is_loopback()) {
        return Err(TunnelTargetSetError::NonLoopback);
    }
    if targets.values().any(|target| target.port() == 0) {
        return Err(TunnelTargetSetError::ZeroPort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(a: u16, b: u16) -> BTreeMap<TunnelId, SocketAddr> {
        [
            (
                TunnelId::new("a").unwrap(),
                SocketAddr::from(([127, 0, 0, 1], a)),
            ),
            (
                TunnelId::new("b").unwrap(),
                SocketAddr::from(([127, 0, 0, 1], b)),
            ),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn generation_swap_is_atomic_and_handles_follow_it() {
        let set = TunnelTargetSet::reloadable(1, [1; 32], targets(3000, 4000)).unwrap();
        let a = set.target(&TunnelId::new("a").unwrap()).unwrap();
        let b = set.target(&TunnelId::new("b").unwrap()).unwrap();
        assert_eq!(a.current().port(), 3000);
        assert_eq!(b.current().port(), 4000);

        assert_eq!(
            set.apply(2, [2; 32], targets(3001, 4001)),
            Ok(TunnelTargetApplyOutcome::Applied)
        );
        assert_eq!(a.current().port(), 3001);
        assert_eq!(b.current().port(), 4001);
        assert_eq!(set.snapshot(), targets(3001, 4001));
        assert_eq!(set.status().successful_reloads, 1);
    }

    #[test]
    fn stale_conflicting_and_shape_changes_retain_last_good() {
        let set = TunnelTargetSet::reloadable(2, [2; 32], targets(3000, 4000)).unwrap();
        assert!(matches!(
            set.apply(1, [1; 32], targets(3001, 4001)),
            Err(TunnelTargetSetError::StaleGeneration { .. })
        ));
        assert!(matches!(
            set.apply(2, [3; 32], targets(3001, 4001)),
            Err(TunnelTargetSetError::ConflictingGeneration(2))
        ));
        let mut changed = targets(3001, 4001);
        changed.remove(&TunnelId::new("b").unwrap());
        assert_eq!(
            set.apply(3, [3; 32], changed),
            Err(TunnelTargetSetError::TunnelSetChanged)
        );
        assert_eq!(set.snapshot(), targets(3000, 4000));

        set.record_reload_failure();
        assert_eq!(set.status().health, TunnelTargetReloadHealth::ReloadFailed);
        assert_eq!(
            set.apply(2, [2; 32], targets(3000, 4000)),
            Ok(TunnelTargetApplyOutcome::Unchanged)
        );
        assert_eq!(set.status().health, TunnelTargetReloadHealth::Healthy);
    }
}
