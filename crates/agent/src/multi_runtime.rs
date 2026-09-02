//! Bounded supervision for multiple independent Agent tunnel transports.

use std::collections::HashSet;

use tokio::task::JoinSet;
use tunnelproxy_common::{shutdown_channel, ShutdownSignal, TunnelId};

use crate::{
    AgentRuntime, AgentRuntimeConfig, AgentRuntimeControl, AgentRuntimeError, AgentRuntimeOutcome,
    AgentRuntimeStatusHandle,
};

/// Hard process-local bound for managed HTTP tunnels in one Agent process.
pub const MAX_MANAGED_HTTP_TUNNELS: usize = 16;

/// Summary returned after every child transport has drained.
#[derive(Debug)]
pub struct MultiAgentRuntimeOutcome {
    pub tunnels: Vec<(TunnelId, AgentRuntimeOutcome)>,
}

impl MultiAgentRuntimeOutcome {
    pub const fn is_graceful_shutdown(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub enum MultiAgentRuntimeError {
    Empty,
    TooMany {
        count: usize,
    },
    DuplicateTunnel(TunnelId),
    InvalidChild(AgentRuntimeError),
    ChildFailed {
        tunnel_id: TunnelId,
        source: AgentRuntimeError,
    },
    ChildStopped(TunnelId),
    ChildTaskFailed,
}

impl std::fmt::Display for MultiAgentRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("multi-tunnel runtime requires at least one tunnel"),
            Self::TooMany { count } => write!(
                formatter,
                "multi-tunnel runtime has {count} tunnels; maximum is {MAX_MANAGED_HTTP_TUNNELS}"
            ),
            Self::DuplicateTunnel(tunnel_id) => {
                write!(formatter, "duplicate managed TunnelId {tunnel_id}")
            }
            Self::InvalidChild(error) => write!(formatter, "invalid child Agent runtime: {error}"),
            Self::ChildFailed { tunnel_id, source } => {
                write!(formatter, "Agent tunnel {tunnel_id} failed: {source}")
            }
            Self::ChildStopped(tunnel_id) => {
                write!(
                    formatter,
                    "Agent tunnel {tunnel_id} stopped before shutdown"
                )
            }
            Self::ChildTaskFailed => formatter.write_str("Agent tunnel task failed"),
        }
    }
}

impl std::error::Error for MultiAgentRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidChild(error) | Self::ChildFailed { source: error, .. } => Some(error),
            _ => None,
        }
    }
}

struct ManagedAgentRuntime {
    tunnel_id: TunnelId,
    runtime: AgentRuntime,
}

/// One fail-closed supervisor over a bounded set of independent transports.
pub struct MultiAgentRuntime {
    children: Vec<ManagedAgentRuntime>,
}

impl MultiAgentRuntime {
    pub fn new(configs: Vec<AgentRuntimeConfig>) -> Result<Self, MultiAgentRuntimeError> {
        if configs.is_empty() {
            return Err(MultiAgentRuntimeError::Empty);
        }
        if configs.len() > MAX_MANAGED_HTTP_TUNNELS {
            return Err(MultiAgentRuntimeError::TooMany {
                count: configs.len(),
            });
        }
        let mut seen = HashSet::with_capacity(configs.len());
        let mut children = Vec::with_capacity(configs.len());
        for config in configs {
            let tunnel_id = config.registration.tunnel_id.clone();
            if !seen.insert(tunnel_id.clone()) {
                return Err(MultiAgentRuntimeError::DuplicateTunnel(tunnel_id));
            }
            let runtime =
                AgentRuntime::new(config).map_err(MultiAgentRuntimeError::InvalidChild)?;
            children.push(ManagedAgentRuntime { tunnel_id, runtime });
        }
        Ok(Self { children })
    }

    pub fn status_handles(&self) -> Vec<AgentRuntimeStatusHandle> {
        self.children
            .iter()
            .map(|child| child.runtime.status_handle())
            .collect()
    }

    pub fn control(&self) -> MultiAgentRuntimeControl {
        MultiAgentRuntimeControl {
            controls: self
                .children
                .iter()
                .map(|child| child.runtime.control())
                .collect(),
        }
    }

    pub async fn run_until_shutdown(
        self,
        external_signal: ShutdownSignal,
    ) -> Result<MultiAgentRuntimeOutcome, MultiAgentRuntimeError> {
        let (trigger, child_signal) = shutdown_channel();
        let mut tasks = JoinSet::new();
        for child in self.children {
            let signal = child_signal.clone();
            tasks.spawn(async move {
                let result = child.runtime.run_until_shutdown(signal).await;
                (child.tunnel_id, result)
            });
        }

        let mut outcomes = Vec::with_capacity(tasks.len());
        let terminal = tokio::select! {
            biased;
            () = external_signal.cancelled() => None,
            joined = tasks.join_next() => match joined {
                Some(Ok((tunnel_id, Ok(outcome)))) => {
                    outcomes.push((tunnel_id.clone(), outcome));
                    Some(MultiAgentRuntimeError::ChildStopped(tunnel_id))
                }
                Some(Ok((tunnel_id, Err(source)))) => {
                    Some(MultiAgentRuntimeError::ChildFailed { tunnel_id, source })
                }
                Some(Err(_)) | None => Some(MultiAgentRuntimeError::ChildTaskFailed),
            },
        };
        trigger.shutdown();

        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((tunnel_id, Ok(outcome))) => outcomes.push((tunnel_id, outcome)),
                Ok((_, Err(_))) | Err(_) => {}
            }
        }

        match terminal {
            Some(error) => Err(error),
            None => Ok(MultiAgentRuntimeOutcome { tunnels: outcomes }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MultiAgentRuntimeControl {
    controls: Vec<AgentRuntimeControl>,
}

impl MultiAgentRuntimeControl {
    pub fn begin_draining(&self) {
        for control in &self.controls {
            control.begin_draining();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelproxy_common::{AgentId, RuntimeShutdownConfig};
    use tunnelproxy_protocol::RegistrationRequest;

    fn config(tunnel: &str, local_port: u16) -> AgentRuntimeConfig {
        let mut config = AgentRuntimeConfig::new(
            "127.0.0.1:9".parse().unwrap(),
            ([127, 0, 0, 1], local_port).into(),
        );
        config.registration = RegistrationRequest::new(
            AgentId::new("agent-multi").unwrap(),
            TunnelId::new(tunnel).unwrap(),
        );
        config.shutdown = RuntimeShutdownConfig::new(std::time::Duration::from_millis(10));
        config
    }

    #[test]
    fn rejects_empty_duplicate_and_over_limit_sets() {
        assert!(matches!(
            MultiAgentRuntime::new(Vec::new()),
            Err(MultiAgentRuntimeError::Empty)
        ));
        assert!(matches!(
            MultiAgentRuntime::new(vec![config("tunnel-a", 3000), config("tunnel-a", 3001)]),
            Err(MultiAgentRuntimeError::DuplicateTunnel(_))
        ));
        let configs = (0..=MAX_MANAGED_HTTP_TUNNELS)
            .map(|index| config(&format!("tunnel-{index}"), 3000))
            .collect();
        assert!(matches!(
            MultiAgentRuntime::new(configs),
            Err(MultiAgentRuntimeError::TooMany { .. })
        ));
    }

    #[tokio::test]
    async fn shutdown_drains_every_child() {
        let runtime =
            MultiAgentRuntime::new(vec![config("tunnel-a", 3000), config("tunnel-b", 3001)])
                .unwrap();
        let statuses = runtime.status_handles();
        let (trigger, signal) = shutdown_channel();
        trigger.shutdown();
        let outcome = runtime.run_until_shutdown(signal).await.unwrap();
        assert_eq!(outcome.tunnels.len(), 2);
        assert!(statuses.iter().all(|status| matches!(
            status.snapshot().state,
            crate::AgentConnectionState::Stopped
        )));
    }
}
