//! Process-level composition for one outbound multiplexed Agent session.

use std::net::SocketAddr;
use std::time::Duration;

use tunnelproxy_common::{RuntimeShutdownConfig, ShutdownSignal};
use tunnelproxy_protocol::TransportSessionId;

use crate::{
    connect, AgentError, AgentSessionCloseReason, ConnectOutcome, MultiplexedAgentConfig,
    MultiplexedAgentConfigError,
};

/// Complete configuration for the runnable Agent process.
#[derive(Debug, Clone)]
pub struct AgentRuntimeConfig {
    pub edge_addr: SocketAddr,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub multiplex: MultiplexedAgentConfig,
    pub shutdown: RuntimeShutdownConfig,
}

impl AgentRuntimeConfig {
    pub fn new(edge_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            edge_addr,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            multiplex: MultiplexedAgentConfig::new(local_addr),
            shutdown: RuntimeShutdownConfig::default(),
        }
    }

    pub fn validate(&self) -> Result<(), AgentRuntimeConfigError> {
        if self.connect_timeout.is_zero() {
            return Err(AgentRuntimeConfigError::ZeroConnectTimeout);
        }
        if self.handshake_timeout.is_zero() {
            return Err(AgentRuntimeConfigError::ZeroHandshakeTimeout);
        }
        self.multiplex
            .validate()
            .map_err(AgentRuntimeConfigError::Multiplex)?;
        self.shutdown
            .validate()
            .map_err(|_| AgentRuntimeConfigError::ZeroDrainTimeout)
    }
}

/// Invalid process-level Agent configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRuntimeConfigError {
    ZeroConnectTimeout,
    ZeroHandshakeTimeout,
    ZeroDrainTimeout,
    Multiplex(MultiplexedAgentConfigError),
}

impl std::fmt::Display for AgentRuntimeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroConnectTimeout => f.write_str("connect_timeout must be greater than zero"),
            Self::ZeroHandshakeTimeout => {
                f.write_str("handshake_timeout must be greater than zero")
            }
            Self::ZeroDrainTimeout => f.write_str("drain_timeout must be greater than zero"),
            Self::Multiplex(error) => write!(f, "invalid multiplex config: {error}"),
        }
    }
}

impl std::error::Error for AgentRuntimeConfigError {}

/// Normal termination of the Agent process runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRuntimeOutcome {
    ShutdownBeforeConnect,
    SessionClosed {
        session_id: TransportSessionId,
        reason: AgentSessionCloseReason,
    },
}

impl AgentRuntimeOutcome {
    /// True only when local process shutdown caused termination.
    pub const fn is_graceful_shutdown(self) -> bool {
        matches!(
            self,
            Self::ShutdownBeforeConnect
                | Self::SessionClosed {
                    reason: AgentSessionCloseReason::LocalShutdown,
                    ..
                }
        )
    }
}

/// Failure to start or drive the Agent process runtime.
#[derive(Debug)]
pub enum AgentRuntimeError {
    InvalidConfig(AgentRuntimeConfigError),
    Connect(AgentError),
    Session(AgentError),
}

impl std::fmt::Display for AgentRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid Agent runtime config: {error}"),
            Self::Connect(error) => write!(f, "Agent connection failed: {error}"),
            Self::Session(error) => write!(f, "Agent session failed: {error}"),
        }
    }
}

impl std::error::Error for AgentRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
            Self::Connect(error) | Self::Session(error) => Some(error),
        }
    }
}

/// Validated, single-session Agent process supervisor.
pub struct AgentRuntime {
    config: AgentRuntimeConfig,
}

impl AgentRuntime {
    pub fn new(config: AgentRuntimeConfig) -> Result<Self, AgentRuntimeError> {
        config
            .validate()
            .map_err(AgentRuntimeError::InvalidConfig)?;
        Ok(Self { config })
    }

    pub const fn config(&self) -> &AgentRuntimeConfig {
        &self.config
    }

    /// Connects outbound, performs the handshake, then drives multiplexed
    /// streams until local shutdown or peer termination. No reconnect occurs.
    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<AgentRuntimeOutcome, AgentRuntimeError> {
        let connecting = connect(
            self.config.edge_addr,
            self.config.connect_timeout,
            self.config.handshake_timeout,
        );
        tokio::pin!(connecting);
        let session = tokio::select! {
            biased;
            () = signal.cancelled() => return Ok(AgentRuntimeOutcome::ShutdownBeforeConnect),
            outcome = &mut connecting => match outcome {
                ConnectOutcome::Established(session) => session,
                ConnectOutcome::Failed { reason } => return Err(AgentRuntimeError::Connect(reason)),
            }
        };
        let session_id = session.session_id;
        let reason = session
            .run_multiplexed_until_shutdown(self.config.multiplex, signal, self.config.shutdown)
            .await
            .map_err(AgentRuntimeError::Session)?;
        Ok(AgentRuntimeOutcome::SessionClosed { session_id, reason })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let config = AgentRuntimeConfig::new(
            "127.0.0.1:7100".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_process_deadlines_are_rejected() {
        let mut config = AgentRuntimeConfig::new(
            "127.0.0.1:7100".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        );
        config.handshake_timeout = Duration::ZERO;
        assert_eq!(
            config.validate(),
            Err(AgentRuntimeConfigError::ZeroHandshakeTimeout)
        );
    }

    #[test]
    fn outcome_distinguishes_peer_close_from_local_shutdown() {
        assert!(AgentRuntimeOutcome::ShutdownBeforeConnect.is_graceful_shutdown());
        assert!(!AgentRuntimeOutcome::SessionClosed {
            session_id: TransportSessionId::new(1).unwrap(),
            reason: AgentSessionCloseReason::PeerClosed,
        }
        .is_graceful_shutdown());
    }
}
