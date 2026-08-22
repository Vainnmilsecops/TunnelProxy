//! `tunnelproxy-common`
//!
//! Shared strongly-typed primitives that genuinely cross every component
//! boundary: identifiers, error sentinels, time helpers, and tiny
//! serialization-free value types.
//!
//! This crate must remain small. If a type is only useful inside one other
//! crate, it does not belong here.

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// Sends one process-local, idempotent graceful-shutdown request.
#[derive(Debug, Clone)]
pub struct ShutdownTrigger {
    sender: Arc<watch::Sender<bool>>,
}

impl ShutdownTrigger {
    /// Requests shutdown. Repeated calls are harmless.
    pub fn shutdown(&self) {
        self.sender.send_replace(true);
    }
}

/// Cloneable cancellation signal retained by runtime and child tasks.
///
/// The shared sender is deliberately retained inside the signal, so dropping
/// the external trigger cannot be mistaken for a shutdown request.
#[derive(Debug, Clone)]
pub struct ShutdownSignal {
    sender: Arc<watch::Sender<bool>>,
}

impl ShutdownSignal {
    /// Returns whether shutdown has already been requested.
    pub fn is_shutdown(&self) -> bool {
        *self.sender.borrow()
    }

    /// Waits for shutdown without losing a request made before this call.
    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        if *receiver.borrow() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow() {
                return;
            }
        }
    }
}

/// Creates the trigger/signal pair used by supervised runtimes.
pub fn shutdown_channel() -> (ShutdownTrigger, ShutdownSignal) {
    let (sender, _) = watch::channel(false);
    let sender = Arc::new(sender);
    (
        ShutdownTrigger {
            sender: Arc::clone(&sender),
        },
        ShutdownSignal { sender },
    )
}

/// Shared drain deadline for graceful runtime shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeShutdownConfig {
    pub drain_timeout: Duration,
}

impl RuntimeShutdownConfig {
    pub const fn new(drain_timeout: Duration) -> Self {
        Self { drain_timeout }
    }

    pub fn validate(self) -> Result<(), RuntimeShutdownConfigError> {
        if self.drain_timeout.is_zero() {
            return Err(RuntimeShutdownConfigError::ZeroDrainTimeout);
        }
        Ok(())
    }
}

impl Default for RuntimeShutdownConfig {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

/// Invalid shutdown configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeShutdownConfigError {
    ZeroDrainTimeout,
}

impl std::fmt::Display for RuntimeShutdownConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("drain_timeout must be greater than zero")
    }
}

impl std::error::Error for RuntimeShutdownConfigError {}

/// Summary returned after a supervised runtime joins all child tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeShutdownOutcome {
    Drained {
        completed_tasks: usize,
    },
    Forced {
        completed_tasks: usize,
        aborted_tasks: usize,
    },
}

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

    #[tokio::test]
    async fn shutdown_is_idempotent_and_not_lost() {
        let (trigger, signal) = shutdown_channel();
        trigger.shutdown();
        trigger.shutdown();
        signal.cancelled().await;
        assert!(signal.is_shutdown());
    }

    #[tokio::test]
    async fn dropping_trigger_is_not_shutdown() {
        let (trigger, signal) = shutdown_channel();
        drop(trigger);
        assert!(!signal.is_shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), signal.cancelled())
                .await
                .is_err()
        );
    }

    #[test]
    fn zero_drain_timeout_is_rejected() {
        assert_eq!(
            RuntimeShutdownConfig::new(Duration::ZERO).validate(),
            Err(RuntimeShutdownConfigError::ZeroDrainTimeout)
        );
    }
}
