//! `tunnelproxy-common`
//!
//! Shared strongly-typed primitives that genuinely cross every component
//! boundary: identifiers, error sentinels, time helpers, and tiny
//! serialization-free value types.
//!
//! This crate must remain small. If a type is only useful inside one other
//! crate, it does not belong here.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

mod credential_bundle;
mod tls_reload;

pub use credential_bundle::{
    publish_agent_credential_bundle, replace_secret_file, AgentCredentialPaths,
    CredentialBundleError,
};

pub use tls_reload::{
    certificate_validity, load_tls_reload_generation, ReloadableConfig, TlsCertificateValidity,
    TlsConfigHealth, TlsConfigStatus, TlsGenerationError, TlsReloadCandidate, TlsReloadFile,
    TlsReloadGeneration, TlsReloadLoadError, TlsReloadRuntime, TlsReloadRuntimeConfig,
    TlsReloadRuntimeError, MAX_TLS_MATERIAL_BYTES, MAX_TLS_RELOAD_MANIFEST_BYTES,
};

/// Operating-system event which requested process shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessShutdownSignal {
    Interrupt,
    #[cfg(unix)]
    Terminate,
}

impl std::fmt::Display for ProcessShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupt => f.write_str("interrupt"),
            #[cfg(unix)]
            Self::Terminate => f.write_str("terminate"),
        }
    }
}

/// Waits for Ctrl-C on every platform and SIGTERM on Unix.
///
/// This function only observes the OS. Entrypoints translate the returned
/// event into a [`ShutdownTrigger`] request so resource cleanup remains under
/// the owning runtime supervisor.
pub async fn wait_for_process_shutdown() -> std::io::Result<ProcessShutdownSignal> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                Ok(ProcessShutdownSignal::Interrupt)
            }
            signal = terminate.recv() => signal
                .map(|_| ProcessShutdownSignal::Terminate)
                .ok_or_else(|| std::io::Error::other("SIGTERM listener closed")),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(ProcessShutdownSignal::Interrupt)
    }
}

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

/// Maximum encoded length of an Agent or Tunnel identifier.
pub const MAX_DURABLE_ID_BYTES: usize = 64;

/// Why a durable identifier was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableIdError {
    Empty,
    TooLong { actual: usize },
    InvalidCharacter { index: usize, byte: u8 },
}

impl std::fmt::Display for DurableIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("identifier must not be empty"),
            Self::TooLong { actual } => write!(
                f,
                "identifier is {actual} bytes; maximum is {MAX_DURABLE_ID_BYTES}"
            ),
            Self::InvalidCharacter { index, byte } => write!(
                f,
                "identifier contains invalid byte 0x{byte:02x} at index {index}"
            ),
        }
    }
}

impl std::error::Error for DurableIdError {}

fn validate_durable_id(value: &str) -> Result<(), DurableIdError> {
    if value.is_empty() {
        return Err(DurableIdError::Empty);
    }
    if value.len() > MAX_DURABLE_ID_BYTES {
        return Err(DurableIdError::TooLong {
            actual: value.len(),
        });
    }
    for (index, byte) in value.bytes().enumerate() {
        if !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_' {
            return Err(DurableIdError::InvalidCharacter { index, byte });
        }
    }
    Ok(())
}

/// Stable identifier for an `agent` registered with the control plane.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentId(String);

impl AgentId {
    /// Construct an [`AgentId`] from a checked string.
    ///
    /// IDs contain 1..=64 ASCII letters, digits, `-`, or `_`.
    pub fn new(value: impl Into<String>) -> Result<Self, DurableIdError> {
        let value = value.into();
        validate_durable_id(&value)?;
        Ok(Self(value))
    }

    /// Borrow the underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stable identifier for a public tunnel exposed by an agent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TunnelId(String);

impl TunnelId {
    pub fn new(value: impl Into<String>) -> Result<Self, DurableIdError> {
        let value = value.into();
        validate_durable_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TunnelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_roundtrips_string() {
        let id = AgentId::new("agent-abc").unwrap();
        assert_eq!(id.as_str(), "agent-abc");
    }

    #[test]
    fn tunnel_id_roundtrips_string() {
        let id = TunnelId::new("blue-cat").unwrap();
        assert_eq!(id.as_str(), "blue-cat");
    }

    #[test]
    fn durable_ids_reject_empty_oversized_and_unsafe_values() {
        assert_eq!(AgentId::new(""), Err(DurableIdError::Empty));
        assert!(matches!(
            TunnelId::new("x".repeat(MAX_DURABLE_ID_BYTES + 1)),
            Err(DurableIdError::TooLong { .. })
        ));
        assert!(matches!(
            AgentId::new("agent/escape"),
            Err(DurableIdError::InvalidCharacter { .. })
        ));
        assert!(TunnelId::new("blue_cat-01").is_ok());
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

    #[test]
    fn process_signal_display_is_stable() {
        assert_eq!(ProcessShutdownSignal::Interrupt.to_string(), "interrupt");
        #[cfg(unix)]
        assert_eq!(ProcessShutdownSignal::Terminate.to_string(), "terminate");
    }
}
