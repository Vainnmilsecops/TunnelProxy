//! Process-level composition and reconnect supervision for one Agent.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use tracing::{info, warn};
use tunnelproxy_common::{RuntimeShutdownConfig, ShutdownSignal};
use tunnelproxy_protocol::TransportSessionId;

use crate::{
    connect_with_security, AgentError, AgentSessionCloseReason, AgentTransportSecurity,
    ConnectOutcome, MultiplexedAgentConfig, MultiplexedAgentConfigError,
};

/// Bounded exponential reconnect policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectConfig {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: u32,
    /// Downward jitter percentage. Limited to 50 so retries never collapse to
    /// a zero-delay loop.
    pub jitter_percent: u8,
    pub stable_session_reset_after: Duration,
    /// Maximum consecutive failures. `None` keeps retrying indefinitely while
    /// delay and resource use remain bounded.
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
            multiplier: 2,
            jitter_percent: 20,
            stable_session_reset_after: Duration::from_secs(30),
            max_attempts: None,
        }
    }
}

impl ReconnectConfig {
    pub fn validate(self) -> Result<(), ReconnectConfigError> {
        if self.initial_delay.is_zero() {
            return Err(ReconnectConfigError::ZeroInitialDelay);
        }
        if self.max_delay.is_zero() {
            return Err(ReconnectConfigError::ZeroMaxDelay);
        }
        if self.initial_delay > self.max_delay {
            return Err(ReconnectConfigError::InitialDelayExceedsMaximum);
        }
        if self.multiplier == 0 {
            return Err(ReconnectConfigError::ZeroMultiplier);
        }
        if self.jitter_percent > 50 {
            return Err(ReconnectConfigError::JitterTooLarge);
        }
        if self.stable_session_reset_after.is_zero() {
            return Err(ReconnectConfigError::ZeroStableSessionReset);
        }
        if self.max_attempts == Some(0) {
            return Err(ReconnectConfigError::ZeroMaxAttempts);
        }
        Ok(())
    }

    /// Calculates one retry delay. `sample` is clamped to 0..=1000 and makes
    /// jitter deterministic in tests; production derives it from a process
    /// seed and the consecutive failure count.
    pub fn delay_for(self, consecutive_failures: u32, sample: u16) -> Duration {
        let exponent = consecutive_failures.saturating_sub(1);
        let mut base = self.initial_delay;
        if self.multiplier > 1 {
            for _ in 0..exponent {
                base = base
                    .checked_mul(self.multiplier)
                    .unwrap_or(self.max_delay)
                    .min(self.max_delay);
                if base == self.max_delay {
                    break;
                }
            }
        }
        let lower_factor = f64::from(100 - self.jitter_percent) / 100.0;
        let lower = base.mul_f64(lower_factor);
        let span = base.saturating_sub(lower);
        lower + span.mul_f64(f64::from(sample.min(1000)) / 1000.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectConfigError {
    ZeroInitialDelay,
    ZeroMaxDelay,
    InitialDelayExceedsMaximum,
    ZeroMultiplier,
    JitterTooLarge,
    ZeroStableSessionReset,
    ZeroMaxAttempts,
}

impl std::fmt::Display for ReconnectConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroInitialDelay => "reconnect initial_delay must be greater than zero",
            Self::ZeroMaxDelay => "reconnect max_delay must be greater than zero",
            Self::InitialDelayExceedsMaximum => "reconnect initial_delay must not exceed max_delay",
            Self::ZeroMultiplier => "reconnect multiplier must be greater than zero",
            Self::JitterTooLarge => "reconnect jitter_percent must be at most 50",
            Self::ZeroStableSessionReset => "stable_session_reset_after must be greater than zero",
            Self::ZeroMaxAttempts => "max_attempts must be greater than zero when configured",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ReconnectConfigError {}

/// Complete configuration for the runnable Agent process.
#[derive(Debug, Clone)]
pub struct AgentRuntimeConfig {
    pub edge_addr: SocketAddr,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub multiplex: MultiplexedAgentConfig,
    pub security: AgentTransportSecurity,
    pub reconnect: ReconnectConfig,
    pub shutdown: RuntimeShutdownConfig,
}

impl AgentRuntimeConfig {
    pub fn new(edge_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            edge_addr,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            multiplex: MultiplexedAgentConfig::new(local_addr),
            security: AgentTransportSecurity::default(),
            reconnect: ReconnectConfig::default(),
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
        if matches!(self.security, AgentTransportSecurity::PlaintextLoopback)
            && !self.edge_addr.ip().is_loopback()
        {
            return Err(AgentRuntimeConfigError::PlaintextEdgeMustBeLoopback(
                self.edge_addr,
            ));
        }
        self.multiplex
            .validate()
            .map_err(AgentRuntimeConfigError::Multiplex)?;
        self.reconnect
            .validate()
            .map_err(AgentRuntimeConfigError::Reconnect)?;
        self.shutdown
            .validate()
            .map_err(|_| AgentRuntimeConfigError::ZeroDrainTimeout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRuntimeConfigError {
    ZeroConnectTimeout,
    ZeroHandshakeTimeout,
    PlaintextEdgeMustBeLoopback(SocketAddr),
    ZeroDrainTimeout,
    Multiplex(MultiplexedAgentConfigError),
    Reconnect(ReconnectConfigError),
}

impl std::fmt::Display for AgentRuntimeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroConnectTimeout => f.write_str("connect_timeout must be greater than zero"),
            Self::ZeroHandshakeTimeout => {
                f.write_str("handshake_timeout must be greater than zero")
            }
            Self::PlaintextEdgeMustBeLoopback(addr) => {
                write!(f, "plaintext Edge address must be loopback, got {addr}")
            }
            Self::ZeroDrainTimeout => f.write_str("drain_timeout must be greater than zero"),
            Self::Multiplex(error) => write!(f, "invalid multiplex config: {error}"),
            Self::Reconnect(error) => write!(f, "invalid reconnect config: {error}"),
        }
    }
}

impl std::error::Error for AgentRuntimeConfigError {}

/// Graceful process termination report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRuntimeOutcome {
    pub connection_attempts: u64,
    pub established_sessions: u64,
    pub successful_reconnects: u64,
    pub last_session_id: Option<TransportSessionId>,
}

impl AgentRuntimeOutcome {
    pub const fn is_graceful_shutdown(self) -> bool {
        true
    }
}

#[derive(Debug)]
pub enum AgentRuntimeError {
    InvalidConfig(AgentRuntimeConfigError),
    Terminal(AgentError),
    ReconnectExhausted {
        consecutive_failures: u32,
        last_error: AgentError,
    },
}

impl std::fmt::Display for AgentRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid Agent runtime config: {error}"),
            Self::Terminal(error) => write!(f, "terminal Agent runtime failure: {error}"),
            Self::ReconnectExhausted {
                consecutive_failures,
                last_error,
            } => write!(
                f,
                "reconnect budget exhausted after {consecutive_failures} failures: {last_error}"
            ),
        }
    }
}

impl std::error::Error for AgentRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
            Self::Terminal(error) => Some(error),
            Self::ReconnectExhausted { last_error, .. } => Some(last_error),
        }
    }
}

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

    /// Reconnects one outbound session at a time until process shutdown or a
    /// terminal protocol/configuration failure.
    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<AgentRuntimeOutcome, AgentRuntimeError> {
        let mut outcome = AgentRuntimeOutcome {
            connection_attempts: 0,
            established_sessions: 0,
            successful_reconnects: 0,
            last_session_id: None,
        };
        let mut consecutive_failures = 0_u32;
        let jitter_seed = process_jitter_seed();

        loop {
            if signal.is_shutdown() {
                return Ok(outcome);
            }
            outcome.connection_attempts = outcome.connection_attempts.saturating_add(1);
            info!(
                attempt = outcome.connection_attempts,
                edge = %self.config.edge_addr,
                event = "reconnect_attempt_started",
                "Agent connection attempt started"
            );
            let connecting = connect_with_security(
                self.config.edge_addr,
                self.config.connect_timeout,
                self.config.handshake_timeout,
                &self.config.security,
            );
            tokio::pin!(connecting);
            let session = tokio::select! {
                biased;
                () = signal.cancelled() => return Ok(outcome),
                connect_outcome = &mut connecting => match connect_outcome {
                    ConnectOutcome::Established(session) => session,
                    ConnectOutcome::Failed { reason } => {
                        if !is_retryable(&reason) {
                            return Err(AgentRuntimeError::Terminal(reason));
                        }
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if retry_exhausted(self.config.reconnect, consecutive_failures) {
                            return Err(AgentRuntimeError::ReconnectExhausted {
                                consecutive_failures,
                                last_error: reason,
                            });
                        }
                        if !wait_for_retry(
                            self.config.reconnect,
                            &signal,
                            consecutive_failures,
                            jitter_seed,
                            &reason,
                        ).await {
                            return Ok(outcome);
                        }
                        continue;
                    }
                }
            };

            let session_id = session.session_id;
            let established_at = tokio::time::Instant::now();
            outcome.established_sessions = outcome.established_sessions.saturating_add(1);
            if outcome.established_sessions > 1 {
                outcome.successful_reconnects = outcome.successful_reconnects.saturating_add(1);
            }
            outcome.last_session_id = Some(session_id);
            info!(
                %session_id,
                reconnects = outcome.successful_reconnects,
                event = "agent_session_reestablished",
                "Agent session established"
            );

            let session_result = session
                .run_multiplexed_until_shutdown(
                    self.config.multiplex.clone(),
                    signal.clone(),
                    self.config.shutdown,
                )
                .await;
            match session_result {
                Ok(AgentSessionCloseReason::LocalShutdown) => return Ok(outcome),
                Ok(AgentSessionCloseReason::PeerClosed) => {
                    if established_at.elapsed() >= self.config.reconnect.stable_session_reset_after
                    {
                        consecutive_failures = 0;
                    }
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let reason = AgentError::ConnectionClosed;
                    if retry_exhausted(self.config.reconnect, consecutive_failures) {
                        return Err(AgentRuntimeError::ReconnectExhausted {
                            consecutive_failures,
                            last_error: reason,
                        });
                    }
                    if !wait_for_retry(
                        self.config.reconnect,
                        &signal,
                        consecutive_failures,
                        jitter_seed,
                        &reason,
                    )
                    .await
                    {
                        return Ok(outcome);
                    }
                }
                Err(error) if is_retryable(&error) => {
                    if established_at.elapsed() >= self.config.reconnect.stable_session_reset_after
                    {
                        consecutive_failures = 0;
                    }
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if retry_exhausted(self.config.reconnect, consecutive_failures) {
                        return Err(AgentRuntimeError::ReconnectExhausted {
                            consecutive_failures,
                            last_error: error,
                        });
                    }
                    if !wait_for_retry(
                        self.config.reconnect,
                        &signal,
                        consecutive_failures,
                        jitter_seed,
                        &error,
                    )
                    .await
                    {
                        return Ok(outcome);
                    }
                }
                Err(error) => return Err(AgentRuntimeError::Terminal(error)),
            }
        }
    }
}

fn is_retryable(error: &AgentError) -> bool {
    matches!(
        error,
        AgentError::Connect(_)
            | AgentError::ConnectTimeout
            | AgentError::TlsHandshakeTimeout
            | AgentError::TlsTransport(_)
            | AgentError::HandshakeTimeout
            | AgentError::SessionIo(_)
            | AgentError::ConnectionClosed
    )
}

fn retry_exhausted(config: ReconnectConfig, consecutive_failures: u32) -> bool {
    config
        .max_attempts
        .is_some_and(|maximum| consecutive_failures >= maximum)
}

async fn wait_for_retry(
    config: ReconnectConfig,
    signal: &ShutdownSignal,
    consecutive_failures: u32,
    seed: u64,
    error: &AgentError,
) -> bool {
    let delay = config.delay_for(
        consecutive_failures,
        jitter_sample(seed, consecutive_failures),
    );
    warn!(
        consecutive_failures,
        delay_ms = delay.as_millis() as u64,
        error = %error,
        event = "reconnect_scheduled",
        "Agent reconnect scheduled"
    );
    tokio::select! {
        biased;
        () = signal.cancelled() => false,
        () = tokio::time::sleep(delay) => true,
    }
}

fn process_jitter_seed() -> u64 {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    time ^ u64::from(std::process::id())
}

fn jitter_sample(seed: u64, attempt: u32) -> u16 {
    let mut value = seed ^ u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    (value.wrapping_mul(0x2545_F491_4F6C_DD1D) % 1001) as u16
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
    fn plaintext_remote_edge_is_rejected() {
        let config = AgentRuntimeConfig::new(
            "192.0.2.1:7100".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        );
        assert!(matches!(
            config.validate(),
            Err(AgentRuntimeConfigError::PlaintextEdgeMustBeLoopback(_))
        ));
    }

    #[test]
    fn backoff_caps_and_jitter_stays_bounded() {
        let config = ReconnectConfig {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            multiplier: 2,
            jitter_percent: 20,
            ..ReconnectConfig::default()
        };
        assert_eq!(config.delay_for(1, 1000), Duration::from_millis(100));
        assert_eq!(config.delay_for(2, 1000), Duration::from_millis(200));
        assert_eq!(config.delay_for(20, 1000), Duration::from_millis(500));
        assert_eq!(config.delay_for(20, 0), Duration::from_millis(400));

        let constant = ReconnectConfig {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            multiplier: 1,
            jitter_percent: 0,
            ..ReconnectConfig::default()
        };
        assert_eq!(
            constant.delay_for(u32::MAX, 1000),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn invalid_reconnect_bounds_are_rejected() {
        let config = ReconnectConfig {
            initial_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(1),
            ..ReconnectConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(ReconnectConfigError::InitialDelayExceedsMaximum)
        );
        let config = ReconnectConfig {
            multiplier: 0,
            ..ReconnectConfig::default()
        };
        assert_eq!(config.validate(), Err(ReconnectConfigError::ZeroMultiplier));
        let config = ReconnectConfig {
            jitter_percent: 51,
            ..ReconnectConfig::default()
        };
        assert_eq!(config.validate(), Err(ReconnectConfigError::JitterTooLarge));
        let config = ReconnectConfig {
            max_attempts: Some(0),
            ..ReconnectConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(ReconnectConfigError::ZeroMaxAttempts)
        );
    }

    #[test]
    fn retry_classification_is_conservative() {
        assert!(is_retryable(&AgentError::ConnectTimeout));
        assert!(is_retryable(&AgentError::ConnectionClosed));
        assert!(!is_retryable(&AgentError::ProtocolViolation {
            reason: "test"
        }));
    }
}
