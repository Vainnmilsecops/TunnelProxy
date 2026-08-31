use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::MissedTickBehavior;
use tracing::{info, warn};
use x509_parser::parse_x509_certificate;

use crate::generation_reload::{
    load_generation_reload, GenerationReload, GenerationReloadError, GenerationReloadFile,
    MAX_RELOAD_MANIFEST_BYTES, MAX_RELOAD_MATERIAL_BYTES,
};
use crate::ShutdownSignal;

pub const MAX_TLS_RELOAD_MANIFEST_BYTES: usize = MAX_RELOAD_MANIFEST_BYTES;
pub const MAX_TLS_MATERIAL_BYTES: usize = MAX_RELOAD_MATERIAL_BYTES;
pub type TlsReloadFile = GenerationReloadFile;
pub type TlsReloadGeneration = GenerationReload;
pub type TlsReloadLoadError = GenerationReloadError;

pub async fn load_tls_reload_generation(
    manifest_path: PathBuf,
    files: Vec<TlsReloadFile>,
) -> Result<TlsReloadGeneration, TlsReloadLoadError> {
    load_generation_reload(manifest_path, files).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsCertificateValidity {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

pub fn certificate_validity(
    certificate_der: &[u8],
) -> Result<TlsCertificateValidity, TlsGenerationError> {
    let (_, certificate) =
        parse_x509_certificate(certificate_der).map_err(|_| TlsGenerationError::CertificateTime)?;
    Ok(TlsCertificateValidity {
        not_before: timestamp_to_system_time(certificate.validity().not_before.timestamp())?,
        not_after: timestamp_to_system_time(certificate.validity().not_after.timestamp())?,
    })
}

fn timestamp_to_system_time(timestamp: i64) -> Result<SystemTime, TlsGenerationError> {
    if timestamp >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(timestamp as u64))
            .ok_or(TlsGenerationError::CertificateTime)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(timestamp.unsigned_abs()))
            .ok_or(TlsGenerationError::CertificateTime)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsConfigHealth {
    Current,
    Expiring,
    ReloadFailed,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsConfigStatus {
    pub generation: u64,
    pub health: TlsConfigHealth,
    pub not_after: SystemTime,
}

struct ReloadState<T> {
    generation: u64,
    manifest_digest: [u8; 32],
    config: Arc<T>,
    validity: TlsCertificateValidity,
    reload_failed: bool,
}

pub struct ReloadableConfig<T> {
    state: Arc<RwLock<ReloadState<T>>>,
}

impl<T> Clone for ReloadableConfig<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<T> ReloadableConfig<T> {
    pub fn new(
        generation: u64,
        manifest_digest: [u8; 32],
        config: T,
        validity: TlsCertificateValidity,
    ) -> Result<Self, TlsGenerationError> {
        validate_candidate_time(validity, SystemTime::now())?;
        if generation == 0 {
            return Err(TlsGenerationError::ZeroGeneration);
        }
        Ok(Self {
            state: Arc::new(RwLock::new(ReloadState {
                generation,
                manifest_digest,
                config: Arc::new(config),
                validity,
                reload_failed: false,
            })),
        })
    }

    pub fn current(&self) -> Arc<T> {
        Arc::clone(
            &self
                .state
                .read()
                .unwrap_or_else(|error| error.into_inner())
                .config,
        )
    }

    pub fn generation(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .generation
    }

    pub fn publish(
        &self,
        generation: u64,
        manifest_digest: [u8; 32],
        config: T,
        validity: TlsCertificateValidity,
    ) -> Result<bool, TlsGenerationError> {
        validate_candidate_time(validity, SystemTime::now())?;
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if generation < state.generation {
            return Err(TlsGenerationError::StaleGeneration {
                current: state.generation,
                received: generation,
            });
        }
        if generation == state.generation {
            if manifest_digest == state.manifest_digest {
                state.reload_failed = false;
                return Ok(false);
            }
            return Err(TlsGenerationError::ConflictingGeneration(generation));
        }
        state.generation = generation;
        state.manifest_digest = manifest_digest;
        state.config = Arc::new(config);
        state.validity = validity;
        state.reload_failed = false;
        Ok(true)
    }

    pub fn mark_reload_failed(&self) {
        self.state
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .reload_failed = true;
    }

    pub fn status(&self, now: SystemTime, expiry_warning: Duration) -> TlsConfigStatus {
        let state = self.state.read().unwrap_or_else(|error| error.into_inner());
        let health = if now >= state.validity.not_after {
            TlsConfigHealth::Expired
        } else if state.reload_failed {
            TlsConfigHealth::ReloadFailed
        } else if state
            .validity
            .not_after
            .duration_since(now)
            .map(|remaining| remaining <= expiry_warning)
            .unwrap_or(false)
        {
            TlsConfigHealth::Expiring
        } else {
            TlsConfigHealth::Current
        };
        TlsConfigStatus {
            generation: state.generation,
            health,
            not_after: state.validity.not_after,
        }
    }
}

fn validate_candidate_time(
    validity: TlsCertificateValidity,
    now: SystemTime,
) -> Result<(), TlsGenerationError> {
    if validity.not_before > now {
        return Err(TlsGenerationError::NotYetValid);
    }
    if validity.not_after <= now {
        return Err(TlsGenerationError::Expired);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsGenerationError {
    ZeroGeneration,
    StaleGeneration { current: u64, received: u64 },
    ConflictingGeneration(u64),
    CertificateTime,
    NotYetValid,
    Expired,
}

impl std::fmt::Display for TlsGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroGeneration => f.write_str("TLS generation must be non-zero"),
            Self::StaleGeneration { current, received } => {
                write!(
                    f,
                    "TLS generation {received} is stale; current is {current}"
                )
            }
            Self::ConflictingGeneration(generation) => {
                write!(f, "TLS generation {generation} has conflicting content")
            }
            Self::CertificateTime => f.write_str("TLS certificate validity could not be decoded"),
            Self::NotYetValid => f.write_str("TLS identity certificate is not yet valid"),
            Self::Expired => f.write_str("TLS identity certificate has expired"),
        }
    }
}

impl std::error::Error for TlsGenerationError {}

pub struct TlsReloadCandidate<T> {
    pub config: T,
    pub validity: TlsCertificateValidity,
}

#[derive(Debug, Clone)]
pub struct TlsReloadRuntimeConfig {
    pub manifest_path: PathBuf,
    pub files: Vec<TlsReloadFile>,
    pub poll_interval: Duration,
    pub expiry_warning: Duration,
}

impl TlsReloadRuntimeConfig {
    pub fn validate(&self) -> Result<(), TlsReloadRuntimeError> {
        if self.manifest_path.as_os_str().is_empty()
            || self.files.is_empty()
            || self.poll_interval.is_zero()
            || self.expiry_warning.is_zero()
        {
            return Err(TlsReloadRuntimeError::InvalidConfig);
        }
        Ok(())
    }
}

pub struct TlsReloadRuntime<T, F> {
    config: TlsReloadRuntimeConfig,
    target: ReloadableConfig<T>,
    build: F,
}

impl<T, F> TlsReloadRuntime<T, F>
where
    T: Send + Sync + 'static,
    F: Fn(&TlsReloadGeneration) -> Result<TlsReloadCandidate<T>, ()> + Send + Sync + 'static,
{
    pub fn new(
        config: TlsReloadRuntimeConfig,
        target: ReloadableConfig<T>,
        build: F,
    ) -> Result<Self, TlsReloadRuntimeError> {
        config.validate()?;
        Ok(Self {
            config,
            target,
            build,
        })
    }

    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
    ) -> Result<(), TlsReloadRuntimeError> {
        let initial = self
            .target
            .status(SystemTime::now(), self.config.expiry_warning);
        match initial.health {
            TlsConfigHealth::Current => info!(
                event = "tls_reload_started",
                generation = initial.generation,
                health = ?initial.health
            ),
            TlsConfigHealth::Expiring
            | TlsConfigHealth::ReloadFailed
            | TlsConfigHealth::Expired => warn!(
                event = "tls_reload_started",
                generation = initial.generation,
                health = ?initial.health
            ),
        }
        let mut last_health = initial.health;
        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => return Ok(()),
                _ = interval.tick() => {}
            }
            let loaded = load_tls_reload_generation(
                self.config.manifest_path.clone(),
                self.config.files.clone(),
            )
            .await;
            match loaded {
                Ok(generation) => match (self.build)(&generation) {
                    Ok(candidate) => {
                        match self.target.publish(
                            generation.generation(),
                            generation.manifest_digest(),
                            candidate.config,
                            candidate.validity,
                        ) {
                            Ok(true) => info!(
                                event = "tls_reload_applied",
                                generation = generation.generation()
                            ),
                            Ok(false) => {}
                            Err(_) => self.target.mark_reload_failed(),
                        }
                    }
                    Err(()) => self.target.mark_reload_failed(),
                },
                Err(_) => self.target.mark_reload_failed(),
            }
            let status = self
                .target
                .status(SystemTime::now(), self.config.expiry_warning);
            if status.health != last_health {
                match status.health {
                    TlsConfigHealth::Current => info!(
                        event = "tls_reload_health",
                        generation = status.generation,
                        health = ?status.health
                    ),
                    TlsConfigHealth::Expiring
                    | TlsConfigHealth::ReloadFailed
                    | TlsConfigHealth::Expired => warn!(
                        event = "tls_reload_health",
                        generation = status.generation,
                        health = ?status.health
                    ),
                }
                last_health = status.health;
            }
            if status.health == TlsConfigHealth::Expired {
                return Err(TlsReloadRuntimeError::ActiveCredentialsExpired {
                    generation: status.generation,
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsReloadRuntimeError {
    InvalidConfig,
    ActiveCredentialsExpired { generation: u64 },
}

impl std::fmt::Display for TlsReloadRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("TLS reload runtime configuration is invalid"),
            Self::ActiveCredentialsExpired { generation } => {
                write!(f, "active TLS generation {generation} has expired")
            }
        }
    }
}

impl std::error::Error for TlsReloadRuntimeError {}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "tunnelproxy-tls-reload-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        directory
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[tokio::test]
    async fn manifest_load_is_bounded_strict_and_digest_checked() {
        let directory = temp_directory();
        let material = directory.join("identity.pem");
        let manifest = directory.join("reload.json");
        std::fs::write(&material, b"credential-bytes").unwrap();
        let digest = Sha256::digest(b"credential-bytes");
        std::fs::write(
            &manifest,
            format!(
                r#"{{"generation":2,"files":{{"identity":"{}"}}}}"#,
                hex(&digest)
            ),
        )
        .unwrap();
        let generation = load_tls_reload_generation(
            manifest.clone(),
            vec![TlsReloadFile::new("identity", material.clone())],
        )
        .await
        .unwrap();
        assert_eq!(generation.generation(), 2);
        assert_eq!(generation.file("identity").unwrap(), b"credential-bytes");

        std::fs::write(&material, b"changed-before-manifest").unwrap();
        assert!(matches!(
            load_tls_reload_generation(
                manifest.clone(),
                vec![TlsReloadFile::new("identity", material.clone())],
            )
            .await,
            Err(TlsReloadLoadError::DigestMismatch(_))
        ));

        std::fs::write(&material, b"credential-bytes").unwrap();
        std::fs::write(
            &manifest,
            format!(
                r#"{{"generation":3,"files":{{"identity":"{}","unexpected":"{}"}}}}"#,
                hex(&digest),
                hex(&digest)
            ),
        )
        .unwrap();
        assert!(matches!(
            load_tls_reload_generation(
                manifest.clone(),
                vec![TlsReloadFile::new("identity", material.clone())]
            )
            .await,
            Err(TlsReloadLoadError::FileSet)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reloadable_generation_is_monotonic_and_last_good_is_retained() {
        let now = SystemTime::now();
        let validity = TlsCertificateValidity {
            not_before: now - Duration::from_secs(1),
            not_after: now + Duration::from_secs(60),
        };
        let target = ReloadableConfig::new(2, [2; 32], "two", validity).unwrap();
        assert!(matches!(
            target.publish(1, [1; 32], "one", validity),
            Err(TlsGenerationError::StaleGeneration { .. })
        ));
        assert_eq!(*target.current(), "two");
        assert!(matches!(
            target.publish(2, [3; 32], "conflict", validity),
            Err(TlsGenerationError::ConflictingGeneration(2))
        ));
        assert_eq!(*target.current(), "two");
        assert!(target.publish(3, [3; 32], "three", validity).unwrap());
        assert_eq!(*target.current(), "three");
    }

    #[test]
    fn status_reports_failure_warning_and_expiry_without_secrets() {
        let now = SystemTime::now();
        let target = ReloadableConfig::new(
            1,
            [0; 32],
            "secret configuration",
            TlsCertificateValidity {
                not_before: now - Duration::from_secs(1),
                not_after: now + Duration::from_secs(10),
            },
        )
        .unwrap();
        assert_eq!(
            target.status(now, Duration::from_secs(20)).health,
            TlsConfigHealth::Expiring
        );
        target.mark_reload_failed();
        assert_eq!(
            target.status(now, Duration::from_secs(1)).health,
            TlsConfigHealth::ReloadFailed
        );
        assert_eq!(
            target
                .status(now + Duration::from_secs(11), Duration::from_secs(1))
                .health,
            TlsConfigHealth::Expired
        );
    }

    #[tokio::test]
    async fn runtime_stops_when_last_known_good_credentials_expire() {
        let now = SystemTime::now();
        let target = ReloadableConfig::new(
            7,
            [7; 32],
            "last-good",
            TlsCertificateValidity {
                not_before: now - Duration::from_secs(1),
                not_after: now + Duration::from_millis(80),
            },
        )
        .unwrap();
        let runtime = TlsReloadRuntime::new(
            TlsReloadRuntimeConfig {
                manifest_path: PathBuf::from("missing-tls-reload-manifest.json"),
                files: vec![TlsReloadFile::new("identity", "missing-identity.pem")],
                poll_interval: Duration::from_millis(10),
                expiry_warning: Duration::from_millis(20),
            },
            target,
            |_| -> Result<TlsReloadCandidate<&'static str>, ()> { unreachable!() },
        )
        .unwrap();
        let (_trigger, signal) = crate::shutdown_channel();
        let result =
            tokio::time::timeout(Duration::from_secs(1), runtime.run_until_shutdown(signal))
                .await
                .expect("reload runtime did not enforce certificate expiry");
        assert_eq!(
            result,
            Err(TlsReloadRuntimeError::ActiveCredentialsExpired { generation: 7 })
        );
    }
}
