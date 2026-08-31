use std::path::PathBuf;
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use crate::generation_reload::{
    load_generation_reload, GenerationReloadError, GenerationReloadFile,
};
use crate::signed_access::{
    load_signed_access_key_ring, SignedAccessError, SignedAccessKeyRing,
    SignedAccessKeyRingActivation,
};
use crate::ShutdownSignal;

const KEY_RING_MATERIAL_NAME: &str = "keyring";

#[derive(Debug, Clone)]
pub struct SignedAccessKeyRingReloadConfig {
    pub manifest_path: PathBuf,
    pub key_ring_path: PathBuf,
    pub poll_interval: Duration,
}

#[derive(Debug)]
pub struct SignedAccessKeyRingReloadRuntime {
    config: SignedAccessKeyRingReloadConfig,
    key_ring: SignedAccessKeyRing,
}

impl SignedAccessKeyRingReloadRuntime {
    pub async fn bootstrap(
        config: SignedAccessKeyRingReloadConfig,
    ) -> Result<(SignedAccessKeyRing, Self), SignedAccessKeyRingReloadError> {
        if config.poll_interval.is_zero() {
            return Err(SignedAccessKeyRingReloadError::ZeroPollInterval);
        }
        let generation = load_candidate(&config).await?;
        let key_ring = load_signed_access_key_ring(generation.file(KEY_RING_MATERIAL_NAME)?)?;
        key_ring.initialize_reload(generation.generation(), generation.manifest_digest());
        let runtime = Self {
            config,
            key_ring: key_ring.clone(),
        };
        Ok((key_ring, runtime))
    }

    pub async fn run_until_shutdown(self, shutdown: ShutdownSignal) {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                _ = interval.tick() => self.reload_once().await,
            }
        }
    }

    async fn reload_once(&self) {
        let generation = match load_candidate(&self.config).await {
            Ok(generation) => generation,
            Err(error) => {
                self.key_ring.mark_reload_failed();
                warn!(error = %error, event = "signed_access_keyring_reload_failed");
                return;
            }
        };
        let candidate =
            match load_signed_access_key_ring(match generation.file(KEY_RING_MATERIAL_NAME) {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.key_ring.mark_reload_failed();
                    warn!(error = %error, event = "signed_access_keyring_reload_failed");
                    return;
                }
            }) {
                Ok(candidate) => candidate,
                Err(error) => {
                    self.key_ring.mark_reload_failed();
                    warn!(error = %error, event = "signed_access_keyring_reload_failed");
                    return;
                }
            };
        match self.key_ring.activate_reload_candidate(
            generation.generation(),
            generation.manifest_digest(),
            &candidate,
        ) {
            SignedAccessKeyRingActivation::Activated => info!(
                generation = generation.generation(),
                event = "signed_access_keyring_reloaded"
            ),
            SignedAccessKeyRingActivation::Unchanged => {}
            SignedAccessKeyRingActivation::Stale => {
                self.key_ring.mark_reload_failed();
                warn!(
                    generation = generation.generation(),
                    event = "signed_access_keyring_reload_stale"
                );
            }
            SignedAccessKeyRingActivation::ConflictingGeneration => {
                self.key_ring.mark_reload_failed();
                warn!(
                    generation = generation.generation(),
                    event = "signed_access_keyring_reload_conflict"
                );
            }
        }
    }
}

async fn load_candidate(
    config: &SignedAccessKeyRingReloadConfig,
) -> Result<crate::generation_reload::GenerationReload, GenerationReloadError> {
    load_generation_reload(
        config.manifest_path.clone(),
        vec![GenerationReloadFile::new(
            KEY_RING_MATERIAL_NAME,
            config.key_ring_path.clone(),
        )],
    )
    .await
}

#[derive(Debug)]
pub enum SignedAccessKeyRingReloadError {
    ZeroPollInterval,
    Generation(GenerationReloadError),
    KeyRing(SignedAccessError),
}

impl std::fmt::Display for SignedAccessKeyRingReloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroPollInterval => {
                formatter.write_str("signed-access reload interval must be greater than zero")
            }
            Self::Generation(error) => write!(
                formatter,
                "signed-access reload generation is invalid: {error}"
            ),
            Self::KeyRing(error) => write!(formatter, "signed-access key ring is invalid: {error}"),
        }
    }
}

impl std::error::Error for SignedAccessKeyRingReloadError {}

impl From<GenerationReloadError> for SignedAccessKeyRingReloadError {
    fn from(error: GenerationReloadError) -> Self {
        Self::Generation(error)
    }
}

impl From<SignedAccessError> for SignedAccessKeyRingReloadError {
    fn from(error: SignedAccessError) -> Self {
        Self::KeyRing(error)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        generate_signed_access_keypair, load_signed_access_signer, merge_signed_access_key_rings,
        shutdown_channel, PublicHostname,
    };

    fn publish(path: &std::path::Path, manifest: &std::path::Path, generation: u64, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::fs::write(
            manifest,
            format!("{{\"generation\":{generation},\"files\":{{\"keyring\":\"{digest}\"}}}}"),
        )
        .unwrap();
    }

    async fn wait_for(
        key_ring: &SignedAccessKeyRing,
        predicate: impl Fn(crate::SignedAccessKeyRingReloadStatus) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if key_ring.reload_status().is_some_and(&predicate) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rotates_with_overlap_and_retains_last_known_good_on_invalid_generation() {
        let directory = std::env::temp_dir().join(format!(
            "tunnelproxy-signed-access-reload-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let keyring_path = directory.join("keyring.json");
        let manifest_path = directory.join("manifest.json");
        let (private_one, public_one) = generate_signed_access_keypair(1).unwrap();
        let (private_two, public_two) = generate_signed_access_keypair(2).unwrap();
        let overlap = merge_signed_access_key_rings(&public_one, &public_two).unwrap();
        let signer_one = load_signed_access_signer(&private_one).unwrap();
        let signer_two = load_signed_access_signer(&private_two).unwrap();
        let hostname = PublicHostname::new("reload.example.test").unwrap();
        let token_one = signer_one.sign(&hostname, 100, 200).unwrap();
        let token_two = signer_two.sign(&hostname, 100, 200).unwrap();

        std::fs::write(&keyring_path, &public_one).unwrap();
        std::fs::write(
            &manifest_path,
            "{\"generation\":1,\"files\":{\"keyring\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}",
        )
        .unwrap();
        assert!(matches!(
            SignedAccessKeyRingReloadRuntime::bootstrap(SignedAccessKeyRingReloadConfig {
                manifest_path: manifest_path.clone(),
                key_ring_path: keyring_path.clone(),
                poll_interval: Duration::from_millis(10),
            })
            .await,
            Err(SignedAccessKeyRingReloadError::Generation(
                GenerationReloadError::DigestMismatch(_)
            ))
        ));

        publish(&keyring_path, &manifest_path, 1, &public_one);
        let (key_ring, runtime) =
            SignedAccessKeyRingReloadRuntime::bootstrap(SignedAccessKeyRingReloadConfig {
                manifest_path: manifest_path.clone(),
                key_ring_path: keyring_path.clone(),
                poll_interval: Duration::from_millis(10),
            })
            .await
            .unwrap();
        let (shutdown, signal) = shutdown_channel();
        let task = tokio::spawn(runtime.run_until_shutdown(signal));
        key_ring.verify(&token_one, &hostname, 150, 100, 0).unwrap();

        publish(&keyring_path, &manifest_path, 2, &overlap);
        wait_for(&key_ring, |status| status.generation == 2).await;
        key_ring.verify(&token_one, &hostname, 150, 100, 0).unwrap();
        key_ring.verify(&token_two, &hostname, 150, 100, 0).unwrap();

        std::fs::write(&keyring_path, &public_two).unwrap();
        std::fs::write(
            &manifest_path,
            "{\"generation\":3,\"files\":{\"keyring\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}",
        )
        .unwrap();
        wait_for(&key_ring, |status| status.reload_failed).await;
        key_ring.verify(&token_one, &hostname, 150, 100, 0).unwrap();

        publish(&keyring_path, &manifest_path, 4, &public_two);
        wait_for(&key_ring, |status| status.generation == 4).await;
        assert_eq!(
            key_ring.verify(&token_one, &hostname, 150, 100, 0),
            Err(SignedAccessError::UnknownKey)
        );
        key_ring.verify(&token_two, &hostname, 150, 100, 0).unwrap();
        let failures = key_ring.reload_status().unwrap().failed_reloads;

        publish(&keyring_path, &manifest_path, 3, &public_one);
        wait_for(&key_ring, |status| status.failed_reloads > failures).await;
        key_ring.verify(&token_two, &hostname, 150, 100, 0).unwrap();
        let failures = key_ring.reload_status().unwrap().failed_reloads;

        publish(&keyring_path, &manifest_path, 4, &public_one);
        wait_for(&key_ring, |status| status.failed_reloads > failures).await;
        key_ring.verify(&token_two, &hostname, 150, 100, 0).unwrap();

        publish(&keyring_path, &manifest_path, 5, &public_two);
        wait_for(&key_ring, |status| status.generation == 5).await;
        let status = key_ring.reload_status().unwrap();
        assert_eq!(status.successful_reloads, 3);
        assert!(status.failed_reloads > 0);
        assert!(!status.reload_failed);

        shutdown.shutdown();
        task.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
