use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{
    decode_versioned_snapshot, encode_versioned_snapshot, SnapshotCodecError,
    VersionedAuthorizationSnapshot, MAX_SNAPSHOT_BYTES,
};

const CACHE_MAGIC: &[u8; 4] = b"TPC1";
const CACHE_FORMAT_VERSION: u16 = 1;
const CACHE_FLAGS: u16 = 0;
const METADATA_BYTES: usize = 20;
const DIGEST_BYTES: usize = 32;
const CACHE_HEADER_BYTES: usize = METADATA_BYTES + DIGEST_BYTES;
const MAX_CACHE_BYTES: usize = CACHE_HEADER_BYTES + MAX_SNAPSHOT_BYTES;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCacheConfig {
    pub directory: PathBuf,
    pub max_stale_age: Duration,
}

impl SnapshotCacheConfig {
    pub fn validate(&self) -> Result<(), SnapshotCacheError> {
        if self.directory.as_os_str().is_empty() || self.max_stale_age.is_zero() {
            return Err(SnapshotCacheError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSnapshot {
    snapshot: VersionedAuthorizationSnapshot,
    authenticated_at: SystemTime,
}

impl CachedSnapshot {
    pub fn snapshot(&self) -> &VersionedAuthorizationSnapshot {
        &self.snapshot
    }

    pub const fn authenticated_at(&self) -> SystemTime {
        self.authenticated_at
    }

    pub fn into_snapshot(self) -> VersionedAuthorizationSnapshot {
        self.snapshot
    }
}

/// Edge-local, single-writer snapshot cache.
///
/// Generation files avoid overwrite-renames so durable replacement works on
/// Windows as well as Unix. The digest detects accidental corruption; it is
/// not a signature and the local filesystem remains inside the Edge trust
/// boundary.
#[derive(Clone)]
pub struct FileSnapshotCache {
    config: SnapshotCacheConfig,
    gate: Arc<Mutex<()>>,
}

impl FileSnapshotCache {
    pub fn new(config: SnapshotCacheConfig) -> Result<Self, SnapshotCacheError> {
        config.validate()?;
        Ok(Self {
            config,
            gate: Arc::new(Mutex::new(())),
        })
    }

    pub const fn max_stale_age(&self) -> Duration {
        self.config.max_stale_age
    }

    pub async fn load(&self) -> Result<CachedSnapshot, SnapshotCacheError> {
        let cache = self.clone();
        tokio::task::spawn_blocking(move || cache.load_sync(SystemTime::now(), true))
            .await
            .map_err(|_| SnapshotCacheError::Task)?
    }

    /// Stores one snapshot whose source was authenticated now and returns the
    /// wall-clock timestamp persisted in the cache record.
    pub async fn store(
        &self,
        snapshot: &VersionedAuthorizationSnapshot,
    ) -> Result<SystemTime, SnapshotCacheError> {
        let cache = self.clone();
        let snapshot = snapshot.clone();
        let authenticated_at = SystemTime::now();
        tokio::task::spawn_blocking(move || {
            cache.store_sync(&snapshot, authenticated_at)?;
            Ok(authenticated_at)
        })
        .await
        .map_err(|_| SnapshotCacheError::Task)?
    }

    fn load_sync(
        &self,
        now: SystemTime,
        enforce_freshness: bool,
    ) -> Result<CachedSnapshot, SnapshotCacheError> {
        let _guard = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        self.load_unlocked(now, enforce_freshness)
    }

    fn load_unlocked(
        &self,
        now: SystemTime,
        enforce_freshness: bool,
    ) -> Result<CachedSnapshot, SnapshotCacheError> {
        let entries = match fs::read_dir(&self.config.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SnapshotCacheError::Missing)
            }
            Err(error) => return Err(SnapshotCacheError::Io(error)),
        };
        let mut generations = Vec::new();
        for entry in entries {
            let entry = entry.map_err(SnapshotCacheError::Io)?;
            let file_type = entry.file_type().map_err(SnapshotCacheError::Io)?;
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp") {
                continue;
            }
            if let Some(version) = generation_version(&name)? {
                generations.push((version, entry.path()));
            }
        }
        let highest = generations
            .iter()
            .map(|(version, _)| *version)
            .max()
            .ok_or(SnapshotCacheError::Missing)?;
        let mut selected: Option<CachedSnapshot> = None;
        for (_, path) in generations
            .iter()
            .filter(|(version, _)| *version == highest)
        {
            let candidate = read_generation(path, now)?;
            if candidate.snapshot.version().get() != highest {
                return Err(SnapshotCacheError::FilenameVersion);
            }
            if let Some(current) = &selected {
                if current.snapshot != candidate.snapshot {
                    return Err(SnapshotCacheError::ConflictingVersion(highest));
                }
                if candidate.authenticated_at > current.authenticated_at {
                    selected = Some(candidate);
                }
            } else {
                selected = Some(candidate);
            }
        }
        let selected = selected.ok_or(SnapshotCacheError::Missing)?;
        if enforce_freshness {
            let age = now
                .duration_since(selected.authenticated_at)
                .map_err(|_| SnapshotCacheError::FutureTimestamp)?;
            if age >= self.config.max_stale_age {
                return Err(SnapshotCacheError::Expired);
            }
        }
        Ok(selected)
    }

    fn store_sync(
        &self,
        snapshot: &VersionedAuthorizationSnapshot,
        authenticated_at: SystemTime,
    ) -> Result<(), SnapshotCacheError> {
        let _guard = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        fs::create_dir_all(&self.config.directory).map_err(SnapshotCacheError::Io)?;
        match self.load_unlocked(authenticated_at, false) {
            Ok(current) if snapshot.version() < current.snapshot.version() => {
                return Err(SnapshotCacheError::StaleVersion {
                    current: current.snapshot.version().get(),
                    received: snapshot.version().get(),
                });
            }
            Ok(current)
                if snapshot.version() == current.snapshot.version()
                    && snapshot != &current.snapshot =>
            {
                return Err(SnapshotCacheError::ConflictingVersion(
                    snapshot.version().get(),
                ));
            }
            Ok(_) | Err(SnapshotCacheError::Missing) => {}
            Err(error) => return Err(error),
        }

        let bytes = encode_cache_record(snapshot, authenticated_at)?;
        let timestamp = unix_millis(authenticated_at)?;
        let nonce = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        let stem = format!(
            "snapshot-{:020}-{:020}-{:020}",
            snapshot.version().get(),
            timestamp,
            nonce
        );
        let temporary = self.config.directory.join(format!("{stem}.tmp"));
        let final_path = self.config.directory.join(format!("{stem}.tpc"));
        let write_result = (|| -> Result<(), SnapshotCacheError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(SnapshotCacheError::Io)?;
            file.write_all(&bytes).map_err(SnapshotCacheError::Io)?;
            file.sync_all().map_err(SnapshotCacheError::Io)?;
            drop(file);
            fs::rename(&temporary, &final_path).map_err(SnapshotCacheError::Io)?;
            sync_directory(&self.config.directory)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
            return write_result;
        }

        for entry in fs::read_dir(&self.config.directory).map_err(SnapshotCacheError::Io)? {
            let path = entry.map_err(SnapshotCacheError::Io)?.path();
            if path == final_path {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with("snapshot-") && (name.ends_with(".tpc") || name.ends_with(".tmp")) {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }
}

fn encode_cache_record(
    snapshot: &VersionedAuthorizationSnapshot,
    authenticated_at: SystemTime,
) -> Result<Vec<u8>, SnapshotCacheError> {
    let payload = encode_versioned_snapshot(snapshot).map_err(SnapshotCacheError::Codec)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| SnapshotCacheError::TooLarge)?;
    let mut metadata = Vec::with_capacity(METADATA_BYTES);
    metadata.extend_from_slice(CACHE_MAGIC);
    metadata.extend_from_slice(&CACHE_FORMAT_VERSION.to_be_bytes());
    metadata.extend_from_slice(&CACHE_FLAGS.to_be_bytes());
    metadata.extend_from_slice(&unix_millis(authenticated_at)?.to_be_bytes());
    metadata.extend_from_slice(&payload_len.to_be_bytes());
    let digest = Sha256::new()
        .chain_update(&metadata)
        .chain_update(&payload)
        .finalize();
    let mut output = Vec::with_capacity(CACHE_HEADER_BYTES + payload.len());
    output.extend_from_slice(&metadata);
    output.extend_from_slice(&digest);
    output.extend_from_slice(&payload);
    if output.len() > MAX_CACHE_BYTES {
        return Err(SnapshotCacheError::TooLarge);
    }
    Ok(output)
}

fn decode_cache_record(
    bytes: &[u8],
    now: SystemTime,
) -> Result<CachedSnapshot, SnapshotCacheError> {
    if bytes.len() > MAX_CACHE_BYTES {
        return Err(SnapshotCacheError::TooLarge);
    }
    if bytes.len() < CACHE_HEADER_BYTES {
        return Err(SnapshotCacheError::Truncated);
    }
    if &bytes[..4] != CACHE_MAGIC {
        return Err(SnapshotCacheError::Magic);
    }
    if u16::from_be_bytes(bytes[4..6].try_into().expect("fixed slice")) != CACHE_FORMAT_VERSION {
        return Err(SnapshotCacheError::FormatVersion);
    }
    if u16::from_be_bytes(bytes[6..8].try_into().expect("fixed slice")) != CACHE_FLAGS {
        return Err(SnapshotCacheError::Flags);
    }
    let timestamp = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed slice"));
    let payload_len = u32::from_be_bytes(bytes[16..20].try_into().expect("fixed slice")) as usize;
    let expected_len = CACHE_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(SnapshotCacheError::TooLarge)?;
    if expected_len != bytes.len() {
        return Err(if expected_len > bytes.len() {
            SnapshotCacheError::Truncated
        } else {
            SnapshotCacheError::TrailingBytes
        });
    }
    let expected_digest = Sha256::new()
        .chain_update(&bytes[..METADATA_BYTES])
        .chain_update(&bytes[CACHE_HEADER_BYTES..])
        .finalize();
    if expected_digest.as_slice() != &bytes[METADATA_BYTES..CACHE_HEADER_BYTES] {
        return Err(SnapshotCacheError::Digest);
    }
    let snapshot = decode_versioned_snapshot(&bytes[CACHE_HEADER_BYTES..])
        .map_err(SnapshotCacheError::Codec)?;
    let canonical = encode_versioned_snapshot(&snapshot).map_err(SnapshotCacheError::Codec)?;
    if canonical.as_slice() != &bytes[CACHE_HEADER_BYTES..] {
        return Err(SnapshotCacheError::NonCanonical);
    }
    let authenticated_at = UNIX_EPOCH
        .checked_add(Duration::from_millis(timestamp))
        .ok_or(SnapshotCacheError::FutureTimestamp)?;
    if authenticated_at > now {
        return Err(SnapshotCacheError::FutureTimestamp);
    }
    Ok(CachedSnapshot {
        snapshot,
        authenticated_at,
    })
}

fn read_generation(path: &Path, now: SystemTime) -> Result<CachedSnapshot, SnapshotCacheError> {
    let metadata = fs::metadata(path).map_err(SnapshotCacheError::Io)?;
    if metadata.len() > MAX_CACHE_BYTES as u64 {
        return Err(SnapshotCacheError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(SnapshotCacheError::Io)?;
    decode_cache_record(&bytes, now)
}

fn generation_version(name: &str) -> Result<Option<u64>, SnapshotCacheError> {
    if !name.starts_with("snapshot-") || !name.ends_with(".tpc") {
        return Ok(None);
    }
    let stem = name.strip_suffix(".tpc").expect("suffix checked");
    let mut parts = stem.split('-');
    if parts.next() != Some("snapshot") {
        return Ok(None);
    }
    let version = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(SnapshotCacheError::Filename)?;
    let timestamp_valid = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some();
    let nonce_valid = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some();
    if !timestamp_valid || !nonce_valid || parts.next().is_some() {
        return Err(SnapshotCacheError::Filename);
    }
    Ok(Some(version))
}

fn unix_millis(time: SystemTime) -> Result<u64, SnapshotCacheError> {
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SnapshotCacheError::Timestamp)?
        .as_millis();
    u64::try_from(millis).map_err(|_| SnapshotCacheError::Timestamp)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), SnapshotCacheError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(SnapshotCacheError::Io)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), SnapshotCacheError> {
    Ok(())
}

#[derive(Debug)]
pub enum SnapshotCacheError {
    InvalidConfig,
    Missing,
    Expired,
    FutureTimestamp,
    Timestamp,
    TooLarge,
    Truncated,
    TrailingBytes,
    Magic,
    FormatVersion,
    Flags,
    Digest,
    NonCanonical,
    Filename,
    FilenameVersion,
    StaleVersion { current: u64, received: u64 },
    ConflictingVersion(u64),
    Codec(SnapshotCodecError),
    Io(std::io::Error),
    Task,
}

impl std::fmt::Display for SnapshotCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("snapshot cache configuration is invalid"),
            Self::Missing => f.write_str("snapshot cache is empty"),
            Self::Expired => f.write_str("snapshot cache has expired"),
            Self::FutureTimestamp => f.write_str("snapshot cache timestamp is in the future"),
            Self::Timestamp => f.write_str("snapshot cache timestamp is invalid"),
            Self::TooLarge => f.write_str("snapshot cache record is too large"),
            Self::Truncated => f.write_str("snapshot cache record is truncated"),
            Self::TrailingBytes => f.write_str("snapshot cache record has trailing bytes"),
            Self::Magic => f.write_str("snapshot cache magic is invalid"),
            Self::FormatVersion => f.write_str("snapshot cache format version is unsupported"),
            Self::Flags => f.write_str("snapshot cache flags are unsupported"),
            Self::Digest => f.write_str("snapshot cache digest does not match"),
            Self::NonCanonical => f.write_str("snapshot cache payload is not canonical"),
            Self::Filename => f.write_str("snapshot cache generation filename is invalid"),
            Self::FilenameVersion => {
                f.write_str("snapshot cache filename version does not match its payload")
            }
            Self::StaleVersion { current, received } => write!(
                f,
                "snapshot cache rejected version {received}; current version is {current}"
            ),
            Self::ConflictingVersion(version) => {
                write!(
                    f,
                    "snapshot cache version {version} has conflicting content"
                )
            }
            Self::Codec(error) => write!(f, "snapshot cache payload is invalid: {error}"),
            Self::Io(_) => f.write_str("snapshot cache filesystem operation failed"),
            Self::Task => f.write_str("snapshot cache blocking task failed"),
        }
    }
}

impl std::error::Error for SnapshotCacheError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizationSnapshot, SnapshotVersion};

    fn snapshot(version: u64) -> VersionedAuthorizationSnapshot {
        VersionedAuthorizationSnapshot::new(
            SnapshotVersion::new(version).unwrap(),
            AuthorizationSnapshot::default(),
        )
    }

    fn temp_cache(max_stale_age: Duration) -> (FileSnapshotCache, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "tunnelproxy-cache-test-{}-{}",
            std::process::id(),
            NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
        ));
        let cache = FileSnapshotCache::new(SnapshotCacheConfig {
            directory: path.clone(),
            max_stale_age,
        })
        .unwrap();
        (cache, path)
    }

    #[test]
    fn record_round_trip_and_corruption_are_detected() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let bytes = encode_cache_record(&snapshot(7), now).unwrap();
        let decoded = decode_cache_record(&bytes, now).unwrap();
        assert_eq!(decoded.snapshot(), &snapshot(7));
        assert_eq!(decoded.authenticated_at(), now);

        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decode_cache_record(&corrupt, now),
            Err(SnapshotCacheError::Digest)
        ));
        assert!(matches!(
            decode_cache_record(&bytes[..CACHE_HEADER_BYTES - 1], now),
            Err(SnapshotCacheError::Truncated)
        ));
        assert!(matches!(
            decode_cache_record(&bytes, now - Duration::from_millis(1)),
            Err(SnapshotCacheError::FutureTimestamp)
        ));
    }

    #[test]
    fn generation_store_is_monotonic_atomic_and_ignores_temp_files() {
        let (cache, directory) = temp_cache(Duration::from_secs(60));
        let now = SystemTime::now();
        cache.store_sync(&snapshot(2), now).unwrap();
        fs::write(directory.join("snapshot-abandoned.tmp"), b"partial").unwrap();
        cache
            .store_sync(&snapshot(4), now + Duration::from_millis(1))
            .unwrap();
        assert_eq!(
            cache
                .load_sync(now + Duration::from_millis(2), true)
                .unwrap()
                .snapshot()
                .version()
                .get(),
            4
        );
        assert!(matches!(
            cache.store_sync(&snapshot(3), now + Duration::from_millis(3)),
            Err(SnapshotCacheError::StaleVersion { .. })
        ));
        let final_count = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("tpc")
            })
            .count();
        assert_eq!(final_count, 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn expired_cache_and_invalid_config_fail_closed() {
        assert!(matches!(
            FileSnapshotCache::new(SnapshotCacheConfig {
                directory: PathBuf::new(),
                max_stale_age: Duration::ZERO,
            }),
            Err(SnapshotCacheError::InvalidConfig)
        ));
        let (cache, directory) = temp_cache(Duration::from_secs(1));
        let written = UNIX_EPOCH + Duration::from_secs(10);
        cache.store_sync(&snapshot(1), written).unwrap();
        assert!(matches!(
            cache.load_sync(written + Duration::from_secs(1), true),
            Err(SnapshotCacheError::Expired)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
