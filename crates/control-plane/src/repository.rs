use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use tunnelproxy_common::{AgentId, TunnelId};

use crate::{
    authorization_snapshot_channel, snapshot_digest, AgentGrant, AuthorizationSnapshot,
    AuthorizationSnapshotPublisher, AuthorizationSnapshotSubscription, CertificateFingerprint,
    SnapshotCodecError, SnapshotPublishOutcome, SnapshotUpdateError, SnapshotVersion, TunnelGrant,
    TunnelStatus, VersionedAuthorizationSnapshot,
};

pub trait SnapshotRepository: Send + Sync + 'static {
    fn load_latest(
        &self,
    ) -> Result<Option<VersionedAuthorizationSnapshot>, SnapshotRepositoryError>;

    fn commit(
        &self,
        snapshot: &VersionedAuthorizationSnapshot,
    ) -> Result<SnapshotCommitOutcome, SnapshotRepositoryError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotCommitOutcome {
    Applied {
        previous: Option<SnapshotVersion>,
        current: SnapshotVersion,
    },
    Unchanged {
        version: SnapshotVersion,
    },
}

#[derive(Debug, Clone)]
pub struct SqliteSnapshotRepository {
    path: PathBuf,
}

impl SqliteSnapshotRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SnapshotRepositoryError> {
        let repository = Self {
            path: path.as_ref().to_path_buf(),
        };
        let connection = repository.connect()?;
        migrate(&connection)?;
        Ok(repository)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<Connection, SnapshotRepositoryError> {
        let connection = Connection::open(&self.path).map_err(storage)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;",
            )
            .map_err(storage)?;
        Ok(connection)
    }
}

impl SnapshotRepository for SqliteSnapshotRepository {
    fn load_latest(
        &self,
    ) -> Result<Option<VersionedAuthorizationSnapshot>, SnapshotRepositoryError> {
        let connection = self.connect()?;
        load_latest_from_connection(&connection)
    }

    fn commit(
        &self,
        snapshot: &VersionedAuthorizationSnapshot,
    ) -> Result<SnapshotCommitOutcome, SnapshotRepositoryError> {
        let digest =
            snapshot_digest(snapshot.snapshot()).map_err(SnapshotRepositoryError::Codec)?;
        let grants = snapshot.snapshot().grants();
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current = transaction
            .query_row(
                "SELECT version, digest FROM snapshot_head WHERE singleton_id = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let previous = match current {
            Some((version, current_digest)) => {
                let version = decode_version_blob(&version)?;
                if snapshot.version() < version {
                    return Err(SnapshotRepositoryError::StaleVersion {
                        current: version,
                        received: snapshot.version(),
                    });
                }
                if snapshot.version() == version {
                    if current_digest.as_slice() == digest {
                        return Ok(SnapshotCommitOutcome::Unchanged { version });
                    }
                    return Err(SnapshotRepositoryError::ConflictingVersion { version });
                }
                Some(version)
            }
            None => None,
        };

        transaction
            .execute("DELETE FROM snapshot_tunnels", [])
            .map_err(storage)?;
        transaction
            .execute("DELETE FROM snapshot_agents", [])
            .map_err(storage)?;
        for grant in grants {
            transaction
                .execute(
                    "INSERT INTO snapshot_agents(certificate, agent_id) VALUES (?1, ?2)",
                    params![
                        grant.certificate.as_bytes().as_slice(),
                        grant.agent_id.as_str()
                    ],
                )
                .map_err(storage)?;
            for tunnel in grant.tunnels {
                let status = match tunnel.status {
                    TunnelStatus::Enabled => 1_i64,
                    TunnelStatus::Disabled => 2_i64,
                };
                transaction
                    .execute(
                        "INSERT INTO snapshot_tunnels(certificate, tunnel_id, status)
                         VALUES (?1, ?2, ?3)",
                        params![
                            grant.certificate.as_bytes().as_slice(),
                            tunnel.tunnel_id.as_str(),
                            status
                        ],
                    )
                    .map_err(storage)?;
            }
        }
        transaction
            .execute(
                "INSERT INTO snapshot_head(singleton_id, version, digest)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(singleton_id) DO UPDATE SET
                    version = excluded.version,
                    digest = excluded.digest",
                params![
                    snapshot.version().get().to_be_bytes().as_slice(),
                    digest.as_slice()
                ],
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        Ok(SnapshotCommitOutcome::Applied {
            previous,
            current: snapshot.version(),
        })
    }
}

fn migrate(connection: &Connection) -> Result<(), SnapshotRepositoryError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS snapshot_head (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
                version BLOB NOT NULL CHECK(length(version) = 8),
                digest BLOB NOT NULL CHECK(length(digest) = 32)
            );
            CREATE TABLE IF NOT EXISTS snapshot_agents (
                certificate BLOB PRIMARY KEY CHECK(length(certificate) = 32),
                agent_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshot_tunnels (
                certificate BLOB NOT NULL,
                tunnel_id TEXT NOT NULL,
                status INTEGER NOT NULL CHECK(status IN (1, 2)),
                PRIMARY KEY(certificate, tunnel_id),
                FOREIGN KEY(certificate) REFERENCES snapshot_agents(certificate)
                    ON DELETE CASCADE
            );",
        )
        .map_err(storage)
}

fn load_latest_from_connection(
    connection: &Connection,
) -> Result<Option<VersionedAuthorizationSnapshot>, SnapshotRepositoryError> {
    let head = connection
        .query_row(
            "SELECT version, digest FROM snapshot_head WHERE singleton_id = 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let Some((version, expected_digest)) = head else {
        return Ok(None);
    };
    let version = decode_version_blob(&version)?;
    let mut agents = connection
        .prepare("SELECT certificate, agent_id FROM snapshot_agents ORDER BY certificate")
        .map_err(storage)?;
    let rows = agents
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage)?;
    let mut grants = Vec::new();
    for row in rows {
        let (certificate, agent_id) = row.map_err(storage)?;
        let certificate = decode_fingerprint(&certificate)?;
        let agent_id = AgentId::new(agent_id).map_err(|_| SnapshotRepositoryError::Corrupt)?;
        let mut tunnels = connection
            .prepare(
                "SELECT tunnel_id, status FROM snapshot_tunnels
                 WHERE certificate = ?1 ORDER BY tunnel_id",
            )
            .map_err(storage)?;
        let rows = tunnels
            .query_map([certificate.as_bytes().as_slice()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage)?;
        let mut tunnel_grants = Vec::new();
        for row in rows {
            let (tunnel_id, status) = row.map_err(storage)?;
            let tunnel_id =
                TunnelId::new(tunnel_id).map_err(|_| SnapshotRepositoryError::Corrupt)?;
            let status = match status {
                1 => TunnelStatus::Enabled,
                2 => TunnelStatus::Disabled,
                _ => return Err(SnapshotRepositoryError::Corrupt),
            };
            tunnel_grants.push(TunnelGrant::new(tunnel_id, status));
        }
        grants.push(AgentGrant::new(certificate, agent_id, tunnel_grants));
    }
    let snapshot =
        AuthorizationSnapshot::new(grants).map_err(|_| SnapshotRepositoryError::Corrupt)?;
    let digest = snapshot_digest(&snapshot).map_err(SnapshotRepositoryError::Codec)?;
    if expected_digest.as_slice() != digest {
        return Err(SnapshotRepositoryError::Corrupt);
    }
    Ok(Some(VersionedAuthorizationSnapshot::new(version, snapshot)))
}

fn decode_version_blob(bytes: &[u8]) -> Result<SnapshotVersion, SnapshotRepositoryError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SnapshotRepositoryError::Corrupt)?;
    SnapshotVersion::new(u64::from_be_bytes(bytes)).ok_or(SnapshotRepositoryError::Corrupt)
}

fn decode_fingerprint(bytes: &[u8]) -> Result<CertificateFingerprint, SnapshotRepositoryError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SnapshotRepositoryError::Corrupt)?;
    Ok(CertificateFingerprint::from_bytes(bytes))
}

fn storage(error: rusqlite::Error) -> SnapshotRepositoryError {
    SnapshotRepositoryError::Storage(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRepositoryError {
    Storage(String),
    Corrupt,
    Codec(SnapshotCodecError),
    StaleVersion {
        current: SnapshotVersion,
        received: SnapshotVersion,
    },
    ConflictingVersion {
        version: SnapshotVersion,
    },
}

impl std::fmt::Display for SnapshotRepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(_) => f.write_str("snapshot repository operation failed"),
            Self::Corrupt => f.write_str("snapshot repository contains invalid data"),
            Self::Codec(error) => write!(f, "snapshot encoding failed: {error}"),
            Self::StaleVersion { current, received } => write!(
                f,
                "snapshot version {received} is stale; repository version is {current}"
            ),
            Self::ConflictingVersion { version } => {
                write!(
                    f,
                    "snapshot version {version} conflicts with durable content"
                )
            }
        }
    }
}

impl std::error::Error for SnapshotRepositoryError {}

#[derive(Clone)]
pub struct PersistentSnapshotAuthority {
    repository: Arc<dyn SnapshotRepository>,
    publisher: AuthorizationSnapshotPublisher,
    commit_gate: Arc<tokio::sync::Mutex<()>>,
}

impl PersistentSnapshotAuthority {
    pub async fn open(
        repository: Arc<dyn SnapshotRepository>,
    ) -> Result<Self, PersistentSnapshotAuthorityError> {
        let loader = Arc::clone(&repository);
        let snapshot = tokio::task::spawn_blocking(move || loader.load_latest())
            .await
            .map_err(|_| PersistentSnapshotAuthorityError::StorageTask)?
            .map_err(PersistentSnapshotAuthorityError::Repository)?
            .ok_or(PersistentSnapshotAuthorityError::Uninitialized)?;
        let (publisher, _) = authorization_snapshot_channel(snapshot);
        Ok(Self {
            repository,
            publisher,
            commit_gate: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn current(&self) -> Arc<VersionedAuthorizationSnapshot> {
        self.publisher.current()
    }

    pub fn subscribe(&self) -> AuthorizationSnapshotSubscription {
        self.publisher.subscribe()
    }

    pub async fn commit(
        &self,
        snapshot: VersionedAuthorizationSnapshot,
    ) -> Result<SnapshotCommitOutcome, PersistentSnapshotAuthorityError> {
        let _guard = self.commit_gate.lock().await;
        let repository = Arc::clone(&self.repository);
        let durable = snapshot.clone();
        let outcome = tokio::task::spawn_blocking(move || repository.commit(&durable))
            .await
            .map_err(|_| PersistentSnapshotAuthorityError::StorageTask)?
            .map_err(PersistentSnapshotAuthorityError::Repository)?;
        match self.publisher.publish(snapshot) {
            Ok(SnapshotPublishOutcome::Applied { .. })
            | Ok(SnapshotPublishOutcome::Unchanged { .. }) => {}
            Err(SnapshotUpdateError::StaleVersion { .. })
            | Err(SnapshotUpdateError::ConflictingVersion { .. }) => {
                return Err(PersistentSnapshotAuthorityError::PublishInvariant)
            }
        }
        Ok(outcome)
    }

    /// Reloads the durable head and publishes it when another trusted
    /// control-plane operation committed a newer complete snapshot.
    pub async fn refresh_from_repository(
        &self,
    ) -> Result<SnapshotPublishOutcome, PersistentSnapshotAuthorityError> {
        let _guard = self.commit_gate.lock().await;
        let repository = Arc::clone(&self.repository);
        let snapshot = tokio::task::spawn_blocking(move || repository.load_latest())
            .await
            .map_err(|_| PersistentSnapshotAuthorityError::StorageTask)?
            .map_err(PersistentSnapshotAuthorityError::Repository)?
            .ok_or(PersistentSnapshotAuthorityError::Uninitialized)?;
        self.publisher
            .publish(snapshot)
            .map_err(|_| PersistentSnapshotAuthorityError::PublishInvariant)
    }
}

impl std::fmt::Debug for PersistentSnapshotAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentSnapshotAuthority")
            .field("version", &self.current().version())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistentSnapshotAuthorityError {
    Uninitialized,
    Repository(SnapshotRepositoryError),
    StorageTask,
    PublishInvariant,
}

impl std::fmt::Display for PersistentSnapshotAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uninitialized => f.write_str("snapshot repository is not initialized"),
            Self::Repository(error) => error.fmt(f),
            Self::StorageTask => f.write_str("snapshot repository worker stopped unexpectedly"),
            Self::PublishInvariant => {
                f.write_str("durable snapshot and live publisher became inconsistent")
            }
        }
    }
}

impl std::error::Error for PersistentSnapshotAuthorityError {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn snapshot(version: u64, status: TunnelStatus) -> VersionedAuthorizationSnapshot {
        VersionedAuthorizationSnapshot::new(
            SnapshotVersion::new(version).unwrap(),
            AuthorizationSnapshot::new(vec![AgentGrant::new(
                CertificateFingerprint::from_bytes([4; 32]),
                AgentId::new("agent-db").unwrap(),
                vec![TunnelGrant::new(
                    TunnelId::new("tunnel-db").unwrap(),
                    status,
                )],
            )])
            .unwrap(),
        )
    }

    fn temp_database() -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "tunnelproxy-snapshot-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        (directory.join("snapshots.sqlite"), directory)
    }

    #[test]
    fn sqlite_commit_survives_reopen_and_enforces_version_ordering() {
        let (path, directory) = temp_database();
        let repository = SqliteSnapshotRepository::open(&path).unwrap();
        assert_eq!(repository.load_latest().unwrap(), None);
        let first = snapshot(3, TunnelStatus::Enabled);
        assert_eq!(
            repository.commit(&first).unwrap(),
            SnapshotCommitOutcome::Applied {
                previous: None,
                current: SnapshotVersion::new(3).unwrap(),
            }
        );
        drop(repository);

        let repository = SqliteSnapshotRepository::open(&path).unwrap();
        assert_eq!(repository.load_latest().unwrap(), Some(first.clone()));
        assert_eq!(
            repository.commit(&first).unwrap(),
            SnapshotCommitOutcome::Unchanged {
                version: SnapshotVersion::new(3).unwrap()
            }
        );
        assert!(matches!(
            repository.commit(&snapshot(2, TunnelStatus::Disabled)),
            Err(SnapshotRepositoryError::StaleVersion { .. })
        ));
        assert!(matches!(
            repository.commit(&snapshot(3, TunnelStatus::Disabled)),
            Err(SnapshotRepositoryError::ConflictingVersion { .. })
        ));
        assert_eq!(repository.load_latest().unwrap(), Some(first));
        drop(repository);
        std::fs::remove_dir_all(directory).unwrap();
    }

    struct FailingRepository {
        initial: VersionedAuthorizationSnapshot,
    }

    impl SnapshotRepository for FailingRepository {
        fn load_latest(
            &self,
        ) -> Result<Option<VersionedAuthorizationSnapshot>, SnapshotRepositoryError> {
            Ok(Some(self.initial.clone()))
        }

        fn commit(
            &self,
            _snapshot: &VersionedAuthorizationSnapshot,
        ) -> Result<SnapshotCommitOutcome, SnapshotRepositoryError> {
            Err(SnapshotRepositoryError::Storage("injected".to_owned()))
        }
    }

    #[tokio::test]
    async fn authority_never_publishes_before_durable_commit() {
        let initial = snapshot(1, TunnelStatus::Enabled);
        let authority = PersistentSnapshotAuthority::open(Arc::new(FailingRepository {
            initial: initial.clone(),
        }))
        .await
        .unwrap();
        let subscription = authority.subscribe();
        assert!(authority
            .commit(snapshot(2, TunnelStatus::Disabled))
            .await
            .is_err());
        assert_eq!(authority.current().as_ref(), &initial);
        assert_eq!(subscription.current().as_ref(), &initial);
    }

    #[tokio::test]
    async fn authority_refresh_publishes_an_external_durable_commit() {
        let (path, directory) = temp_database();
        let repository = Arc::new(SqliteSnapshotRepository::open(&path).unwrap());
        repository
            .commit(&snapshot(1, TunnelStatus::Enabled))
            .unwrap();
        let authority = PersistentSnapshotAuthority::open(repository.clone())
            .await
            .unwrap();
        let mut subscription = authority.subscribe();
        repository
            .commit(&snapshot(2, TunnelStatus::Disabled))
            .unwrap();
        assert!(matches!(
            authority.refresh_from_repository().await.unwrap(),
            SnapshotPublishOutcome::Applied { .. }
        ));
        subscription.changed().await.unwrap();
        assert_eq!(subscription.current().version().get(), 2);
        assert!(matches!(
            authority.refresh_from_repository().await.unwrap(),
            SnapshotPublishOutcome::Unchanged { .. }
        ));
        drop(authority);
        drop(repository);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
