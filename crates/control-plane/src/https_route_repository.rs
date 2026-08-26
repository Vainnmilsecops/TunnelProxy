//! Transactional, versioned HTTPS hostname route catalog.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use tunnelproxy_common::{PublicHostname, TunnelId};

pub const MAX_HTTPS_ROUTE_RECORDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpsRouteCatalogVersion(NonZeroU64);

impl HttpsRouteCatalogVersion {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    fn next(self) -> Result<Self, HttpsRouteRepositoryError> {
        self.get()
            .checked_add(1)
            .and_then(Self::new)
            .ok_or(HttpsRouteRepositoryError::VersionExhausted)
    }
}

impl std::fmt::Display for HttpsRouteCatalogVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsRouteStatus {
    Enabled,
    Disabled,
}

impl HttpsRouteStatus {
    fn from_raw(value: i64) -> Result<Self, HttpsRouteRepositoryError> {
        match value {
            1 => Ok(Self::Enabled),
            2 => Ok(Self::Disabled),
            _ => Err(HttpsRouteRepositoryError::Corrupt),
        }
    }

    const fn as_raw(self) -> i64 {
        match self {
            Self::Enabled => 1,
            Self::Disabled => 2,
        }
    }
}

impl std::fmt::Display for HttpsRouteStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        })
    }
}

impl std::str::FromStr for HttpsRouteStatus {
    type Err = HttpsRouteStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            _ => Err(HttpsRouteStatusParseError),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpsRouteStatusParseError;

impl std::fmt::Display for HttpsRouteStatusParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HTTPS route status must be enabled or disabled")
    }
}

impl std::error::Error for HttpsRouteStatusParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRouteRecord {
    pub hostname: PublicHostname,
    pub tunnel_id: TunnelId,
    pub status: HttpsRouteStatus,
}

impl HttpsRouteRecord {
    pub const fn new(
        hostname: PublicHostname,
        tunnel_id: TunnelId,
        status: HttpsRouteStatus,
    ) -> Self {
        Self {
            hostname,
            tunnel_id,
            status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRouteCatalog {
    version: HttpsRouteCatalogVersion,
    routes: Vec<HttpsRouteRecord>,
}

impl HttpsRouteCatalog {
    pub const fn version(&self) -> HttpsRouteCatalogVersion {
        self.version
    }

    pub fn routes(&self) -> &[HttpsRouteRecord] {
        &self.routes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsRouteMutationOutcome {
    Applied {
        previous: HttpsRouteCatalogVersion,
        current: HttpsRouteCatalogVersion,
    },
    Unchanged {
        version: HttpsRouteCatalogVersion,
    },
}

#[derive(Clone)]
pub struct HttpsRouteRepository {
    path: PathBuf,
}

impl HttpsRouteRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, HttpsRouteRepositoryError> {
        let path = path.as_ref().to_path_buf();
        crate::SqliteSnapshotRepository::open(&path)
            .map_err(|_| HttpsRouteRepositoryError::Storage("snapshot migration".to_owned()))?;
        let repository = Self { path };
        let connection = repository.connect()?;
        migrate(&connection)?;
        load_catalog(&connection)?;
        Ok(repository)
    }

    pub fn load(&self) -> Result<HttpsRouteCatalog, HttpsRouteRepositoryError> {
        load_catalog(&self.connect()?)
    }

    pub fn upsert(
        &self,
        record: &HttpsRouteRecord,
    ) -> Result<HttpsRouteMutationOutcome, HttpsRouteRepositoryError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current_catalog = load_catalog(&transaction)?;
        let current_version = current_catalog.version();
        let existing = current_catalog
            .routes()
            .iter()
            .find(|candidate| candidate.hostname == record.hostname);
        if let Some(existing) = existing {
            if existing.tunnel_id == record.tunnel_id && existing.status == record.status {
                return Ok(HttpsRouteMutationOutcome::Unchanged {
                    version: current_version,
                });
            }
        } else if current_catalog.routes().len() >= MAX_HTTPS_ROUTE_RECORDS {
            return Err(HttpsRouteRepositoryError::CapacityExceeded);
        }
        let next_version = current_version.next()?;
        transaction
            .execute(
                "INSERT INTO https_routes(hostname, tunnel_id, status)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(hostname) DO UPDATE SET
                    tunnel_id = excluded.tunnel_id,
                    status = excluded.status",
                params![
                    record.hostname.as_str(),
                    record.tunnel_id.as_str(),
                    record.status.as_raw()
                ],
            )
            .map_err(storage)?;
        store_version(&transaction, next_version)?;
        transaction.commit().map_err(storage)?;
        Ok(HttpsRouteMutationOutcome::Applied {
            previous: current_version,
            current: next_version,
        })
    }

    pub fn remove(
        &self,
        hostname: &PublicHostname,
    ) -> Result<HttpsRouteMutationOutcome, HttpsRouteRepositoryError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current_catalog = load_catalog(&transaction)?;
        let current_version = current_catalog.version();
        let exists = current_catalog
            .routes()
            .iter()
            .any(|candidate| candidate.hostname == *hostname);
        if !exists {
            return Ok(HttpsRouteMutationOutcome::Unchanged {
                version: current_version,
            });
        }
        let next_version = current_version.next()?;
        transaction
            .execute(
                "DELETE FROM https_routes WHERE hostname = ?1",
                [hostname.as_str()],
            )
            .map_err(storage)?;
        store_version(&transaction, next_version)?;
        transaction.commit().map_err(storage)?;
        Ok(HttpsRouteMutationOutcome::Applied {
            previous: current_version,
            current: next_version,
        })
    }

    fn connect(&self) -> Result<Connection, HttpsRouteRepositoryError> {
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

impl std::fmt::Debug for HttpsRouteRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpsRouteRepository")
            .finish_non_exhaustive()
    }
}

fn migrate(connection: &Connection) -> Result<(), HttpsRouteRepositoryError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS https_route_catalog_head (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
                version BLOB NOT NULL CHECK(length(version) = 8)
            );
            CREATE TABLE IF NOT EXISTS https_routes (
                hostname TEXT PRIMARY KEY,
                tunnel_id TEXT NOT NULL,
                status INTEGER NOT NULL CHECK(status IN (1, 2))
            );
            INSERT INTO https_route_catalog_head(singleton_id, version)
            VALUES (1, X'0000000000000001')
            ON CONFLICT(singleton_id) DO NOTHING;",
        )
        .map_err(storage)
}

fn load_catalog(connection: &Connection) -> Result<HttpsRouteCatalog, HttpsRouteRepositoryError> {
    let version = load_version(connection)?;
    let mut statement = connection
        .prepare(
            "SELECT hostname, tunnel_id, status FROM https_routes
             ORDER BY hostname LIMIT ?1",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(
            [i64::try_from(MAX_HTTPS_ROUTE_RECORDS + 1).unwrap()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(storage)?;
    let mut routes = Vec::new();
    for row in rows {
        let (hostname, tunnel_id, status) = row.map_err(storage)?;
        if routes.len() == MAX_HTTPS_ROUTE_RECORDS {
            return Err(HttpsRouteRepositoryError::CapacityExceeded);
        }
        routes.push(HttpsRouteRecord::new(
            PublicHostname::new(hostname).map_err(|_| HttpsRouteRepositoryError::Corrupt)?,
            TunnelId::new(tunnel_id).map_err(|_| HttpsRouteRepositoryError::Corrupt)?,
            HttpsRouteStatus::from_raw(status)?,
        ));
    }
    Ok(HttpsRouteCatalog { version, routes })
}

fn load_version(
    connection: &Connection,
) -> Result<HttpsRouteCatalogVersion, HttpsRouteRepositoryError> {
    let bytes = connection
        .query_row(
            "SELECT version FROM https_route_catalog_head WHERE singleton_id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(storage)?
        .ok_or(HttpsRouteRepositoryError::Corrupt)?;
    decode_version(&bytes)
}

fn store_version(
    transaction: &Transaction<'_>,
    version: HttpsRouteCatalogVersion,
) -> Result<(), HttpsRouteRepositoryError> {
    transaction
        .execute(
            "UPDATE https_route_catalog_head SET version = ?1 WHERE singleton_id = 1",
            [version.get().to_be_bytes().as_slice()],
        )
        .map_err(storage)?;
    Ok(())
}

fn decode_version(bytes: &[u8]) -> Result<HttpsRouteCatalogVersion, HttpsRouteRepositoryError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| HttpsRouteRepositoryError::Corrupt)?;
    HttpsRouteCatalogVersion::new(u64::from_be_bytes(bytes))
        .ok_or(HttpsRouteRepositoryError::Corrupt)
}

fn storage(error: rusqlite::Error) -> HttpsRouteRepositoryError {
    HttpsRouteRepositoryError::Storage(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsRouteRepositoryError {
    Storage(String),
    Corrupt,
    CapacityExceeded,
    VersionExhausted,
}

impl std::fmt::Display for HttpsRouteRepositoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Storage(_) => "HTTPS route repository operation failed",
            Self::Corrupt => "HTTPS route repository contains invalid data",
            Self::CapacityExceeded => "HTTPS route catalog capacity is exhausted",
            Self::VersionExhausted => "HTTPS route catalog version is exhausted",
        })
    }
}

impl std::error::Error for HttpsRouteRepositoryError {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{
        AuthorizationSnapshot, SnapshotRepository, SnapshotVersion, SqliteSnapshotRepository,
        VersionedAuthorizationSnapshot,
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn temp_database() -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "tunnelproxy-https-routes-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        (directory.join("state.sqlite"), directory)
    }

    fn record(hostname: &str, tunnel: &str, status: HttpsRouteStatus) -> HttpsRouteRecord {
        HttpsRouteRecord::new(
            PublicHostname::new(hostname).unwrap(),
            TunnelId::new(tunnel).unwrap(),
            status,
        )
    }

    #[test]
    fn upsert_is_transactional_idempotent_and_survives_reopen() {
        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        assert_eq!(
            repository.load().unwrap().version(),
            HttpsRouteCatalogVersion::FIRST
        );
        let first = record("Demo.Example.test.", "tunnel-a", HttpsRouteStatus::Enabled);
        assert_eq!(
            repository.upsert(&first).unwrap(),
            HttpsRouteMutationOutcome::Applied {
                previous: HttpsRouteCatalogVersion::new(1).unwrap(),
                current: HttpsRouteCatalogVersion::new(2).unwrap(),
            }
        );
        assert!(matches!(
            repository.upsert(&first).unwrap(),
            HttpsRouteMutationOutcome::Unchanged { version }
                if version == HttpsRouteCatalogVersion::new(2).unwrap()
        ));
        let changed = record("demo.example.test", "tunnel-b", HttpsRouteStatus::Disabled);
        repository.upsert(&changed).unwrap();
        drop(repository);
        let catalog = HttpsRouteRepository::open(&path).unwrap().load().unwrap();
        assert_eq!(catalog.version().get(), 3);
        assert_eq!(catalog.routes(), &[changed]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn remove_is_idempotent_and_catalog_is_sorted() {
        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        let second = record("z.example.test", "tunnel-z", HttpsRouteStatus::Enabled);
        let first = record("a.example.test", "tunnel-a", HttpsRouteStatus::Enabled);
        repository.upsert(&second).unwrap();
        repository.upsert(&first).unwrap();
        assert_eq!(
            repository.load().unwrap().routes(),
            &[first.clone(), second]
        );
        let removed = repository.remove(&first.hostname).unwrap();
        assert!(matches!(removed, HttpsRouteMutationOutcome::Applied { .. }));
        let unchanged = repository.remove(&first.hostname).unwrap();
        assert!(matches!(
            unchanged,
            HttpsRouteMutationOutcome::Unchanged { .. }
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn capacity_and_version_exhaustion_fail_without_partial_mutation() {
        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        for index in 0..MAX_HTTPS_ROUTE_RECORDS {
            repository
                .upsert(&record(
                    &format!("route-{index}.example.test"),
                    "tunnel-a",
                    HttpsRouteStatus::Enabled,
                ))
                .unwrap();
        }
        assert_eq!(
            repository.upsert(&record(
                "overflow.example.test",
                "tunnel-a",
                HttpsRouteStatus::Enabled,
            )),
            Err(HttpsRouteRepositoryError::CapacityExceeded)
        );
        assert_eq!(
            repository.load().unwrap().routes().len(),
            MAX_HTTPS_ROUTE_RECORDS
        );
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE https_route_catalog_head SET version = ?1 WHERE singleton_id = 1",
                [u64::MAX.to_be_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            repository.remove(&PublicHostname::new("route-0.example.test").unwrap()),
            Err(HttpsRouteRepositoryError::VersionExhausted)
        );
        assert_eq!(
            repository.load().unwrap().routes().len(),
            MAX_HTTPS_ROUTE_RECORDS
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn corrupt_rows_fail_closed() {
        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        repository
            .upsert(&record(
                "demo.example.test",
                "tunnel-a",
                HttpsRouteStatus::Enabled,
            ))
            .unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("PRAGMA ignore_check_constraints = ON", [])
            .unwrap();
        connection
            .execute("UPDATE https_routes SET hostname = 'bad_host'", [])
            .unwrap();
        drop(connection);
        assert_eq!(repository.load(), Err(HttpsRouteRepositoryError::Corrupt));
        assert_eq!(
            repository.upsert(&record(
                "other.example.test",
                "tunnel-b",
                HttpsRouteStatus::Enabled,
            )),
            Err(HttpsRouteRepositoryError::Corrupt)
        );
        assert_eq!(
            repository.remove(&PublicHostname::new("demo.example.test").unwrap()),
            Err(HttpsRouteRepositoryError::Corrupt)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn route_migration_preserves_existing_snapshot_state() {
        let (path, directory) = temp_database();
        let snapshot = VersionedAuthorizationSnapshot::new(
            SnapshotVersion::new(9).unwrap(),
            AuthorizationSnapshot::default(),
        );
        let snapshots = SqliteSnapshotRepository::open(&path).unwrap();
        snapshots.commit(&snapshot).unwrap();
        let routes = HttpsRouteRepository::open(&path).unwrap();
        routes
            .upsert(&record(
                "demo.example.test",
                "tunnel-a",
                HttpsRouteStatus::Enabled,
            ))
            .unwrap();
        assert_eq!(snapshots.load_latest().unwrap(), Some(snapshot));
        assert_eq!(routes.load().unwrap().routes().len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
