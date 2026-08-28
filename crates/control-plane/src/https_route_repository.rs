//! Transactional, versioned HTTPS hostname route catalog.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use tunnelproxy_common::{PublicHostname, TunnelId};

pub const MAX_HTTPS_ROUTE_RECORDS: usize = 64;
pub const MANAGED_HOSTNAME_ENTROPY_BYTES: usize = 16;
pub const MAX_MANAGED_HOSTNAME_ALLOCATION_ATTEMPTS: usize = 16;

const MANAGED_HOSTNAME_PREFIX: &str = "tp-";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedHostnameBaseDomain(PublicHostname);

impl ManagedHostnameBaseDomain {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ManagedHostnameBaseDomainError> {
        let domain = PublicHostname::new(value)
            .map_err(|_| ManagedHostnameBaseDomainError::InvalidHostname)?;
        managed_hostname_from_entropy(&domain, &[0; MANAGED_HOSTNAME_ENTROPY_BYTES])
            .map_err(|_| ManagedHostnameBaseDomainError::TooLong)?;
        Ok(Self(domain))
    }

    pub fn as_hostname(&self) -> &PublicHostname {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for ManagedHostnameBaseDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedHostnameBaseDomainError {
    InvalidHostname,
    TooLong,
}

impl std::fmt::Display for ManagedHostnameBaseDomainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHostname => "managed hostname base domain is not a valid public hostname",
            Self::TooLong => "managed hostname base domain leaves no room for an allocation label",
        })
    }
}

impl std::error::Error for ManagedHostnameBaseDomainError {}

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
    pub fn new(
        version: HttpsRouteCatalogVersion,
        mut routes: Vec<HttpsRouteRecord>,
    ) -> Result<Self, HttpsRouteCatalogError> {
        if routes.len() > MAX_HTTPS_ROUTE_RECORDS {
            return Err(HttpsRouteCatalogError::TooManyRoutes);
        }
        routes.sort_unstable_by(|left, right| left.hostname.cmp(&right.hostname));
        if routes
            .windows(2)
            .any(|pair| pair[0].hostname == pair[1].hostname)
        {
            return Err(HttpsRouteCatalogError::DuplicateHostname);
        }
        Ok(Self { version, routes })
    }

    pub const fn version(&self) -> HttpsRouteCatalogVersion {
        self.version
    }

    pub fn routes(&self) -> &[HttpsRouteRecord] {
        &self.routes
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsRouteCatalogError {
    TooManyRoutes,
    DuplicateHostname,
}

impl std::fmt::Display for HttpsRouteCatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TooManyRoutes => "HTTPS route catalog exceeds its route limit",
            Self::DuplicateHostname => "HTTPS route catalog contains a duplicate hostname",
        })
    }
}

impl std::error::Error for HttpsRouteCatalogError {}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedHostnameAllocationOutcome {
    Allocated {
        hostname: PublicHostname,
        previous: HttpsRouteCatalogVersion,
        current: HttpsRouteCatalogVersion,
    },
    Existing {
        hostname: PublicHostname,
        version: HttpsRouteCatalogVersion,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedHostnameReleaseOutcome {
    Released {
        hostname: PublicHostname,
        previous: HttpsRouteCatalogVersion,
        current: HttpsRouteCatalogVersion,
    },
    Absent {
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
        validate_managed_hostnames(&connection)?;
        Ok(repository)
    }

    pub fn load(&self) -> Result<HttpsRouteCatalog, HttpsRouteRepositoryError> {
        let connection = self.connect()?;
        let catalog = load_catalog(&connection)?;
        validate_managed_hostnames(&connection)?;
        Ok(catalog)
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
        validate_managed_hostnames(&transaction)?;
        let current_version = current_catalog.version();
        if is_managed_hostname(&transaction, &record.hostname)? {
            return Err(HttpsRouteRepositoryError::ManagedHostnameConflict);
        }
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
        validate_managed_hostnames(&transaction)?;
        let current_version = current_catalog.version();
        if is_managed_hostname(&transaction, hostname)? {
            return Err(HttpsRouteRepositoryError::ManagedHostnameConflict);
        }
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

    pub fn allocate_managed_hostname(
        &self,
        tunnel_id: &TunnelId,
        base_domain: &ManagedHostnameBaseDomain,
    ) -> Result<ManagedHostnameAllocationOutcome, HttpsRouteRepositoryError> {
        self.allocate_managed_hostname_with(tunnel_id, base_domain, |entropy| {
            getrandom::getrandom(entropy).map_err(|_| HttpsRouteRepositoryError::EntropyUnavailable)
        })
    }

    fn allocate_managed_hostname_with<F>(
        &self,
        tunnel_id: &TunnelId,
        base_domain: &ManagedHostnameBaseDomain,
        mut fill_entropy: F,
    ) -> Result<ManagedHostnameAllocationOutcome, HttpsRouteRepositoryError>
    where
        F: FnMut(&mut [u8]) -> Result<(), HttpsRouteRepositoryError>,
    {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current_catalog = load_catalog(&transaction)?;
        validate_managed_hostnames(&transaction)?;
        let current_version = current_catalog.version();
        if let Some((hostname, existing_base_domain)) =
            managed_hostname_for_tunnel(&transaction, tunnel_id)?
        {
            if &existing_base_domain != base_domain {
                return Err(HttpsRouteRepositoryError::ManagedBaseDomainConflict);
            }
            return Ok(ManagedHostnameAllocationOutcome::Existing {
                hostname,
                version: current_version,
            });
        }
        if current_catalog.routes().len() >= MAX_HTTPS_ROUTE_RECORDS {
            return Err(HttpsRouteRepositoryError::CapacityExceeded);
        }
        let next_version = current_version.next()?;
        let mut entropy = [0_u8; MANAGED_HOSTNAME_ENTROPY_BYTES];
        let mut selected = None;
        for _ in 0..MAX_MANAGED_HOSTNAME_ALLOCATION_ATTEMPTS {
            fill_entropy(&mut entropy)?;
            let candidate = managed_hostname_from_entropy(base_domain.as_hostname(), &entropy)
                .map_err(|_| HttpsRouteRepositoryError::Corrupt)?;
            if !hostname_exists(&transaction, &candidate)? {
                selected = Some(candidate);
                break;
            }
        }
        let hostname = selected.ok_or(HttpsRouteRepositoryError::AllocationAttemptsExhausted)?;
        transaction
            .execute(
                "INSERT INTO https_routes(hostname, tunnel_id, status) VALUES (?1, ?2, ?3)",
                params![
                    hostname.as_str(),
                    tunnel_id.as_str(),
                    HttpsRouteStatus::Enabled.as_raw()
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO managed_https_hostnames(tunnel_id, hostname, base_domain)
                 VALUES (?1, ?2, ?3)",
                params![tunnel_id.as_str(), hostname.as_str(), base_domain.as_str()],
            )
            .map_err(storage)?;
        store_version(&transaction, next_version)?;
        transaction.commit().map_err(storage)?;
        Ok(ManagedHostnameAllocationOutcome::Allocated {
            hostname,
            previous: current_version,
            current: next_version,
        })
    }

    pub fn release_managed_hostname(
        &self,
        tunnel_id: &TunnelId,
    ) -> Result<ManagedHostnameReleaseOutcome, HttpsRouteRepositoryError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current_catalog = load_catalog(&transaction)?;
        validate_managed_hostnames(&transaction)?;
        let current_version = current_catalog.version();
        let Some((hostname, _)) = managed_hostname_for_tunnel(&transaction, tunnel_id)? else {
            return Ok(ManagedHostnameReleaseOutcome::Absent {
                version: current_version,
            });
        };
        let next_version = current_version.next()?;
        transaction
            .execute(
                "DELETE FROM managed_https_hostnames WHERE tunnel_id = ?1",
                [tunnel_id.as_str()],
            )
            .map_err(storage)?;
        let removed = transaction
            .execute(
                "DELETE FROM https_routes WHERE hostname = ?1 AND tunnel_id = ?2",
                params![hostname.as_str(), tunnel_id.as_str()],
            )
            .map_err(storage)?;
        if removed != 1 {
            return Err(HttpsRouteRepositoryError::Corrupt);
        }
        store_version(&transaction, next_version)?;
        transaction.commit().map_err(storage)?;
        Ok(ManagedHostnameReleaseOutcome::Released {
            hostname,
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
            CREATE TABLE IF NOT EXISTS managed_https_hostnames (
                tunnel_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL UNIQUE,
                base_domain TEXT NOT NULL,
                FOREIGN KEY(hostname) REFERENCES https_routes(hostname) ON DELETE RESTRICT
            );
            INSERT INTO https_route_catalog_head(singleton_id, version)
            VALUES (1, X'0000000000000001')
            ON CONFLICT(singleton_id) DO NOTHING;",
        )
        .map_err(storage)
}

fn validate_managed_hostnames(connection: &Connection) -> Result<(), HttpsRouteRepositoryError> {
    let mut statement = connection
        .prepare(
            "SELECT managed.tunnel_id, managed.hostname, managed.base_domain,
                    routes.tunnel_id, routes.status
             FROM managed_https_hostnames AS managed
             LEFT JOIN https_routes AS routes ON routes.hostname = managed.hostname
             ORDER BY managed.tunnel_id LIMIT ?1",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(
            [i64::try_from(MAX_HTTPS_ROUTE_RECORDS + 1).unwrap()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .map_err(storage)?;
    for (count, row) in rows.enumerate() {
        if count == MAX_HTTPS_ROUTE_RECORDS {
            return Err(HttpsRouteRepositoryError::Corrupt);
        }
        let (raw_tunnel, raw_hostname, raw_base_domain, route_tunnel, route_status) =
            row.map_err(storage)?;
        let tunnel_id =
            TunnelId::new(raw_tunnel).map_err(|_| HttpsRouteRepositoryError::Corrupt)?;
        let hostname =
            PublicHostname::new(&raw_hostname).map_err(|_| HttpsRouteRepositoryError::Corrupt)?;
        let base_domain = ManagedHostnameBaseDomain::new(&raw_base_domain)
            .map_err(|_| HttpsRouteRepositoryError::Corrupt)?;
        if hostname.as_str() != raw_hostname
            || base_domain.as_str() != raw_base_domain
            || route_tunnel.as_deref() != Some(tunnel_id.as_str())
            || route_status != Some(HttpsRouteStatus::Enabled.as_raw())
            || !managed_hostname_matches(&hostname, &base_domain)
        {
            return Err(HttpsRouteRepositoryError::Corrupt);
        }
    }
    Ok(())
}

fn managed_hostname_for_tunnel(
    connection: &Connection,
    tunnel_id: &TunnelId,
) -> Result<Option<(PublicHostname, ManagedHostnameBaseDomain)>, HttpsRouteRepositoryError> {
    let allocation = connection
        .query_row(
            "SELECT hostname, base_domain FROM managed_https_hostnames WHERE tunnel_id = ?1",
            [tunnel_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage)?;
    allocation
        .map(|(hostname, base_domain)| {
            Ok((
                PublicHostname::new(hostname).map_err(|_| HttpsRouteRepositoryError::Corrupt)?,
                ManagedHostnameBaseDomain::new(base_domain)
                    .map_err(|_| HttpsRouteRepositoryError::Corrupt)?,
            ))
        })
        .transpose()
}

fn is_managed_hostname(
    connection: &Connection,
    hostname: &PublicHostname,
) -> Result<bool, HttpsRouteRepositoryError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_https_hostnames WHERE hostname = ?1)",
            [hostname.as_str()],
            |row| row.get(0),
        )
        .map_err(storage)
}

fn hostname_exists(
    connection: &Connection,
    hostname: &PublicHostname,
) -> Result<bool, HttpsRouteRepositoryError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM https_routes WHERE hostname = ?1)",
            [hostname.as_str()],
            |row| row.get(0),
        )
        .map_err(storage)
}

fn managed_hostname_from_entropy(
    base_domain: &PublicHostname,
    entropy: &[u8; MANAGED_HOSTNAME_ENTROPY_BYTES],
) -> Result<PublicHostname, tunnelproxy_common::PublicHostnameError> {
    let mut label = String::with_capacity(MANAGED_HOSTNAME_PREFIX.len() + entropy.len() * 2);
    label.push_str(MANAGED_HOSTNAME_PREFIX);
    for byte in entropy {
        label.push(LOWER_HEX[usize::from(byte >> 4)] as char);
        label.push(LOWER_HEX[usize::from(byte & 0x0f)] as char);
    }
    PublicHostname::new(format!("{label}.{}", base_domain.as_str()))
}

fn managed_hostname_matches(
    hostname: &PublicHostname,
    base_domain: &ManagedHostnameBaseDomain,
) -> bool {
    let Some(label) = hostname
        .as_str()
        .strip_suffix(base_domain.as_str())
        .and_then(|prefix| prefix.strip_suffix('.'))
    else {
        return false;
    };
    label.len() == MANAGED_HOSTNAME_PREFIX.len() + MANAGED_HOSTNAME_ENTROPY_BYTES * 2
        && label.starts_with(MANAGED_HOSTNAME_PREFIX)
        && label[MANAGED_HOSTNAME_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    HttpsRouteCatalog::new(version, routes).map_err(|error| match error {
        HttpsRouteCatalogError::TooManyRoutes => HttpsRouteRepositoryError::CapacityExceeded,
        HttpsRouteCatalogError::DuplicateHostname => HttpsRouteRepositoryError::Corrupt,
    })
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
    ManagedHostnameConflict,
    ManagedBaseDomainConflict,
    EntropyUnavailable,
    AllocationAttemptsExhausted,
}

impl std::fmt::Display for HttpsRouteRepositoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Storage(_) => "HTTPS route repository operation failed",
            Self::Corrupt => "HTTPS route repository contains invalid data",
            Self::CapacityExceeded => "HTTPS route catalog capacity is exhausted",
            Self::VersionExhausted => "HTTPS route catalog version is exhausted",
            Self::ManagedHostnameConflict => {
                "managed hostname must be changed through its lifecycle commands"
            }
            Self::ManagedBaseDomainConflict => {
                "managed hostname already exists under a different base domain"
            }
            Self::EntropyUnavailable => "managed hostname entropy source is unavailable",
            Self::AllocationAttemptsExhausted => {
                "managed hostname allocation collision retry limit was exhausted"
            }
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
    fn managed_hostname_lifecycle_is_atomic_idempotent_and_owned() {
        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        let tunnel_id = TunnelId::new("managed-tunnel").unwrap();
        let base_domain = ManagedHostnameBaseDomain::new("Example.TEST.").unwrap();
        assert_eq!(base_domain.as_str(), "example.test");
        let allocated = repository
            .allocate_managed_hostname_with(&tunnel_id, &base_domain, |entropy| {
                entropy.fill(0xab);
                Ok(())
            })
            .unwrap();
        let expected = managed_hostname_from_entropy(
            base_domain.as_hostname(),
            &[0xab; MANAGED_HOSTNAME_ENTROPY_BYTES],
        )
        .unwrap();
        assert_eq!(
            allocated,
            ManagedHostnameAllocationOutcome::Allocated {
                hostname: expected.clone(),
                previous: HttpsRouteCatalogVersion::new(1).unwrap(),
                current: HttpsRouteCatalogVersion::new(2).unwrap(),
            }
        );
        assert_eq!(
            repository.load().unwrap().routes(),
            &[HttpsRouteRecord::new(
                expected.clone(),
                tunnel_id.clone(),
                HttpsRouteStatus::Enabled,
            )]
        );
        assert_eq!(
            repository.upsert(&HttpsRouteRecord::new(
                expected.clone(),
                tunnel_id.clone(),
                HttpsRouteStatus::Enabled,
            )),
            Err(HttpsRouteRepositoryError::ManagedHostnameConflict)
        );
        assert_eq!(
            repository.remove(&expected),
            Err(HttpsRouteRepositoryError::ManagedHostnameConflict)
        );
        let existing = repository
            .allocate_managed_hostname_with(&tunnel_id, &base_domain, |_| {
                panic!("idempotent allocation must not request new entropy")
            })
            .unwrap();
        assert_eq!(
            existing,
            ManagedHostnameAllocationOutcome::Existing {
                hostname: expected.clone(),
                version: HttpsRouteCatalogVersion::new(2).unwrap(),
            }
        );
        assert_eq!(
            repository.allocate_managed_hostname_with(
                &tunnel_id,
                &ManagedHostnameBaseDomain::new("other.example").unwrap(),
                |_| panic!("conflicting base domain must not request entropy"),
            ),
            Err(HttpsRouteRepositoryError::ManagedBaseDomainConflict)
        );

        drop(repository);
        let repository = HttpsRouteRepository::open(&path).unwrap();
        assert_eq!(
            repository.release_managed_hostname(&tunnel_id).unwrap(),
            ManagedHostnameReleaseOutcome::Released {
                hostname: expected,
                previous: HttpsRouteCatalogVersion::new(2).unwrap(),
                current: HttpsRouteCatalogVersion::new(3).unwrap(),
            }
        );
        assert_eq!(
            repository.release_managed_hostname(&tunnel_id).unwrap(),
            ManagedHostnameReleaseOutcome::Absent {
                version: HttpsRouteCatalogVersion::new(3).unwrap(),
            }
        );
        assert!(repository.load().unwrap().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn managed_hostname_collision_retry_and_failures_leave_no_partial_state() {
        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        let base_domain = ManagedHostnameBaseDomain::new("example.test").unwrap();
        let collision = managed_hostname_from_entropy(
            base_domain.as_hostname(),
            &[0; MANAGED_HOSTNAME_ENTROPY_BYTES],
        )
        .unwrap();
        repository
            .upsert(&HttpsRouteRecord::new(
                collision,
                TunnelId::new("manual-tunnel").unwrap(),
                HttpsRouteStatus::Enabled,
            ))
            .unwrap();
        let mut attempt = 0_u8;
        let tunnel = TunnelId::new("managed-tunnel").unwrap();
        let allocated = repository
            .allocate_managed_hostname_with(&tunnel, &base_domain, |entropy| {
                entropy.fill(attempt);
                attempt += 1;
                Ok(())
            })
            .unwrap();
        let expected = managed_hostname_from_entropy(
            base_domain.as_hostname(),
            &[1; MANAGED_HOSTNAME_ENTROPY_BYTES],
        )
        .unwrap();
        assert!(matches!(
            allocated,
            ManagedHostnameAllocationOutcome::Allocated { hostname, current, .. }
                if hostname == expected && current.get() == 3
        ));

        let before = repository.load().unwrap();
        assert_eq!(
            repository.allocate_managed_hostname_with(
                &TunnelId::new("collision-exhausted").unwrap(),
                &base_domain,
                |entropy| {
                    entropy.fill(0);
                    Ok(())
                },
            ),
            Err(HttpsRouteRepositoryError::AllocationAttemptsExhausted)
        );
        assert_eq!(repository.load().unwrap(), before);
        assert_eq!(
            repository.allocate_managed_hostname_with(
                &TunnelId::new("entropy-failed").unwrap(),
                &base_domain,
                |_| Err(HttpsRouteRepositoryError::EntropyUnavailable),
            ),
            Err(HttpsRouteRepositoryError::EntropyUnavailable)
        );
        assert_eq!(repository.load().unwrap(), before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn managed_hostname_base_domain_and_version_bounds_fail_before_mutation() {
        assert_eq!(
            ManagedHostnameBaseDomain::new("*.example.test"),
            Err(ManagedHostnameBaseDomainError::InvalidHostname)
        );
        assert_eq!(
            ManagedHostnameBaseDomain::new(format!(
                "{}.{}.{}.{}.test",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(21),
            )),
            Err(ManagedHostnameBaseDomainError::TooLong)
        );

        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE https_route_catalog_head SET version = ?1 WHERE singleton_id = 1",
                [u64::MAX.to_be_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            repository.allocate_managed_hostname_with(
                &TunnelId::new("version-exhausted").unwrap(),
                &ManagedHostnameBaseDomain::new("example.test").unwrap(),
                |_| panic!("version exhaustion must be checked before entropy"),
            ),
            Err(HttpsRouteRepositoryError::VersionExhausted)
        );
        assert!(repository.load().unwrap().is_empty());
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
        assert_eq!(
            repository.allocate_managed_hostname_with(
                &TunnelId::new("managed-overflow").unwrap(),
                &ManagedHostnameBaseDomain::new("example.test").unwrap(),
                |_| panic!("capacity exhaustion must be checked before entropy"),
            ),
            Err(HttpsRouteRepositoryError::CapacityExceeded)
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
    fn corrupt_managed_hostname_metadata_fails_closed() {
        let (path, directory) = temp_database();
        let repository = HttpsRouteRepository::open(&path).unwrap();
        let tunnel = TunnelId::new("managed-corrupt").unwrap();
        repository
            .allocate_managed_hostname_with(
                &tunnel,
                &ManagedHostnameBaseDomain::new("example.test").unwrap(),
                |entropy| {
                    entropy.fill(0x42);
                    Ok(())
                },
            )
            .unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE managed_https_hostnames SET base_domain = 'other.test'",
                [],
            )
            .unwrap();
        drop(connection);
        assert_eq!(repository.load(), Err(HttpsRouteRepositoryError::Corrupt));
        assert_eq!(
            repository.release_managed_hostname(&tunnel),
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

    #[test]
    fn managed_hostname_migration_preserves_legacy_routes_as_operator_owned() {
        let (path, directory) = temp_database();
        SqliteSnapshotRepository::open(&path).unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE https_route_catalog_head (
                    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
                    version BLOB NOT NULL CHECK(length(version) = 8)
                );
                CREATE TABLE https_routes (
                    hostname TEXT PRIMARY KEY,
                    tunnel_id TEXT NOT NULL,
                    status INTEGER NOT NULL CHECK(status IN (1, 2))
                );
                INSERT INTO https_route_catalog_head(singleton_id, version)
                VALUES (1, X'0000000000000002');
                INSERT INTO https_routes(hostname, tunnel_id, status)
                VALUES ('legacy.example.test', 'legacy-tunnel', 1);",
            )
            .unwrap();
        drop(connection);

        let repository = HttpsRouteRepository::open(&path).unwrap();
        let legacy = record(
            "legacy.example.test",
            "legacy-tunnel",
            HttpsRouteStatus::Enabled,
        );
        assert_eq!(
            repository.load().unwrap().routes(),
            std::slice::from_ref(&legacy)
        );
        assert_eq!(
            repository.upsert(&legacy).unwrap(),
            HttpsRouteMutationOutcome::Unchanged {
                version: HttpsRouteCatalogVersion::new(2).unwrap(),
            }
        );
        assert!(matches!(
            repository.remove(&legacy.hostname).unwrap(),
            HttpsRouteMutationOutcome::Applied { current, .. } if current.get() == 3
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
