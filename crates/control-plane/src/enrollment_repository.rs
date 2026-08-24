use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use tunnelproxy_common::{AgentId, TunnelId};
use tunnelproxy_protocol::EnrollmentRequestId;

use crate::{
    snapshot_digest, AgentGrant, AuthorizationSnapshot, CertificateFingerprint, SnapshotVersion,
    TunnelGrant, TunnelStatus, VersionedAuthorizationSnapshot,
};

#[derive(Debug, Clone)]
pub struct EnrollmentRepository {
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct EnrollmentTokenBinding {
    pub agent_id: AgentId,
    pub tunnel_id: TunnelId,
}

#[derive(Debug, Clone)]
pub struct IssuanceCandidate {
    pub request_id: EnrollmentRequestId,
    pub presented_token_hash: [u8; 32],
    pub next_token_hash: [u8; 32],
    pub agent_id: AgentId,
    pub tunnel_id: TunnelId,
    pub csr_digest: [u8; 32],
    pub certificate_pem: Vec<u8>,
    pub fingerprint: CertificateFingerprint,
    pub not_after_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableIssuance {
    pub generation: SnapshotVersion,
    pub certificate_pem: Vec<u8>,
    pub fingerprint: CertificateFingerprint,
    pub not_after_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresentedTokenKind {
    Bootstrap,
    Renewal(CertificateFingerprint),
}

impl EnrollmentRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EnrollmentRepositoryError> {
        let path = path.as_ref().to_path_buf();
        crate::SqliteSnapshotRepository::open(&path)
            .map_err(|_| EnrollmentRepositoryError::Storage)?;
        let repository = Self { path };
        let connection = repository.connect()?;
        migrate(&connection)?;
        Ok(repository)
    }

    fn connect(&self) -> Result<Connection, EnrollmentRepositoryError> {
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

    pub fn create_bootstrap_token(
        &self,
        token_hash: [u8; 32],
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
        expires_at_unix: u64,
    ) -> Result<(), EnrollmentRepositoryError> {
        let expires =
            i64::try_from(expires_at_unix).map_err(|_| EnrollmentRepositoryError::InvalidTime)?;
        self.connect()?
            .execute(
                "INSERT INTO enrollment_bootstrap_tokens(
                    token_hash, agent_id, tunnel_id, expires_at, consumed
                 ) VALUES (?1, ?2, ?3, ?4, 0)",
                params![
                    token_hash.as_slice(),
                    agent_id.as_str(),
                    tunnel_id.as_str(),
                    expires
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    EnrollmentRepositoryError::Conflict
                } else {
                    storage(error)
                }
            })?;
        Ok(())
    }

    pub fn validate_token(
        &self,
        token_hash: [u8; 32],
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
        now_unix: u64,
    ) -> Result<EnrollmentTokenBinding, EnrollmentRepositoryError> {
        let connection = self.connect()?;
        authenticate_token(&connection, token_hash, agent_id, tunnel_id, now_unix)?;
        Ok(EnrollmentTokenBinding {
            agent_id: agent_id.clone(),
            tunnel_id: tunnel_id.clone(),
        })
    }

    pub fn commit_issuance(
        &self,
        candidate: &IssuanceCandidate,
        now_unix: u64,
    ) -> Result<DurableIssuance, EnrollmentRepositoryError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;

        if let Some(existing) = load_issuance(&transaction, candidate.request_id)? {
            verify_idempotent_candidate(&existing, candidate)?;
            transaction.commit().map_err(storage)?;
            return Ok(existing.issuance);
        }

        let token_kind = authenticate_token(
            &transaction,
            candidate.presented_token_hash,
            &candidate.agent_id,
            &candidate.tunnel_id,
            now_unix,
        )?;
        let current = load_snapshot(&transaction)?;
        let generation = next_version(current.version())?;
        let mut grants = current.snapshot().grants();
        if grants
            .iter()
            .any(|grant| grant.certificate == candidate.fingerprint)
        {
            return Err(EnrollmentRepositoryError::Conflict);
        }
        grants.push(AgentGrant::new(
            candidate.fingerprint,
            candidate.agent_id.clone(),
            vec![TunnelGrant::new(
                candidate.tunnel_id.clone(),
                TunnelStatus::Enabled,
            )],
        ));
        let snapshot = VersionedAuthorizationSnapshot::new(
            generation,
            AuthorizationSnapshot::new(grants).map_err(|_| EnrollmentRepositoryError::Corrupt)?,
        );
        replace_snapshot(&transaction, &snapshot)?;

        let previous = match token_kind {
            PresentedTokenKind::Bootstrap => None,
            PresentedTokenKind::Renewal(fingerprint) => Some(fingerprint),
        };
        transaction
            .execute(
                "INSERT INTO agent_credentials(
                    fingerprint, request_id, agent_id, tunnel_id, csr_digest,
                    auth_token_hash, renewal_token_hash, certificate_pem,
                    not_after, generation, state, previous_fingerprint
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11)",
                params![
                    candidate.fingerprint.as_bytes().as_slice(),
                    candidate.request_id.as_bytes().as_slice(),
                    candidate.agent_id.as_str(),
                    candidate.tunnel_id.as_str(),
                    candidate.csr_digest.as_slice(),
                    candidate.presented_token_hash.as_slice(),
                    candidate.next_token_hash.as_slice(),
                    candidate.certificate_pem,
                    i64::try_from(candidate.not_after_unix)
                        .map_err(|_| EnrollmentRepositoryError::InvalidTime)?,
                    generation.get().to_be_bytes().as_slice(),
                    previous.map(|value| value.as_bytes().to_vec()),
                ],
            )
            .map_err(storage)?;
        if token_kind == PresentedTokenKind::Bootstrap {
            transaction
                .execute(
                    "UPDATE enrollment_bootstrap_tokens SET consumed = 1
                     WHERE token_hash = ?1",
                    [candidate.presented_token_hash.as_slice()],
                )
                .map_err(storage)?;
        }
        transaction.commit().map_err(storage)?;
        Ok(DurableIssuance {
            generation,
            certificate_pem: candidate.certificate_pem.clone(),
            fingerprint: candidate.fingerprint,
            not_after_unix: candidate.not_after_unix,
        })
    }

    /// Authenticates an issuance before CSR signing. A durable result is
    /// returned for an exact retry, including after a bootstrap token was
    /// consumed by the original transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn preflight_issuance(
        &self,
        request_id: EnrollmentRequestId,
        presented_token_hash: [u8; 32],
        next_token_hash: [u8; 32],
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
        csr_digest: [u8; 32],
        now_unix: u64,
    ) -> Result<Option<DurableIssuance>, EnrollmentRepositoryError> {
        let connection = self.connect()?;
        if let Some(existing) = load_issuance(&connection, request_id)? {
            verify_idempotent_fields(
                &existing,
                presented_token_hash,
                next_token_hash,
                agent_id,
                tunnel_id,
                csr_digest,
            )?;
            return Ok(Some(existing.issuance));
        }
        authenticate_token(
            &connection,
            presented_token_hash,
            agent_id,
            tunnel_id,
            now_unix,
        )?;
        Ok(None)
    }

    pub fn activate(
        &self,
        request_id: EnrollmentRequestId,
        renewal_token_hash: [u8; 32],
        fingerprint: CertificateFingerprint,
    ) -> Result<SnapshotVersion, EnrollmentRepositoryError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row = transaction
            .query_row(
                "SELECT state, previous_fingerprint FROM agent_credentials
                 WHERE request_id = ?1 AND fingerprint = ?2
                   AND renewal_token_hash = ?3",
                params![
                    request_id.as_bytes().as_slice(),
                    fingerprint.as_bytes().as_slice(),
                    renewal_token_hash.as_slice()
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or(EnrollmentRepositoryError::Unauthorized)?;
        if row.0 == 2 {
            let version = load_snapshot(&transaction)?.version();
            transaction.commit().map_err(storage)?;
            return Ok(version);
        }
        if row.0 != 1 {
            return Err(EnrollmentRepositoryError::Conflict);
        }
        let previous = row.1.map(|bytes| decode_fingerprint(&bytes)).transpose()?;
        let current = load_snapshot(&transaction)?;
        let version = if let Some(previous) = previous {
            let grants: Vec<_> = current
                .snapshot()
                .grants()
                .into_iter()
                .filter(|grant| grant.certificate != previous)
                .collect();
            let version = next_version(current.version())?;
            let snapshot = VersionedAuthorizationSnapshot::new(
                version,
                AuthorizationSnapshot::new(grants)
                    .map_err(|_| EnrollmentRepositoryError::Corrupt)?,
            );
            replace_snapshot(&transaction, &snapshot)?;
            transaction
                .execute(
                    "UPDATE agent_credentials SET state = 3 WHERE fingerprint = ?1",
                    [previous.as_bytes().as_slice()],
                )
                .map_err(storage)?;
            version
        } else {
            current.version()
        };
        transaction
            .execute(
                "UPDATE agent_credentials SET state = 2 WHERE fingerprint = ?1",
                [fingerprint.as_bytes().as_slice()],
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        Ok(version)
    }
}

pub fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}

pub fn provision_bootstrap_token(
    database_path: impl AsRef<Path>,
    agent_id: &AgentId,
    tunnel_id: &TunnelId,
    ttl: std::time::Duration,
    output_path: &Path,
) -> Result<(), EnrollmentRepositoryError> {
    if ttl.is_zero() || output_path.as_os_str().is_empty() {
        return Err(EnrollmentRepositoryError::InvalidTime);
    }
    let now = unix_time_now()?;
    let expires = now
        .checked_add(ttl.as_secs())
        .ok_or(EnrollmentRepositoryError::InvalidTime)?;
    let mut token = [0_u8; 32];
    getrandom::getrandom(&mut token).map_err(|_| EnrollmentRepositoryError::Random)?;
    let repository = EnrollmentRepository::open(database_path)?;
    repository.create_bootstrap_token(token_hash(&token), agent_id, tunnel_id, expires)?;
    let value: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
    tunnelproxy_common::replace_secret_file(output_path, format!("{value}\n").as_bytes())
        .map_err(|_| EnrollmentRepositoryError::TokenOutput)?;
    Ok(())
}

pub fn unix_time_now() -> Result<u64, EnrollmentRepositoryError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| EnrollmentRepositoryError::InvalidTime)
}

fn migrate(connection: &Connection) -> Result<(), EnrollmentRepositoryError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS enrollment_bootstrap_tokens (
                token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
                agent_id TEXT NOT NULL,
                tunnel_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL CHECK(consumed IN (0, 1))
            );
            CREATE TABLE IF NOT EXISTS agent_credentials (
                fingerprint BLOB PRIMARY KEY CHECK(length(fingerprint) = 32),
                request_id BLOB NOT NULL UNIQUE CHECK(length(request_id) = 16),
                agent_id TEXT NOT NULL,
                tunnel_id TEXT NOT NULL,
                csr_digest BLOB NOT NULL CHECK(length(csr_digest) = 32),
                auth_token_hash BLOB NOT NULL CHECK(length(auth_token_hash) = 32),
                renewal_token_hash BLOB NOT NULL CHECK(length(renewal_token_hash) = 32),
                certificate_pem BLOB NOT NULL,
                not_after INTEGER NOT NULL,
                generation BLOB NOT NULL CHECK(length(generation) = 8),
                state INTEGER NOT NULL CHECK(state IN (1, 2, 3)),
                previous_fingerprint BLOB NULL CHECK(
                    previous_fingerprint IS NULL OR length(previous_fingerprint) = 32
                )
            );",
        )
        .map_err(storage)
}

fn authenticate_token(
    connection: &Connection,
    token_hash: [u8; 32],
    agent_id: &AgentId,
    tunnel_id: &TunnelId,
    now_unix: u64,
) -> Result<PresentedTokenKind, EnrollmentRepositoryError> {
    let bootstrap = connection
        .query_row(
            "SELECT agent_id, tunnel_id, expires_at, consumed
             FROM enrollment_bootstrap_tokens WHERE token_hash = ?1",
            [token_hash.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    if let Some((bound_agent, bound_tunnel, expires, consumed)) = bootstrap {
        if bound_agent != agent_id.as_str() || bound_tunnel != tunnel_id.as_str() {
            return Err(EnrollmentRepositoryError::IdentityMismatch);
        }
        if consumed != 0 {
            return Err(EnrollmentRepositoryError::Unauthorized);
        }
        if expires < 0 || expires as u64 <= now_unix {
            return Err(EnrollmentRepositoryError::TokenExpired);
        }
        return Ok(PresentedTokenKind::Bootstrap);
    }

    let active = connection
        .query_row(
            "SELECT fingerprint, agent_id, tunnel_id FROM agent_credentials
             WHERE renewal_token_hash = ?1 AND state = 2",
            [token_hash.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .ok_or(EnrollmentRepositoryError::Unauthorized)?;
    if active.1 != agent_id.as_str() || active.2 != tunnel_id.as_str() {
        return Err(EnrollmentRepositoryError::IdentityMismatch);
    }
    Ok(PresentedTokenKind::Renewal(decode_fingerprint(&active.0)?))
}

struct ExistingIssuance {
    issuance: DurableIssuance,
    auth_token_hash: [u8; 32],
    next_token_hash: [u8; 32],
    agent_id: String,
    tunnel_id: String,
    csr_digest: [u8; 32],
}

fn load_issuance(
    connection: &Connection,
    request_id: EnrollmentRequestId,
) -> Result<Option<ExistingIssuance>, EnrollmentRepositoryError> {
    connection
        .query_row(
            "SELECT generation, certificate_pem, fingerprint, not_after,
                    auth_token_hash, renewal_token_hash, agent_id, tunnel_id, csr_digest
             FROM agent_credentials WHERE request_id = ?1",
            [request_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .map(|row| {
            if row.3 < 0 {
                return Err(EnrollmentRepositoryError::Corrupt);
            }
            Ok(ExistingIssuance {
                issuance: DurableIssuance {
                    generation: decode_version(&row.0)?,
                    certificate_pem: row.1,
                    fingerprint: decode_fingerprint(&row.2)?,
                    not_after_unix: row.3 as u64,
                },
                auth_token_hash: decode_array(&row.4)?,
                next_token_hash: decode_array(&row.5)?,
                agent_id: row.6,
                tunnel_id: row.7,
                csr_digest: decode_array(&row.8)?,
            })
        })
        .transpose()
}

fn verify_idempotent_candidate(
    existing: &ExistingIssuance,
    candidate: &IssuanceCandidate,
) -> Result<(), EnrollmentRepositoryError> {
    verify_idempotent_fields(
        existing,
        candidate.presented_token_hash,
        candidate.next_token_hash,
        &candidate.agent_id,
        &candidate.tunnel_id,
        candidate.csr_digest,
    )
}

fn verify_idempotent_fields(
    existing: &ExistingIssuance,
    presented_token_hash: [u8; 32],
    next_token_hash: [u8; 32],
    agent_id: &AgentId,
    tunnel_id: &TunnelId,
    csr_digest: [u8; 32],
) -> Result<(), EnrollmentRepositoryError> {
    if existing.auth_token_hash != presented_token_hash
        || existing.next_token_hash != next_token_hash
        || existing.agent_id != agent_id.as_str()
        || existing.tunnel_id != tunnel_id.as_str()
        || existing.csr_digest != csr_digest
    {
        return Err(EnrollmentRepositoryError::Conflict);
    }
    Ok(())
}

fn load_snapshot(
    connection: &Connection,
) -> Result<VersionedAuthorizationSnapshot, EnrollmentRepositoryError> {
    crate::repository::load_latest_from_connection(connection)
        .map_err(|_| EnrollmentRepositoryError::Storage)?
        .ok_or(EnrollmentRepositoryError::Uninitialized)
}

fn replace_snapshot(
    transaction: &Transaction<'_>,
    snapshot: &VersionedAuthorizationSnapshot,
) -> Result<(), EnrollmentRepositoryError> {
    let digest =
        snapshot_digest(snapshot.snapshot()).map_err(|_| EnrollmentRepositoryError::Corrupt)?;
    transaction
        .execute("DELETE FROM snapshot_tunnels", [])
        .map_err(storage)?;
    transaction
        .execute("DELETE FROM snapshot_agents", [])
        .map_err(storage)?;
    for grant in snapshot.snapshot().grants() {
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
            "UPDATE snapshot_head SET version = ?1, digest = ?2 WHERE singleton_id = 1",
            params![
                snapshot.version().get().to_be_bytes().as_slice(),
                digest.as_slice()
            ],
        )
        .map_err(storage)?;
    Ok(())
}

fn next_version(current: SnapshotVersion) -> Result<SnapshotVersion, EnrollmentRepositoryError> {
    current
        .get()
        .checked_add(1)
        .and_then(SnapshotVersion::new)
        .ok_or(EnrollmentRepositoryError::VersionExhausted)
}

fn decode_version(bytes: &[u8]) -> Result<SnapshotVersion, EnrollmentRepositoryError> {
    SnapshotVersion::new(u64::from_be_bytes(decode_array(bytes)?))
        .ok_or(EnrollmentRepositoryError::Corrupt)
}

fn decode_fingerprint(bytes: &[u8]) -> Result<CertificateFingerprint, EnrollmentRepositoryError> {
    Ok(CertificateFingerprint::from_bytes(decode_array(bytes)?))
}

fn decode_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], EnrollmentRepositoryError> {
    bytes
        .try_into()
        .map_err(|_| EnrollmentRepositoryError::Corrupt)
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn storage(_: rusqlite::Error) -> EnrollmentRepositoryError {
    EnrollmentRepositoryError::Storage
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentRepositoryError {
    Storage,
    Uninitialized,
    Unauthorized,
    TokenExpired,
    IdentityMismatch,
    Conflict,
    Corrupt,
    InvalidTime,
    VersionExhausted,
    Random,
    TokenOutput,
}

impl std::fmt::Display for EnrollmentRepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Storage => "enrollment repository operation failed",
            Self::Uninitialized => "authorization snapshot is not initialized",
            Self::Unauthorized => "enrollment token is not authorized",
            Self::TokenExpired => "enrollment token has expired",
            Self::IdentityMismatch => "enrollment token identity does not match the request",
            Self::Conflict => "enrollment request conflicts with durable state",
            Self::Corrupt => "enrollment repository contains invalid state",
            Self::InvalidTime => "enrollment timestamp is invalid",
            Self::VersionExhausted => "authorization snapshot version is exhausted",
            Self::Random => "secure enrollment token generation failed",
            Self::TokenOutput => "enrollment token output could not be written",
        };
        f.write_str(message)
    }
}

impl std::error::Error for EnrollmentRepositoryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizationError, SnapshotRepository, SqliteSnapshotRepository};

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunnelproxy-enrollment-{label}-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn candidate(
        request: u8,
        presented: [u8; 32],
        next: [u8; 32],
        fingerprint: u8,
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
    ) -> IssuanceCandidate {
        IssuanceCandidate {
            request_id: EnrollmentRequestId::from_bytes([request; 16]),
            presented_token_hash: token_hash(&presented),
            next_token_hash: token_hash(&next),
            agent_id: agent_id.clone(),
            tunnel_id: tunnel_id.clone(),
            csr_digest: [request; 32],
            certificate_pem: vec![request; 16],
            fingerprint: CertificateFingerprint::from_bytes([fingerprint; 32]),
            not_after_unix: 10_000,
        }
    }

    #[test]
    fn issuance_and_activation_are_atomic_idempotent_and_rotate_authorization() {
        let path = test_path("rotation");
        let snapshots = SqliteSnapshotRepository::open(&path).unwrap();
        snapshots
            .commit(&VersionedAuthorizationSnapshot::new(
                SnapshotVersion::FIRST,
                AuthorizationSnapshot::default(),
            ))
            .unwrap();
        let repository = EnrollmentRepository::open(&path).unwrap();
        let agent_id = AgentId::new("agent-enrolled").unwrap();
        let tunnel_id = TunnelId::new("tunnel-enrolled").unwrap();
        let bootstrap = [1; 32];
        let renewal_one = [2; 32];
        let renewal_two = [3; 32];
        repository
            .create_bootstrap_token(token_hash(&bootstrap), &agent_id, &tunnel_id, 1_000)
            .unwrap();

        assert!(matches!(
            repository.validate_token(token_hash(&bootstrap), &agent_id, &tunnel_id, 1_000),
            Err(EnrollmentRepositoryError::TokenExpired)
        ));
        let wrong_agent = AgentId::new("agent-other").unwrap();
        assert!(matches!(
            repository.validate_token(token_hash(&bootstrap), &wrong_agent, &tunnel_id, 100),
            Err(EnrollmentRepositoryError::IdentityMismatch)
        ));

        let first = candidate(10, bootstrap, renewal_one, 11, &agent_id, &tunnel_id);
        let issued = repository.commit_issuance(&first, 100).unwrap();
        assert_eq!(issued.generation.get(), 2);
        assert_eq!(repository.commit_issuance(&first, 100).unwrap(), issued);
        assert!(matches!(
            repository.validate_token(token_hash(&bootstrap), &agent_id, &tunnel_id, 100),
            Err(EnrollmentRepositoryError::Unauthorized)
        ));
        let version = repository
            .activate(
                first.request_id,
                token_hash(&renewal_one),
                first.fingerprint,
            )
            .unwrap();
        assert_eq!(version.get(), 2);
        assert_eq!(
            repository
                .activate(
                    first.request_id,
                    token_hash(&renewal_one),
                    first.fingerprint
                )
                .unwrap(),
            version
        );

        let second = candidate(20, renewal_one, renewal_two, 22, &agent_id, &tunnel_id);
        assert_eq!(
            repository
                .commit_issuance(&second, 200)
                .unwrap()
                .generation
                .get(),
            3
        );
        let overlap = snapshots.load_latest().unwrap().unwrap();
        assert_eq!(overlap.snapshot().certificate_count(), 2);
        assert!(overlap
            .snapshot()
            .authorize(&first.fingerprint, &agent_id, &tunnel_id)
            .is_ok());
        assert!(overlap
            .snapshot()
            .authorize(&second.fingerprint, &agent_id, &tunnel_id)
            .is_ok());

        assert_eq!(
            repository.activate(second.request_id, [9; 32], second.fingerprint),
            Err(EnrollmentRepositoryError::Unauthorized)
        );
        assert_eq!(
            repository
                .activate(
                    second.request_id,
                    token_hash(&renewal_two),
                    second.fingerprint,
                )
                .unwrap()
                .get(),
            4
        );
        let active = snapshots.load_latest().unwrap().unwrap();
        assert_eq!(active.snapshot().certificate_count(), 1);
        assert_eq!(
            active
                .snapshot()
                .authorize(&first.fingerprint, &agent_id, &tunnel_id),
            Err(AuthorizationError::UnknownCertificate)
        );
        assert!(active
            .snapshot()
            .authorize(&second.fingerprint, &agent_id, &tunnel_id)
            .is_ok());

        drop(repository);
        drop(snapshots);
        let _ = std::fs::remove_file(path);
    }
}
