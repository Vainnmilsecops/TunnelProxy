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

const MAX_RECONCILE_BATCH: usize = 256;
const MAX_CREDENTIAL_STATUS_ROWS: u64 = 1_024;

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
    pub activation_deadline_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableIssuance {
    pub generation: SnapshotVersion,
    pub certificate_pem: Vec<u8>,
    pub fingerprint: CertificateFingerprint,
    pub not_after_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    Pending,
    Active,
    Retired,
    Revoked,
    Expired,
}

impl CredentialState {
    const fn from_raw(value: i64) -> Result<Self, EnrollmentRepositoryError> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Active),
            3 => Ok(Self::Retired),
            4 => Ok(Self::Revoked),
            5 => Ok(Self::Expired),
            _ => Err(EnrollmentRepositoryError::Corrupt),
        }
    }
}

impl std::fmt::Display for CredentialState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStatus {
    pub fingerprint: CertificateFingerprint,
    pub generation: SnapshotVersion,
    pub state: CredentialState,
    pub not_after_unix: u64,
    pub activation_deadline_unix: u64,
    pub terminal_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStatusReport {
    pub snapshot_version: SnapshotVersion,
    pub credentials: Vec<CredentialStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialMutationOutcome {
    pub snapshot_version: SnapshotVersion,
    pub affected_credentials: u64,
    pub snapshot_changed: bool,
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
                    token_hash, agent_id, tunnel_id, expires_at, consumed, revoked
                 ) VALUES (?1, ?2, ?3, ?4, 0, 0)",
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
        if candidate.activation_deadline_unix <= now_unix
            || candidate.activation_deadline_unix > candidate.not_after_unix
        {
            return Err(EnrollmentRepositoryError::InvalidTime);
        }
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;

        if let Some(existing) = load_issuance(&transaction, candidate.request_id)? {
            verify_idempotent_candidate(&existing, candidate)?;
            ensure_retryable_state(existing.state)?;
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
                    not_after, generation, state, previous_fingerprint,
                    activation_deadline, terminal_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, ?12, NULL)",
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
                    i64::try_from(candidate.activation_deadline_unix)
                        .map_err(|_| EnrollmentRepositoryError::InvalidTime)?,
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
            ensure_retryable_state(existing.state)?;
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
        now_unix: u64,
    ) -> Result<SnapshotVersion, EnrollmentRepositoryError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row = transaction
            .query_row(
                "SELECT state, previous_fingerprint, activation_deadline
                 FROM agent_credentials
                 WHERE request_id = ?1 AND fingerprint = ?2
                   AND renewal_token_hash = ?3",
                params![
                    request_id.as_bytes().as_slice(),
                    fingerprint.as_bytes().as_slice(),
                    renewal_token_hash.as_slice()
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or(EnrollmentRepositoryError::Unauthorized)?;
        let state = CredentialState::from_raw(row.0)?;
        if state == CredentialState::Active {
            let version = load_snapshot(&transaction)?.version();
            transaction.commit().map_err(storage)?;
            return Ok(version);
        }
        match state {
            CredentialState::Revoked => return Err(EnrollmentRepositoryError::CredentialRevoked),
            CredentialState::Expired => return Err(EnrollmentRepositoryError::RequestExpired),
            CredentialState::Retired => return Err(EnrollmentRepositoryError::Conflict),
            CredentialState::Pending | CredentialState::Active => {}
        }
        if row.2 < 0 || row.2 as u64 <= now_unix {
            expire_pending_credential(&transaction, fingerprint, now_unix)?;
            transaction.commit().map_err(storage)?;
            return Err(EnrollmentRepositoryError::RequestExpired);
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

    pub fn revoke_agent(
        &self,
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
        now_unix: u64,
    ) -> Result<CredentialMutationOutcome, EnrollmentRepositoryError> {
        let terminal_at =
            i64::try_from(now_unix).map_err(|_| EnrollmentRepositoryError::InvalidTime)?;
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        transaction
            .execute(
                "UPDATE enrollment_bootstrap_tokens
                 SET consumed = 1, revoked = 1
                 WHERE agent_id = ?1 AND tunnel_id = ?2",
                params![agent_id.as_str(), tunnel_id.as_str()],
            )
            .map_err(storage)?;
        let affected = transaction
            .execute(
                "UPDATE agent_credentials SET state = 4, terminal_at = ?1
                 WHERE agent_id = ?2 AND tunnel_id = ?3 AND state IN (1, 2)",
                params![terminal_at, agent_id.as_str(), tunnel_id.as_str()],
            )
            .map_err(storage)? as u64;
        let current = load_snapshot(&transaction)?;
        let grants = remove_agent_tunnel(current.snapshot().grants(), agent_id, tunnel_id);
        let snapshot_changed = grants != current.snapshot().grants();
        let snapshot_version = if snapshot_changed {
            let version = next_version(current.version())?;
            replace_snapshot(
                &transaction,
                &VersionedAuthorizationSnapshot::new(
                    version,
                    AuthorizationSnapshot::new(grants)
                        .map_err(|_| EnrollmentRepositoryError::Corrupt)?,
                ),
            )?;
            version
        } else {
            current.version()
        };
        transaction.commit().map_err(storage)?;
        Ok(CredentialMutationOutcome {
            snapshot_version,
            affected_credentials: affected,
            snapshot_changed,
        })
    }

    pub fn reconcile_expired(
        &self,
        now_unix: u64,
    ) -> Result<CredentialMutationOutcome, EnrollmentRepositoryError> {
        let terminal_at =
            i64::try_from(now_unix).map_err(|_| EnrollmentRepositoryError::InvalidTime)?;
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut statement = transaction
            .prepare(
                "SELECT fingerprint FROM agent_credentials
                 WHERE state = 1 AND activation_deadline <= ?1
                 ORDER BY fingerprint LIMIT ?2",
            )
            .map_err(storage)?;
        let fingerprints: Vec<CertificateFingerprint> = statement
            .query_map(params![terminal_at, MAX_RECONCILE_BATCH as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(storage)?
            .map(|row| {
                row.map_err(storage)
                    .and_then(|bytes| decode_fingerprint(&bytes))
            })
            .collect::<Result<_, _>>()?;
        drop(statement);
        let current = load_snapshot(&transaction)?;
        if fingerprints.is_empty() {
            let version = current.version();
            transaction.commit().map_err(storage)?;
            return Ok(CredentialMutationOutcome {
                snapshot_version: version,
                affected_credentials: 0,
                snapshot_changed: false,
            });
        }
        let grants: Vec<_> = current
            .snapshot()
            .grants()
            .into_iter()
            .filter(|grant| !fingerprints.contains(&grant.certificate))
            .collect();
        let snapshot_changed = grants != current.snapshot().grants();
        let snapshot_version = if snapshot_changed {
            let version = next_version(current.version())?;
            replace_snapshot(
                &transaction,
                &VersionedAuthorizationSnapshot::new(
                    version,
                    AuthorizationSnapshot::new(grants)
                        .map_err(|_| EnrollmentRepositoryError::Corrupt)?,
                ),
            )?;
            version
        } else {
            current.version()
        };
        for fingerprint in &fingerprints {
            transaction
                .execute(
                    "UPDATE agent_credentials SET state = 5, terminal_at = ?1
                     WHERE fingerprint = ?2 AND state = 1",
                    params![terminal_at, fingerprint.as_bytes().as_slice()],
                )
                .map_err(storage)?;
        }
        transaction.commit().map_err(storage)?;
        Ok(CredentialMutationOutcome {
            snapshot_version,
            affected_credentials: fingerprints.len() as u64,
            snapshot_changed,
        })
    }

    pub fn credential_status(
        &self,
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
    ) -> Result<CredentialStatusReport, EnrollmentRepositoryError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction().map_err(storage)?;
        let snapshot_version = load_snapshot(&transaction)?.version();
        let mut statement = transaction
            .prepare(
                "SELECT fingerprint, generation, state, not_after,
                        activation_deadline, terminal_at
                 FROM agent_credentials
                 WHERE agent_id = ?1 AND tunnel_id = ?2
                 ORDER BY generation, fingerprint LIMIT ?3",
            )
            .map_err(storage)?;
        let credentials = statement
            .query_map(
                params![
                    agent_id.as_str(),
                    tunnel_id.as_str(),
                    (MAX_CREDENTIAL_STATUS_ROWS + 1) as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .map_err(storage)?
            .map(|row| {
                let row = row.map_err(storage)?;
                if row.3 < 0 || row.4 < 0 || row.5.is_some_and(|value| value < 0) {
                    return Err(EnrollmentRepositoryError::Corrupt);
                }
                Ok(CredentialStatus {
                    fingerprint: decode_fingerprint(&row.0)?,
                    generation: decode_version(&row.1)?,
                    state: CredentialState::from_raw(row.2)?,
                    not_after_unix: row.3 as u64,
                    activation_deadline_unix: row.4 as u64,
                    terminal_at_unix: row.5.map(|value| value as u64),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if credentials.len() as u64 > MAX_CREDENTIAL_STATUS_ROWS {
            return Err(EnrollmentRepositoryError::ResourceLimit);
        }
        transaction.commit().map_err(storage)?;
        Ok(CredentialStatusReport {
            snapshot_version,
            credentials,
        })
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
                consumed INTEGER NOT NULL CHECK(consumed IN (0, 1)),
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
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
                state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4, 5)),
                previous_fingerprint BLOB NULL CHECK(
                    previous_fingerprint IS NULL OR length(previous_fingerprint) = 32
                ),
                activation_deadline INTEGER NOT NULL,
                terminal_at INTEGER NULL
            );",
        )
        .map_err(storage)?;
    if !has_column(connection, "enrollment_bootstrap_tokens", "revoked")? {
        connection
            .execute(
                "ALTER TABLE enrollment_bootstrap_tokens
                 ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))",
                [],
            )
            .map_err(storage)?;
    }
    if !has_column(connection, "agent_credentials", "activation_deadline")? {
        connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 ALTER TABLE agent_credentials RENAME TO agent_credentials_session21;
                 CREATE TABLE agent_credentials (
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
                    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4, 5)),
                    previous_fingerprint BLOB NULL CHECK(
                        previous_fingerprint IS NULL OR length(previous_fingerprint) = 32
                    ),
                    activation_deadline INTEGER NOT NULL,
                    terminal_at INTEGER NULL
                 );
                 INSERT INTO agent_credentials(
                    fingerprint, request_id, agent_id, tunnel_id, csr_digest,
                    auth_token_hash, renewal_token_hash, certificate_pem,
                    not_after, generation, state, previous_fingerprint,
                    activation_deadline, terminal_at
                 ) SELECT fingerprint, request_id, agent_id, tunnel_id, csr_digest,
                          auth_token_hash, renewal_token_hash, certificate_pem,
                          not_after, generation, state, previous_fingerprint,
                          not_after, NULL
                   FROM agent_credentials_session21;
                 DROP TABLE agent_credentials_session21;
                 PRAGMA user_version = 22;
                 COMMIT;",
            )
            .map_err(storage)?;
    } else {
        connection
            .pragma_update(None, "user_version", 22)
            .map_err(storage)?;
    }
    Ok(())
}

fn has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, EnrollmentRepositoryError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(storage)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(storage)?;
    for candidate in columns {
        if candidate.map_err(storage)? == column {
            return Ok(true);
        }
    }
    Ok(false)
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
            "SELECT agent_id, tunnel_id, expires_at, consumed, revoked
             FROM enrollment_bootstrap_tokens WHERE token_hash = ?1",
            [token_hash.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    if let Some((bound_agent, bound_tunnel, expires, consumed, revoked)) = bootstrap {
        if bound_agent != agent_id.as_str() || bound_tunnel != tunnel_id.as_str() {
            return Err(EnrollmentRepositoryError::IdentityMismatch);
        }
        if revoked != 0 {
            return Err(EnrollmentRepositoryError::CredentialRevoked);
        }
        if consumed != 0 {
            return Err(EnrollmentRepositoryError::Unauthorized);
        }
        if expires < 0 || expires as u64 <= now_unix {
            return Err(EnrollmentRepositoryError::TokenExpired);
        }
        return Ok(PresentedTokenKind::Bootstrap);
    }

    let credential = connection
        .query_row(
            "SELECT fingerprint, agent_id, tunnel_id, state FROM agent_credentials
             WHERE renewal_token_hash = ?1 AND state IN (2, 4)
             ORDER BY state DESC LIMIT 1",
            [token_hash.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .ok_or(EnrollmentRepositoryError::Unauthorized)?;
    if credential.1 != agent_id.as_str() || credential.2 != tunnel_id.as_str() {
        return Err(EnrollmentRepositoryError::IdentityMismatch);
    }
    if CredentialState::from_raw(credential.3)? == CredentialState::Revoked {
        return Err(EnrollmentRepositoryError::CredentialRevoked);
    }
    Ok(PresentedTokenKind::Renewal(decode_fingerprint(
        &credential.0,
    )?))
}

struct ExistingIssuance {
    issuance: DurableIssuance,
    auth_token_hash: [u8; 32],
    next_token_hash: [u8; 32],
    agent_id: String,
    tunnel_id: String,
    csr_digest: [u8; 32],
    state: CredentialState,
}

fn load_issuance(
    connection: &Connection,
    request_id: EnrollmentRequestId,
) -> Result<Option<ExistingIssuance>, EnrollmentRepositoryError> {
    connection
        .query_row(
            "SELECT generation, certificate_pem, fingerprint, not_after,
                    auth_token_hash, renewal_token_hash, agent_id, tunnel_id, csr_digest, state
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
                    row.get::<_, i64>(9)?,
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
                state: CredentialState::from_raw(row.9)?,
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

fn ensure_retryable_state(state: CredentialState) -> Result<(), EnrollmentRepositoryError> {
    match state {
        CredentialState::Pending | CredentialState::Active => Ok(()),
        CredentialState::Revoked => Err(EnrollmentRepositoryError::CredentialRevoked),
        CredentialState::Expired => Err(EnrollmentRepositoryError::RequestExpired),
        CredentialState::Retired => Err(EnrollmentRepositoryError::Conflict),
    }
}

fn expire_pending_credential(
    transaction: &Transaction<'_>,
    fingerprint: CertificateFingerprint,
    now_unix: u64,
) -> Result<SnapshotVersion, EnrollmentRepositoryError> {
    let current = load_snapshot(transaction)?;
    let grants: Vec<_> = current
        .snapshot()
        .grants()
        .into_iter()
        .filter(|grant| grant.certificate != fingerprint)
        .collect();
    let version = if grants != current.snapshot().grants() {
        let version = next_version(current.version())?;
        replace_snapshot(
            transaction,
            &VersionedAuthorizationSnapshot::new(
                version,
                AuthorizationSnapshot::new(grants)
                    .map_err(|_| EnrollmentRepositoryError::Corrupt)?,
            ),
        )?;
        version
    } else {
        current.version()
    };
    transaction
        .execute(
            "UPDATE agent_credentials SET state = 5, terminal_at = ?1
             WHERE fingerprint = ?2 AND state = 1",
            params![
                i64::try_from(now_unix).map_err(|_| EnrollmentRepositoryError::InvalidTime)?,
                fingerprint.as_bytes().as_slice(),
            ],
        )
        .map_err(storage)?;
    Ok(version)
}

fn remove_agent_tunnel(
    grants: Vec<AgentGrant>,
    agent_id: &AgentId,
    tunnel_id: &TunnelId,
) -> Vec<AgentGrant> {
    grants
        .into_iter()
        .filter_map(|mut grant| {
            if &grant.agent_id == agent_id {
                grant
                    .tunnels
                    .retain(|tunnel| &tunnel.tunnel_id != tunnel_id);
            }
            (!grant.tunnels.is_empty()).then_some(grant)
        })
        .collect()
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
    CredentialRevoked,
    RequestExpired,
    IdentityMismatch,
    Conflict,
    Corrupt,
    InvalidTime,
    VersionExhausted,
    Random,
    TokenOutput,
    ResourceLimit,
}

impl std::fmt::Display for EnrollmentRepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Storage => "enrollment repository operation failed",
            Self::Uninitialized => "authorization snapshot is not initialized",
            Self::Unauthorized => "enrollment token is not authorized",
            Self::TokenExpired => "enrollment token has expired",
            Self::CredentialRevoked => "Agent credential has been revoked",
            Self::RequestExpired => "enrollment activation request has expired",
            Self::IdentityMismatch => "enrollment token identity does not match the request",
            Self::Conflict => "enrollment request conflicts with durable state",
            Self::Corrupt => "enrollment repository contains invalid state",
            Self::InvalidTime => "enrollment timestamp is invalid",
            Self::VersionExhausted => "authorization snapshot version is exhausted",
            Self::Random => "secure enrollment token generation failed",
            Self::TokenOutput => "enrollment token output could not be written",
            Self::ResourceLimit => "credential query exceeds its bounded result limit",
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
            activation_deadline_unix: 9_000,
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
                110,
            )
            .unwrap();
        assert_eq!(version.get(), 2);
        assert_eq!(
            repository
                .activate(
                    first.request_id,
                    token_hash(&renewal_one),
                    first.fingerprint,
                    110,
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
            repository.activate(second.request_id, [9; 32], second.fingerprint, 210),
            Err(EnrollmentRepositoryError::Unauthorized)
        );
        assert_eq!(
            repository
                .activate(
                    second.request_id,
                    token_hash(&renewal_two),
                    second.fingerprint,
                    210,
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

    #[test]
    fn expired_renewal_removes_only_pending_fingerprint_and_tombstones_request() {
        let path = test_path("expired-renewal");
        let snapshots = SqliteSnapshotRepository::open(&path).unwrap();
        snapshots
            .commit(&VersionedAuthorizationSnapshot::new(
                SnapshotVersion::FIRST,
                AuthorizationSnapshot::default(),
            ))
            .unwrap();
        let repository = EnrollmentRepository::open(&path).unwrap();
        let agent_id = AgentId::new("agent-expired").unwrap();
        let tunnel_id = TunnelId::new("tunnel-expired").unwrap();
        let bootstrap = [31; 32];
        let renewal_one = [32; 32];
        let renewal_two = [33; 32];
        repository
            .create_bootstrap_token(token_hash(&bootstrap), &agent_id, &tunnel_id, 1_000)
            .unwrap();
        let first = candidate(31, bootstrap, renewal_one, 41, &agent_id, &tunnel_id);
        repository.commit_issuance(&first, 100).unwrap();
        repository
            .activate(
                first.request_id,
                token_hash(&renewal_one),
                first.fingerprint,
                110,
            )
            .unwrap();
        let mut pending = candidate(32, renewal_one, renewal_two, 42, &agent_id, &tunnel_id);
        pending.activation_deadline_unix = 250;
        repository.commit_issuance(&pending, 200).unwrap();

        let outcome = repository.reconcile_expired(250).unwrap();
        assert_eq!(outcome.affected_credentials, 1);
        assert!(outcome.snapshot_changed);
        assert_eq!(outcome.snapshot_version.get(), 4);
        let snapshot = snapshots.load_latest().unwrap().unwrap();
        assert!(snapshot
            .snapshot()
            .authorize(&first.fingerprint, &agent_id, &tunnel_id)
            .is_ok());
        assert_eq!(
            snapshot
                .snapshot()
                .authorize(&pending.fingerprint, &agent_id, &tunnel_id),
            Err(AuthorizationError::UnknownCertificate)
        );
        assert!(repository
            .validate_token(token_hash(&renewal_one), &agent_id, &tunnel_id, 251)
            .is_ok());
        assert_eq!(
            repository.preflight_issuance(
                pending.request_id,
                pending.presented_token_hash,
                pending.next_token_hash,
                &agent_id,
                &tunnel_id,
                pending.csr_digest,
                251,
            ),
            Err(EnrollmentRepositoryError::RequestExpired)
        );
        let report = repository.credential_status(&agent_id, &tunnel_id).unwrap();
        assert_eq!(report.credentials.len(), 2);
        assert_eq!(report.credentials[0].state, CredentialState::Active);
        assert_eq!(report.credentials[1].state, CredentialState::Expired);
        assert_eq!(report.credentials[1].terminal_at_unix, Some(250));

        drop(repository);
        drop(snapshots);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn activation_at_deadline_expires_the_pending_credential_atomically() {
        let path = test_path("activation-deadline");
        let snapshots = SqliteSnapshotRepository::open(&path).unwrap();
        snapshots
            .commit(&VersionedAuthorizationSnapshot::new(
                SnapshotVersion::FIRST,
                AuthorizationSnapshot::default(),
            ))
            .unwrap();
        let repository = EnrollmentRepository::open(&path).unwrap();
        let agent_id = AgentId::new("agent-deadline").unwrap();
        let tunnel_id = TunnelId::new("tunnel-deadline").unwrap();
        let bootstrap = [41; 32];
        let renewal = [42; 32];
        repository
            .create_bootstrap_token(token_hash(&bootstrap), &agent_id, &tunnel_id, 1_000)
            .unwrap();
        let mut issued = candidate(41, bootstrap, renewal, 43, &agent_id, &tunnel_id);
        issued.activation_deadline_unix = 150;
        repository.commit_issuance(&issued, 100).unwrap();

        assert_eq!(
            repository.activate(
                issued.request_id,
                token_hash(&renewal),
                issued.fingerprint,
                150,
            ),
            Err(EnrollmentRepositoryError::RequestExpired)
        );
        let snapshot = snapshots.load_latest().unwrap().unwrap();
        assert_eq!(snapshot.version().get(), 3);
        assert_eq!(
            snapshot
                .snapshot()
                .authorize(&issued.fingerprint, &agent_id, &tunnel_id),
            Err(AuthorizationError::UnknownCertificate)
        );
        assert_eq!(
            repository.preflight_issuance(
                issued.request_id,
                issued.presented_token_hash,
                issued.next_token_hash,
                &agent_id,
                &tunnel_id,
                issued.csr_digest,
                151,
            ),
            Err(EnrollmentRepositoryError::RequestExpired)
        );

        drop(repository);
        drop(snapshots);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn revocation_is_idempotent_removes_authority_and_invalidates_tokens() {
        let path = test_path("revoke");
        let snapshots = SqliteSnapshotRepository::open(&path).unwrap();
        snapshots
            .commit(&VersionedAuthorizationSnapshot::new(
                SnapshotVersion::FIRST,
                AuthorizationSnapshot::default(),
            ))
            .unwrap();
        let repository = EnrollmentRepository::open(&path).unwrap();
        let agent_id = AgentId::new("agent-revoked").unwrap();
        let tunnel_id = TunnelId::new("tunnel-revoked").unwrap();
        let bootstrap = [51; 32];
        let renewal = [52; 32];
        repository
            .create_bootstrap_token(token_hash(&bootstrap), &agent_id, &tunnel_id, 1_000)
            .unwrap();
        let issued = candidate(51, bootstrap, renewal, 53, &agent_id, &tunnel_id);
        repository.commit_issuance(&issued, 100).unwrap();
        repository
            .activate(
                issued.request_id,
                token_hash(&renewal),
                issued.fingerprint,
                110,
            )
            .unwrap();

        let revoked = repository.revoke_agent(&agent_id, &tunnel_id, 120).unwrap();
        assert_eq!(revoked.affected_credentials, 1);
        assert!(revoked.snapshot_changed);
        assert_eq!(revoked.snapshot_version.get(), 3);
        assert_eq!(
            snapshots
                .load_latest()
                .unwrap()
                .unwrap()
                .snapshot()
                .authorize(&issued.fingerprint, &agent_id, &tunnel_id),
            Err(AuthorizationError::UnknownCertificate)
        );
        assert!(matches!(
            repository.validate_token(token_hash(&renewal), &agent_id, &tunnel_id, 121),
            Err(EnrollmentRepositoryError::CredentialRevoked)
        ));
        let repeated = repository.revoke_agent(&agent_id, &tunnel_id, 122).unwrap();
        assert_eq!(repeated.affected_credentials, 0);
        assert!(!repeated.snapshot_changed);
        assert_eq!(repeated.snapshot_version, revoked.snapshot_version);
        let report = repository.credential_status(&agent_id, &tunnel_id).unwrap();
        assert_eq!(report.credentials[0].state, CredentialState::Revoked);
        assert_eq!(report.credentials[0].terminal_at_unix, Some(120));

        drop(repository);
        drop(snapshots);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn session_21_schema_migrates_before_revocation_state_is_used() {
        let path = test_path("migration");
        let snapshots = SqliteSnapshotRepository::open(&path).unwrap();
        snapshots
            .commit(&VersionedAuthorizationSnapshot::new(
                SnapshotVersion::FIRST,
                AuthorizationSnapshot::default(),
            ))
            .unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE enrollment_bootstrap_tokens (
                    token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
                    agent_id TEXT NOT NULL, tunnel_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed INTEGER NOT NULL CHECK(consumed IN (0, 1))
                 );
                 CREATE TABLE agent_credentials (
                    fingerprint BLOB PRIMARY KEY CHECK(length(fingerprint) = 32),
                    request_id BLOB NOT NULL UNIQUE CHECK(length(request_id) = 16),
                    agent_id TEXT NOT NULL, tunnel_id TEXT NOT NULL,
                    csr_digest BLOB NOT NULL CHECK(length(csr_digest) = 32),
                    auth_token_hash BLOB NOT NULL CHECK(length(auth_token_hash) = 32),
                    renewal_token_hash BLOB NOT NULL CHECK(length(renewal_token_hash) = 32),
                    certificate_pem BLOB NOT NULL, not_after INTEGER NOT NULL,
                    generation BLOB NOT NULL CHECK(length(generation) = 8),
                    state INTEGER NOT NULL CHECK(state IN (1, 2, 3)),
                    previous_fingerprint BLOB NULL CHECK(
                        previous_fingerprint IS NULL OR length(previous_fingerprint) = 32
                    )
                 );",
            )
            .unwrap();
        drop(connection);

        let repository = EnrollmentRepository::open(&path).unwrap();
        let connection = repository.connect().unwrap();
        assert!(has_column(&connection, "agent_credentials", "activation_deadline").unwrap());
        assert!(has_column(&connection, "agent_credentials", "terminal_at").unwrap());
        assert!(has_column(&connection, "enrollment_bootstrap_tokens", "revoked").unwrap());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            22
        );

        drop(connection);
        drop(repository);
        drop(snapshots);
        let _ = std::fs::remove_file(path);
    }
}
