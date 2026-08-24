use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use tunnelproxy_common::{AgentId, TunnelId};
use tunnelproxy_control_plane::{
    enrollment_token_hash, unix_time_now, AuthorizationSnapshot, EnrollmentRepository,
    EnrollmentRepositoryError, SnapshotRepository, SnapshotVersion, SqliteSnapshotRepository,
    VersionedAuthorizationSnapshot,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

fn temp_directory() -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "tunnelproxy-control-cli-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    directory
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_tunnelproxy-control-plane")
}

#[test]
fn help_and_invalid_arguments_have_stable_exit_codes() {
    let help = Command::new(binary()).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("snapshot JSON manifest"));

    let invalid = Command::new(binary()).arg("serve").output().unwrap();
    assert_eq!(invalid.status.code(), Some(2));
}

#[test]
fn import_command_initializes_a_durable_snapshot_database() {
    let directory = temp_directory();
    let database = directory.join("snapshots.sqlite");
    let manifest = directory.join("snapshot.json");
    std::fs::write(&manifest, br#"{"version":0,"agents":[]}"#).unwrap();
    let invalid = Command::new(binary())
        .arg("import")
        .arg("--database")
        .arg(&database)
        .arg("--snapshot")
        .arg(&manifest)
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));

    std::fs::write(
        &manifest,
        br#"{
            "version": 4,
            "agents": [{
                "certificate_sha256": "abababababababababababababababababababababababababababababababab",
                "agent_id": "agent-cli",
                "tunnels": [{"tunnel_id": "tunnel-cli", "status": "enabled"}]
            }]
        }"#,
    )
    .unwrap();
    let result = Command::new(binary())
        .arg("import")
        .arg("--database")
        .arg(&database)
        .arg("--snapshot")
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let repository = SqliteSnapshotRepository::open(&database).unwrap();
    let loaded = repository.load_latest().unwrap().unwrap();
    assert_eq!(loaded.version().get(), 4);
    drop(repository);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn create_token_writes_a_bound_secret_file_without_printing_the_token() {
    let directory = temp_directory();
    let database = directory.join("snapshots.sqlite");
    SqliteSnapshotRepository::open(&database).unwrap();
    let token_path = directory.join("bootstrap.token");
    let result = Command::new(binary())
        .arg("create-token")
        .arg("--database")
        .arg(&database)
        .arg("--agent-id")
        .arg("agent-cli-token")
        .arg("--tunnel-id")
        .arg("tunnel-cli-token")
        .arg("--output")
        .arg(&token_path)
        .arg("--ttl-ms")
        .arg("60000")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "create-token stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let token_text = std::fs::read_to_string(&token_path).unwrap();
    let token_text = token_text.trim();
    assert_eq!(token_text.len(), 64);
    assert!(!String::from_utf8_lossy(&result.stdout).contains(token_text));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(token_text));
    let mut token = [0_u8; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&token_text[index * 2..index * 2 + 2], 16).unwrap();
    }
    EnrollmentRepository::open(&database)
        .unwrap()
        .validate_token(
            enrollment_token_hash(&token),
            &AgentId::new("agent-cli-token").unwrap(),
            &TunnelId::new("tunnel-cli-token").unwrap(),
            unix_time_now().unwrap(),
        )
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn revoke_and_status_commands_are_idempotent_and_secret_safe() {
    let directory = temp_directory();
    let database = directory.join("snapshots.sqlite");
    SqliteSnapshotRepository::open(&database)
        .unwrap()
        .commit(&VersionedAuthorizationSnapshot::new(
            SnapshotVersion::FIRST,
            AuthorizationSnapshot::default(),
        ))
        .unwrap();
    let token_path = directory.join("bootstrap.token");
    let create = Command::new(binary())
        .args([
            "create-token",
            "--database",
            database.to_str().unwrap(),
            "--agent-id",
            "agent-revoke-cli",
            "--tunnel-id",
            "tunnel-revoke-cli",
            "--output",
            token_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(create.status.success());
    let token_text = std::fs::read_to_string(&token_path).unwrap();
    let token_text = token_text.trim();
    let mut token = [0_u8; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&token_text[index * 2..index * 2 + 2], 16).unwrap();
    }

    for _ in 0..2 {
        let revoke = Command::new(binary())
            .args([
                "revoke-agent",
                "--database",
                database.to_str().unwrap(),
                "--agent-id",
                "agent-revoke-cli",
                "--tunnel-id",
                "tunnel-revoke-cli",
            ])
            .output()
            .unwrap();
        assert!(revoke.status.success());
        assert!(!String::from_utf8_lossy(&revoke.stdout).contains(token_text));
        assert!(!String::from_utf8_lossy(&revoke.stderr).contains(token_text));
    }
    assert!(matches!(
        EnrollmentRepository::open(&database)
            .unwrap()
            .validate_token(
                enrollment_token_hash(&token),
                &AgentId::new("agent-revoke-cli").unwrap(),
                &TunnelId::new("tunnel-revoke-cli").unwrap(),
                unix_time_now().unwrap(),
            ),
        Err(EnrollmentRepositoryError::CredentialRevoked)
    ));

    let status = Command::new(binary())
        .args([
            "credential-status",
            "--database",
            database.to_str().unwrap(),
            "--agent-id",
            "agent-revoke-cli",
            "--tunnel-id",
            "tunnel-revoke-cli",
        ])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("snapshot_version=1"));
    assert!(!String::from_utf8_lossy(&status.stdout).contains(token_text));
    std::fs::remove_dir_all(directory).unwrap();
}
