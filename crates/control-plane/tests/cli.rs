use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use tunnelproxy_common::{AgentId, PublicHostname, TunnelId};
use tunnelproxy_control_plane::{
    enrollment_token_hash, unix_time_now, AuthorizationSnapshot, EnrollmentRepository,
    EnrollmentRepositoryError, HttpsRouteRepository, HttpsRouteStatus, SnapshotRepository,
    SnapshotVersion, SqliteSnapshotRepository, VersionedAuthorizationSnapshot,
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
    let help = Command::new(binary())
        .arg("--help")
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("snapshot JSON manifest"));
    assert!(help.stderr.is_empty());

    let invalid = Command::new(binary())
        .arg("serve")
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    let stderr = String::from_utf8(invalid.stderr).unwrap();
    assert!(!stderr.contains('\u{1b}'));
    let event: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert!(event["timestamp"].is_string());
    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["target"], "tunnelproxy_control_plane");
    assert!(event["fields"].is_object());
}

#[test]
fn buffered_text_and_json_errors_are_drained_before_exit() {
    for format in ["text", "json"] {
        let output = Command::new(binary())
            .arg("serve")
            .env("TUNNELPROXY_LOG_FORMAT", format)
            .env("TUNNELPROXY_LOG_BUFFER_CAPACITY", "4")
            .env("TUNNELPROXY_LOG_DRAIN_TIMEOUT_MS", "1000")
            .env("RUST_LOG", "info")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        if format == "json" {
            let event: Value = serde_json::from_str(stderr.trim()).unwrap();
            assert_eq!(event["target"], "tunnelproxy_control_plane");
        } else {
            assert!(stderr.contains("invalid Control Plane CLI arguments"));
        }
    }
}

#[test]
fn invalid_logging_configuration_stops_before_file_mutation() {
    let directory = temp_directory();
    for (suffix, format, filter, capacity) in [
        ("format", "secret-format", None, None),
        ("filter", "json", Some("secret-filter["), None),
        ("buffer", "json", None, Some("secret-capacity")),
    ] {
        let database = directory.join(format!("must-not-exist-{suffix}.sqlite"));
        let token = directory.join(format!("must-not-exist-{suffix}.token"));
        let mut command = Command::new(binary());
        command
            .args([
                "create-token",
                "--database",
                database.to_str().unwrap(),
                "--agent-id",
                "agent-no-mutation",
                "--tunnel-id",
                "tunnel-no-mutation",
                "--output",
                token.to_str().unwrap(),
            ])
            .env("TUNNELPROXY_LOG_FORMAT", format);
        if let Some(filter) = filter {
            command.env("RUST_LOG", filter);
        }
        if let Some(capacity) = capacity {
            command.env("TUNNELPROXY_LOG_BUFFER_CAPACITY", capacity);
        }
        let result = command.output().unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-"));
        assert!(!database.exists());
        assert!(!token.exists());
    }
    std::fs::remove_dir_all(directory).unwrap();
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
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
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
    for line in String::from_utf8_lossy(&result.stderr).lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert!(event["fields"].is_object());
    }
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

#[test]
fn https_route_cli_is_canonical_idempotent_sorted_and_validates_before_mutation() {
    let directory = temp_directory();
    let invalid_database = directory.join("must-not-exist.sqlite");
    let invalid = Command::new(binary())
        .args([
            "https-route-upsert",
            "--database",
            invalid_database.to_str().unwrap(),
            "--hostname",
            "*.example.test",
            "--tunnel-id",
            "tunnel-invalid",
            "--status",
            "enabled",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!invalid_database.exists());

    let database = directory.join("state.sqlite");
    let first = Command::new(binary())
        .args([
            "https-route-upsert",
            "--database",
            database.to_str().unwrap(),
            "--hostname",
            "Z.Example.TEST.",
            "--tunnel-id",
            "tunnel-z",
            "--status",
            "enabled",
        ])
        .output()
        .unwrap();
    assert!(first.status.success());
    assert_eq!(
        String::from_utf8(first.stdout).unwrap(),
        "catalog_version=2 changed=true\n"
    );
    let repeated = Command::new(binary())
        .args([
            "https-route-upsert",
            "--database",
            database.to_str().unwrap(),
            "--hostname",
            "z.example.test",
            "--tunnel-id",
            "tunnel-z",
            "--status",
            "enabled",
        ])
        .output()
        .unwrap();
    assert!(repeated.status.success());
    assert_eq!(
        String::from_utf8(repeated.stdout).unwrap(),
        "catalog_version=2 changed=false\n"
    );
    let second = Command::new(binary())
        .args([
            "https-route-upsert",
            "--database",
            database.to_str().unwrap(),
            "--hostname",
            "a.example.test",
            "--tunnel-id",
            "tunnel-a",
            "--status",
            "disabled",
        ])
        .output()
        .unwrap();
    assert!(second.status.success());

    let listed = Command::new(binary())
        .args(["https-route-list", "--database", database.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap(),
        "catalog_version=3\nhostname=a.example.test tunnel_id=tunnel-a status=disabled\nhostname=z.example.test tunnel_id=tunnel-z status=enabled\n"
    );

    let removed = Command::new(binary())
        .args([
            "https-route-remove",
            "--database",
            database.to_str().unwrap(),
            "--hostname",
            "a.example.test",
        ])
        .output()
        .unwrap();
    assert!(removed.status.success());
    assert_eq!(
        String::from_utf8(removed.stdout).unwrap(),
        "catalog_version=4 changed=true\n"
    );
    let absent = Command::new(binary())
        .args([
            "https-route-remove",
            "--database",
            database.to_str().unwrap(),
            "--hostname",
            "a.example.test",
        ])
        .output()
        .unwrap();
    assert!(absent.status.success());
    assert_eq!(
        String::from_utf8(absent.stdout).unwrap(),
        "catalog_version=4 changed=false\n"
    );

    let catalog = HttpsRouteRepository::open(&database)
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(catalog.version().get(), 4);
    assert_eq!(catalog.routes().len(), 1);
    assert_eq!(
        catalog.routes()[0].hostname,
        PublicHostname::new("z.example.test").unwrap()
    );
    assert_eq!(catalog.routes()[0].status, HttpsRouteStatus::Enabled);
    std::fs::remove_dir_all(directory).unwrap();
}
