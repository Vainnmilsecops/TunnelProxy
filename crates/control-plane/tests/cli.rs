use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use tunnelproxy_control_plane::{SnapshotRepository, SqliteSnapshotRepository};

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
