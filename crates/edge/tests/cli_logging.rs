use std::process::{Command, Output};

use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_tunnelproxy-edge")
}

fn run(args: &[&str], format: &str, filter: &str) -> Output {
    Command::new(binary())
        .args(args)
        .env("TUNNELPROXY_LOG_FORMAT", format)
        .env("RUST_LOG", filter)
        .output()
        .unwrap()
}

#[test]
fn json_mode_emits_one_schema_stable_error_event_to_stderr() {
    let output = run(&["--unknown"], "json", "info");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains('\u{1b}'));
    let lines: Vec<_> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "unexpected stderr: {stderr}");
    let event: Value = serde_json::from_str(lines[0]).unwrap();
    assert!(event["timestamp"].is_string());
    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["target"], "tunnelproxy_edge");
    assert!(event["fields"].is_object());
}

#[test]
fn filter_and_stdout_stderr_contracts_hold() {
    let filtered = run(&["--unknown"], "json", "off");
    assert_eq!(filtered.status.code(), Some(2));
    assert!(filtered.stdout.is_empty());
    assert!(filtered.stderr.is_empty());

    let help = run(&["--help"], "json", "info");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).starts_with("Usage:"));
    assert!(help.stderr.is_empty());
}
