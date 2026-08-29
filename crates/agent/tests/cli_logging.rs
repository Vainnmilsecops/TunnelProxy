use std::process::{Command, Output};

use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_tunnelproxy-agent")
}

fn run(args: &[&str], format: &str, filter: &str) -> Output {
    Command::new(binary())
        .args(args)
        .env("TUNNELPROXY_LOG_FORMAT", format)
        .env("RUST_LOG", filter)
        .output()
        .unwrap()
}

fn run_buffered(args: &[&str], format: &str) -> Output {
    Command::new(binary())
        .args(args)
        .env("TUNNELPROXY_LOG_FORMAT", format)
        .env("TUNNELPROXY_LOG_BUFFER_CAPACITY", "4")
        .env("TUNNELPROXY_LOG_DRAIN_TIMEOUT_MS", "1000")
        .env("RUST_LOG", "info")
        .output()
        .unwrap()
}

fn assert_error_event(output: &Output, expected_target: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(!stderr.contains('\u{1b}'));
    let lines: Vec<_> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "unexpected stderr: {stderr}");
    let event: Value = serde_json::from_str(lines[0]).unwrap();
    assert!(event["timestamp"].is_string());
    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["target"], expected_target);
    assert!(event["fields"].is_object());
}

#[test]
fn json_mode_emits_one_schema_stable_error_event_to_stderr() {
    let output = run(&["--unknown"], "json", "info");
    assert_error_event(&output, "tunnelproxy_agent");
}

#[test]
fn filter_can_disable_json_events() {
    let output = run(&["--unknown"], "json", "off");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn help_remains_plain_stdout_in_json_mode() {
    let output = run(&["--help"], "json", "info");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("Usage:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn managed_http_help_and_configuration_errors_preserve_cli_contracts() {
    let help = run(&["http", "--help"], "json", "info");
    assert!(help.status.success());
    let stdout = String::from_utf8(help.stdout).unwrap();
    assert!(stdout.contains("tunnelproxy-agent http <port> [OPTIONS]"));
    assert!(stdout.contains("managed hostname remains allocated on exit"));
    assert!(help.stderr.is_empty());

    let invalid = run(&["http", "0"], "json", "info");
    assert_error_event(&invalid, "tunnelproxy_agent");
}

#[test]
fn invalid_operations_config_fails_before_outbound_connect() {
    let edge = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    edge.set_nonblocking(true).unwrap();
    let occupied_operations = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let output = Command::new(binary())
        .args([
            "--edge",
            &edge.local_addr().unwrap().to_string(),
            "--ops-listen",
            &occupied_operations.local_addr().unwrap().to_string(),
        ])
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(matches!(
        edge.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    let non_loopback = run(&["--ops-listen", "0.0.0.0:9091"], "json", "info");
    assert_eq!(non_loopback.status.code(), Some(2));
}

#[test]
fn buffered_text_and_json_errors_are_drained_before_exit() {
    let text = run_buffered(&["--unknown"], "text");
    assert_eq!(text.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&text.stderr).contains("invalid Agent CLI arguments"));

    let json = run_buffered(&["--unknown"], "json");
    assert_error_event(&json, "tunnelproxy_agent");
}
