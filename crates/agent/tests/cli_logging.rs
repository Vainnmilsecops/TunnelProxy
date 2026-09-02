use std::process::{Command, Output};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_tunnelproxy-agent")
}

fn canonical_binary() -> &'static str {
    env!("CARGO_BIN_EXE_tunnelproxy")
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
    assert!(stdout.contains("tunnelproxy-agent start [--config <path>] [OPTIONS]"));
    assert!(stdout.contains("managed hostname remains allocated on exit"));
    assert!(help.stderr.is_empty());

    let invalid = run(&["http", "0"], "json", "info");
    assert_error_event(&invalid, "tunnelproxy_agent");
}

#[test]
fn canonical_binary_uses_its_own_name_and_validates_config_without_network() {
    let help = Command::new(canonical_binary())
        .arg("--help")
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("tunnelproxy http <port> [OPTIONS]"));
    assert!(!help.contains("tunnelproxy-agent"));

    let edge = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    edge.set_nonblocking(true).unwrap();
    let hostname = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    hostname.set_nonblocking(true).unwrap();
    let directory =
        std::env::temp_dir().join(format!("tunnelproxy-canonical-cli-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();

    let mut authority_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let authority_key = KeyPair::generate().unwrap();
    let authority = authority_params.self_signed(&authority_key).unwrap();
    let mut client_params = CertificateParams::new(vec!["agent.test".to_owned()]).unwrap();
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client = client_params
        .signed_by(&client_key, &authority, &authority_key)
        .unwrap();
    std::fs::write(directory.join("ca.pem"), authority.pem()).unwrap();
    std::fs::write(directory.join("agent.pem"), client.pem()).unwrap();
    std::fs::write(directory.join("agent-key.pem"), client_key.serialize_pem()).unwrap();
    let config = directory.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{
                "version": 1,
                "edge": {{
                    "address": "{}",
                    "ca": "ca.pem",
                    "server_name": "edge.test"
                }},
                "hostname": {{
                    "address": "{}",
                    "ca": "ca.pem",
                    "server_name": "control.test"
                }},
                "identity": {{
                    "agent_id": "agent-profile",
                    "tunnel_id": "tunnel-profile",
                    "client_certificate": "agent.pem",
                    "client_private_key": "agent-key.pem"
                }}
            }}"#,
            edge.local_addr().unwrap(),
            hostname.local_addr().unwrap()
        ),
    )
    .unwrap();

    let validated = Command::new(canonical_binary())
        .args(["config", "validate", "--config"])
        .arg(&config)
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert!(validated.status.success());
    assert_eq!(validated.stdout, b"configuration valid\n");
    assert!(validated.stderr.is_empty());
    assert!(matches!(
        edge.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert!(matches!(
        hostname.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    let v1_start = Command::new(canonical_binary())
        .args(["start", "--config"])
        .arg(&config)
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert_eq!(v1_start.status.code(), Some(2));

    std::fs::write(
        &config,
        format!(
            r#"{{
                "version": 2,
                "edge": {{
                    "address": "{}",
                    "ca": "ca.pem",
                    "server_name": "edge.test"
                }},
                "hostname": {{
                    "address": "{}",
                    "ca": "ca.pem",
                    "server_name": "control.test"
                }},
                "identity": {{
                    "agent_id": "agent-profile",
                    "client_certificate": "agent.pem",
                    "client_private_key": "agent-key.pem"
                }},
                "tunnels": [
                    {{ "tunnel_id": "tunnel-a", "local_port": 3000 }},
                    {{ "tunnel_id": "tunnel-b", "local_port": 3001 }}
                ]
            }}"#,
            edge.local_addr().unwrap(),
            hostname.local_addr().unwrap()
        ),
    )
    .unwrap();
    let validated_v2 = Command::new(canonical_binary())
        .args(["config", "validate", "--config"])
        .arg(&config)
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert!(validated_v2.status.success());
    assert_eq!(validated_v2.stdout, b"configuration valid\n");
    assert!(validated_v2.stderr.is_empty());
    assert!(matches!(
        edge.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert!(matches!(
        hostname.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    let v2_http = Command::new(canonical_binary())
        .args(["http", "3000", "--config"])
        .arg(&config)
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert_eq!(v2_http.status.code(), Some(2));

    let secret_marker = "INLINE_SECRET_MUST_NOT_BE_LOGGED";
    std::fs::write(&config, format!(r#"{{"secret":"{secret_marker}"}}"#)).unwrap();
    let rejected = Command::new(canonical_binary())
        .args(["config", "validate", "--config"])
        .arg(&config)
        .env("TUNNELPROXY_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert!(!String::from_utf8(rejected.stderr)
        .unwrap()
        .contains(secret_marker));

    std::fs::remove_dir_all(directory).unwrap();
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
