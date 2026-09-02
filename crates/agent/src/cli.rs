//! Shared runnable Agent CLI driver used by both installed executables.

use std::collections::HashSet;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::{
    bootstrap_agent_credentials, AgentEnrollmentConfig, AgentEnrollmentError,
    AgentEnrollmentRuntime, AgentHostnameClient, AgentHostnameError, AgentOperationsConfig,
    AgentOperationsError, AgentOperationsOutcome, AgentOperationsRuntime, AgentOperationsTunnel,
    AgentRuntime, AgentRuntimeConfig, AgentRuntimeOutcome, AgentTlsConfig, AgentTlsConfigError,
    AgentTlsReloadBootstrapError, AgentTlsReloadConfig, AgentTlsReloadRuntime,
    AgentTransportSecurity, EnrollmentClientConfig, HostnameClientConfig, MultiAgentRuntime,
    MultiAgentRuntimeError, MultiAgentRuntimeOutcome, PublicReachabilityConfig,
    PublicReachabilityError, PublicReachabilityMonitorConfig, PublicReachabilityProbe,
    PublicReachabilityState, RuntimeShutdownConfig, DEFAULT_PUBLIC_REACHABILITY_ATTEMPT_TIMEOUT,
    DEFAULT_PUBLIC_REACHABILITY_FAILURE_THRESHOLD, DEFAULT_PUBLIC_REACHABILITY_RETRY_INTERVAL,
    DEFAULT_PUBLIC_REACHABILITY_TIMEOUT, MAX_MANAGED_HTTP_TUNNELS,
    MAX_PUBLIC_REACHABILITY_FAILURE_THRESHOLD, MAX_PUBLIC_REACHABILITY_MONITOR_INTERVAL,
    MAX_PUBLIC_REACHABILITY_TIMEOUT, MIN_PUBLIC_REACHABILITY_MONITOR_INTERVAL,
};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tunnelproxy_common::{
    init_process_logging, shutdown_channel, wait_for_process_shutdown, AgentCredentialPaths,
    AgentId, ProcessLogFormat, PublicHostname, ShutdownSignal, TunnelId,
};
use tunnelproxy_protocol::RegistrationRequest;

// Preserve the original runnable binary's stable tracing target after moving
// the shared driver into the library for use by both executable wrappers.
macro_rules! error {
    ($($tokens:tt)*) => {
        tracing::error!(target: "tunnelproxy_agent", $($tokens)*)
    };
}

macro_rules! info {
    ($($tokens:tt)*) => {
        tracing::info!(target: "tunnelproxy_agent", $($tokens)*)
    };
}

macro_rules! warn {
    ($($tokens:tt)*) => {
        tracing::warn!(target: "tunnelproxy_agent", $($tokens)*)
    };
}

const USAGE_TEMPLATE: &str = "\
Usage:
  tunnelproxy-agent [OPTIONS]
  tunnelproxy-agent http <port> [OPTIONS]
  tunnelproxy-agent start [--config <path>] [OPTIONS]
  tunnelproxy-agent config validate [--config <path>]
  tunnelproxy-agent hostname-allocate [OPTIONS]
  tunnelproxy-agent hostname-release [OPTIONS]

Options:
  --config <path>                strict local Agent config v1/v2
  --edge <addr>                  Edge address  (default 127.0.0.1:7100)
  --local <addr>                 local service (default 127.0.0.1:3000)
  --agent-id <id>                durable Agent ID (default agent-dev)
  --tunnel-id <id>               durable Tunnel ID (default tunnel-dev)
  --max-streams <usize>          stream limit  (default 32)
  --connect-timeout-ms <ms>      TCP timeout   (default 5000)
  --handshake-timeout-ms <ms>    handshake     (default 10000)
  --drain-timeout-ms <ms>        stream drain  (default 10000)
  --reconnect-initial-ms <ms>    first retry   (default 250)
  --reconnect-max-ms <ms>        retry ceiling (default 30000)
  --reconnect-multiplier <n>     backoff factor(default 2)
  --reconnect-jitter-percent <n> downward jitter (default 20)
  --stable-session-reset-ms <ms> reset streak  (default 30000)
  --max-reconnect-attempts <n>   failure limit (default unlimited)
  --ops-listen <loopback-addr>   enable health/readiness/metrics endpoint
  --max-ops-connections <usize>  operations connection limit (default 8)
  --ops-header-timeout-ms <ms>   operations header deadline (default 2000)
  --ops-request-timeout-ms <ms>  operations request deadline (default 5000)
  --tls-ca <path>                trusted Edge CA PEM
  --tls-client-cert <path>       Agent certificate PEM
  --tls-client-key <path>        Agent private key PEM
  --tls-server-name <name>       verified Edge DNS name
  --tls-handshake-timeout-ms <ms> TLS timeout  (default 10000)
  --tls-reload-manifest <path>   atomic TLS generation manifest
  --tls-reload-interval-ms <ms>  reload poll   (default 1000)
  --tls-expiry-warning-ms <ms>   expiry warning(default 604800000)
  --enroll-only                  enroll/renew credentials and exit
  --enrollment-server <addr>     Control Plane enrollment address
  --enrollment-ca <path>         trusted enrollment server CA PEM
  --enrollment-server-name <name> verified enrollment DNS name
  --enrollment-token <path>      bootstrap/current renewal token file
  --enrollment-pending <path>    durable enrollment journal file
  --renew-before-ms <ms>         renew before expiry (default 604800000)
  --enrollment-poll-ms <ms>      renewal poll interval (default 60000)
  --enrollment-connect-timeout-ms <ms> TCP timeout (default 5000)
  --enrollment-handshake-timeout-ms <ms> TLS timeout (default 10000)
  --enrollment-request-timeout-ms <ms> request timeout (default 30000)
  --enrollment-activation-timeout-ms <ms> reload wait (default 30000)
Hostname command options:
  --hostname-server <addr>          Control Plane hostname address (required)
  --hostname-ca <path>              trusted hostname server CA PEM (required)
  --hostname-server-name <name>     verified hostname service DNS name (required)
  --tls-client-cert <path>          Agent certificate PEM (required)
  --tls-client-key <path>           Agent private key PEM (required)
  --agent-id <id>                   authorized Agent ID (required)
  --tunnel-id <id>                  authorized Tunnel ID (required)
  --connect-timeout-ms <ms>         TCP timeout (default 5000)
  --tls-handshake-timeout-ms <ms>   TLS timeout (default 10000)
  --request-timeout-ms <ms>         request timeout (default 5000)
Managed HTTP options:
  --hostname-server <addr>          Control Plane hostname address (required without config)
  --hostname-ca <path>              trusted hostname server CA PEM (required without config)
  --hostname-server-name <name>     verified hostname service DNS name (required without config)
  --hostname-request-timeout-ms <ms> allocation deadline (default 5000)
  --verify-public-reachability        wait for a public HTTPS Edge challenge
  --public-reachability-ca <path>     optional private/public probe CA bundle
  --public-reachability-timeout-ms <ms> total probe deadline (default 30000)
  --public-reachability-monitor-interval-ms <ms> continuous check delay (10000..3600000)
  --public-reachability-failure-threshold <n> failures before unready (default 3)
  Uses the common Edge, Agent identity, TLS, reconnect, enrollment, and
  operations options above. The managed hostname remains allocated on exit.
Multi-tunnel options:
  start requires config v2 with 1..16 unique TunnelIds and loopback ports.
  Shared CLI options override shared config; --local, --tunnel-id, and
  --enroll-only are rejected. Each tunnel uses one Agent transport.
  --help                         print this help and exit
";

const AGENT_CONFIG_VERSION: u32 = 1;
const MULTI_AGENT_CONFIG_VERSION: u32 = 2;
const MAX_AGENT_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_PUBLIC_REACHABILITY_CA_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigFile {
    version: u32,
    edge: AgentConfigEdge,
    hostname: AgentConfigHostname,
    identity: AgentConfigIdentity,
    #[serde(default)]
    public_reachability: Option<AgentConfigPublicReachability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiAgentConfigFile {
    version: u32,
    edge: AgentConfigEdge,
    hostname: AgentConfigHostname,
    identity: MultiAgentConfigIdentity,
    tunnels: Vec<AgentConfigTunnel>,
    #[serde(default)]
    public_reachability: Option<AgentConfigPublicReachability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiAgentConfigIdentity {
    agent_id: String,
    client_certificate: PathBuf,
    client_private_key: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigTunnel {
    tunnel_id: String,
    local_port: u16,
}

#[derive(Debug)]
enum AgentConfigDocument {
    Single(AgentConfigFile),
    Multi(MultiAgentConfigFile),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedTunnelSpec {
    tunnel_id: TunnelId,
    local: SocketAddr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigEdge {
    address: String,
    ca: PathBuf,
    server_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigHostname {
    address: String,
    ca: PathBuf,
    server_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigIdentity {
    agent_id: String,
    tunnel_id: String,
    client_certificate: PathBuf,
    client_private_key: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigPublicReachability {
    enabled: bool,
    ca: Option<PathBuf>,
    timeout_ms: Option<u64>,
    monitor_interval_ms: Option<u64>,
    failure_threshold: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigPathSource {
    Explicit,
    Environment,
    PlatformDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedConfigPath {
    path: PathBuf,
    source: ConfigPathSource,
}

#[derive(Debug)]
enum AgentConfigError {
    MissingPath,
    NotFound,
    Read,
    TooLarge,
    InvalidSchema,
    UnsupportedVersion,
    VersionRequiresCommand,
    InvalidAddress(&'static str),
    InvalidIdentifier(&'static str),
    EmptyTunnels,
    TooManyTunnels,
    DuplicateTunnel,
    ZeroLocalPort,
    EmptyPath(&'static str),
    InvalidTls,
}

impl std::fmt::Display for AgentConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingPath => "Agent config path is unavailable",
            Self::NotFound => "Agent config file was not found",
            Self::Read => "Agent config file could not be read",
            Self::TooLarge => "Agent config file exceeds the 64 KiB limit",
            Self::InvalidSchema => "Agent config schema is invalid",
            Self::UnsupportedVersion => "Agent config version is unsupported",
            Self::VersionRequiresCommand => "Agent config version does not support this command",
            Self::InvalidAddress(kind) => {
                return write!(formatter, "Agent config {kind} address is invalid")
            }
            Self::InvalidIdentifier(kind) => {
                return write!(formatter, "Agent config {kind} is invalid")
            }
            Self::EmptyTunnels => "Agent config must contain at least one tunnel",
            Self::TooManyTunnels => "Agent config exceeds the 16-tunnel limit",
            Self::DuplicateTunnel => "Agent config contains a duplicate TunnelId",
            Self::ZeroLocalPort => "Agent config tunnel local_port must be greater than zero",
            Self::EmptyPath(kind) => return write!(formatter, "Agent config {kind} path is empty"),
            Self::InvalidTls => "Agent config TLS material is invalid",
        })
    }
}

impl std::error::Error for AgentConfigError {}

fn platform_default_config_path(
    windows: bool,
    app_data: Option<OsString>,
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    if windows {
        return app_data
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(|base| base.join("TunnelProxy").join("config.json"));
    }
    if let Some(base) = xdg_config_home.filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(base).join("tunnelproxy").join("config.json"));
    }
    home.filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|base| base.join(".config").join("tunnelproxy").join("config.json"))
}

fn runtime_default_config_path() -> Option<PathBuf> {
    platform_default_config_path(
        cfg!(windows),
        std::env::var_os("APPDATA"),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn select_config_path_from(
    explicit: Option<&Path>,
    environment: Option<OsString>,
    platform_default: Option<PathBuf>,
) -> Result<SelectedConfigPath, AgentConfigError> {
    if let Some(path) = explicit {
        if path.as_os_str().is_empty() {
            return Err(AgentConfigError::MissingPath);
        }
        return Ok(SelectedConfigPath {
            path: path.to_owned(),
            source: ConfigPathSource::Explicit,
        });
    }
    if let Some(path) = environment.filter(|value| !value.is_empty()) {
        return Ok(SelectedConfigPath {
            path: PathBuf::from(path),
            source: ConfigPathSource::Environment,
        });
    }
    platform_default
        .map(|path| SelectedConfigPath {
            path,
            source: ConfigPathSource::PlatformDefault,
        })
        .ok_or(AgentConfigError::MissingPath)
}

fn select_config_path(explicit: Option<&Path>) -> Result<SelectedConfigPath, AgentConfigError> {
    select_config_path_from(
        explicit,
        std::env::var_os("TUNNELPROXY_CONFIG"),
        runtime_default_config_path(),
    )
}

async fn load_agent_config(path: &Path) -> Result<AgentConfigDocument, AgentConfigError> {
    let file = tokio::fs::File::open(path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AgentConfigError::NotFound
        } else {
            AgentConfigError::Read
        }
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_AGENT_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| AgentConfigError::Read)?;
    if bytes.len() as u64 > MAX_AGENT_CONFIG_BYTES {
        return Err(AgentConfigError::TooLarge);
    }
    parse_agent_config(&bytes)
}

fn parse_agent_config(bytes: &[u8]) -> Result<AgentConfigDocument, AgentConfigError> {
    if let Ok(config) = serde_json::from_slice::<AgentConfigFile>(bytes) {
        if config.version != AGENT_CONFIG_VERSION {
            return Err(AgentConfigError::UnsupportedVersion);
        }
        return Ok(AgentConfigDocument::Single(config));
    }
    let config: MultiAgentConfigFile =
        serde_json::from_slice(bytes).map_err(|_| AgentConfigError::InvalidSchema)?;
    if config.version != MULTI_AGENT_CONFIG_VERSION {
        return Err(AgentConfigError::UnsupportedVersion);
    }
    Ok(AgentConfigDocument::Multi(config))
}

fn resolve_config_relative_path(config_path: &Path, value: PathBuf) -> PathBuf {
    if value.is_absolute() {
        value
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(value)
    }
}

fn require_nonempty_path(path: &Path, kind: &'static str) -> Result<(), AgentConfigError> {
    if path.as_os_str().is_empty() {
        Err(AgentConfigError::EmptyPath(kind))
    } else {
        Ok(())
    }
}

fn apply_agent_config(
    parsed: &mut ParsedArgs,
    config_path: &Path,
    config: AgentConfigFile,
) -> Result<(), AgentConfigError> {
    let tunnel_id = TunnelId::new(&config.identity.tunnel_id)
        .map_err(|_| AgentConfigError::InvalidIdentifier("TunnelId"))?;
    if !parsed.tunnel_id_explicit {
        parsed.tunnel_id = tunnel_id;
    }
    apply_shared_agent_config(
        parsed,
        config_path,
        config.edge,
        config.hostname,
        config.identity.agent_id,
        config.identity.client_certificate,
        config.identity.client_private_key,
        config.public_reachability,
    )
}

fn apply_multi_agent_config(
    parsed: &mut ParsedArgs,
    config_path: &Path,
    config: MultiAgentConfigFile,
) -> Result<Vec<ManagedTunnelSpec>, AgentConfigError> {
    if config.tunnels.is_empty() {
        return Err(AgentConfigError::EmptyTunnels);
    }
    if config.tunnels.len() > MAX_MANAGED_HTTP_TUNNELS {
        return Err(AgentConfigError::TooManyTunnels);
    }
    let mut seen = HashSet::with_capacity(config.tunnels.len());
    let mut tunnels = Vec::with_capacity(config.tunnels.len());
    for tunnel in config.tunnels {
        let tunnel_id = TunnelId::new(&tunnel.tunnel_id)
            .map_err(|_| AgentConfigError::InvalidIdentifier("TunnelId"))?;
        if !seen.insert(tunnel_id.clone()) {
            return Err(AgentConfigError::DuplicateTunnel);
        }
        if tunnel.local_port == 0 {
            return Err(AgentConfigError::ZeroLocalPort);
        }
        tunnels.push(ManagedTunnelSpec {
            tunnel_id,
            local: SocketAddr::from(([127, 0, 0, 1], tunnel.local_port)),
        });
    }
    apply_shared_agent_config(
        parsed,
        config_path,
        config.edge,
        config.hostname,
        config.identity.agent_id,
        config.identity.client_certificate,
        config.identity.client_private_key,
        config.public_reachability,
    )?;
    Ok(tunnels)
}

#[allow(clippy::too_many_arguments)]
fn apply_shared_agent_config(
    parsed: &mut ParsedArgs,
    config_path: &Path,
    edge_config: AgentConfigEdge,
    hostname_config: AgentConfigHostname,
    agent_id_raw: String,
    client_certificate_path: PathBuf,
    client_private_key_path: PathBuf,
    public_reachability: Option<AgentConfigPublicReachability>,
) -> Result<(), AgentConfigError> {
    let edge = edge_config
        .address
        .parse::<SocketAddr>()
        .map_err(|_| AgentConfigError::InvalidAddress("Edge"))?;
    let hostname = hostname_config
        .address
        .parse::<SocketAddr>()
        .map_err(|_| AgentConfigError::InvalidAddress("hostname service"))?;
    let agent_id =
        AgentId::new(&agent_id_raw).map_err(|_| AgentConfigError::InvalidIdentifier("AgentId"))?;
    require_nonempty_path(&edge_config.ca, "Edge CA")?;
    require_nonempty_path(&hostname_config.ca, "hostname CA")?;
    require_nonempty_path(&client_certificate_path, "client certificate")?;
    require_nonempty_path(&client_private_key_path, "client private key")?;
    let edge_ca = resolve_config_relative_path(config_path, edge_config.ca);
    let hostname_ca = resolve_config_relative_path(config_path, hostname_config.ca);
    let client_certificate = resolve_config_relative_path(config_path, client_certificate_path);
    let client_private_key = resolve_config_relative_path(config_path, client_private_key_path);

    if !parsed.edge_explicit {
        parsed.edge = edge;
    }
    if !parsed.hostname_server_explicit {
        parsed.hostname_server = Some(hostname);
    }
    if !parsed.agent_id_explicit {
        parsed.agent_id = agent_id;
    }
    if !parsed.tls_ca_explicit {
        parsed.tls_ca = Some(edge_ca);
    }
    if !parsed.hostname_ca_explicit {
        parsed.hostname_ca = Some(hostname_ca);
    }
    if !parsed.tls_client_cert_explicit {
        parsed.tls_client_cert = Some(client_certificate);
    }
    if !parsed.tls_client_key_explicit {
        parsed.tls_client_key = Some(client_private_key);
    }
    if !parsed.tls_server_name_explicit {
        parsed.tls_server_name = Some(edge_config.server_name);
    }
    if !parsed.hostname_server_name_explicit {
        parsed.hostname_server_name = Some(hostname_config.server_name);
    }
    if let Some(reachability) = public_reachability {
        if !reachability.enabled
            && (reachability.ca.is_some()
                || reachability.timeout_ms.is_some()
                || reachability.monitor_interval_ms.is_some()
                || reachability.failure_threshold.is_some())
        {
            return Err(AgentConfigError::InvalidSchema);
        }
        if !parsed.verify_public_reachability_explicit {
            parsed.verify_public_reachability = reachability.enabled;
        }
        if let Some(ca) = reachability.ca {
            require_nonempty_path(&ca, "public reachability CA")?;
            if !parsed.public_reachability_ca_explicit {
                parsed.public_reachability_ca = Some(resolve_config_relative_path(config_path, ca));
            }
            parsed.public_reachability_options_present = true;
        }
        if let Some(timeout_ms) = reachability.timeout_ms {
            if !parsed.public_reachability_timeout_explicit {
                parsed.public_reachability_timeout = Duration::from_millis(timeout_ms);
            }
            parsed.public_reachability_options_present = true;
        }
        if let Some(interval_ms) = reachability.monitor_interval_ms {
            if !parsed.public_reachability_monitor_interval_explicit {
                parsed.public_reachability_monitor_interval =
                    Some(Duration::from_millis(interval_ms));
            }
            parsed.public_reachability_options_present = true;
        }
        if let Some(failure_threshold) = reachability.failure_threshold {
            if !parsed.public_reachability_failure_threshold_explicit {
                parsed.public_reachability_failure_threshold = failure_threshold;
            }
            parsed.public_reachability_failure_threshold_present = true;
            parsed.public_reachability_options_present = true;
        }
    }
    parsed.hostname_options_present = true;
    Ok(())
}

fn http_configuration_complete(parsed: &ParsedArgs) -> bool {
    matches!(
        (
            &parsed.tls_ca,
            &parsed.tls_client_cert,
            &parsed.tls_client_key,
            &parsed.tls_server_name,
            parsed.hostname_server,
            &parsed.hostname_ca,
            &parsed.hostname_server_name,
        ),
        (
            Some(_),
            Some(_),
            Some(_),
            Some(_),
            Some(_),
            Some(_),
            Some(_)
        )
    )
}

fn validate_http_configuration(parsed: &ParsedArgs) -> Result<(), ArgError> {
    if !matches!(
        (
            &parsed.tls_ca,
            &parsed.tls_client_cert,
            &parsed.tls_client_key,
            &parsed.tls_server_name,
        ),
        (Some(_), Some(_), Some(_), Some(_))
    ) {
        return Err(ArgError::HttpRequiresMutualTls);
    }
    if !matches!(
        (
            parsed.hostname_server,
            &parsed.hostname_ca,
            &parsed.hostname_server_name,
        ),
        (Some(_), Some(_), Some(_))
    ) {
        return Err(ArgError::IncompleteHostnameOptions);
    }
    if parsed.public_reachability_options_present && !parsed.verify_public_reachability {
        return Err(ArgError::PublicReachabilityOptionsWithoutOptIn);
    }
    if parsed.verify_public_reachability
        && (parsed.public_reachability_timeout.is_zero()
            || parsed.public_reachability_timeout > MAX_PUBLIC_REACHABILITY_TIMEOUT)
    {
        return Err(ArgError::InvalidPublicReachabilityTimeout);
    }
    if let Some(interval) = parsed.public_reachability_monitor_interval {
        if !(MIN_PUBLIC_REACHABILITY_MONITOR_INTERVAL..=MAX_PUBLIC_REACHABILITY_MONITOR_INTERVAL)
            .contains(&interval)
        {
            return Err(ArgError::InvalidPublicReachabilityMonitorInterval);
        }
    }
    if parsed.public_reachability_failure_threshold_present
        && parsed.public_reachability_monitor_interval.is_none()
    {
        return Err(ArgError::PublicReachabilityThresholdRequiresMonitor);
    }
    if parsed.public_reachability_failure_threshold == 0
        || parsed.public_reachability_failure_threshold > MAX_PUBLIC_REACHABILITY_FAILURE_THRESHOLD
    {
        return Err(ArgError::InvalidPublicReachabilityFailureThreshold);
    }
    Ok(())
}

async fn apply_optional_http_config(parsed: &mut ParsedArgs) -> Result<(), AgentConfigError> {
    let selected = match select_config_path(parsed.config_path.as_deref()) {
        Ok(selected) => selected,
        Err(AgentConfigError::MissingPath) if http_configuration_complete(parsed) => return Ok(()),
        Err(error) => return Err(error),
    };
    match load_agent_config(&selected.path).await {
        Ok(AgentConfigDocument::Single(config)) => {
            apply_agent_config(parsed, &selected.path, config)
        }
        Ok(AgentConfigDocument::Multi(_)) => Err(AgentConfigError::VersionRequiresCommand),
        Err(AgentConfigError::NotFound)
            if selected.source == ConfigPathSource::PlatformDefault
                && http_configuration_complete(parsed) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn parse_config_validate_command(args: &[String]) -> Result<Option<PathBuf>, ArgError> {
    if args.get(1).map(String::as_str) != Some("validate") {
        return Err(ArgError::MissingRequired("config validate"));
    }
    let mut config_path = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(value(args, index, "--config")?));
                index += 2;
            }
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
    }
    Ok(config_path)
}

#[derive(Debug)]
enum ConfigValidateError {
    Arguments(ArgError),
    Config(AgentConfigError),
}

impl std::fmt::Display for ConfigValidateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arguments(error) => error.fmt(formatter),
            Self::Config(error) => error.fmt(formatter),
        }
    }
}

async fn run_config_validate(args: &[String]) -> Result<(), ConfigValidateError> {
    let explicit = parse_config_validate_command(args).map_err(ConfigValidateError::Arguments)?;
    let selected = select_config_path(explicit.as_deref()).map_err(ConfigValidateError::Config)?;
    let document = load_agent_config(&selected.path)
        .await
        .map_err(ConfigValidateError::Config)?;
    let mut parsed = ParsedArgs::default();
    let tunnels = match document {
        AgentConfigDocument::Single(config) => {
            apply_agent_config(&mut parsed, &selected.path, config)
                .map_err(ConfigValidateError::Config)?;
            vec![ManagedTunnelSpec {
                tunnel_id: parsed.tunnel_id.clone(),
                local: parsed.local,
            }]
        }
        AgentConfigDocument::Multi(config) => {
            apply_multi_agent_config(&mut parsed, &selected.path, config)
                .map_err(ConfigValidateError::Config)?
        }
    };
    validate_http_configuration(&parsed).map_err(ConfigValidateError::Arguments)?;
    let loaded = load_transport_security(&parsed)
        .await
        .map_err(|_| ConfigValidateError::Config(AgentConfigError::InvalidTls))?;
    load_http_hostname_client(&parsed)
        .await
        .map_err(|_| ConfigValidateError::Config(AgentConfigError::InvalidTls))?;
    load_public_reachability_template(&parsed)
        .await
        .map_err(|_| ConfigValidateError::Config(AgentConfigError::InvalidTls))?;
    let configs = tunnels
        .into_iter()
        .map(|tunnel| {
            let mut runtime = AgentRuntimeConfig::new(parsed.edge, tunnel.local);
            runtime.registration =
                RegistrationRequest::new(parsed.agent_id.clone(), tunnel.tunnel_id);
            runtime.security = loaded.security.clone();
            runtime
        })
        .collect::<Vec<_>>();
    MultiAgentRuntime::new(configs)
        .map_err(|_| ConfigValidateError::Config(AgentConfigError::InvalidSchema))?;
    Ok(())
}

async fn apply_required_multi_config(
    parsed: &mut ParsedArgs,
) -> Result<Vec<ManagedTunnelSpec>, AgentConfigError> {
    let selected = select_config_path(parsed.config_path.as_deref())?;
    match load_agent_config(&selected.path).await? {
        AgentConfigDocument::Multi(config) => {
            apply_multi_agent_config(parsed, &selected.path, config)
        }
        AgentConfigDocument::Single(_) => Err(AgentConfigError::VersionRequiresCommand),
    }
}

/// Runs the shared Agent CLI using the executable name supplied by its wrapper.
pub async fn run(binary_name: &'static str) -> ExitCode {
    let logging = match init_process_logging() {
        Ok(logging) => logging,
        Err(error) => {
            eprintln!("failed to configure logging: {error}");
            return ExitCode::from(2);
        }
    };
    let log_format = logging.format();
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("config") {
        if args
            .iter()
            .skip(1)
            .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
        {
            println!("{}", usage(binary_name));
            return ExitCode::SUCCESS;
        }
        return match run_config_validate(&args).await {
            Ok(()) => {
                println!("configuration valid");
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "Agent config validation failed");
                print_usage_for_error(log_format, binary_name);
                ExitCode::from(2)
            }
        };
    }
    if matches!(
        args.first().map(String::as_str),
        Some("hostname-allocate" | "hostname-release")
    ) {
        if matches!(args.get(1).map(String::as_str), Some("--help" | "-h")) {
            println!("{}", usage(binary_name));
            return ExitCode::SUCCESS;
        }
        return match run_hostname_command(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let configuration_error = error.is_configuration_error();
                error!(%error, "Agent hostname command failed");
                if configuration_error {
                    print_usage_for_error(log_format, binary_name);
                    ExitCode::from(2)
                } else {
                    ExitCode::from(1)
                }
            }
        };
    }
    if args.first().map(String::as_str) == Some("start") {
        if matches!(args.get(1).map(String::as_str), Some("--help" | "-h")) {
            println!("{}", usage(binary_name));
            return ExitCode::SUCCESS;
        }
        return run_multi_tunnel(binary_name, log_format, &args[1..]).await;
    }
    if matches!(
        (
            args.first().map(String::as_str),
            args.get(1).map(String::as_str)
        ),
        (Some("http"), Some("--help" | "-h"))
    ) {
        println!("{}", usage(binary_name));
        return ExitCode::SUCCESS;
    }
    let (mode, mut parsed) = match parse_run_command(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            error!(%error, "invalid Agent CLI arguments");
            print_usage_for_error(log_format, binary_name);
            return ExitCode::from(2);
        }
    };
    if parsed.help {
        println!("{}", usage(binary_name));
        return ExitCode::SUCCESS;
    }
    if mode == RunMode::Http {
        if let Err(error) = apply_optional_http_config(&mut parsed).await {
            error!(%error, "failed to load Agent config");
            print_usage_for_error(log_format, binary_name);
            return ExitCode::from(2);
        }
        if let Err(error) = validate_http_configuration(&parsed) {
            error!(%error, "invalid managed HTTP configuration");
            print_usage_for_error(log_format, binary_name);
            return ExitCode::from(2);
        }
    }

    let enrollment_config = match load_enrollment_config(&parsed).await {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "failed to configure Agent enrollment");
            return ExitCode::from(2);
        }
    };
    if parsed.enroll_only {
        let Some(config) = enrollment_config.as_ref() else {
            error!("--enroll-only requires complete enrollment arguments");
            return ExitCode::from(2);
        };
        return match bootstrap_agent_credentials(config).await {
            Ok(generation) => {
                info!(generation, "Agent credential enrollment completed");
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "Agent credential enrollment failed");
                ExitCode::from(1)
            }
        };
    }

    let mut config = AgentRuntimeConfig::new(parsed.edge, parsed.local);
    config.connect_timeout = parsed.connect_timeout;
    config.handshake_timeout = parsed.handshake_timeout;
    config.multiplex.max_concurrent_streams = parsed.max_streams;
    config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
    config.reconnect.initial_delay = parsed.reconnect_initial;
    config.reconnect.max_delay = parsed.reconnect_max;
    config.reconnect.multiplier = parsed.reconnect_multiplier;
    config.reconnect.jitter_percent = parsed.reconnect_jitter_percent;
    config.reconnect.stable_session_reset_after = parsed.stable_session_reset;
    config.reconnect.max_attempts = parsed.max_reconnect_attempts;
    config.registration =
        RegistrationRequest::new(parsed.agent_id.clone(), parsed.tunnel_id.clone());
    let loaded_tls = match load_transport_security(&parsed).await {
        Ok(security) => security,
        Err(error) => {
            error!(%error, "failed to configure Agent TLS");
            return ExitCode::from(2);
        }
    };
    let enrollment_runtime = match (&enrollment_config, &loaded_tls.security) {
        (Some(enrollment), AgentTransportSecurity::MutualTls(tls)) => {
            match AgentEnrollmentRuntime::new(enrollment.clone(), tls.clone()) {
                Ok(runtime) => Some(runtime),
                Err(error) => {
                    error!(%error, "failed to configure Agent renewal runtime");
                    return ExitCode::from(2);
                }
            }
        }
        (Some(_), AgentTransportSecurity::PlaintextLoopback) => {
            error!("automatic renewal requires Agent mutual TLS");
            return ExitCode::from(2);
        }
        (None, _) => None,
    };
    config.security = loaded_tls.security;
    let runtime = match AgentRuntime::new(config) {
        Ok(runtime) => runtime,
        Err(error) => {
            error!(%error, "failed to configure Agent runtime");
            return ExitCode::from(2);
        }
    };
    let runtime_status = runtime.status_handle();
    let runtime_control = runtime.control();
    let operations_tunnel = (mode == RunMode::Http).then(|| {
        AgentOperationsTunnel::new(
            parsed.tunnel_id.clone(),
            parsed.local,
            runtime_status.clone(),
        )
    });
    let operations = match parsed.ops_listen {
        Some(listen_addr) => {
            let mut config = AgentOperationsConfig::loopback(listen_addr);
            config.max_concurrent_connections = parsed.max_ops_connections;
            config.header_read_timeout = parsed.ops_header_timeout;
            config.request_timeout = parsed.ops_request_timeout;
            config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
            let result = match &operations_tunnel {
                Some(tunnel) => {
                    AgentOperationsRuntime::bind_tunnels(config, vec![tunnel.clone()]).await
                }
                None => AgentOperationsRuntime::bind(config, runtime_status.clone()).await,
            };
            match result {
                Ok(runtime) => {
                    info!(listen_addr = %runtime.local_addr(), "Agent operations endpoint started");
                    Some(runtime)
                }
                Err(error) => {
                    error!(%error, "failed to start Agent operations endpoint");
                    return ExitCode::from(2);
                }
            }
        }
        None => None,
    };
    let public_reachability = match load_public_reachability_template(&parsed).await {
        Ok(template) => template,
        Err(error) => {
            error!(%error, "failed to configure public reachability verification");
            return ExitCode::from(2);
        }
    };
    if let Some(template) = &public_reachability {
        runtime_status.require_public_reachability(template.monitor.is_some());
    }
    let managed_http = match mode {
        RunMode::Tunnel => None,
        RunMode::Http => {
            info!(
                agent_id = %parsed.agent_id,
                tunnel_id = %parsed.tunnel_id,
                event = "managed_http_allocation_started",
                "Managed HTTP hostname allocation started"
            );
            let client = match load_http_hostname_client(&parsed).await {
                Ok(client) => client,
                Err(error) => {
                    let configuration_error = error.is_configuration_error();
                    error!(%error, "failed to configure managed HTTP hostname client");
                    if configuration_error {
                        print_usage_for_error(log_format, binary_name);
                        return ExitCode::from(2);
                    }
                    return ExitCode::from(1);
                }
            };
            let allocation = match client
                .allocate(parsed.agent_id.clone(), parsed.tunnel_id.clone())
                .await
            {
                Ok(allocation) => allocation,
                Err(error) => {
                    error!(%error, "managed HTTP hostname allocation failed");
                    return ExitCode::from(1);
                }
            };
            info!(
                hostname = %allocation.hostname,
                catalog_version = allocation.catalog_version,
                changed = allocation.changed,
                event = "managed_http_hostname_published",
                "Managed HTTP hostname is durable and published"
            );
            operations_tunnel
                .as_ref()
                .expect("managed HTTP operations metadata exists")
                .publish_hostname(allocation.hostname.clone());
            Some(ManagedHttpAnnouncement {
                probe: public_reachability
                    .as_ref()
                    .map(|template| template.build(allocation.hostname.clone()))
                    .transpose()
                    .expect("public reachability template was prevalidated"),
                monitor: public_reachability
                    .as_ref()
                    .and_then(|template| template.monitor),
                hostname: allocation.hostname,
                local: parsed.local,
            })
        }
    };
    info!(
        edge = %parsed.edge,
        local = %parsed.local,
        agent_id = %parsed.agent_id,
        tunnel_id = %parsed.tunnel_id,
        "Agent runtime starting"
    );

    let (trigger, signal) = shutdown_channel();
    let (operations_trigger, operations_signal) = shutdown_channel();
    let readiness_future =
        run_optional_managed_http_readiness(managed_http, runtime_status, signal.clone());
    tokio::pin!(readiness_future);
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = run_optional_tls_reloader(loaded_tls.reloader, signal.clone());
    tokio::pin!(reload_future);
    let enrollment_future = run_optional_enrollment(enrollment_runtime, signal.clone());
    tokio::pin!(enrollment_future);
    let operations_future = run_optional_operations(operations, operations_signal);
    tokio::pin!(operations_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let operations = operations_future.await;
            combine_exit_codes(agent_exit_code(result), operations)
        },
        reload = &mut reload_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = runtime_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let operations = operations_future.await;
            let code = match reload {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(%error, "Agent TLS reload runtime failed");
                    ExitCode::from(1)
                }
            };
            combine_exit_codes(code, operations)
        },
        enrollment = &mut enrollment_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = runtime_future.await;
            let _ = reload_future.await;
            operations_trigger.shutdown();
            let operations = operations_future.await;
            let code = match enrollment {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(%error, "Agent enrollment runtime failed");
                    ExitCode::from(1)
                }
            };
            combine_exit_codes(code, operations)
        },
        operations = &mut operations_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            combine_exit_codes(ExitCode::from(1), operations)
        },
        observed = &mut os_signal => {
            match observed {
                Ok(cause) => info!(%cause, "process shutdown requested"),
                Err(error) => {
                    error!(%error, "OS shutdown listener failed");
                    runtime_control.begin_draining();
                    trigger.shutdown();
                    let _ = readiness_future.await;
                    let _ = runtime_future.await;
                    let _ = reload_future.await;
                    let _ = enrollment_future.await;
                    operations_trigger.shutdown();
                    let operations = operations_future.await;
                    return combine_exit_codes(ExitCode::from(1), operations);
                }
            }
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let result = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let operations = operations_future.await;
            combine_exit_codes(agent_exit_code(result), operations)
        },
        readiness = &mut readiness_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let operations = operations_future.await;
            let code = match readiness {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(%error, event = "managed_http_public_reachability_failed", "Managed HTTP public reachability verification failed");
                    ExitCode::from(1)
                }
            };
            combine_exit_codes(code, operations)
        }
    }
}

async fn run_multi_tunnel(
    binary_name: &'static str,
    log_format: ProcessLogFormat,
    args: &[String],
) -> ExitCode {
    let mut parsed = match parse_start_command(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            error!(%error, "invalid multi-tunnel Agent CLI arguments");
            print_usage_for_error(log_format, binary_name);
            return ExitCode::from(2);
        }
    };
    if parsed.help {
        println!("{}", usage(binary_name));
        return ExitCode::SUCCESS;
    }
    let tunnels = match apply_required_multi_config(&mut parsed).await {
        Ok(tunnels) => tunnels,
        Err(error) => {
            error!(%error, "failed to load multi-tunnel Agent config");
            print_usage_for_error(log_format, binary_name);
            return ExitCode::from(2);
        }
    };
    if let Err(error) = validate_http_configuration(&parsed) {
        error!(%error, "invalid multi-tunnel managed HTTP configuration");
        print_usage_for_error(log_format, binary_name);
        return ExitCode::from(2);
    }

    let enrollment_config = match load_enrollment_config(&parsed).await {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "failed to configure Agent enrollment");
            return ExitCode::from(2);
        }
    };
    let loaded_tls = match load_transport_security(&parsed).await {
        Ok(security) => security,
        Err(error) => {
            error!(%error, "failed to configure Agent TLS");
            return ExitCode::from(2);
        }
    };
    let enrollment_runtime = match (&enrollment_config, &loaded_tls.security) {
        (Some(enrollment), AgentTransportSecurity::MutualTls(tls)) => {
            match AgentEnrollmentRuntime::new(enrollment.clone(), tls.clone()) {
                Ok(runtime) => Some(runtime),
                Err(error) => {
                    error!(%error, "failed to configure Agent renewal runtime");
                    return ExitCode::from(2);
                }
            }
        }
        (Some(_), AgentTransportSecurity::PlaintextLoopback) => {
            error!("automatic renewal requires Agent mutual TLS");
            return ExitCode::from(2);
        }
        (None, _) => None,
    };
    let public_reachability = match load_public_reachability_template(&parsed).await {
        Ok(template) => template,
        Err(error) => {
            error!(%error, "failed to configure public reachability verification");
            return ExitCode::from(2);
        }
    };
    let hostname_client = match load_http_hostname_client(&parsed).await {
        Ok(client) => client,
        Err(error) => {
            let configuration_error = error.is_configuration_error();
            error!(%error, "failed to configure managed HTTP hostname client");
            if configuration_error {
                print_usage_for_error(log_format, binary_name);
                return ExitCode::from(2);
            }
            return ExitCode::from(1);
        }
    };

    let configs = tunnels
        .iter()
        .map(|tunnel| build_runtime_config(&parsed, tunnel, loaded_tls.security.clone()))
        .collect();
    let runtime = match MultiAgentRuntime::new(configs) {
        Ok(runtime) => runtime,
        Err(error) => {
            error!(%error, "failed to configure multi-tunnel Agent runtime");
            return ExitCode::from(2);
        }
    };
    let runtime_statuses = runtime.status_handles();
    let runtime_control = runtime.control();
    let operations_tunnels = tunnels
        .iter()
        .zip(&runtime_statuses)
        .map(|(tunnel, status)| {
            AgentOperationsTunnel::new(tunnel.tunnel_id.clone(), tunnel.local, status.clone())
        })
        .collect::<Vec<_>>();
    if let Some(template) = &public_reachability {
        for status in &runtime_statuses {
            status.require_public_reachability(template.monitor.is_some());
        }
    }
    let operations = match parsed.ops_listen {
        Some(listen_addr) => {
            let mut config = AgentOperationsConfig::loopback(listen_addr);
            config.max_concurrent_connections = parsed.max_ops_connections;
            config.header_read_timeout = parsed.ops_header_timeout;
            config.request_timeout = parsed.ops_request_timeout;
            config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
            match AgentOperationsRuntime::bind_tunnels(config, operations_tunnels.clone()).await {
                Ok(runtime) => {
                    info!(listen_addr = %runtime.local_addr(), "Agent operations endpoint started");
                    Some(runtime)
                }
                Err(error) => {
                    error!(%error, "failed to start Agent operations endpoint");
                    return ExitCode::from(2);
                }
            }
        }
        None => None,
    };

    let mut announcements = Vec::with_capacity(tunnels.len());
    for (tunnel, operations_tunnel) in tunnels.iter().zip(&operations_tunnels) {
        info!(
            agent_id = %parsed.agent_id,
            tunnel_id = %tunnel.tunnel_id,
            event = "managed_http_allocation_started",
            "Managed HTTP hostname allocation started"
        );
        let allocation = match hostname_client
            .allocate(parsed.agent_id.clone(), tunnel.tunnel_id.clone())
            .await
        {
            Ok(allocation) => allocation,
            Err(error) => {
                error!(
                    tunnel_id = %tunnel.tunnel_id,
                    %error,
                    "managed HTTP hostname allocation failed"
                );
                return ExitCode::from(1);
            }
        };
        info!(
            hostname = %allocation.hostname,
            catalog_version = allocation.catalog_version,
            changed = allocation.changed,
            event = "managed_http_hostname_published",
            "Managed HTTP hostname is durable and published"
        );
        operations_tunnel.publish_hostname(allocation.hostname.clone());
        announcements.push(ManagedHttpAnnouncement {
            probe: public_reachability
                .as_ref()
                .map(|template| template.build(allocation.hostname.clone()))
                .transpose()
                .expect("public reachability template was prevalidated"),
            monitor: public_reachability
                .as_ref()
                .and_then(|template| template.monitor),
            hostname: allocation.hostname,
            local: tunnel.local,
        });
    }

    for tunnel in &tunnels {
        info!(
            edge = %parsed.edge,
            local = %tunnel.local,
            agent_id = %parsed.agent_id,
            tunnel_id = %tunnel.tunnel_id,
            "Agent tunnel runtime starting"
        );
    }

    let readiness = announcements
        .into_iter()
        .zip(runtime_statuses)
        .collect::<Vec<_>>();
    let (trigger, signal) = shutdown_channel();
    let (operations_trigger, operations_signal) = shutdown_channel();
    let readiness_future = run_multi_managed_http_readiness(readiness, signal.clone());
    tokio::pin!(readiness_future);
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = run_optional_tls_reloader(loaded_tls.reloader, signal.clone());
    tokio::pin!(reload_future);
    let enrollment_future = run_optional_enrollment(enrollment_runtime, signal.clone());
    tokio::pin!(enrollment_future);
    let operations_future = run_optional_operations(operations, operations_signal);
    tokio::pin!(operations_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            combine_exit_codes(multi_agent_exit_code(result), operations_future.await)
        },
        reload = &mut reload_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = runtime_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let code = match reload {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(%error, "Agent TLS reload runtime failed");
                    ExitCode::from(1)
                }
            };
            combine_exit_codes(code, operations_future.await)
        },
        enrollment = &mut enrollment_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = runtime_future.await;
            let _ = reload_future.await;
            operations_trigger.shutdown();
            let code = match enrollment {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(%error, "Agent enrollment runtime failed");
                    ExitCode::from(1)
                }
            };
            combine_exit_codes(code, operations_future.await)
        },
        operations = &mut operations_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let _ = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            combine_exit_codes(ExitCode::from(1), operations)
        },
        observed = &mut os_signal => {
            match observed {
                Ok(cause) => info!(%cause, "process shutdown requested"),
                Err(error) => {
                    error!(%error, "OS shutdown listener failed");
                    runtime_control.begin_draining();
                    trigger.shutdown();
                    let _ = readiness_future.await;
                    let _ = runtime_future.await;
                    let _ = reload_future.await;
                    let _ = enrollment_future.await;
                    operations_trigger.shutdown();
                    return combine_exit_codes(ExitCode::from(1), operations_future.await);
                }
            }
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = readiness_future.await;
            let result = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            combine_exit_codes(multi_agent_exit_code(result), operations_future.await)
        },
        readiness = &mut readiness_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            let _ = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let code = match readiness {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    error!(
                        %error,
                        event = "managed_http_public_reachability_failed",
                        "Multi-tunnel public reachability verification failed"
                    );
                    ExitCode::from(1)
                }
            };
            combine_exit_codes(code, operations_future.await)
        }
    }
}

fn build_runtime_config(
    parsed: &ParsedArgs,
    tunnel: &ManagedTunnelSpec,
    security: AgentTransportSecurity,
) -> AgentRuntimeConfig {
    let mut config = AgentRuntimeConfig::new(parsed.edge, tunnel.local);
    config.connect_timeout = parsed.connect_timeout;
    config.handshake_timeout = parsed.handshake_timeout;
    config.multiplex.max_concurrent_streams = parsed.max_streams;
    config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
    config.reconnect.initial_delay = parsed.reconnect_initial;
    config.reconnect.max_delay = parsed.reconnect_max;
    config.reconnect.multiplier = parsed.reconnect_multiplier;
    config.reconnect.jitter_percent = parsed.reconnect_jitter_percent;
    config.reconnect.stable_session_reset_after = parsed.stable_session_reset;
    config.reconnect.max_attempts = parsed.max_reconnect_attempts;
    config.registration =
        RegistrationRequest::new(parsed.agent_id.clone(), tunnel.tunnel_id.clone());
    config.security = security;
    config
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Tunnel,
    Http,
}

#[derive(Debug, Clone)]
struct PublicReachabilityTemplate {
    ca_pem: Option<Vec<u8>>,
    total_timeout: Duration,
    monitor: Option<PublicReachabilityMonitorConfig>,
}

impl PublicReachabilityTemplate {
    fn build(
        &self,
        hostname: PublicHostname,
    ) -> Result<PublicReachabilityProbe, PublicReachabilityError> {
        PublicReachabilityProbe::new(PublicReachabilityConfig {
            hostname,
            ca_pem: self.ca_pem.clone(),
            total_timeout: self.total_timeout,
            attempt_timeout: DEFAULT_PUBLIC_REACHABILITY_ATTEMPT_TIMEOUT.min(self.total_timeout),
            retry_interval: DEFAULT_PUBLIC_REACHABILITY_RETRY_INTERVAL.min(self.total_timeout),
            server_addr_override: None,
        })
    }
}

#[derive(Debug)]
enum PublicReachabilityLoadError {
    ReadCa,
    Invalid(PublicReachabilityError),
}

impl std::fmt::Display for PublicReachabilityLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadCa => formatter.write_str("public reachability CA bundle could not be read"),
            Self::Invalid(error) => write!(formatter, "invalid public reachability probe: {error}"),
        }
    }
}

async fn load_public_reachability_template(
    parsed: &ParsedArgs,
) -> Result<Option<PublicReachabilityTemplate>, PublicReachabilityLoadError> {
    if !parsed.verify_public_reachability {
        return Ok(None);
    }
    let ca_pem = match &parsed.public_reachability_ca {
        Some(path) => {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|_| PublicReachabilityLoadError::ReadCa)?;
            let mut bytes = Vec::new();
            file.take(MAX_PUBLIC_REACHABILITY_CA_BYTES + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| PublicReachabilityLoadError::ReadCa)?;
            if bytes.is_empty() || bytes.len() as u64 > MAX_PUBLIC_REACHABILITY_CA_BYTES {
                return Err(PublicReachabilityLoadError::ReadCa);
            }
            Some(bytes)
        }
        None => None,
    };
    let template = PublicReachabilityTemplate {
        ca_pem,
        total_timeout: parsed.public_reachability_timeout,
        monitor: parsed.public_reachability_monitor_interval.map(|interval| {
            PublicReachabilityMonitorConfig {
                interval,
                failure_threshold: parsed.public_reachability_failure_threshold,
            }
        }),
    };
    if let Some(monitor) = template.monitor {
        monitor
            .validate()
            .map_err(PublicReachabilityLoadError::Invalid)?;
    }
    template
        .build(PublicHostname::new("reachability.invalid").expect("static hostname is valid"))
        .map_err(PublicReachabilityLoadError::Invalid)?;
    Ok(Some(template))
}

#[derive(Debug)]
struct ManagedHttpAnnouncement {
    hostname: PublicHostname,
    local: SocketAddr,
    probe: Option<PublicReachabilityProbe>,
    monitor: Option<PublicReachabilityMonitorConfig>,
}

impl ManagedHttpAnnouncement {
    fn mapping(&self) -> String {
        format!("https://{} -> http://{}", self.hostname, self.local)
    }
}

async fn announce_managed_http_ready(
    announcement: ManagedHttpAnnouncement,
    status: crate::AgentRuntimeStatusHandle,
    signal: ShutdownSignal,
) -> Result<(), PublicReachabilityError> {
    let mut poll = tokio::time::interval(Duration::from_millis(10));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = signal.cancelled() => {
                return Err(PublicReachabilityError::Cancelled { attempts: 0 });
            },
            _ = poll.tick() => {
                if status.snapshot().is_transport_ready() {
                    if let Some(probe) = &announcement.probe {
                        info!(event = "managed_http_public_reachability_started", "Managed HTTP public reachability verification started");
                        match probe.verify_until_success(signal.clone()).await {
                            Ok(outcome) => {
                                status.record_public_reachability_success(outcome.attempts);
                                info!(
                                    attempts = outcome.attempts,
                                    event = "managed_http_public_reachability_succeeded",
                                    "Managed HTTP public reachability verified"
                                );
                            }
                            Err(error @ PublicReachabilityError::Timeout { attempts, last_failure }) => {
                                status.record_public_reachability_failure(
                                    attempts,
                                    Some(last_failure),
                                    false,
                                );
                                return Err(error);
                            }
                            Err(error @ PublicReachabilityError::Cancelled { attempts }) => {
                                status.record_public_reachability_failure(attempts, None, true);
                                return Err(error);
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    println!("{}", announcement.mapping());
                    info!(
                        hostname = %announcement.hostname,
                        local = %announcement.local,
                        event = "managed_http_ready",
                        "Managed HTTP tunnel is ready"
                    );
                    if let (Some(probe), Some(monitor)) =
                        (announcement.probe, announcement.monitor)
                    {
                        return run_public_reachability_monitor(
                            probe,
                            monitor,
                            status,
                            signal,
                        )
                        .await;
                    }
                    signal.cancelled().await;
                    return Ok(());
                }
            }
        }
    }
}

async fn run_public_reachability_monitor(
    probe: PublicReachabilityProbe,
    config: PublicReachabilityMonitorConfig,
    status: crate::AgentRuntimeStatusHandle,
    signal: ShutdownSignal,
) -> Result<(), PublicReachabilityError> {
    loop {
        tokio::select! {
            biased;
            () = signal.cancelled() => return Ok(()),
            () = tokio::time::sleep(config.interval) => {}
        }
        let previous = status.snapshot().public_reachability_state;
        match probe.verify_once(signal.clone()).await {
            Ok(()) => {
                status.record_public_reachability_monitor_success();
                if previous != PublicReachabilityState::Healthy {
                    info!(
                        previous_state = previous.as_str(),
                        event = "managed_http_public_reachability_recovered",
                        "Managed HTTP public reachability recovered"
                    );
                }
            }
            Err(PublicReachabilityError::AttemptFailed(failure)) => {
                let state = status
                    .record_public_reachability_monitor_failure(failure, config.failure_threshold);
                if state != previous {
                    warn!(
                        previous_state = previous.as_str(),
                        state = state.as_str(),
                        failure = failure.as_str(),
                        consecutive_failures =
                            status.snapshot().public_reachability_consecutive_failures,
                        event = "managed_http_public_reachability_state_changed",
                        "Managed HTTP public reachability state changed"
                    );
                }
            }
            Err(PublicReachabilityError::Cancelled { .. }) => {
                status.record_public_reachability_monitor_cancellation();
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
}

async fn run_optional_managed_http_readiness(
    announcement: Option<ManagedHttpAnnouncement>,
    status: crate::AgentRuntimeStatusHandle,
    signal: ShutdownSignal,
) -> Result<(), PublicReachabilityError> {
    match announcement {
        Some(announcement) => announce_managed_http_ready(announcement, status, signal).await,
        None => {
            signal.cancelled().await;
            Ok(())
        }
    }
}

async fn run_multi_managed_http_readiness(
    announcements: Vec<(ManagedHttpAnnouncement, crate::AgentRuntimeStatusHandle)>,
    signal: ShutdownSignal,
) -> Result<(), PublicReachabilityError> {
    let mut tasks = tokio::task::JoinSet::new();
    for (announcement, status) in announcements {
        let child_signal = signal.clone();
        tasks.spawn(async move {
            announce_managed_http_ready(announcement, status, child_signal).await
        });
    }
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) if signal.is_shutdown() => {}
            Ok(Ok(())) => return Ok(()),
            Ok(Err(_)) if signal.is_shutdown() => {}
            Ok(Err(error)) => return Err(error),
            Err(_) if signal.is_shutdown() => {}
            Err(_) => return Err(PublicReachabilityError::Cancelled { attempts: 0 }),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostnameAction {
    Allocate,
    Release,
}

#[derive(Debug, PartialEq, Eq)]
struct HostnameCommandArgs {
    action: HostnameAction,
    server_addr: SocketAddr,
    server_ca: PathBuf,
    server_name: String,
    client_cert: PathBuf,
    client_key: PathBuf,
    agent_id: AgentId,
    tunnel_id: TunnelId,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    request_timeout: Duration,
}

async fn run_hostname_command(args: &[String]) -> Result<(), HostnameCommandError> {
    let args = parse_hostname_command(args).map_err(HostnameCommandError::Arguments)?;
    let (server_ca_pem, client_cert_pem, client_key_pem) = tokio::try_join!(
        tokio::fs::read(&args.server_ca),
        tokio::fs::read(&args.client_cert),
        tokio::fs::read(&args.client_key),
    )
    .map_err(|_| HostnameCommandError::ReadTls)?;
    let client = AgentHostnameClient::new(HostnameClientConfig {
        server_addr: args.server_addr,
        server_name: args.server_name,
        server_ca_pem,
        client_cert_pem,
        client_key_pem,
        connect_timeout: args.connect_timeout,
        handshake_timeout: args.handshake_timeout,
        request_timeout: args.request_timeout,
    })
    .map_err(HostnameCommandError::Client)?;
    match args.action {
        HostnameAction::Allocate => {
            let outcome = client
                .allocate(args.agent_id, args.tunnel_id)
                .await
                .map_err(HostnameCommandError::Client)?;
            println!(
                "hostname={} catalog_version={} changed={}",
                outcome.hostname, outcome.catalog_version, outcome.changed
            );
        }
        HostnameAction::Release => {
            let outcome = client
                .release(args.agent_id, args.tunnel_id)
                .await
                .map_err(HostnameCommandError::Client)?;
            println!(
                "hostname={} catalog_version={} changed={}",
                outcome
                    .hostname
                    .map_or_else(|| "-".to_owned(), |hostname| hostname.to_string()),
                outcome.catalog_version,
                outcome.changed
            );
        }
    }
    Ok(())
}

async fn load_http_hostname_client(
    parsed: &ParsedArgs,
) -> Result<AgentHostnameClient, HostnameCommandError> {
    let (server_ca, client_cert, client_key) = tokio::try_join!(
        tokio::fs::read(
            parsed
                .hostname_ca
                .as_ref()
                .expect("validated managed HTTP hostname CA"),
        ),
        tokio::fs::read(
            parsed
                .tls_client_cert
                .as_ref()
                .expect("validated managed HTTP client certificate"),
        ),
        tokio::fs::read(
            parsed
                .tls_client_key
                .as_ref()
                .expect("validated managed HTTP client private key"),
        ),
    )
    .map_err(|_| HostnameCommandError::ReadTls)?;
    AgentHostnameClient::new(HostnameClientConfig {
        server_addr: parsed
            .hostname_server
            .expect("validated managed HTTP hostname server"),
        server_name: parsed
            .hostname_server_name
            .clone()
            .expect("validated managed HTTP hostname server name"),
        server_ca_pem: server_ca,
        client_cert_pem: client_cert,
        client_key_pem: client_key,
        connect_timeout: parsed.connect_timeout,
        handshake_timeout: parsed.tls_handshake_timeout,
        request_timeout: parsed.hostname_request_timeout,
    })
    .map_err(HostnameCommandError::Client)
}

fn parse_hostname_command(args: &[String]) -> Result<HostnameCommandArgs, ArgError> {
    let action = match args.first().map(String::as_str) {
        Some("hostname-allocate") => HostnameAction::Allocate,
        Some("hostname-release") => HostnameAction::Release,
        Some(command) => return Err(ArgError::UnknownFlag(command.to_owned())),
        None => return Err(ArgError::MissingRequired("hostname command")),
    };
    let mut server_addr = None;
    let mut server_ca = None;
    let mut server_name = None;
    let mut client_cert = None;
    let mut client_key = None;
    let mut agent_id = None;
    let mut tunnel_id = None;
    let mut connect_timeout = Duration::from_secs(5);
    let mut handshake_timeout = Duration::from_secs(10);
    let mut request_timeout = Duration::from_secs(5);
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--hostname-server" => server_addr = Some(parse_addr(args, index, flag)?),
            "--hostname-ca" => server_ca = Some(PathBuf::from(value(args, index, flag)?)),
            "--hostname-server-name" => server_name = Some(value(args, index, flag)?.to_owned()),
            "--tls-client-cert" => client_cert = Some(PathBuf::from(value(args, index, flag)?)),
            "--tls-client-key" => client_key = Some(PathBuf::from(value(args, index, flag)?)),
            "--agent-id" => agent_id = Some(parse_agent_id(args, index, flag)?),
            "--tunnel-id" => tunnel_id = Some(parse_tunnel_id(args, index, flag)?),
            "--connect-timeout-ms" => {
                connect_timeout = Duration::from_millis(parse_number(args, index, flag)?)
            }
            "--tls-handshake-timeout-ms" => {
                handshake_timeout = Duration::from_millis(parse_number(args, index, flag)?)
            }
            "--request-timeout-ms" => {
                request_timeout = Duration::from_millis(parse_number(args, index, flag)?)
            }
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    Ok(HostnameCommandArgs {
        action,
        server_addr: server_addr.ok_or(ArgError::MissingRequired("--hostname-server"))?,
        server_ca: server_ca.ok_or(ArgError::MissingRequired("--hostname-ca"))?,
        server_name: server_name.ok_or(ArgError::MissingRequired("--hostname-server-name"))?,
        client_cert: client_cert.ok_or(ArgError::MissingRequired("--tls-client-cert"))?,
        client_key: client_key.ok_or(ArgError::MissingRequired("--tls-client-key"))?,
        agent_id: agent_id.ok_or(ArgError::MissingRequired("--agent-id"))?,
        tunnel_id: tunnel_id.ok_or(ArgError::MissingRequired("--tunnel-id"))?,
        connect_timeout,
        handshake_timeout,
        request_timeout,
    })
}

#[derive(Debug)]
enum HostnameCommandError {
    Arguments(ArgError),
    ReadTls,
    Client(AgentHostnameError),
}

impl HostnameCommandError {
    fn is_configuration_error(&self) -> bool {
        matches!(
            self,
            Self::Arguments(_)
                | Self::ReadTls
                | Self::Client(
                    AgentHostnameError::InvalidConfig | AgentHostnameError::TlsConfig(_)
                )
        )
    }
}

impl std::fmt::Display for HostnameCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arguments(error) => error.fmt(formatter),
            Self::ReadTls => formatter.write_str("failed to read hostname TLS PEM files"),
            Self::Client(error) => error.fmt(formatter),
        }
    }
}

fn usage(binary_name: &str) -> String {
    USAGE_TEMPLATE.replace("tunnelproxy-agent", binary_name)
}

fn print_usage_for_error(log_format: ProcessLogFormat, binary_name: &str) {
    if log_format == ProcessLogFormat::Text {
        eprintln!("{}", usage(binary_name));
    }
}

async fn run_optional_enrollment(
    runtime: Option<AgentEnrollmentRuntime>,
    signal: tunnelproxy_common::ShutdownSignal,
) -> Result<(), AgentEnrollmentError> {
    match runtime {
        Some(runtime) => runtime.run_until_shutdown(signal).await,
        None => {
            signal.cancelled().await;
            Ok(())
        }
    }
}

async fn run_optional_operations(
    runtime: Option<AgentOperationsRuntime>,
    signal: tunnelproxy_common::ShutdownSignal,
) -> Result<Option<AgentOperationsOutcome>, AgentOperationsError> {
    match runtime {
        Some(runtime) => runtime.run_until_shutdown(signal).await.map(Some),
        None => {
            signal.cancelled().await;
            Ok(None)
        }
    }
}

fn combine_exit_codes(
    base: ExitCode,
    operations: Result<Option<AgentOperationsOutcome>, AgentOperationsError>,
) -> ExitCode {
    match operations {
        Ok(Some(outcome)) if outcome.was_forced() => {
            error!(
                ?outcome,
                "Agent operations shutdown exceeded its drain deadline"
            );
            ExitCode::from(1)
        }
        Ok(Some(outcome)) => {
            info!(?outcome, "Agent operations shutdown completed");
            base
        }
        Ok(None) => base,
        Err(error) => {
            error!(%error, "Agent operations runtime failed");
            ExitCode::from(1)
        }
    }
}

async fn run_optional_tls_reloader(
    reloader: Option<AgentTlsReloadRuntime>,
    signal: tunnelproxy_common::ShutdownSignal,
) -> Result<(), tunnelproxy_common::TlsReloadRuntimeError> {
    match reloader {
        Some(reloader) => reloader.run_until_shutdown(signal).await,
        None => {
            signal.cancelled().await;
            Ok(())
        }
    }
}

fn agent_exit_code(result: Result<AgentRuntimeOutcome, crate::AgentRuntimeError>) -> ExitCode {
    match result {
        Ok(outcome) if outcome.is_graceful_shutdown() => {
            info!(?outcome, "Agent shutdown completed");
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
            error!(?outcome, "Agent stopped without a local shutdown request");
            ExitCode::from(1)
        }
        Err(error) => {
            error!(%error, "Agent runtime failed");
            ExitCode::from(1)
        }
    }
}

fn multi_agent_exit_code(
    result: Result<MultiAgentRuntimeOutcome, MultiAgentRuntimeError>,
) -> ExitCode {
    match result {
        Ok(outcome) if outcome.is_graceful_shutdown() => {
            info!(
                tunnels = outcome.tunnels.len(),
                "Multi-tunnel Agent shutdown completed"
            );
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
            error!(
                tunnels = outcome.tunnels.len(),
                "Multi-tunnel Agent stopped unexpectedly"
            );
            ExitCode::from(1)
        }
        Err(error) => {
            error!(%error, "Multi-tunnel Agent runtime failed");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedArgs {
    config_path: Option<PathBuf>,
    edge: SocketAddr,
    edge_explicit: bool,
    local: SocketAddr,
    local_explicit: bool,
    agent_id: AgentId,
    agent_id_explicit: bool,
    tunnel_id: TunnelId,
    tunnel_id_explicit: bool,
    max_streams: usize,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    drain_timeout: Duration,
    reconnect_initial: Duration,
    reconnect_max: Duration,
    reconnect_multiplier: u32,
    reconnect_jitter_percent: u8,
    stable_session_reset: Duration,
    max_reconnect_attempts: Option<u32>,
    ops_listen: Option<SocketAddr>,
    max_ops_connections: usize,
    ops_header_timeout: Duration,
    ops_request_timeout: Duration,
    tls_ca: Option<PathBuf>,
    tls_ca_explicit: bool,
    tls_client_cert: Option<PathBuf>,
    tls_client_cert_explicit: bool,
    tls_client_key: Option<PathBuf>,
    tls_client_key_explicit: bool,
    tls_server_name: Option<String>,
    tls_server_name_explicit: bool,
    tls_handshake_timeout: Duration,
    tls_reload_manifest: Option<PathBuf>,
    tls_reload_interval: Duration,
    tls_expiry_warning: Duration,
    tls_reload_options_present: bool,
    hostname_server: Option<SocketAddr>,
    hostname_server_explicit: bool,
    hostname_ca: Option<PathBuf>,
    hostname_ca_explicit: bool,
    hostname_server_name: Option<String>,
    hostname_server_name_explicit: bool,
    hostname_request_timeout: Duration,
    hostname_options_present: bool,
    verify_public_reachability: bool,
    verify_public_reachability_explicit: bool,
    public_reachability_ca: Option<PathBuf>,
    public_reachability_ca_explicit: bool,
    public_reachability_timeout: Duration,
    public_reachability_timeout_explicit: bool,
    public_reachability_monitor_interval: Option<Duration>,
    public_reachability_monitor_interval_explicit: bool,
    public_reachability_failure_threshold: u64,
    public_reachability_failure_threshold_explicit: bool,
    public_reachability_failure_threshold_present: bool,
    public_reachability_options_present: bool,
    enroll_only: bool,
    enrollment_server: Option<SocketAddr>,
    enrollment_ca: Option<PathBuf>,
    enrollment_server_name: Option<String>,
    enrollment_token: Option<PathBuf>,
    enrollment_pending: Option<PathBuf>,
    renew_before: Duration,
    enrollment_poll: Duration,
    enrollment_connect_timeout: Duration,
    enrollment_handshake_timeout: Duration,
    enrollment_request_timeout: Duration,
    enrollment_activation_timeout: Duration,
    enrollment_options_present: bool,
    help: bool,
}

impl Default for ParsedArgs {
    fn default() -> Self {
        Self {
            config_path: None,
            edge: "127.0.0.1:7100".parse().unwrap(),
            edge_explicit: false,
            local: "127.0.0.1:3000".parse().unwrap(),
            local_explicit: false,
            agent_id: AgentId::new("agent-dev").unwrap(),
            agent_id_explicit: false,
            tunnel_id: TunnelId::new("tunnel-dev").unwrap(),
            tunnel_id_explicit: false,
            max_streams: 32,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
            reconnect_initial: Duration::from_millis(250),
            reconnect_max: Duration::from_secs(30),
            reconnect_multiplier: 2,
            reconnect_jitter_percent: 20,
            stable_session_reset: Duration::from_secs(30),
            max_reconnect_attempts: None,
            ops_listen: None,
            max_ops_connections: 8,
            ops_header_timeout: Duration::from_secs(2),
            ops_request_timeout: Duration::from_secs(5),
            tls_ca: None,
            tls_ca_explicit: false,
            tls_client_cert: None,
            tls_client_cert_explicit: false,
            tls_client_key: None,
            tls_client_key_explicit: false,
            tls_server_name: None,
            tls_server_name_explicit: false,
            tls_handshake_timeout: Duration::from_secs(10),
            tls_reload_manifest: None,
            tls_reload_interval: Duration::from_secs(1),
            tls_expiry_warning: Duration::from_secs(7 * 24 * 60 * 60),
            tls_reload_options_present: false,
            hostname_server: None,
            hostname_server_explicit: false,
            hostname_ca: None,
            hostname_ca_explicit: false,
            hostname_server_name: None,
            hostname_server_name_explicit: false,
            hostname_request_timeout: Duration::from_secs(5),
            hostname_options_present: false,
            verify_public_reachability: false,
            verify_public_reachability_explicit: false,
            public_reachability_ca: None,
            public_reachability_ca_explicit: false,
            public_reachability_timeout: DEFAULT_PUBLIC_REACHABILITY_TIMEOUT,
            public_reachability_timeout_explicit: false,
            public_reachability_monitor_interval: None,
            public_reachability_monitor_interval_explicit: false,
            public_reachability_failure_threshold: DEFAULT_PUBLIC_REACHABILITY_FAILURE_THRESHOLD,
            public_reachability_failure_threshold_explicit: false,
            public_reachability_failure_threshold_present: false,
            public_reachability_options_present: false,
            enroll_only: false,
            enrollment_server: None,
            enrollment_ca: None,
            enrollment_server_name: None,
            enrollment_token: None,
            enrollment_pending: None,
            renew_before: Duration::from_secs(7 * 24 * 60 * 60),
            enrollment_poll: Duration::from_secs(60),
            enrollment_connect_timeout: Duration::from_secs(5),
            enrollment_handshake_timeout: Duration::from_secs(10),
            enrollment_request_timeout: Duration::from_secs(30),
            enrollment_activation_timeout: Duration::from_secs(30),
            enrollment_options_present: false,
            help: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ArgError {
    MissingRequired(&'static str),
    MissingValue(String),
    InvalidAddress { flag: String, value: String },
    InvalidNumber { flag: String, value: String },
    InvalidIdentifier { flag: String, value: String },
    InvalidHttpPort(String),
    ZeroHttpPort,
    HttpLocalConflict,
    HttpEnrollOnlyConflict,
    HttpRequiresMutualTls,
    StartLocalConflict,
    StartTunnelConflict,
    StartEnrollOnlyConflict,
    IncompleteHostnameOptions,
    HostnameOptionsRequireHttp,
    ConfigRequiresHttp,
    PublicReachabilityRequiresHttp,
    PublicReachabilityOptionsWithoutOptIn,
    InvalidPublicReachabilityTimeout,
    InvalidPublicReachabilityMonitorInterval,
    PublicReachabilityThresholdRequiresMonitor,
    InvalidPublicReachabilityFailureThreshold,
    UnknownFlag(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequired(flag) => write!(f, "missing required option: {flag}"),
            Self::MissingValue(flag) => write!(f, "{flag} requires a value"),
            Self::InvalidAddress { flag, value } => {
                write!(f, "{flag}={value} is not a valid socket address")
            }
            Self::InvalidNumber { flag, value } => {
                write!(f, "{flag}={value} is not a valid integer")
            }
            Self::InvalidIdentifier { flag, value } => {
                write!(f, "{flag}={value} is not a valid durable identifier")
            }
            Self::InvalidHttpPort(value) => {
                write!(f, "http port {value} is not a valid TCP port")
            }
            Self::ZeroHttpPort => f.write_str("http port must be greater than zero"),
            Self::HttpLocalConflict => {
                f.write_str("http <port> cannot be combined with --local")
            }
            Self::HttpEnrollOnlyConflict => {
                f.write_str("http <port> cannot be combined with --enroll-only")
            }
            Self::HttpRequiresMutualTls => f.write_str(
                "http <port> requires --tls-ca, --tls-client-cert, --tls-client-key, and --tls-server-name",
            ),
            Self::StartLocalConflict => {
                f.write_str("start reads local ports from config v2 and rejects --local")
            }
            Self::StartTunnelConflict => {
                f.write_str("start reads TunnelIds from config v2 and rejects --tunnel-id")
            }
            Self::StartEnrollOnlyConflict => {
                f.write_str("start cannot be combined with --enroll-only")
            }
            Self::IncompleteHostnameOptions => f.write_str(
                "http <port> requires --hostname-server, --hostname-ca, and --hostname-server-name",
            ),
            Self::HostnameOptionsRequireHttp => {
                f.write_str("managed HTTP hostname options require http <port> or start")
            }
            Self::ConfigRequiresHttp => {
                f.write_str("--config is supported by http <port>, start, and config validate")
            }
            Self::PublicReachabilityRequiresHttp => {
                f.write_str("public reachability options require http <port> or start")
            }
            Self::PublicReachabilityOptionsWithoutOptIn => {
                f.write_str("public reachability tuning requires --verify-public-reachability")
            }
            Self::InvalidPublicReachabilityTimeout => f.write_str(
                "public reachability timeout must be between 1 ms and 300000 ms",
            ),
            Self::InvalidPublicReachabilityMonitorInterval => f.write_str(
                "public reachability monitor interval must be between 10000 ms and 3600000 ms",
            ),
            Self::PublicReachabilityThresholdRequiresMonitor => f.write_str(
                "public reachability failure threshold requires a monitor interval",
            ),
            Self::InvalidPublicReachabilityFailureThreshold => f.write_str(
                "public reachability failure threshold must be between 1 and 10",
            ),
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

fn parse_start_command(args: &[String]) -> Result<ParsedArgs, ArgError> {
    let mut parsed = parse_args(args)?;
    if parsed.local_explicit {
        return Err(ArgError::StartLocalConflict);
    }
    if parsed.tunnel_id_explicit {
        return Err(ArgError::StartTunnelConflict);
    }
    if parsed.enroll_only {
        return Err(ArgError::StartEnrollOnlyConflict);
    }
    // A v2 profile is always managed HTTP, including values supplied by the
    // config after this initial CLI-only validation.
    parsed.local_explicit = false;
    Ok(parsed)
}

fn parse_run_command(args: &[String]) -> Result<(RunMode, ParsedArgs), ArgError> {
    if args.first().map(String::as_str) != Some("http") {
        let parsed = parse_args(args)?;
        if parsed.hostname_options_present {
            return Err(ArgError::HostnameOptionsRequireHttp);
        }
        if parsed.config_path.is_some() {
            return Err(ArgError::ConfigRequiresHttp);
        }
        if parsed.public_reachability_options_present || parsed.verify_public_reachability {
            return Err(ArgError::PublicReachabilityRequiresHttp);
        }
        return Ok((RunMode::Tunnel, parsed));
    }

    let raw_port = args
        .get(1)
        .ok_or(ArgError::MissingRequired("http <port>"))?;
    let port = raw_port
        .parse::<u16>()
        .map_err(|_| ArgError::InvalidHttpPort(raw_port.clone()))?;
    if port == 0 {
        return Err(ArgError::ZeroHttpPort);
    }
    let mut parsed = parse_args(&args[2..])?;
    if parsed.help {
        parsed.local = SocketAddr::from(([127, 0, 0, 1], port));
        return Ok((RunMode::Http, parsed));
    }
    if parsed.local_explicit {
        return Err(ArgError::HttpLocalConflict);
    }
    if parsed.enroll_only {
        return Err(ArgError::HttpEnrollOnlyConflict);
    }
    parsed.local = SocketAddr::from(([127, 0, 0, 1], port));
    Ok((RunMode::Http, parsed))
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, ArgError> {
    let mut parsed = ParsedArgs::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--config" => {
                parsed.config_path = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--help" | "-h" => {
                parsed.help = true;
                index += 1;
            }
            "--edge" => {
                parsed.edge = parse_addr(args, index, flag)?;
                parsed.edge_explicit = true;
                index += 2;
            }
            "--local" => {
                parsed.local = parse_addr(args, index, flag)?;
                parsed.local_explicit = true;
                index += 2;
            }
            "--agent-id" => {
                parsed.agent_id = parse_agent_id(args, index, flag)?;
                parsed.agent_id_explicit = true;
                index += 2;
            }
            "--tunnel-id" => {
                parsed.tunnel_id = parse_tunnel_id(args, index, flag)?;
                parsed.tunnel_id_explicit = true;
                index += 2;
            }
            "--max-streams" => {
                parsed.max_streams = parse_number(args, index, flag)?;
                index += 2;
            }
            "--connect-timeout-ms" => {
                parsed.connect_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--handshake-timeout-ms" => {
                parsed.handshake_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--drain-timeout-ms" => {
                parsed.drain_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--reconnect-initial-ms" => {
                parsed.reconnect_initial = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--reconnect-max-ms" => {
                parsed.reconnect_max = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--reconnect-multiplier" => {
                parsed.reconnect_multiplier = parse_number(args, index, flag)?;
                index += 2;
            }
            "--reconnect-jitter-percent" => {
                parsed.reconnect_jitter_percent = parse_number(args, index, flag)?;
                index += 2;
            }
            "--stable-session-reset-ms" => {
                parsed.stable_session_reset =
                    Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--max-reconnect-attempts" => {
                parsed.max_reconnect_attempts = Some(parse_number(args, index, flag)?);
                index += 2;
            }
            "--ops-listen" => {
                parsed.ops_listen = Some(parse_addr(args, index, flag)?);
                index += 2;
            }
            "--max-ops-connections" => {
                parsed.max_ops_connections = parse_number(args, index, flag)?;
                index += 2;
            }
            "--ops-header-timeout-ms" => {
                parsed.ops_header_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--ops-request-timeout-ms" => {
                parsed.ops_request_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--tls-ca" => {
                parsed.tls_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.tls_ca_explicit = true;
                index += 2;
            }
            "--tls-client-cert" => {
                parsed.tls_client_cert = Some(PathBuf::from(value(args, index, flag)?));
                parsed.tls_client_cert_explicit = true;
                index += 2;
            }
            "--tls-client-key" => {
                parsed.tls_client_key = Some(PathBuf::from(value(args, index, flag)?));
                parsed.tls_client_key_explicit = true;
                index += 2;
            }
            "--tls-server-name" => {
                parsed.tls_server_name = Some(value(args, index, flag)?.to_string());
                parsed.tls_server_name_explicit = true;
                index += 2;
            }
            "--tls-handshake-timeout-ms" => {
                parsed.tls_handshake_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--tls-reload-manifest" => {
                parsed.tls_reload_manifest = Some(PathBuf::from(value(args, index, flag)?));
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            "--tls-reload-interval-ms" => {
                parsed.tls_reload_interval =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            "--tls-expiry-warning-ms" => {
                parsed.tls_expiry_warning = Duration::from_millis(parse_number(args, index, flag)?);
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            "--hostname-server" => {
                parsed.hostname_server = Some(parse_addr(args, index, flag)?);
                parsed.hostname_server_explicit = true;
                parsed.hostname_options_present = true;
                index += 2;
            }
            "--hostname-ca" => {
                parsed.hostname_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.hostname_ca_explicit = true;
                parsed.hostname_options_present = true;
                index += 2;
            }
            "--hostname-server-name" => {
                parsed.hostname_server_name = Some(value(args, index, flag)?.to_owned());
                parsed.hostname_server_name_explicit = true;
                parsed.hostname_options_present = true;
                index += 2;
            }
            "--hostname-request-timeout-ms" => {
                parsed.hostname_request_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.hostname_options_present = true;
                index += 2;
            }
            "--verify-public-reachability" => {
                parsed.verify_public_reachability = true;
                parsed.verify_public_reachability_explicit = true;
                index += 1;
            }
            "--public-reachability-ca" => {
                parsed.public_reachability_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.public_reachability_ca_explicit = true;
                parsed.public_reachability_options_present = true;
                index += 2;
            }
            "--public-reachability-timeout-ms" => {
                parsed.public_reachability_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.public_reachability_timeout_explicit = true;
                parsed.public_reachability_options_present = true;
                index += 2;
            }
            "--public-reachability-monitor-interval-ms" => {
                parsed.public_reachability_monitor_interval =
                    Some(Duration::from_millis(parse_number(args, index, flag)?));
                parsed.public_reachability_monitor_interval_explicit = true;
                parsed.public_reachability_options_present = true;
                index += 2;
            }
            "--public-reachability-failure-threshold" => {
                parsed.public_reachability_failure_threshold = parse_number(args, index, flag)?;
                parsed.public_reachability_failure_threshold_explicit = true;
                parsed.public_reachability_failure_threshold_present = true;
                parsed.public_reachability_options_present = true;
                index += 2;
            }
            "--enroll-only" => {
                parsed.enroll_only = true;
                parsed.enrollment_options_present = true;
                index += 1;
            }
            "--enrollment-server" => {
                parsed.enrollment_server = Some(parse_addr(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-ca" => {
                parsed.enrollment_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-server-name" => {
                parsed.enrollment_server_name = Some(value(args, index, flag)?.to_string());
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-token" => {
                parsed.enrollment_token = Some(PathBuf::from(value(args, index, flag)?));
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-pending" => {
                parsed.enrollment_pending = Some(PathBuf::from(value(args, index, flag)?));
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--renew-before-ms" => {
                parsed.renew_before = Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-poll-ms" => {
                parsed.enrollment_poll = Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-connect-timeout-ms" => {
                parsed.enrollment_connect_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-handshake-timeout-ms" => {
                parsed.enrollment_handshake_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-request-timeout-ms" => {
                parsed.enrollment_request_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            "--enrollment-activation-timeout-ms" => {
                parsed.enrollment_activation_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.enrollment_options_present = true;
                index += 2;
            }
            other => return Err(ArgError::UnknownFlag(other.to_string())),
        }
    }
    Ok(parsed)
}

#[derive(Debug)]
enum TlsLoadError {
    IncompleteArguments,
    Read(&'static str),
    Invalid(AgentTlsConfigError),
    IncompleteReloadArguments,
    Reload(AgentTlsReloadBootstrapError),
}

impl std::fmt::Display for TlsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "TLS requires --tls-ca, --tls-client-cert, --tls-client-key, and --tls-server-name",
            ),
            Self::Read(kind) => write!(f, "failed to read TLS {kind} PEM file"),
            Self::Invalid(error) => write!(f, "invalid TLS configuration: {error}"),
            Self::IncompleteReloadArguments => f.write_str(
                "TLS reload options require --tls-reload-manifest and complete TLS paths",
            ),
            Self::Reload(error) => write!(f, "invalid TLS reload configuration: {error}"),
        }
    }
}

struct LoadedTransportSecurity {
    security: AgentTransportSecurity,
    reloader: Option<AgentTlsReloadRuntime>,
}

async fn load_transport_security(
    parsed: &ParsedArgs,
) -> Result<LoadedTransportSecurity, TlsLoadError> {
    match (
        &parsed.tls_ca,
        &parsed.tls_client_cert,
        &parsed.tls_client_key,
        &parsed.tls_server_name,
    ) {
        (None, None, None, None) if !parsed.tls_reload_options_present => {
            Ok(LoadedTransportSecurity {
                security: AgentTransportSecurity::PlaintextLoopback,
                reloader: None,
            })
        }
        (Some(ca), Some(cert), Some(key), Some(server_name)) => {
            if let Some(manifest_path) = &parsed.tls_reload_manifest {
                let (tls, reloader) = AgentTlsReloadRuntime::bootstrap(
                    AgentTlsReloadConfig {
                        manifest_path: manifest_path.clone(),
                        server_ca_path: ca.clone(),
                        client_certificate_path: cert.clone(),
                        client_private_key_path: key.clone(),
                        poll_interval: parsed.tls_reload_interval,
                        expiry_warning: parsed.tls_expiry_warning,
                    },
                    server_name,
                    parsed.tls_handshake_timeout,
                )
                .await
                .map_err(TlsLoadError::Reload)?;
                return Ok(LoadedTransportSecurity {
                    security: AgentTransportSecurity::MutualTls(tls),
                    reloader: Some(reloader),
                });
            }
            if parsed.tls_reload_options_present {
                return Err(TlsLoadError::IncompleteReloadArguments);
            }
            let ca = tokio::fs::read(ca)
                .await
                .map_err(|_| TlsLoadError::Read("CA"))?;
            let cert = tokio::fs::read(cert)
                .await
                .map_err(|_| TlsLoadError::Read("client certificate"))?;
            let key = tokio::fs::read(key)
                .await
                .map_err(|_| TlsLoadError::Read("client private key"))?;
            AgentTlsConfig::from_pem(&ca, &cert, &key, server_name, parsed.tls_handshake_timeout)
                .map(|tls| LoadedTransportSecurity {
                    security: AgentTransportSecurity::MutualTls(tls),
                    reloader: None,
                })
                .map_err(TlsLoadError::Invalid)
        }
        _ => Err(TlsLoadError::IncompleteArguments),
    }
}

#[derive(Debug)]
enum EnrollmentLoadError {
    IncompleteArguments,
    ReloadManifestRequired,
    ReadCa,
    Invalid(AgentEnrollmentError),
}

impl std::fmt::Display for EnrollmentLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "enrollment requires --enrollment-server, --enrollment-ca, \
                 --enrollment-server-name, --enrollment-token, --enrollment-pending, complete \
                 Agent TLS paths, --tls-server-name, and --tls-reload-manifest",
            ),
            Self::ReloadManifestRequired => {
                f.write_str("automatic enrollment requires --tls-reload-manifest")
            }
            Self::ReadCa => f.write_str("failed to read enrollment server CA PEM file"),
            Self::Invalid(error) => write!(f, "invalid enrollment configuration: {error}"),
        }
    }
}

async fn load_enrollment_config(
    parsed: &ParsedArgs,
) -> Result<Option<AgentEnrollmentConfig>, EnrollmentLoadError> {
    if !parsed.enrollment_options_present {
        return Ok(None);
    }
    let (
        Some(server_addr),
        Some(enrollment_ca),
        Some(enrollment_server_name),
        Some(token_path),
        Some(pending_path),
        Some(server_ca_path),
        Some(client_certificate_path),
        Some(client_private_key_path),
        Some(edge_server_name),
        Some(manifest_path),
    ) = (
        parsed.enrollment_server,
        parsed.enrollment_ca.as_ref(),
        parsed.enrollment_server_name.as_ref(),
        parsed.enrollment_token.as_ref(),
        parsed.enrollment_pending.as_ref(),
        parsed.tls_ca.as_ref(),
        parsed.tls_client_cert.as_ref(),
        parsed.tls_client_key.as_ref(),
        parsed.tls_server_name.as_ref(),
        parsed.tls_reload_manifest.as_ref(),
    )
    else {
        if !parsed.enroll_only && parsed.tls_reload_manifest.is_none() {
            return Err(EnrollmentLoadError::ReloadManifestRequired);
        }
        return Err(EnrollmentLoadError::IncompleteArguments);
    };
    let server_ca_pem = tokio::fs::read(enrollment_ca)
        .await
        .map_err(|_| EnrollmentLoadError::ReadCa)?;
    let config = AgentEnrollmentConfig {
        client: EnrollmentClientConfig {
            server_addr,
            server_name: enrollment_server_name.clone(),
            server_ca_pem,
            connect_timeout: parsed.enrollment_connect_timeout,
            handshake_timeout: parsed.enrollment_handshake_timeout,
            request_timeout: parsed.enrollment_request_timeout,
        },
        agent_id: parsed.agent_id.clone(),
        tunnel_id: parsed.tunnel_id.clone(),
        token_path: token_path.clone(),
        pending_path: pending_path.clone(),
        credentials: AgentCredentialPaths {
            server_ca: server_ca_path.clone(),
            client_certificate: client_certificate_path.clone(),
            client_private_key: client_private_key_path.clone(),
            reload_manifest: manifest_path.clone(),
        },
        edge_server_name: edge_server_name.clone(),
        edge_tls_handshake_timeout: parsed.tls_handshake_timeout,
        renew_before: parsed.renew_before,
        poll_interval: parsed.enrollment_poll,
        activation_timeout: parsed.enrollment_activation_timeout,
    };
    config.validate().map_err(EnrollmentLoadError::Invalid)?;
    Ok(Some(config))
}

fn value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, ArgError> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| ArgError::MissingValue(flag.to_string()))
}

fn parse_addr(args: &[String], index: usize, flag: &str) -> Result<SocketAddr, ArgError> {
    let raw = value(args, index, flag)?;
    raw.parse().map_err(|_| ArgError::InvalidAddress {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

fn parse_number<T>(args: &[String], index: usize, flag: &str) -> Result<T, ArgError>
where
    T: std::str::FromStr,
{
    let raw = value(args, index, flag)?;
    raw.parse().map_err(|_| ArgError::InvalidNumber {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

fn parse_agent_id(args: &[String], index: usize, flag: &str) -> Result<AgentId, ArgError> {
    let raw = value(args, index, flag)?;
    AgentId::new(raw).map_err(|_| ArgError::InvalidIdentifier {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

fn parse_tunnel_id(args: &[String], index: usize, flag: &str) -> Result<TunnelId, ArgError> {
    let raw = value(args, index, flag)?;
    TunnelId::new(raw).map_err(|_| ArgError::InvalidIdentifier {
        flag: flag.to_string(),
        value: raw.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn defaults_are_stable() {
        assert_eq!(parse_args(&[]).unwrap(), ParsedArgs::default());
    }

    #[test]
    fn hostname_commands_require_complete_authenticated_inputs() {
        let parsed = parse_hostname_command(&args(&[
            "hostname-allocate",
            "--hostname-server",
            "127.0.0.1:17400",
            "--hostname-ca",
            "control-ca.pem",
            "--hostname-server-name",
            "control.test",
            "--tls-client-cert",
            "agent.pem",
            "--tls-client-key",
            "agent-key.pem",
            "--agent-id",
            "agent-prod",
            "--tunnel-id",
            "tunnel-prod",
            "--request-timeout-ms",
            "900",
        ]))
        .unwrap();
        assert_eq!(parsed.action, HostnameAction::Allocate);
        assert_eq!(parsed.server_addr.port(), 17400);
        assert_eq!(parsed.request_timeout, Duration::from_millis(900));
        assert!(matches!(
            parse_hostname_command(&args(&[
                "hostname-release",
                "--hostname-server",
                "127.0.0.1:17400"
            ])),
            Err(ArgError::MissingRequired("--hostname-ca"))
        ));
    }

    #[test]
    fn managed_http_command_composes_loopback_target_and_authenticated_services() {
        let (mode, parsed) = parse_run_command(&args(&[
            "http",
            "8080",
            "--edge",
            "127.0.0.1:17100",
            "--hostname-server",
            "127.0.0.1:17400",
            "--hostname-ca",
            "hostname-ca.pem",
            "--hostname-server-name",
            "control.test",
            "--hostname-request-timeout-ms",
            "900",
            "--tls-ca",
            "edge-ca.pem",
            "--tls-client-cert",
            "agent.pem",
            "--tls-client-key",
            "agent-key.pem",
            "--tls-server-name",
            "edge.test",
            "--agent-id",
            "agent-prod",
            "--tunnel-id",
            "tunnel-prod",
            "--verify-public-reachability",
            "--public-reachability-ca",
            "probe-ca.pem",
            "--public-reachability-timeout-ms",
            "12000",
            "--public-reachability-monitor-interval-ms",
            "15000",
            "--public-reachability-failure-threshold",
            "4",
        ]))
        .unwrap();
        assert_eq!(mode, RunMode::Http);
        assert_eq!(parsed.local, "127.0.0.1:8080".parse().unwrap());
        assert!(!parsed.local_explicit);
        assert_eq!(parsed.hostname_server.unwrap().port(), 17400);
        assert_eq!(parsed.hostname_ca, Some(PathBuf::from("hostname-ca.pem")));
        assert_eq!(parsed.hostname_server_name.as_deref(), Some("control.test"));
        assert_eq!(parsed.hostname_request_timeout, Duration::from_millis(900));
        assert_eq!(parsed.agent_id.as_str(), "agent-prod");
        assert_eq!(parsed.tunnel_id.as_str(), "tunnel-prod");
        assert!(parsed.verify_public_reachability);
        assert_eq!(
            parsed.public_reachability_ca,
            Some(PathBuf::from("probe-ca.pem"))
        );
        assert_eq!(parsed.public_reachability_timeout, Duration::from_secs(12));
        assert_eq!(
            parsed.public_reachability_monitor_interval,
            Some(Duration::from_secs(15))
        );
        assert_eq!(parsed.public_reachability_failure_threshold, 4);
        assert!(validate_http_configuration(&parsed).is_ok());
        assert_eq!(
            ManagedHttpAnnouncement {
                hostname: PublicHostname::new("tp-0123456789abcdef0123456789abcdef.test").unwrap(),
                local: parsed.local,
                probe: None,
                monitor: None,
            }
            .mapping(),
            "https://tp-0123456789abcdef0123456789abcdef.test -> http://127.0.0.1:8080"
        );
    }

    #[test]
    fn managed_http_command_rejects_ambiguous_or_incomplete_configuration() {
        assert!(matches!(
            parse_run_command(&args(&["http", "0"])),
            Err(ArgError::ZeroHttpPort)
        ));
        assert!(matches!(
            parse_run_command(&args(&["http", "not-a-port"])),
            Err(ArgError::InvalidHttpPort(_))
        ));
        assert!(matches!(
            parse_run_command(&args(&["http", "3000", "--local", "127.0.0.1:4000"])),
            Err(ArgError::HttpLocalConflict)
        ));
        let (_, incomplete) = parse_run_command(&args(&["http", "3000"])).unwrap();
        assert!(matches!(
            validate_http_configuration(&incomplete),
            Err(ArgError::HttpRequiresMutualTls)
        ));
        let (_, missing_hostname) = parse_run_command(&args(&[
            "http",
            "3000",
            "--tls-ca",
            "edge-ca.pem",
            "--tls-client-cert",
            "agent.pem",
            "--tls-client-key",
            "agent-key.pem",
            "--tls-server-name",
            "edge.test",
        ]))
        .unwrap();
        assert!(matches!(
            validate_http_configuration(&missing_hostname),
            Err(ArgError::IncompleteHostnameOptions)
        ));
        assert!(matches!(
            parse_run_command(&args(&[
                "--hostname-server",
                "127.0.0.1:7400",
                "--hostname-ca",
                "hostname-ca.pem",
                "--hostname-server-name",
                "control.test",
            ])),
            Err(ArgError::HostnameOptionsRequireHttp)
        ));
        assert!(matches!(
            parse_run_command(&args(&["--verify-public-reachability"])),
            Err(ArgError::PublicReachabilityRequiresHttp)
        ));

        let (_, tuning_without_opt_in) = parse_run_command(&args(&[
            "http",
            "3000",
            "--tls-ca",
            "edge-ca.pem",
            "--tls-client-cert",
            "agent.pem",
            "--tls-client-key",
            "agent-key.pem",
            "--tls-server-name",
            "edge.test",
            "--hostname-server",
            "127.0.0.1:17400",
            "--hostname-ca",
            "hostname-ca.pem",
            "--hostname-server-name",
            "control.test",
            "--public-reachability-timeout-ms",
            "1000",
        ]))
        .unwrap();
        assert!(matches!(
            validate_http_configuration(&tuning_without_opt_in),
            Err(ArgError::PublicReachabilityOptionsWithoutOptIn)
        ));

        let (_, threshold_without_monitor) = parse_run_command(&args(&[
            "http",
            "3000",
            "--tls-ca",
            "edge-ca.pem",
            "--tls-client-cert",
            "agent.pem",
            "--tls-client-key",
            "agent-key.pem",
            "--tls-server-name",
            "edge.test",
            "--hostname-server",
            "127.0.0.1:17400",
            "--hostname-ca",
            "hostname-ca.pem",
            "--hostname-server-name",
            "control.test",
            "--verify-public-reachability",
            "--public-reachability-failure-threshold",
            "3",
        ]))
        .unwrap();
        assert!(matches!(
            validate_http_configuration(&threshold_without_monitor),
            Err(ArgError::PublicReachabilityThresholdRequiresMonitor)
        ));
        let mut invalid_interval = threshold_without_monitor.clone();
        invalid_interval.public_reachability_monitor_interval = Some(Duration::from_millis(9_999));
        assert!(matches!(
            validate_http_configuration(&invalid_interval),
            Err(ArgError::InvalidPublicReachabilityMonitorInterval)
        ));
        let mut invalid_threshold = invalid_interval;
        invalid_threshold.public_reachability_monitor_interval = Some(Duration::from_secs(10));
        invalid_threshold.public_reachability_failure_threshold = 11;
        assert!(matches!(
            validate_http_configuration(&invalid_threshold),
            Err(ArgError::InvalidPublicReachabilityFailureThreshold)
        ));
    }

    fn valid_config_json() -> &'static [u8] {
        br#"{
            "version": 1,
            "edge": {
                "address": "127.0.0.1:17100",
                "ca": "edge-ca.pem",
                "server_name": "edge.test"
            },
            "hostname": {
                "address": "127.0.0.1:17400",
                "ca": "hostname-ca.pem",
                "server_name": "control.test"
            },
            "identity": {
                "agent_id": "agent-profile",
                "tunnel_id": "tunnel-profile",
                "client_certificate": "agent.pem",
                "client_private_key": "agent-key.pem"
            }
        }"#
    }

    fn valid_multi_config_json() -> &'static [u8] {
        br#"{
            "version": 2,
            "edge": {
                "address": "127.0.0.1:17100",
                "ca": "edge-ca.pem",
                "server_name": "edge.test"
            },
            "hostname": {
                "address": "127.0.0.1:17400",
                "ca": "hostname-ca.pem",
                "server_name": "control.test"
            },
            "identity": {
                "agent_id": "agent-profile",
                "client_certificate": "agent.pem",
                "client_private_key": "agent-key.pem"
            },
            "tunnels": [
                { "tunnel_id": "tunnel-a", "local_port": 3000 },
                { "tunnel_id": "tunnel-b", "local_port": 3001 }
            ]
        }"#
    }

    #[test]
    fn multi_config_is_strict_bounded_and_resolves_loopback_tunnels() {
        let AgentConfigDocument::Multi(config) =
            parse_agent_config(valid_multi_config_json()).unwrap()
        else {
            panic!("expected config v2");
        };
        let mut parsed = ParsedArgs::default();
        let config_path = PathBuf::from("profiles").join("config.json");
        let tunnels = apply_multi_agent_config(&mut parsed, &config_path, config).unwrap();
        assert_eq!(
            tunnels,
            vec![
                ManagedTunnelSpec {
                    tunnel_id: TunnelId::new("tunnel-a").unwrap(),
                    local: "127.0.0.1:3000".parse().unwrap(),
                },
                ManagedTunnelSpec {
                    tunnel_id: TunnelId::new("tunnel-b").unwrap(),
                    local: "127.0.0.1:3001".parse().unwrap(),
                },
            ]
        );
        assert_eq!(parsed.agent_id.as_str(), "agent-profile");
        assert_eq!(parsed.tls_ca, Some(PathBuf::from("profiles/edge-ca.pem")));

        let duplicate = String::from_utf8(valid_multi_config_json().to_vec())
            .unwrap()
            .replace("tunnel-b", "tunnel-a");
        let AgentConfigDocument::Multi(config) = parse_agent_config(duplicate.as_bytes()).unwrap()
        else {
            panic!("expected config v2");
        };
        assert!(matches!(
            apply_multi_agent_config(&mut ParsedArgs::default(), Path::new("config.json"), config),
            Err(AgentConfigError::DuplicateTunnel)
        ));

        let zero = String::from_utf8(valid_multi_config_json().to_vec())
            .unwrap()
            .replace("\"local_port\": 3000", "\"local_port\": 0");
        let AgentConfigDocument::Multi(config) = parse_agent_config(zero.as_bytes()).unwrap()
        else {
            panic!("expected config v2");
        };
        assert!(matches!(
            apply_multi_agent_config(&mut ParsedArgs::default(), Path::new("config.json"), config),
            Err(AgentConfigError::ZeroLocalPort)
        ));

        let make_config = |tunnels| MultiAgentConfigFile {
            version: MULTI_AGENT_CONFIG_VERSION,
            edge: AgentConfigEdge {
                address: "127.0.0.1:7100".to_owned(),
                ca: PathBuf::from("edge-ca.pem"),
                server_name: "edge.test".to_owned(),
            },
            hostname: AgentConfigHostname {
                address: "127.0.0.1:7400".to_owned(),
                ca: PathBuf::from("hostname-ca.pem"),
                server_name: "control.test".to_owned(),
            },
            identity: MultiAgentConfigIdentity {
                agent_id: "agent-profile".to_owned(),
                client_certificate: PathBuf::from("agent.pem"),
                client_private_key: PathBuf::from("agent-key.pem"),
            },
            tunnels,
            public_reachability: None,
        };
        assert!(matches!(
            apply_multi_agent_config(
                &mut ParsedArgs::default(),
                Path::new("config.json"),
                make_config(Vec::new()),
            ),
            Err(AgentConfigError::EmptyTunnels)
        ));
        let too_many = (0..=MAX_MANAGED_HTTP_TUNNELS)
            .map(|index| AgentConfigTunnel {
                tunnel_id: format!("tunnel-{index}"),
                local_port: 3000,
            })
            .collect();
        assert!(matches!(
            apply_multi_agent_config(
                &mut ParsedArgs::default(),
                Path::new("config.json"),
                make_config(too_many),
            ),
            Err(AgentConfigError::TooManyTunnels)
        ));
    }

    #[test]
    fn start_command_reserves_tunnel_shape_for_config_v2() {
        let parsed = parse_start_command(&args(&["--config", "profile.json"])).unwrap();
        assert_eq!(parsed.config_path, Some(PathBuf::from("profile.json")));
        assert!(matches!(
            parse_start_command(&args(&["--local", "127.0.0.1:3000"])),
            Err(ArgError::StartLocalConflict)
        ));
        assert!(matches!(
            parse_start_command(&args(&["--tunnel-id", "tunnel-a"])),
            Err(ArgError::StartTunnelConflict)
        ));
        assert!(matches!(
            parse_start_command(&args(&["--enroll-only"])),
            Err(ArgError::StartEnrollOnlyConflict)
        ));
    }

    #[test]
    fn strict_config_layers_relative_paths_below_explicit_cli_values() {
        let config_json = String::from_utf8(valid_config_json().to_vec())
            .unwrap()
            .replace(
                "\n            }\n        }",
                "\n            },\n            \"public_reachability\": {\n                \"enabled\": true,\n                \"ca\": \"probe-ca.pem\",\n                \"timeout_ms\": 9000,\n                \"monitor_interval_ms\": 10000,\n                \"failure_threshold\": 4\n            }\n        }",
            );
        let AgentConfigDocument::Single(config) =
            parse_agent_config(config_json.as_bytes()).unwrap()
        else {
            panic!("expected config v1");
        };
        let mut parsed = parse_args(&args(&[
            "--edge",
            "127.0.0.1:27100",
            "--tls-client-cert",
            "override-agent.pem",
            "--public-reachability-timeout-ms",
            "12000",
            "--public-reachability-failure-threshold",
            "5",
        ]))
        .unwrap();
        let config_path = PathBuf::from("profiles").join("config.json");
        apply_agent_config(&mut parsed, &config_path, config).unwrap();

        assert_eq!(parsed.edge.port(), 27100);
        assert_eq!(parsed.hostname_server.unwrap().port(), 17400);
        assert_eq!(parsed.agent_id.as_str(), "agent-profile");
        assert_eq!(parsed.tunnel_id.as_str(), "tunnel-profile");
        assert_eq!(parsed.tls_ca, Some(PathBuf::from("profiles/edge-ca.pem")));
        assert_eq!(
            parsed.hostname_ca,
            Some(PathBuf::from("profiles/hostname-ca.pem"))
        );
        assert_eq!(
            parsed.tls_client_cert,
            Some(PathBuf::from("override-agent.pem"))
        );
        assert_eq!(
            parsed.tls_client_key,
            Some(PathBuf::from("profiles/agent-key.pem"))
        );
        assert_eq!(parsed.tls_server_name.as_deref(), Some("edge.test"));
        assert_eq!(parsed.hostname_server_name.as_deref(), Some("control.test"));
        assert!(parsed.verify_public_reachability);
        assert_eq!(
            parsed.public_reachability_ca,
            Some(PathBuf::from("profiles/probe-ca.pem"))
        );
        assert_eq!(parsed.public_reachability_timeout, Duration::from_secs(12));
        assert_eq!(
            parsed.public_reachability_monitor_interval,
            Some(Duration::from_secs(10))
        );
        assert_eq!(parsed.public_reachability_failure_threshold, 5);
        assert!(validate_http_configuration(&parsed).is_ok());
    }

    #[test]
    fn config_schema_rejects_unknown_duplicate_and_unsupported_values() {
        let unknown = String::from_utf8(valid_config_json().to_vec())
            .unwrap()
            .replace("\"version\": 1,", "\"version\": 1, \"unknown\": true,");
        assert!(matches!(
            parse_agent_config(unknown.as_bytes()),
            Err(AgentConfigError::InvalidSchema)
        ));
        let duplicate = String::from_utf8(valid_config_json().to_vec())
            .unwrap()
            .replace("\"version\": 1,", "\"version\": 1, \"version\": 1,");
        assert!(matches!(
            parse_agent_config(duplicate.as_bytes()),
            Err(AgentConfigError::InvalidSchema)
        ));
        let unsupported = String::from_utf8(valid_config_json().to_vec())
            .unwrap()
            .replace("\"version\": 1", "\"version\": 2");
        assert!(matches!(
            parse_agent_config(unsupported.as_bytes()),
            Err(AgentConfigError::UnsupportedVersion)
        ));
        let disabled_monitor = String::from_utf8(valid_config_json().to_vec())
            .unwrap()
            .replace(
                "\n            }\n        }",
                "\n            },\n            \"public_reachability\": {\n                \"enabled\": false,\n                \"monitor_interval_ms\": 10000\n            }\n        }",
            );
        let AgentConfigDocument::Single(config) =
            parse_agent_config(disabled_monitor.as_bytes()).unwrap()
        else {
            panic!("expected config v1");
        };
        assert!(matches!(
            apply_agent_config(&mut ParsedArgs::default(), Path::new("config.json"), config,),
            Err(AgentConfigError::InvalidSchema)
        ));
    }

    #[tokio::test]
    async fn reachability_monitor_crosses_threshold_and_stops_on_shutdown() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable = listener.local_addr().unwrap();
        drop(listener);
        let probe = PublicReachabilityProbe::new(PublicReachabilityConfig {
            hostname: PublicHostname::new("monitor.example.test").unwrap(),
            ca_pem: None,
            total_timeout: Duration::from_millis(50),
            attempt_timeout: Duration::from_millis(20),
            retry_interval: Duration::from_millis(5),
            server_addr_override: Some(unavailable),
        })
        .unwrap();
        let runtime = AgentRuntime::new(AgentRuntimeConfig::new(
            "127.0.0.1:7100".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        ))
        .unwrap();
        let status = runtime.status_handle();
        status.require_public_reachability(true);
        status.record_public_reachability_success(1);
        let (trigger, signal) = shutdown_channel();
        let monitor = tokio::spawn(run_public_reachability_monitor(
            probe,
            PublicReachabilityMonitorConfig {
                interval: Duration::from_millis(1),
                failure_threshold: 2,
            },
            status.clone(),
            signal,
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if status.snapshot().public_reachability_state == PublicReachabilityState::Unhealthy
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("monitor did not cross the failure threshold");
        trigger.shutdown();
        monitor.await.unwrap().unwrap();
        let snapshot = status.snapshot();
        assert!(snapshot.public_reachability_monitor_cycles >= 2);
        assert_eq!(
            snapshot.public_reachability_monitor_failures,
            snapshot.public_reachability_monitor_cycles
        );
        assert!(snapshot.public_reachability_consecutive_failures >= 2);
        assert_eq!(snapshot.public_reachability_unhealthy_transitions, 1);
        assert!(!snapshot.is_ready());
    }

    #[test]
    fn config_path_precedence_and_platform_defaults_are_deterministic() {
        let explicit = PathBuf::from("explicit.json");
        let selected = select_config_path_from(
            Some(&explicit),
            Some(OsString::from("environment.json")),
            Some(PathBuf::from("default.json")),
        )
        .unwrap();
        assert_eq!(selected.path, explicit);
        assert_eq!(selected.source, ConfigPathSource::Explicit);

        let selected = select_config_path_from(
            None,
            Some(OsString::from("environment.json")),
            Some(PathBuf::from("default.json")),
        )
        .unwrap();
        assert_eq!(selected.path, PathBuf::from("environment.json"));
        assert_eq!(selected.source, ConfigPathSource::Environment);

        assert_eq!(
            platform_default_config_path(true, Some(OsString::from("app-data")), None, None,),
            Some(PathBuf::from("app-data/TunnelProxy/config.json"))
        );
        assert_eq!(
            platform_default_config_path(
                false,
                None,
                Some(OsString::from("xdg")),
                Some(OsString::from("home")),
            ),
            Some(PathBuf::from("xdg/tunnelproxy/config.json"))
        );
        assert_eq!(
            platform_default_config_path(false, None, None, Some(OsString::from("home")),),
            Some(PathBuf::from("home/.config/tunnelproxy/config.json"))
        );
    }

    #[tokio::test]
    async fn config_file_read_is_hard_bounded() {
        let directory =
            std::env::temp_dir().join(format!("tunnelproxy-agent-config-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("oversized.json");
        std::fs::write(&path, vec![b' '; MAX_AGENT_CONFIG_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            load_agent_config(&path).await,
            Err(AgentConfigError::TooLarge)
        ));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn all_flags_parse() {
        let parsed = parse_args(&args(&[
            "--edge",
            "127.0.0.1:17100",
            "--local",
            "127.0.0.1:13000",
            "--agent-id",
            "agent-prod",
            "--tunnel-id",
            "tunnel-prod",
            "--max-streams",
            "8",
            "--connect-timeout-ms",
            "100",
            "--handshake-timeout-ms",
            "200",
            "--drain-timeout-ms",
            "300",
            "--reconnect-initial-ms",
            "10",
            "--reconnect-max-ms",
            "400",
            "--reconnect-multiplier",
            "3",
            "--reconnect-jitter-percent",
            "15",
            "--stable-session-reset-ms",
            "500",
            "--max-reconnect-attempts",
            "7",
            "--ops-listen",
            "127.0.0.1:19091",
            "--max-ops-connections",
            "9",
            "--ops-header-timeout-ms",
            "900",
            "--ops-request-timeout-ms",
            "1000",
            "--tls-ca",
            "ca.pem",
            "--tls-client-cert",
            "agent.pem",
            "--tls-client-key",
            "agent-key.pem",
            "--tls-server-name",
            "edge.test",
            "--tls-handshake-timeout-ms",
            "600",
            "--tls-reload-manifest",
            "agent-tls.json",
            "--tls-reload-interval-ms",
            "700",
            "--tls-expiry-warning-ms",
            "800",
        ]))
        .unwrap();
        assert_eq!(parsed.edge.port(), 17100);
        assert_eq!(parsed.local.port(), 13000);
        assert_eq!(parsed.agent_id.as_str(), "agent-prod");
        assert_eq!(parsed.tunnel_id.as_str(), "tunnel-prod");
        assert_eq!(parsed.max_streams, 8);
        assert_eq!(parsed.connect_timeout, Duration::from_millis(100));
        assert_eq!(parsed.handshake_timeout, Duration::from_millis(200));
        assert_eq!(parsed.drain_timeout, Duration::from_millis(300));
        assert_eq!(parsed.reconnect_initial, Duration::from_millis(10));
        assert_eq!(parsed.reconnect_max, Duration::from_millis(400));
        assert_eq!(parsed.reconnect_multiplier, 3);
        assert_eq!(parsed.reconnect_jitter_percent, 15);
        assert_eq!(parsed.stable_session_reset, Duration::from_millis(500));
        assert_eq!(parsed.max_reconnect_attempts, Some(7));
        assert_eq!(parsed.ops_listen.unwrap().port(), 19091);
        assert_eq!(parsed.max_ops_connections, 9);
        assert_eq!(parsed.ops_header_timeout, Duration::from_millis(900));
        assert_eq!(parsed.ops_request_timeout, Duration::from_millis(1000));
        assert_eq!(parsed.tls_ca, Some(PathBuf::from("ca.pem")));
        assert_eq!(parsed.tls_client_cert, Some(PathBuf::from("agent.pem")));
        assert_eq!(parsed.tls_client_key, Some(PathBuf::from("agent-key.pem")));
        assert_eq!(parsed.tls_server_name.as_deref(), Some("edge.test"));
        assert_eq!(parsed.tls_handshake_timeout, Duration::from_millis(600));
        assert_eq!(
            parsed.tls_reload_manifest,
            Some(PathBuf::from("agent-tls.json"))
        );
        assert_eq!(parsed.tls_reload_interval, Duration::from_millis(700));
        assert_eq!(parsed.tls_expiry_warning, Duration::from_millis(800));
    }

    #[test]
    fn invalid_and_missing_values_are_typed() {
        assert!(matches!(
            parse_args(&args(&["--edge", "bad"])),
            Err(ArgError::InvalidAddress { .. })
        ));
        assert!(matches!(
            parse_args(&args(&["--max-streams"])),
            Err(ArgError::MissingValue(_))
        ));
        assert!(matches!(
            parse_args(&args(&["--unknown"])),
            Err(ArgError::UnknownFlag(_))
        ));
        assert!(matches!(
            parse_args(&args(&["--agent-id", "bad/id"])),
            Err(ArgError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn enrollment_flags_parse_without_secret_values_on_command_line() {
        let parsed = parse_args(&args(&[
            "--enroll-only",
            "--enrollment-server",
            "127.0.0.1:17300",
            "--enrollment-ca",
            "enrollment-ca.pem",
            "--enrollment-server-name",
            "enrollment.test",
            "--enrollment-token",
            "renewal.token",
            "--enrollment-pending",
            "enrollment.pending",
            "--renew-before-ms",
            "100",
            "--enrollment-poll-ms",
            "200",
            "--enrollment-connect-timeout-ms",
            "300",
            "--enrollment-handshake-timeout-ms",
            "400",
            "--enrollment-request-timeout-ms",
            "500",
            "--enrollment-activation-timeout-ms",
            "600",
        ]))
        .unwrap();
        assert!(parsed.enroll_only);
        assert_eq!(parsed.enrollment_server.unwrap().port(), 17300);
        assert_eq!(
            parsed.enrollment_ca,
            Some(PathBuf::from("enrollment-ca.pem"))
        );
        assert_eq!(
            parsed.enrollment_server_name.as_deref(),
            Some("enrollment.test")
        );
        assert_eq!(parsed.renew_before, Duration::from_millis(100));
        assert_eq!(parsed.enrollment_poll, Duration::from_millis(200));
        assert_eq!(
            parsed.enrollment_activation_timeout,
            Duration::from_millis(600)
        );
    }

    #[tokio::test]
    async fn partial_tls_arguments_are_rejected() {
        let parsed = ParsedArgs {
            tls_ca: Some(PathBuf::from("ca.pem")),
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_security(&parsed).await,
            Err(TlsLoadError::IncompleteArguments)
        ));

        let reload_without_tls = ParsedArgs {
            tls_reload_manifest: Some(PathBuf::from("reload.json")),
            tls_reload_options_present: true,
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_security(&reload_without_tls).await,
            Err(TlsLoadError::IncompleteArguments)
        ));
    }
}
