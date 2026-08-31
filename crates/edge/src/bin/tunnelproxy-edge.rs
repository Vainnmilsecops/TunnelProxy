//! Runnable single-tunnel Edge process with graceful OS shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use tracing::{error, info, warn};
use tunnelproxy_common::{
    init_process_logging, load_signed_access_key_ring, shutdown_channel, wait_for_process_shutdown,
    AgentId, ProcessLogFormat, SignedAccessKeyRingReloadConfig, SignedAccessKeyRingReloadRuntime,
    TunnelId, MAX_SIGNED_ACCESS_KEY_FILE_BYTES,
};
use tunnelproxy_control_plane::{
    HttpsRouteClientConfig, HttpsRouteClientTlsReloadConfig, HttpsRouteClientTlsReloadRuntime,
    SnapshotBootstrapSource, SnapshotCacheConfig, SnapshotClientConfig,
    SnapshotClientTlsReloadConfig, SnapshotClientTlsReloadRuntime, SnapshotTlsConfigError,
    SnapshotTlsReloadBootstrapError,
};
use tunnelproxy_edge::{
    ConnectIngressConfig, EdgeOperationsConfig, EdgeRegistrationPolicy,
    EdgeRegistrationPolicyError, EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeError,
    EdgeRuntimeOutcome, EdgeTlsConfig, EdgeTlsConfigError, EdgeTlsReloadBootstrapError,
    EdgeTlsReloadConfig, EdgeTlsReloadRuntime, EdgeTransportSecurity, Http2IngressConfig,
    HttpHostRoutes, HttpHostname, HttpIngressConfig, HttpIngressExposurePolicy,
    HttpRequestRateLimitConfig, PublicHttpProtocolPolicy, PublicTlsConfig, PublicTlsConfigError,
    PublicTlsReloadBootstrapError, PublicTlsReloadConfig, PublicTlsReloadRuntime,
    RawIngressExposurePolicy, RuntimeShutdownConfig, SignedAccessIngressConfig,
    SnapshotAwareEdgeRuntime, SnapshotAwareEdgeRuntimeError, SnapshotAwareEdgeRuntimeOutcome,
    WebSocketIngressConfig,
};

const USAGE: &str = "\
Usage: tunnelproxy-edge [OPTIONS]

Options:
  --agent-listen <addr>            Agent listener (default 127.0.0.1:7100)
  --raw-listen <addr>              raw ingress   (default 127.0.0.1:7000)
  --agent-id <id>                  authorized Agent ID (default agent-dev)
  --tunnel-id <id>                 authorized Tunnel ID (default tunnel-dev)
  --max-streams <usize>            stream limit  (default 32)
  --max-agent-sessions <usize>     Agent session limit (default 1)
  --max-raw-connections <usize>    ingress limit (default 32)
  --allow-public-raw-ingress       explicitly allow a non-loopback raw listener
  --max-raw-connections-per-ip <usize> required per-IP limit in public mode
  --https-listen <addr>            replace raw ingress with HTTPS
  --https-host <hostname>          exact public hostname routed to Tunnel ID
  --https-route-server <addr>      authenticated dynamic route service
  --https-route-max-stale-ms <ms>  route lifetime after disconnect (default 300000)
  --https-route-tls-reload-manifest <path> route-client TLS generation manifest
  --public-tls-cert <path>         public HTTPS certificate PEM
  --public-tls-key <path>          public HTTPS private key PEM
  --public-tls-reload-manifest <path> public HTTPS TLS generation manifest
  --allow-public-https-ingress     explicitly allow non-loopback HTTPS
  --max-http-connections <usize>   HTTPS connection limit (default 32)
  --max-http-connections-per-ip <usize> required per-IP public HTTPS limit
  --max-http-header-bytes <usize>  HTTP/1 buffer (default 16384)
  --max-http-headers <usize>       header count (default 64)
  --max-http-request-body-bytes <usize> body limit (default 10485760)
  --max-http-requests-per-connection <usize> keep-alive request cap (default 1)
  --enable-http2                  opt in to bounded HTTP/2 plus HTTP/1.1 fallback
  --max-http2-concurrent-streams <u32> HTTP/2 stream limit (default 32)
  --http2-keepalive-interval-ms <ms> HTTP/2 ping interval (default 30000)
  --http2-keepalive-timeout-ms <ms> HTTP/2 ping timeout (default 10000)
  --enable-websocket-upgrade       opt in to bounded HTTP/1.1 WebSocket upgrades
  --enable-http2-websocket         opt in to bounded RFC 8441 WebSocket over HTTP/2
  --max-websocket-sessions <usize> WebSocket session limit (default 32)
  --websocket-idle-timeout-ms <ms> WebSocket idle deadline (default 60000)
  --enable-connect                 opt in to route-bound HTTP/1.1 CONNECT
  --enable-http2-connect           opt in to route-bound classic HTTP/2 CONNECT
  --max-connect-sessions <usize>   CONNECT session limit (default 32)
  --connect-idle-timeout-ms <ms>   CONNECT idle deadline (default 60000)
  --connect-authority-port <u16>   required CONNECT authority port (default 443)
  --require-signed-access          require expiring tp_access URL signatures
  --signed-access-keyring <path>   bounded Ed25519 public-key ring JSON
  --signed-access-keyring-reload-manifest <path> signed-access generation manifest
  --signed-access-reload-interval-ms <ms> key-ring poll interval (default 1000)
  --signed-access-max-ttl-seconds <seconds> maximum token TTL (default 3600)
  --signed-access-clock-skew-seconds <seconds> accepted clock skew (default 30)
  --http-requests-per-second <u64> global request rate (default 100)
  --http-request-burst <u64>       global burst capacity (default 200)
  --http-requests-per-ip-per-second <u64> per-IP rate (default 20)
  --http-request-burst-per-ip <u64> per-IP burst capacity (default 40)
  --max-http-rate-limit-peers <usize> tracked peer bound (default 4096)
  --http-rate-limit-idle-ms <ms> peer bucket TTL (default 300000)
  --http-header-timeout-ms <ms>    header deadline (default 10000)
  --http-request-timeout-ms <ms>   full request deadline (default 60000)
  --ops-listen <loopback-addr>     enable health/readiness/metrics endpoint
  --max-ops-connections <usize>    operations connection limit (default 8)
  --ops-header-timeout-ms <ms>     operations header deadline (default 2000)
  --ops-request-timeout-ms <ms>    operations request deadline (default 5000)
  --drain-timeout-ms <ms>          stage drain   (default 10000)
  --tls-cert <path>                Edge certificate PEM
  --tls-key <path>                 Edge private key PEM
  --tls-client-ca <path>           trusted Agent CA PEM
  --authorized-client-cert <path>  exact authorized Agent certificate PEM
  --tls-handshake-timeout-ms <ms>  TLS timeout   (default 10000)
  --tls-reload-manifest <path>     Agent-facing TLS generation manifest
  --snapshot-server <addr>         Control Plane snapshot service
  --snapshot-ca <path>             trusted Control Plane CA PEM
  --snapshot-client-cert <path>    Edge snapshot client certificate PEM
  --snapshot-client-key <path>     Edge snapshot client private key PEM
  --snapshot-server-name <name>    Control Plane TLS server name
  --snapshot-connect-timeout-ms <ms>    connect timeout (default 5000)
  --snapshot-handshake-timeout-ms <ms>  TLS timeout (default 5000)
  --snapshot-subscribe-timeout-ms <ms>  subscribe timeout (default 5000)
  --snapshot-reconnect-initial-ms <ms>  first retry delay (default 250)
  --snapshot-reconnect-max-ms <ms>      maximum retry delay (default 30000)
  --snapshot-cache-dir <path>           opt-in cold-start snapshot cache
  --snapshot-cache-max-stale-ms <ms>    maximum offline cache age
  --snapshot-tls-reload-manifest <path> snapshot-client TLS generation manifest
  --tls-reload-interval-ms <ms>         reload poll (default 1000)
  --tls-expiry-warning-ms <ms>          expiry warning (default 604800000)
  --help                           print this help and exit
";

#[tokio::main]
async fn main() -> ExitCode {
    let logging = match init_process_logging() {
        Ok(logging) => logging,
        Err(error) => {
            eprintln!("failed to configure logging: {error}");
            return ExitCode::from(2);
        }
    };
    let log_format = logging.format();

    let args: Vec<_> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            error!(%error, "invalid Edge CLI arguments");
            print_usage_for_error(log_format);
            return ExitCode::from(2);
        }
    };
    if parsed.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let raw_exposure = match raw_exposure_policy(&parsed) {
        Ok(exposure) => exposure,
        Err(error) => {
            error!(%error, "invalid raw ingress exposure policy");
            print_usage_for_error(log_format);
            return ExitCode::from(2);
        }
    };

    let mut config = EdgeRuntimeConfig::dev_defaults();
    config.multiplex.agent_listener.listen_addr = parsed.agent_listen;
    config.multiplex.max_streams_per_session = parsed.max_streams;
    config.multiplex.agent_listener.max_agent_sessions = parsed.max_agent_sessions;
    config.raw_listen_addr = parsed.raw_listen;
    config.tunnel_id = parsed.tunnel_id.clone();
    config.max_raw_connections = parsed.max_raw_connections;
    config.raw_exposure = raw_exposure;
    config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
    config.operations = parsed.ops_listen.map(|listen_addr| {
        let mut operations = EdgeOperationsConfig::loopback(listen_addr);
        operations.max_concurrent_connections = parsed.max_ops_connections;
        operations.header_read_timeout = parsed.ops_header_timeout;
        operations.request_timeout = parsed.ops_request_timeout;
        operations.shutdown = config.shutdown;
        operations
    });
    let (https_ingress, public_tls_reloader, signed_access_reloader) =
        match load_https_configuration(&parsed).await {
            Ok(configuration) => configuration,
            Err(error) => {
                error!(%error, "failed to configure public HTTPS ingress");
                return ExitCode::from(2);
            }
        };
    config.https_ingress = https_ingress;
    let (https_routes, https_route_reloader) = match load_https_route_configuration(&parsed).await {
        Ok(configuration) => configuration,
        Err(error) => {
            error!(%error, "failed to configure HTTPS route distribution");
            return ExitCode::from(2);
        }
    };
    let authorization = match load_transport_configuration(&parsed).await {
        Ok(configuration) => configuration,
        Err(error) => {
            error!(%error, "failed to configure Edge transport authorization");
            return ExitCode::from(2);
        }
    };
    match authorization {
        LoadedAuthorization::Static {
            security,
            registration,
            mut reloaders,
        } => {
            if https_routes.is_some() {
                error!("dynamic HTTPS routes require snapshot authorization");
                return ExitCode::from(2);
            }
            reloaders.public = public_tls_reloader;
            reloaders.signed_access = signed_access_reloader;
            config.multiplex.security = security;
            config.multiplex.registration = registration;
            run_static_edge(config, reloaders, &parsed).await
        }
        LoadedAuthorization::Snapshot {
            security,
            snapshots,
            cache,
            mut reloaders,
        } => {
            reloaders.public = public_tls_reloader;
            reloaders.signed_access = signed_access_reloader;
            reloaders.routes = https_route_reloader;
            config.multiplex.security = security;
            run_snapshot_edge(config, snapshots, cache, https_routes, reloaders, &parsed).await
        }
    }
}

fn print_usage_for_error(log_format: ProcessLogFormat) {
    if log_format == ProcessLogFormat::Text {
        eprintln!("{USAGE}");
    }
}

async fn run_static_edge(
    config: EdgeRuntimeConfig,
    reloaders: LoadedTlsReloaders,
    parsed: &ParsedArgs,
) -> ExitCode {
    let runtime = match EdgeRuntime::bind(config).await {
        Ok(runtime) => runtime,
        Err(error) => return edge_start_error(error),
    };
    log_edge_started(runtime.agent_addr(), parsed, "static");
    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = reloaders.run_until_shutdown(signal);
    tokio::pin!(reload_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = reload_future.await;
            edge_exit_code(result)
        },
        reload = &mut reload_future => {
            trigger.shutdown();
            let _ = runtime_future.await;
            tls_reload_exit_code(reload)
        },
        observed = &mut os_signal => {
            if let Err(error) = observed {
                error!(%error, "OS shutdown listener failed");
                trigger.shutdown();
                let _ = runtime_future.await;
                return ExitCode::from(1);
            }
            trigger.shutdown();
            let result = runtime_future.await;
            let _ = reload_future.await;
            edge_exit_code(result)
        }
    }
}

async fn run_snapshot_edge(
    config: EdgeRuntimeConfig,
    snapshots: SnapshotClientConfig,
    cache: Option<SnapshotCacheConfig>,
    https_routes: Option<HttpsRouteClientConfig>,
    reloaders: LoadedTlsReloaders,
    parsed: &ParsedArgs,
) -> ExitCode {
    let bind_result = match (cache, https_routes) {
        (Some(cache), Some(routes)) => {
            SnapshotAwareEdgeRuntime::bind_with_cache_and_https_routes(
                config, snapshots, cache, routes,
            )
            .await
        }
        (None, Some(routes)) => {
            SnapshotAwareEdgeRuntime::bind_with_https_routes(config, snapshots, routes).await
        }
        (Some(cache), None) => {
            SnapshotAwareEdgeRuntime::bind_with_cache(config, snapshots, cache).await
        }
        (None, None) => SnapshotAwareEdgeRuntime::bind(config, snapshots).await,
    };
    let runtime = match bind_result {
        Ok(runtime) => runtime,
        Err(error) => {
            error!(%error, "failed to bootstrap snapshot-aware Edge runtime");
            return if matches!(
                error,
                SnapshotAwareEdgeRuntimeError::Edge(EdgeRuntimeError::InvalidConfig(_))
            ) {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            };
        }
    };
    let authorization = match runtime.bootstrap_source() {
        SnapshotBootstrapSource::Online => "snapshot-live",
        SnapshotBootstrapSource::DiskCache => "snapshot-stale-cache",
    };
    log_edge_started(runtime.agent_addr(), parsed, authorization);
    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = reloaders.run_until_shutdown(signal);
    tokio::pin!(reload_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = reload_future.await;
            snapshot_edge_exit_code(result)
        },
        reload = &mut reload_future => {
            trigger.shutdown();
            let _ = runtime_future.await;
            tls_reload_exit_code(reload)
        },
        observed = &mut os_signal => {
            if let Err(error) = observed {
                error!(%error, "OS shutdown listener failed");
                trigger.shutdown();
                let _ = runtime_future.await;
                return ExitCode::from(1);
            }
            trigger.shutdown();
            let result = runtime_future.await;
            let _ = reload_future.await;
            snapshot_edge_exit_code(result)
        }
    }
}

fn tls_reload_exit_code(result: Result<(), TlsReloadSupervisorError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "Edge TLS reload runtime failed");
            ExitCode::from(1)
        }
    }
}

fn log_edge_started(agent_addr: SocketAddr, parsed: &ParsedArgs, authorization: &'static str) {
    info!(
        %agent_addr,
        raw_addr = %parsed.raw_listen,
        https_addr = ?parsed.https_listen,
        operations_addr = ?parsed.ops_listen,
        https_host = ?parsed.https_host,
        https_route_server = ?parsed.https_route_server,
        http2_enabled = parsed.enable_http2,
        websocket_enabled = parsed.enable_websocket_upgrade,
        http2_websocket_enabled = parsed.enable_http2_websocket,
        connect_enabled = parsed.enable_connect,
        http2_connect_enabled = parsed.enable_http2_connect,
        agent_id = %parsed.agent_id,
        tunnel_id = %parsed.tunnel_id,
        public_raw_ingress = parsed.allow_public_raw_ingress,
        max_raw_connections_per_ip = ?parsed.max_raw_connections_per_ip,
        authorization,
        "Edge runtime is waiting for one Agent"
    );
}

fn edge_start_error(error: EdgeRuntimeError) -> ExitCode {
    error!(%error, "failed to start Edge runtime");
    if matches!(error, EdgeRuntimeError::InvalidConfig(_)) {
        ExitCode::from(2)
    } else {
        ExitCode::from(1)
    }
}

fn edge_exit_code(
    result: Result<EdgeRuntimeOutcome, tunnelproxy_edge::EdgeRuntimeError>,
) -> ExitCode {
    match result {
        Ok(outcome) if outcome.was_forced() => {
            warn!(?outcome, "Edge shutdown exceeded a drain deadline");
            ExitCode::from(1)
        }
        Ok(outcome) => {
            info!(?outcome, "Edge shutdown completed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            error!(%error, "Edge runtime failed");
            ExitCode::from(1)
        }
    }
}

fn snapshot_edge_exit_code(
    result: Result<SnapshotAwareEdgeRuntimeOutcome, SnapshotAwareEdgeRuntimeError>,
) -> ExitCode {
    match result {
        Ok(outcome) if outcome.was_forced() => {
            warn!(?outcome, "Edge shutdown exceeded a drain deadline");
            ExitCode::from(1)
        }
        Ok(outcome) => {
            info!(?outcome, "Edge shutdown completed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            error!(%error, "snapshot-aware Edge runtime failed");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    agent_listen: SocketAddr,
    raw_listen: SocketAddr,
    agent_id: AgentId,
    tunnel_id: TunnelId,
    max_streams: usize,
    max_agent_sessions: usize,
    max_raw_connections: usize,
    allow_public_raw_ingress: bool,
    max_raw_connections_per_ip: Option<usize>,
    raw_options_present: bool,
    https_options_present: bool,
    https_listen: Option<SocketAddr>,
    https_host: Option<HttpHostname>,
    https_route_server: Option<SocketAddr>,
    https_route_max_stale: Option<Duration>,
    https_route_tls_reload_manifest: Option<PathBuf>,
    public_tls_cert: Option<PathBuf>,
    public_tls_key: Option<PathBuf>,
    public_tls_reload_manifest: Option<PathBuf>,
    allow_public_https_ingress: bool,
    max_http_connections: usize,
    max_http_connections_per_ip: Option<usize>,
    max_http_header_bytes: usize,
    max_http_headers: usize,
    max_http_request_body_bytes: usize,
    max_http_requests_per_connection: usize,
    enable_http2: bool,
    max_http2_concurrent_streams: u32,
    http2_keep_alive_interval: Duration,
    http2_keep_alive_timeout: Duration,
    http2_options_present: bool,
    enable_websocket_upgrade: bool,
    enable_http2_websocket: bool,
    max_websocket_sessions: usize,
    websocket_idle_timeout: Duration,
    websocket_options_present: bool,
    enable_connect: bool,
    enable_http2_connect: bool,
    max_connect_sessions: usize,
    connect_idle_timeout: Duration,
    connect_authority_port: u16,
    connect_options_present: bool,
    require_signed_access: bool,
    signed_access_keyring: Option<PathBuf>,
    signed_access_keyring_reload_manifest: Option<PathBuf>,
    signed_access_reload_interval: Duration,
    signed_access_reload_options_present: bool,
    signed_access_maximum_ttl: Duration,
    signed_access_clock_skew: Duration,
    signed_access_options_present: bool,
    http_requests_per_second: u64,
    http_request_burst: u64,
    http_requests_per_ip_per_second: u64,
    http_request_burst_per_ip: u64,
    max_http_rate_limit_peers: usize,
    http_rate_limit_idle: Duration,
    http_header_timeout: Duration,
    http_request_timeout: Duration,
    ops_listen: Option<SocketAddr>,
    max_ops_connections: usize,
    ops_header_timeout: Duration,
    ops_request_timeout: Duration,
    ops_options_present: bool,
    drain_timeout: Duration,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    authorized_client_cert: Option<PathBuf>,
    tls_handshake_timeout: Duration,
    tls_reload_manifest: Option<PathBuf>,
    snapshot_server: Option<SocketAddr>,
    snapshot_ca: Option<PathBuf>,
    snapshot_client_cert: Option<PathBuf>,
    snapshot_client_key: Option<PathBuf>,
    snapshot_server_name: Option<String>,
    snapshot_connect_timeout: Duration,
    snapshot_handshake_timeout: Duration,
    snapshot_subscribe_timeout: Duration,
    snapshot_reconnect_initial: Duration,
    snapshot_reconnect_max: Duration,
    snapshot_cache_dir: Option<PathBuf>,
    snapshot_cache_max_stale: Option<Duration>,
    snapshot_tls_reload_manifest: Option<PathBuf>,
    tls_reload_interval: Duration,
    tls_expiry_warning: Duration,
    tls_reload_options_present: bool,
    snapshot_options_present: bool,
    help: bool,
}

impl Default for ParsedArgs {
    fn default() -> Self {
        Self {
            agent_listen: "127.0.0.1:7100".parse().unwrap(),
            raw_listen: "127.0.0.1:7000".parse().unwrap(),
            agent_id: AgentId::new("agent-dev").unwrap(),
            tunnel_id: TunnelId::new("tunnel-dev").unwrap(),
            max_streams: 32,
            max_agent_sessions: 1,
            max_raw_connections: 32,
            allow_public_raw_ingress: false,
            max_raw_connections_per_ip: None,
            raw_options_present: false,
            https_options_present: false,
            https_listen: None,
            https_host: None,
            https_route_server: None,
            https_route_max_stale: None,
            https_route_tls_reload_manifest: None,
            public_tls_cert: None,
            public_tls_key: None,
            public_tls_reload_manifest: None,
            allow_public_https_ingress: false,
            max_http_connections: 32,
            max_http_connections_per_ip: None,
            max_http_header_bytes: 16 * 1024,
            max_http_headers: 64,
            max_http_request_body_bytes: 10 * 1024 * 1024,
            max_http_requests_per_connection: 1,
            enable_http2: false,
            max_http2_concurrent_streams: 32,
            http2_keep_alive_interval: Duration::from_secs(30),
            http2_keep_alive_timeout: Duration::from_secs(10),
            http2_options_present: false,
            enable_websocket_upgrade: false,
            enable_http2_websocket: false,
            max_websocket_sessions: 32,
            websocket_idle_timeout: Duration::from_secs(60),
            websocket_options_present: false,
            enable_connect: false,
            enable_http2_connect: false,
            max_connect_sessions: 32,
            connect_idle_timeout: Duration::from_secs(60),
            connect_authority_port: 443,
            connect_options_present: false,
            require_signed_access: false,
            signed_access_keyring: None,
            signed_access_keyring_reload_manifest: None,
            signed_access_reload_interval: Duration::from_secs(1),
            signed_access_reload_options_present: false,
            signed_access_maximum_ttl: Duration::from_secs(60 * 60),
            signed_access_clock_skew: Duration::from_secs(30),
            signed_access_options_present: false,
            http_requests_per_second: 100,
            http_request_burst: 200,
            http_requests_per_ip_per_second: 20,
            http_request_burst_per_ip: 40,
            max_http_rate_limit_peers: 4_096,
            http_rate_limit_idle: Duration::from_secs(5 * 60),
            http_header_timeout: Duration::from_secs(10),
            http_request_timeout: Duration::from_secs(60),
            ops_listen: None,
            max_ops_connections: 8,
            ops_header_timeout: Duration::from_secs(2),
            ops_request_timeout: Duration::from_secs(5),
            ops_options_present: false,
            drain_timeout: Duration::from_secs(10),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            authorized_client_cert: None,
            tls_handshake_timeout: Duration::from_secs(10),
            tls_reload_manifest: None,
            snapshot_server: None,
            snapshot_ca: None,
            snapshot_client_cert: None,
            snapshot_client_key: None,
            snapshot_server_name: None,
            snapshot_connect_timeout: Duration::from_secs(5),
            snapshot_handshake_timeout: Duration::from_secs(5),
            snapshot_subscribe_timeout: Duration::from_secs(5),
            snapshot_reconnect_initial: Duration::from_millis(250),
            snapshot_reconnect_max: Duration::from_secs(30),
            snapshot_cache_dir: None,
            snapshot_cache_max_stale: None,
            snapshot_tls_reload_manifest: None,
            tls_reload_interval: Duration::from_secs(1),
            tls_expiry_warning: Duration::from_secs(7 * 24 * 60 * 60),
            tls_reload_options_present: false,
            snapshot_options_present: false,
            help: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ArgError {
    MissingValue(String),
    InvalidAddress { flag: String, value: String },
    InvalidNumber { flag: String, value: String },
    InvalidIdentifier { flag: String, value: String },
    PublicRawOptInRequired,
    PublicRawPerIpLimitRequired,
    PublicRawPerIpLimitWithoutOptIn,
    PublicRawPerIpLimitInvalid,
    InvalidHostname(String),
    HttpsRouteHostConflict,
    HttpsRouteStaleWithoutServer,
    HttpsRouteReloadWithoutServer,
    Http2OptionsWithoutOptIn,
    Http2ConnectWithoutHttp2,
    Http2WebSocketWithoutHttp2,
    WebSocketOptionsWithoutOptIn,
    ConnectOptionsWithoutOptIn,
    SignedAccessOptionsWithoutOptIn,
    SignedAccessReloadWithoutManifest,
    SignedAccessConnectConflict,
    IngressModeConflict,
    PublicHttpsOptInRequired,
    PublicHttpsPerIpLimitRequired,
    PublicHttpsPerIpLimitWithoutOptIn,
    PublicHttpsPerIpLimitInvalid,
    OperationsOptionsWithoutListener,
    UnknownFlag(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            Self::PublicRawOptInRequired => {
                f.write_str("a non-loopback raw listener requires --allow-public-raw-ingress")
            }
            Self::PublicRawPerIpLimitRequired => {
                f.write_str("public raw ingress requires --max-raw-connections-per-ip")
            }
            Self::PublicRawPerIpLimitWithoutOptIn => {
                f.write_str("--max-raw-connections-per-ip requires --allow-public-raw-ingress")
            }
            Self::PublicRawPerIpLimitInvalid => f.write_str(
                "--max-raw-connections-per-ip must be non-zero and cannot exceed --max-raw-connections",
            ),
            Self::InvalidHostname(value) => write!(f, "invalid HTTPS hostname: {value}"),
            Self::HttpsRouteHostConflict => {
                f.write_str("--https-host cannot be combined with --https-route-server")
            }
            Self::HttpsRouteStaleWithoutServer => {
                f.write_str("--https-route-max-stale-ms requires --https-route-server")
            }
            Self::HttpsRouteReloadWithoutServer => {
                f.write_str("--https-route-tls-reload-manifest requires --https-route-server")
            }
            Self::Http2OptionsWithoutOptIn => {
                f.write_str("HTTP/2 tuning options require --enable-http2")
            }
            Self::Http2ConnectWithoutHttp2 => {
                f.write_str("--enable-http2-connect requires --enable-http2")
            }
            Self::Http2WebSocketWithoutHttp2 => {
                f.write_str("--enable-http2-websocket requires --enable-http2")
            }
            Self::WebSocketOptionsWithoutOptIn => {
                f.write_str("WebSocket tuning options require --enable-websocket-upgrade")
            }
            Self::ConnectOptionsWithoutOptIn => {
                f.write_str("CONNECT tuning options require --enable-connect")
            }
            Self::SignedAccessOptionsWithoutOptIn => {
                f.write_str("signed-access options require --require-signed-access")
            }
            Self::SignedAccessReloadWithoutManifest => f.write_str(
                "--signed-access-reload-interval-ms requires --signed-access-keyring-reload-manifest",
            ),
            Self::SignedAccessConnectConflict => {
                f.write_str("--require-signed-access cannot be combined with CONNECT ingress")
            }
            Self::IngressModeConflict => {
                f.write_str("raw-ingress options cannot be combined with --https-listen")
            }
            Self::PublicHttpsOptInRequired => f.write_str(
                "a non-loopback HTTPS listener requires --allow-public-https-ingress",
            ),
            Self::PublicHttpsPerIpLimitRequired => f.write_str(
                "public HTTPS ingress requires --max-http-connections-per-ip",
            ),
            Self::PublicHttpsPerIpLimitWithoutOptIn => f.write_str(
                "--max-http-connections-per-ip requires --allow-public-https-ingress",
            ),
            Self::PublicHttpsPerIpLimitInvalid => f.write_str(
                "--max-http-connections-per-ip must be non-zero and cannot exceed --max-http-connections",
            ),
            Self::OperationsOptionsWithoutListener => {
                f.write_str("operations limit/timeout options require --ops-listen")
            }
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, ArgError> {
    let mut parsed = ParsedArgs::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--help" | "-h" => {
                parsed.help = true;
                index += 1;
            }
            "--agent-listen" => {
                parsed.agent_listen = parse_addr(args, index, flag)?;
                index += 2;
            }
            "--raw-listen" => {
                parsed.raw_listen = parse_addr(args, index, flag)?;
                parsed.raw_options_present = true;
                index += 2;
            }
            "--agent-id" => {
                parsed.agent_id = parse_agent_id(args, index, flag)?;
                index += 2;
            }
            "--tunnel-id" => {
                parsed.tunnel_id = parse_tunnel_id(args, index, flag)?;
                index += 2;
            }
            "--max-streams" => {
                parsed.max_streams = parse_number(args, index, flag)?;
                index += 2;
            }
            "--max-agent-sessions" => {
                parsed.max_agent_sessions = parse_number(args, index, flag)?;
                index += 2;
            }
            "--max-raw-connections" => {
                parsed.max_raw_connections = parse_number(args, index, flag)?;
                parsed.raw_options_present = true;
                index += 2;
            }
            "--allow-public-raw-ingress" => {
                parsed.allow_public_raw_ingress = true;
                parsed.raw_options_present = true;
                index += 1;
            }
            "--max-raw-connections-per-ip" => {
                parsed.max_raw_connections_per_ip = Some(parse_number(args, index, flag)?);
                parsed.raw_options_present = true;
                index += 2;
            }
            "--https-listen" => {
                parsed.https_listen = Some(parse_addr(args, index, flag)?);
                parsed.https_options_present = true;
                index += 2;
            }
            "--https-host" => {
                let raw = value(args, index, flag)?;
                parsed.https_host = Some(
                    HttpHostname::new(raw)
                        .map_err(|_| ArgError::InvalidHostname(raw.to_owned()))?,
                );
                parsed.https_options_present = true;
                index += 2;
            }
            "--https-route-server" => {
                parsed.https_route_server = Some(parse_addr(args, index, flag)?);
                parsed.https_options_present = true;
                index += 2;
            }
            "--https-route-max-stale-ms" => {
                parsed.https_route_max_stale =
                    Some(Duration::from_millis(parse_number(args, index, flag)?));
                parsed.https_options_present = true;
                index += 2;
            }
            "--https-route-tls-reload-manifest" => {
                parsed.https_route_tls_reload_manifest =
                    Some(PathBuf::from(value(args, index, flag)?));
                parsed.https_options_present = true;
                parsed.tls_reload_options_present = true;
                index += 2;
            }
            "--public-tls-cert" => {
                parsed.public_tls_cert = Some(PathBuf::from(value(args, index, flag)?));
                parsed.https_options_present = true;
                index += 2;
            }
            "--public-tls-key" => {
                parsed.public_tls_key = Some(PathBuf::from(value(args, index, flag)?));
                parsed.https_options_present = true;
                index += 2;
            }
            "--public-tls-reload-manifest" => {
                parsed.public_tls_reload_manifest = Some(PathBuf::from(value(args, index, flag)?));
                parsed.https_options_present = true;
                index += 2;
            }
            "--allow-public-https-ingress" => {
                parsed.allow_public_https_ingress = true;
                parsed.https_options_present = true;
                index += 1;
            }
            "--max-http-connections" => {
                parsed.max_http_connections = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--max-http-connections-per-ip" => {
                parsed.max_http_connections_per_ip = Some(parse_number(args, index, flag)?);
                parsed.https_options_present = true;
                index += 2;
            }
            "--max-http-header-bytes" => {
                parsed.max_http_header_bytes = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--max-http-headers" => {
                parsed.max_http_headers = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--max-http-request-body-bytes" => {
                parsed.max_http_request_body_bytes = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--max-http-requests-per-connection" => {
                parsed.max_http_requests_per_connection = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--enable-http2" => {
                parsed.enable_http2 = true;
                parsed.https_options_present = true;
                index += 1;
            }
            "--max-http2-concurrent-streams" => {
                parsed.max_http2_concurrent_streams = parse_number(args, index, flag)?;
                parsed.http2_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--http2-keepalive-interval-ms" => {
                parsed.http2_keep_alive_interval =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.http2_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--http2-keepalive-timeout-ms" => {
                parsed.http2_keep_alive_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.http2_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--enable-websocket-upgrade" => {
                parsed.enable_websocket_upgrade = true;
                parsed.https_options_present = true;
                index += 1;
            }
            "--enable-http2-websocket" => {
                parsed.enable_http2_websocket = true;
                parsed.https_options_present = true;
                index += 1;
            }
            "--max-websocket-sessions" => {
                parsed.max_websocket_sessions = parse_number(args, index, flag)?;
                parsed.websocket_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--websocket-idle-timeout-ms" => {
                parsed.websocket_idle_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.websocket_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--enable-connect" => {
                parsed.enable_connect = true;
                parsed.https_options_present = true;
                index += 1;
            }
            "--enable-http2-connect" => {
                parsed.enable_http2_connect = true;
                parsed.https_options_present = true;
                index += 1;
            }
            "--max-connect-sessions" => {
                parsed.max_connect_sessions = parse_number(args, index, flag)?;
                parsed.connect_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--connect-idle-timeout-ms" => {
                parsed.connect_idle_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.connect_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--connect-authority-port" => {
                parsed.connect_authority_port = parse_number(args, index, flag)?;
                parsed.connect_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--require-signed-access" => {
                parsed.require_signed_access = true;
                parsed.https_options_present = true;
                index += 1;
            }
            "--signed-access-keyring" => {
                parsed.signed_access_keyring = Some(PathBuf::from(value(args, index, flag)?));
                parsed.signed_access_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--signed-access-keyring-reload-manifest" => {
                parsed.signed_access_keyring_reload_manifest =
                    Some(PathBuf::from(value(args, index, flag)?));
                parsed.signed_access_reload_options_present = true;
                parsed.signed_access_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--signed-access-reload-interval-ms" => {
                parsed.signed_access_reload_interval =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.signed_access_reload_options_present = true;
                parsed.signed_access_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--signed-access-max-ttl-seconds" => {
                parsed.signed_access_maximum_ttl =
                    Duration::from_secs(parse_number(args, index, flag)?);
                parsed.signed_access_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--signed-access-clock-skew-seconds" => {
                parsed.signed_access_clock_skew =
                    Duration::from_secs(parse_number(args, index, flag)?);
                parsed.signed_access_options_present = true;
                parsed.https_options_present = true;
                index += 2;
            }
            "--http-requests-per-second" => {
                parsed.http_requests_per_second = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--http-request-burst" => {
                parsed.http_request_burst = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--http-requests-per-ip-per-second" => {
                parsed.http_requests_per_ip_per_second = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--http-request-burst-per-ip" => {
                parsed.http_request_burst_per_ip = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--max-http-rate-limit-peers" => {
                parsed.max_http_rate_limit_peers = parse_number(args, index, flag)?;
                parsed.https_options_present = true;
                index += 2;
            }
            "--http-rate-limit-idle-ms" => {
                parsed.http_rate_limit_idle =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.https_options_present = true;
                index += 2;
            }
            "--http-header-timeout-ms" => {
                parsed.http_header_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.https_options_present = true;
                index += 2;
            }
            "--http-request-timeout-ms" => {
                parsed.http_request_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.https_options_present = true;
                index += 2;
            }
            "--ops-listen" => {
                parsed.ops_listen = Some(parse_addr(args, index, flag)?);
                index += 2;
            }
            "--max-ops-connections" => {
                parsed.max_ops_connections = parse_number(args, index, flag)?;
                parsed.ops_options_present = true;
                index += 2;
            }
            "--ops-header-timeout-ms" => {
                parsed.ops_header_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                parsed.ops_options_present = true;
                index += 2;
            }
            "--ops-request-timeout-ms" => {
                parsed.ops_request_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.ops_options_present = true;
                index += 2;
            }
            "--drain-timeout-ms" => {
                parsed.drain_timeout = Duration::from_millis(parse_number(args, index, flag)?);
                index += 2;
            }
            "--tls-cert" => {
                parsed.tls_cert = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-key" => {
                parsed.tls_key = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-client-ca" => {
                parsed.tls_client_ca = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--authorized-client-cert" => {
                parsed.authorized_client_cert = Some(PathBuf::from(value(args, index, flag)?));
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
            "--snapshot-server" => {
                parsed.snapshot_server = Some(parse_addr(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-ca" => {
                parsed.snapshot_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-client-cert" => {
                parsed.snapshot_client_cert = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-client-key" => {
                parsed.snapshot_client_key = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-server-name" => {
                parsed.snapshot_server_name = Some(value(args, index, flag)?.to_owned());
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-connect-timeout-ms" => {
                parsed.snapshot_connect_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-handshake-timeout-ms" => {
                parsed.snapshot_handshake_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-subscribe-timeout-ms" => {
                parsed.snapshot_subscribe_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-reconnect-initial-ms" => {
                parsed.snapshot_reconnect_initial =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-reconnect-max-ms" => {
                parsed.snapshot_reconnect_max =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-cache-dir" => {
                parsed.snapshot_cache_dir = Some(PathBuf::from(value(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-cache-max-stale-ms" => {
                parsed.snapshot_cache_max_stale =
                    Some(Duration::from_millis(parse_number(args, index, flag)?));
                parsed.snapshot_options_present = true;
                index += 2;
            }
            "--snapshot-tls-reload-manifest" => {
                parsed.snapshot_tls_reload_manifest =
                    Some(PathBuf::from(value(args, index, flag)?));
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
            other => return Err(ArgError::UnknownFlag(other.to_string())),
        }
    }
    if parsed.ops_options_present && parsed.ops_listen.is_none() {
        return Err(ArgError::OperationsOptionsWithoutListener);
    }
    if parsed.https_route_server.is_some() && parsed.https_host.is_some() {
        return Err(ArgError::HttpsRouteHostConflict);
    }
    if parsed.https_route_max_stale.is_some() && parsed.https_route_server.is_none() {
        return Err(ArgError::HttpsRouteStaleWithoutServer);
    }
    if parsed.https_route_tls_reload_manifest.is_some() && parsed.https_route_server.is_none() {
        return Err(ArgError::HttpsRouteReloadWithoutServer);
    }
    if parsed.http2_options_present && !parsed.enable_http2 {
        return Err(ArgError::Http2OptionsWithoutOptIn);
    }
    if parsed.enable_http2_connect && !parsed.enable_http2 {
        return Err(ArgError::Http2ConnectWithoutHttp2);
    }
    if parsed.enable_http2_websocket && !parsed.enable_http2 {
        return Err(ArgError::Http2WebSocketWithoutHttp2);
    }
    if parsed.websocket_options_present
        && !parsed.enable_websocket_upgrade
        && !parsed.enable_http2_websocket
    {
        return Err(ArgError::WebSocketOptionsWithoutOptIn);
    }
    if parsed.connect_options_present && !parsed.enable_connect && !parsed.enable_http2_connect {
        return Err(ArgError::ConnectOptionsWithoutOptIn);
    }
    if parsed.signed_access_options_present && !parsed.require_signed_access {
        return Err(ArgError::SignedAccessOptionsWithoutOptIn);
    }
    if parsed.signed_access_reload_options_present
        && parsed.signed_access_keyring_reload_manifest.is_none()
    {
        return Err(ArgError::SignedAccessReloadWithoutManifest);
    }
    if parsed.require_signed_access && (parsed.enable_connect || parsed.enable_http2_connect) {
        return Err(ArgError::SignedAccessConnectConflict);
    }
    Ok(parsed)
}

fn raw_exposure_policy(parsed: &ParsedArgs) -> Result<RawIngressExposurePolicy, ArgError> {
    if parsed.https_listen.is_some() {
        if parsed.raw_options_present {
            return Err(ArgError::IngressModeConflict);
        }
        return Ok(RawIngressExposurePolicy::LoopbackOnly);
    }
    if !parsed.allow_public_raw_ingress {
        if parsed.max_raw_connections_per_ip.is_some() {
            return Err(ArgError::PublicRawPerIpLimitWithoutOptIn);
        }
        if !parsed.raw_listen.ip().is_loopback() {
            return Err(ArgError::PublicRawOptInRequired);
        }
        return Ok(RawIngressExposurePolicy::LoopbackOnly);
    }
    let max_connections_per_ip = parsed
        .max_raw_connections_per_ip
        .ok_or(ArgError::PublicRawPerIpLimitRequired)?;
    if max_connections_per_ip == 0 || max_connections_per_ip > parsed.max_raw_connections {
        return Err(ArgError::PublicRawPerIpLimitInvalid);
    }
    Ok(RawIngressExposurePolicy::Public {
        max_connections_per_ip,
    })
}

fn https_exposure_policy(parsed: &ParsedArgs) -> Result<HttpIngressExposurePolicy, ArgError> {
    let Some(listen_addr) = parsed.https_listen else {
        if parsed.max_http_connections_per_ip.is_some() {
            return Err(ArgError::PublicHttpsPerIpLimitWithoutOptIn);
        }
        return Ok(HttpIngressExposurePolicy::LoopbackOnly);
    };
    if !parsed.allow_public_https_ingress {
        if parsed.max_http_connections_per_ip.is_some() {
            return Err(ArgError::PublicHttpsPerIpLimitWithoutOptIn);
        }
        if !listen_addr.ip().is_loopback() {
            return Err(ArgError::PublicHttpsOptInRequired);
        }
        return Ok(HttpIngressExposurePolicy::LoopbackOnly);
    }
    let max_connections_per_ip = parsed
        .max_http_connections_per_ip
        .ok_or(ArgError::PublicHttpsPerIpLimitRequired)?;
    if max_connections_per_ip == 0 || max_connections_per_ip > parsed.max_http_connections {
        return Err(ArgError::PublicHttpsPerIpLimitInvalid);
    }
    Ok(HttpIngressExposurePolicy::Public {
        max_connections_per_ip,
    })
}

#[derive(Debug)]
enum TlsLoadError {
    IncompleteArguments,
    AuthorizationMode,
    IncompleteSnapshotArguments,
    Read(&'static str),
    Invalid(EdgeTlsConfigError),
    InvalidRegistration(EdgeRegistrationPolicyError),
    InvalidSnapshotTls(SnapshotTlsConfigError),
    InvalidSnapshotConfig,
    InvalidHttpsRouteTls(SnapshotTlsConfigError),
    InvalidHttpsRouteConfig,
    IncompleteSnapshotCacheArguments,
    InvalidSnapshotCache,
    ReloadArguments,
    EdgeReload(EdgeTlsReloadBootstrapError),
    SnapshotReload(SnapshotTlsReloadBootstrapError),
    HttpsRouteReload(SnapshotTlsReloadBootstrapError),
    IncompletePublicHttpsArguments,
    PublicHttpsWithoutListener,
    PublicHttpsExposure(ArgError),
    InvalidPublicTls(PublicTlsConfigError),
    InvalidHttpIngress(tunnelproxy_edge::HttpIngressConfigError),
    PublicReload(PublicTlsReloadBootstrapError),
    MissingSignedAccessKeyRing,
    ReadSignedAccessKeyRing,
    InvalidSignedAccessKeyRing,
    SignedAccessReload(tunnelproxy_common::SignedAccessKeyRingReloadError),
}

impl std::fmt::Display for TlsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteArguments => f.write_str(
                "Agent TLS requires --tls-cert, --tls-key, and --tls-client-ca",
            ),
            Self::AuthorizationMode => f.write_str(
                "Agent TLS requires exactly one authorization source: --authorized-client-cert or the complete snapshot group",
            ),
            Self::IncompleteSnapshotArguments => f.write_str(
                "snapshot authorization requires server, CA, client certificate/key, and server name",
            ),
            Self::Read(kind) => write!(f, "failed to read TLS {kind} PEM file"),
            Self::Invalid(error) => write!(f, "invalid TLS configuration: {error}"),
            Self::InvalidRegistration(error) => {
                write!(f, "invalid registration authorization: {error}")
            }
            Self::InvalidSnapshotTls(error) => {
                write!(f, "invalid snapshot TLS configuration: {error}")
            }
            Self::InvalidSnapshotConfig => f.write_str("snapshot client configuration is invalid"),
            Self::InvalidHttpsRouteTls(error) => {
                write!(f, "invalid HTTPS route client TLS configuration: {error}")
            }
            Self::InvalidHttpsRouteConfig => {
                f.write_str("HTTPS route client configuration is invalid")
            }
            Self::IncompleteSnapshotCacheArguments => f.write_str(
                "snapshot cache requires both --snapshot-cache-dir and --snapshot-cache-max-stale-ms",
            ),
            Self::InvalidSnapshotCache => {
                f.write_str("snapshot cache directory and maximum stale age are invalid")
            }
            Self::ReloadArguments => f.write_str(
                "TLS reload manifests require complete matching TLS path groups and non-zero reload settings",
            ),
            Self::EdgeReload(error) => write!(f, "Agent-facing TLS reload is invalid: {error}"),
            Self::SnapshotReload(error) => {
                write!(f, "snapshot-client TLS reload is invalid: {error}")
            }
            Self::HttpsRouteReload(error) => {
                write!(f, "HTTPS route-client TLS reload is invalid: {error}")
            }
            Self::IncompletePublicHttpsArguments => f.write_str(
                "HTTPS ingress requires --https-listen, one route source, --public-tls-cert, and --public-tls-key",
            ),
            Self::PublicHttpsWithoutListener => {
                f.write_str("public HTTPS options require --https-listen")
            }
            Self::PublicHttpsExposure(error) => error.fmt(f),
            Self::InvalidPublicTls(error) => write!(f, "invalid public TLS configuration: {error}"),
            Self::InvalidHttpIngress(error) => write!(f, "invalid HTTPS ingress: {error}"),
            Self::PublicReload(error) => write!(f, "public TLS reload is invalid: {error}"),
            Self::MissingSignedAccessKeyRing => {
                f.write_str("--require-signed-access requires --signed-access-keyring")
            }
            Self::ReadSignedAccessKeyRing => {
                f.write_str("failed to read signed-access public-key ring")
            }
            Self::InvalidSignedAccessKeyRing => {
                f.write_str("signed-access public-key ring is invalid")
            }
            Self::SignedAccessReload(error) => {
                write!(f, "signed-access key-ring reload is invalid: {error}")
            }
        }
    }
}

#[derive(Default)]
struct LoadedTlsReloaders {
    edge: Option<EdgeTlsReloadRuntime>,
    snapshot: Option<SnapshotClientTlsReloadRuntime>,
    public: Option<PublicTlsReloadRuntime>,
    routes: Option<HttpsRouteClientTlsReloadRuntime>,
    signed_access: Option<SignedAccessKeyRingReloadRuntime>,
}

impl LoadedTlsReloaders {
    async fn run_until_shutdown(
        self,
        signal: tunnelproxy_common::ShutdownSignal,
    ) -> Result<(), TlsReloadSupervisorError> {
        let mut tasks = tokio::task::JoinSet::new();
        if let Some(runtime) = self.edge {
            let child_signal = signal.clone();
            tasks.spawn(async move {
                runtime
                    .run_until_shutdown(child_signal)
                    .await
                    .map_err(TlsReloadSupervisorError::Edge)
            });
        }
        if let Some(runtime) = self.snapshot {
            let child_signal = signal.clone();
            tasks.spawn(async move {
                runtime
                    .run_until_shutdown(child_signal)
                    .await
                    .map_err(TlsReloadSupervisorError::Snapshot)
            });
        }
        if let Some(runtime) = self.public {
            let child_signal = signal.clone();
            tasks.spawn(async move {
                runtime
                    .run_until_shutdown(child_signal)
                    .await
                    .map_err(TlsReloadSupervisorError::Public)
            });
        }
        if let Some(runtime) = self.routes {
            let child_signal = signal.clone();
            tasks.spawn(async move {
                runtime
                    .run_until_shutdown(child_signal)
                    .await
                    .map_err(TlsReloadSupervisorError::HttpsRoute)
            });
        }
        if let Some(runtime) = self.signed_access {
            let child_signal = signal.clone();
            tasks.spawn(async move {
                runtime.run_until_shutdown(child_signal).await;
                Ok(())
            });
        }
        if tasks.is_empty() {
            signal.cancelled().await;
            return Ok(());
        }
        tokio::select! {
            biased;
            () = signal.cancelled() => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Ok(())
            }
            result = tasks.join_next() => match result {
                Some(Ok(result)) => result,
                Some(Err(_)) | None => Err(TlsReloadSupervisorError::Task),
            }
        }
    }
}

#[derive(Debug)]
enum TlsReloadSupervisorError {
    Edge(tunnelproxy_common::TlsReloadRuntimeError),
    Snapshot(tunnelproxy_common::TlsReloadRuntimeError),
    Public(tunnelproxy_common::TlsReloadRuntimeError),
    HttpsRoute(tunnelproxy_common::TlsReloadRuntimeError),
    Task,
}

impl std::fmt::Display for TlsReloadSupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Edge(error) => write!(f, "Agent-facing TLS reload failed: {error}"),
            Self::Snapshot(error) => write!(f, "snapshot-client TLS reload failed: {error}"),
            Self::Public(error) => write!(f, "public TLS reload failed: {error}"),
            Self::HttpsRoute(error) => write!(f, "HTTPS route-client TLS reload failed: {error}"),
            Self::Task => f.write_str("TLS reload task stopped unexpectedly"),
        }
    }
}

enum LoadedAuthorization {
    Static {
        security: EdgeTransportSecurity,
        registration: EdgeRegistrationPolicy,
        reloaders: LoadedTlsReloaders,
    },
    Snapshot {
        security: EdgeTransportSecurity,
        snapshots: SnapshotClientConfig,
        cache: Option<SnapshotCacheConfig>,
        reloaders: LoadedTlsReloaders,
    },
}

async fn load_transport_configuration(
    parsed: &ParsedArgs,
) -> Result<LoadedAuthorization, TlsLoadError> {
    match (&parsed.tls_cert, &parsed.tls_key, &parsed.tls_client_ca) {
        (None, None, None) => {
            if parsed.authorized_client_cert.is_some()
                || has_snapshot_arguments(parsed)
                || parsed.tls_reload_options_present
            {
                return Err(TlsLoadError::AuthorizationMode);
            }
            Ok(LoadedAuthorization::Static {
                security: EdgeTransportSecurity::PlaintextLoopback,
                registration: EdgeRegistrationPolicy::loopback_development(
                    parsed.agent_id.clone(),
                    parsed.tunnel_id.clone(),
                ),
                reloaders: LoadedTlsReloaders::default(),
            })
        }
        (Some(cert), Some(key), Some(client_ca)) => {
            let snapshot_mode = match (
                &parsed.authorized_client_cert,
                has_snapshot_arguments(parsed),
            ) {
                (Some(_), true) | (None, false) => return Err(TlsLoadError::AuthorizationMode),
                (Some(_), false) => false,
                (None, true) if snapshot_arguments_complete(parsed) => true,
                (None, true) => return Err(TlsLoadError::IncompleteSnapshotArguments),
            };
            if parsed.tls_reload_options_present
                && parsed.tls_reload_manifest.is_none()
                && parsed.snapshot_tls_reload_manifest.is_none()
                && parsed.https_route_tls_reload_manifest.is_none()
            {
                return Err(TlsLoadError::ReloadArguments);
            }
            if !snapshot_mode && parsed.snapshot_tls_reload_manifest.is_some() {
                return Err(TlsLoadError::ReloadArguments);
            }
            if !snapshot_mode {
                if let Some(manifest_path) = &parsed.tls_reload_manifest {
                    let Some(authorized_client_certificate_path) = &parsed.authorized_client_cert
                    else {
                        return Err(TlsLoadError::AuthorizationMode);
                    };
                    let (tls, registration, runtime) =
                        EdgeTlsReloadRuntime::bootstrap_with_static_authorization(
                            EdgeTlsReloadConfig {
                                manifest_path: manifest_path.clone(),
                                server_certificate_path: cert.clone(),
                                server_private_key_path: key.clone(),
                                client_ca_path: client_ca.clone(),
                                poll_interval: parsed.tls_reload_interval,
                                expiry_warning: parsed.tls_expiry_warning,
                            },
                            authorized_client_certificate_path.clone(),
                            parsed.tls_handshake_timeout,
                            parsed.agent_id.clone(),
                            parsed.tunnel_id.clone(),
                        )
                        .await
                        .map_err(TlsLoadError::EdgeReload)?;
                    return Ok(LoadedAuthorization::Static {
                        security: EdgeTransportSecurity::MutualTls(tls),
                        registration,
                        reloaders: LoadedTlsReloaders {
                            edge: Some(runtime),
                            snapshot: None,
                            public: None,
                            routes: None,
                            signed_access: None,
                        },
                    });
                }
            }
            let (tls, edge_reloader) = if let Some(manifest_path) = &parsed.tls_reload_manifest {
                let (tls, runtime) = EdgeTlsReloadRuntime::bootstrap(
                    EdgeTlsReloadConfig {
                        manifest_path: manifest_path.clone(),
                        server_certificate_path: cert.clone(),
                        server_private_key_path: key.clone(),
                        client_ca_path: client_ca.clone(),
                        poll_interval: parsed.tls_reload_interval,
                        expiry_warning: parsed.tls_expiry_warning,
                    },
                    parsed.tls_handshake_timeout,
                )
                .await
                .map_err(TlsLoadError::EdgeReload)?;
                (tls, Some(runtime))
            } else {
                let cert = tokio::fs::read(cert)
                    .await
                    .map_err(|_| TlsLoadError::Read("server certificate"))?;
                let key = tokio::fs::read(key)
                    .await
                    .map_err(|_| TlsLoadError::Read("server private key"))?;
                let client_ca = tokio::fs::read(client_ca)
                    .await
                    .map_err(|_| TlsLoadError::Read("client CA"))?;
                let tls =
                    EdgeTlsConfig::from_pem(&cert, &key, &client_ca, parsed.tls_handshake_timeout)
                        .map_err(TlsLoadError::Invalid)?;
                (tls, None)
            };
            let security = EdgeTransportSecurity::MutualTls(tls);
            if snapshot_mode {
                load_snapshot_configuration(parsed, security, edge_reloader).await
            } else {
                let Some(authorized_client_cert) = &parsed.authorized_client_cert else {
                    return Err(TlsLoadError::AuthorizationMode);
                };
                let authorized_client_cert = tokio::fs::read(authorized_client_cert)
                    .await
                    .map_err(|_| TlsLoadError::Read("authorized client certificate"))?;
                let registration = EdgeRegistrationPolicy::mutual_tls_from_client_cert_pem(
                    parsed.agent_id.clone(),
                    parsed.tunnel_id.clone(),
                    &authorized_client_cert,
                )
                .map_err(TlsLoadError::InvalidRegistration)?;
                Ok(LoadedAuthorization::Static {
                    security,
                    registration,
                    reloaders: LoadedTlsReloaders {
                        edge: edge_reloader,
                        snapshot: None,
                        public: None,
                        routes: None,
                        signed_access: None,
                    },
                })
            }
        }
        _ => Err(TlsLoadError::IncompleteArguments),
    }
}

fn has_snapshot_arguments(parsed: &ParsedArgs) -> bool {
    parsed.snapshot_options_present
}

fn snapshot_arguments_complete(parsed: &ParsedArgs) -> bool {
    parsed.snapshot_server.is_some()
        && parsed.snapshot_ca.is_some()
        && parsed.snapshot_client_cert.is_some()
        && parsed.snapshot_client_key.is_some()
        && parsed.snapshot_server_name.is_some()
}

async fn load_snapshot_configuration(
    parsed: &ParsedArgs,
    security: EdgeTransportSecurity,
    edge_reloader: Option<EdgeTlsReloadRuntime>,
) -> Result<LoadedAuthorization, TlsLoadError> {
    let cache = snapshot_cache_configuration(parsed)?;
    let (Some(server), Some(ca), Some(client_cert), Some(client_key), Some(server_name)) = (
        parsed.snapshot_server,
        parsed.snapshot_ca.as_ref(),
        parsed.snapshot_client_cert.as_ref(),
        parsed.snapshot_client_key.as_ref(),
        parsed.snapshot_server_name.as_deref(),
    ) else {
        return Err(TlsLoadError::IncompleteSnapshotArguments);
    };
    let (mut snapshots, snapshot_reloader) =
        if let Some(manifest_path) = &parsed.snapshot_tls_reload_manifest {
            let (config, runtime) = SnapshotClientTlsReloadRuntime::bootstrap(
                server,
                server_name,
                SnapshotClientTlsReloadConfig {
                    manifest_path: manifest_path.clone(),
                    server_ca_path: ca.clone(),
                    client_certificate_path: client_cert.clone(),
                    client_private_key_path: client_key.clone(),
                    poll_interval: parsed.tls_reload_interval,
                    expiry_warning: parsed.tls_expiry_warning,
                },
            )
            .await
            .map_err(TlsLoadError::SnapshotReload)?;
            (config, Some(runtime))
        } else {
            let (ca, client_cert, client_key) = tokio::try_join!(
                read_tls_file(ca, "snapshot CA"),
                read_tls_file(client_cert, "snapshot client certificate"),
                read_tls_file(client_key, "snapshot client private key"),
            )?;
            let config =
                SnapshotClientConfig::from_pem(server, &ca, &client_cert, &client_key, server_name)
                    .map_err(TlsLoadError::InvalidSnapshotTls)?;
            (config, None)
        };
    snapshots.connect_timeout = parsed.snapshot_connect_timeout;
    snapshots.handshake_timeout = parsed.snapshot_handshake_timeout;
    snapshots.subscribe_timeout = parsed.snapshot_subscribe_timeout;
    snapshots.reconnect_initial_delay = parsed.snapshot_reconnect_initial;
    snapshots.reconnect_max_delay = parsed.snapshot_reconnect_max;
    snapshots
        .validate()
        .map_err(|_| TlsLoadError::InvalidSnapshotConfig)?;
    Ok(LoadedAuthorization::Snapshot {
        security,
        snapshots,
        cache,
        reloaders: LoadedTlsReloaders {
            edge: edge_reloader,
            snapshot: snapshot_reloader,
            public: None,
            routes: None,
            signed_access: None,
        },
    })
}

fn snapshot_cache_configuration(
    parsed: &ParsedArgs,
) -> Result<Option<SnapshotCacheConfig>, TlsLoadError> {
    match (
        parsed.snapshot_cache_dir.clone(),
        parsed.snapshot_cache_max_stale,
    ) {
        (None, None) => Ok(None),
        (Some(directory), Some(max_stale_age)) => {
            let config = SnapshotCacheConfig {
                directory,
                max_stale_age,
            };
            config
                .validate()
                .map_err(|_| TlsLoadError::InvalidSnapshotCache)?;
            Ok(Some(config))
        }
        _ => Err(TlsLoadError::IncompleteSnapshotCacheArguments),
    }
}

async fn load_https_configuration(
    parsed: &ParsedArgs,
) -> Result<
    (
        Option<HttpIngressConfig>,
        Option<PublicTlsReloadRuntime>,
        Option<SignedAccessKeyRingReloadRuntime>,
    ),
    TlsLoadError,
> {
    let Some(listen_addr) = parsed.https_listen else {
        if parsed.https_options_present {
            return Err(TlsLoadError::PublicHttpsWithoutListener);
        }
        return Ok((None, None, None));
    };
    let (Some(certificate_path), Some(private_key_path)) = (
        parsed.public_tls_cert.clone(),
        parsed.public_tls_key.clone(),
    ) else {
        return Err(TlsLoadError::IncompletePublicHttpsArguments);
    };
    if parsed.https_host.is_none() && parsed.https_route_server.is_none() {
        return Err(TlsLoadError::IncompletePublicHttpsArguments);
    }
    let exposure = https_exposure_policy(parsed).map_err(TlsLoadError::PublicHttpsExposure)?;
    let request_rate_limit = HttpRequestRateLimitConfig {
        global_requests_per_second: parsed.http_requests_per_second,
        global_burst: parsed.http_request_burst,
        per_ip_requests_per_second: parsed.http_requests_per_ip_per_second,
        per_ip_burst: parsed.http_request_burst_per_ip,
        max_tracked_ips: parsed.max_http_rate_limit_peers,
        peer_idle_ttl: parsed.http_rate_limit_idle,
    };
    request_rate_limit.validate().map_err(|error| {
        TlsLoadError::InvalidHttpIngress(
            tunnelproxy_edge::HttpIngressConfigError::InvalidRequestRateLimit(error),
        )
    })?;
    let (signed_access, signed_access_reloader) = if parsed.require_signed_access {
        let path = parsed
            .signed_access_keyring
            .as_ref()
            .ok_or(TlsLoadError::MissingSignedAccessKeyRing)?;
        let (key_ring, reloader) = match &parsed.signed_access_keyring_reload_manifest {
            Some(manifest_path) => {
                let (key_ring, runtime) =
                    SignedAccessKeyRingReloadRuntime::bootstrap(SignedAccessKeyRingReloadConfig {
                        manifest_path: manifest_path.clone(),
                        key_ring_path: path.clone(),
                        poll_interval: parsed.signed_access_reload_interval,
                    })
                    .await
                    .map_err(TlsLoadError::SignedAccessReload)?;
                (key_ring, Some(runtime))
            }
            None => {
                let bytes = read_signed_access_key_ring(path).await?;
                let key_ring = load_signed_access_key_ring(&bytes)
                    .map_err(|_| TlsLoadError::InvalidSignedAccessKeyRing)?;
                (key_ring, None)
            }
        };
        (
            Some(SignedAccessIngressConfig {
                key_ring,
                maximum_ttl: parsed.signed_access_maximum_ttl,
                clock_skew: parsed.signed_access_clock_skew,
            }),
            reloader,
        )
    } else {
        (None, None)
    };
    let protocols = if parsed.enable_http2 {
        PublicHttpProtocolPolicy::Http1AndHttp2
    } else {
        PublicHttpProtocolPolicy::Http1Only
    };
    let (tls, reloader) = match &parsed.public_tls_reload_manifest {
        Some(manifest_path) => {
            let (tls, runtime) = PublicTlsReloadRuntime::bootstrap_with_protocols(
                PublicTlsReloadConfig {
                    manifest_path: manifest_path.clone(),
                    server_certificate_path: certificate_path,
                    server_private_key_path: private_key_path,
                    poll_interval: parsed.tls_reload_interval,
                    expiry_warning: parsed.tls_expiry_warning,
                },
                parsed.tls_handshake_timeout,
                protocols,
            )
            .await
            .map_err(TlsLoadError::PublicReload)?;
            (tls, Some(runtime))
        }
        None => {
            let certificate = read_tls_file(&certificate_path, "public server certificate").await?;
            let private_key = read_tls_file(&private_key_path, "public server private key").await?;
            let tls = PublicTlsConfig::from_pem_with_protocols(
                &certificate,
                &private_key,
                parsed.tls_handshake_timeout,
                protocols,
            )
            .map_err(TlsLoadError::InvalidPublicTls)?;
            (tls, None)
        }
    };
    let config = HttpIngressConfig {
        listen_addr,
        routes: match parsed.https_host.clone() {
            Some(hostname) => HttpHostRoutes::single(hostname, parsed.tunnel_id.clone()),
            None => HttpHostRoutes::dynamic_unavailable(),
        },
        tls,
        exposure,
        max_concurrent_connections: parsed.max_http_connections,
        max_header_bytes: parsed.max_http_header_bytes,
        max_headers: parsed.max_http_headers,
        max_request_body_bytes: parsed.max_http_request_body_bytes,
        max_requests_per_connection: parsed.max_http_requests_per_connection,
        http2: parsed.enable_http2.then_some(Http2IngressConfig {
            max_concurrent_streams: parsed.max_http2_concurrent_streams,
            keep_alive_interval: parsed.http2_keep_alive_interval,
            keep_alive_timeout: parsed.http2_keep_alive_timeout,
        }),
        websocket: (parsed.enable_websocket_upgrade || parsed.enable_http2_websocket).then_some(
            WebSocketIngressConfig {
                enable_http1: parsed.enable_websocket_upgrade,
                enable_http2: parsed.enable_http2_websocket,
                max_concurrent_sessions: parsed.max_websocket_sessions,
                idle_timeout: parsed.websocket_idle_timeout,
            },
        ),
        connect: (parsed.enable_connect || parsed.enable_http2_connect).then_some(
            ConnectIngressConfig {
                enable_http1: parsed.enable_connect,
                enable_http2: parsed.enable_http2_connect,
                max_concurrent_sessions: parsed.max_connect_sessions,
                idle_timeout: parsed.connect_idle_timeout,
                authority_port: parsed.connect_authority_port,
            },
        ),
        signed_access,
        request_rate_limit,
        header_read_timeout: parsed.http_header_timeout,
        request_timeout: parsed.http_request_timeout,
        duplex_capacity: 64 * 1024,
        shutdown: RuntimeShutdownConfig::new(parsed.drain_timeout),
    };
    config
        .validate()
        .map_err(TlsLoadError::InvalidHttpIngress)?;
    Ok((Some(config), reloader, signed_access_reloader))
}

async fn load_https_route_configuration(
    parsed: &ParsedArgs,
) -> Result<
    (
        Option<HttpsRouteClientConfig>,
        Option<HttpsRouteClientTlsReloadRuntime>,
    ),
    TlsLoadError,
> {
    let Some(server) = parsed.https_route_server else {
        return Ok((None, None));
    };
    let (Some(ca), Some(client_cert), Some(client_key), Some(server_name)) = (
        parsed.snapshot_ca.as_ref(),
        parsed.snapshot_client_cert.as_ref(),
        parsed.snapshot_client_key.as_ref(),
        parsed.snapshot_server_name.as_deref(),
    ) else {
        return Err(TlsLoadError::IncompleteSnapshotArguments);
    };
    let max_stale_age = parsed
        .https_route_max_stale
        .unwrap_or(Duration::from_secs(5 * 60));
    if let Some(manifest_path) = &parsed.https_route_tls_reload_manifest {
        let (config, runtime) = HttpsRouteClientTlsReloadRuntime::bootstrap(
            server,
            server_name,
            HttpsRouteClientTlsReloadConfig {
                manifest_path: manifest_path.clone(),
                server_ca_path: ca.clone(),
                client_certificate_path: client_cert.clone(),
                client_private_key_path: client_key.clone(),
                poll_interval: parsed.tls_reload_interval,
                expiry_warning: parsed.tls_expiry_warning,
                max_stale_age,
            },
        )
        .await
        .map_err(TlsLoadError::HttpsRouteReload)?;
        return Ok((Some(config), Some(runtime)));
    }
    let (ca, client_cert, client_key) = tokio::try_join!(
        read_tls_file(ca, "HTTPS route Control Plane CA"),
        read_tls_file(client_cert, "HTTPS route Edge client certificate"),
        read_tls_file(client_key, "HTTPS route Edge client private key"),
    )?;
    let config = HttpsRouteClientConfig::from_pem(
        server,
        &ca,
        &client_cert,
        &client_key,
        server_name,
        max_stale_age,
    )
    .map_err(TlsLoadError::InvalidHttpsRouteTls)?;
    config
        .validate()
        .map_err(|_| TlsLoadError::InvalidHttpsRouteConfig)?;
    Ok((Some(config), None))
}

async fn read_tls_file(path: &PathBuf, kind: &'static str) -> Result<Vec<u8>, TlsLoadError> {
    tokio::fs::read(path)
        .await
        .map_err(|_| TlsLoadError::Read(kind))
}

async fn read_signed_access_key_ring(path: &PathBuf) -> Result<Vec<u8>, TlsLoadError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| TlsLoadError::ReadSignedAccessKeyRing)?;
    let mut bytes = Vec::new();
    file.take((MAX_SIGNED_ACCESS_KEY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| TlsLoadError::ReadSignedAccessKeyRing)?;
    if bytes.len() > MAX_SIGNED_ACCESS_KEY_FILE_BYTES {
        return Err(TlsLoadError::InvalidSignedAccessKeyRing);
    }
    Ok(bytes)
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
    fn all_flags_parse() {
        let parsed = parse_args(&args(&[
            "--agent-listen",
            "127.0.0.1:17100",
            "--raw-listen",
            "127.0.0.1:17000",
            "--agent-id",
            "agent-prod",
            "--tunnel-id",
            "tunnel-prod",
            "--max-streams",
            "8",
            "--max-agent-sessions",
            "3",
            "--max-raw-connections",
            "9",
            "--allow-public-raw-ingress",
            "--max-raw-connections-per-ip",
            "3",
            "--ops-listen",
            "127.0.0.1:19090",
            "--max-ops-connections",
            "6",
            "--ops-header-timeout-ms",
            "108",
            "--ops-request-timeout-ms",
            "109",
            "--drain-timeout-ms",
            "250",
            "--tls-cert",
            "edge.pem",
            "--tls-key",
            "edge-key.pem",
            "--tls-client-ca",
            "ca.pem",
            "--authorized-client-cert",
            "agent.pem",
            "--tls-handshake-timeout-ms",
            "350",
            "--tls-reload-manifest",
            "edge-tls.json",
            "--snapshot-server",
            "127.0.0.1:17200",
            "--snapshot-ca",
            "control-ca.pem",
            "--snapshot-client-cert",
            "edge-client.pem",
            "--snapshot-client-key",
            "edge-client-key.pem",
            "--snapshot-server-name",
            "control-plane.test",
            "--snapshot-connect-timeout-ms",
            "101",
            "--snapshot-handshake-timeout-ms",
            "102",
            "--snapshot-subscribe-timeout-ms",
            "103",
            "--snapshot-reconnect-initial-ms",
            "104",
            "--snapshot-reconnect-max-ms",
            "105",
            "--snapshot-cache-dir",
            "edge-cache",
            "--snapshot-cache-max-stale-ms",
            "60000",
            "--snapshot-tls-reload-manifest",
            "snapshot-client-tls.json",
            "--tls-reload-interval-ms",
            "106",
            "--tls-expiry-warning-ms",
            "107",
        ]))
        .unwrap();
        assert_eq!(parsed.agent_listen.port(), 17100);
        assert_eq!(parsed.raw_listen.port(), 17000);
        assert_eq!(parsed.agent_id.as_str(), "agent-prod");
        assert_eq!(parsed.tunnel_id.as_str(), "tunnel-prod");
        assert_eq!(parsed.max_streams, 8);
        assert_eq!(parsed.max_agent_sessions, 3);
        assert_eq!(parsed.max_raw_connections, 9);
        assert!(parsed.allow_public_raw_ingress);
        assert_eq!(parsed.max_raw_connections_per_ip, Some(3));
        assert_eq!(parsed.ops_listen.unwrap().port(), 19090);
        assert_eq!(parsed.max_ops_connections, 6);
        assert_eq!(parsed.ops_header_timeout, Duration::from_millis(108));
        assert_eq!(parsed.ops_request_timeout, Duration::from_millis(109));
        assert_eq!(parsed.drain_timeout, Duration::from_millis(250));
        assert_eq!(parsed.tls_cert, Some(PathBuf::from("edge.pem")));
        assert_eq!(parsed.tls_key, Some(PathBuf::from("edge-key.pem")));
        assert_eq!(parsed.tls_client_ca, Some(PathBuf::from("ca.pem")));
        assert_eq!(
            parsed.authorized_client_cert,
            Some(PathBuf::from("agent.pem"))
        );
        assert_eq!(parsed.tls_handshake_timeout, Duration::from_millis(350));
        assert_eq!(
            parsed.tls_reload_manifest,
            Some(PathBuf::from("edge-tls.json"))
        );
        assert_eq!(parsed.snapshot_server.unwrap().port(), 17200);
        assert_eq!(parsed.snapshot_ca, Some(PathBuf::from("control-ca.pem")));
        assert_eq!(
            parsed.snapshot_server_name.as_deref(),
            Some("control-plane.test")
        );
        assert_eq!(parsed.snapshot_connect_timeout, Duration::from_millis(101));
        assert_eq!(parsed.snapshot_reconnect_max, Duration::from_millis(105));
        assert_eq!(parsed.snapshot_cache_dir, Some(PathBuf::from("edge-cache")));
        assert_eq!(
            parsed.snapshot_cache_max_stale,
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parsed.snapshot_tls_reload_manifest,
            Some(PathBuf::from("snapshot-client-tls.json"))
        );
        assert_eq!(parsed.tls_reload_interval, Duration::from_millis(106));
        assert_eq!(parsed.tls_expiry_warning, Duration::from_millis(107));
        assert!(parsed.snapshot_options_present);
    }

    #[test]
    fn invalid_and_missing_values_are_typed() {
        assert!(matches!(
            parse_args(&args(&["--raw-listen", "bad"])),
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
            parse_args(&args(&["--tunnel-id", "bad/id"])),
            Err(ArgError::InvalidIdentifier { .. })
        ));
        assert_eq!(
            parse_args(&args(&["--max-ops-connections", "2"])),
            Err(ArgError::OperationsOptionsWithoutListener)
        );
    }

    #[test]
    fn public_raw_cli_policy_is_explicit_and_complete() {
        let non_loopback = parse_args(&args(&["--raw-listen", "0.0.0.0:7000"])).unwrap();
        assert_eq!(
            raw_exposure_policy(&non_loopback),
            Err(ArgError::PublicRawOptInRequired)
        );

        let per_ip_without_opt_in =
            parse_args(&args(&["--max-raw-connections-per-ip", "2"])).unwrap();
        assert_eq!(
            raw_exposure_policy(&per_ip_without_opt_in),
            Err(ArgError::PublicRawPerIpLimitWithoutOptIn)
        );

        let missing_per_ip = parse_args(&args(&["--allow-public-raw-ingress"])).unwrap();
        assert_eq!(
            raw_exposure_policy(&missing_per_ip),
            Err(ArgError::PublicRawPerIpLimitRequired)
        );

        let invalid_per_ip = parse_args(&args(&[
            "--max-raw-connections",
            "1",
            "--allow-public-raw-ingress",
            "--max-raw-connections-per-ip",
            "2",
        ]))
        .unwrap();
        assert_eq!(
            raw_exposure_policy(&invalid_per_ip),
            Err(ArgError::PublicRawPerIpLimitInvalid)
        );

        let public = parse_args(&args(&[
            "--raw-listen",
            "0.0.0.0:7000",
            "--allow-public-raw-ingress",
            "--max-raw-connections-per-ip",
            "2",
        ]))
        .unwrap();
        assert_eq!(
            raw_exposure_policy(&public),
            Ok(RawIngressExposurePolicy::Public {
                max_connections_per_ip: 2
            })
        );
    }

    #[test]
    fn public_https_cli_policy_is_exact_complete_and_mutually_exclusive() {
        let parsed = parse_args(&args(&[
            "--https-listen",
            "0.0.0.0:443",
            "--https-host",
            "Demo.Example.Test.",
            "--public-tls-cert",
            "public.pem",
            "--public-tls-key",
            "public-key.pem",
            "--public-tls-reload-manifest",
            "public-tls.json",
            "--allow-public-https-ingress",
            "--max-http-connections",
            "20",
            "--max-http-connections-per-ip",
            "4",
            "--max-http-header-bytes",
            "32768",
            "--max-http-headers",
            "40",
            "--max-http-request-body-bytes",
            "2048",
            "--max-http-requests-per-connection",
            "3",
            "--enable-http2",
            "--max-http2-concurrent-streams",
            "12",
            "--http2-keepalive-interval-ms",
            "4000",
            "--http2-keepalive-timeout-ms",
            "1000",
            "--enable-websocket-upgrade",
            "--enable-http2-websocket",
            "--max-websocket-sessions",
            "8",
            "--websocket-idle-timeout-ms",
            "2500",
            "--enable-connect",
            "--enable-http2-connect",
            "--max-connect-sessions",
            "7",
            "--connect-idle-timeout-ms",
            "2600",
            "--connect-authority-port",
            "8443",
            "--http-requests-per-second",
            "50",
            "--http-request-burst",
            "100",
            "--http-requests-per-ip-per-second",
            "10",
            "--http-request-burst-per-ip",
            "20",
            "--max-http-rate-limit-peers",
            "512",
            "--http-rate-limit-idle-ms",
            "1500",
            "--http-header-timeout-ms",
            "301",
            "--http-request-timeout-ms",
            "302",
        ]))
        .unwrap();
        assert_eq!(parsed.https_listen.unwrap().port(), 443);
        assert_eq!(
            parsed.https_host.as_ref().unwrap().as_str(),
            "demo.example.test"
        );
        assert_eq!(parsed.max_http_connections, 20);
        assert_eq!(parsed.max_http_connections_per_ip, Some(4));
        assert_eq!(parsed.max_http_header_bytes, 32768);
        assert_eq!(parsed.max_http_headers, 40);
        assert_eq!(parsed.max_http_request_body_bytes, 2048);
        assert_eq!(parsed.max_http_requests_per_connection, 3);
        assert!(parsed.enable_http2);
        assert_eq!(parsed.max_http2_concurrent_streams, 12);
        assert_eq!(parsed.http2_keep_alive_interval, Duration::from_secs(4));
        assert_eq!(parsed.http2_keep_alive_timeout, Duration::from_secs(1));
        assert!(parsed.enable_websocket_upgrade);
        assert!(parsed.enable_http2_websocket);
        assert_eq!(parsed.max_websocket_sessions, 8);
        assert_eq!(parsed.websocket_idle_timeout, Duration::from_millis(2500));
        assert!(parsed.enable_connect);
        assert!(parsed.enable_http2_connect);
        assert_eq!(parsed.max_connect_sessions, 7);
        assert_eq!(parsed.connect_idle_timeout, Duration::from_millis(2600));
        assert_eq!(parsed.connect_authority_port, 8443);
        assert_eq!(parsed.http_requests_per_second, 50);
        assert_eq!(parsed.http_request_burst, 100);
        assert_eq!(parsed.http_requests_per_ip_per_second, 10);
        assert_eq!(parsed.http_request_burst_per_ip, 20);
        assert_eq!(parsed.max_http_rate_limit_peers, 512);
        assert_eq!(parsed.http_rate_limit_idle, Duration::from_millis(1500));
        assert_eq!(
            https_exposure_policy(&parsed),
            Ok(HttpIngressExposurePolicy::Public {
                max_connections_per_ip: 4
            })
        );

        let implicit = parse_args(&args(&["--https-listen", "0.0.0.0:443"])).unwrap();
        assert_eq!(
            https_exposure_policy(&implicit),
            Err(ArgError::PublicHttpsOptInRequired)
        );
        let conflicting = parse_args(&args(&[
            "--https-listen",
            "127.0.0.1:8443",
            "--raw-listen",
            "127.0.0.1:7000",
        ]))
        .unwrap();
        assert_eq!(
            raw_exposure_policy(&conflicting),
            Err(ArgError::IngressModeConflict)
        );
        assert!(matches!(
            parse_args(&args(&["--https-host", "bad_host"])),
            Err(ArgError::InvalidHostname(_))
        ));
        assert_eq!(
            parse_args(&args(&["--max-http2-concurrent-streams", "2"])),
            Err(ArgError::Http2OptionsWithoutOptIn)
        );
        assert_eq!(
            parse_args(&args(&["--max-websocket-sessions", "2"])),
            Err(ArgError::WebSocketOptionsWithoutOptIn)
        );
        assert_eq!(
            parse_args(&args(&["--max-connect-sessions", "2"])),
            Err(ArgError::ConnectOptionsWithoutOptIn)
        );
        assert_eq!(
            parse_args(&args(&["--enable-http2-connect"])),
            Err(ArgError::Http2ConnectWithoutHttp2)
        );
        assert_eq!(
            parse_args(&args(&["--enable-http2-websocket"])),
            Err(ArgError::Http2WebSocketWithoutHttp2)
        );
        let http2_websocket = parse_args(&args(&[
            "--enable-http2",
            "--enable-http2-websocket",
            "--max-websocket-sessions",
            "2",
        ]))
        .unwrap();
        assert!(http2_websocket.enable_http2_websocket);
        assert!(!http2_websocket.enable_websocket_upgrade);
        assert_eq!(http2_websocket.max_websocket_sessions, 2);
        let http2_connect = parse_args(&args(&[
            "--enable-http2",
            "--enable-http2-connect",
            "--max-connect-sessions",
            "2",
        ]))
        .unwrap();
        assert!(http2_connect.enable_http2_connect);
        assert!(!http2_connect.enable_connect);
        assert_eq!(http2_connect.max_connect_sessions, 2);
    }

    #[test]
    fn dynamic_https_route_flags_are_bounded_and_exclusive() {
        let parsed = parse_args(&args(&[
            "--https-listen",
            "127.0.0.1:8443",
            "--https-route-server",
            "127.0.0.1:17201",
            "--https-route-max-stale-ms",
            "45000",
            "--https-route-tls-reload-manifest",
            "route-client-tls.json",
            "--public-tls-cert",
            "public.pem",
            "--public-tls-key",
            "public-key.pem",
        ]))
        .unwrap();
        assert_eq!(parsed.https_route_server.unwrap().port(), 17201);
        assert_eq!(parsed.https_route_max_stale, Some(Duration::from_secs(45)));
        assert_eq!(
            parsed.https_route_tls_reload_manifest,
            Some(PathBuf::from("route-client-tls.json"))
        );
        assert!(matches!(
            parse_args(&args(&[
                "--https-host",
                "demo.example.test",
                "--https-route-server",
                "127.0.0.1:17201",
            ])),
            Err(ArgError::HttpsRouteHostConflict)
        ));
        assert_eq!(
            parse_args(&args(&["--https-route-max-stale-ms", "1000"])),
            Err(ArgError::HttpsRouteStaleWithoutServer)
        );
        assert_eq!(
            parse_args(&args(&[
                "--https-route-tls-reload-manifest",
                "route-client-tls.json",
            ])),
            Err(ArgError::HttpsRouteReloadWithoutServer)
        );
    }

    #[tokio::test]
    async fn partial_tls_arguments_are_rejected() {
        let parsed = ParsedArgs {
            tls_cert: Some(PathBuf::from("edge.pem")),
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_configuration(&parsed).await,
            Err(TlsLoadError::IncompleteArguments)
        ));

        let partial_snapshot = ParsedArgs {
            tls_cert: Some(PathBuf::from("edge.pem")),
            tls_key: Some(PathBuf::from("edge-key.pem")),
            tls_client_ca: Some(PathBuf::from("agent-ca.pem")),
            snapshot_server: Some("127.0.0.1:7200".parse().unwrap()),
            snapshot_options_present: true,
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_transport_configuration(&partial_snapshot).await,
            Err(TlsLoadError::IncompleteSnapshotArguments)
        ));

        let conflicting = ParsedArgs {
            authorized_client_cert: Some(PathBuf::from("agent.pem")),
            ..partial_snapshot
        };
        assert!(matches!(
            load_transport_configuration(&conflicting).await,
            Err(TlsLoadError::AuthorizationMode)
        ));

        let partial_cache = ParsedArgs {
            tls_cert: Some(PathBuf::from("edge.pem")),
            tls_key: Some(PathBuf::from("edge-key.pem")),
            tls_client_ca: Some(PathBuf::from("agent-ca.pem")),
            snapshot_server: Some("127.0.0.1:7200".parse().unwrap()),
            snapshot_ca: Some(PathBuf::from("control-ca.pem")),
            snapshot_client_cert: Some(PathBuf::from("edge-client.pem")),
            snapshot_client_key: Some(PathBuf::from("edge-client-key.pem")),
            snapshot_server_name: Some("control-plane.test".to_owned()),
            snapshot_cache_dir: Some(PathBuf::from("edge-cache")),
            snapshot_options_present: true,
            ..ParsedArgs::default()
        };
        assert!(matches!(
            snapshot_cache_configuration(&partial_cache),
            Err(TlsLoadError::IncompleteSnapshotCacheArguments)
        ));

        let partial_https = ParsedArgs {
            https_listen: Some("127.0.0.1:8443".parse().unwrap()),
            https_host: Some(HttpHostname::new("demo.example.test").unwrap()),
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_https_configuration(&partial_https).await,
            Err(TlsLoadError::IncompletePublicHttpsArguments)
        ));

        let orphaned_https_option = parse_args(&args(&["--max-http-connections", "8"]))
            .expect("the option value itself is valid");
        assert!(matches!(
            load_https_configuration(&orphaned_https_option).await,
            Err(TlsLoadError::PublicHttpsWithoutListener)
        ));

        let invalid_rate_limit = ParsedArgs {
            https_listen: Some("127.0.0.1:8443".parse().unwrap()),
            https_host: Some(HttpHostname::new("demo.example.test").unwrap()),
            public_tls_cert: Some(PathBuf::from("public.pem")),
            public_tls_key: Some(PathBuf::from("public-key.pem")),
            http_requests_per_second: 0,
            ..ParsedArgs::default()
        };
        assert!(matches!(
            load_https_configuration(&invalid_rate_limit).await,
            Err(TlsLoadError::InvalidHttpIngress(
                tunnelproxy_edge::HttpIngressConfigError::InvalidRequestRateLimit(_)
            ))
        ));
    }

    #[test]
    fn signed_access_cli_is_explicit_bounded_and_connect_incompatible() {
        let parsed = parse_args(&args(&[
            "--require-signed-access",
            "--signed-access-keyring",
            "public-ring.json",
            "--signed-access-keyring-reload-manifest",
            "signed-access-generation.json",
            "--signed-access-reload-interval-ms",
            "250",
            "--signed-access-max-ttl-seconds",
            "300",
            "--signed-access-clock-skew-seconds",
            "15",
        ]))
        .unwrap();
        assert!(parsed.require_signed_access);
        assert_eq!(
            parsed.signed_access_keyring,
            Some(PathBuf::from("public-ring.json"))
        );
        assert_eq!(parsed.signed_access_maximum_ttl, Duration::from_secs(300));
        assert_eq!(parsed.signed_access_clock_skew, Duration::from_secs(15));
        assert_eq!(
            parsed.signed_access_keyring_reload_manifest,
            Some(PathBuf::from("signed-access-generation.json"))
        );
        assert_eq!(
            parsed.signed_access_reload_interval,
            Duration::from_millis(250)
        );
        assert_eq!(
            parse_args(&args(&["--signed-access-keyring", "public-ring.json"])),
            Err(ArgError::SignedAccessOptionsWithoutOptIn)
        );
        assert_eq!(
            parse_args(&args(&["--require-signed-access", "--enable-connect"])),
            Err(ArgError::SignedAccessConnectConflict)
        );
        assert_eq!(
            parse_args(&args(&[
                "--require-signed-access",
                "--signed-access-keyring",
                "public-ring.json",
                "--signed-access-reload-interval-ms",
                "250",
            ])),
            Err(ArgError::SignedAccessReloadWithoutManifest)
        );
    }
}
