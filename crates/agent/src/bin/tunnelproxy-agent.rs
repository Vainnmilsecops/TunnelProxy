//! Runnable outbound Agent process with graceful OS shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info};
use tunnelproxy_agent::{
    bootstrap_agent_credentials, AgentEnrollmentConfig, AgentEnrollmentError,
    AgentEnrollmentRuntime, AgentHostnameClient, AgentHostnameError, AgentOperationsConfig,
    AgentOperationsError, AgentOperationsOutcome, AgentOperationsRuntime, AgentRuntime,
    AgentRuntimeConfig, AgentRuntimeOutcome, AgentTlsConfig, AgentTlsConfigError,
    AgentTlsReloadBootstrapError, AgentTlsReloadConfig, AgentTlsReloadRuntime,
    AgentTransportSecurity, EnrollmentClientConfig, HostnameClientConfig, RuntimeShutdownConfig,
};
use tunnelproxy_common::{
    init_process_logging, shutdown_channel, wait_for_process_shutdown, AgentCredentialPaths,
    AgentId, ProcessLogFormat, PublicHostname, ShutdownSignal, TunnelId,
};
use tunnelproxy_protocol::RegistrationRequest;

const USAGE: &str = "\
Usage:
  tunnelproxy-agent [OPTIONS]
  tunnelproxy-agent http <port> [OPTIONS]
  tunnelproxy-agent hostname-allocate [OPTIONS]
  tunnelproxy-agent hostname-release [OPTIONS]

Options:
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
  --hostname-server <addr>          Control Plane hostname address (required)
  --hostname-ca <path>              trusted hostname server CA PEM (required)
  --hostname-server-name <name>     verified hostname service DNS name (required)
  --hostname-request-timeout-ms <ms> allocation deadline (default 5000)
  Uses the common Edge, Agent identity, TLS, reconnect, enrollment, and
  operations options above. The managed hostname remains allocated on exit.
  --help                         print this help and exit
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
    if matches!(
        args.first().map(String::as_str),
        Some("hostname-allocate" | "hostname-release")
    ) {
        if matches!(args.get(1).map(String::as_str), Some("--help" | "-h")) {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        return match run_hostname_command(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let configuration_error = error.is_configuration_error();
                error!(%error, "Agent hostname command failed");
                if configuration_error {
                    print_usage_for_error(log_format);
                    ExitCode::from(2)
                } else {
                    ExitCode::from(1)
                }
            }
        };
    }
    if matches!(
        (
            args.first().map(String::as_str),
            args.get(1).map(String::as_str)
        ),
        (Some("http"), Some("--help" | "-h"))
    ) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let (mode, parsed) = match parse_run_command(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            error!(%error, "invalid Agent CLI arguments");
            print_usage_for_error(log_format);
            return ExitCode::from(2);
        }
    };
    if parsed.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
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
    let operations = match parsed.ops_listen {
        Some(listen_addr) => {
            let mut config = AgentOperationsConfig::loopback(listen_addr);
            config.max_concurrent_connections = parsed.max_ops_connections;
            config.header_read_timeout = parsed.ops_header_timeout;
            config.request_timeout = parsed.ops_request_timeout;
            config.shutdown = RuntimeShutdownConfig::new(parsed.drain_timeout);
            match AgentOperationsRuntime::bind(config, runtime_status.clone()).await {
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
                        print_usage_for_error(log_format);
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
            Some(ManagedHttpAnnouncement {
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
    let ready_task = managed_http.map(|announcement| {
        tokio::spawn(announce_managed_http_ready(
            announcement,
            runtime_status,
            signal.clone(),
        ))
    });
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
    return tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            join_ready_task(ready_task).await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let operations = operations_future.await;
            combine_exit_codes(agent_exit_code(result), operations)
        },
        reload = &mut reload_future => {
            runtime_control.begin_draining();
            trigger.shutdown();
            join_ready_task(ready_task).await;
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
            join_ready_task(ready_task).await;
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
            join_ready_task(ready_task).await;
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
                    join_ready_task(ready_task).await;
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
            join_ready_task(ready_task).await;
            let result = runtime_future.await;
            let _ = reload_future.await;
            let _ = enrollment_future.await;
            operations_trigger.shutdown();
            let operations = operations_future.await;
            combine_exit_codes(agent_exit_code(result), operations)
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Tunnel,
    Http,
}

#[derive(Debug)]
struct ManagedHttpAnnouncement {
    hostname: PublicHostname,
    local: SocketAddr,
}

impl ManagedHttpAnnouncement {
    fn mapping(&self) -> String {
        format!("https://{} -> http://{}", self.hostname, self.local)
    }
}

async fn announce_managed_http_ready(
    announcement: ManagedHttpAnnouncement,
    status: tunnelproxy_agent::AgentRuntimeStatusHandle,
    signal: ShutdownSignal,
) {
    let mut poll = tokio::time::interval(Duration::from_millis(10));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = signal.cancelled() => return,
            _ = poll.tick() => {
                if status.snapshot().is_ready() {
                    println!("{}", announcement.mapping());
                    info!(
                        hostname = %announcement.hostname,
                        local = %announcement.local,
                        event = "managed_http_ready",
                        "Managed HTTP tunnel is ready"
                    );
                    return;
                }
            }
        }
    }
}

async fn join_ready_task(task: Option<tokio::task::JoinHandle<()>>) {
    if let Some(task) = task {
        if let Err(error) = task.await {
            error!(%error, "managed HTTP readiness task failed");
        }
    }
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

fn print_usage_for_error(log_format: ProcessLogFormat) {
    if log_format == ProcessLogFormat::Text {
        eprintln!("{USAGE}");
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

fn agent_exit_code(
    result: Result<AgentRuntimeOutcome, tunnelproxy_agent::AgentRuntimeError>,
) -> ExitCode {
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

#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    edge: SocketAddr,
    local: SocketAddr,
    local_explicit: bool,
    agent_id: AgentId,
    tunnel_id: TunnelId,
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
    tls_client_cert: Option<PathBuf>,
    tls_client_key: Option<PathBuf>,
    tls_server_name: Option<String>,
    tls_handshake_timeout: Duration,
    tls_reload_manifest: Option<PathBuf>,
    tls_reload_interval: Duration,
    tls_expiry_warning: Duration,
    tls_reload_options_present: bool,
    hostname_server: Option<SocketAddr>,
    hostname_ca: Option<PathBuf>,
    hostname_server_name: Option<String>,
    hostname_request_timeout: Duration,
    hostname_options_present: bool,
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
            edge: "127.0.0.1:7100".parse().unwrap(),
            local: "127.0.0.1:3000".parse().unwrap(),
            local_explicit: false,
            agent_id: AgentId::new("agent-dev").unwrap(),
            tunnel_id: TunnelId::new("tunnel-dev").unwrap(),
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
            tls_client_cert: None,
            tls_client_key: None,
            tls_server_name: None,
            tls_handshake_timeout: Duration::from_secs(10),
            tls_reload_manifest: None,
            tls_reload_interval: Duration::from_secs(1),
            tls_expiry_warning: Duration::from_secs(7 * 24 * 60 * 60),
            tls_reload_options_present: false,
            hostname_server: None,
            hostname_ca: None,
            hostname_server_name: None,
            hostname_request_timeout: Duration::from_secs(5),
            hostname_options_present: false,
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
    IncompleteHostnameOptions,
    HostnameOptionsRequireHttp,
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
            Self::IncompleteHostnameOptions => f.write_str(
                "http <port> requires --hostname-server, --hostname-ca, and --hostname-server-name",
            ),
            Self::HostnameOptionsRequireHttp => {
                f.write_str("managed HTTP hostname options require the http <port> command")
            }
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

fn parse_run_command(args: &[String]) -> Result<(RunMode, ParsedArgs), ArgError> {
    if args.first().map(String::as_str) != Some("http") {
        let parsed = parse_args(args)?;
        if parsed.hostname_options_present {
            return Err(ArgError::HostnameOptionsRequireHttp);
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
    parsed.local = SocketAddr::from(([127, 0, 0, 1], port));
    Ok((RunMode::Http, parsed))
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
            "--edge" => {
                parsed.edge = parse_addr(args, index, flag)?;
                index += 2;
            }
            "--local" => {
                parsed.local = parse_addr(args, index, flag)?;
                parsed.local_explicit = true;
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
                index += 2;
            }
            "--tls-client-cert" => {
                parsed.tls_client_cert = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-client-key" => {
                parsed.tls_client_key = Some(PathBuf::from(value(args, index, flag)?));
                index += 2;
            }
            "--tls-server-name" => {
                parsed.tls_server_name = Some(value(args, index, flag)?.to_string());
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
                parsed.hostname_options_present = true;
                index += 2;
            }
            "--hostname-ca" => {
                parsed.hostname_ca = Some(PathBuf::from(value(args, index, flag)?));
                parsed.hostname_options_present = true;
                index += 2;
            }
            "--hostname-server-name" => {
                parsed.hostname_server_name = Some(value(args, index, flag)?.to_owned());
                parsed.hostname_options_present = true;
                index += 2;
            }
            "--hostname-request-timeout-ms" => {
                parsed.hostname_request_timeout =
                    Duration::from_millis(parse_number(args, index, flag)?);
                parsed.hostname_options_present = true;
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
        assert_eq!(
            ManagedHttpAnnouncement {
                hostname: PublicHostname::new("tp-0123456789abcdef0123456789abcdef.test").unwrap(),
                local: parsed.local,
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
        assert!(matches!(
            parse_run_command(&args(&["http", "3000"])),
            Err(ArgError::HttpRequiresMutualTls)
        ));
        assert!(matches!(
            parse_run_command(&args(&[
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
            ])),
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
