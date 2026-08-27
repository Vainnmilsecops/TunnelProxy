//! Runnable authorization snapshot import and distribution process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tracing::{error, info};
use tunnelproxy_common::{
    init_process_logging, shutdown_channel, wait_for_process_shutdown, AgentId, ProcessLogFormat,
    PublicHostname, TunnelId,
};
use tunnelproxy_control_plane::{
    parse_snapshot_manifest, provision_bootstrap_token, unix_time_now, AgentCertificateIssuer,
    ControlPlaneOperationsConfig, ControlPlaneRuntime, ControlPlaneRuntimeConfig,
    EnrollmentRepository, EnrollmentServerConfig, EnrollmentServerTlsConfig,
    HttpsRouteMutationOutcome, HttpsRouteRecord, HttpsRouteRepository, HttpsRouteServerConfig,
    HttpsRouteServerTlsConfig, HttpsRouteStatus, SnapshotCommitOutcome, SnapshotRepository,
    SnapshotServerConfig, SnapshotServerTlsConfig, SnapshotServerTlsReloadConfig,
    SnapshotServerTlsReloadRuntime, SnapshotTlsConfigError, SnapshotTlsReloadBootstrapError,
    SqliteSnapshotRepository, MAX_SNAPSHOT_BYTES,
};

const USAGE: &str = "\
Usage:
  tunnelproxy-control-plane serve [OPTIONS]
  tunnelproxy-control-plane import [OPTIONS]
  tunnelproxy-control-plane create-token [OPTIONS]
  tunnelproxy-control-plane revoke-agent [OPTIONS]
  tunnelproxy-control-plane credential-status [OPTIONS]
  tunnelproxy-control-plane https-route-upsert [OPTIONS]
  tunnelproxy-control-plane https-route-remove [OPTIONS]
  tunnelproxy-control-plane https-route-list [OPTIONS]

Serve options:
  --database <path>                  SQLite snapshot database (required)
  --listen <addr>                    snapshot listener (default 127.0.0.1:7200)
  --tls-cert <path>                  Control Plane certificate PEM (required)
  --tls-key <path>                   Control Plane private key PEM (required)
  --edge-client-ca <path>            trusted Edge client CA PEM (required)
  --max-edge-clients <usize>         client limit (default 64)
  --tls-handshake-timeout-ms <ms>    TLS timeout (default 5000)
  --request-timeout-ms <ms>          protocol I/O timeout (default 5000)
  --refresh-interval-ms <ms>         SQLite refresh interval (default 500)
  --https-route-listen <addr>        opt-in HTTPS route distribution listener
  --ops-listen <addr>                opt-in loopback operations listener
  --max-ops-connections <usize>      operations connection limit (default 8)
  --ops-header-timeout-ms <ms>       operations header timeout (default 2000)
  --ops-request-timeout-ms <ms>      operations request timeout (default 5000)
  --tls-reload-manifest <path>       atomic TLS generation manifest
  --tls-reload-interval-ms <ms>      reload poll (default 1000)
  --tls-expiry-warning-ms <ms>       expiry warning (default 604800000)
  --enrollment-listen <addr>         opt-in Agent enrollment listener
  --issuer-cert <path>               Agent issuer CA certificate PEM
  --issuer-key <path>                Agent issuer CA private key PEM
  --agent-server-ca <path>           Edge server CA returned to Agents
  --agent-cert-validity-ms <ms>      issued leaf lifetime (default 86400000)
  --max-enrollment-clients <usize>   enrollment limit (default 32)
  --enrollment-request-timeout-ms <ms> request deadline (default 10000)
  --enrollment-activation-grace-ms <ms> activation grace, minimum 1000 (default 600000)
  --enrollment-reconcile-interval-ms <ms> reconciliation poll (default 30000)

Import options:
  --database <path>                  SQLite snapshot database (required)
  --snapshot <path>                  full snapshot JSON manifest (required)

Create-token options:
  --database <path>                  SQLite snapshot database (required)
  --agent-id <id>                    bound Agent ID (required)
  --tunnel-id <id>                   bound Tunnel ID (required)
  --output <path>                    secret token output file (required)
  --ttl-ms <ms>                      bootstrap token lifetime (default 600000)

Credential command options:
  --database <path>                  SQLite snapshot database (required)
  --agent-id <id>                    exact Agent ID (required)
  --tunnel-id <id>                   exact Tunnel ID (required)

HTTPS route upsert options:
  --database <path>                  SQLite state database (required)
  --hostname <name>                  exact public DNS hostname (required)
  --tunnel-id <id>                   target Tunnel ID (required)
  --status <enabled|disabled>        administrative route state (required)

HTTPS route remove/list options:
  --database <path>                  SQLite state database (required)
  --hostname <name>                  exact hostname (remove only, required)

  --help                             print this help and exit
";

#[tokio::main]
async fn main() -> ExitCode {
    let log_format = match init_process_logging() {
        Ok(format) => format,
        Err(error) => {
            eprintln!("failed to configure logging: {error}");
            return ExitCode::from(2);
        }
    };
    let args: Vec<_> = std::env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(error) => {
            error!(%error, "invalid Control Plane CLI arguments");
            print_usage_for_error(log_format);
            return ExitCode::from(2);
        }
    };
    match command {
        ParsedCommand::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        ParsedCommand::Import(args) => match run_import(args).await {
            Ok(outcome) => {
                info!(?outcome, "snapshot import completed");
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "snapshot import failed");
                error.exit_code()
            }
        },
        ParsedCommand::Serve(args) => match run_server(*args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                error!(%error, "Control Plane runtime failed");
                error.exit_code()
            }
        },
        ParsedCommand::CreateToken(args) => match run_create_token(args).await {
            Ok(()) => {
                info!("Agent enrollment bootstrap token created");
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "bootstrap token creation failed");
                ExitCode::from(1)
            }
        },
        ParsedCommand::RevokeAgent(args) => match run_revoke_agent(&args).await {
            Ok(outcome) => {
                info!(
                    agent_id = %args.agent_id,
                    tunnel_id = %args.tunnel_id,
                    affected_credentials = outcome.affected_credentials,
                    snapshot_version = outcome.snapshot_version.get(),
                    event = "credential_revoked"
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "Agent credential revocation failed");
                ExitCode::from(1)
            }
        },
        ParsedCommand::CredentialStatus(args) => match run_credential_status(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                error!(%error, "credential status query failed");
                ExitCode::from(1)
            }
        },
        ParsedCommand::HttpsRouteUpsert(args) => match run_https_route_upsert(args).await {
            Ok(outcome) => {
                print_route_mutation(outcome);
                info!(?outcome, "HTTPS route upsert completed");
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "HTTPS route upsert failed");
                ExitCode::from(1)
            }
        },
        ParsedCommand::HttpsRouteRemove(args) => match run_https_route_remove(args).await {
            Ok(outcome) => {
                print_route_mutation(outcome);
                info!(?outcome, "HTTPS route removal completed");
                ExitCode::SUCCESS
            }
            Err(error) => {
                error!(%error, "HTTPS route removal failed");
                ExitCode::from(1)
            }
        },
        ParsedCommand::HttpsRouteList(args) => match run_https_route_list(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                error!(%error, "HTTPS route listing failed");
                ExitCode::from(1)
            }
        },
    }
}

fn print_usage_for_error(log_format: ProcessLogFormat) {
    if log_format == ProcessLogFormat::Text {
        eprintln!("{USAGE}");
    }
}

async fn run_import(args: ImportArgs) -> Result<SnapshotCommitOutcome, ImportError> {
    let bytes = read_manifest(args.snapshot).await?;
    let snapshot = parse_snapshot_manifest(&bytes).map_err(ImportError::Manifest)?;
    tokio::task::spawn_blocking(move || {
        let repository =
            SqliteSnapshotRepository::open(args.database).map_err(ImportError::Repository)?;
        repository
            .commit(&snapshot)
            .map_err(ImportError::Repository)
    })
    .await
    .map_err(|_| ImportError::StorageTask)?
}

async fn read_manifest(path: PathBuf) -> Result<Vec<u8>, ImportError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| ImportError::ReadManifest)?;
    let mut limited = file.take((MAX_SNAPSHOT_BYTES + 1) as u64);
    let mut bytes = Vec::with_capacity(MAX_SNAPSHOT_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ImportError::ReadManifest)?;
    Ok(bytes)
}

async fn run_server(args: ServeArgs) -> Result<(), ServeError> {
    let (tls, reloader) = load_server_tls(&args).await?;
    let https_route_server = load_https_route_server_config(&args).await?;
    let enrollment = load_enrollment_server_config(&args).await?;
    let runtime_config = ControlPlaneRuntimeConfig {
        database_path: args.database.clone(),
        refresh_interval: args.refresh_interval,
        snapshot_server: SnapshotServerConfig {
            listen_addr: args.listen,
            max_edge_clients: args.max_edge_clients,
            request_timeout: args.request_timeout,
            tls,
        },
        https_route_server,
        operations: args.operations.map(|operations| {
            let mut config = ControlPlaneOperationsConfig::loopback(operations.listen);
            config.max_concurrent_connections = operations.max_connections;
            config.header_read_timeout = operations.header_timeout;
            config.request_timeout = operations.request_timeout;
            config
        }),
    };
    let runtime = match enrollment {
        Some(enrollment) => {
            ControlPlaneRuntime::bind_with_enrollment(runtime_config, enrollment).await
        }
        None => ControlPlaneRuntime::bind(runtime_config).await,
    }
    .map_err(ServeError::Runtime)?;
    info!(
        listen_addr = %runtime.local_addr(),
        snapshot_version = runtime.current_version().get(),
        "Control Plane snapshot service started"
    );
    if let Some(addr) = runtime.enrollment_addr() {
        info!(%addr, "Control Plane enrollment service started");
    }
    if let Some(addr) = runtime.https_route_addr() {
        info!(%addr, "Control Plane HTTPS route distribution service started");
    }
    if let Some(addr) = runtime.operations_addr() {
        info!(%addr, "Control Plane operations service started");
    }
    let (trigger, signal) = shutdown_channel();
    let runtime_future = runtime.run_until_shutdown(signal.clone());
    tokio::pin!(runtime_future);
    let reload_future = run_optional_tls_reloader(reloader, signal);
    tokio::pin!(reload_future);
    let os_signal = wait_for_process_shutdown();
    tokio::pin!(os_signal);
    let outcome = tokio::select! {
        result = &mut runtime_future => {
            trigger.shutdown();
            let _ = reload_future.await;
            result.map_err(ServeError::Runtime)?
        },
        reload = &mut reload_future => {
            trigger.shutdown();
            let _ = runtime_future.await;
            reload.map_err(ServeError::ReloadRuntime)?;
            return Ok(());
        },
        observed = &mut os_signal => {
            observed.map_err(|_| ServeError::Signal)?;
            trigger.shutdown();
            let outcome = runtime_future.await.map_err(ServeError::Runtime)?;
            let _ = reload_future.await;
            outcome
        }
    };
    info!(?outcome, "Control Plane shutdown completed");
    Ok(())
}

async fn load_https_route_server_config(
    args: &ServeArgs,
) -> Result<Option<HttpsRouteServerConfig>, ServeError> {
    let Some(listen_addr) = args.https_route_listen else {
        return Ok(None);
    };
    let (certificate, private_key, edge_client_ca) = tokio::try_join!(
        read_pem(args.tls_cert.clone(), "server certificate"),
        read_pem(args.tls_key.clone(), "server private key"),
        read_pem(args.edge_client_ca.clone(), "Edge client CA"),
    )?;
    let tls = HttpsRouteServerTlsConfig::from_pem(
        &certificate,
        &private_key,
        &edge_client_ca,
        args.tls_handshake_timeout,
    )
    .map_err(ServeError::Tls)?;
    Ok(Some(HttpsRouteServerConfig {
        listen_addr,
        max_edge_clients: args.max_edge_clients,
        request_timeout: args.request_timeout,
        tls,
    }))
}

async fn load_enrollment_server_config(
    args: &ServeArgs,
) -> Result<Option<EnrollmentServerConfig>, ServeError> {
    let Some(enrollment) = &args.enrollment else {
        return Ok(None);
    };
    let (server_certificate, server_private_key, issuer_certificate, issuer_private_key, agent_ca) =
        tokio::try_join!(
            read_pem(args.tls_cert.clone(), "enrollment server certificate"),
            read_pem(args.tls_key.clone(), "enrollment server private key"),
            read_pem(enrollment.issuer_cert.clone(), "Agent issuer certificate"),
            read_pem(enrollment.issuer_key.clone(), "Agent issuer private key"),
            read_pem(enrollment.agent_server_ca.clone(), "Agent Edge server CA"),
        )?;
    let tls = EnrollmentServerTlsConfig::from_pem(
        &server_certificate,
        &server_private_key,
        args.tls_handshake_timeout,
    )
    .map_err(ServeError::EnrollmentTls)?;
    let issuer = AgentCertificateIssuer::from_pem(
        &issuer_certificate,
        &issuer_private_key,
        enrollment.agent_cert_validity,
    )
    .map_err(ServeError::Issuer)?;
    Ok(Some(EnrollmentServerConfig {
        listen_addr: enrollment.listen,
        max_clients: enrollment.max_clients,
        request_timeout: enrollment.request_timeout,
        activation_grace: enrollment.activation_grace,
        reconcile_interval: enrollment.reconcile_interval,
        database_path: args.database.clone(),
        tls,
        issuer,
        agent_server_ca_pem: agent_ca,
    }))
}

async fn run_create_token(args: CreateTokenArgs) -> Result<(), CreateTokenError> {
    tokio::task::spawn_blocking(move || {
        provision_bootstrap_token(
            args.database,
            &args.agent_id,
            &args.tunnel_id,
            args.ttl,
            &args.output,
        )
    })
    .await
    .map_err(|_| CreateTokenError::StorageTask)?
    .map_err(CreateTokenError::Repository)
}

async fn load_server_tls(
    args: &ServeArgs,
) -> Result<
    (
        SnapshotServerTlsConfig,
        Option<SnapshotServerTlsReloadRuntime>,
    ),
    ServeError,
> {
    if let Some(manifest_path) = &args.tls_reload_manifest {
        let (tls, runtime) = SnapshotServerTlsReloadRuntime::bootstrap(
            SnapshotServerTlsReloadConfig {
                manifest_path: manifest_path.clone(),
                server_certificate_path: args.tls_cert.clone(),
                server_private_key_path: args.tls_key.clone(),
                client_ca_path: args.edge_client_ca.clone(),
                poll_interval: args.tls_reload_interval,
                expiry_warning: args.tls_expiry_warning,
            },
            args.tls_handshake_timeout,
        )
        .await
        .map_err(ServeError::ReloadBootstrap)?;
        return Ok((tls, Some(runtime)));
    }
    let (certificate, private_key, edge_client_ca) = tokio::try_join!(
        read_pem(args.tls_cert.clone(), "server certificate"),
        read_pem(args.tls_key.clone(), "server private key"),
        read_pem(args.edge_client_ca.clone(), "Edge client CA"),
    )?;
    let tls = SnapshotServerTlsConfig::from_pem(
        &certificate,
        &private_key,
        &edge_client_ca,
        args.tls_handshake_timeout,
    )
    .map_err(ServeError::Tls)?;
    Ok((tls, None))
}

async fn run_optional_tls_reloader(
    reloader: Option<SnapshotServerTlsReloadRuntime>,
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

async fn read_pem(path: PathBuf, kind: &'static str) -> Result<Vec<u8>, ServeError> {
    tokio::fs::read(path)
        .await
        .map_err(|_| ServeError::ReadPem(kind))
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedCommand {
    Help,
    Serve(Box<ServeArgs>),
    Import(ImportArgs),
    CreateToken(CreateTokenArgs),
    RevokeAgent(CredentialTargetArgs),
    CredentialStatus(CredentialTargetArgs),
    HttpsRouteUpsert(HttpsRouteUpsertArgs),
    HttpsRouteRemove(HttpsRouteRemoveArgs),
    HttpsRouteList(HttpsRouteListArgs),
}

#[derive(Debug, PartialEq, Eq)]
struct ServeArgs {
    database: PathBuf,
    listen: SocketAddr,
    https_route_listen: Option<SocketAddr>,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    edge_client_ca: PathBuf,
    max_edge_clients: usize,
    tls_handshake_timeout: Duration,
    request_timeout: Duration,
    refresh_interval: Duration,
    tls_reload_manifest: Option<PathBuf>,
    tls_reload_interval: Duration,
    tls_expiry_warning: Duration,
    enrollment: Option<EnrollmentArgs>,
    operations: Option<OperationsArgs>,
}

#[derive(Debug, PartialEq, Eq)]
struct OperationsArgs {
    listen: SocketAddr,
    max_connections: usize,
    header_timeout: Duration,
    request_timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
struct EnrollmentArgs {
    listen: SocketAddr,
    issuer_cert: PathBuf,
    issuer_key: PathBuf,
    agent_server_ca: PathBuf,
    agent_cert_validity: Duration,
    max_clients: usize,
    request_timeout: Duration,
    activation_grace: Duration,
    reconcile_interval: Duration,
}

async fn run_revoke_agent(
    args: &CredentialTargetArgs,
) -> Result<tunnelproxy_control_plane::CredentialMutationOutcome, CredentialCommandError> {
    let database = args.database.clone();
    let agent_id = args.agent_id.clone();
    let tunnel_id = args.tunnel_id.clone();
    tokio::task::spawn_blocking(move || {
        EnrollmentRepository::open(database)?.revoke_agent(&agent_id, &tunnel_id, unix_time_now()?)
    })
    .await
    .map_err(|_| CredentialCommandError::StorageTask)?
    .map_err(CredentialCommandError::Repository)
}

async fn run_credential_status(args: CredentialTargetArgs) -> Result<(), CredentialCommandError> {
    let report = tokio::task::spawn_blocking(move || {
        EnrollmentRepository::open(args.database)?
            .credential_status(&args.agent_id, &args.tunnel_id)
    })
    .await
    .map_err(|_| CredentialCommandError::StorageTask)?
    .map_err(CredentialCommandError::Repository)?;
    println!("snapshot_version={}", report.snapshot_version.get());
    for credential in report.credentials {
        println!(
            "fingerprint={} generation={} state={} not_after_unix={} activation_deadline_unix={} terminal_at_unix={}",
            credential.fingerprint,
            credential.generation.get(),
            credential.state,
            credential.not_after_unix,
            credential.activation_deadline_unix,
            credential
                .terminal_at_unix
                .map_or_else(|| "-".to_owned(), |value| value.to_string())
        );
    }
    Ok(())
}

async fn run_https_route_upsert(
    args: HttpsRouteUpsertArgs,
) -> Result<HttpsRouteMutationOutcome, HttpsRouteCommandError> {
    tokio::task::spawn_blocking(move || {
        HttpsRouteRepository::open(args.database)?.upsert(&HttpsRouteRecord::new(
            args.hostname,
            args.tunnel_id,
            args.status,
        ))
    })
    .await
    .map_err(|_| HttpsRouteCommandError::StorageTask)?
    .map_err(HttpsRouteCommandError::Repository)
}

async fn run_https_route_remove(
    args: HttpsRouteRemoveArgs,
) -> Result<HttpsRouteMutationOutcome, HttpsRouteCommandError> {
    tokio::task::spawn_blocking(move || {
        HttpsRouteRepository::open(args.database)?.remove(&args.hostname)
    })
    .await
    .map_err(|_| HttpsRouteCommandError::StorageTask)?
    .map_err(HttpsRouteCommandError::Repository)
}

async fn run_https_route_list(args: HttpsRouteListArgs) -> Result<(), HttpsRouteCommandError> {
    let catalog =
        tokio::task::spawn_blocking(move || HttpsRouteRepository::open(args.database)?.load())
            .await
            .map_err(|_| HttpsRouteCommandError::StorageTask)?
            .map_err(HttpsRouteCommandError::Repository)?;
    println!("catalog_version={}", catalog.version());
    for route in catalog.routes() {
        println!(
            "hostname={} tunnel_id={} status={}",
            route.hostname, route.tunnel_id, route.status
        );
    }
    Ok(())
}

fn print_route_mutation(outcome: HttpsRouteMutationOutcome) {
    match outcome {
        HttpsRouteMutationOutcome::Applied { current, .. } => {
            println!("catalog_version={current} changed=true");
        }
        HttpsRouteMutationOutcome::Unchanged { version } => {
            println!("catalog_version={version} changed=false");
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ImportArgs {
    database: PathBuf,
    snapshot: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
struct CreateTokenArgs {
    database: PathBuf,
    agent_id: AgentId,
    tunnel_id: TunnelId,
    output: PathBuf,
    ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialTargetArgs {
    database: PathBuf,
    agent_id: AgentId,
    tunnel_id: TunnelId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpsRouteUpsertArgs {
    database: PathBuf,
    hostname: PublicHostname,
    tunnel_id: TunnelId,
    status: HttpsRouteStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpsRouteRemoveArgs {
    database: PathBuf,
    hostname: PublicHostname,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpsRouteListArgs {
    database: PathBuf,
}

fn parse_args(args: &[String]) -> Result<ParsedCommand, ArgError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(ArgError::MissingCommand);
    };
    if matches!(command, "--help" | "-h") {
        return Ok(ParsedCommand::Help);
    }
    match command {
        "serve" => parse_serve(&args[1..]).map(|args| ParsedCommand::Serve(Box::new(args))),
        "import" => parse_import(&args[1..]).map(ParsedCommand::Import),
        "create-token" => parse_create_token(&args[1..]).map(ParsedCommand::CreateToken),
        "revoke-agent" => parse_credential_target(&args[1..]).map(ParsedCommand::RevokeAgent),
        "credential-status" => {
            parse_credential_target(&args[1..]).map(ParsedCommand::CredentialStatus)
        }
        "https-route-upsert" => {
            parse_https_route_upsert(&args[1..]).map(ParsedCommand::HttpsRouteUpsert)
        }
        "https-route-remove" => {
            parse_https_route_remove(&args[1..]).map(ParsedCommand::HttpsRouteRemove)
        }
        "https-route-list" => parse_https_route_list(&args[1..]).map(ParsedCommand::HttpsRouteList),
        other => Err(ArgError::UnknownCommand(other.to_owned())),
    }
}

fn parse_serve(args: &[String]) -> Result<ServeArgs, ArgError> {
    let mut database = None;
    let mut listen = "127.0.0.1:7200".parse().unwrap();
    let mut https_route_listen = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut edge_client_ca = None;
    let mut max_edge_clients = 64;
    let mut tls_handshake_timeout = Duration::from_secs(5);
    let mut request_timeout = Duration::from_secs(5);
    let mut refresh_interval = Duration::from_millis(500);
    let mut tls_reload_manifest = None;
    let mut tls_reload_interval = Duration::from_secs(1);
    let mut tls_expiry_warning = Duration::from_secs(7 * 24 * 60 * 60);
    let mut reload_tuning_present = false;
    let mut enrollment_listen = None;
    let mut issuer_cert = None;
    let mut issuer_key = None;
    let mut agent_server_ca = None;
    let mut agent_cert_validity = Duration::from_secs(24 * 60 * 60);
    let mut max_enrollment_clients = 32;
    let mut enrollment_request_timeout = Duration::from_secs(10);
    let mut enrollment_activation_grace = Duration::from_secs(10 * 60);
    let mut enrollment_reconcile_interval = Duration::from_secs(30);
    let mut enrollment_options_present = false;
    let mut operations_listen = None;
    let mut max_operations_connections = 8;
    let mut operations_header_timeout = Duration::from_secs(2);
    let mut operations_request_timeout = Duration::from_secs(5);
    let mut operations_options_present = false;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            "--listen" => listen = parse_addr(args, index, flag)?,
            "--https-route-listen" => {
                https_route_listen = Some(parse_addr(args, index, flag)?);
            }
            "--tls-cert" => tls_cert = Some(parse_path(args, index, flag)?),
            "--tls-key" => tls_key = Some(parse_path(args, index, flag)?),
            "--edge-client-ca" => edge_client_ca = Some(parse_path(args, index, flag)?),
            "--max-edge-clients" => max_edge_clients = parse_positive(args, index, flag)?,
            "--tls-handshake-timeout-ms" => {
                tls_handshake_timeout = parse_duration(args, index, flag)?;
            }
            "--request-timeout-ms" => request_timeout = parse_duration(args, index, flag)?,
            "--refresh-interval-ms" => refresh_interval = parse_duration(args, index, flag)?,
            "--ops-listen" => {
                operations_listen = Some(parse_addr(args, index, flag)?);
                operations_options_present = true;
            }
            "--max-ops-connections" => {
                max_operations_connections = parse_positive(args, index, flag)?;
                operations_options_present = true;
            }
            "--ops-header-timeout-ms" => {
                operations_header_timeout = parse_duration(args, index, flag)?;
                operations_options_present = true;
            }
            "--ops-request-timeout-ms" => {
                operations_request_timeout = parse_duration(args, index, flag)?;
                operations_options_present = true;
            }
            "--tls-reload-manifest" => {
                tls_reload_manifest = Some(parse_path(args, index, flag)?);
            }
            "--tls-reload-interval-ms" => {
                tls_reload_interval = parse_duration(args, index, flag)?;
                reload_tuning_present = true;
            }
            "--tls-expiry-warning-ms" => {
                tls_expiry_warning = parse_duration(args, index, flag)?;
                reload_tuning_present = true;
            }
            "--enrollment-listen" => {
                enrollment_listen = Some(parse_addr(args, index, flag)?);
                enrollment_options_present = true;
            }
            "--issuer-cert" => {
                issuer_cert = Some(parse_path(args, index, flag)?);
                enrollment_options_present = true;
            }
            "--issuer-key" => {
                issuer_key = Some(parse_path(args, index, flag)?);
                enrollment_options_present = true;
            }
            "--agent-server-ca" => {
                agent_server_ca = Some(parse_path(args, index, flag)?);
                enrollment_options_present = true;
            }
            "--agent-cert-validity-ms" => {
                agent_cert_validity = parse_duration(args, index, flag)?;
                enrollment_options_present = true;
            }
            "--max-enrollment-clients" => {
                max_enrollment_clients = parse_positive(args, index, flag)?;
                enrollment_options_present = true;
            }
            "--enrollment-request-timeout-ms" => {
                enrollment_request_timeout = parse_duration(args, index, flag)?;
                enrollment_options_present = true;
            }
            "--enrollment-activation-grace-ms" => {
                enrollment_activation_grace = parse_duration(args, index, flag)?;
                enrollment_options_present = true;
            }
            "--enrollment-reconcile-interval-ms" => {
                enrollment_reconcile_interval = parse_duration(args, index, flag)?;
                enrollment_options_present = true;
            }
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    if reload_tuning_present && tls_reload_manifest.is_none() {
        return Err(ArgError::MissingRequired("--tls-reload-manifest"));
    }
    let enrollment = if enrollment_options_present {
        Some(EnrollmentArgs {
            listen: enrollment_listen.ok_or(ArgError::MissingRequired("--enrollment-listen"))?,
            issuer_cert: issuer_cert.ok_or(ArgError::MissingRequired("--issuer-cert"))?,
            issuer_key: issuer_key.ok_or(ArgError::MissingRequired("--issuer-key"))?,
            agent_server_ca: agent_server_ca
                .ok_or(ArgError::MissingRequired("--agent-server-ca"))?,
            agent_cert_validity,
            max_clients: max_enrollment_clients,
            request_timeout: enrollment_request_timeout,
            activation_grace: enrollment_activation_grace,
            reconcile_interval: enrollment_reconcile_interval,
        })
    } else {
        None
    };
    let operations = if operations_options_present {
        Some(OperationsArgs {
            listen: operations_listen.ok_or(ArgError::MissingRequired("--ops-listen"))?,
            max_connections: max_operations_connections,
            header_timeout: operations_header_timeout,
            request_timeout: operations_request_timeout,
        })
    } else {
        None
    };
    Ok(ServeArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
        listen,
        https_route_listen,
        tls_cert: tls_cert.ok_or(ArgError::MissingRequired("--tls-cert"))?,
        tls_key: tls_key.ok_or(ArgError::MissingRequired("--tls-key"))?,
        edge_client_ca: edge_client_ca.ok_or(ArgError::MissingRequired("--edge-client-ca"))?,
        max_edge_clients,
        tls_handshake_timeout,
        request_timeout,
        refresh_interval,
        tls_reload_manifest,
        tls_reload_interval,
        tls_expiry_warning,
        enrollment,
        operations,
    })
}

fn parse_create_token(args: &[String]) -> Result<CreateTokenArgs, ArgError> {
    let mut database = None;
    let mut agent_id = None;
    let mut tunnel_id = None;
    let mut output = None;
    let mut ttl = Duration::from_secs(10 * 60);
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            "--agent-id" => {
                agent_id = Some(
                    AgentId::new(value(args, index, flag)?)
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                )
            }
            "--tunnel-id" => {
                tunnel_id = Some(
                    TunnelId::new(value(args, index, flag)?)
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                )
            }
            "--output" => output = Some(parse_path(args, index, flag)?),
            "--ttl-ms" => ttl = parse_duration(args, index, flag)?,
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    Ok(CreateTokenArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
        agent_id: agent_id.ok_or(ArgError::MissingRequired("--agent-id"))?,
        tunnel_id: tunnel_id.ok_or(ArgError::MissingRequired("--tunnel-id"))?,
        output: output.ok_or(ArgError::MissingRequired("--output"))?,
        ttl,
    })
}

fn parse_credential_target(args: &[String]) -> Result<CredentialTargetArgs, ArgError> {
    let mut database = None;
    let mut agent_id = None;
    let mut tunnel_id = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            "--agent-id" => {
                agent_id = Some(
                    AgentId::new(value(args, index, flag)?)
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                );
            }
            "--tunnel-id" => {
                tunnel_id = Some(
                    TunnelId::new(value(args, index, flag)?)
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                );
            }
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    Ok(CredentialTargetArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
        agent_id: agent_id.ok_or(ArgError::MissingRequired("--agent-id"))?,
        tunnel_id: tunnel_id.ok_or(ArgError::MissingRequired("--tunnel-id"))?,
    })
}

fn parse_https_route_upsert(args: &[String]) -> Result<HttpsRouteUpsertArgs, ArgError> {
    let mut database = None;
    let mut hostname = None;
    let mut tunnel_id = None;
    let mut status = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            "--hostname" => {
                hostname = Some(
                    PublicHostname::new(value(args, index, flag)?)
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                );
            }
            "--tunnel-id" => {
                tunnel_id = Some(
                    TunnelId::new(value(args, index, flag)?)
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                );
            }
            "--status" => {
                status = Some(
                    value(args, index, flag)?
                        .parse()
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                );
            }
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    Ok(HttpsRouteUpsertArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
        hostname: hostname.ok_or(ArgError::MissingRequired("--hostname"))?,
        tunnel_id: tunnel_id.ok_or(ArgError::MissingRequired("--tunnel-id"))?,
        status: status.ok_or(ArgError::MissingRequired("--status"))?,
    })
}

fn parse_https_route_remove(args: &[String]) -> Result<HttpsRouteRemoveArgs, ArgError> {
    let mut database = None;
    let mut hostname = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            "--hostname" => {
                hostname = Some(
                    PublicHostname::new(value(args, index, flag)?)
                        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?,
                );
            }
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    Ok(HttpsRouteRemoveArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
        hostname: hostname.ok_or(ArgError::MissingRequired("--hostname"))?,
    })
}

fn parse_https_route_list(args: &[String]) -> Result<HttpsRouteListArgs, ArgError> {
    let mut database = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    Ok(HttpsRouteListArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
    })
}

fn parse_import(args: &[String]) -> Result<ImportArgs, ArgError> {
    let mut database = None;
    let mut snapshot = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            "--snapshot" => snapshot = Some(parse_path(args, index, flag)?),
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    Ok(ImportArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
        snapshot: snapshot.ok_or(ArgError::MissingRequired("--snapshot"))?,
    })
}

fn value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, ArgError> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| ArgError::MissingValue(flag.to_owned()))
}

fn parse_path(args: &[String], index: usize, flag: &str) -> Result<PathBuf, ArgError> {
    let value = value(args, index, flag)?;
    if value.is_empty() {
        return Err(ArgError::InvalidValue(flag.to_owned()));
    }
    Ok(PathBuf::from(value))
}

fn parse_addr(args: &[String], index: usize, flag: &str) -> Result<SocketAddr, ArgError> {
    value(args, index, flag)?
        .parse()
        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))
}

fn parse_positive<T>(args: &[String], index: usize, flag: &str) -> Result<T, ArgError>
where
    T: std::str::FromStr + PartialEq + From<u8>,
{
    let value = value(args, index, flag)?
        .parse::<T>()
        .map_err(|_| ArgError::InvalidValue(flag.to_owned()))?;
    if value == T::from(0) {
        return Err(ArgError::InvalidValue(flag.to_owned()));
    }
    Ok(value)
}

fn parse_duration(args: &[String], index: usize, flag: &str) -> Result<Duration, ArgError> {
    parse_positive(args, index, flag).map(Duration::from_millis)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ArgError {
    MissingCommand,
    UnknownCommand(String),
    MissingRequired(&'static str),
    MissingValue(String),
    InvalidValue(String),
    UnknownFlag(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCommand => f.write_str("a Control Plane command is required"),
            Self::UnknownCommand(command) => write!(f, "unknown command: {command}"),
            Self::MissingRequired(flag) => write!(f, "required argument {flag} is missing"),
            Self::MissingValue(flag) => write!(f, "{flag} requires a value"),
            Self::InvalidValue(flag) => write!(f, "{flag} has an invalid value"),
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

#[derive(Debug)]
enum ImportError {
    ReadManifest,
    Manifest(tunnelproxy_control_plane::SnapshotManifestError),
    Repository(tunnelproxy_control_plane::SnapshotRepositoryError),
    StorageTask,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadManifest => f.write_str("failed to read snapshot manifest"),
            Self::Manifest(error) => error.fmt(f),
            Self::Repository(error) => error.fmt(f),
            Self::StorageTask => f.write_str("snapshot import worker stopped unexpectedly"),
        }
    }
}

impl ImportError {
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::ReadManifest | Self::Manifest(_) => ExitCode::from(2),
            Self::Repository(
                tunnelproxy_control_plane::SnapshotRepositoryError::StaleVersion { .. }
                | tunnelproxy_control_plane::SnapshotRepositoryError::ConflictingVersion { .. }
                | tunnelproxy_control_plane::SnapshotRepositoryError::Codec(_),
            ) => ExitCode::from(2),
            Self::Repository(_) | Self::StorageTask => ExitCode::from(1),
        }
    }
}

#[derive(Debug)]
enum ServeError {
    ReadPem(&'static str),
    Tls(SnapshotTlsConfigError),
    Runtime(tunnelproxy_control_plane::ControlPlaneRuntimeError),
    Signal,
    ReloadBootstrap(SnapshotTlsReloadBootstrapError),
    ReloadRuntime(tunnelproxy_common::TlsReloadRuntimeError),
    EnrollmentTls(tunnelproxy_control_plane::EnrollmentTlsConfigError),
    Issuer(tunnelproxy_control_plane::CertificateIssuerError),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadPem(kind) => write!(f, "failed to read TLS {kind} PEM file"),
            Self::Tls(error) => error.fmt(f),
            Self::Runtime(error) => error.fmt(f),
            Self::Signal => f.write_str("OS shutdown listener failed"),
            Self::ReloadBootstrap(error) => write!(f, "TLS reload bootstrap failed: {error}"),
            Self::ReloadRuntime(error) => write!(f, "TLS reload runtime failed: {error}"),
            Self::EnrollmentTls(error) => error.fmt(f),
            Self::Issuer(error) => error.fmt(f),
        }
    }
}

impl ServeError {
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::ReadPem(_)
            | Self::Tls(_)
            | Self::ReloadBootstrap(_)
            | Self::EnrollmentTls(_)
            | Self::Issuer(_) => ExitCode::from(2),
            Self::Runtime(
                tunnelproxy_control_plane::ControlPlaneRuntimeError::InvalidConfig
                | tunnelproxy_control_plane::ControlPlaneRuntimeError::Authority(
                    tunnelproxy_control_plane::PersistentSnapshotAuthorityError::Uninitialized,
                ),
            ) => ExitCode::from(2),
            Self::Runtime(_) | Self::Signal | Self::ReloadRuntime(_) => ExitCode::from(1),
        }
    }
}

#[derive(Debug)]
enum CreateTokenError {
    Repository(tunnelproxy_control_plane::EnrollmentRepositoryError),
    StorageTask,
}

impl std::fmt::Display for CreateTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => error.fmt(f),
            Self::StorageTask => f.write_str("bootstrap token worker stopped unexpectedly"),
        }
    }
}

#[derive(Debug)]
enum CredentialCommandError {
    Repository(tunnelproxy_control_plane::EnrollmentRepositoryError),
    StorageTask,
}

impl std::fmt::Display for CredentialCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => error.fmt(f),
            Self::StorageTask => f.write_str("credential storage worker stopped unexpectedly"),
        }
    }
}

#[derive(Debug)]
enum HttpsRouteCommandError {
    Repository(tunnelproxy_control_plane::HttpsRouteRepositoryError),
    StorageTask,
}

impl std::fmt::Display for HttpsRouteCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => error.fmt(formatter),
            Self::StorageTask => {
                formatter.write_str("HTTPS route storage worker stopped unexpectedly")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn serve_and_import_flags_parse() {
        let serve = parse_args(&args(&[
            "serve",
            "--database",
            "state.db",
            "--tls-cert",
            "server.pem",
            "--tls-key",
            "server-key.pem",
            "--edge-client-ca",
            "edge-ca.pem",
            "--listen",
            "127.0.0.1:17200",
            "--max-edge-clients",
            "8",
            "--tls-handshake-timeout-ms",
            "100",
            "--request-timeout-ms",
            "200",
            "--refresh-interval-ms",
            "300",
            "--tls-reload-manifest",
            "control-tls.json",
            "--tls-reload-interval-ms",
            "400",
            "--tls-expiry-warning-ms",
            "500",
            "--ops-listen",
            "127.0.0.1:19090",
            "--max-ops-connections",
            "3",
            "--ops-header-timeout-ms",
            "600",
            "--ops-request-timeout-ms",
            "700",
        ]))
        .unwrap();
        let ParsedCommand::Serve(serve) = serve else {
            panic!("expected serve command");
        };
        assert_eq!(serve.listen.port(), 17200);
        assert_eq!(serve.max_edge_clients, 8);
        assert_eq!(serve.refresh_interval, Duration::from_millis(300));
        assert_eq!(
            serve.tls_reload_manifest,
            Some(PathBuf::from("control-tls.json"))
        );
        assert_eq!(serve.tls_reload_interval, Duration::from_millis(400));
        assert_eq!(serve.tls_expiry_warning, Duration::from_millis(500));
        let operations = serve.operations.unwrap();
        assert_eq!(operations.listen.port(), 19090);
        assert_eq!(operations.max_connections, 3);
        assert_eq!(operations.header_timeout, Duration::from_millis(600));
        assert_eq!(operations.request_timeout, Duration::from_millis(700));

        assert_eq!(
            parse_args(&args(&[
                "import",
                "--database",
                "state.db",
                "--snapshot",
                "state.json"
            ])),
            Ok(ParsedCommand::Import(ImportArgs {
                database: PathBuf::from("state.db"),
                snapshot: PathBuf::from("state.json"),
            }))
        );
    }

    #[test]
    fn missing_partial_and_zero_values_fail() {
        assert!(matches!(parse_args(&[]), Err(ArgError::MissingCommand)));
        assert!(matches!(
            parse_args(&args(&["serve", "--database", "state.db"])),
            Err(ArgError::MissingRequired(_))
        ));
        assert!(matches!(
            parse_args(&args(&[
                "serve",
                "--database",
                "state.db",
                "--tls-cert",
                "server.pem",
                "--tls-key",
                "key.pem",
                "--edge-client-ca",
                "ca.pem",
                "--max-edge-clients",
                "0",
            ])),
            Err(ArgError::InvalidValue(_))
        ));
        assert!(matches!(
            parse_args(&args(&[
                "serve",
                "--database",
                "state.db",
                "--tls-cert",
                "server.pem",
                "--tls-key",
                "key.pem",
                "--edge-client-ca",
                "ca.pem",
                "--max-ops-connections",
                "2",
            ])),
            Err(ArgError::MissingRequired("--ops-listen"))
        ));
        assert!(matches!(
            parse_args(&args(&["import", "--database"])),
            Err(ArgError::MissingValue(_))
        ));
    }

    #[test]
    fn enrollment_and_token_commands_require_complete_bound_inputs() {
        let command = parse_args(&args(&[
            "serve",
            "--database",
            "state.db",
            "--tls-cert",
            "server.pem",
            "--tls-key",
            "server-key.pem",
            "--edge-client-ca",
            "edge-client-ca.pem",
            "--enrollment-listen",
            "127.0.0.1:17300",
            "--issuer-cert",
            "issuer.pem",
            "--issuer-key",
            "issuer-key.pem",
            "--agent-server-ca",
            "edge-server-ca.pem",
            "--agent-cert-validity-ms",
            "1000",
            "--max-enrollment-clients",
            "4",
            "--enrollment-request-timeout-ms",
            "500",
            "--enrollment-activation-grace-ms",
            "1000",
            "--enrollment-reconcile-interval-ms",
            "100",
        ]))
        .unwrap();
        let ParsedCommand::Serve(serve) = command else {
            panic!("expected serve command");
        };
        let enrollment = serve.enrollment.unwrap();
        assert_eq!(enrollment.listen.port(), 17300);
        assert_eq!(enrollment.agent_cert_validity, Duration::from_secs(1));
        assert_eq!(enrollment.max_clients, 4);
        assert_eq!(enrollment.request_timeout, Duration::from_millis(500));
        assert_eq!(enrollment.activation_grace, Duration::from_secs(1));
        assert_eq!(enrollment.reconcile_interval, Duration::from_millis(100));

        assert_eq!(
            parse_args(&args(&[
                "create-token",
                "--database",
                "state.db",
                "--agent-id",
                "agent-token",
                "--tunnel-id",
                "tunnel-token",
                "--output",
                "bootstrap.token",
                "--ttl-ms",
                "1000",
            ])),
            Ok(ParsedCommand::CreateToken(CreateTokenArgs {
                database: PathBuf::from("state.db"),
                agent_id: AgentId::new("agent-token").unwrap(),
                tunnel_id: TunnelId::new("tunnel-token").unwrap(),
                output: PathBuf::from("bootstrap.token"),
                ttl: Duration::from_secs(1),
            }))
        );
        assert!(matches!(
            parse_args(&args(&[
                "serve",
                "--database",
                "state.db",
                "--tls-cert",
                "server.pem",
                "--tls-key",
                "server-key.pem",
                "--edge-client-ca",
                "edge-client-ca.pem",
                "--enrollment-listen",
                "127.0.0.1:17300",
            ])),
            Err(ArgError::MissingRequired("--issuer-cert"))
        ));
        let target = CredentialTargetArgs {
            database: PathBuf::from("state.db"),
            agent_id: AgentId::new("agent-token").unwrap(),
            tunnel_id: TunnelId::new("tunnel-token").unwrap(),
        };
        assert_eq!(
            parse_args(&args(&[
                "revoke-agent",
                "--database",
                "state.db",
                "--agent-id",
                "agent-token",
                "--tunnel-id",
                "tunnel-token",
            ])),
            Ok(ParsedCommand::RevokeAgent(target.clone()))
        );
        assert_eq!(
            parse_args(&args(&[
                "credential-status",
                "--database",
                "state.db",
                "--agent-id",
                "agent-token",
                "--tunnel-id",
                "tunnel-token",
            ])),
            Ok(ParsedCommand::CredentialStatus(target))
        );
    }

    #[test]
    fn https_route_commands_parse_canonical_values_and_reject_invalid_input() {
        assert_eq!(
            parse_args(&args(&[
                "https-route-upsert",
                "--database",
                "state.db",
                "--hostname",
                "Demo.Example.TEST.",
                "--tunnel-id",
                "tunnel-route",
                "--status",
                "disabled",
            ])),
            Ok(ParsedCommand::HttpsRouteUpsert(HttpsRouteUpsertArgs {
                database: PathBuf::from("state.db"),
                hostname: PublicHostname::new("demo.example.test").unwrap(),
                tunnel_id: TunnelId::new("tunnel-route").unwrap(),
                status: HttpsRouteStatus::Disabled,
            }))
        );
        assert_eq!(
            parse_args(&args(&[
                "https-route-remove",
                "--database",
                "state.db",
                "--hostname",
                "demo.example.test",
            ])),
            Ok(ParsedCommand::HttpsRouteRemove(HttpsRouteRemoveArgs {
                database: PathBuf::from("state.db"),
                hostname: PublicHostname::new("demo.example.test").unwrap(),
            }))
        );
        assert_eq!(
            parse_args(&args(&["https-route-list", "--database", "state.db"])),
            Ok(ParsedCommand::HttpsRouteList(HttpsRouteListArgs {
                database: PathBuf::from("state.db"),
            }))
        );
        assert!(matches!(
            parse_args(&args(&[
                "https-route-upsert",
                "--database",
                "must-not-exist.db",
                "--hostname",
                "*.example.test",
                "--tunnel-id",
                "tunnel-route",
                "--status",
                "enabled",
            ])),
            Err(ArgError::InvalidValue(flag)) if flag == "--hostname"
        ));
        assert!(matches!(
            parse_args(&args(&[
                "https-route-upsert",
                "--database",
                "state.db",
                "--hostname",
                "demo.example.test",
                "--tunnel-id",
                "tunnel-route",
                "--status",
                "active",
            ])),
            Err(ArgError::InvalidValue(flag)) if flag == "--status"
        ));
    }
}
