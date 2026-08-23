//! Runnable authorization snapshot import and distribution process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tunnelproxy_common::{shutdown_channel, wait_for_process_shutdown};
use tunnelproxy_control_plane::{
    parse_snapshot_manifest, ControlPlaneRuntime, ControlPlaneRuntimeConfig, SnapshotCommitOutcome,
    SnapshotRepository, SnapshotServerConfig, SnapshotServerTlsConfig,
    SnapshotServerTlsReloadConfig, SnapshotServerTlsReloadRuntime, SnapshotTlsConfigError,
    SnapshotTlsReloadBootstrapError, SqliteSnapshotRepository, MAX_SNAPSHOT_BYTES,
};

const USAGE: &str = "\
Usage:
  tunnelproxy-control-plane serve [OPTIONS]
  tunnelproxy-control-plane import [OPTIONS]

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
  --tls-reload-manifest <path>       atomic TLS generation manifest
  --tls-reload-interval-ms <ms>      reload poll (default 1000)
  --tls-expiry-warning-ms <ms>       expiry warning (default 604800000)

Import options:
  --database <path>                  SQLite snapshot database (required)
  --snapshot <path>                  full snapshot JSON manifest (required)

  --help                             print this help and exit
";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(error) => {
            error!(%error, "invalid Control Plane CLI arguments");
            eprintln!("{USAGE}");
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
    let runtime = ControlPlaneRuntime::bind(ControlPlaneRuntimeConfig {
        database_path: args.database,
        refresh_interval: args.refresh_interval,
        snapshot_server: SnapshotServerConfig {
            listen_addr: args.listen,
            max_edge_clients: args.max_edge_clients,
            request_timeout: args.request_timeout,
            tls,
        },
    })
    .await
    .map_err(ServeError::Runtime)?;
    info!(
        listen_addr = %runtime.local_addr(),
        snapshot_version = runtime.current_version().get(),
        "Control Plane snapshot service started"
    );
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
}

#[derive(Debug, PartialEq, Eq)]
struct ServeArgs {
    database: PathBuf,
    listen: SocketAddr,
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
}

#[derive(Debug, PartialEq, Eq)]
struct ImportArgs {
    database: PathBuf,
    snapshot: PathBuf,
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
        other => Err(ArgError::UnknownCommand(other.to_owned())),
    }
}

fn parse_serve(args: &[String]) -> Result<ServeArgs, ArgError> {
    let mut database = None;
    let mut listen = "127.0.0.1:7200".parse().unwrap();
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
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--database" => database = Some(parse_path(args, index, flag)?),
            "--listen" => listen = parse_addr(args, index, flag)?,
            "--tls-cert" => tls_cert = Some(parse_path(args, index, flag)?),
            "--tls-key" => tls_key = Some(parse_path(args, index, flag)?),
            "--edge-client-ca" => edge_client_ca = Some(parse_path(args, index, flag)?),
            "--max-edge-clients" => max_edge_clients = parse_positive(args, index, flag)?,
            "--tls-handshake-timeout-ms" => {
                tls_handshake_timeout = parse_duration(args, index, flag)?;
            }
            "--request-timeout-ms" => request_timeout = parse_duration(args, index, flag)?,
            "--refresh-interval-ms" => refresh_interval = parse_duration(args, index, flag)?,
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
            other => return Err(ArgError::UnknownFlag(other.to_owned())),
        }
        index += 2;
    }
    if reload_tuning_present && tls_reload_manifest.is_none() {
        return Err(ArgError::MissingRequired("--tls-reload-manifest"));
    }
    Ok(ServeArgs {
        database: database.ok_or(ArgError::MissingRequired("--database"))?,
        listen,
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
            Self::MissingCommand => f.write_str("serve or import command is required"),
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
        }
    }
}

impl ServeError {
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::ReadPem(_) | Self::Tls(_) | Self::ReloadBootstrap(_) => ExitCode::from(2),
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
            parse_args(&args(&["import", "--database"])),
            Err(ArgError::MissingValue(_))
        ));
    }
}
