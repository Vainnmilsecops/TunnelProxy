//! Process-wide, secret-safe stderr logging configuration.

use std::env::VarError;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tracing_subscriber::filter::ParseError;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

/// Environment variable selecting the process log renderer.
pub const LOG_FORMAT_ENV: &str = "TUNNELPROXY_LOG_FORMAT";
/// Optional bounded event count which enables nonblocking stderr logging.
pub const LOG_BUFFER_CAPACITY_ENV: &str = "TUNNELPROXY_LOG_BUFFER_CAPACITY";
/// Maximum time to drain an enabled nonblocking buffer during shutdown.
pub const LOG_DRAIN_TIMEOUT_ENV: &str = "TUNNELPROXY_LOG_DRAIN_TIMEOUT_MS";
pub const MAX_LOG_BUFFER_CAPACITY: usize = 1_024;
pub const MAX_LOG_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_LOG_EVENT_BYTES: usize = 16 * 1024;

const DEFAULT_LOG_FILTER: &str = "info";
const DEFAULT_LOG_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(2);

static PROCESS_LOGGING_TELEMETRY: OnceLock<ProcessLoggingTelemetry> = OnceLock::new();

/// Supported process log renderers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLogFormat {
    /// Human-readable compact events.
    Text,
    /// One JSON object per event, suitable for log collectors.
    Json,
}

impl ProcessLogFormat {
    fn parse(value: Option<&str>) -> Result<Self, ProcessLoggingConfigError> {
        match value {
            None | Some("text") => Ok(Self::Text),
            Some("json") => Ok(Self::Json),
            Some(_) => Err(ProcessLoggingConfigError::InvalidFormat),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NonblockingConfig {
    capacity: usize,
    drain_timeout: Duration,
}

/// Invalid logging configuration or failed process-wide subscriber setup.
#[derive(Debug)]
pub enum ProcessLoggingConfigError {
    NonUnicodeFormat,
    InvalidFormat,
    NonUnicodeFilter,
    InvalidFilter(ParseError),
    NonUnicodeBufferCapacity,
    InvalidBufferCapacity,
    NonUnicodeDrainTimeout,
    InvalidDrainTimeout,
    DrainTimeoutWithoutBuffer,
    WorkerSpawn(io::Error),
    SubscriberAlreadySet,
}

impl std::fmt::Display for ProcessLoggingConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonUnicodeFormat => {
                write!(formatter, "{LOG_FORMAT_ENV} must contain Unicode text")
            }
            Self::InvalidFormat => {
                write!(formatter, "{LOG_FORMAT_ENV} must be `text` or `json`")
            }
            Self::NonUnicodeFilter => formatter.write_str("RUST_LOG must contain Unicode text"),
            Self::InvalidFilter(_) => formatter.write_str("RUST_LOG contains an invalid filter"),
            Self::NonUnicodeBufferCapacity => {
                write!(formatter, "{LOG_BUFFER_CAPACITY_ENV} must contain Unicode text")
            }
            Self::InvalidBufferCapacity => write!(
                formatter,
                "{LOG_BUFFER_CAPACITY_ENV} must be an integer from 1 through {MAX_LOG_BUFFER_CAPACITY}"
            ),
            Self::NonUnicodeDrainTimeout => {
                write!(formatter, "{LOG_DRAIN_TIMEOUT_ENV} must contain Unicode text")
            }
            Self::InvalidDrainTimeout => write!(
                formatter,
                "{LOG_DRAIN_TIMEOUT_ENV} must be an integer from 1 through {}",
                MAX_LOG_DRAIN_TIMEOUT.as_millis()
            ),
            Self::DrainTimeoutWithoutBuffer => write!(
                formatter,
                "{LOG_DRAIN_TIMEOUT_ENV} requires {LOG_BUFFER_CAPACITY_ENV}"
            ),
            Self::WorkerSpawn(_) => formatter.write_str("failed to start the process log worker"),
            Self::SubscriberAlreadySet => {
                formatter.write_str("the process logging subscriber is already configured")
            }
        }
    }
}

impl std::error::Error for ProcessLoggingConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidFilter(error) => Some(error),
            Self::WorkerSpawn(error) => Some(error),
            _ => None,
        }
    }
}

/// Fixed-cardinality counters for the optional nonblocking process log sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessLoggingSnapshot {
    pub buffer_capacity_events: u64,
    pub accepted_events: u64,
    pub dropped_events: u64,
    pub oversized_events: u64,
    pub write_failures: u64,
}

#[derive(Clone, Debug, Default)]
struct ProcessLoggingTelemetry {
    inner: Arc<ProcessLoggingTelemetryInner>,
}

#[derive(Debug, Default)]
struct ProcessLoggingTelemetryInner {
    buffer_capacity_events: u64,
    accepted_events: AtomicU64,
    dropped_events: AtomicU64,
    oversized_events: AtomicU64,
    write_failures: AtomicU64,
}

impl ProcessLoggingTelemetry {
    fn buffered(capacity: usize) -> Self {
        Self {
            inner: Arc::new(ProcessLoggingTelemetryInner {
                buffer_capacity_events: u64::try_from(capacity).unwrap_or(u64::MAX),
                ..ProcessLoggingTelemetryInner::default()
            }),
        }
    }

    fn snapshot(&self) -> ProcessLoggingSnapshot {
        ProcessLoggingSnapshot {
            buffer_capacity_events: self.inner.buffer_capacity_events,
            accepted_events: self.inner.accepted_events.load(Ordering::Relaxed),
            dropped_events: self.inner.dropped_events.load(Ordering::Relaxed),
            oversized_events: self.inner.oversized_events.load(Ordering::Relaxed),
            write_failures: self.inner.write_failures.load(Ordering::Relaxed),
        }
    }
}

/// Returns process-global logging telemetry without touching the log sink.
pub fn process_logging_snapshot() -> ProcessLoggingSnapshot {
    PROCESS_LOGGING_TELEMETRY
        .get()
        .map(ProcessLoggingTelemetry::snapshot)
        .unwrap_or_default()
}

/// Guard which keeps an optional nonblocking stderr worker alive.
///
/// Dropping the guard stops admission, drains within the configured deadline,
/// and detaches a blocked writer rather than hanging process shutdown.
#[must_use = "the process logging guard must live until process shutdown"]
pub struct ProcessLoggingGuard {
    format: ProcessLogFormat,
    _worker: Option<NonblockingWorkerGuard>,
    telemetry: ProcessLoggingTelemetry,
}

impl ProcessLoggingGuard {
    pub const fn format(&self) -> ProcessLogFormat {
        self.format
    }

    pub fn snapshot(&self) -> ProcessLoggingSnapshot {
        self.telemetry.snapshot()
    }
}

fn read_env(name: &'static str) -> Result<Option<String>, VarError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(error @ VarError::NotUnicode(_)) => Err(error),
    }
}

fn parse_filter(value: Option<&str>) -> Result<EnvFilter, ProcessLoggingConfigError> {
    EnvFilter::try_new(value.unwrap_or(DEFAULT_LOG_FILTER))
        .map_err(ProcessLoggingConfigError::InvalidFilter)
}

fn parse_nonblocking_config(
    capacity: Option<&str>,
    drain_timeout_ms: Option<&str>,
) -> Result<Option<NonblockingConfig>, ProcessLoggingConfigError> {
    let Some(capacity) = capacity else {
        return if drain_timeout_ms.is_some() {
            Err(ProcessLoggingConfigError::DrainTimeoutWithoutBuffer)
        } else {
            Ok(None)
        };
    };
    let capacity = capacity
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=MAX_LOG_BUFFER_CAPACITY).contains(value))
        .ok_or(ProcessLoggingConfigError::InvalidBufferCapacity)?;
    let drain_timeout = match drain_timeout_ms {
        Some(value) => {
            let milliseconds = value
                .parse::<u64>()
                .ok()
                .filter(|value| {
                    (1..=u64::try_from(MAX_LOG_DRAIN_TIMEOUT.as_millis()).unwrap_or(u64::MAX))
                        .contains(value)
                })
                .ok_or(ProcessLoggingConfigError::InvalidDrainTimeout)?;
            Duration::from_millis(milliseconds)
        }
        None => DEFAULT_LOG_DRAIN_TIMEOUT,
    };
    Ok(Some(NonblockingConfig {
        capacity,
        drain_timeout,
    }))
}

/// Installs the process-wide subscriber and returns its lifetime guard.
///
/// Both renderers write only to stderr. Callers must retain the returned guard
/// and should reserve stdout for stable command output and help text.
pub fn init_process_logging() -> Result<ProcessLoggingGuard, ProcessLoggingConfigError> {
    let format = ProcessLogFormat::parse(
        read_env(LOG_FORMAT_ENV)
            .map_err(|_| ProcessLoggingConfigError::NonUnicodeFormat)?
            .as_deref(),
    )?;
    let filter = parse_filter(
        read_env("RUST_LOG")
            .map_err(|_| ProcessLoggingConfigError::NonUnicodeFilter)?
            .as_deref(),
    )?;
    let buffer_capacity = read_env(LOG_BUFFER_CAPACITY_ENV)
        .map_err(|_| ProcessLoggingConfigError::NonUnicodeBufferCapacity)?;
    let drain_timeout = read_env(LOG_DRAIN_TIMEOUT_ENV)
        .map_err(|_| ProcessLoggingConfigError::NonUnicodeDrainTimeout)?;
    let nonblocking =
        parse_nonblocking_config(buffer_capacity.as_deref(), drain_timeout.as_deref())?;

    let telemetry = nonblocking.map_or_else(ProcessLoggingTelemetry::default, |config| {
        ProcessLoggingTelemetry::buffered(config.capacity)
    });
    let worker = match nonblocking {
        Some(config) => {
            let (writer, worker) = nonblocking_writer(io::stderr(), config, telemetry.clone())?;
            install_subscriber(format, filter, writer)?;
            Some(worker)
        }
        None => {
            install_subscriber(format, filter, io::stderr)?;
            None
        }
    };
    let _ = PROCESS_LOGGING_TELEMETRY.set(telemetry.clone());
    Ok(ProcessLoggingGuard {
        format,
        _worker: worker,
        telemetry,
    })
}

fn install_subscriber<W>(
    format: ProcessLogFormat,
    filter: EnvFilter,
    writer: W,
) -> Result<(), ProcessLoggingConfigError>
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let result = match format {
        ProcessLogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init(),
        ProcessLogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .with_target(true)
            .flatten_event(false)
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init(),
    };
    result.map_err(|_| ProcessLoggingConfigError::SubscriberAlreadySet)
}

#[derive(Clone)]
struct NonblockingMakeWriter {
    state: Arc<NonblockingState>,
}

struct NonblockingState {
    sender: SyncSender<Vec<u8>>,
    accepting: AtomicBool,
    telemetry: ProcessLoggingTelemetry,
}

impl<'writer> MakeWriter<'writer> for NonblockingMakeWriter {
    type Writer = BoundedEventWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        BoundedEventWriter {
            state: Arc::clone(&self.state),
            bytes: Vec::with_capacity(256),
            oversized: false,
        }
    }
}

struct BoundedEventWriter {
    state: Arc<NonblockingState>,
    bytes: Vec<u8>,
    oversized: bool,
}

impl Write for BoundedEventWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.oversized {
            match self.bytes.len().checked_add(bytes.len()) {
                Some(total) if total <= MAX_LOG_EVENT_BYTES => self.bytes.extend_from_slice(bytes),
                _ => {
                    self.bytes.clear();
                    self.oversized = true;
                }
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BoundedEventWriter {
    fn drop(&mut self) {
        if self.oversized {
            self.state
                .telemetry
                .inner
                .oversized_events
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.bytes.is_empty() {
            return;
        }
        if !self.state.accepting.load(Ordering::Acquire) {
            self.state
                .telemetry
                .inner
                .dropped_events
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        match self.state.sender.try_send(std::mem::take(&mut self.bytes)) {
            Ok(()) => {
                self.state
                    .telemetry
                    .inner
                    .accepted_events
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.state
                    .telemetry
                    .inner
                    .dropped_events
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

struct NonblockingWorkerGuard {
    state: Arc<NonblockingState>,
    completed: Receiver<()>,
    thread: Option<JoinHandle<()>>,
    drain_timeout: Duration,
}

impl NonblockingWorkerGuard {
    fn shutdown(&mut self) -> bool {
        let Some(worker) = self.thread.take() else {
            return true;
        };
        self.state.accepting.store(false, Ordering::Release);
        if self.completed.recv_timeout(self.drain_timeout).is_ok() {
            let _ = worker.join();
            true
        } else {
            drop(worker);
            false
        }
    }
}

impl Drop for NonblockingWorkerGuard {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn nonblocking_writer<W>(
    writer: W,
    config: NonblockingConfig,
    telemetry: ProcessLoggingTelemetry,
) -> Result<(NonblockingMakeWriter, NonblockingWorkerGuard), ProcessLoggingConfigError>
where
    W: Write + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(config.capacity);
    let state = Arc::new(NonblockingState {
        sender,
        accepting: AtomicBool::new(true),
        telemetry,
    });
    let (completed_tx, completed) = mpsc::sync_channel(1);
    let worker_state = Arc::clone(&state);
    let thread = thread::Builder::new()
        .name("tunnelproxy-log-writer".to_string())
        .spawn(move || {
            run_log_worker(writer, receiver, &worker_state);
            let _ = completed_tx.send(());
        })
        .map_err(ProcessLoggingConfigError::WorkerSpawn)?;
    Ok((
        NonblockingMakeWriter {
            state: Arc::clone(&state),
        },
        NonblockingWorkerGuard {
            state,
            completed,
            thread: Some(thread),
            drain_timeout: config.drain_timeout,
        },
    ))
}

fn run_log_worker<W>(mut writer: W, receiver: Receiver<Vec<u8>>, state: &NonblockingState)
where
    W: Write,
{
    loop {
        match receiver.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(event) => {
                if writer.write_all(&event).is_err() {
                    state
                        .telemetry
                        .inner
                        .write_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(RecvTimeoutError::Timeout) if state.accepting.load(Ordering::Acquire) => {}
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
        }
    }
    while let Ok(event) = receiver.try_recv() {
        if writer.write_all(&event).is_err() {
            state
                .telemetry
                .inner
                .write_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    if writer.flush().is_err() {
        state
            .telemetry
            .inner
            .write_failures
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use std::time::Instant;

    #[derive(Clone, Default)]
    struct SharedWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BlockingWriter {
        entered: SyncSender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("test sink failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Write for BlockingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.entered.try_send(());
            let (lock, wake) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn emit(writer: &NonblockingMakeWriter, bytes: &[u8]) {
        let mut event = writer.make_writer();
        event.write_all(bytes).unwrap();
    }

    #[test]
    fn format_defaults_to_text_and_accepts_documented_values() {
        assert_eq!(
            ProcessLogFormat::parse(None).unwrap(),
            ProcessLogFormat::Text
        );
        assert_eq!(
            ProcessLogFormat::parse(Some("text")).unwrap(),
            ProcessLogFormat::Text
        );
        assert_eq!(
            ProcessLogFormat::parse(Some("json")).unwrap(),
            ProcessLogFormat::Json
        );
    }

    #[test]
    fn format_rejects_empty_unknown_and_case_changed_values() {
        for value in ["", "JSON", "pretty"] {
            assert!(matches!(
                ProcessLogFormat::parse(Some(value)),
                Err(ProcessLoggingConfigError::InvalidFormat)
            ));
        }
    }

    #[test]
    fn filter_accepts_directives_and_rejects_invalid_syntax() {
        assert!(parse_filter(None).is_ok());
        assert!(parse_filter(Some("warn,tunnelproxy_edge=debug")).is_ok());
        assert!(matches!(
            parse_filter(Some("tunnelproxy_edge[")),
            Err(ProcessLoggingConfigError::InvalidFilter(_))
        ));
    }

    #[test]
    fn configuration_errors_do_not_echo_values() {
        let filter = parse_filter(Some("secret-token[")).unwrap_err().to_string();
        assert!(!filter.contains("secret-token"));
        let capacity = parse_nonblocking_config(Some("secret-capacity"), None)
            .unwrap_err()
            .to_string();
        assert!(!capacity.contains("secret-capacity"));
        let timeout = parse_nonblocking_config(Some("1"), Some("secret-timeout"))
            .unwrap_err()
            .to_string();
        assert!(!timeout.contains("secret-timeout"));
    }

    #[test]
    fn nonblocking_configuration_is_opt_in_strict_and_bounded() {
        assert_eq!(parse_nonblocking_config(None, None).unwrap(), None);
        assert!(matches!(
            parse_nonblocking_config(None, Some("10")),
            Err(ProcessLoggingConfigError::DrainTimeoutWithoutBuffer)
        ));
        for value in ["0", "1025", "invalid"] {
            assert!(matches!(
                parse_nonblocking_config(Some(value), None),
                Err(ProcessLoggingConfigError::InvalidBufferCapacity)
            ));
        }
        for value in ["0", "5001", "invalid"] {
            assert!(matches!(
                parse_nonblocking_config(Some("1"), Some(value)),
                Err(ProcessLoggingConfigError::InvalidDrainTimeout)
            ));
        }
        assert_eq!(
            parse_nonblocking_config(Some("8"), Some("250")).unwrap(),
            Some(NonblockingConfig {
                capacity: 8,
                drain_timeout: Duration::from_millis(250),
            })
        );
    }

    #[test]
    fn healthy_worker_preserves_fifo_and_drains_on_shutdown() {
        let output = SharedWriter::default();
        let observed = Arc::clone(&output.bytes);
        let telemetry = ProcessLoggingTelemetry::buffered(4);
        let (writer, mut worker) = nonblocking_writer(
            output,
            NonblockingConfig {
                capacity: 4,
                drain_timeout: Duration::from_secs(1),
            },
            telemetry.clone(),
        )
        .unwrap();
        emit(&writer, b"first\n");
        emit(&writer, b"second\n");
        assert!(worker.shutdown());
        assert_eq!(&*observed.lock().unwrap(), b"first\nsecond\n");
        assert_eq!(telemetry.snapshot().accepted_events, 2);
        assert_eq!(telemetry.snapshot().dropped_events, 0);
    }

    #[test]
    fn blocked_sink_never_blocks_producer_and_queue_drops_newest() {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let output = Arc::new(Mutex::new(Vec::new()));
        let telemetry = ProcessLoggingTelemetry::buffered(2);
        let (writer, mut worker) = nonblocking_writer(
            BlockingWriter {
                entered: entered_tx,
                release: Arc::clone(&release),
                bytes: Arc::clone(&output),
            },
            NonblockingConfig {
                capacity: 2,
                drain_timeout: Duration::from_millis(20),
            },
            telemetry.clone(),
        )
        .unwrap();
        emit(&writer, b"in-flight\n");
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let started = Instant::now();
        emit(&writer, b"queued-1\n");
        emit(&writer, b"queued-2\n");
        emit(&writer, b"dropped\n");
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(telemetry.snapshot().accepted_events, 3);
        assert_eq!(telemetry.snapshot().dropped_events, 1);

        let shutdown_started = Instant::now();
        assert!(!worker.shutdown());
        assert!(shutdown_started.elapsed() < Duration::from_millis(500));
        let (lock, wake) = &*release;
        *lock.lock().unwrap() = true;
        wake.notify_all();
    }

    #[test]
    fn oversized_event_is_discarded_without_partial_output() {
        let output = SharedWriter::default();
        let observed = Arc::clone(&output.bytes);
        let telemetry = ProcessLoggingTelemetry::buffered(1);
        let (writer, mut worker) = nonblocking_writer(
            output,
            NonblockingConfig {
                capacity: 1,
                drain_timeout: Duration::from_secs(1),
            },
            telemetry.clone(),
        )
        .unwrap();
        emit(&writer, &vec![b'x'; MAX_LOG_EVENT_BYTES + 1]);
        assert!(worker.shutdown());
        assert!(observed.lock().unwrap().is_empty());
        assert_eq!(telemetry.snapshot().oversized_events, 1);
        assert_eq!(telemetry.snapshot().accepted_events, 0);
    }

    #[test]
    fn sink_write_failures_are_counted_without_stopping_the_worker() {
        let telemetry = ProcessLoggingTelemetry::buffered(2);
        let (writer, mut worker) = nonblocking_writer(
            FailingWriter,
            NonblockingConfig {
                capacity: 2,
                drain_timeout: Duration::from_secs(1),
            },
            telemetry.clone(),
        )
        .unwrap();
        emit(&writer, b"first\n");
        emit(&writer, b"second\n");
        assert!(worker.shutdown());
        assert_eq!(telemetry.snapshot().accepted_events, 2);
        assert_eq!(telemetry.snapshot().write_failures, 2);
    }
}
