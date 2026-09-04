//! `tunnelproxy-edge`
//!
//! Public ingress and live tunnel routing for TunnelProxy.
//!
//! This crate contains three distinct but coexisting TCP primitives:
//!
//! - The **echo baseline** from Session 02 (`run_listener`,
//!   `handle_connection`). Binds a TCP listener and echoes every byte
//!   back to the client. Kept for regression coverage and as the
//!   simplest possible networking smoke test.
//!
//! - The **bidirectional TCP relay** from Session 03
//!   (`run_relay_listener`, `relay_connection`, `relay_bidirectional`,
//!   [`RelayStats`], [`RelayError`], [`RelayDirection`]). Binds a TCP
//!   listener; for every accepted downstream connection it opens a
//!   fresh upstream TCP connection to a configured address and
//!   forwards raw bytes concurrently in both directions under an
//!   activity-aware idle deadline. The relay preserves TCP
//!   half-close semantics so that EOF in one direction does not kill
//!   traffic in the other.
//!
//! - The **local TCP forwarder** from Session 04
//!   ([`ForwardConfig`], [`ForwardError`], [`Forwarder`],
//!   [`ConnectionId`], [`ConnectionLifecycle`], [`ConnectionOutcome`]).
//!   It is the hardened, configurable, lifecycle-aware foundation of
//!   the relay: explicit forwarding configuration, per-connection
//!   identity, structured lifecycle phases, bounded upstream connect
//!   and relay-idle timeouts, explicit max-concurrent-connections policy, and
//!   RAII-managed resource cleanup. The forwarder is built on top of
//!   the same byte-stream primitive as the Session 03 relay, so the
//!   underlying full-duplex and half-close semantics are preserved by
//!   construction.
//!
//! - The **Agent control transport** from Sessions 06–07
//!   (`AgentTransportListener`, `AgentListenerConfig`,
//!   `TransportSessionId`, `AgentSession`, `HandshakeState`).
//!   A protocol-aware TCP listener that accepts Agent connections,
//!   performs the v2 handshake (HELLO → REGISTER → REGISTERED),
//!   and maintains established transport sessions. Bounded concurrent
//!   admission via semaphore; bounded handshake and Edge-initiated heartbeat
//!   liveness via configurable timeouts.
//!
//! - The **single-stream reverse path** from Session 08
//!   (`SingleStreamEdgeRuntime`, `SingleStreamEdgeConfig`). It binds a separate
//!   loopback raw-TCP ingress, opens one framed stream through the established
//!   Agent transport, preserves half-close, and allows sequential reuse. It is
//!   deliberately not a public HTTP router or concurrent multiplexer.
//!
//! The echo baseline and relay primitives are **layer-4 TCP** primitives
//! that exist to validate the byte-stream pipeline, lifecycle, and
//! resource discipline. The Agent transport is the first protocol-aware
//! runtime. Session 08 implements the loopback raw-TCP vertical slice;
//! Session 12 composes it into a runnable single-Agent process, Session 14
//! adds mutual TLS to that Agent transport, and Session 23 adds explicit
//! public raw TCP exposure backed by dynamic authorization and per-IP
//! admission. Sessions 25 and 34 add bounded HTTP/1.1 routing; Session 44 adds
//! opt-in bounded HTTP/2 with the same exact cached routing and local HTTP/1.1
//! forwarding path.
//! See `docs/ai/DECISIONS.md` (ADR-002, ADR-005, ADR-006, ADR-007) and
//! `docs/TECH_DEBT.md` for the deliberate limitations.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio::task::JoinSet;
use tracing::{debug, error, info, trace, warn};

pub use tunnelproxy_common::{
    shutdown_channel, RuntimeShutdownConfig, RuntimeShutdownConfigError, RuntimeShutdownOutcome,
    ShutdownSignal, ShutdownTrigger,
};

/// Default development bind address for the edge listener.
///
/// `127.0.0.1:7000` is local-only. The edge MUST NOT bind a public
/// address in the foundation phase; doing so would conflict with the
/// production architecture and with INV-001 (only agents initiate
/// outbound tunnels).
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:7000";

/// Default upstream address for the relay/forwarder development
/// binary.
///
/// Pairs with [`DEFAULT_BIND_ADDR`]: a forwarder listening on
/// `127.0.0.1:7000` will forward to `127.0.0.1:8000` by default.
pub const DEFAULT_UPSTREAM_ADDR: &str = "127.0.0.1:8000";

/// Default maximum concurrent connections for the forwarder.
///
/// Bounds the total in-flight relays. New connections that arrive
/// while this many relays are already active are rejected cleanly
/// (the downstream socket is shut down and the connection is logged
/// with [`ConnectionLifecycle::CapacityRejected`]).
pub const DEFAULT_MAX_CONNECTIONS: usize = 100;

/// Default maximum number of concurrently running echo handlers.
///
/// Echo admission happens before a handler task is spawned, so this also
/// bounds the listener's live task set under connection floods.
pub const DEFAULT_ECHO_MAX_CONNECTIONS: usize = 100;

/// Default upstream TCP connect timeout.
///
/// Bound the time a single downstream connection spends waiting to
/// dial the upstream. Distinct from the smaller read deadlines
/// enforced inside the relay.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default maximum period without a successfully forwarded byte.
///
/// The deadline is shared by both relay directions and resets after a
/// complete non-empty write. It therefore bounds silent peers and blocked
/// writes without imposing a maximum lifetime on active connections.
pub const DEFAULT_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Smallest configurable relay idle timeout.
pub const MIN_RELAY_IDLE_TIMEOUT: Duration = Duration::from_millis(1);

/// Largest configurable relay idle timeout (one hour).
pub const MAX_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Size of the per-connection read buffer used by the Session 02 echo
/// baseline.
///
/// 8 KiB is a reasonable default for the byte-stream baseline. The
/// invariant in INV-002 (no unbounded buffering) is satisfied because
/// the buffer is a fixed allocation and is reused across reads; we
/// never call `read_to_end` on a live socket. The relay / forwarder uses this
/// same bound for one buffer in each direction.
pub const READ_BUFFER_SIZE: usize = 8 * 1024;

// ---------------------------------------------------------------------------
// Session 02 — TCP echo baseline (preserved compatibility surface)
// ---------------------------------------------------------------------------

/// Bounded connection policy for the compatibility TCP echo server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoConfig {
    /// Maximum number of concurrently running connection handlers.
    pub max_connections: usize,
    /// Maximum time without a successfully echoed non-empty write.
    pub idle_timeout: Duration,
}

impl Default for EchoConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_ECHO_MAX_CONNECTIONS,
            idle_timeout: DEFAULT_RELAY_IDLE_TIMEOUT,
        }
    }
}

impl EchoConfig {
    /// Validate the echo admission and idle-timeout bounds.
    pub fn validate(&self) -> Result<(), EchoConfigError> {
        if self.max_connections == 0 {
            return Err(EchoConfigError::ZeroMaxConnections);
        }
        if self.max_connections > Semaphore::MAX_PERMITS {
            return Err(EchoConfigError::TooManyConnections);
        }
        if self.idle_timeout < MIN_RELAY_IDLE_TIMEOUT {
            return Err(EchoConfigError::IdleTimeoutTooSmall);
        }
        if self.idle_timeout > MAX_RELAY_IDLE_TIMEOUT {
            return Err(EchoConfigError::IdleTimeoutTooLarge);
        }
        Ok(())
    }
}

/// Invalid [`EchoConfig`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoConfigError {
    /// `max_connections` must be strictly greater than zero.
    ZeroMaxConnections,
    /// `max_connections` must fit Tokio's semaphore implementation.
    TooManyConnections,
    /// `idle_timeout` must be at least one millisecond.
    IdleTimeoutTooSmall,
    /// `idle_timeout` must not exceed one hour.
    IdleTimeoutTooLarge,
}

impl std::fmt::Display for EchoConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaxConnections => {
                f.write_str("echo max_connections must be greater than zero")
            }
            Self::TooManyConnections => {
                f.write_str("echo max_connections exceeds the semaphore limit")
            }
            Self::IdleTimeoutTooSmall => {
                f.write_str("echo idle_timeout must be at least 1 millisecond")
            }
            Self::IdleTimeoutTooLarge => {
                f.write_str("echo idle_timeout must not exceed 3600000 milliseconds")
            }
        }
    }
}

impl std::error::Error for EchoConfigError {}

/// Bind a TCP listener and serve connections forever, echoing every
/// byte received from each client back to that client until EOF or
/// error.
///
/// This is the Session 02 baseline. Kept for regression coverage and
/// as the simplest possible networking smoke test. New code should
/// prefer the forwarder / relay primitives below for any non-trivial
/// workload.
///
/// `bind_addr` is resolved by the caller. Use [`DEFAULT_BIND_ADDR`]
/// for the development binary.
///
/// Each accepted connection is handled by [`handle_connection`],
/// spawned as an independent Tokio task so that one connection's
/// failure cannot stall others. Connection-level errors are logged
/// and swallowed; listener-level fatal errors return them to the
/// caller.
///
/// The function returns `Ok(())` only when [`TcpListener::accept`]
/// itself fails — for example when the bound socket is closed by the
/// process supervisor. Normal per-connection closes are not
/// propagated upward.
pub async fn run_listener(bind_addr: SocketAddr) -> std::io::Result<()> {
    run_listener_with_config(bind_addr, EchoConfig::default()).await
}

/// Bind and run the echo listener with explicit bounded admission policy.
pub async fn run_listener_with_config(
    bind_addr: SocketAddr,
    config: EchoConfig,
) -> std::io::Result<()> {
    validate_echo_config(config)?;
    let listener = TcpListener::bind(bind_addr).await?;
    serve_listener_with_config(listener, config).await
}

/// Serve a pre-bound listener with bounded pre-spawn connection admission.
///
/// Accepting a socket does not imply spawning a task: when capacity is full,
/// the socket is dropped inline and the listener continues. This form is
/// useful to callers that bind port zero and need to inspect the selected
/// address before serving.
pub async fn serve_listener_with_config(
    listener: TcpListener,
    config: EchoConfig,
) -> std::io::Result<()> {
    validate_echo_config(config)?;
    let local = listener.local_addr()?;
    info!(
        addr = %local,
        max_connections = config.max_connections,
        idle_timeout_ms = config.idle_timeout.as_millis() as u64,
        event = "tcp_server_started",
        "TCP server bound"
    );

    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    admit_echo_connection(
                        &mut tasks,
                        stream,
                        peer,
                        Arc::clone(&permits),
                        config,
                    );
                }
                Err(err) => {
                error!(error = %err, event = "tcp_listener_accept_error", "accept failed");
                return Err(err);
                }
            },
        }
    }
}

/// Runs the echo baseline until shutdown, then joins or aborts every child.
pub async fn run_listener_until_shutdown(
    bind_addr: SocketAddr,
    signal: ShutdownSignal,
    shutdown: RuntimeShutdownConfig,
) -> std::io::Result<RuntimeShutdownOutcome> {
    run_listener_until_shutdown_with_config(bind_addr, EchoConfig::default(), signal, shutdown)
        .await
}

/// Runs the explicitly configured bounded echo listener until shutdown.
pub async fn run_listener_until_shutdown_with_config(
    bind_addr: SocketAddr,
    config: EchoConfig,
    signal: ShutdownSignal,
    shutdown: RuntimeShutdownConfig,
) -> std::io::Result<RuntimeShutdownOutcome> {
    validate_echo_config(config)?;
    validate_shutdown(shutdown)?;
    let listener = TcpListener::bind(bind_addr).await?;
    serve_listener_until_shutdown_with_config(listener, config, signal, shutdown).await
}

/// Serve a pre-bound echo listener until shutdown under explicit bounds.
pub async fn serve_listener_until_shutdown_with_config(
    listener: TcpListener,
    config: EchoConfig,
    signal: ShutdownSignal,
    shutdown: RuntimeShutdownConfig,
) -> std::io::Result<RuntimeShutdownOutcome> {
    validate_echo_config(config)?;
    validate_shutdown(shutdown)?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = signal.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                admit_echo_connection(
                    &mut tasks,
                    stream,
                    peer,
                    Arc::clone(&permits),
                    config,
                );
            }
        }
    }
    drop(listener);
    Ok(drain_tasks(tasks, shutdown.drain_timeout).await)
}

fn validate_echo_config(config: EchoConfig) -> std::io::Result<()> {
    config
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
}

fn admit_echo_connection(
    tasks: &mut JoinSet<()>,
    stream: TcpStream,
    peer: SocketAddr,
    permits: Arc<Semaphore>,
    config: EchoConfig,
) {
    let permit = match permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
            warn!(
                peer = %peer,
                max_connections = config.max_connections,
                event = "tcp_connection_rejected_capacity",
                "echo capacity unavailable; downstream closed"
            );
            drop(stream);
            return;
        }
    };
    info!(
        peer = %peer,
        event = "tcp_connection_accepted",
        "accepted connection"
    );
    tasks.spawn(async move {
        let _permit = permit;
        handle_connection_with_idle_timeout(stream, peer, config.idle_timeout).await;
    });
}

/// Drive a single accepted TCP connection: read bytes in a fixed
/// buffer and echo them back until the peer half-closes or the
/// connection errors.
///
/// Exposed as a public function so integration tests can drive a
/// pre-built `TcpStream` directly. Real listener use funnels here via
/// [`run_listener`].
///
/// This function never panics on ordinary network failures. Read
/// errors after the first byte are treated as a normal close. Write
/// errors are logged and cause the connection to be dropped so the
/// caller can reclaim the socket.
pub async fn handle_connection(stream: TcpStream, peer: SocketAddr) {
    handle_connection_with_idle_timeout(stream, peer, DEFAULT_RELAY_IDLE_TIMEOUT).await;
}

/// Drive the echo baseline with an explicit activity-aware idle deadline.
///
/// The deadline resets only after a non-empty read has been written back in
/// full. A blocked write therefore remains bounded by the same deadline as a
/// silent read. This explicit variant supports deterministic tests while
/// [`handle_connection`] preserves the original public signature.
pub async fn handle_connection_with_idle_timeout(
    mut stream: TcpStream,
    peer: SocketAddr,
    idle_timeout: Duration,
) {
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        let read = tokio::select! {
            biased;
            () = &mut idle => {
                debug!(
                    peer = %peer,
                    idle_timeout_ms = idle_timeout.as_millis() as u64,
                    event = "tcp_connection_idle_timeout",
                    "client connection exceeded its idle deadline"
                );
                return;
            }
            read = stream.read(&mut buf) => read,
        };
        match read {
            Ok(0) => {
                debug!(
                    peer = %peer,
                    event = "tcp_connection_closed",
                    "client closed connection (EOF)"
                );
                return;
            }
            Ok(n) => {
                trace!(
                    peer = %peer,
                    event = "tcp_connection_read",
                    bytes = n,
                    "received bytes"
                );
                match tokio::time::timeout_at(idle.deadline(), stream.write_all(&buf[..n])).await {
                    Ok(Ok(())) => idle
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle_timeout),
                    Ok(Err(err)) => {
                        warn!(
                            peer = %peer,
                            error = %err,
                            event = "tcp_connection_error",
                            "write failed; dropping connection"
                        );
                        return;
                    }
                    Err(_) => {
                        debug!(
                            peer = %peer,
                            idle_timeout_ms = idle_timeout.as_millis() as u64,
                            event = "tcp_connection_idle_timeout",
                            "client write exceeded its idle deadline"
                        );
                        return;
                    }
                }
            }
            Err(err) => {
                warn!(
                    peer = %peer,
                    error = %err,
                    event = "tcp_connection_error",
                    "read failed; dropping connection"
                );
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session 03 — bidirectional TCP relay (preserved unchanged)
// ---------------------------------------------------------------------------

/// Summary of bytes forwarded in both directions during a single
/// relay connection.
///
/// Returned by [`relay_bidirectional`] and surfaced through
/// [`relay_connection`] so callers and tests can assert that traffic
/// actually flowed through the relay.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    /// Bytes forwarded from the downstream client to the upstream
    /// server.
    pub bytes_downstream_to_upstream: u64,
    /// Bytes forwarded from the upstream server back to the
    /// downstream client.
    pub bytes_upstream_to_downstream: u64,
}

/// Errors that can occur during a single Session 03 relay connection.
///
/// Coarse-grained on purpose: the relay is a TCP primitive, not a
/// diagnostic tool. Tests and the dev binary use the variants only to
/// distinguish "could not even open the upstream" from "upstream
/// opened but I/O failed while relaying". Session 04 introduces
/// [`ForwardError`] for the lifecycle-aware forwarder.
#[derive(Debug)]
pub enum RelayError {
    /// Opening the upstream TCP connection failed for a specific
    /// downstream connection. The downstream connection is dropped;
    /// the listener keeps running.
    UpstreamConnect {
        upstream: SocketAddr,
        source: std::io::Error,
    },
    /// One half of the bidirectional copy failed after both sockets
    /// were established. The other half is shorted out as part of the
    /// relay teardown.
    Copy {
        from: RelayDirection,
        to: RelayDirection,
        source: std::io::Error,
    },
    /// Neither direction completed a non-empty write before the shared idle
    /// deadline, or a write/half-close could not finish by that deadline.
    IdleTimeout { idle_timeout: Duration },
}

/// Identifies which side of the relay a byte copy involves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    Downstream,
    Upstream,
}

impl std::fmt::Display for RelayDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayDirection::Downstream => f.write_str("downstream"),
            RelayDirection::Upstream => f.write_str("upstream"),
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::UpstreamConnect { upstream, source } => {
                write!(f, "upstream connect to {upstream} failed: {source}")
            }
            RelayError::Copy { from, to, source } => {
                write!(f, "copy {from} -> {to} failed: {source}")
            }
            RelayError::IdleTimeout { idle_timeout } => write!(
                f,
                "relay idle timeout after {} ms",
                idle_timeout.as_millis()
            ),
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RelayError::UpstreamConnect { source, .. } => Some(source),
            RelayError::Copy { source, .. } => Some(source),
            RelayError::IdleTimeout { .. } => None,
        }
    }
}

/// Forward raw bytes concurrently in both directions between
/// `downstream` and `upstream` until either side closes its write
/// half.
///
/// The relay is **byte-oriented**: it never inspects, parses, or
/// rewrites payload bytes. Each direction is forwarded independently
/// using two fixed-buffer read/write branches. When one direction finishes,
/// the matching write half on the other side is shut down so the remote peer
/// observes EOF.
///
/// Returns the total byte counts forwarded in each direction.
///
/// INV-002 (no unbounded buffering) is structurally satisfied because
/// Each direction owns one fixed 8 KiB intermediate buffer and awaits writes
/// to propagate backpressure naturally.
pub async fn relay_bidirectional(
    downstream: TcpStream,
    upstream: TcpStream,
) -> Result<RelayStats, RelayError> {
    relay_bidirectional_with_idle_timeout(downstream, upstream, DEFAULT_RELAY_IDLE_TIMEOUT).await
}

/// Forward bytes in both directions under one activity-aware idle deadline.
///
/// Each direction uses a fixed-size buffer. A successful non-empty write in
/// either direction resets the shared deadline. EOF half-closes the opposite
/// writer and leaves the remaining direction active. Silent reads, blocked
/// writes, and blocked half-closes all fail with [`RelayError::IdleTimeout`].
pub async fn relay_bidirectional_with_idle_timeout(
    mut downstream: TcpStream,
    mut upstream: TcpStream,
    idle_timeout: Duration,
) -> Result<RelayStats, RelayError> {
    let (mut downstream_read, mut downstream_write) = downstream.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let started = tokio::time::Instant::now();
    let (activity_tx, mut activity_rx) = watch::channel(started);
    let downstream_to_upstream = copy_relay_direction(
        &mut downstream_read,
        &mut upstream_write,
        RelayDirection::Downstream,
        RelayDirection::Upstream,
        activity_tx.clone(),
    );
    let upstream_to_downstream = copy_relay_direction(
        &mut upstream_read,
        &mut downstream_write,
        RelayDirection::Upstream,
        RelayDirection::Downstream,
        activity_tx,
    );
    tokio::pin!(downstream_to_upstream);
    tokio::pin!(upstream_to_downstream);

    let mut downstream_bytes = None;
    let mut upstream_bytes = None;
    let mut activity_open = true;
    let mut deadline = started + idle_timeout;
    let idle = tokio::time::sleep_until(deadline);
    tokio::pin!(idle);

    while downstream_bytes.is_none() || upstream_bytes.is_none() {
        tokio::select! {
            biased;
            changed = activity_rx.changed(), if activity_open => {
                match changed {
                    Ok(()) => {
                        let progress_at = *activity_rx.borrow_and_update();
                        if progress_at > deadline {
                            return Err(RelayError::IdleTimeout { idle_timeout });
                        }
                        deadline = progress_at + idle_timeout;
                        idle.as_mut().reset(deadline);
                    }
                    Err(_) => activity_open = false,
                }
            }
            () = &mut idle => return Err(RelayError::IdleTimeout { idle_timeout }),
            result = &mut downstream_to_upstream, if downstream_bytes.is_none() => {
                downstream_bytes = Some(result?);
            }
            result = &mut upstream_to_downstream, if upstream_bytes.is_none() => {
                upstream_bytes = Some(result?);
            }
        }
    }

    Ok(RelayStats {
        bytes_downstream_to_upstream: downstream_bytes.unwrap_or_default(),
        bytes_upstream_to_downstream: upstream_bytes.unwrap_or_default(),
    })
}

async fn copy_relay_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    from: RelayDirection,
    to: RelayDirection,
    activity: watch::Sender<tokio::time::Instant>,
) -> Result<u64, RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; READ_BUFFER_SIZE];
    let mut transferred = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|source| RelayError::Copy { from, to, source })?;
        if read == 0 {
            writer
                .shutdown()
                .await
                .map_err(|source| RelayError::Copy { from, to, source })?;
            return Ok(transferred);
        }
        writer
            .write_all(&buffer[..read])
            .await
            .map_err(|source| RelayError::Copy { from, to, source })?;
        transferred = transferred.saturating_add(read as u64);
        activity.send_replace(tokio::time::Instant::now());
    }
}

/// Accept a downstream `TcpStream`, open a fresh upstream connection
/// to `upstream_addr`, and forward bytes bidirectionally between the
/// two until either side closes.
pub async fn relay_connection(
    mut downstream: TcpStream,
    peer: SocketAddr,
    upstream_addr: SocketAddr,
) -> Result<RelayStats, RelayError> {
    info!(
        event = "relay_connection_accepted",
        peer = %peer,
        upstream = %upstream_addr,
        "relay: downstream accepted, dialing upstream"
    );

    let upstream = match TcpStream::connect(upstream_addr).await {
        Ok(stream) => {
            info!(
                event = "relay_upstream_connected",
                peer = %peer,
                upstream = %upstream_addr,
                "relay: upstream connected"
            );
            stream
        }
        Err(source) => {
            error!(
                event = "relay_failed",
                peer = %peer,
                upstream = %upstream_addr,
                error = %source,
                "relay: upstream connect failed; closing downstream only"
            );
            let _ = downstream.shutdown().await;
            return Err(RelayError::UpstreamConnect {
                upstream: upstream_addr,
                source,
            });
        }
    };

    info!(
        event = "relay_started",
        peer = %peer,
        upstream = %upstream_addr,
        "relay: starting bidirectional copy"
    );

    let stats = relay_bidirectional(downstream, upstream).await;

    match &stats {
        Ok(s) => info!(
            event = "relay_completed",
            peer = %peer,
            upstream = %upstream_addr,
            bytes_downstream_to_upstream = s.bytes_downstream_to_upstream,
            bytes_upstream_to_downstream = s.bytes_upstream_to_downstream,
            "relay: completed"
        ),
        Err(err) => warn!(
            event = "relay_failed",
            peer = %peer,
            upstream = %upstream_addr,
            error = %err,
            "relay: copy failed"
        ),
    }

    stats
}

/// Bind a TCP listener on `bind_addr`. For each accepted downstream
/// connection, open a fresh upstream TCP connection to `upstream_addr`
/// and forward bytes bidirectionally until either side closes.
///
/// Session 03 kept admission unbounded. Session 04 supersedes this
/// default with [`Forwarder`] (bounded concurrency, connect timeout,
/// structured lifecycle). For new code prefer the [`Forwarder`].
pub async fn run_relay_listener(
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;
    info!(
        addr = %local,
        upstream = %upstream_addr,
        event = "relay_server_started",
        "relay server bound"
    );

    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    tasks.spawn(async move {
                        let _ = relay_connection(stream, peer, upstream_addr).await;
                    });
                }
                Err(err) => {
                    error!(error = %err, event = "relay_listener_accept_error", "accept failed");
                    return Err(err);
                }
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

/// Runs the relay listener until shutdown and drains supervised relays.
pub async fn run_relay_listener_until_shutdown(
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
    signal: ShutdownSignal,
    shutdown: RuntimeShutdownConfig,
) -> std::io::Result<RuntimeShutdownOutcome> {
    validate_shutdown(shutdown)?;
    let listener = TcpListener::bind(bind_addr).await?;
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = signal.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                tasks.spawn(async move {
                    let _ = relay_connection(stream, peer, upstream_addr).await;
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    drop(listener);
    Ok(drain_tasks(tasks, shutdown.drain_timeout).await)
}

// ---------------------------------------------------------------------------
// Session 04 — TCP forwarder: connection identity, lifecycle, bounded
// concurrency, bounded upstream-connect timeout, RAII resource cleanup.
// ---------------------------------------------------------------------------

/// Process-local allocator for [`ConnectionId`].
///
/// Wraps a [`AtomicU64`] counter; allocating a new ID is a single
/// `fetch_add`. IDs are 1-indexed and never reused for the lifetime
/// of the process.
#[derive(Debug, Default)]
pub struct ConnectionIdAllocator {
    next: AtomicU64,
}

impl ConnectionIdAllocator {
    /// Create a new allocator starting at 0 (next issued ID is 1).
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }

    /// Allocate and return the next [`ConnectionId`].
    ///
    /// This is `&self` (not `&mut self`) so the allocator can live
    /// behind an `Arc` and be shared across spawned tasks / test
    /// harnesses.
    pub fn next_id(&self) -> ConnectionId {
        let raw = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        ConnectionId(raw)
    }
}

/// Strongly typed connection identity for the forwarder.
///
/// A `ConnectionId` is allocated by [`ConnectionIdAllocator::next_id`]
/// at the moment a downstream connection is accepted, and is then
/// attached to every log event and `ConnectionOutcome` for that
/// connection's lifetime. IDs are process-local and are not
/// persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn#{}", self.0)
    }
}

/// Configuration for a [`Forwarder`].
///
/// Values are validated by [`ForwardConfig::validate`] before the
/// forwarder is constructed. The defaults used by the development
/// binary are documented on each field.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Downstream listen address (what clients connect to).
    pub listen_addr: SocketAddr,
    /// Upstream service address (what the forwarder dials).
    pub upstream_addr: SocketAddr,
    /// Maximum concurrent in-flight relays. Must be `> 0`.
    pub max_connections: usize,
    /// Per-connection timeout for `TcpStream::connect(upstream_addr)`.
    /// Must be non-zero.
    pub connect_timeout: Duration,
    /// Shared activity-aware idle timeout for the established relay. Must be
    /// between [`MIN_RELAY_IDLE_TIMEOUT`] and [`MAX_RELAY_IDLE_TIMEOUT`].
    pub relay_idle_timeout: Duration,
}

impl ForwardConfig {
    /// Local-development defaults: `127.0.0.1:7000` →
    /// `127.0.0.1:8000`, 100 concurrent connections, 5 s connect
    /// timeout, and 60 s relay idle timeout.
    pub fn dev_defaults() -> Self {
        Self {
            listen_addr: DEFAULT_BIND_ADDR
                .parse()
                .expect("hardcoded default bind address is valid"),
            upstream_addr: DEFAULT_UPSTREAM_ADDR
                .parse()
                .expect("hardcoded default upstream address is valid"),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            relay_idle_timeout: DEFAULT_RELAY_IDLE_TIMEOUT,
        }
    }

    /// Validate `self`; return a structured error if any field is
    /// unusable.
    pub fn validate(&self) -> Result<(), ForwardConfigError> {
        if self.max_connections == 0 {
            return Err(ForwardConfigError::ZeroMaxConnections);
        }
        if self.connect_timeout.is_zero() {
            return Err(ForwardConfigError::ZeroConnectTimeout);
        }
        if self.relay_idle_timeout < MIN_RELAY_IDLE_TIMEOUT {
            return Err(ForwardConfigError::RelayIdleTimeoutTooSmall);
        }
        if self.relay_idle_timeout > MAX_RELAY_IDLE_TIMEOUT {
            return Err(ForwardConfigError::RelayIdleTimeoutTooLarge);
        }
        Ok(())
    }
}

/// Errors produced by [`ForwardConfig::validate`].
#[derive(Debug, PartialEq, Eq)]
pub enum ForwardConfigError {
    /// `max_connections` must be strictly greater than zero.
    ZeroMaxConnections,
    /// `connect_timeout` must be a positive [`Duration`].
    ZeroConnectTimeout,
    /// `relay_idle_timeout` must be at least one millisecond.
    RelayIdleTimeoutTooSmall,
    /// `relay_idle_timeout` must not exceed one hour.
    RelayIdleTimeoutTooLarge,
}

impl std::fmt::Display for ForwardConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardConfigError::ZeroMaxConnections => {
                f.write_str("max_connections must be greater than zero")
            }
            ForwardConfigError::ZeroConnectTimeout => {
                f.write_str("connect_timeout must be greater than zero")
            }
            ForwardConfigError::RelayIdleTimeoutTooSmall => {
                f.write_str("relay_idle_timeout must be at least 1 millisecond")
            }
            ForwardConfigError::RelayIdleTimeoutTooLarge => {
                f.write_str("relay_idle_timeout must not exceed 3600000 milliseconds")
            }
        }
    }
}

impl std::error::Error for ForwardConfigError {}

/// Connection lifecycle phase observed by the forwarder.
///
/// The forwarder logs one or more of these per connection. They are
/// also embedded in [`ConnectionOutcome`] so tests can assert the
/// observed path without parsing log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionLifecycle {
    /// The downstream TCP connection was accepted. Capacity was
    /// available; the per-connection task is now driving the relay.
    Accepted,
    /// The downstream TCP connection was accepted but rejected
    /// immediately because no concurrency permit was available. The
    /// downstream socket was shut down and the listener kept
    /// accepting.
    CapacityRejected,
    /// The downstream connection was accepted but the upstream TCP
    /// connect is in progress.
    ConnectingUpstream,
    /// The upstream TCP connect returned an I/O error (refused,
    /// timeout, unreachable, …). The downstream socket was shut down
    /// and the listener kept accepting.
    UpstreamConnectFailed,
    /// The upstream TCP connect did not complete within
    /// [`ForwardConfig::connect_timeout`]. The downstream socket was
    /// shut down and the listener kept accepting.
    UpstreamConnectTimeout,
    /// Both sockets are open and bounded bidirectional forwarding is running.
    Relaying,
    /// Bounded bidirectional forwarding returned an I/O error before either
    /// side cleanly closed.
    RelayIoFailed,
    /// Neither direction completed a write before the relay idle deadline.
    RelayIdleTimeout,
    /// Either side closed cleanly and the relay returned
    /// [`RelayStats`].
    Closed,
}

impl ConnectionLifecycle {
    /// Short identifier used as the `phase` field in log events.
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionLifecycle::Accepted => "accepted",
            ConnectionLifecycle::CapacityRejected => "capacity_rejected",
            ConnectionLifecycle::ConnectingUpstream => "connecting_upstream",
            ConnectionLifecycle::UpstreamConnectFailed => "upstream_connect_failed",
            ConnectionLifecycle::UpstreamConnectTimeout => "upstream_connect_timeout",
            ConnectionLifecycle::Relaying => "relaying",
            ConnectionLifecycle::RelayIoFailed => "relay_io_failed",
            ConnectionLifecycle::RelayIdleTimeout => "relay_idle_timeout",
            ConnectionLifecycle::Closed => "closed",
        }
    }
}

/// Per-connection failure categorized for logging and tests.
///
/// `ConnectionOutcome::Failure` carries one of these so callers can
/// distinguish "we never reached the upstream" from "the upstream
/// was unreachable" from "the upstream timed out" from "the relay
/// itself failed".
#[derive(Debug)]
pub enum ForwardError {
    /// No concurrency permit was available; the downstream socket
    /// was rejected before any upstream dial.
    CapacityExhausted,
    /// The upstream TCP connect returned an I/O error (refused,
    /// network unreachable, …). The downstream was shut down.
    UpstreamConnect { source: std::io::Error },
    /// The upstream TCP connect did not complete within
    /// `ForwardConfig::connect_timeout`. The downstream was shut
    /// down.
    UpstreamConnectTimeout,
    /// Bounded bidirectional forwarding returned an I/O error after both
    /// sockets were established.
    RelayIo {
        from: RelayDirection,
        to: RelayDirection,
        source: std::io::Error,
    },
    /// The established relay made no successful transfer before its shared
    /// activity deadline.
    RelayIdleTimeout { idle_timeout: Duration },
}

impl ForwardError {
    /// Stable category identifier used as the `error_category` field
    /// in log events.
    pub fn category(&self) -> &'static str {
        match self {
            ForwardError::CapacityExhausted => "capacity_exhausted",
            ForwardError::UpstreamConnect { .. } => "upstream_connect_failed",
            ForwardError::UpstreamConnectTimeout => "upstream_connect_timeout",
            ForwardError::RelayIo { .. } => "relay_io_failed",
            ForwardError::RelayIdleTimeout { .. } => "relay_idle_timeout",
        }
    }

    /// Last lifecycle phase the connection reached before the error.
    pub fn phase(&self) -> ConnectionLifecycle {
        match self {
            ForwardError::CapacityExhausted => ConnectionLifecycle::CapacityRejected,
            ForwardError::UpstreamConnect { .. } => ConnectionLifecycle::UpstreamConnectFailed,
            ForwardError::UpstreamConnectTimeout => ConnectionLifecycle::UpstreamConnectTimeout,
            ForwardError::RelayIo { .. } => ConnectionLifecycle::RelayIoFailed,
            ForwardError::RelayIdleTimeout { .. } => ConnectionLifecycle::RelayIdleTimeout,
        }
    }
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::CapacityExhausted => {
                f.write_str("forwarder at max_connections; connection rejected")
            }
            ForwardError::UpstreamConnect { source } => {
                write!(f, "upstream connect failed: {source}")
            }
            ForwardError::UpstreamConnectTimeout => f.write_str("upstream connect timed out"),
            ForwardError::RelayIo { from, to, source } => {
                write!(f, "relay I/O failed ({from} -> {to}): {source}")
            }
            ForwardError::RelayIdleTimeout { idle_timeout } => write!(
                f,
                "relay idle timeout after {} ms",
                idle_timeout.as_millis()
            ),
        }
    }
}

impl std::error::Error for ForwardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ForwardError::CapacityExhausted => None,
            ForwardError::UpstreamConnect { source } => Some(source),
            ForwardError::UpstreamConnectTimeout => None,
            ForwardError::RelayIo { source, .. } => Some(source),
            ForwardError::RelayIdleTimeout { .. } => None,
        }
    }
}

/// Per-connection result returned by
/// [`Forwarder::handle_connection`].
///
/// Tests use this to assert that a connection reached a particular
/// phase, forwarded a specific number of bytes in each direction,
/// and lasted a measurable amount of time. Production code can
/// ignore it; it is logged via the lifecycle struct.
#[derive(Debug)]
pub struct ConnectionOutcome {
    pub connection_id: ConnectionId,
    pub peer: SocketAddr,
    pub upstream: SocketAddr,
    pub outcome: Result<RelayStats, ForwardError>,
    pub duration: Duration,
}

impl ConnectionOutcome {
    /// The last lifecycle phase the connection reached. This is the
    /// success phase (`Closed`) on success, or the failure phase from
    /// [`ForwardError::phase`] on failure. Useful for tests that do
    /// not want to pattern-match on `Result`.
    pub fn final_phase(&self) -> ConnectionLifecycle {
        match &self.outcome {
            Ok(_) => ConnectionLifecycle::Closed,
            Err(err) => err.phase(),
        }
    }
}

/// Bounded, lifecycle-aware local TCP forwarder.
///
/// The forwarder binds a `TcpListener` on `config.listen_addr`. For
/// every accepted downstream connection:
///
/// 1. allocate a [`ConnectionId`];
/// 2. try to acquire a permit from an [`Arc<Semaphore>`] sized to
///    `config.max_connections`. If no permit is available the
///    downstream is shut down and the listener continues. This is
///    the documented capacity-exhaustion policy;
/// 3. dial the upstream under `config.connect_timeout`. Timeouts and
///    I/O errors are distinguished and surface as
///    [`ForwardError::UpstreamConnectTimeout`] or
///    [`ForwardError::UpstreamConnect`];
/// 4. forward raw bytes in both directions through fixed buffers under the
///    shared activity-aware idle deadline;
/// 5. release the semaphore permit (RAII via
///    [`OwnedSemaphorePermit`]).
///
/// Per-connection resources (`TcpStream`s, permit) are owned by the
/// per-connection task so dropping the task drops everything. There
/// are no detached child tasks.
pub struct Forwarder {
    config: ForwardConfig,
    semaphore: Arc<Semaphore>,
    ids: Arc<ConnectionIdAllocator>,
}

impl Forwarder {
    /// Construct a forwarder. Returns an error if `config` is not
    /// valid; the listener is not yet bound.
    pub fn new(config: ForwardConfig) -> Result<Self, ForwardConfigError> {
        config.validate()?;
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(config.max_connections)),
            ids: Arc::new(ConnectionIdAllocator::new()),
            config,
        })
    }

    /// Effective forwarder config (after defaults / validation).
    pub fn config(&self) -> &ForwardConfig {
        &self.config
    }

    /// Number of currently-available permits. Useful for tests and
    /// for the dev binary to log capacity headroom.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Bind the listener and run the forwarder until
    /// [`TcpListener::accept`] itself fails.
    pub async fn run(self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let local = listener.local_addr()?;
        info!(
            addr = %local,
            upstream = %self.config.upstream_addr,
            max_connections = self.config.max_connections,
            connect_timeout_ms = self.config.connect_timeout.as_millis() as u64,
            relay_idle_timeout_ms = self.config.relay_idle_timeout.as_millis() as u64,
            event = "forwarder_started",
            "forwarder bound"
        );

        let semaphore = self.semaphore;
        let ids = self.ids;
        let upstream_addr = self.config.upstream_addr;
        let timeouts = ForwardConnectionTimeouts {
            connect: self.config.connect_timeout,
            relay_idle: self.config.relay_idle_timeout,
        };

        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted?;
                    spawn_forwarder_task(
                        &mut tasks,
                        stream,
                        peer,
                        Arc::clone(&semaphore),
                        Arc::clone(&ids),
                        upstream_addr,
                        timeouts,
                    );
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }

    /// Runs until signalled, then drains supervised forwarder connections.
    pub async fn run_until_shutdown(
        self,
        signal: ShutdownSignal,
        shutdown: RuntimeShutdownConfig,
    ) -> std::io::Result<RuntimeShutdownOutcome> {
        validate_shutdown(shutdown)?;
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let semaphore = self.semaphore;
        let ids = self.ids;
        let upstream_addr = self.config.upstream_addr;
        let timeouts = ForwardConnectionTimeouts {
            connect: self.config.connect_timeout,
            relay_idle: self.config.relay_idle_timeout,
        };
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = signal.cancelled() => break,
                accepted = listener.accept() => {
                    let (stream, peer) = accepted?;
                    spawn_forwarder_task(
                        &mut tasks,
                        stream,
                        peer,
                        Arc::clone(&semaphore),
                        Arc::clone(&ids),
                        upstream_addr,
                        timeouts,
                    );
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        drop(listener);
        Ok(drain_tasks(tasks, shutdown.drain_timeout).await)
    }
}

#[derive(Debug, Clone, Copy)]
struct ForwardConnectionTimeouts {
    connect: Duration,
    relay_idle: Duration,
}

fn spawn_forwarder_task(
    tasks: &mut JoinSet<()>,
    mut stream: TcpStream,
    peer: SocketAddr,
    semaphore: Arc<Semaphore>,
    ids: Arc<ConnectionIdAllocator>,
    upstream_addr: SocketAddr,
    timeouts: ForwardConnectionTimeouts,
) {
    tasks.spawn(async move {
        let id = ids.next_id();
        let permit = match semaphore.try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                let _ = stream.shutdown().await;
                error!(
                    connection_id = %id,
                    peer = %peer,
                    upstream = %upstream_addr,
                    event = "connection_rejected_capacity",
                    "forwarder capacity unavailable; downstream closed"
                );
                return;
            }
        };
        let outcome = forward_handle_connection_with_idle_timeout(
            id,
            stream,
            peer,
            upstream_addr,
            timeouts.connect,
            timeouts.relay_idle,
            permit,
        )
        .await;
        log_outcome(&outcome, upstream_addr);
    });
}

/// Drive a single accepted downstream connection through the full
/// lifecycle on behalf of [`Forwarder`].
///
/// Exposed publicly so integration tests can drive the full lifecycle
/// without owning a listener. The function takes ownership of the
/// `permit`: dropping the function releases it.
pub async fn forward_handle_connection(
    connection_id: ConnectionId,
    downstream: TcpStream,
    peer: SocketAddr,
    upstream_addr: SocketAddr,
    connect_timeout: Duration,
    permit: OwnedSemaphorePermit,
) -> ConnectionOutcome {
    forward_handle_connection_with_idle_timeout(
        connection_id,
        downstream,
        peer,
        upstream_addr,
        connect_timeout,
        DEFAULT_RELAY_IDLE_TIMEOUT,
        permit,
    )
    .await
}

/// Drive one forwarder connection with an explicit established-relay idle
/// timeout while retaining the original [`forward_handle_connection`] API.
pub async fn forward_handle_connection_with_idle_timeout(
    connection_id: ConnectionId,
    mut downstream: TcpStream,
    peer: SocketAddr,
    upstream_addr: SocketAddr,
    connect_timeout: Duration,
    relay_idle_timeout: Duration,
    permit: OwnedSemaphorePermit,
) -> ConnectionOutcome {
    let started = Instant::now();

    info!(
        connection_id = %connection_id,
        peer = %peer,
        upstream = %upstream_addr,
        event = "upstream_connecting",
        "dialing upstream"
    );

    let upstream =
        match tokio::time::timeout(connect_timeout, TcpStream::connect(upstream_addr)).await {
            Ok(Ok(stream)) => {
                info!(
                    connection_id = %connection_id,
                    peer = %peer,
                    upstream = %upstream_addr,
                    event = "upstream_connected",
                    "upstream TCP connection established"
                );
                stream
            }
            Ok(Err(source)) => {
                error!(
                    connection_id = %connection_id,
                    peer = %peer,
                    upstream = %upstream_addr,
                    error = %source,
                    error_category = "upstream_connect_failed",
                    event = "upstream_connect_failed",
                    "upstream connect failed; shutting down downstream only"
                );
                let _ = downstream.shutdown().await;
                drop(permit);
                return ConnectionOutcome {
                    connection_id,
                    peer,
                    upstream: upstream_addr,
                    outcome: Err(ForwardError::UpstreamConnect { source }),
                    duration: started.elapsed(),
                };
            }
            Err(_elapsed) => {
                error!(
                    connection_id = %connection_id,
                    peer = %peer,
                    upstream = %upstream_addr,
                    error_category = "upstream_connect_timeout",
                    event = "upstream_connect_timeout",
                    "upstream connect timed out; shutting down downstream only"
                );
                let _ = downstream.shutdown().await;
                drop(permit);
                return ConnectionOutcome {
                    connection_id,
                    peer,
                    upstream: upstream_addr,
                    outcome: Err(ForwardError::UpstreamConnectTimeout),
                    duration: started.elapsed(),
                };
            }
        };

    info!(
        connection_id = %connection_id,
        peer = %peer,
        upstream = %upstream_addr,
        event = "relay_started",
        "starting bidirectional copy"
    );

    let relay_result =
        relay_bidirectional_with_id(connection_id, downstream, upstream, relay_idle_timeout).await;
    let outcome = match relay_result {
        Ok(stats) => {
            info!(
                connection_id = %connection_id,
                peer = %peer,
                upstream = %upstream_addr,
                bytes_downstream_to_upstream = stats.bytes_downstream_to_upstream,
                bytes_upstream_to_downstream = stats.bytes_upstream_to_downstream,
                event = "relay_completed",
                "relay completed"
            );
            Ok(stats)
        }
        Err(err) => {
            warn!(
                connection_id = %connection_id,
                peer = %peer,
                upstream = %upstream_addr,
                error = %err,
                event = "relay_failed",
                "relay copy failed"
            );
            Err(forward_from_relay(err))
        }
    };

    drop(permit);

    ConnectionOutcome {
        connection_id,
        peer,
        upstream: upstream_addr,
        outcome,
        duration: started.elapsed(),
    }
}

/// Runs the bounded relay body and attaches the connection ID to failure logs.
/// Conversion into [`ForwardError`] happens at the connection-lifecycle boundary.
async fn relay_bidirectional_with_id(
    connection_id: ConnectionId,
    downstream: TcpStream,
    upstream: TcpStream,
    idle_timeout: Duration,
) -> Result<RelayStats, RelayError> {
    let res = relay_bidirectional_with_idle_timeout(downstream, upstream, idle_timeout).await;
    match res {
        Ok(stats) => Ok(stats),
        Err(error) => {
            trace!(
                connection_id = %connection_id,
                error = %error,
                event = "relay_io_error",
                "bounded bidirectional relay failed"
            );
            Err(error)
        }
    }
}

/// Map a [`RelayError`] into the matching [`ForwardError`].
fn forward_from_relay(err: RelayError) -> ForwardError {
    match err {
        RelayError::UpstreamConnect { source, .. } => ForwardError::UpstreamConnect { source },
        RelayError::Copy { from, to, source } => ForwardError::RelayIo { from, to, source },
        RelayError::IdleTimeout { idle_timeout } => ForwardError::RelayIdleTimeout { idle_timeout },
    }
}

/// Log a structured summary of a finished connection outcome.
///
/// This is a free function (rather than a method on
/// `ConnectionOutcome`) so it can be called from the listener task
/// after `handle_connection` returns, while still keeping the
/// `Display` / `error_category` formatting close to the data.
fn log_outcome(outcome: &ConnectionOutcome, _upstream: SocketAddr) {
    let duration_ms = outcome.duration.as_millis() as u64;
    match &outcome.outcome {
        Ok(stats) => {
            info!(
                connection_id = %outcome.connection_id,
                peer = %outcome.peer,
                upstream = %outcome.upstream,
                phase = outcome.final_phase().as_str(),
                bytes_downstream_to_upstream = stats.bytes_downstream_to_upstream,
                bytes_upstream_to_downstream = stats.bytes_upstream_to_downstream,
                duration_ms,
                event = "connection_closed",
                "connection completed"
            );
        }
        Err(err) => {
            warn!(
                connection_id = %outcome.connection_id,
                peer = %outcome.peer,
                upstream = %outcome.upstream,
                phase = outcome.final_phase().as_str(),
                error_category = err.category(),
                error = %err,
                duration_ms,
                event = "connection_closed",
                "connection closed with failure"
            );
        }
    }
}

fn validate_shutdown(config: RuntimeShutdownConfig) -> std::io::Result<()> {
    config
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
}

async fn drain_tasks<T: 'static>(
    mut tasks: JoinSet<T>,
    drain_timeout: Duration,
) -> RuntimeShutdownOutcome {
    let deadline = tokio::time::Instant::now() + drain_timeout;
    let mut completed_tasks = 0;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(_)) => completed_tasks += 1,
            Ok(None) => break,
            Err(_) => {
                let aborted_tasks = tasks.len();
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return RuntimeShutdownOutcome::Forced {
                    completed_tasks,
                    aborted_tasks,
                };
            }
        }
    }
    RuntimeShutdownOutcome::Drained { completed_tasks }
}

mod admission;
pub mod agent_transport;
pub mod http_ingress;
mod http_rate_limit;
mod http_tls;
pub mod multiplex;
mod operations;
pub mod raw_ingress;
mod request_history;
mod runtime;
mod snapshot_runtime;
mod tls;

pub use http_ingress::{
    ConnectIngressConfig, Http2IngressConfig, HttpHostRoutes, HttpHostRoutesError, HttpHostname,
    HttpHostnameError, HttpIngressConfig, HttpIngressConfigError, HttpIngressError,
    HttpIngressExposurePolicy, HttpIngressOutcome, HttpIngressRuntime, HttpIngressStatus,
    HttpIngressStatusHandle, SignedAccessIngressConfig, WebSocketIngressConfig,
    MAX_CONNECT_SESSIONS, MAX_HTTP2_CONCURRENT_STREAMS, MAX_HTTP_HEADER_BYTES,
    MAX_HTTP_HOST_ROUTES, MAX_HTTP_REQUESTS_PER_CONNECTION, MAX_SIGNED_ACCESS_CLOCK_SKEW,
    MAX_SIGNED_ACCESS_TTL, MAX_WEBSOCKET_SESSIONS, MIN_HTTP_HEADER_BYTES,
};
pub use http_rate_limit::{
    HttpRequestRateLimitConfig, HttpRequestRateLimitConfigError, MAX_HTTP_RATE_LIMIT_IDLE,
    MAX_HTTP_RATE_LIMIT_PEERS, MAX_HTTP_REQUESTS_PER_SECOND, MAX_HTTP_REQUEST_BURST,
    MIN_HTTP_RATE_LIMIT_IDLE,
};
pub use http_tls::{
    PublicHttpProtocolPolicy, PublicTlsConfig, PublicTlsConfigError, PublicTlsReloadBootstrapError,
    PublicTlsReloadConfig, PublicTlsReloadRuntime, PUBLIC_HTTP1_ALPN, PUBLIC_HTTP2_ALPN,
};
pub use multiplex::{
    AuthorizationSourceStatus, EdgeAuthorizationStatus, EdgeSessionRouter, MultiplexedEdgeConfig,
    MultiplexedEdgeConfigError, MultiplexedEdgeRuntime, RouteError, RoutedStream,
    RoutedStreamCloseReason,
};
pub use operations::{
    EdgeOperationsConfig, EdgeOperationsConfigError, EdgeOperationsError, EdgeOperationsOutcome,
    MAX_OPERATIONS_CONNECTIONS, MAX_OPERATIONS_HEADERS, MAX_OPERATIONS_HEADER_BYTES,
    MIN_OPERATIONS_HEADER_BYTES,
};
pub use raw_ingress::{
    RawIngressConfigError, RawIngressExposurePolicy, RawIngressManagerConfig, RawIngressRoute,
    RawIngressRouteConfig, RawIngressRouteError, RawIngressRouteId, RawIngressRouteManager,
    RawIngressRouteState, RawIngressRouteStatus, RawIngressRouteTarget,
};
pub use request_history::{MAX_REQUEST_HISTORY_ENTRIES, MAX_REQUEST_HISTORY_RESPONSE_BYTES};
pub use runtime::{
    EdgeRuntime, EdgeRuntimeConfig, EdgeRuntimeConfigError, EdgeRuntimeError, EdgeRuntimeOutcome,
};
pub use snapshot_runtime::{
    SnapshotAwareEdgeRuntime, SnapshotAwareEdgeRuntimeError, SnapshotAwareEdgeRuntimeOutcome,
};
pub use tls::{
    bootstrap_registration_from_snapshot_service, EdgeRegistrationPolicy,
    EdgeRegistrationPolicyError, EdgeTlsConfig, EdgeTlsConfigError, EdgeTlsReloadBootstrapError,
    EdgeTlsReloadConfig, EdgeTlsReloadRuntime, EdgeTransportSecurity,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test for `ConnectionId`: allocator yields unique
    /// monotonic IDs.
    #[test]
    fn connection_id_allocator_is_monotonic() {
        let alloc = ConnectionIdAllocator::new();
        let a = alloc.next_id();
        let b = alloc.next_id();
        let c = alloc.next_id();
        assert_eq!(a, ConnectionId(1));
        assert_eq!(b, ConnectionId(2));
        assert_eq!(c, ConnectionId(3));
        assert_eq!(a.to_string(), "conn#1");
    }

    /// `ForwardConfig::dev_defaults()` is valid.
    #[test]
    fn dev_defaults_validate() {
        ForwardConfig::dev_defaults()
            .validate()
            .expect("dev defaults must be valid");
    }

    /// Echo admission defaults are finite and invalid bounds fail before bind.
    #[test]
    fn echo_config_is_strict_and_bounded() {
        EchoConfig::default()
            .validate()
            .expect("echo defaults must be valid");

        let config = EchoConfig {
            max_connections: 0,
            ..EchoConfig::default()
        };
        assert_eq!(config.validate(), Err(EchoConfigError::ZeroMaxConnections));

        let config = EchoConfig {
            max_connections: Semaphore::MAX_PERMITS + 1,
            ..EchoConfig::default()
        };
        assert_eq!(config.validate(), Err(EchoConfigError::TooManyConnections));

        let config = EchoConfig {
            max_connections: 1,
            idle_timeout: Duration::ZERO,
        };
        assert_eq!(config.validate(), Err(EchoConfigError::IdleTimeoutTooSmall));

        let config = EchoConfig {
            idle_timeout: MAX_RELAY_IDLE_TIMEOUT + Duration::from_millis(1),
            ..config
        };
        assert_eq!(config.validate(), Err(EchoConfigError::IdleTimeoutTooLarge));
    }

    /// `ForwardConfig::validate` rejects a zero-capacity forwarder.
    #[test]
    fn validate_rejects_zero_max_connections() {
        let cfg = ForwardConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            upstream_addr: "127.0.0.1:1".parse().unwrap(),
            max_connections: 0,
            connect_timeout: Duration::from_secs(5),
            relay_idle_timeout: DEFAULT_RELAY_IDLE_TIMEOUT,
        };
        assert_eq!(cfg.validate(), Err(ForwardConfigError::ZeroMaxConnections));
    }

    /// `ForwardConfig::validate` rejects a zero connect timeout.
    #[test]
    fn validate_rejects_zero_connect_timeout() {
        let cfg = ForwardConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            upstream_addr: "127.0.0.1:1".parse().unwrap(),
            max_connections: 16,
            connect_timeout: Duration::ZERO,
            relay_idle_timeout: DEFAULT_RELAY_IDLE_TIMEOUT,
        };
        assert_eq!(cfg.validate(), Err(ForwardConfigError::ZeroConnectTimeout));
    }

    /// `ForwardConfig::validate` enforces the documented idle-timeout range.
    #[test]
    fn validate_rejects_relay_idle_timeout_outside_bounds() {
        let mut cfg = ForwardConfig::dev_defaults();
        cfg.relay_idle_timeout = Duration::ZERO;
        assert_eq!(
            cfg.validate(),
            Err(ForwardConfigError::RelayIdleTimeoutTooSmall)
        );

        cfg.relay_idle_timeout = MAX_RELAY_IDLE_TIMEOUT + Duration::from_millis(1);
        assert_eq!(
            cfg.validate(),
            Err(ForwardConfigError::RelayIdleTimeoutTooLarge)
        );
    }

    /// `ForwardError::category` and `phase` cover all variants.
    #[test]
    fn forward_error_categories_and_phases_are_stable() {
        let cap = ForwardError::CapacityExhausted;
        assert_eq!(cap.category(), "capacity_exhausted");
        assert_eq!(cap.phase(), ConnectionLifecycle::CapacityRejected);

        let io = std::io::Error::other("x");
        let up = ForwardError::UpstreamConnect { source: io };
        assert_eq!(up.category(), "upstream_connect_failed");
        assert_eq!(up.phase(), ConnectionLifecycle::UpstreamConnectFailed);

        let to = ForwardError::UpstreamConnectTimeout;
        assert_eq!(to.category(), "upstream_connect_timeout");
        assert_eq!(to.phase(), ConnectionLifecycle::UpstreamConnectTimeout);

        let relay = ForwardError::RelayIo {
            from: RelayDirection::Downstream,
            to: RelayDirection::Upstream,
            source: std::io::Error::other("x"),
        };
        assert_eq!(relay.category(), "relay_io_failed");
        assert_eq!(relay.phase(), ConnectionLifecycle::RelayIoFailed);

        let idle = ForwardError::RelayIdleTimeout {
            idle_timeout: DEFAULT_RELAY_IDLE_TIMEOUT,
        };
        assert_eq!(idle.category(), "relay_idle_timeout");
        assert_eq!(idle.phase(), ConnectionLifecycle::RelayIdleTimeout);
    }

    /// Session 03 `RelayStats` default is still zero.
    #[test]
    fn relay_stats_default_is_zero() {
        let stats = RelayStats::default();
        assert_eq!(stats.bytes_downstream_to_upstream, 0);
        assert_eq!(stats.bytes_upstream_to_downstream, 0);
    }

    /// Session 03 `RelayError` display keeps the address out of
    /// payload content.
    #[test]
    fn relay_error_display_does_not_leak_payloads() {
        let err = RelayError::UpstreamConnect {
            upstream: "127.0.0.1:1".parse().unwrap(),
            source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("upstream"));
        assert!(rendered.contains("refused"));
    }
}
