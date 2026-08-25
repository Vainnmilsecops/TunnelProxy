//! Bounded in-memory request-rate admission for public HTTP ingress.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TOKEN_SCALE: u128 = 1_000_000_000;
const PEER_CLEANUP_BATCH: usize = 64;

pub const MAX_HTTP_REQUESTS_PER_SECOND: u64 = 1_000_000;
pub const MAX_HTTP_REQUEST_BURST: u64 = 1_000_000;
pub const MAX_HTTP_RATE_LIMIT_PEERS: usize = 65_536;
pub const MIN_HTTP_RATE_LIMIT_IDLE: Duration = Duration::from_millis(1);
pub const MAX_HTTP_RATE_LIMIT_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRequestRateLimitConfig {
    pub global_requests_per_second: u64,
    pub global_burst: u64,
    pub per_ip_requests_per_second: u64,
    pub per_ip_burst: u64,
    pub max_tracked_ips: usize,
    pub peer_idle_ttl: Duration,
}

impl Default for HttpRequestRateLimitConfig {
    fn default() -> Self {
        Self {
            global_requests_per_second: 100,
            global_burst: 200,
            per_ip_requests_per_second: 20,
            per_ip_burst: 40,
            max_tracked_ips: 4_096,
            peer_idle_ttl: Duration::from_secs(5 * 60),
        }
    }
}

impl HttpRequestRateLimitConfig {
    pub fn validate(self) -> Result<(), HttpRequestRateLimitConfigError> {
        validate_quota(
            self.global_requests_per_second,
            self.global_burst,
            HttpRequestRateLimitConfigError::InvalidGlobalRate,
            HttpRequestRateLimitConfigError::InvalidGlobalBurst,
        )?;
        validate_quota(
            self.per_ip_requests_per_second,
            self.per_ip_burst,
            HttpRequestRateLimitConfigError::InvalidPerIpRate,
            HttpRequestRateLimitConfigError::InvalidPerIpBurst,
        )?;
        if self.per_ip_requests_per_second > self.global_requests_per_second {
            return Err(HttpRequestRateLimitConfigError::PerIpRateExceedsGlobal);
        }
        if self.per_ip_burst > self.global_burst {
            return Err(HttpRequestRateLimitConfigError::PerIpBurstExceedsGlobal);
        }
        if self.max_tracked_ips == 0 || self.max_tracked_ips > MAX_HTTP_RATE_LIMIT_PEERS {
            return Err(HttpRequestRateLimitConfigError::InvalidTrackedIpLimit);
        }
        if self.peer_idle_ttl < MIN_HTTP_RATE_LIMIT_IDLE
            || self.peer_idle_ttl > MAX_HTTP_RATE_LIMIT_IDLE
        {
            return Err(HttpRequestRateLimitConfigError::InvalidPeerIdleTtl);
        }
        Ok(())
    }
}

fn validate_quota(
    rate: u64,
    burst: u64,
    invalid_rate: HttpRequestRateLimitConfigError,
    invalid_burst: HttpRequestRateLimitConfigError,
) -> Result<(), HttpRequestRateLimitConfigError> {
    if rate == 0 || rate > MAX_HTTP_REQUESTS_PER_SECOND {
        return Err(invalid_rate);
    }
    if burst < rate || burst > MAX_HTTP_REQUEST_BURST {
        return Err(invalid_burst);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestRateLimitConfigError {
    InvalidGlobalRate,
    InvalidGlobalBurst,
    InvalidPerIpRate,
    InvalidPerIpBurst,
    PerIpRateExceedsGlobal,
    PerIpBurstExceedsGlobal,
    InvalidTrackedIpLimit,
    InvalidPeerIdleTtl,
}

impl std::fmt::Display for HttpRequestRateLimitConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidGlobalRate => {
                "global HTTP request rate must be between 1 and 1000000 per second"
            }
            Self::InvalidGlobalBurst => {
                "global HTTP burst must be at least its rate and no greater than 1000000"
            }
            Self::InvalidPerIpRate => {
                "per-IP HTTP request rate must be between 1 and 1000000 per second"
            }
            Self::InvalidPerIpBurst => {
                "per-IP HTTP burst must be at least its rate and no greater than 1000000"
            }
            Self::PerIpRateExceedsGlobal => {
                "per-IP HTTP request rate cannot exceed the global rate"
            }
            Self::PerIpBurstExceedsGlobal => "per-IP HTTP burst cannot exceed the global burst",
            Self::InvalidTrackedIpLimit => {
                "tracked HTTP rate-limit IPs must be between 1 and 65536"
            }
            Self::InvalidPeerIdleTtl => {
                "HTTP rate-limit peer idle TTL must be between 1 ms and 24 hours"
            }
        })
    }
}

impl std::error::Error for HttpRequestRateLimitConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpRateLimitRejection {
    Global { retry_after: Duration },
    PerIp { retry_after: Duration },
    PeerTableFull { retry_after: Duration },
}

impl HttpRateLimitRejection {
    pub(crate) const fn retry_after(self) -> Duration {
        match self {
            Self::Global { retry_after }
            | Self::PerIp { retry_after }
            | Self::PeerTableFull { retry_after } => retry_after,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpRateLimiterStatus {
    pub(crate) tracked_peer_ips: usize,
    pub(crate) peak_tracked_peer_ips: usize,
}

#[derive(Clone)]
pub(crate) struct HttpRequestRateLimiter {
    config: HttpRequestRateLimitConfig,
    inner: Arc<Mutex<RateLimiterState>>,
}

impl HttpRequestRateLimiter {
    pub(crate) fn new(config: HttpRequestRateLimitConfig) -> Self {
        Self::at(config, Instant::now())
    }

    fn at(config: HttpRequestRateLimitConfig, now: Instant) -> Self {
        debug_assert!(config.validate().is_ok());
        Self {
            config,
            inner: Arc::new(Mutex::new(RateLimiterState {
                global: TokenBucket::new(
                    config.global_requests_per_second,
                    config.global_burst,
                    now,
                ),
                peers: HashMap::new(),
                peer_order: VecDeque::new(),
                peak_tracked_peer_ips: 0,
            })),
        }
    }

    pub(crate) fn try_admit(&self, peer: IpAddr) -> Result<(), HttpRateLimitRejection> {
        self.try_admit_at(peer, Instant::now())
    }

    fn try_admit_at(&self, peer: IpAddr, now: Instant) -> Result<(), HttpRateLimitRejection> {
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        state.global.refill(now);
        if let Some(retry_after) = state.global.retry_after() {
            return Err(HttpRateLimitRejection::Global { retry_after });
        }

        if !state.peers.contains_key(&peer) {
            cleanup_idle_peers(&mut state, now, self.config.peer_idle_ttl);
            if state.peers.len() >= self.config.max_tracked_ips {
                return Err(HttpRateLimitRejection::PeerTableFull {
                    retry_after: self.config.peer_idle_ttl.min(Duration::from_secs(60)),
                });
            }
            state.peers.insert(
                peer,
                PeerBucket {
                    bucket: TokenBucket::new(
                        self.config.per_ip_requests_per_second,
                        self.config.per_ip_burst,
                        now,
                    ),
                    last_seen: now,
                },
            );
            state.peer_order.push_back(peer);
            state.peak_tracked_peer_ips = state.peak_tracked_peer_ips.max(state.peers.len());
        }

        let peer_bucket = state
            .peers
            .get_mut(&peer)
            .expect("peer bucket was inserted before admission");
        peer_bucket.bucket.refill(now);
        peer_bucket.last_seen = now;
        let peer_retry = peer_bucket.bucket.retry_after();

        if let Some(retry_after) = peer_retry {
            return Err(HttpRateLimitRejection::PerIp { retry_after });
        }

        state.global.consume();
        state
            .peers
            .get_mut(&peer)
            .expect("peer bucket remains present")
            .bucket
            .consume();
        Ok(())
    }

    pub(crate) fn status(&self) -> HttpRateLimiterStatus {
        let state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        HttpRateLimiterStatus {
            tracked_peer_ips: state.peers.len(),
            peak_tracked_peer_ips: state.peak_tracked_peer_ips,
        }
    }
}

struct RateLimiterState {
    global: TokenBucket,
    peers: HashMap<IpAddr, PeerBucket>,
    peer_order: VecDeque<IpAddr>,
    peak_tracked_peer_ips: usize,
}

struct PeerBucket {
    bucket: TokenBucket,
    last_seen: Instant,
}

fn cleanup_idle_peers(state: &mut RateLimiterState, now: Instant, idle_ttl: Duration) {
    let candidates = state.peer_order.len().min(PEER_CLEANUP_BATCH);
    for _ in 0..candidates {
        let Some(peer) = state.peer_order.pop_front() else {
            break;
        };
        let expired = state
            .peers
            .get(&peer)
            .is_some_and(|bucket| now.saturating_duration_since(bucket.last_seen) >= idle_ttl);
        if expired {
            state.peers.remove(&peer);
        } else {
            state.peer_order.push_back(peer);
        }
    }
}

struct TokenBucket {
    rate: u64,
    capacity: u128,
    tokens: u128,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: u64, burst: u64, now: Instant) -> Self {
        let capacity = u128::from(burst) * TOKEN_SCALE;
        Self {
            rate,
            capacity,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        if now <= self.last_refill {
            return;
        }
        let elapsed = now.saturating_duration_since(self.last_refill);
        let replenished = elapsed.as_nanos().saturating_mul(u128::from(self.rate));
        self.tokens = self.tokens.saturating_add(replenished).min(self.capacity);
        self.last_refill = now;
    }

    fn retry_after(&self) -> Option<Duration> {
        if self.tokens >= TOKEN_SCALE {
            return None;
        }
        let deficit = TOKEN_SCALE - self.tokens;
        let rate = u128::from(self.rate);
        let nanos = deficit.saturating_add(rate - 1) / rate;
        Some(Duration::from_nanos(
            u64::try_from(nanos).unwrap_or(u64::MAX),
        ))
    }

    fn consume(&mut self) {
        debug_assert!(self.tokens >= TOKEN_SCALE);
        self.tokens = self.tokens.saturating_sub(TOKEN_SCALE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HttpRequestRateLimitConfig {
        HttpRequestRateLimitConfig {
            global_requests_per_second: 2,
            global_burst: 2,
            per_ip_requests_per_second: 1,
            per_ip_burst: 1,
            max_tracked_ips: 2,
            peer_idle_ttl: Duration::from_secs(5),
        }
    }

    #[test]
    fn configuration_is_strict_and_bounded() {
        let mut candidate = HttpRequestRateLimitConfig::default();
        assert!(candidate.validate().is_ok());
        candidate.global_requests_per_second = 0;
        assert_eq!(
            candidate.validate(),
            Err(HttpRequestRateLimitConfigError::InvalidGlobalRate)
        );
        candidate = HttpRequestRateLimitConfig::default();
        candidate.per_ip_burst = candidate.per_ip_requests_per_second - 1;
        assert_eq!(
            candidate.validate(),
            Err(HttpRequestRateLimitConfigError::InvalidPerIpBurst)
        );
        candidate = HttpRequestRateLimitConfig::default();
        candidate.max_tracked_ips = MAX_HTTP_RATE_LIMIT_PEERS + 1;
        assert_eq!(
            candidate.validate(),
            Err(HttpRequestRateLimitConfigError::InvalidTrackedIpLimit)
        );
    }

    #[test]
    fn per_ip_buckets_are_isolated_and_refill_without_sleeping() {
        let now = Instant::now();
        let limiter = HttpRequestRateLimiter::at(config(), now);
        let first = IpAddr::from([127, 0, 0, 1]);
        let second = IpAddr::from([127, 0, 0, 2]);
        assert_eq!(limiter.try_admit_at(first, now), Ok(()));
        assert!(matches!(
            limiter.try_admit_at(first, now),
            Err(HttpRateLimitRejection::PerIp { .. })
        ));
        assert_eq!(limiter.try_admit_at(second, now), Ok(()));
        assert_eq!(
            limiter.try_admit_at(first, now + Duration::from_secs(1)),
            Ok(())
        );
    }

    #[test]
    fn rejected_peer_does_not_consume_a_global_token() {
        let now = Instant::now();
        let limiter = HttpRequestRateLimiter::at(config(), now);
        let first = IpAddr::from([127, 0, 0, 1]);
        let second = IpAddr::from([127, 0, 0, 2]);
        assert_eq!(limiter.try_admit_at(first, now), Ok(()));
        assert!(matches!(
            limiter.try_admit_at(first, now),
            Err(HttpRateLimitRejection::PerIp { .. })
        ));
        assert_eq!(limiter.try_admit_at(second, now), Ok(()));
        assert!(matches!(
            limiter.try_admit_at(second, now),
            Err(HttpRateLimitRejection::Global { .. }) | Err(HttpRateLimitRejection::PerIp { .. })
        ));
    }

    #[test]
    fn global_bucket_limits_distinct_peers_and_reports_retry_time() {
        let now = Instant::now();
        let mut candidate = config();
        candidate.max_tracked_ips = 3;
        let limiter = HttpRequestRateLimiter::at(candidate, now);
        assert_eq!(
            limiter.try_admit_at(IpAddr::from([10, 0, 0, 1]), now),
            Ok(())
        );
        assert_eq!(
            limiter.try_admit_at(IpAddr::from([10, 0, 0, 2]), now),
            Ok(())
        );
        let rejection = limiter
            .try_admit_at(IpAddr::from([10, 0, 0, 3]), now)
            .unwrap_err();
        assert_eq!(
            rejection,
            HttpRateLimitRejection::Global {
                retry_after: Duration::from_millis(500)
            }
        );
    }

    #[test]
    fn peer_table_is_bounded_and_idle_entries_are_reclaimed_in_batches() {
        let now = Instant::now();
        let mut candidate = config();
        candidate.global_requests_per_second = 10;
        candidate.global_burst = 10;
        let limiter = HttpRequestRateLimiter::at(candidate, now);
        assert_eq!(
            limiter.try_admit_at(IpAddr::from([10, 0, 0, 1]), now),
            Ok(())
        );
        assert_eq!(
            limiter.try_admit_at(IpAddr::from([10, 0, 0, 2]), now),
            Ok(())
        );
        assert!(matches!(
            limiter.try_admit_at(IpAddr::from([10, 0, 0, 3]), now),
            Err(HttpRateLimitRejection::PeerTableFull { .. })
        ));
        assert_eq!(limiter.status().tracked_peer_ips, 2);
        assert_eq!(
            limiter.try_admit_at(IpAddr::from([10, 0, 0, 3]), now + Duration::from_secs(5)),
            Ok(())
        );
        let status = limiter.status();
        assert_eq!(status.tracked_peer_ips, 1);
        assert_eq!(status.peak_tracked_peer_ips, 2);
    }

    #[test]
    fn refill_math_saturates_at_capacity_and_backward_time_adds_nothing() {
        let now = Instant::now();
        let mut bucket =
            TokenBucket::new(MAX_HTTP_REQUESTS_PER_SECOND, MAX_HTTP_REQUEST_BURST, now);
        bucket.consume();
        bucket.refill(now + MAX_HTTP_RATE_LIMIT_IDLE);
        assert_eq!(bucket.tokens, bucket.capacity);
        bucket.consume();
        let tokens = bucket.tokens;
        bucket.refill(now);
        assert_eq!(bucket.tokens, tokens);
    }
}
