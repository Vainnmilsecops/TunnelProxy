//! Bounded, redacted, process-local HTTPS request history.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

pub const MAX_REQUEST_HISTORY_ENTRIES: usize = 128;
pub const MAX_REQUEST_HISTORY_PATH_BYTES: usize = 2 * 1024;
pub const MAX_REQUEST_HISTORY_METHOD_BYTES: usize = 32;
pub const MAX_REQUEST_HISTORY_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequestHistoryProtocol {
    Http1,
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequestHistoryOutcome {
    Forwarded,
    LocalUnavailable,
    Timeout,
    Rejected,
}

impl RequestHistoryOutcome {
    pub(crate) const ALL: [Self; 4] = [
        Self::Forwarded,
        Self::LocalUnavailable,
        Self::Timeout,
        Self::Rejected,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::LocalUnavailable => "local_unavailable",
            Self::Timeout => "timeout",
            Self::Rejected => "rejected",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Forwarded => 0,
            Self::LocalUnavailable => 1,
            Self::Timeout => 2,
            Self::Rejected => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RequestHistoryEntry {
    pub request_id: u64,
    pub hostname: String,
    pub tunnel_id: String,
    pub method: String,
    pub path: String,
    pub path_truncated: bool,
    pub protocol: RequestHistoryProtocol,
    pub response_status: u16,
    pub response_header_ms: u64,
    pub outcome: RequestHistoryOutcome,
}

#[derive(Debug, Clone)]
pub(crate) struct RequestHistorySnapshot {
    pub capacity: usize,
    pub recorded_total: u64,
    pub evicted_total: u64,
    pub sequence_exhaustions: u64,
    pub outcomes: [u64; 4],
    pub entries: Vec<RequestHistoryEntry>,
}

impl RequestHistorySnapshot {
    pub(crate) fn outcome_count(&self, outcome: RequestHistoryOutcome) -> u64 {
        self.outcomes[outcome.index()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestHistoryConfigError {
    InvalidCapacity,
}

impl std::fmt::Display for RequestHistoryConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("request history capacity must be between 1 and 128")
    }
}

impl std::error::Error for RequestHistoryConfigError {}

#[derive(Debug)]
struct RequestHistoryState {
    capacity: usize,
    next_id: u64,
    recorded_total: u64,
    evicted_total: u64,
    sequence_exhaustions: u64,
    outcomes: [u64; 4],
    entries: VecDeque<RequestHistoryEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct RequestHistory {
    state: Arc<Mutex<RequestHistoryState>>,
}

impl RequestHistory {
    pub(crate) fn new(capacity: usize) -> Result<Self, RequestHistoryConfigError> {
        if !(1..=MAX_REQUEST_HISTORY_ENTRIES).contains(&capacity) {
            return Err(RequestHistoryConfigError::InvalidCapacity);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(RequestHistoryState {
                capacity,
                next_id: 1,
                recorded_total: 0,
                evicted_total: 0,
                sequence_exhaustions: 0,
                outcomes: [0; 4],
                entries: VecDeque::with_capacity(capacity),
            })),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        &self,
        hostname: &str,
        tunnel_id: &str,
        method: &str,
        path: &str,
        protocol: RequestHistoryProtocol,
        started: Instant,
    ) -> RequestHistoryPending {
        let (path, path_truncated) = bounded_path(path);
        RequestHistoryPending {
            history: self.clone(),
            hostname: hostname.to_owned(),
            tunnel_id: tunnel_id.to_owned(),
            method: bounded_method(method),
            path,
            path_truncated,
            protocol,
            started,
            outcome: RequestHistoryOutcome::Forwarded,
        }
    }

    fn record(&self, pending: RequestHistoryPending, response_status: u16, elapsed: Duration) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.next_id == 0 {
            state.sequence_exhaustions = state.sequence_exhaustions.saturating_add(1);
            return;
        }
        let request_id = state.next_id;
        state.next_id = request_id.checked_add(1).unwrap_or(0);
        if state.entries.len() == state.capacity {
            state.entries.pop_front();
            state.evicted_total = state.evicted_total.saturating_add(1);
        }
        state.recorded_total = state.recorded_total.saturating_add(1);
        state.outcomes[pending.outcome.index()] =
            state.outcomes[pending.outcome.index()].saturating_add(1);
        state.entries.push_back(RequestHistoryEntry {
            request_id,
            hostname: pending.hostname,
            tunnel_id: pending.tunnel_id,
            method: pending.method,
            path: pending.path,
            path_truncated: pending.path_truncated,
            protocol: pending.protocol,
            response_status,
            response_header_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
            outcome: pending.outcome,
        });
    }

    pub(crate) fn snapshot(&self) -> RequestHistorySnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RequestHistorySnapshot {
            capacity: state.capacity,
            recorded_total: state.recorded_total,
            evicted_total: state.evicted_total,
            sequence_exhaustions: state.sequence_exhaustions,
            outcomes: state.outcomes,
            entries: state.entries.iter().rev().cloned().collect(),
        }
    }
}

pub(crate) struct RequestHistoryPending {
    history: RequestHistory,
    hostname: String,
    tunnel_id: String,
    method: String,
    path: String,
    path_truncated: bool,
    protocol: RequestHistoryProtocol,
    started: Instant,
    outcome: RequestHistoryOutcome,
}

impl RequestHistoryPending {
    pub(crate) fn set_outcome(&mut self, outcome: RequestHistoryOutcome) {
        self.outcome = outcome;
    }

    pub(crate) fn finish(self, response_status: u16) {
        let elapsed = self.started.elapsed();
        let history = self.history.clone();
        history.record(self, response_status, elapsed);
    }
}

fn bounded_method(method: &str) -> String {
    if method.len() <= MAX_REQUEST_HISTORY_METHOD_BYTES {
        method.to_owned()
    } else {
        "OTHER".to_owned()
    }
}

fn bounded_path(path: &str) -> (String, bool) {
    if path.len() <= MAX_REQUEST_HISTORY_PATH_BYTES {
        return (path.to_owned(), false);
    }
    let mut end = MAX_REQUEST_HISTORY_PATH_BYTES;
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    (path[..end].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(history: &RequestHistory, path: &str, outcome: RequestHistoryOutcome) {
        let mut pending = history.begin(
            "demo.example.test",
            "tunnel-dev",
            "GET",
            path,
            RequestHistoryProtocol::Http1,
            Instant::now(),
        );
        pending.set_outcome(outcome);
        pending.finish(200);
    }

    #[test]
    fn history_is_newest_first_bounded_and_counts_eviction() {
        let history = RequestHistory::new(2).unwrap();
        record(&history, "/one", RequestHistoryOutcome::Forwarded);
        record(&history, "/two", RequestHistoryOutcome::LocalUnavailable);
        record(&history, "/three", RequestHistoryOutcome::Rejected);

        let snapshot = history.snapshot();
        assert_eq!(snapshot.recorded_total, 3);
        assert_eq!(snapshot.evicted_total, 1);
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0].request_id, 3);
        assert_eq!(snapshot.entries[0].path, "/three");
        assert_eq!(snapshot.entries[1].request_id, 2);
        assert_eq!(snapshot.outcome_count(RequestHistoryOutcome::Forwarded), 1);
        assert_eq!(snapshot.outcome_count(RequestHistoryOutcome::Rejected), 1);
    }

    #[test]
    fn metadata_is_bounded_and_sequence_exhaustion_fails_closed() {
        let history = RequestHistory::new(1).unwrap();
        let long_path = format!("/{}é", "x".repeat(MAX_REQUEST_HISTORY_PATH_BYTES));
        let pending = history.begin(
            "demo.example.test",
            "tunnel-dev",
            &"M".repeat(MAX_REQUEST_HISTORY_METHOD_BYTES + 1),
            &long_path,
            RequestHistoryProtocol::Http2,
            Instant::now(),
        );
        assert_eq!(pending.method, "OTHER");
        assert!(pending.path_truncated);
        assert!(pending.path.len() <= MAX_REQUEST_HISTORY_PATH_BYTES);
        pending.finish(204);

        history
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next_id = 0;
        record(&history, "/ignored", RequestHistoryOutcome::Timeout);
        let snapshot = history.snapshot();
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.sequence_exhaustions, 1);
    }

    #[test]
    fn capacity_is_strict() {
        assert!(RequestHistory::new(0).is_err());
        assert!(RequestHistory::new(MAX_REQUEST_HISTORY_ENTRIES + 1).is_err());
    }
}
