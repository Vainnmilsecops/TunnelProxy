//! Fixed-cardinality process-local telemetry for multiplexed transports.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::BoundedQueueTelemetry;

/// Cloneable atomic telemetry shared by multiplexed sessions in one process.
#[derive(Clone, Debug, Default)]
pub struct MultiplexTelemetry {
    inner: Arc<MultiplexTelemetryInner>,
    data_queue: BoundedQueueTelemetry,
}

#[derive(Debug, Default)]
struct MultiplexTelemetryInner {
    active_streams: AtomicU64,
    peak_active_streams: AtomicU64,
    sent_data_frames: AtomicU64,
    sent_data_bytes: AtomicU64,
    received_data_frames: AtomicU64,
    received_data_bytes: AtomicU64,
    flow_control_resets: AtomicU64,
    control_burst_yields: AtomicU64,
}

/// Point-in-time multiplexed transport metrics with no identity dimensions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MultiplexTelemetrySnapshot {
    pub active_streams: u64,
    pub peak_active_streams: u64,
    pub sent_data_frames: u64,
    pub sent_data_bytes: u64,
    pub received_data_frames: u64,
    pub received_data_bytes: u64,
    pub data_admission_waits: u64,
    pub data_pipeline_frames: u64,
    pub peak_data_pipeline_frames: u64,
    pub flow_control_resets: u64,
    pub control_burst_yields: u64,
}

impl MultiplexTelemetry {
    pub fn snapshot(&self) -> MultiplexTelemetrySnapshot {
        let queue = self.data_queue.snapshot();
        MultiplexTelemetrySnapshot {
            active_streams: self.inner.active_streams.load(Ordering::Relaxed),
            peak_active_streams: self.inner.peak_active_streams.load(Ordering::Relaxed),
            sent_data_frames: self.inner.sent_data_frames.load(Ordering::Relaxed),
            sent_data_bytes: self.inner.sent_data_bytes.load(Ordering::Relaxed),
            received_data_frames: self.inner.received_data_frames.load(Ordering::Relaxed),
            received_data_bytes: self.inner.received_data_bytes.load(Ordering::Relaxed),
            data_admission_waits: to_u64(queue.admission_waits),
            data_pipeline_frames: to_u64(queue.admitted_items),
            peak_data_pipeline_frames: to_u64(queue.peak_admitted_items),
            flow_control_resets: self.inner.flow_control_resets.load(Ordering::Relaxed),
            control_burst_yields: self.inner.control_burst_yields.load(Ordering::Relaxed),
        }
    }

    pub fn data_queue_telemetry(&self) -> BoundedQueueTelemetry {
        self.data_queue.clone()
    }

    pub fn stream_opened(&self) -> MultiplexStreamGuard {
        let active = self.inner.active_streams.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&self.inner.peak_active_streams, active);
        MultiplexStreamGuard {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn data_sent(&self, bytes: usize) {
        self.inner.sent_data_frames.fetch_add(1, Ordering::Relaxed);
        self.inner
            .sent_data_bytes
            .fetch_add(to_u64(bytes), Ordering::Relaxed);
    }

    pub fn data_received(&self, bytes: usize) {
        self.inner
            .received_data_frames
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .received_data_bytes
            .fetch_add(to_u64(bytes), Ordering::Relaxed);
    }

    pub fn flow_control_reset(&self) {
        self.inner
            .flow_control_resets
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn control_burst_yielded(&self) {
        self.inner
            .control_burst_yields
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Active-stream gauge guard. Dropping it releases exactly one stream slot.
pub struct MultiplexStreamGuard {
    inner: Arc<MultiplexTelemetryInner>,
}

impl Drop for MultiplexStreamGuard {
    fn drop(&mut self) {
        self.inner.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

fn update_peak(peak: &AtomicU64, candidate: u64) {
    let mut current = peak.load(Ordering::Relaxed);
    while candidate > current {
        match peak.compare_exchange_weak(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_monotonic_and_stream_gauges_are_raii() {
        let telemetry = MultiplexTelemetry::default();
        let first = telemetry.stream_opened();
        let second = telemetry.stream_opened();
        telemetry.data_sent(17);
        telemetry.data_received(23);
        telemetry.flow_control_reset();
        telemetry.control_burst_yielded();

        assert_eq!(
            telemetry.snapshot(),
            MultiplexTelemetrySnapshot {
                active_streams: 2,
                peak_active_streams: 2,
                sent_data_frames: 1,
                sent_data_bytes: 17,
                received_data_frames: 1,
                received_data_bytes: 23,
                flow_control_resets: 1,
                control_burst_yields: 1,
                ..MultiplexTelemetrySnapshot::default()
            }
        );
        drop(first);
        drop(second);
        assert_eq!(telemetry.snapshot().active_streams, 0);
        assert_eq!(telemetry.snapshot().peak_active_streams, 2);
    }
}
