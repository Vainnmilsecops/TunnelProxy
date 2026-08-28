//! Bounded process-local admission plus deterministic fair queueing.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// One admitted queue item. Its permit remains held until the item is dropped.
pub struct BoundedQueueItem<T> {
    value: T,
    _permit: OwnedSemaphorePermit,
    _telemetry: Option<BoundedQueueOccupancyGuard>,
}

impl<T> BoundedQueueItem<T> {
    pub const fn value(&self) -> &T {
        &self.value
    }
}

/// Cloneable producer for a channel whose total admitted items are bounded
/// independently from receiver-side buffering.
pub struct BoundedQueueSender<T> {
    sender: mpsc::Sender<BoundedQueueItem<T>>,
    permits: Arc<Semaphore>,
    telemetry: Option<BoundedQueueTelemetry>,
}

impl<T> Clone for BoundedQueueSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            permits: Arc::clone(&self.permits),
            telemetry: self.telemetry.clone(),
        }
    }
}

impl<T> BoundedQueueSender<T> {
    pub async fn send(&self, value: T) -> Result<(), BoundedQueueClosed> {
        let permits = Arc::clone(&self.permits);
        let permit = match permits.try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                if let Some(telemetry) = &self.telemetry {
                    telemetry.admission_waited();
                }
                Arc::clone(&self.permits)
                    .acquire_owned()
                    .await
                    .map_err(|_| BoundedQueueClosed)?
            }
            Err(TryAcquireError::Closed) => return Err(BoundedQueueClosed),
        };
        let telemetry = self.telemetry.as_ref().map(BoundedQueueTelemetry::admitted);
        self.sender
            .send(BoundedQueueItem {
                value,
                _permit: permit,
                _telemetry: telemetry,
            })
            .await
            .map_err(|_| BoundedQueueClosed)
    }
}

/// The bounded queue consumer has closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedQueueClosed;

impl std::fmt::Display for BoundedQueueClosed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded queue is closed")
    }
}

impl std::error::Error for BoundedQueueClosed {}

/// Creates a channel whose queued, scheduled, and in-flight items share one
/// hard admission bound.
pub fn bounded_queue_channel<T>(
    capacity: NonZeroUsize,
) -> (BoundedQueueSender<T>, mpsc::Receiver<BoundedQueueItem<T>>) {
    bounded_queue_channel_inner(capacity, None)
}

/// Creates a hard-bounded channel and observes admission waits plus the full
/// admitted item lifetime without changing queue behavior.
pub fn bounded_queue_channel_with_telemetry<T>(
    capacity: NonZeroUsize,
    telemetry: BoundedQueueTelemetry,
) -> (BoundedQueueSender<T>, mpsc::Receiver<BoundedQueueItem<T>>) {
    bounded_queue_channel_inner(capacity, Some(telemetry))
}

fn bounded_queue_channel_inner<T>(
    capacity: NonZeroUsize,
    telemetry: Option<BoundedQueueTelemetry>,
) -> (BoundedQueueSender<T>, mpsc::Receiver<BoundedQueueItem<T>>) {
    let (sender, receiver) = mpsc::channel(capacity.get());
    (
        BoundedQueueSender {
            sender,
            permits: Arc::new(Semaphore::new(capacity.get())),
            telemetry,
        },
        receiver,
    )
}

/// Fixed-cardinality observation for one or more bounded queue instances.
#[derive(Clone, Debug, Default)]
pub struct BoundedQueueTelemetry {
    inner: Arc<BoundedQueueTelemetryInner>,
}

#[derive(Debug, Default)]
struct BoundedQueueTelemetryInner {
    admission_waits: AtomicUsize,
    admitted_items: AtomicUsize,
    peak_admitted_items: AtomicUsize,
}

/// Point-in-time bounded queue counters and gauges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundedQueueTelemetrySnapshot {
    pub admission_waits: usize,
    pub admitted_items: usize,
    pub peak_admitted_items: usize,
}

impl BoundedQueueTelemetry {
    pub fn snapshot(&self) -> BoundedQueueTelemetrySnapshot {
        BoundedQueueTelemetrySnapshot {
            admission_waits: self.inner.admission_waits.load(Ordering::Relaxed),
            admitted_items: self.inner.admitted_items.load(Ordering::Relaxed),
            peak_admitted_items: self.inner.peak_admitted_items.load(Ordering::Relaxed),
        }
    }

    fn admission_waited(&self) {
        self.inner.admission_waits.fetch_add(1, Ordering::Relaxed);
    }

    fn admitted(&self) -> BoundedQueueOccupancyGuard {
        let current = self.inner.admitted_items.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&self.inner.peak_admitted_items, current);
        BoundedQueueOccupancyGuard {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct BoundedQueueOccupancyGuard {
    inner: Arc<BoundedQueueTelemetryInner>,
}

impl Drop for BoundedQueueOccupancyGuard {
    fn drop(&mut self) {
        self.inner.admitted_items.fetch_sub(1, Ordering::Relaxed);
    }
}

fn update_peak(peak: &AtomicUsize, candidate: usize) {
    let mut current = peak.load(Ordering::Relaxed);
    while candidate > current {
        match peak.compare_exchange_weak(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

/// A bounded FIFO per key with round-robin service between active keys.
pub struct BoundedFairQueue<K, V> {
    capacity: NonZeroUsize,
    len: usize,
    active: VecDeque<K>,
    queues: HashMap<K, VecDeque<V>>,
}

impl<K, V> BoundedFairQueue<K, V>
where
    K: Copy + Eq + Hash,
{
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            len: 0,
            active: VecDeque::new(),
            queues: HashMap::new(),
        }
    }

    /// Enqueues an item while preserving FIFO order for its key.
    pub fn push(&mut self, key: K, value: V) -> Result<(), FairQueueFull<V>> {
        if self.len == self.capacity.get() {
            return Err(FairQueueFull(value));
        }
        match self.queues.get_mut(&key) {
            Some(queue) => queue.push_back(value),
            None => {
                self.active.push_back(key);
                self.queues.insert(key, VecDeque::from([value]));
            }
        }
        self.len += 1;
        Ok(())
    }

    /// Returns one item from the next active key.
    pub fn pop(&mut self) -> Option<V> {
        let key = self.active.pop_front()?;
        let (value, remains_active) = {
            let queue = self
                .queues
                .get_mut(&key)
                .expect("active fair-queue key must have a queue");
            let value = queue
                .pop_front()
                .expect("active fair-queue key must have an item");
            (value, !queue.is_empty())
        };
        self.len -= 1;
        if remains_active {
            self.active.push_back(key);
        } else {
            self.queues.remove(&key);
        }
        Some(value)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn active_keys(&self) -> usize {
        self.active.len()
    }
}

/// Item rejected because the fair queue reached its configured bound.
#[derive(Debug)]
pub struct FairQueueFull<T>(pub T);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_preserves_per_key_fifo() {
        let mut queue = BoundedFairQueue::new(NonZeroUsize::new(8).unwrap());
        queue.push(1, "a1").unwrap();
        queue.push(1, "a2").unwrap();
        queue.push(1, "a3").unwrap();
        queue.push(2, "b1").unwrap();
        queue.push(2, "b2").unwrap();

        let mut output = Vec::new();
        while let Some(value) = queue.pop() {
            output.push(value);
        }

        assert_eq!(output, ["a1", "b1", "a2", "b2", "a3"]);
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.active_keys(), 0);
    }

    #[test]
    fn capacity_is_strict_and_rejected_item_is_returned() {
        let mut queue = BoundedFairQueue::new(NonZeroUsize::new(2).unwrap());
        queue.push(1, "a").unwrap();
        queue.push(2, "b").unwrap();
        let FairQueueFull(rejected) = queue.push(3, "c").unwrap_err();
        assert_eq!(rejected, "c");
        assert_eq!(queue.len(), 2);
    }

    #[tokio::test]
    async fn admission_permit_is_held_until_the_item_is_dropped() {
        let (sender, mut receiver) = bounded_queue_channel(NonZeroUsize::new(1).unwrap());
        sender.send("first").await.unwrap();
        let second_sender = sender.clone();
        let second = tokio::spawn(async move { second_sender.send("second").await });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());

        let first = receiver.recv().await.unwrap();
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        drop(first);

        second.await.unwrap().unwrap();
        assert_eq!(receiver.recv().await.unwrap().value(), &"second");
    }

    #[tokio::test]
    async fn telemetry_distinguishes_waits_and_tracks_raii_occupancy() {
        let telemetry = BoundedQueueTelemetry::default();
        let (sender, mut receiver) =
            bounded_queue_channel_with_telemetry(NonZeroUsize::new(1).unwrap(), telemetry.clone());
        sender.send("first").await.unwrap();
        assert_eq!(
            telemetry.snapshot(),
            BoundedQueueTelemetrySnapshot {
                admission_waits: 0,
                admitted_items: 1,
                peak_admitted_items: 1,
            }
        );

        let waiting_sender = sender.clone();
        let waiting = tokio::spawn(async move { waiting_sender.send("second").await });
        tokio::task::yield_now().await;
        assert_eq!(telemetry.snapshot().admission_waits, 1);
        assert!(!waiting.is_finished());

        drop(receiver.recv().await.unwrap());
        waiting.await.unwrap().unwrap();
        assert_eq!(telemetry.snapshot().admitted_items, 1);
        drop(receiver);
        assert_eq!(telemetry.snapshot().admitted_items, 0);
        assert_eq!(telemetry.snapshot().peak_admitted_items, 1);
    }
}
