//! Bounded process-local admission plus deterministic fair queueing.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;

use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

/// One admitted queue item. Its permit remains held until the item is dropped.
pub struct BoundedQueueItem<T> {
    value: T,
    _permit: OwnedSemaphorePermit,
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
}

impl<T> Clone for BoundedQueueSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            permits: Arc::clone(&self.permits),
        }
    }
}

impl<T> BoundedQueueSender<T> {
    pub async fn send(&self, value: T) -> Result<(), BoundedQueueClosed> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| BoundedQueueClosed)?;
        self.sender
            .send(BoundedQueueItem {
                value,
                _permit: permit,
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
    let (sender, receiver) = mpsc::channel(capacity.get());
    (
        BoundedQueueSender {
            sender,
            permits: Arc::new(Semaphore::new(capacity.get())),
        },
        receiver,
    )
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
}
