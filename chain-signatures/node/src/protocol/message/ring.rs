//! A bounded MPSC ring-buffer channel with drop-oldest semantics.
//!
//! When the channel is at capacity, `send_lossy` evicts the oldest (front)
//! entry before pushing the new one, so the receiver always sees the most
//! recent messages rather than being stuck with stale ones.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio::sync::mpsc::error::{SendError, TryRecvError};

struct Shared<T> {
    buffer: Mutex<VecDeque<T>>,
    capacity: usize,
    notify: Notify,
}

pub struct RingSender<T>(Arc<Shared<T>>);
pub struct RingReceiver<T>(Arc<Shared<T>>);

pub fn ring_channel<T>(capacity: usize) -> (RingSender<T>, RingReceiver<T>) {
    let shared = Arc::new(Shared {
        buffer: Mutex::new(VecDeque::with_capacity(capacity)),
        capacity,
        notify: Notify::new(),
    });
    (RingSender(shared.clone()), RingReceiver(shared))
}

impl<T: Send> RingSender<T> {
    /// Send a message, dropping the oldest entry if the channel is at capacity.
    ///
    /// Returns `Ok(true)` if an entry was evicted to make room, `Ok(false)` if
    /// the message was buffered without eviction, or `Err` if the receiver has
    /// been dropped.
    pub fn send_lossy(&self, msg: T) -> Result<bool, SendError<T>> {
        if Arc::strong_count(&self.0) == 1 {
            return Err(SendError(msg));
        }
        let mut buf = self.0.buffer.lock().unwrap();
        let dropped = if buf.len() >= self.0.capacity {
            buf.pop_front();
            true
        } else {
            false
        };
        buf.push_back(msg);
        drop(buf);
        self.0.notify.notify_one();
        Ok(dropped)
    }

    pub fn len(&self) -> usize {
        self.0.buffer.lock().unwrap().len()
    }

    pub fn max_capacity(&self) -> usize {
        self.0.capacity
    }
}

impl<T: Send> RingReceiver<T> {
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            // Register the notification listener BEFORE checking the buffer.
            // This avoids missing a send that races between our empty-check and
            // the subsequent .await.
            let mut notified = std::pin::pin!(self.0.notify.notified());
            notified.as_mut().enable();

            {
                let mut buf = self.0.buffer.lock().unwrap();
                if let Some(msg) = buf.pop_front() {
                    return Some(msg);
                }
                // If the sender was dropped and the buffer is empty, signal EOF.
                if Arc::strong_count(&self.0) == 1 {
                    return None;
                }
            }

            notified.await;
        }
    }

    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let mut buf = self.0.buffer.lock().unwrap();
        if let Some(msg) = buf.pop_front() {
            return Ok(msg);
        }
        if Arc::strong_count(&self.0) == 1 {
            return Err(TryRecvError::Disconnected);
        }
        Err(TryRecvError::Empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_oldest_when_full() {
        let (tx, mut rx) = ring_channel::<u32>(3);
        // Fill to capacity
        assert_eq!(tx.send_lossy(1).unwrap(), false); // no eviction
        assert_eq!(tx.send_lossy(2).unwrap(), false);
        assert_eq!(tx.send_lossy(3).unwrap(), false);
        // Overflow: oldest (1) is evicted
        assert_eq!(tx.send_lossy(4).unwrap(), true);
        assert_eq!(tx.send_lossy(5).unwrap(), true);

        // Receiver sees 3, 4, 5 (not 1, 2)
        assert_eq!(rx.try_recv().unwrap(), 3);
        assert_eq!(rx.try_recv().unwrap(), 4);
        assert_eq!(rx.try_recv().unwrap(), 5);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn len_reflects_buffer() {
        let (tx, mut rx) = ring_channel::<u32>(4);
        assert_eq!(tx.len(), 0);
        tx.send_lossy(1).unwrap();
        tx.send_lossy(2).unwrap();
        assert_eq!(tx.len(), 2);
        rx.try_recv().unwrap();
        assert_eq!(tx.len(), 1);
    }

    #[test]
    fn send_lossy_fails_when_receiver_dropped() {
        let (tx, rx) = ring_channel::<u32>(4);
        drop(rx);
        assert!(tx.send_lossy(1).is_err());
    }

    #[test]
    fn try_recv_returns_disconnected_when_sender_dropped() {
        use tokio::sync::mpsc::error::TryRecvError;
        let (tx, mut rx) = ring_channel::<u32>(4);
        tx.send_lossy(42).unwrap();
        drop(tx);
        assert_eq!(rx.try_recv().unwrap(), 42);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
    }

    #[tokio::test]
    async fn recv_wakes_on_send() {
        let (tx, mut rx) = ring_channel::<u32>(4);
        let handle = tokio::spawn(async move { rx.recv().await });
        tx.send_lossy(99).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), handle)
            .await
            .expect("timed out")
            .expect("join error");
        assert_eq!(result, Some(99));
    }

    #[tokio::test]
    async fn recv_returns_none_when_sender_dropped() {
        let (tx, mut rx) = ring_channel::<u32>(4);
        drop(tx);
        assert_eq!(rx.recv().await, None);
    }
}
