use std::num::NonZeroUsize;

use tokio::sync::mpsc::{self, error::TryRecvError};

use super::types::{MessageFilterId, Protocols};

/// Maximum size for the filter of messages. This is roughly determined by the
/// max number of protocols that can be within our system. It's not an upper
/// bound but merely to serve as a good enough amount to maintain the IDs of
/// protocols long enough on the case that they make it back into the system
/// somehow after being erased.
pub const MAX_FILTER_SIZE: NonZeroUsize = NonZeroUsize::new(64 * 1024).unwrap();

#[derive(Debug)]
pub(crate) struct MessageFilter {
    filter_rx: mpsc::Receiver<(Protocols, u64)>,
    filter: lru::LruCache<(Protocols, u64), ()>,
}

impl MessageFilter {
    pub fn new(filter_rx: mpsc::Receiver<(Protocols, u64)>) -> Self {
        Self {
            filter_rx,
            filter: lru::LruCache::new(MAX_FILTER_SIZE),
        }
    }

    pub fn contains<M: MessageFilterId>(&mut self, msg: &M) -> bool {
        // Check if the message is already in the filter. Doing `get` here will also
        // update the LRU cache and promote the rank of this id to be most recent.
        self.filter.get(&(M::PROTOCOL, msg.id())).is_some()
    }

    pub fn contains_id(&mut self, id: u64, protocol: Protocols) -> bool {
        // Check if the message is already in the filter. Doing `get` here will also
        // update the LRU cache and promote the rank of this id to be most recent.
        self.filter.get(&(protocol, id)).is_some()
    }

    pub async fn update(&mut self) {
        let Some((msg_type, id)) = self.filter_rx.recv().await else {
            return;
        };

        self.filter.put((msg_type, id), ());
    }

    pub fn try_update(&mut self) {
        loop {
            let (msg_type, id) = match self.filter_rx.try_recv() {
                Ok(filter) => filter,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            };
            self.filter.put((msg_type, id), ());
        }
    }

    pub fn clear(&mut self) {
        self.filter.clear();
    }
}
