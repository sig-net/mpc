use std::num::NonZeroUsize;

use tokio::sync::mpsc;

use super::types::{MessageFilterId, Protocols};

/// Maximum size for the filter of messages. This is roughly determined by the
/// max number of protocols that can be within our system. It's not an upper
/// bound but merely to serve as a good enough amount to maintain the IDs of
/// protocols long enough on the case that they make it back into the system
/// somehow after being erased.
pub const MAX_FILTER_SIZE: NonZeroUsize = NonZeroUsize::new(64 * 1024).unwrap();

#[derive(Debug)]
pub(crate) struct MessageFilter {
    filter_tx: mpsc::Sender<(Protocols, u64)>,
    filter_rx: mpsc::Receiver<(Protocols, u64)>,
    filter: lru::LruCache<(Protocols, u64), ()>,
}

impl MessageFilter {
    pub fn new(
        filter_tx: mpsc::Sender<(Protocols, u64)>,
        filter_rx: mpsc::Receiver<(Protocols, u64)>,
    ) -> Self {
        Self {
            filter_tx,
            filter_rx,
            filter: lru::LruCache::new(MAX_FILTER_SIZE),
        }
    }

    pub fn contains<M: MessageFilterId>(&mut self, msg: &M) -> bool {
        // Check if the message is already in the filter. Doing `get` here will also
        // update the LRU cache and promote the rank of this id to be most recent.
        self.filter.get(&(M::PROTOCOL, msg.id())).is_some()
    }

    pub async fn update(&mut self) {
        let Some((msg_type, id)) = self.filter_rx.recv().await else {
            return;
        };

        self.filter.put((msg_type, id), ());
        crate::metrics::messaging::set_channel_capacity("filter", self.filter_tx.capacity());
    }

    pub fn try_update(&mut self) {
        let mut updated = false;
        while let Ok((msg_type, id)) = self.filter_rx.try_recv() {
            self.filter.put((msg_type, id), ());
            updated = true;
        }

        if updated {
            crate::metrics::messaging::set_channel_capacity("filter", self.filter_tx.capacity());
        }
    }

    pub fn clear(&mut self) {
        self.filter.clear();
    }
}
