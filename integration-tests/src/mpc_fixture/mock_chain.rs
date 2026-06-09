//! Simulated chain that distributes events to all nodes' streams with
//! optional per-node filters for simulating event misses.

use crate::mpc_fixture::mock_stream::MockStream;
use mpc_node::protocol::{IndexedSignRequest, SignKind};
use mpc_node::rpc::RpcAction;
use mpc_node::stream::ChainEvent;
use mpc_primitives::Chain;
use std::sync::Arc;
use tokio::sync::Mutex;

pub enum EventDelivery {
    Deliver,
    Drop,
}

pub type ChainEventFilter = Box<dyn FnMut(&ChainEvent) -> EventDelivery + Send>;

struct MockChainInner {
    node_streams: Vec<MockStream>,
    filters: Vec<Option<ChainEventFilter>>,
}

#[derive(Clone)]
pub struct MockChain {
    inner: Arc<Mutex<MockChainInner>>,
}

impl MockChain {
    pub fn new(node_streams: Vec<MockStream>) -> Self {
        let num_nodes = node_streams.len();
        Self {
            inner: Arc::new(Mutex::new(MockChainInner {
                node_streams,
                filters: (0..num_nodes).map(|_| None).collect(),
            })),
        }
    }

    pub async fn set_filter(&self, node_idx: usize, filter: ChainEventFilter) {
        self.inner.lock().await.filters[node_idx] = Some(filter);
    }

    pub async fn add_sign_requests(&self, requests: &[IndexedSignRequest]) {
        let mut inner = self.inner.lock().await;
        let events: Vec<ChainEvent> = requests
            .iter()
            .map(|r| ChainEvent::SignRequest(r.clone()))
            .collect();
        inner.distribute_events(&events).await;
    }

    /// Convert an RPC publish into respond event(s) and distribute to all nodes.
    pub async fn on_rpc_publish(&self, action: &RpcAction) {
        let events = Self::rpc_action_to_events(action);
        if events.is_empty() {
            return;
        }
        self.inner.lock().await.distribute_events(&events).await;
    }

    fn rpc_action_to_events(action: &RpcAction) -> Vec<ChainEvent> {
        let RpcAction::Publish(publish_action) = action;

        if publish_action.indexed.chain != Chain::Solana {
            return vec![];
        }
        if !matches!(publish_action.indexed.kind, SignKind::Sign) {
            tracing::warn!(
                kind=?publish_action.indexed.kind,
                "MockChain: kind not yet supported",
            );
            return vec![];
        }

        let respond_event = mpc_node::stream::ops::SignatureRespondedEvent {
            request_id: publish_action.indexed.id.request_id,
            signature: publish_action.signature,
            chain: Chain::Solana,
        };
        vec![ChainEvent::Respond(respond_event)]
    }
}

impl MockChainInner {
    async fn distribute_events(&mut self, events: &[ChainEvent]) {
        for (i, stream) in self.node_streams.iter().enumerate() {
            let filtered: Vec<ChainEvent> = events
                .iter()
                .filter(|event| {
                    if let Some(filter) = self.filters[i].as_mut() {
                        matches!(filter(event), EventDelivery::Deliver)
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();

            stream.prepare_block_of_events(&filtered).await;
            stream.progress_block_height(1).await;
        }
    }
}
