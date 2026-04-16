use elliptic_curve::sec1::ToEncodedPoint;
use mpc_node::protocol::{IndexedSignRequest, SignKind};
use mpc_node::rpc::RpcAction;
use mpc_node::stream::{ChainEvent, ChainStream};
use mpc_primitives::Chain;
use solana_sdk::pubkey::Pubkey;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Default, Clone)]
pub struct MockStream {
    inner: Arc<Mutex<InnerMockStream>>,
}

#[derive(Default)]
pub struct InnerMockStream {
    block_height: u64,
    /// Events for blocks >= `block_height`, not ready to be published, yet.
    future_blocks: Vec<Vec<ChainEvent>>,
    /// Events already produced < `block_height` but not yet consumed by
    /// `next_event()`.
    pending_events: Vec<ChainEvent>,
}

impl ChainStream for MockStream {
    const CHAIN: Chain = Chain::Solana;

    async fn start(&mut self) {
        let mut guard = self.inner.lock().await;
        guard.pending_events.push(ChainEvent::CatchupCompleted);
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        loop {
            let mut guard = self.inner.lock().await;
            let out = guard.pending_events.pop();
            if out.is_some() {
                return out;
            }
            // TODO: would be better to avoid sleep by awaiting new data
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl MockStream {
    pub async fn deep_clone(&self) -> Self {
        let guard = self.inner.lock().await;
        let cloned = InnerMockStream {
            block_height: guard.block_height,
            future_blocks: guard.future_blocks.clone(),
            pending_events: guard.pending_events.clone(),
        };
        Self {
            inner: Arc::new(Mutex::new(cloned)),
        }
    }

    pub async fn progress_block_height(&self, steps: usize) {
        let mut guard = self.inner.lock().await;
        guard.progress_block_height(steps)
    }

    /// Add a future block that contains signature requesting events.
    pub async fn prepare_block_of_sign_requests(&self, requests: &[IndexedSignRequest]) {
        let mut guard = self.inner.lock().await;
        guard.prepare_block_of_sign_requests(requests)
    }

    /// Add a future block that contains events corresponding to the provided rpc actions.
    pub async fn prepare_block_of_rpc_actions(&self, actions: &[RpcAction]) {
        let mut guard = self.inner.lock().await;
        guard.prepare_block_of_rpc_actions(actions)
    }
}

impl InnerMockStream {
    /// Move events from future blocks tp pending blocks.
    pub fn progress_block_height(&mut self, steps: usize) {
        let checked_steps = steps.min(self.future_blocks.len());
        for mut block in self.future_blocks.drain(0..checked_steps) {
            self.pending_events.append(&mut block);
            self.pending_events
                .push(ChainEvent::Block(self.block_height));
            self.block_height += 1;
        }
    }

    /// Add a future block that contains signature requesting events.
    pub fn prepare_block_of_sign_requests(&mut self, requests: &[IndexedSignRequest]) {
        let mut block = Vec::new();

        for request in requests {
            // Skip events for other chains
            if request.chain != MockStream::CHAIN {
                continue;
            }

            block.push(ChainEvent::SignRequest(request.clone()))
        }

        self.future_blocks.push(block);
    }

    /// Add a future block that contains events corresponding to the provided rpc actions.
    pub fn prepare_block_of_rpc_actions(&mut self, actions: &[RpcAction]) {
        let mut block = Vec::new();

        for action in actions {
            let RpcAction::Publish(publish_action) = action;

            // Skip events for other chains
            if publish_action.indexed.chain != MockStream::CHAIN {
                continue;
            }

            // for now, the mock stream only converts signature RPC actions to chain events
            if !matches!(publish_action.indexed.kind, SignKind::Sign,) {
                tracing::warn!(
                    kind=?publish_action.indexed.kind,
                    "kind not yet supported in test framework",
                );
                continue;
            }

            // type conversions that would usually happen in RPC publishing -> Solana contract -> CPI event library
            let big_r = publish_action.signature.big_r.to_encoded_point(false);
            let sol_event = signet_program::SignatureRespondedEvent {
                request_id: publish_action.indexed.id.request_id,
                responder: Pubkey::new_unique(),
                signature: mpc_node::util::mpc_to_sol_signature(&publish_action.signature, big_r),
            };

            let respond_event = mpc_node::stream::ops::SignatureRespondedEvent::Solana(sol_event);

            block.push(ChainEvent::Respond(respond_event));
        }

        self.future_blocks.push(block);
    }
}
