use anyhow::Context as _;
use async_trait::async_trait;
use mpc_chain_integration_core::ChainIndexer;
use mpc_node::protocol::IndexedSignRequest;
use mpc_node::rpc::RpcAction;
use mpc_primitives::{Chain, ChainEvent, SignKind};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

#[derive(Default, Clone)]
pub struct MockStream {
    inner: Arc<Mutex<InnerMockStream>>,
}

/// Holds chain events to be processed in tests.
///
/// Events are grouped into blocks and drained by the indexer's `run()`.
#[derive(Default)]
pub struct InnerMockStream {
    /// The current simulated block height. Events are only released on
    /// `next_event()` if they belong to a block <= `block_height`.
    block_height: u64,
    /// Events for blocks >= `block_height`, not ready to be published, yet.
    future_blocks: Vec<Vec<ChainEvent>>,
    /// Events already produced < `block_height` but not yet consumed.
    pending_events: Vec<ChainEvent>,
}

pub struct MockIndexer {
    inner: Arc<Mutex<InnerMockStream>>,
}

impl MockIndexer {
    pub fn from_stream(stream: &MockStream) -> Self {
        Self {
            inner: stream.inner.clone(),
        }
    }
}

#[async_trait]
impl ChainIndexer for MockIndexer {
    const CHAIN: Chain = Chain::Solana;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // No catchup data — emit immediately, then forward prepared events.
        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("mock events_tx closed during catchup")?;

        loop {
            let event = self.inner.lock().await.pending_events.pop();
            if let Some(event) = event {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    res = events_tx.send(event) => {
                        if res.is_err() {
                            return Ok(());
                        }
                    }
                }
            } else {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        }
    }
}

impl MockStream {
    /// Clones internal data to create different copies of the stream that can
    /// be drained independently. The standard clone only does an Arc::clone.
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

    /// Add a future block containing arbitrary chain events.
    pub async fn prepare_block_of_events(&self, events: &[ChainEvent]) {
        let mut guard = self.inner.lock().await;
        guard.future_blocks.push(events.to_vec())
    }

    /// Add a future block that contains events corresponding to the provided rpc actions.
    pub async fn prepare_block_of_rpc_actions(&self, actions: &[RpcAction]) {
        let mut guard = self.inner.lock().await;
        guard.prepare_block_of_rpc_actions(actions)
    }
}

impl InnerMockStream {
    /// Move events from future blocks to pending blocks.
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
            if request.chain != Chain::Solana {
                continue;
            }

            block.push(ChainEvent::SignRequest {
                request: request.clone(),
                block_timestamp: None,
            });
        }

        self.future_blocks.push(block);
    }

    /// Add a future block that contains events corresponding to the provided rpc actions.
    pub fn prepare_block_of_rpc_actions(&mut self, actions: &[RpcAction]) {
        let mut block = Vec::new();

        for action in actions {
            let RpcAction::Publish(publish_action) = action;

            // Skip events for other chains
            if publish_action.request.chain != Chain::Solana {
                continue;
            }

            // for now, the mock stream only converts signature RPC actions to chain events
            if !matches!(publish_action.request.kind, SignKind::Sign,) {
                tracing::warn!(
                    kind=?publish_action.request.kind,
                    "kind not yet supported in test framework",
                );
                continue;
            }

            let respond_event = mpc_primitives::SignatureRespondedEvent {
                request_id: publish_action.request.id.request_id,
                signature: publish_action.signature,
                chain: Chain::Solana,
            };

            block.push(ChainEvent::Respond(respond_event));
        }

        self.future_blocks.push(block);
    }
}
