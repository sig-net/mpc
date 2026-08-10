//! The node reads the indexer consumes: the [`ChainSource`] seam and its subxt implementation.

use crate::config::MidnightConfig;
use crate::reader::Node;
use crate::rpc::{BlockRef, MidnightRpc};
use crate::state::decode_contract_state;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use mpc_utils::task::AbortOnDrop;
use tokio::sync::mpsc;

/// What a contract-state read found.
pub(crate) enum ContractState {
    Tree(Node),
    /// Not present at that block.
    Absent,
    /// The node served bytes that did not deserialize.
    Undecodable(anyhow::Error),
}

/// The node reads `run()` consumes, as a test seam.
#[async_trait]
pub(crate) trait ChainSource: Send + Sync {
    async fn finalized_head(&self) -> anyhow::Result<BlockRef>;
    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef>;
    /// The decoded state tree of `address_64hex` at `at_hash`.
    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState>;
    /// Pushes live finalized blocks into `tx` until the underlying stream ends; the
    /// returned guard aborts the producer on drop.
    async fn spawn_block_producer(&self, tx: mpsc::Sender<BlockRef>)
        -> anyhow::Result<AbortOnDrop>;
}

/// Bytes that do not deserialize are charged to the contract that owns them, never to
/// the read: the decode is in-process, so there is no transport that could have failed.
fn classify_decode(decoded: anyhow::Result<Node>) -> anyhow::Result<ContractState> {
    match decoded {
        Ok(tree) => Ok(ContractState::Tree(tree)),
        Err(err) => Ok(ContractState::Undecodable(err)),
    }
}

pub(crate) struct LiveSource {
    rpc: MidnightRpc,
}

impl LiveSource {
    pub(crate) async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        Ok(Self {
            rpc: MidnightRpc::connect(config).await?,
        })
    }
}

#[async_trait]
impl ChainSource for LiveSource {
    async fn finalized_head(&self) -> anyhow::Result<BlockRef> {
        self.rpc.finalized_block_ref().await
    }

    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef> {
        self.rpc.block_ref_at(number).await
    }

    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState> {
        match self.rpc.contract_state(address_64hex, at_hash).await? {
            None => Ok(ContractState::Absent),
            // Decoded in-process by the ledger's own deserializer: the state path makes
            // no network call beyond the node read above.
            Some(state) => classify_decode(decode_contract_state(&state)),
        }
    }

    async fn spawn_block_producer(
        &self,
        tx: mpsc::Sender<BlockRef>,
    ) -> anyhow::Result<AbortOnDrop> {
        let mut stream = self.rpc.subscribe_finalized().await?;
        Ok(AbortOnDrop(tokio::spawn(async move {
            while let Some(block) = stream.next().await {
                if tx.send(block).await.is_err() {
                    return;
                }
            }
        })))
    }
}
