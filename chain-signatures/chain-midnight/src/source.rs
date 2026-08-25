//! The node reads the indexer consumes: the [`ChainSource`] seam and its subxt implementation.

use crate::config::MidnightConfig;
use crate::reader::Node;
use crate::rpc::{BlockRef, MidnightRpc};
use crate::state::decode_contract_state;

use async_trait::async_trait;

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
}

pub(crate) struct LiveSource {
    rpc: MidnightRpc,
}

impl LiveSource {
    pub(crate) fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        Ok(Self {
            rpc: MidnightRpc::connect(config)?,
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
            Some(state) => Ok(match decode_contract_state(&state) {
                Ok(tree) => ContractState::Tree(tree),
                Err(err) => ContractState::Undecodable(err),
            }),
        }
    }
}
