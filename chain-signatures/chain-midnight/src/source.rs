//! The node reads the indexer consumes: the [`ChainSource`] seam and its subxt implementation.

use crate::config::MidnightConfig;
use crate::emissions::SingletonCallEmissions;
use crate::reader::Node;
use crate::rpc::{BlockRef, MidnightRpc};
use crate::state::decode_contract_state;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use mpc_utils::task::AbortOnDrop;
use tokio::sync::mpsc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockProofSeed {
    pub reported_genesis_hash: [u8; 32],
    pub reported_block_number: u64,
    pub reported_block_hash: [u8; 32],
    pub singleton_address: [u8; 32],
    pub scale_header: Vec<u8>,
    pub scale_body: Vec<Vec<u8>>,
    pub scale_system_events: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CandidateTransactionEmissions {
    pub extrinsic_index: u32,
    pub calls: Vec<SingletonCallEmissions>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockEmissions {
    pub proof_seed: BlockProofSeed,
    pub candidates: Vec<CandidateTransactionEmissions>,
}

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
    async fn block_emissions(
        &self,
        block: &BlockRef,
        singleton: &[u8; 32],
    ) -> anyhow::Result<Option<BlockEmissions>>;
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
fn classify_decode(decoded: anyhow::Result<Node>) -> ContractState {
    match decoded {
        Ok(tree) => ContractState::Tree(tree),
        Err(err) => ContractState::Undecodable(err),
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

    async fn block_emissions(
        &self,
        block: &BlockRef,
        singleton: &[u8; 32],
    ) -> anyhow::Result<Option<BlockEmissions>> {
        self.rpc.block_emissions(block, singleton).await
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
            Some(state) => Ok(classify_decode(decode_contract_state(&state))),
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

#[cfg(test)]
mod proof_seed_tests {
    use super::*;
    use crate::emissions::{Emission, EmissionKind, SingletonCallEmissions};

    #[test]
    fn block_emissions_preserves_the_proof_seed_and_locator() {
        let expected = BlockEmissions {
            proof_seed: BlockProofSeed {
                reported_genesis_hash: [0x11; 32],
                reported_block_number: 42,
                reported_block_hash: [0x22; 32],
                singleton_address: [0x33; 32],
                scale_header: vec![0x44, 0x45],
                scale_body: vec![vec![0x51], vec![0x52, 0x53], vec![0x54]],
                scale_system_events: vec![0x61, 0x62, 0x63],
            },
            candidates: vec![CandidateTransactionEmissions {
                extrinsic_index: 1,
                calls: vec![SingletonCallEmissions {
                    call_index: 1,
                    emissions: vec![
                        Emission {
                            kind: EmissionKind::SignBidirectional,
                            payload: [0x71; 256],
                        },
                        Emission {
                            kind: EmissionKind::SignatureResponded,
                            payload: [0x72; 256],
                        },
                    ],
                }],
            }],
        };

        let carried = expected.clone();
        assert_eq!(carried, expected);
        assert_eq!(carried.candidates[0].extrinsic_index, 1);
        assert_eq!(carried.candidates[0].calls[0].call_index, 1);
        assert_eq!(
            carried.candidates[0].calls[0].emissions[1].kind,
            EmissionKind::SignatureResponded
        );
    }
}
