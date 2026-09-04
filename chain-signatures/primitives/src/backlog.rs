use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha3::Digest;

use crate::Chain;

/// A checkpoint digest submitted for consensus voting and tracked by the
/// contract.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct CheckpointDigest {
    pub chain: Chain,
    pub height: u64,
    #[serde(with = "serde_bytes")]
    pub digest: [u8; 32],
}

impl CheckpointDigest {
    pub fn new(chain: Chain, height: u64, digest: [u8; 32]) -> Self {
        Self {
            chain,
            height,
            digest,
        }
    }
}

/// Digest of a backlog checkpoint.
///
/// Shared so the node (hashing its live backlog) and the contract (deriving
/// [`reset_checkpoint_digest`]) cannot drift apart.
pub fn checkpoint_digest(
    chain: Chain,
    block_height: u64,
    request_ids: impl IntoIterator<Item = [u8; 32]>,
    cumulative_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(chain.caip2_chain_id().as_bytes());
    hasher.update(block_height.to_le_bytes());
    for request_id in request_ids {
        hasher.update(request_id);
    }
    hasher.update(cumulative_digest);
    hasher.finalize().into()
}

/// The cumulative digest of a checkpoint holding no pending requests.
pub fn empty_cumulative_digest() -> [u8; 32] {
    sha3::Sha3_256::new().finalize().into()
}

/// Digest of the canonical *reset* checkpoint for `(chain, height)`: the one
/// asserting an empty backlog at `height`.
///
/// Being a pure function of the pair is what lets a reset be an ordinary
/// settled checkpoint. The contract can settle a digest for a state no node
/// holds yet, and each node rebuilds the matching checkpoint locally instead
/// of fetching it from a peer that would never have it.
pub fn reset_checkpoint_digest(chain: Chain, height: u64) -> [u8; 32] {
    checkpoint_digest(chain, height, std::iter::empty(), empty_cumulative_digest())
}
