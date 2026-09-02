use borsh::{BorshDeserialize, BorshSerialize};
use k256::{Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use sha3::Digest;

use crate::{Chain, SignId};

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
pub struct ConsensusCheckpointDigest {
    pub chain: Chain,
    pub height: u64,
    #[serde(with = "serde_bytes")]
    pub digest: [u8; 32],
}

impl ConsensusCheckpointDigest {
    pub fn new(chain: Chain, height: u64, digest: [u8; 32]) -> Self {
        Self {
            chain,
            height,
            digest,
        }
    }
    pub fn sign_payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + std::mem::size_of::<u64>() + 32);
        bytes.extend_from_slice(&self.chain.to_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub fn sign_payload_hash(&self) -> [u8; 32] {
        use sha3::digest::FixedOutput;

        <Secp256k1 as k256::ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(
            self.sign_payload_bytes(),
        )
        .finalize_fixed()
        .into()
    }

    pub fn sign_payload_scalar(&self) -> Scalar {
        use k256::elliptic_curve::ops::Reduce;
        let bytes: k256::elliptic_curve::FieldBytes<Secp256k1> = self.sign_payload_hash().into();
        <Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&bytes)
    }

    pub fn sign_path(&self) -> String {
        self.height.to_string()
    }

    pub fn sign_id(&self) -> SignId {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b"checkpoint");
        hasher.update(self.chain.caip2_chain_id().as_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.sign_payload_hash());
        hasher.update(crate::LATEST_MPC_KEY_VERSION.to_le_bytes());
        let request_id: [u8; 32] = hasher.finalize().into();
        SignId::new(request_id)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointDigest {
    pub height: u64,
    pub digest: [u8; 32],
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
