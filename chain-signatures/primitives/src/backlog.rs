use borsh::{BorshDeserialize, BorshSerialize};
use k256::{Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::fmt;

use crate::{Chain, SignId};

/// Transaction information tracked across checkpoints.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct PendingTx {
    pub sign_id: SignId,
    #[serde(with = "serde_bytes")]
    pub transaction: Vec<u8>,
}

impl fmt::Debug for PendingTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTx")
            .field("sign_id", &self.sign_id)
            .finish()
    }
}

/// A checkpoint represents the backlog state at a specific block height.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Checkpoint {
    pub chain: Chain,
    pub block_height: u64,
    pub pending_requests: Vec<PendingTx>,
}

impl Checkpoint {
    pub fn empty(chain: Chain) -> Self {
        Self {
            chain,
            block_height: 0,
            pending_requests: Vec::new(),
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(self.chain.caip2_chain_id().as_bytes());
        hasher.update(self.block_height.to_le_bytes());
        for pending in &self.pending_requests {
            hasher.update(pending.sign_id.request_id);
            hasher.update(&pending.transaction);
        }
        hasher.finalize().into()
    }
}

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
        SignId::from_checkpoint(self.chain, self.height, &self.sign_payload_hash())
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointDigest {
    pub height: u64,
    pub digest: [u8; 32],
}
