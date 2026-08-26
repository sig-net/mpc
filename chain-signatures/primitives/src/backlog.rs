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

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointDigest {
    pub height: u64,
    pub digest: [u8; 32],
}

/// The contract's checkpoint directive for a chain.
///
/// Absence (no entry) means the contract holds no directive: chains fall back
/// to their own anchoring behavior. A [`CheckpointDirective::Restart`] marker
/// is written by a checkpoint reset and instructs indexers to restart from
/// the given height.
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
pub enum CheckpointDirective {
    /// Checkpoints were reset; indexers should restart from this height.
    Restart(u64),
    /// The latest consensus-settled checkpoint digest.
    Consensus(ConsensusCheckpointDigest),
}

impl CheckpointDirective {
    /// The settled checkpoint digest, if this is a consensus directive.
    pub fn consensus_digest(&self) -> Option<&ConsensusCheckpointDigest> {
        match self {
            CheckpointDirective::Restart(_) => None,
            CheckpointDirective::Consensus(digest) => Some(digest),
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            CheckpointDirective::Restart(height) => *height,
            CheckpointDirective::Consensus(digest) => digest.height,
        }
    }
}
