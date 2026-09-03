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
    /// Commitment to each pending request's checkpoint-consensus phase.
    ///
    /// This is computed by hashing each request's checkpoint-consensus phase
    /// in the same sorted order as `pending_requests`. It lets the checkpoint
    /// digest commit to cross-node request progress without hashing
    /// `transaction`, which is the full recovery payload and may include
    /// node-local fields.
    ///
    /// The phase distinguishes only "awaiting the initial response on this chain"
    /// from "past it". Generation versus publication is local progress that only a
    /// signature's participants make, and the target-execution boundary is gated on
    /// another chain's height, so neither is committed to here.
    ///
    /// The phase encoding is a consensus wire format: nodes computing it differently
    /// cannot agree on a checkpoint even with identical backlogs. Changing it splits
    /// the network into pre- and post-change groups for the duration of a rolling
    /// upgrade, so treat any change as a coordinated release.
    #[serde(default, with = "serde_bytes")]
    pub cumulative_digest: [u8; 32],
}

impl Checkpoint {
    pub fn empty(chain: Chain) -> Self {
        Self {
            chain,
            block_height: 0,
            pending_requests: Vec::new(),
            cumulative_digest: Self::empty_cumulative_digest(),
        }
    }

    pub fn empty_cumulative_digest() -> [u8; 32] {
        sha3::Sha3_256::new().finalize().into()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(self.chain.caip2_chain_id().as_bytes());
        hasher.update(self.block_height.to_le_bytes());
        for pending in &self.pending_requests {
            hasher.update(pending.sign_id.request_id);
        }
        hasher.update(self.cumulative_digest);
        hasher.finalize().into()
    }
}

/// A checkpoint digest submitted for consensus voting and tracked by the
/// contract.
///
/// This is the single checkpoint-digest type across the node and the contract.
/// It carries its own `chain` so that values moving through per-chain watch
/// channels or maps keyed by `Chain` always carry a consistent chain: prefer
/// reading the value's `chain` field rather than trusting an external key.
///
/// The Borsh layout (field order `chain`, `height`, `digest`) matches the
/// previously stored `ConsensusCheckpointDigest` byte-for-byte, so persisted
/// contract state needs no migration for this rename/merge.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The merged `CheckpointDigest` keeps the exact Borsh layout that
    /// `ConsensusCheckpointDigest` persisted on-chain: `chain` (1 byte),
    /// `height` (LE u64), `digest` (32 bytes). Borsh is field-order based, so
    /// this is also the contract-state migration contract — any reordering or
    /// field addition here silently breaks persisted state.
    #[test]
    fn borsh_layout_is_chain_then_height_then_digest() {
        let checkpoint = CheckpointDigest::new(Chain::Solana, 0x0102_0304_0506_0708, [0xAB; 32]);
        let bytes = borsh::to_vec(&checkpoint).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&checkpoint.chain.to_bytes());
        expected.extend_from_slice(&checkpoint.height.to_le_bytes());
        expected.extend_from_slice(&checkpoint.digest);
        assert_eq!(bytes, expected);

        // Round-trip.
        let decoded = CheckpointDigest::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded, checkpoint);
    }

    /// The consensus signing payload must stay byte-for-byte identical to the
    /// old `ConsensusCheckpointDigest::sign_payload_bytes`: the chain byte, the
    /// LE height, then the digest.
    #[test]
    fn sign_payload_bytes_is_chain_then_height_then_digest() {
        let checkpoint = CheckpointDigest::new(Chain::Ethereum, 42, [0x42; 32]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&checkpoint.chain.to_bytes());
        expected.extend_from_slice(&checkpoint.height.to_le_bytes());
        expected.extend_from_slice(&checkpoint.digest);
        assert_eq!(checkpoint.sign_payload_bytes(), expected);
    }

    #[test]
    fn sign_payload_hash_and_scalar_are_deterministic_and_input_dependent() {
        let a = CheckpointDigest::new(Chain::Ethereum, 42, [0x42; 32]);
        let b = CheckpointDigest::new(Chain::Ethereum, 42, [0x42; 32]);
        let c = CheckpointDigest::new(Chain::Solana, 42, [0x42; 32]);
        let d = CheckpointDigest::new(Chain::Ethereum, 43, [0x42; 32]);

        assert_eq!(a.sign_payload_hash(), b.sign_payload_hash());
        assert_eq!(a.sign_payload_scalar(), b.sign_payload_scalar());
        assert_ne!(a.sign_payload_hash(), c.sign_payload_hash());
        assert_ne!(a.sign_payload_hash(), d.sign_payload_hash());

        assert_eq!(a.sign_path(), "42");
    }

    /// `sign_id` commits to chain, height, and the signing payload; identical
    /// digests on different chains/heights must produce different ids.
    #[test]
    fn sign_id_is_deterministic_and_input_dependent() {
        let a = CheckpointDigest::new(Chain::Ethereum, 42, [0x42; 32]);
        let b = CheckpointDigest::new(Chain::Ethereum, 42, [0x42; 32]);
        let c = CheckpointDigest::new(Chain::Solana, 42, [0x42; 32]);
        let d = CheckpointDigest::new(Chain::Ethereum, 43, [0x42; 32]);

        assert_eq!(a.sign_id(), b.sign_id());
        assert_ne!(a.sign_id(), c.sign_id());
        assert_ne!(a.sign_id(), d.sign_id());
    }
}
