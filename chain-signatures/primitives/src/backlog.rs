use borsh::{BorshDeserialize, BorshSerialize};
use k256::{Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use sha3::Digest;

use crate::{Chain, SignId};

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
