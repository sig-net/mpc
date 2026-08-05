use borsh::{BorshDeserialize, BorshSerialize};
use k256::{Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::fmt;

use crate::{Chain, SignId};

/// Version of the canonical checkpoint commitment format.
pub const CHECKPOINT_SCHEMA_VERSION: u32 = 2;

fn legacy_checkpoint_schema_version() -> u32 {
    1
}

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
    /// Full durable recovery payload.
    #[serde(with = "serde_bytes")]
    pub transaction: Vec<u8>,
    /// Canonical source-chain projection committed by the checkpoint digest.
    /// Empty values are accepted only for legacy checkpoints.
    #[serde(default, with = "serde_bytes")]
    pub canonical_transaction: Vec<u8>,
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
    /// Wire-level version for the canonical checkpoint projection.
    #[serde(default = "legacy_checkpoint_schema_version")]
    pub schema_version: u32,
    pub chain: Chain,
    pub block_height: u64,
    pub pending_requests: Vec<PendingTx>,
    /// Legacy status projection retained for wire compatibility.
    ///
    /// Version 2 checkpoint digests commit directly to the canonical pending
    /// payload, so this field is intentionally not part of `digest()`.
    #[serde(default, with = "serde_bytes")]
    pub cumulative_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointValidationError {
    UnsupportedSchemaVersion(u32),
    UnsortedPendingRequests,
    DuplicatePendingRequest(SignId),
}

impl std::fmt::Display for CheckpointValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported checkpoint schema version {version}")
            }
            Self::UnsortedPendingRequests => {
                write!(f, "checkpoint pending requests are not canonically ordered")
            }
            Self::DuplicatePendingRequest(id) => {
                write!(f, "checkpoint contains duplicate pending request {id:?}")
            }
        }
    }
}

impl std::error::Error for CheckpointValidationError {}

impl Checkpoint {
    pub fn empty(chain: Chain) -> Self {
        Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            chain,
            block_height: 0,
            pending_requests: Vec::new(),
            cumulative_digest: Self::empty_cumulative_digest(),
        }
    }

    pub fn empty_cumulative_digest() -> [u8; 32] {
        sha3::Sha3_256::new().finalize().into()
    }

    /// Validate the structural invariants required by canonical serialization.
    pub fn validate(&self) -> Result<(), CheckpointValidationError> {
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION {
            return Err(CheckpointValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        for pair in self.pending_requests.windows(2) {
            if pair[0].sign_id > pair[1].sign_id {
                return Err(CheckpointValidationError::UnsortedPendingRequests);
            }
            if pair[0].sign_id == pair[1].sign_id {
                return Err(CheckpointValidationError::DuplicatePendingRequest(
                    pair[0].sign_id,
                ));
            }
        }
        Ok(())
    }

    /// Return the deterministic bytes committed by a version 2 checkpoint.
    ///
    /// Pending requests are sorted by `SignId` for the commitment even when a
    /// caller constructed the value in another order. Recovery/persistence
    /// still require canonical ordering through `validate()` so the wire
    /// projection cannot have multiple representations for one checkpoint.
    pub fn canonical_payload_bytes(&self) -> Vec<u8> {
        let mut pending_requests = self.pending_requests.clone();
        pending_requests.sort_by_key(|pending| pending.sign_id);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"mpc-checkpoint");
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        bytes.extend_from_slice(&borsh::to_vec(&self.chain).expect("serialize checkpoint chain"));
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(
            &borsh::to_vec(&(pending_requests.len() as u32))
                .expect("serialize checkpoint request count"),
        );
        for pending in pending_requests {
            bytes.extend_from_slice(&pending.sign_id.request_id);
            bytes.extend_from_slice(&(pending.canonical_transaction.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&pending.canonical_transaction);
        }
        bytes
    }

    pub fn digest(&self) -> [u8; 32] {
        sha3::Sha3_256::digest(self.canonical_payload_bytes()).into()
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
