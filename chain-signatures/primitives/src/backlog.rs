use borsh::{BorshDeserialize, BorshSerialize};
use k256::{Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::sync::Arc;

use crate::{BidirectionalTx, Chain, IndexedSignRequest, SignId, Signature};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Participant(pub u32);

impl From<u32> for Participant {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<Participant> for u32 {
    fn from(p: Participant) -> Self {
        p.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishState {
    pub signature: Signature,
    pub participants: Vec<Participant>,
    pub is_proposer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignStatus {
    PendingGeneration,
    PendingPublish { publish: PublishState },
    PendingExecution { tx: BidirectionalTx },
    PendingGenerationBidirectional,
    PendingPublishBidirectional { publish: PublishState },
}

impl SignStatus {
    pub fn is_pending_generation(&self) -> bool {
        matches!(
            self,
            SignStatus::PendingGeneration | SignStatus::PendingGenerationBidirectional
        )
    }

    pub fn is_pending_execution(&self) -> bool {
        matches!(self, SignStatus::PendingExecution { .. })
    }

    /// Project this status onto what is observable at a checkpoint's own chain height.
    pub fn consensus_tag(&self) -> u8 {
        match self {
            SignStatus::PendingGeneration | SignStatus::PendingPublish { .. } => 0,
            SignStatus::PendingExecution { .. } => 1,
            SignStatus::PendingGenerationBidirectional
            | SignStatus::PendingPublishBidirectional { .. } => 2,
        }
    }

    pub fn execution_tx(&self) -> Option<&BidirectionalTx> {
        match self {
            SignStatus::PendingExecution { tx } => Some(tx),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BacklogError {
    #[error("request not found for chain {chain:?} with id {id:?}")]
    NotFound { chain: Chain, id: SignId },
    #[error("chain not initialized: {chain:?}")]
    ChainNotInitialized { chain: Chain },
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("cannot advance sign request: status must be pending generation or publishing")]
    InvalidAdvanceTransition,
    #[error("cannot mark publishing: status must be pending generation")]
    InvalidPublishingTransition,
    #[error("cannot transition to bidirectional response: id must match and request must be RespondBidirectional")]
    InvalidBidirectionalResponseTransition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacklogEntry {
    pub request: Arc<IndexedSignRequest>,
    pub status: SignStatus,
}

impl BacklogEntry {
    pub fn new(request: Arc<IndexedSignRequest>) -> Self {
        Self {
            request,
            status: SignStatus::PendingGeneration,
        }
    }

    pub fn with_status(request: Arc<IndexedSignRequest>, status: SignStatus) -> Self {
        Self { request, status }
    }

    pub fn pending_execution(request: Arc<IndexedSignRequest>, tx: BidirectionalTx) -> Self {
        Self::with_status(request, SignStatus::PendingExecution { tx })
    }

    pub fn sign_id(&self) -> SignId {
        self.request.id
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.request.id.request_id
    }

    pub fn source_chain(&self) -> Chain {
        self.request.chain
    }

    pub fn status(&self) -> SignStatus {
        self.status.clone()
    }

    pub fn execution_tx(&self) -> Option<&BidirectionalTx> {
        self.status.execution_tx()
    }

    pub fn set_status(&mut self, status: SignStatus) {
        self.status = status;
    }

    pub fn set_request(&mut self, request: Arc<IndexedSignRequest>) {
        self.request = request;
    }

    pub fn transition_to_bidirectional_response(
        &mut self,
        request: Arc<IndexedSignRequest>,
    ) -> Result<(), BacklogError> {
        if self.request.id != request.id
            || !matches!(&request.kind, crate::SignKind::RespondBidirectional(_))
        {
            return Err(BacklogError::InvalidBidirectionalResponseTransition);
        }

        self.request = request;
        self.status = SignStatus::PendingGenerationBidirectional;
        Ok(())
    }

    pub fn mark_publishing(&mut self, publish: PublishState) -> Result<(), BacklogError> {
        match (&self.request.kind, self.status.clone()) {
            (
                crate::SignKind::Sign | crate::SignKind::SignBidirectional(_),
                SignStatus::PendingGeneration,
            ) => {
                self.status = SignStatus::PendingPublish { publish };
                Ok(())
            }
            (
                crate::SignKind::RespondBidirectional(_),
                SignStatus::PendingGenerationBidirectional,
            ) => {
                self.status = SignStatus::PendingPublishBidirectional { publish };
                Ok(())
            }
            _ => Err(BacklogError::InvalidPublishingTransition),
        }
    }

    pub fn advance_to_execution(
        &mut self,
        bidirectional_tx: BidirectionalTx,
    ) -> Result<(), BacklogError> {
        match (&self.request.kind, self.status.clone()) {
            (
                crate::SignKind::SignBidirectional(_),
                SignStatus::PendingGeneration | SignStatus::PendingPublish { .. },
            ) => {
                self.status = SignStatus::PendingExecution {
                    tx: bidirectional_tx,
                };
                Ok(())
            }
            _ => Err(BacklogError::InvalidAdvanceTransition),
        }
    }

    pub fn is_bidirectional(&self) -> bool {
        matches!(self.request.kind, crate::SignKind::SignBidirectional(_))
    }

    pub fn typename(&self) -> &'static str {
        match (&self.request.kind, &self.status) {
            (crate::SignKind::Sign, _) => "Sign",
            (crate::SignKind::SignBidirectional(_), SignStatus::PendingExecution { .. }) => {
                "BidirectionalExecution"
            }
            (crate::SignKind::SignBidirectional(_), SignStatus::PendingGeneration) => {
                "BidirectionalPending"
            }
            (crate::SignKind::SignBidirectional(_), _) => "BidirectionalPending",
            (
                crate::SignKind::RespondBidirectional(_),
                SignStatus::PendingGenerationBidirectional,
            ) => "BidirectionalRespondPending",
            (crate::SignKind::RespondBidirectional(_), _) => "RespondBidirectional",
        }
    }
}

/// A checkpoint represents the backlog state at a specific block height.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub chain: Chain,
    pub block_height: u64,
    pub pending_requests: Vec<BacklogEntry>,
    /// Commitment to each pending request's checkpoint-consensus phase.
    ///
    /// This is computed by hashing each request's checkpoint-consensus phase
    /// in the same sorted order as `pending_requests`. It lets the checkpoint
    /// digest commit to cross-node request progress without hashing
    /// the full recovery payload, which may include node-local fields.
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
        for entry in &self.pending_requests {
            hasher.update(entry.sign_id().request_id);
        }
        hasher.update(self.cumulative_digest);
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
