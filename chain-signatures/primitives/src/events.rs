use std::sync::Arc;

use crate::{
    bidirectional::RespondBidirectionalEvent, BidirectionalTxId, Chain, IndexedSignRequest, SignId,
    Signature,
};

/// The target block a response attests: its height, and its hash, which the
/// response's entropy derives from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttestedBlock {
    pub height: u64,
    pub hash: [u8; 32],
}

impl std::fmt::Debug for AttestedBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.height, hex::encode(self.hash))
    }
}

/// Unified event produced by a chain stream
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ChainEvent {
    SignRequest {
        /// The sign request that was observed on the chain.
        request: Arc<IndexedSignRequest>,
        /// Optional block timestamp of the request, if available. This is used for metrics reporting.
        block_timestamp: Option<u64>,
    },
    Respond(SignatureRespondedEvent),
    RespondBidirectional(RespondBidirectionalEvent),

    /// Catchup has completed and live events may be forwarded to the signer.
    CatchupCompleted,

    /// Block height indicating the client has observed/processed up to `u64` (slot/block)
    Block(u64),

    /// A watched bidirectional execution has been observed on the target chain.
    /// The client detected the execution, performed chain-specific extraction, and
    /// carries either the serialized output (Success) or a failure indicator.
    ExecutionConfirmed {
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        source_chain: Chain,
        block: AttestedBlock,
        result: ExecutionOutcome,
    },

    /// The hash of a final block whose height the node asked for, to attest at it.
    BlockHash(AttestedBlock),
}

impl std::fmt::Debug for ChainEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainEvent::SignRequest {
                request,
                block_timestamp,
            } => f
                .debug_struct("SignRequest")
                .field("id", &request.id)
                .field("chain", &request.chain.as_str())
                .field("block_timestamp", block_timestamp)
                .finish(),
            ChainEvent::Respond(ev) => f
                .debug_tuple("Respond")
                .field(&ev.request_id)
                .field(&ev.chain.as_str())
                .finish(),
            ChainEvent::RespondBidirectional(ev) => f
                .debug_tuple("RespondBidirectional")
                .field(&ev.request_id)
                .field(&ev.chain.as_str())
                .finish(),
            ChainEvent::CatchupCompleted => write!(f, "CatchupCompleted"),
            ChainEvent::Block(b) => write!(f, "Block({b})"),
            ChainEvent::BlockHash(block) => {
                write!(f, "BlockHash({block:?})")
            }
            ChainEvent::ExecutionConfirmed {
                tx_id,
                sign_id,
                source_chain,
                block,
                result,
            } => f
                .debug_struct("ExecutionConfirmed")
                .field("tx_id", tx_id)
                .field("sign_id", sign_id)
                .field("source_chain", source_chain)
                .field("block", block)
                .field("result", result)
                .finish(),
        }
    }
}

/// Internal watcher result, carrying successful output or an extraction failure.
/// Unlike an attestation outcome kind, extraction failure cannot be signed and
/// requires source-specific cleanup or parking.
#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    Success {
        output: Vec<u8>,
    },
    /// Reverted execution, or a replacement/consumed nonce under a source
    /// chain's legacy failure policy.
    Failed,
    /// The transaction executed, but its output could not be interpreted against
    /// the request's own schemas.
    ExtractionFailed,
    /// A finalized different transaction consumed this transaction's nonce.
    /// Emitted for Midnight only, at the observed replacement block's height.
    Unviable,
}

#[derive(Clone, Debug)]
pub struct SignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub signature: Signature,
    pub chain: Chain,
}
