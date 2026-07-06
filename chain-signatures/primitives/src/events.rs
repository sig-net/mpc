use crate::{
    bidirectional::RespondBidirectionalEvent, BidirectionalTxId, Chain, IndexedSignRequest, SignId,
    Signature,
};

/// Unified event produced by a chain stream
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ChainEvent {
    SignRequest {
        /// The sign request that was observed on the chain.
        request: IndexedSignRequest,
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
        block_height: u64,
        result: ExecutionOutcome,
    },
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
            ChainEvent::ExecutionConfirmed {
                tx_id,
                sign_id,
                source_chain,
                block_height,
                result,
            } => f
                .debug_struct("ExecutionConfirmed")
                .field("tx_id", tx_id)
                .field("sign_id", sign_id)
                .field("source_chain", source_chain)
                .field("block_height", block_height)
                .field("result", result)
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    Success { output: Vec<u8> },
    Failed,
}

#[derive(Clone, Debug)]
pub struct SignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub signature: Signature,
    pub chain: Chain,
}
