use crate::{Chain, RespondBidirectionalTx, SignArgs, SignBidirectionalEvent, SignId};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SignKind {
    Sign,
    SignBidirectional(SignBidirectionalEvent),
    RespondBidirectional(RespondBidirectionalTx),
}

/// All relevant info pertaining to an indexed sign request.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IndexedSignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    /// Unix timestamp when the request was indexed by MPC node.
    /// Preserved across recoveries to maintain original request creation time.
    pub unix_timestamp_indexed: u64,
    pub kind: SignKind,
}

impl IndexedSignRequest {
    pub fn new(
        id: SignId,
        args: SignArgs,
        chain: Chain,
        unix_timestamp_indexed: u64,
        kind: SignKind,
    ) -> Self {
        Self {
            id,
            args,
            chain,
            unix_timestamp_indexed,
            kind,
        }
    }

    pub fn sign(id: SignId, args: SignArgs, chain: Chain, unix_timestamp_indexed: u64) -> Self {
        Self::new(id, args, chain, unix_timestamp_indexed, SignKind::Sign)
    }

    pub fn sign_bidirectional(
        id: SignId,
        args: SignArgs,
        chain: Chain,
        unix_timestamp_indexed: u64,
        event: SignBidirectionalEvent,
    ) -> Self {
        Self::new(
            id,
            args,
            chain,
            unix_timestamp_indexed,
            SignKind::SignBidirectional(event),
        )
    }

    pub fn respond_bidirectional(
        id: SignId,
        args: SignArgs,
        chain: Chain,
        unix_timestamp_indexed: u64,
        tx: RespondBidirectionalTx,
    ) -> Self {
        Self::new(
            id,
            args,
            chain,
            unix_timestamp_indexed,
            SignKind::RespondBidirectional(tx),
        )
    }
}
