use std::sync::Arc;

use crate::{Chain, RespondBidirectionalTx, SignArgs, SignBidirectionalEvent, SignId};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SignKind {
    Sign,
    SignBidirectional(SignBidirectionalEvent),
    RespondBidirectional(RespondBidirectionalTx),
}

/// Payload-free projection of `SignKind`, used as a metric label.
///
/// For bidirectional requests this doubles as the leg discriminator: both legs
/// share a `SignId` and run the same phases, so the kind is the only thing that
/// tells the initial signature apart from the post-execution response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    Sign,
    SignBidirectional,
    RespondBidirectional,
}

impl RequestKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::SignBidirectional => "sign_bidirectional",
            Self::RespondBidirectional => "respond_bidirectional",
        }
    }
}

impl SignKind {
    pub fn request_kind(&self) -> RequestKind {
        match self {
            Self::Sign => RequestKind::Sign,
            Self::SignBidirectional(_) => RequestKind::SignBidirectional,
            Self::RespondBidirectional(_) => RequestKind::RespondBidirectional,
        }
    }
}

/// Messages sent into the node's sign-request processing queue.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum SignCommand {
    Request(Arc<IndexedSignRequest>),
    Completion(SignId),
    AbortChain(Chain),
}

/// All relevant info pertaining to an indexed sign request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

    /// Metric-label kind of this request. See [`RequestKind`].
    pub fn request_kind(&self) -> RequestKind {
        self.kind.request_kind()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The label strings are a metrics contract: dashboards and alerts select on
    /// them, so a rename here silently breaks queries rather than the build.
    #[test]
    fn request_kind_labels_are_stable() {
        assert_eq!(RequestKind::Sign.as_str(), "sign");
        assert_eq!(
            RequestKind::SignBidirectional.as_str(),
            "sign_bidirectional"
        );
        assert_eq!(
            RequestKind::RespondBidirectional.as_str(),
            "respond_bidirectional"
        );
    }
}
