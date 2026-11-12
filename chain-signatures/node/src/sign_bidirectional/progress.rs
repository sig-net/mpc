//! Backlog-facing progress and status of bidirectional requests.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::backlog::Publishing;
use crate::protocol::IndexedSignRequest;
use mpc_primitives::BidirectionalTx;

/// Progress of an active Cait-Sith MPC signing round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignProgress {
    /// Actively running or awaiting MPC signing.
    Generating,
    /// Signature produced; ready to publish or awaiting on-chain inclusion.
    Publishing(Publishing),
}

impl SignProgress {
    pub fn is_generating(&self) -> bool {
        matches!(self, Self::Generating)
    }

    pub fn publishing(&self) -> Option<&Publishing> {
        match self {
            Self::Publishing(publish) => Some(publish),
            Self::Generating => None,
        }
    }
}

/// Lifecycle stages of a two-phase bidirectional transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BidirectionalProgress {
    /// Phase 1: Signing the initial transaction for the source chain.
    Initial(SignProgress),
    /// Awaiting execution on the target chain.
    Executing(Arc<BidirectionalTx>),
    /// Phase 2: Signing the completion/respond transaction for the source chain.
    Final {
        respond_request: Arc<IndexedSignRequest>,
        progress: SignProgress,
    },
    /// Terminal output extraction failure; retained for source checkpoint agreement.
    Parked(Arc<BidirectionalTx>),
}

/// Overall status of any request held in the backlog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignStatus {
    Sign(SignProgress),
    Bidirectional(BidirectionalProgress),
}

impl SignStatus {
    pub fn is_pending_generation(&self) -> bool {
        match self {
            Self::Sign(progress) => progress.is_generating(),
            Self::Bidirectional(BidirectionalProgress::Initial(progress)) => {
                progress.is_generating()
            }
            Self::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                progress.is_generating()
            }
            Self::Bidirectional(
                BidirectionalProgress::Executing(_) | BidirectionalProgress::Parked(_),
            ) => false,
        }
    }

    pub fn is_pending_execution(&self) -> bool {
        matches!(
            self,
            Self::Bidirectional(BidirectionalProgress::Executing(_))
        )
    }

    pub fn execution_tx(&self) -> Option<&Arc<BidirectionalTx>> {
        match self {
            Self::Bidirectional(BidirectionalProgress::Executing(tx)) => Some(tx),
            _ => None,
        }
    }

    pub fn publishing(&self) -> Option<&Publishing> {
        match self {
            Self::Sign(progress) => progress.publishing(),
            Self::Bidirectional(BidirectionalProgress::Initial(progress)) => progress.publishing(),
            Self::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                progress.publishing()
            }
            Self::Bidirectional(
                BidirectionalProgress::Executing(_) | BidirectionalProgress::Parked(_),
            ) => None,
        }
    }

    /// Project this status onto what is observable at a checkpoint's own chain height.
    ///
    /// * `0` — the initial source-chain phase (standard Sign or initial Bidirectional).
    /// * `1` — the post-initial phase (Bidirectional awaiting target execution, parked, or final response).
    pub fn consensus_tag(&self) -> u8 {
        match self {
            Self::Sign(_) | Self::Bidirectional(BidirectionalProgress::Initial(_)) => 0,
            Self::Bidirectional(
                BidirectionalProgress::Executing(_)
                | BidirectionalProgress::Final { .. }
                | BidirectionalProgress::Parked(_),
            ) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BidirectionalProgress, SignProgress, SignStatus};
    use crate::backlog::mock::{mock_bidi_response, mock_publishing, mock_tx};
    use std::sync::Arc;

    #[test]
    fn test_checkpoint_consensus_bytes_deterministic_across_publish_states() {
        let dummy_tx = Arc::new(mock_tx(1));
        let dummy_respond_req = mock_bidi_response(&dummy_tx);

        let generation_tag = SignStatus::Sign(SignProgress::Generating).consensus_tag();
        let publish_tag =
            SignStatus::Sign(SignProgress::Publishing(mock_publishing())).consensus_tag();
        assert_eq!(
            generation_tag, publish_tag,
            "Generating and Publishing must produce identical consensus tags"
        );

        // Initial bidirectional phase matches standard sign
        let bidi_initial_gen_tag =
            SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating))
                .consensus_tag();
        assert_eq!(generation_tag, bidi_initial_gen_tag);

        // Post-initial phase: target-chain execution and the final response
        // generation/publish are indistinguishable at the source-chain height.
        let execution_tag =
            SignStatus::Bidirectional(BidirectionalProgress::Executing(dummy_tx)).consensus_tag();
        let gen_bidi_tag = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: Arc::clone(&dummy_respond_req),
            progress: SignProgress::Generating,
        })
        .consensus_tag();
        let pub_bidi_tag = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: dummy_respond_req,
            progress: SignProgress::Publishing(mock_publishing()),
        })
        .consensus_tag();
        assert_eq!(
            execution_tag, gen_bidi_tag,
            "Executing and Final Generating must share a consensus tag \
             (target-chain execution is not observable at the source-chain height)"
        );
        assert_eq!(
            gen_bidi_tag, pub_bidi_tag,
            "Final Generating and Final Publishing must produce identical consensus tags"
        );

        // The initial source-chain phase is observable at this checkpoint's height,
        // so it differs from the post-initial phase (execution / final response).
        assert_ne!(generation_tag, gen_bidi_tag);
    }
}
