//! Backlog-facing progress and status of bidirectional requests.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::backlog::Publishing;
use crate::protocol::IndexedSignRequest;

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
    /// Awaiting execution on the target chain, under any of the entry's transactions.
    Executing,
    /// Phase 2: Signing the completion/respond transaction for the source chain.
    Final {
        respond_request: Arc<IndexedSignRequest>,
        progress: SignProgress,
    },
    /// Terminal output extraction failure; kept until the request's Response.
    Parked,
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
                BidirectionalProgress::Executing | BidirectionalProgress::Parked,
            ) => false,
        }
    }

    pub fn is_pending_execution(&self) -> bool {
        matches!(self, Self::Bidirectional(BidirectionalProgress::Executing))
    }

    pub fn publishing(&self) -> Option<&Publishing> {
        match self {
            Self::Sign(progress) => progress.publishing(),
            Self::Bidirectional(BidirectionalProgress::Initial(progress)) => progress.publishing(),
            Self::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                progress.publishing()
            }
            Self::Bidirectional(
                BidirectionalProgress::Executing | BidirectionalProgress::Parked,
            ) => None,
        }
    }
}
