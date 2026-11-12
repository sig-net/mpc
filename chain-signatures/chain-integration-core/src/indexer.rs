use mpc_primitives::{Chain, ChainConfig, ChainEvent, ExecutionOutcome};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::telemetry::ExtractionFailureKind;

/// Outcome to attest when a request's transaction can never execute — its
/// replay protection consumed by another request's transaction, or its
/// validity window closed. `Unviable` only where the source encodes it
/// (`ChainConfig::encodes_unviable`); the rest refund on `Failed`.
pub fn unexecutable_outcome(source: Chain) -> ExecutionOutcome {
    if source.encodes_unviable() {
        ExecutionOutcome::Unviable
    } else {
        ExecutionOutcome::Failed
    }
}

/// A failed output extraction.
///
/// Only failures that are a pure function of on-chain data and the request's
/// own schemas are [`Terminal`](ExtractionFailure::Terminal): every node
/// derives them identically. Anything that depends on *this* node's RPC
/// endpoint — transport errors, missing tracer support, a malformed
/// provider response, an unverdicted receipt — is
/// [`Retryable`](ExtractionFailure::Retryable), because a peer with a
/// healthy endpoint would extract an output just fine and unilaterally
/// failing here would stall signing on divergent responses.
/// A terminal classification does not authorize removing source-checkpoint
/// membership based on independently advancing destination observations.
#[derive(Debug, thiserror::Error)]
pub enum ExtractionFailure {
    #[error(transparent)]
    Retryable(#[from] anyhow::Error),
    #[error("{0:#}")]
    Terminal(#[source] anyhow::Error),
}

impl ExtractionFailure {
    pub fn kind(&self) -> ExtractionFailureKind {
        match self {
            Self::Retryable(_) => ExtractionFailureKind::Retryable,
            Self::Terminal(_) => ExtractionFailureKind::Terminal,
        }
    }
}

/// Interface for a chain indexer that owns its full catchup + live loop.
///
/// Implementations emit the ordered event sequence (catchup events →
/// [`ChainEvent::CatchupCompleted`] → live events) on `events_tx`, resuming from
/// the chain's persisted progress and its own current tip. `cancel` is honoured
/// for supervisor-driven kill+restart on regression/watchdog.
#[async_trait::async_trait]
pub trait ChainIndexer: Send + Sync + 'static {
    const CHAIN: Chain;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()>;
}
