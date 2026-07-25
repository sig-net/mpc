//! Midnight indexer implementation.

use crate::config::MidnightConfig;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::Empty;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{Chain, ChainEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct MidnightIndexer<S: StateManager, T: ChainTelemetry> {
    config: MidnightConfig,
    state_manager: S,
    /// Held for the read path; the scaffold indexes nothing, so it reports nothing.
    #[allow(dead_code)]
    telemetry: T,
}

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    pub async fn new(
        config: MidnightConfig,
        state_manager: S,
        telemetry: T,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            state_manager,
            telemetry,
        })
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for MidnightIndexer<S, T> {
    const CHAIN: Chain = Chain::Midnight;

    // TODO: not used, required by trait, remove later
    type Block = ();
    type Iter = Empty<()>;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let checkpoint = self
            .state_manager
            .get_processed_block(Chain::Midnight)
            .await
            .unwrap_or(0);

        tracing::warn!(
            checkpoint,
            node_ws_url = %self.config.node_ws_url,
            sidecar_url = %self.config.sidecar_url,
            "midnight indexer scaffold: no requests will be indexed"
        );

        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send midnight catchup completed event")?;

        cancel.cancelled().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_chain_integration_core::utils::stream::chain_event_channel;
    use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
    use std::time::Duration;

    type TestIndexer = MidnightIndexer<MockStateManager, NoopChainTelemetry>;

    #[tokio::test]
    async fn midnight_indexer_runs_noop() {
        assert_eq!(TestIndexer::CHAIN, Chain::Midnight);

        let indexer = TestIndexer::new(
            MidnightConfig::default(),
            MockStateManager::new(),
            NoopChainTelemetry,
        )
        .await
        .expect("indexer construction should succeed");

        let (events_tx, mut events_rx) = chain_event_channel();
        let cancel = CancellationToken::new();
        let mut run_handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { indexer.run(events_tx, cancel).await }
        });

        let event = tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
            .await
            .expect("timed out waiting for chain event")
            .expect("events channel closed before any event was emitted");
        assert!(
            matches!(event, ChainEvent::CatchupCompleted),
            "expected CatchupCompleted, got {event:?}"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut run_handle)
                .await
                .is_err(),
            "run() returned before cancel fired"
        );

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), run_handle)
            .await
            .expect("run() should stop promptly after cancel")
            .expect("run task panicked")
            .expect("run() should exit Ok on cancel");
    }
}
