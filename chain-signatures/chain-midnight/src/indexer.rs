//! Midnight indexer implementation.

use crate::config::MidnightConfig;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::Empty;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{Chain, ChainEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Scaffold indexer: emits `CatchupCompleted`, then parks until cancelled.
///
/// When Midnight is ENABLED, this scaffold restart-loops roughly every
/// 5m15s: the stream supervisor's watchdog fires on `live_block_timeout(Midnight)`,
/// which is `expected_finality_time_secs` (15) plus the 300-second buffer,
/// because the scaffold never emits `ChainEvent::Block`. Harmless log noise
/// until the read path lands; written down here so it is read rather than
/// rediscovered in production logs.
///
/// The silence is also load-bearing, not only noisy.
/// `checkpoint_interval(Midnight)` is already `Some(120)`, so the first
/// `ChainEvent::Block` emitted after catchup starts checkpoint creation
/// (`stream/ops.rs::process_block_event`), a threshold signing request for
/// a chain that cannot yet publish. Emitting blocks is therefore not a
/// self-contained change: checkpoint signing stalls unless threshold-many
/// nodes have Midnight enabled, and a node without it still buffers peer
/// posits for checkpoint ids it never sees locally, in `posit_queues`
/// entries that only `retire_task` removes. Turn block emission on only
/// with a network-wide Midnight rollout, and ideally a bound or reaper on
/// `posit_queues`, first.
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
            MidnightConfig {
                sidecar_url: "http://127.0.0.1:8790".to_string(),
                node_ws_url: "ws://127.0.0.1:9944".to_string(),
                central_address: "ab".repeat(32),
                network_id: "undeployed".to_string(),
                rpc: Default::default(),
                sidecar: Default::default(),
                indexer: Default::default(),
            },
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
