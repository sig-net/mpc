//! Midnight indexer implementation.

use crate::config::MidnightConfig;
use crate::rpc::ArchiveState;

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
        // Fail on an unusable config here, once, rather than forever at
        // runtime once the read path dials these endpoints.
        config.validate()?;
        // Deliberately network-free beyond that: the CLI gate calls new()
        // once and logs the error without retrying, so a dial here would
        // turn a transient outage at boot into a permanently disabled
        // chain. The archive-state probe and catchup-mode selection run at
        // the start of each supervised run() instead, via
        // MidnightRpc::probe_archive_state and select_catchup_mode: B6
        // wires that call when it writes run(), B7 implements the catchup
        // modes the result selects.
        Ok(Self {
            config,
            state_manager,
            telemetry,
        })
    }
}

/// Applies the startup policy to the archive probe's answer:
/// probe-and-degrade by default, strict refusal when the operator set
/// `require_archive_state`.
///
/// Degrading means catchup falls back to the WATERMARK path (resume from
/// the last processed block using only data the node still serves) instead
/// of exact-block contract-state reads. B6's `run()` consumes the returned
/// mode at its start, right after `MidnightRpc::connect`, and threads it
/// into the catchup step; B7 implements the two modes it selects; see
/// `probe_archive_state` for why the probe does not run at construction.
/// A `midnight_state_pruned` gauge has no `ChainTelemetry` hook yet, so
/// the warning below is the operational signal until telemetry grows one.
pub fn select_catchup_mode(
    state: ArchiveState,
    require_archive_state: bool,
) -> anyhow::Result<ArchiveState> {
    match state {
        ArchiveState::Archive => Ok(state),
        ArchiveState::Pruned { probed_height } => {
            anyhow::ensure!(
                !require_archive_state,
                "midnight node cannot serve contract state at height {probed_height} and \
                 require_archive_state is set: rerun the node with --state-pruning archive, \
                 or unset require_archive_state to accept watermark catchup"
            );
            tracing::warn!(
                probed_height,
                "midnight node is pruned within the archive probe window; catchup will \
                 degrade to the watermark path. Rerun the node with --state-pruning archive \
                 to restore exact-block reads"
            );
            Ok(state)
        }
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

    #[test]
    fn select_catchup_mode_degrades_pruned_by_default() {
        // Probe-and-degrade: pruned is a MODE, not an error, unless the
        // operator opted into strict refusal. Archive always passes.
        assert_eq!(
            select_catchup_mode(ArchiveState::Archive, false).unwrap(),
            ArchiveState::Archive
        );
        assert_eq!(
            select_catchup_mode(ArchiveState::Archive, true).unwrap(),
            ArchiveState::Archive
        );
        assert_eq!(
            select_catchup_mode(ArchiveState::Pruned { probed_height: 924 }, false).unwrap(),
            ArchiveState::Pruned { probed_height: 924 }
        );
    }

    #[test]
    fn select_catchup_mode_refuses_pruned_when_archive_state_is_required() {
        // The strict error must hand the operator everything needed to act:
        // the option that made this fatal, the height that failed, and the
        // node-side fix.
        let err = select_catchup_mode(ArchiveState::Pruned { probed_height: 924 }, true)
            .expect_err("require_archive_state turns pruned into a startup error")
            .to_string();
        for needle in ["require_archive_state", "924", "--state-pruning archive"] {
            assert!(
                err.contains(needle),
                "strict refusal must name {needle:?}, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn midnight_indexer_rejects_an_unusable_config() {
        let config = MidnightConfig {
            sidecar_url: "http://127.0.0.1:8790".to_string(),
            node_ws_url: String::new(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            rpc: Default::default(),
            sidecar: Default::default(),
            indexer: Default::default(),
        };
        let Err(err) = TestIndexer::new(config, MockStateManager::new(), NoopChainTelemetry).await
        else {
            panic!("an empty node_ws_url must fail at construction, not forever at runtime")
        };
        let err = err.to_string();
        assert!(err.contains("node_ws_url"), "unexpected error: {err}");
    }
}
