use crate::backlog::{consensus, Backlog, CheckpointError};
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::types::CheckpointWatcher;

use mpc_primitives::Chain;
use near_account_id::AccountId;
use tokio::sync::watch;

/// Drop pending bodies that a restart cannot safely keep rebuilding on.
///
/// A pending body may have been produced by an older checkpoint format. Its vote can
/// still be in flight, so it might settle after the restart; the node must be able to
/// serve it to peers, but must not treat it as the base it builds the next body on.
/// The canonical settled checkpoint is the sole authority: it is recovered from peers
/// by the ordinary alignment path, and new requests build on top of it.
///
/// Bodies are moved to a serve-only orphan store, then all pending entries are cleared
/// in one step. Only bodies strictly above the settled height are orphaned — a pending
/// at or below it is stale history that a forward-moving consensus can never settle,
/// and it is dropped along with the rest by `clear_pending`.
///
/// Hydration is excluded: its indexer has no backfill, so discarding pending bodies and
/// relying on the settled checkpoint plus peer replay would lose requests that cannot
/// be rebuilt from chain history (doc/checkpoints.md §7).
///
/// Returns the number of bodies moved to the orphan store.
pub(crate) async fn discard_unconfirmed_pending_on_restart(
    chain: Chain,
    backlog: &Backlog,
) -> Result<usize, CheckpointError> {
    if chain == Chain::Hydration {
        tracing::info!(
            ?chain,
            "keeping pending checkpoints on restart (no backfill)"
        );
        return Ok(0);
    }

    let checkpoints = backlog.checkpoints();
    let settled = checkpoints
        .storage()
        .load_latest(chain)
        .await
        .map_err(|source| CheckpointError::Storage { chain, source })?;
    let Some(settled) = settled else {
        // Nothing settled yet: there is no authoritative base to build on, so the
        // pending bodies are all this node has. Keep them.
        tracing::info!(?chain, "no settled checkpoint on startup; keeping pending");
        return Ok(0);
    };

    let pending = checkpoints.load_pending(chain).await?;
    let discarded: Vec<_> = pending
        .into_iter()
        .filter(|cp| cp.block_height > settled.block_height)
        .collect();
    if discarded.is_empty() {
        return Ok(0);
    }

    for checkpoint in &discarded {
        checkpoints.persist_orphan(checkpoint).await?;
    }
    // One atomic clear for the whole chain, after every body is safely retained.
    checkpoints.clear_pending(chain).await?;
    // Re-hydration happens in `recover_backlog` below, after this returns.
    Ok(discarded.len())
}

/// Node-side checkpoint recovery:
/// loads the local checkpoint into the backlog (it only touches local storage),
/// then aligns the backlog with the consensus checkpoint feed. Mesh availability
/// is handled inside `align_backlog_with_consensus` when it needs to fetch a
/// checkpoint from peers. Returns whether the backlog was rebased.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_backlog(
    chain: Chain,
    load_local: bool,
    backlog: &Backlog,
    checkpoints_rx: &mut CheckpointWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    my_account_id: &AccountId,
    root_pk: mpc_primitives::PublicKey,
) -> Result<bool, CheckpointError> {
    tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");

    // Startup only (not in-process indexer restarts): discard pending bodies from
    // an older format before hydration/regression, retaining them serve-only.
    if load_local {
        let discarded = discard_unconfirmed_pending_on_restart(chain, backlog).await?;
        if discarded > 0 {
            tracing::info!(%chain, discarded, "discarded unconfirmed pending checkpoints on startup");
        }
    }

    // Hydrate the in-memory pending checkpoint counter from storage on every
    // recovery pass so any counter drift self-heals across restarts. After a
    // startup discard this resets the counter to the now-empty pending set.
    backlog.checkpoints().hydrate(chain).await?;

    // Hydrate local backlog state from durable storage on initial startup.
    if load_local {
        match backlog.recover_local(chain, root_pk).await? {
            Some(checkpoint) => {
                tracing::info!(
                    ?chain,
                    height = checkpoint.block_height,
                    "hydrated local checkpoint"
                );
            }
            None => {
                tracing::info!(?chain, "no local checkpoint found");
            }
        }
    }

    let rebased = consensus::align_backlog_with_consensus(
        chain,
        backlog,
        checkpoints_rx,
        mesh_state,
        node_client,
        my_account_id,
        root_pk,
    )
    .await
    .is_some();

    Ok(rebased)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Checkpoint;
    use crate::storage::checkpoint_storage::CheckpointStorage;
    use mpc_chain_integration_core::StateManager;

    fn settled(chain: Chain, height: u64) -> Checkpoint {
        Checkpoint::reset(chain, height)
    }

    async fn backlog_with(chain: Chain, settled_height: u64, pending_heights: &[u64]) -> Backlog {
        let storage = CheckpointStorage::in_memory();
        storage
            .persist(&settled(chain, settled_height))
            .await
            .unwrap();
        for &height in pending_heights {
            storage
                .persist_pending(&Checkpoint::reset(chain, height))
                .await
                .unwrap();
        }
        Backlog::persisted(storage)
    }

    #[tokio::test]
    async fn startup_discard_moves_pending_above_settled_to_orphan() {
        let chain = Chain::Ethereum;
        let backlog = backlog_with(chain, 100, &[90, 110, 120]).await;
        backlog.checkpoints().hydrate(chain).await.unwrap();
        assert_eq!(backlog.checkpoints().count(chain), 3);

        let discarded = discard_unconfirmed_pending_on_restart(chain, &backlog)
            .await
            .unwrap();
        assert_eq!(
            discarded, 2,
            "only bodies above the settled height are moved"
        );

        assert!(backlog
            .checkpoints()
            .load_pending(chain)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(backlog.checkpoints().count(chain), 3, "caller re-hydrates");
        backlog.checkpoints().hydrate(chain).await.unwrap();
        assert_eq!(backlog.checkpoints().count(chain), 0);

        // The canonical settled checkpoint is untouched and authoritative.
        assert_eq!(
            backlog
                .checkpoints()
                .storage()
                .load_latest(chain)
                .await
                .unwrap(),
            Some(settled(chain, 100))
        );
        // The discarded bodies are still servable by digest.
        for height in [110, 120] {
            let cp = settled(chain, height);
            assert_eq!(
                backlog.checkpoints().find(chain, cp.digest()).await,
                Some(cp)
            );
        }
        // A pending at or below the settled height was dropped, not orphaned.
        assert_eq!(
            backlog
                .checkpoints()
                .find_orphan(chain, settled(chain, 90).digest())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn startup_discard_skips_hydration() {
        // Hydration has no backfill; discarding its pending bodies would lose requests
        // that cannot be replayed from chain history (doc/checkpoints.md §7).
        let chain = Chain::Hydration;
        let backlog = backlog_with(chain, 100, &[110]).await;
        let digest = settled(chain, 110).digest();
        backlog.checkpoints().hydrate(chain).await.unwrap();

        let discarded = discard_unconfirmed_pending_on_restart(chain, &backlog)
            .await
            .unwrap();
        assert_eq!(discarded, 0);
        assert_eq!(backlog.checkpoints().count(chain), 1);
        assert_eq!(
            backlog.checkpoints().load_pending(chain).await.unwrap(),
            vec![settled(chain, 110)]
        );
        assert_eq!(
            backlog
                .checkpoints()
                .find_orphan(chain, digest)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn startup_discard_is_isolated_per_chain() {
        let storage = CheckpointStorage::in_memory();
        storage
            .persist(&settled(Chain::Ethereum, 100))
            .await
            .unwrap();
        storage.persist(&settled(Chain::Solana, 200)).await.unwrap();
        storage
            .persist_pending(&settled(Chain::Ethereum, 110))
            .await
            .unwrap();
        storage
            .persist_pending(&settled(Chain::Solana, 210))
            .await
            .unwrap();
        let backlog = Backlog::persisted(storage);

        assert_eq!(
            discard_unconfirmed_pending_on_restart(Chain::Ethereum, &backlog)
                .await
                .unwrap(),
            1
        );
        assert!(backlog
            .checkpoints()
            .load_pending(Chain::Ethereum)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            backlog
                .checkpoints()
                .load_pending(Chain::Solana)
                .await
                .unwrap(),
            vec![settled(Chain::Solana, 210)]
        );
        assert!(backlog
            .checkpoints()
            .find(Chain::Ethereum, settled(Chain::Ethereum, 110).digest())
            .await
            .is_some());
        assert_eq!(
            backlog
                .checkpoints()
                .find_orphan(Chain::Solana, settled(Chain::Solana, 210).digest())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn startup_discard_skips_when_there_is_no_settled_checkpoint() {
        let chain = Chain::Ethereum;
        let storage = CheckpointStorage::in_memory();
        storage.persist_pending(&settled(chain, 110)).await.unwrap();
        let backlog = Backlog::persisted(storage);

        assert_eq!(
            discard_unconfirmed_pending_on_restart(chain, &backlog)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            backlog.checkpoints().load_pending(chain).await.unwrap(),
            vec![settled(chain, 110)]
        );
    }

    #[tokio::test]
    async fn recovery_hydrates_from_settled_checkpoint_after_discard() {
        // End-to-end through `recover_backlog`: with pending emptied, `recover_local`
        // falls back to the canonical settled checkpoint, so new requests build on
        // top of it rather than on a body from the old format.
        let chain = Chain::Ethereum;
        let backlog = backlog_with(chain, 100, &[110, 120]).await;
        let (_digest_tx, mut digest_rx) = watch::channel(None);
        let (_mesh_tx, mut mesh_rx) = watch::channel(MeshState::default());
        let client = NodeClient::new();
        let me: AccountId = "test.near".parse().unwrap();

        let rebased = recover_backlog(
            chain,
            true,
            &backlog,
            &mut digest_rx,
            &mut mesh_rx,
            &client,
            &me,
            k256::AffinePoint::GENERATOR,
        )
        .await
        .unwrap();
        assert!(!rebased, "no consensus digest; nothing to rebase onto");

        assert_eq!(backlog.checkpoints().count(chain), 0, "counter reset");
        assert_eq!(backlog.get_processed_block(chain).await, Some(100));
        assert_eq!(
            backlog.checkpoints().latest(chain).await.unwrap(),
            Some(settled(chain, 100))
        );
        // The discarded bodies remain servable to peers.
        assert_eq!(
            backlog
                .checkpoints()
                .find(chain, settled(chain, 110).digest())
                .await,
            Some(settled(chain, 110))
        );
        // A second startup pass (load_local = false) must not re-discard anything.
        let _ = recover_backlog(
            chain,
            false,
            &backlog,
            &mut digest_rx,
            &mut mesh_rx,
            &client,
            &me,
            k256::AffinePoint::GENERATOR,
        )
        .await
        .unwrap();
        assert!(backlog
            .checkpoints()
            .load_pending(chain)
            .await
            .unwrap()
            .is_empty());
    }
}
