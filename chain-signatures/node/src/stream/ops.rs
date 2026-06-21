use crate::backlog::Backlog;
use crate::metrics::requests::record_indexing_step_reached;
use crate::protocol::{Chain, IndexedSignRequest, Sign};
use crate::respond_bidirectional::CompletedTx;
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::sign_bidirectional::{SignBidirectionalEventExt, SignStatus};
use anchor_lang::prelude::Pubkey;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, ExecutionOutcome, RespondBidirectionalEvent, SignId,
    SignKind, Signature, SignatureRespondedEvent,
};
use tokio::sync::mpsc;

pub(crate) async fn process_sign_request(
    sign_request: IndexedSignRequest,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    caught_up: bool,
) -> anyhow::Result<()> {
    // Ethereum records its own indexing latency (includes finality delay) from the block timestamp in `parse_block`.
    if sign_request.chain != Chain::Ethereum {
        record_indexing_step_reached(sign_request.chain);
    }

    if matches!(sign_request.kind, SignKind::RespondBidirectional(_)) {
        anyhow::bail!("Unexpected sign request kind");
    }

    backlog.insert(sign_request.clone()).await;

    let chain = sign_request.chain;
    if caught_up {
        if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
            tracing::error!(?err, %chain, "failed to send sign request into queue");
        }
    }

    Ok(())
}

pub(crate) async fn requeue_pending_sign_requests(
    backlog: &Backlog,
    source_chain: Chain,
    sign_tx: mpsc::Sender<Sign>,
) {
    for sign_request in backlog.take_requeueable_requests(source_chain).await {
        let sign_id = sign_request.id;
        let source_chain = sign_request.chain;
        if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
            tracing::error!(
                ?err,
                ?sign_id,
                ?source_chain,
                "failed to requeue sign request after catchup"
            );
        }
    }
}

pub(crate) async fn resume_pending_publish_requests(
    backlog: &Backlog,
    source_chain: Chain,
    contract_watcher: &ContractStateWatcher,
    rpc: &RpcChannel,
) {
    let publishable = backlog.publishable_requests(source_chain).await;
    if publishable.is_empty() {
        return;
    }

    let Some(public_key) = contract_watcher.public_key().await else {
        tracing::warn!(%source_chain, count = publishable.len(), "cannot resume pending publish requests without a public key");
        return;
    };
    for (sign_request, publish) in publishable {
        if !publish.is_proposer {
            continue;
        }

        let sign_id = sign_request.id;
        rpc.publish_signature(
            public_key,
            sign_request,
            publish.signature,
            publish.participants,
        );
        tracing::info!(?sign_id, %source_chain, "resumed pending publish request after catchup");
    }
}

fn verify_entry_signature(
    root_public_key: mpc_primitives::PublicKey,
    entry: &crate::backlog::BacklogEntry,
    signature: &Signature,
    sign_id: SignId,
) -> anyhow::Result<()> {
    mpc_crypto::verify_signature(
        root_public_key,
        entry.request.args.epsilon,
        entry.request.args.payload,
        signature,
    )
    .map_err(|err| {
        anyhow::anyhow!(
            "respond event carried invalid signature for sign id {:?}: {err}",
            sign_id
        )
    })
}

pub(crate) async fn process_respond_event(
    respond_event: SignatureRespondedEvent,
    sign_tx: mpsc::Sender<Sign>,
    root_pk: mpc_primitives::PublicKey,
    backlog: &Backlog,
    caught_up: bool,
) -> anyhow::Result<()> {
    let sign_id = SignId::new(respond_event.request_id);
    let source_chain = respond_event.chain;
    let Some(entry) = backlog.get(source_chain, &sign_id).await else {
        tracing::info!(
            ?sign_id,
            ?source_chain,
            "respond event is already finalized or pruned; skipping"
        );
        return Ok(());
    };

    let responded_signature = respond_event.signature;

    verify_entry_signature(root_pk, &entry, &responded_signature, sign_id)?;

    let event = match &entry.request.kind {
        SignKind::Sign => {
            tracing::info!(?sign_id, "sign request completed successfully");
            backlog.remove(source_chain, &sign_id).await;
            if caught_up {
                if let Err(err) = sign_tx.send(Sign::Completion(sign_id)).await {
                    anyhow::bail!("failed to send completion for respond event: {err:?}");
                }
            }
            return Ok(());
        }
        SignKind::SignBidirectional(event) => event,
        SignKind::RespondBidirectional(_) => {
            anyhow::bail!("unexpected sign type: RespondBidirectional should not be generated from a sign event");
        }
        SignKind::Checkpoint(_) => {
            anyhow::bail!(
                "unexpected sign type: Checkpoint should not be generated from a sign event"
            );
        }
    };

    if entry.execution_tx().is_some() {
        tracing::info!(
            ?sign_id,
            ?source_chain,
            entry_type = %entry.typename(),
            "respond event backlog entry is already advanced; treating as processed"
        );
        return Ok(());
    }

    tracing::info!(?sign_id, "bidirectional processing initial respond event");
    let target_chain = event.target_chain().map_err(|err| {
        anyhow::anyhow!("failed to process respond event: {err:?} for sign id: {sign_id:?}")
    })?;

    // Get the MPC public key and derive the from_address.
    let epsilon = event.epsilon()?;
    let from_address = crate::sign_bidirectional::derive_user_address(root_pk, epsilon);

    let mpc_sig = responded_signature;

    // Sign and hash the transaction to get the correct tx_id and nonce
    let (signed_tx_hash, nonce) = crate::sign_bidirectional::sign_and_hash_transaction(
        &event.serialized_transaction,
        mpc_sig,
    )?;

    let tx_id = BidirectionalTxId(signed_tx_hash);

    let bidirectional_tx = BidirectionalTx {
        id: tx_id,
        sender: event.sender,
        serialized_transaction: event.serialized_transaction.clone(),
        source_chain,
        target_chain,
        caip2_id: event.caip2_id.clone(),
        key_version: event.key_version,
        deposit: event.deposit,
        path: event.path.clone(),
        algo: event.algo.clone(),
        dest: event.dest.clone(),
        params: event.params.clone(),
        output_deserialization_schema: event.output_deserialization_schema.clone(),
        respond_serialization_schema: event.respond_serialization_schema.clone(),
        request_id: respond_event.request_id,
        from_address: **from_address,
        nonce,
    };

    tracing::info!(
        ?sign_id,
        ?tx_id,
        nonce = ?bidirectional_tx.nonce,
        from_address = ?bidirectional_tx.from_address,
        "bidirectional tx details before advancement",
    );

    match backlog
        .advance(source_chain, sign_id, bidirectional_tx)
        .await
    {
        Ok(_) => {
            tracing::info!(
                ?sign_id,
                ?tx_id,
                ?target_chain,
                "advance bidirectional tx to execution successful"
            );
        }
        Err(err) => {
            tracing::error!(
                ?sign_id,
                ?tx_id,
                ?target_chain,
                ?err,
                "advance bidirectional tx to execution failed"
            );
        }
    }

    Ok(())
}

pub(crate) async fn process_respond_bidirectional_event(
    event: RespondBidirectionalEvent,
    sign_tx: mpsc::Sender<Sign>,
    root_pk: mpc_primitives::PublicKey,
    backlog: &Backlog,
    caught_up: bool,
) -> anyhow::Result<()> {
    let sign_id = SignId::new(event.request_id);
    let source_chain = event.chain;
    tracing::info!(?sign_id, "processing RespondBidirectionalEvent");

    let Some(entry) = backlog.get(source_chain, &sign_id).await else {
        tracing::warn!(?sign_id, "bidirectional tx not found on completion");
        return Ok(());
    };

    if !matches!(entry.request.kind, SignKind::RespondBidirectional(_)) {
        anyhow::bail!(
            "unexpected sign type for RespondBidirectionalEvent: {:?}",
            entry.request.kind
        );
    }

    verify_entry_signature(root_pk, &entry, &event.signature, sign_id)?;

    if backlog.remove(source_chain, &sign_id).await.is_some() {
        tracing::info!(?sign_id, "bidirectional tx completed");
    } else {
        tracing::warn!(?sign_id, "bidirectional tx not found on completion");
        return Ok(());
    }

    if caught_up {
        sign_tx
            .send(Sign::Completion(sign_id))
            .await
            .map_err(|err| anyhow::anyhow!("failed to send completion for respond bidirectional: {err:?} for sign id: {sign_id:?}"))?;
    }

    Ok(())
}

/// Process an execution confirmation emitted by a chain client.
/// The target chain is the chain where the execution was observed.
#[allow(clippy::too_many_arguments)]
pub async fn process_execution_confirmed(
    tx_id: mpc_primitives::BidirectionalTxId,
    sign_id: SignId,
    source_chain: Chain,
    block_height: u64,
    result: ExecutionOutcome,
    backlog: &Backlog,
    sign_tx: mpsc::Sender<Sign>,
    target_chain: Chain,
    caught_up: bool,
) -> anyhow::Result<()> {
    tracing::info!(
        ?tx_id,
        ?sign_id,
        ?source_chain,
        ?target_chain,
        block_height,
        "handling execution confirmation"
    );

    // Remove the watcher; if it's not found, it might have been processed already
    let Some((unwatched_sign_id, pending_tx)) =
        backlog.unwatch_execution(target_chain, &tx_id).await
    else {
        tracing::warn!(
            ?tx_id,
            "execution watcher not found (maybe already processed)"
        );
        return Ok(());
    };
    if unwatched_sign_id != sign_id {
        tracing::warn!(?tx_id, expected = ?unwatched_sign_id, actual = ?sign_id, "sign_id mismatch between event and watcher");
    }

    let chain_ctx = backlog
        .get(pending_tx.source_chain, &unwatched_sign_id)
        .await
        .and_then(|entry| match entry.request.kind {
            SignKind::SignBidirectional(event) => event.chain_ctx,
            _ => None,
        });

    let completed_tx = CompletedTx::new(pending_tx.clone());

    let sign_request = match result {
        ExecutionOutcome::Success { output } => completed_tx
            .create_sign_request_from_serialized_output(source_chain, output, chain_ctx)?,
        ExecutionOutcome::Failed => {
            completed_tx
                .create_failed_sign_request(source_chain, chain_ctx)
                .await?
        }
    };

    if let Err(err) = backlog
        .set_request(
            pending_tx.source_chain,
            &unwatched_sign_id,
            sign_request.clone(),
        )
        .await
    {
        tracing::error!(
            ?tx_id,
            ?unwatched_sign_id,
            ?source_chain,
            ?err,
            "failed to persist completion request on pending tx"
        );
        anyhow::bail!("failed to persist completion request for sign id: {unwatched_sign_id:?}");
    }

    let set_res = backlog
        .set_status(
            pending_tx.source_chain,
            &unwatched_sign_id,
            SignStatus::PendingGenerationBidirectional,
        )
        .await;
    let updated_tx = match set_res {
        Some(tx) => tx,
        None => {
            tracing::error!(?tx_id, ?unwatched_sign_id, source_chain = ?pending_tx.source_chain, "failed to set status on pending tx");
            anyhow::bail!("failed to set status for sign id: {unwatched_sign_id:?}");
        }
    };
    tracing::info!(?tx_id, ?unwatched_sign_id, updated_status = ?updated_tx.status(), "set_status returned transaction");

    let chain = sign_request.chain;
    // Execution confirmations are observed on the target chain, but the follow-up
    // request belongs to the source chain. Do not let the target chain's catchup
    // barrier strand that follow-up work.
    if caught_up || chain != target_chain {
        if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
            tracing::error!(?err, %chain, "failed to send sign request into queue");
        }
    }

    Ok(())
}

pub(crate) async fn process_block_event(
    chain: Chain,
    block: u64,
    backlog: &Backlog,
    sign_tx: &mpsc::Sender<Sign>,
    caught_up: bool,
) {
    let Some(checkpoint) = backlog.set_processed_block(chain, block).await else {
        crate::metrics::indexers::LATEST_BLOCK_NUMBER
            .with_label_values(&[chain.as_str(), "finalized"])
            .set(block as i64);
        return;
    };

    tracing::info!(block, ?checkpoint, %chain, "created checkpoint");
    if caught_up {
        let digest = checkpoint.digest();
        let epsilon = mpc_crypto::derive_epsilon_checkpoint(chain, checkpoint.block_height);
        let sign = Sign::Checkpoint(IndexedSignRequest::checkpoint(
            mpc_primitives::ConsensusCheckpointDigest {
                chain,
                height: checkpoint.block_height,
                digest,
            },
            epsilon,
        ));
        if let Err(err) = sign_tx.send(sign).await {
            tracing::error!(?err, %chain, "failed to enqueue checkpoint sign request");
        }
    }

    crate::metrics::indexers::LATEST_BLOCK_NUMBER
        .with_label_values(&[chain.as_str(), "finalized"])
        .set(block as i64);
}

/// Decode a [u8; 32] sender into its canonical on-chain address string.
/// Canton is intentionally absent: its sender is a variable-length party ID
/// hashed irreversibly into the [u8; 32] slot, so callers with access to the
/// original party string must short-circuit before reaching here (see
/// `SignBidirectionalEvent::sender_string` / `BidirectionalTx::sender_string`).
pub(crate) fn sender_string(sender: [u8; 32], source_chain: Chain) -> anyhow::Result<String> {
    match source_chain {
        Chain::Solana => Ok(Pubkey::new_from_array(sender).to_string()),
        Chain::Hydration => Ok(crate::indexer_hydration::ss58_address_from_account32(
            sender,
        )),
        _ => anyhow::bail!("Unsupported chain: {source_chain}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::connection::NodeStatus;
    use crate::mesh::{wait_threshold_active, MeshState};
    use crate::protocol::contract::primitives::ParticipantInfo;
    use crate::sign_bidirectional::SignStatus;
    use crate::storage::checkpoint_storage::CheckpointStorage;
    use crate::stream::ops::process_execution_confirmed;
    use crate::util::current_unix_timestamp;

    use alloy::primitives::{Address, B256};
    use cait_sith::protocol::Participant;
    use k256::{ProjectivePoint, Scalar};
    use mpc_primitives::{RespondBidirectionalTx, SignArgs, SignBidirectionalEvent, SignKind};
    use near_primitives::types::AccountId;
    use solana_sdk::pubkey::Pubkey;
    use std::time::Duration;
    use tokio::sync::{mpsc, watch};
    use tokio::time::timeout;

    fn test_indexed_request(
        sign_id: SignId,
        chain: Chain,
        args: SignArgs,
        unix_timestamp_indexed: u64,
        kind: SignKind,
    ) -> IndexedSignRequest {
        IndexedSignRequest::new(sign_id, args, chain, unix_timestamp_indexed, kind)
    }

    fn test_bidirectional_tx(id: u8, source_chain: Chain, target_chain: Chain) -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId(B256::from([id; 32]).0),
            sender: [0u8; 32],
            serialized_transaction: vec![1, 2, 3],
            source_chain,
            target_chain,
            caip2_id: target_chain.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 1000,
            path: "test_path".to_string(),
            algo: "ECDSA".to_string(),
            dest: "0x1234567890123456789012345678901234567890".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: [id; 32],
            from_address: **Address::ZERO,
            nonce: 0,
        }
    }

    fn test_sign_args(id: u8) -> SignArgs {
        SignArgs {
            entropy: [id; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        }
    }

    use crate::kdf::valid_signature;

    fn test_canton_sign_bidirectional_request(
        sign_id: SignId,
        sign_event_contract_id: &str,
    ) -> IndexedSignRequest {
        let ctx = crate::indexer_canton::CantonChainCtx {
            sign_event_contract_id: sign_event_contract_id.to_string(),
        };
        let chain_ctx =
            Some(borsh::to_vec(&ctx).expect("CantonChainCtx Borsh serialization is infallible"));
        IndexedSignRequest::sign_bidirectional(
            sign_id,
            test_sign_args(sign_id.request_id[0]),
            Chain::Canton,
            current_unix_timestamp(),
            SignBidirectionalEvent {
                sender: [7u8; 32],
                serialized_transaction: vec![1, 2, 3],
                caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
                key_version: 1,
                deposit: 0,
                path: "test_path".to_string(),
                algo: "ECDSA".to_string(),
                dest: "0x1234567890123456789012345678901234567890".to_string(),
                params: "{}".to_string(),
                output_deserialization_schema: vec![],
                respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                chain: Chain::Canton,
                chain_ctx,
            },
        )
    }

    #[test]
    fn signature_respond_event_conversion() {
        let big_r = ProjectivePoint::GENERATOR.to_affine();
        let s_scalar = Scalar::from(5u64);
        let recovery_id: u8 = 1;

        let event = SignatureRespondedEvent {
            request_id: [0u8; 32],
            signature: Signature::new(big_r, s_scalar, recovery_id),
            chain: Chain::Ethereum,
        };

        // check fields
        let sig = event.signature;
        assert_eq!(sig.recovery_id, recovery_id);
        assert_eq!(sig.s, s_scalar);
        assert_eq!(sig.big_r, big_r);
        assert_eq!(event.chain, Chain::Ethereum);
    }

    #[tokio::test]
    async fn recover_backlog_requeues_pending_signs() {
        // Prepare backlog with a single pending sign request on a chain that
        // should be marked for requeue during recovery.
        let backlog = Backlog::new();
        let sign_id = SignId::new([9u8; 32]);
        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        // Add a request and persist a checkpoint so recover() can load it
        let unix_timestamp_indexed = current_unix_timestamp();
        backlog
            .insert(test_indexed_request(
                sign_id,
                Chain::Solana,
                args.clone(),
                unix_timestamp_indexed,
                SignKind::Sign,
            ))
            .await;
        backlog.checkpoint(Chain::Solana).await;

        let threshold = 1;
        let mut mesh_state = MeshState::default();
        let participant = Participant::from(0u32);
        mesh_state.update(participant, NodeStatus::Active, ParticipantInfo::new(0));
        let (_mesh_tx, mut mesh_rx) = watch::channel(mesh_state);
        wait_threshold_active(&mut mesh_rx, threshold).await;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let checkpoint = backlog
            .storage
            .load_latest(Chain::Solana)
            .await
            .unwrap()
            .unwrap();
        backlog.recover_by_checkpoint(checkpoint).await.unwrap();

        requeue_pending_sign_requests(&backlog, Chain::Solana, sign_tx).await;

        // We should receive the recovered sign request
        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .expect("recv should not timeout");

        match msg.expect("sign_rx should contain a message") {
            Sign::Request(req) => {
                assert_eq!(req.id, sign_id);
                assert_eq!(req.args, args);
                assert_eq!(req.chain, Chain::Solana);
                assert_eq!(req.kind, SignKind::Sign);
                // Verify that the unix_timestamp_indexed is preserved from the original entry
                assert_eq!(req.unix_timestamp_indexed, unix_timestamp_indexed);
                assert!(req.unix_timestamp_indexed <= current_unix_timestamp());
            }
            other => panic!("unexpected message: {:?}", other),
        }
    }

    #[tokio::test]
    async fn process_execution_confirmed_success_creates_respond_request() {
        let backlog = Backlog::new();
        let tx = test_bidirectional_tx(1, Chain::Solana, Chain::Ethereum);
        let sign_id = SignId::new(tx.request_id);

        // Insert a pending Sign request on the source chain
        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        let unix_timestamp_indexed = current_unix_timestamp();
        backlog
            .insert(test_indexed_request(
                sign_id,
                tx.source_chain,
                args.clone(),
                unix_timestamp_indexed,
                SignKind::Sign,
            ))
            .await;

        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        // Call the handler with a Success and empty output
        let tx_id = tx.id;
        // ensure watcher exists before processing
        let before_watchers = backlog.execution_watchers(tx.target_chain).await;
        assert!(before_watchers.contains_key(&tx.id));
        process_execution_confirmed(
            tx_id,
            sign_id,
            tx.source_chain,
            123u64,
            ExecutionOutcome::Success { output: vec![] },
            &backlog,
            sign_tx,
            tx.target_chain,
            true,
        )
        .await
        .unwrap();

        // Watcher should be removed
        let watchers = backlog.execution_watchers(tx.target_chain).await;
        tracing::info!(?watchers, "watchers after execution confirmed");
        assert!(watchers.is_empty());

        // Source chain request should now wait for final bidirectional response.
        // inspect the transaction to provide more debugging info on failure
        let maybe_tx = backlog.get(tx.source_chain, &sign_id).await;
        assert!(maybe_tx.is_some(), "expected sign tx to still exist");
        let tx_after = maybe_tx.unwrap();
        assert_eq!(
            tx_after.status(),
            SignStatus::PendingGenerationBidirectional,
            "expected PendingGenerationBidirectional but found status: {:?}",
            tx_after.status()
        );
        assert!(matches!(
            tx_after.request.kind,
            SignKind::RespondBidirectional(_)
        ));

        // A sign request should have been sent to the sign queue
        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => {
                if let mpc_primitives::SignKind::RespondBidirectional(res) = req.kind {
                    assert_eq!(res.tx_id, tx.id);
                } else {
                    panic!("Expected RespondBidirectional request");
                }
            }
            _ => panic!("Expected Sign::Request"),
        }
    }

    #[tokio::test]
    async fn process_execution_confirmed_is_idempotent_after_first_processing() {
        let backlog = Backlog::new();
        let tx = test_bidirectional_tx(7, Chain::Solana, Chain::Ethereum);
        let sign_id = SignId::new(tx.request_id);
        let args = SignArgs {
            entropy: [7u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        backlog
            .insert(test_indexed_request(
                sign_id,
                tx.source_chain,
                args,
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;
        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        process_execution_confirmed(
            tx.id,
            sign_id,
            tx.source_chain,
            123u64,
            ExecutionOutcome::Success { output: vec![] },
            &backlog,
            sign_tx.clone(),
            tx.target_chain,
            true,
        )
        .await
        .unwrap();

        process_execution_confirmed(
            tx.id,
            sign_id,
            tx.source_chain,
            124u64,
            ExecutionOutcome::Success { output: vec![] },
            &backlog,
            sign_tx,
            tx.target_chain,
            true,
        )
        .await
        .unwrap();

        let first = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match first {
            Sign::Request(req) => assert!(matches!(req.kind, SignKind::RespondBidirectional(_))),
            other => panic!("expected one sign request, got {other:?}"),
        }

        let no_second = timeout(Duration::from_millis(100), sign_rx.recv()).await;
        assert!(matches!(no_second, Err(_) | Ok(None)));

        assert!(backlog.execution_watchers(tx.target_chain).await.is_empty());
    }

    #[tokio::test]
    async fn process_execution_confirmed_warns_but_still_uses_watcher_sign_id() {
        let backlog = Backlog::new();
        let tx = test_bidirectional_tx(8, Chain::Solana, Chain::Ethereum);
        let sign_id = SignId::new(tx.request_id);
        let mismatched_sign_id = SignId::new([88u8; 32]);
        let args = SignArgs {
            entropy: [8u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        backlog
            .insert(test_indexed_request(
                sign_id,
                tx.source_chain,
                args,
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;
        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        process_execution_confirmed(
            tx.id,
            mismatched_sign_id,
            tx.source_chain,
            321u64,
            ExecutionOutcome::Failed,
            &backlog,
            sign_tx,
            tx.target_chain,
            true,
        )
        .await
        .unwrap();

        let tx_after = backlog.get(tx.source_chain, &sign_id).await.unwrap();
        assert_eq!(
            tx_after.status(),
            SignStatus::PendingGenerationBidirectional
        );
        assert!(matches!(
            tx_after.request.kind,
            SignKind::RespondBidirectional(_)
        ));
        assert!(backlog.execution_watchers(tx.target_chain).await.is_empty());

        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => assert_eq!(req.id, sign_id),
            other => panic!("expected sign request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_execution_confirmed_recovery_requeues_final_respond_after_send_failure() {
        let storage = CheckpointStorage::in_memory();
        let backlog = Backlog::persisted(storage.clone());
        let tx = test_bidirectional_tx(9, Chain::Solana, Chain::Ethereum);
        let sign_id = SignId::new(tx.request_id);
        let args = SignArgs {
            entropy: [9u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        backlog
            .insert(test_indexed_request(
                sign_id,
                tx.source_chain,
                args.clone(),
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;
        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, sign_rx) = mpsc::channel(4);
        drop(sign_rx);

        process_execution_confirmed(
            tx.id,
            sign_id,
            tx.source_chain,
            444u64,
            ExecutionOutcome::Success { output: vec![] },
            &backlog,
            sign_tx,
            tx.target_chain,
            true,
        )
        .await
        .unwrap();

        backlog.set_processed_block(tx.source_chain, 10).await;
        backlog.checkpoint(tx.source_chain).await;

        let threshold = 1;
        let mut mesh_state = MeshState::default();
        let participant = Participant::from(0u32);
        mesh_state.update(participant, NodeStatus::Active, ParticipantInfo::new(0));
        let (_mesh_tx, mut mesh_rx) = watch::channel(mesh_state);
        wait_threshold_active(&mut mesh_rx, threshold).await;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let recovered = Backlog::persisted(storage.clone());

        let checkpoint = recovered
            .storage
            .load_latest(tx.source_chain)
            .await
            .unwrap()
            .unwrap();
        recovered.recover_by_checkpoint(checkpoint).await.unwrap();

        requeue_pending_sign_requests(&recovered, tx.source_chain, sign_tx).await;

        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => {
                assert_eq!(req.id, sign_id);
                assert!(matches!(req.kind, SignKind::RespondBidirectional(_)));
            }
            other => panic!("expected recovered final respond request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_respond_event_rejects_invalid_bidirectional_target_chain() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([11u8; 32]);
        let args = SignArgs {
            entropy: [11u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        let mut rlp_s = rlp::RlpStream::new_list(9);
        rlp_s.append(&0u64);
        rlp_s.append(&0u64);
        rlp_s.append(&0u64);
        rlp_s.append(&Vec::<u8>::new());
        rlp_s.append(&0u64);
        rlp_s.append(&Vec::<u8>::new());
        rlp_s.append(&1u64);
        rlp_s.append(&0u64);
        rlp_s.append(&0u64);
        let unsigned_rlp = rlp_s.out().to_vec();

        backlog
            .insert(IndexedSignRequest::sign_bidirectional(
                sign_id,
                args.clone(),
                Chain::Ethereum,
                current_unix_timestamp(),
                SignBidirectionalEvent {
                    sender: Default::default(),
                    serialized_transaction: unsigned_rlp,
                    dest: "0x1234567890123456789012345678901234567890".to_string(),
                    caip2_id: "not-a-chain".to_string(),
                    key_version: 0,
                    deposit: 0,
                    path: "m/0".to_string(),
                    algo: "ECDSA".to_string(),
                    params: "{}".to_string(),
                    chain: Chain::Solana,
                    chain_ctx: Some(Pubkey::new_unique().to_bytes().to_vec()),
                    output_deserialization_schema: vec![],
                    respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                },
            ))
            .await;

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let event = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature: valid_signature(&root_sk, &args),
            chain: Chain::Ethereum,
        };

        let account_id: AccountId = "test.near".parse().unwrap();
        let public_key = root_sk.public_key().into();
        let (_contract_watcher, _tx) =
            ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

        let (sign_tx, _sign_rx) = mpsc::channel(4);

        let err = process_respond_event(event, sign_tx, public_key, &backlog, true)
            .await
            .expect_err("invalid chain should fail");
        assert!(err.to_string().contains("UnknownCaip2Id(\"not-a-chain\")"));
    }

    #[tokio::test]
    async fn process_sign_request_rejects_respond_bidirectional_kind() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([12u8; 32]);
        let args = SignArgs {
            entropy: [12u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        let request = IndexedSignRequest::respond_bidirectional(
            sign_id,
            args,
            Chain::Solana,
            current_unix_timestamp(),
            RespondBidirectionalTx {
                tx_id: BidirectionalTxId(B256::from([12u8; 32]).0),
                output: vec![],
                chain_ctx: None,
            },
        );

        let (sign_tx, _sign_rx) = mpsc::channel(4);
        let err = process_sign_request(request, sign_tx, backlog, true)
            .await
            .expect_err("RespondBidirectional should be rejected from the sign queue path");
        assert!(err.to_string().contains("Unexpected sign request kind"));
    }

    #[tokio::test]
    async fn process_respond_event_rejects_invalid_signature() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([15u8; 32]);
        let args = test_sign_args(15);

        backlog
            .insert(test_indexed_request(
                sign_id,
                Chain::Ethereum,
                args.clone(),
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let mut invalid_signature = valid_signature(&root_sk, &args);
        invalid_signature.s += Scalar::ONE;

        let event = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature: invalid_signature,
            chain: Chain::Ethereum,
        };

        let account_id: AccountId = "test.near".parse().unwrap();
        let public_key = root_sk.public_key().into();
        let (_contract_watcher, _tx) =
            ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

        let (sign_tx, _sign_rx) = mpsc::channel(4);

        let err = process_respond_event(event, sign_tx, public_key, &backlog, true)
            .await
            .expect_err("invalid signature should be rejected");
        assert!(err.to_string().contains("invalid signature"));
        assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_some());
    }

    #[tokio::test]
    async fn process_respond_bidirectional_event_duplicate_is_idempotent() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([13u8; 32]);
        let args = test_sign_args(13);

        backlog
            .insert(IndexedSignRequest::respond_bidirectional(
                sign_id,
                args.clone(),
                Chain::Solana,
                current_unix_timestamp(),
                RespondBidirectionalTx {
                    tx_id: BidirectionalTxId(B256::from([13u8; 32]).0),
                    output: vec![1, 2, 3],
                    chain_ctx: None,
                },
            ))
            .await;

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let signature = valid_signature(&root_sk, &args);

        let duplicate_event0 = respond_event(sign_id, signature);
        let duplicate_event1 = respond_event(sign_id, signature);

        let account_id: AccountId = "test.near".parse().unwrap();
        let public_key = root_sk.public_key().into();
        let (_contract_watcher, _tx) =
            ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        process_respond_bidirectional_event(
            duplicate_event0,
            sign_tx.clone(),
            public_key,
            &backlog,
            true,
        )
        .await
        .expect("first completion should succeed");

        process_respond_bidirectional_event(duplicate_event1, sign_tx, public_key, &backlog, true)
            .await
            .expect("duplicate completion should be ignored");

        let first = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match first {
            Sign::Completion(id) => assert_eq!(id, sign_id),
            other => panic!("expected completion, got {other:?}"),
        }

        let no_second = timeout(Duration::from_millis(100), sign_rx.recv()).await;
        assert!(matches!(no_second, Err(_) | Ok(None)));
    }

    #[tokio::test]
    async fn process_respond_bidirectional_event_rejects_invalid_signature() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([16u8; 32]);
        let args = test_sign_args(16);

        backlog
            .insert(IndexedSignRequest::respond_bidirectional(
                sign_id,
                args.clone(),
                Chain::Solana,
                current_unix_timestamp(),
                RespondBidirectionalTx {
                    tx_id: BidirectionalTxId(B256::from([16u8; 32]).0),
                    output: vec![1, 2, 3],
                    chain_ctx: None,
                },
            ))
            .await;

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let mut invalid_signature = valid_signature(&root_sk, &args);
        invalid_signature.s += Scalar::ONE;

        let event = respond_event(sign_id, invalid_signature);

        let account_id: AccountId = "test.near".parse().unwrap();
        let public_key = root_sk.public_key().into();
        let (_contract_watcher, _tx) =
            ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

        let (sign_tx, _sign_rx) = mpsc::channel(4);

        let err = process_respond_bidirectional_event(event, sign_tx, public_key, &backlog, true)
            .await
            .expect_err("invalid signature should be rejected");
        assert!(err.to_string().contains("invalid signature"));
        assert!(backlog.get(Chain::Solana, &sign_id).await.is_some());
    }

    #[tokio::test]
    async fn process_respond_event_duplicate_ethereum_is_idempotent() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([3u8; 32]);
        let args = test_sign_args(1);

        backlog
            .insert(test_indexed_request(
                sign_id,
                Chain::Ethereum,
                args.clone(),
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let event = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature: valid_signature(&root_sk, &args),
            chain: Chain::Ethereum,
        };

        let account_id: AccountId = "test.near".parse().unwrap();
        let public_key = root_sk.public_key().into();
        let (_contract_watcher, _tx) =
            ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        // First event should complete the request.
        process_respond_event(event.clone(), sign_tx.clone(), public_key, &backlog, true)
            .await
            .expect("first respond event should succeed");

        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Completion(id) => assert_eq!(id, sign_id),
            _ => panic!("expected completion"),
        }

        // Duplicate events should be ignored, not treated as an error.
        // This mirrors production behavior where the same respond log can be
        // emitted repeatedly by the Ethereum indexer pipeline.
        for _ in 0..16 {
            process_respond_event(event.clone(), sign_tx.clone(), public_key, &backlog, true)
                .await
                .expect("duplicate respond event should be idempotent");
        }

        let no_extra = timeout(Duration::from_millis(100), sign_rx.recv()).await;
        assert!(
            matches!(no_extra, Err(_) | Ok(None)),
            "expected no additional completion message, got: {no_extra:?}"
        );
    }

    #[tokio::test]
    async fn process_respond_event_advances_bidirectional_from_pending_publish() {
        let backlog = Backlog::new();
        let tx = test_bidirectional_tx(14, Chain::Ethereum, Chain::Solana);
        let sign_id = SignId::new(tx.request_id);
        let args = test_sign_args(14);

        let mut rlp_s = rlp::RlpStream::new_list(9);
        rlp_s.append(&0u64);
        rlp_s.append(&0u64);
        rlp_s.append(&0u64);
        rlp_s.append(&Vec::<u8>::new());
        rlp_s.append(&0u64);
        rlp_s.append(&Vec::<u8>::new());
        rlp_s.append(&1u64);
        rlp_s.append(&0u64);
        rlp_s.append(&0u64);
        let unsigned_rlp = rlp_s.out().to_vec();

        backlog
            .insert(IndexedSignRequest::sign_bidirectional(
                sign_id,
                args.clone(),
                Chain::Ethereum,
                current_unix_timestamp(),
                SignBidirectionalEvent {
                    sender: Default::default(),
                    serialized_transaction: unsigned_rlp,
                    dest: tx.dest.clone(),
                    caip2_id: tx.caip2_id.clone(),
                    key_version: tx.key_version,
                    deposit: tx.deposit,
                    path: tx.path.clone(),
                    algo: tx.algo.clone(),
                    params: tx.params.clone(),
                    chain: Chain::Solana,
                    chain_ctx: Some(Pubkey::new_unique().to_bytes().to_vec()),
                    output_deserialization_schema: tx.output_deserialization_schema.clone(),
                    respond_serialization_schema: tx.respond_serialization_schema.clone(),
                },
            ))
            .await;

        backlog
            .set_status(
                Chain::Ethereum,
                &sign_id,
                crate::sign_bidirectional::SignStatus::PendingPublish {
                    publish: crate::sign_bidirectional::PublishState {
                        signature: Signature::new(
                            ProjectivePoint::GENERATOR.to_affine(),
                            Scalar::ONE,
                            0,
                        ),
                        participants: vec![],
                        is_proposer: true,
                    },
                },
            )
            .await;

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let event = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature: valid_signature(&root_sk, &args),
            chain: Chain::Ethereum,
        };

        let account_id: AccountId = "test.near".parse().unwrap();
        let public_key = root_sk.public_key().into();
        let (_contract_watcher, _tx) =
            ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

        let (sign_tx, _sign_rx) = mpsc::channel(4);

        process_respond_event(event, sign_tx, public_key, &backlog, false)
            .await
            .expect("respond event should advance pending publish bidirectional entries");

        let entry = backlog
            .get(Chain::Ethereum, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert!(matches!(
            entry.status(),
            SignStatus::PendingExecution { .. }
        ));
        let execution_tx_id = entry
            .execution_tx()
            .expect("pending execution entries should store the execution transaction")
            .id;

        let watchers = backlog.execution_watchers(Chain::Solana).await;
        assert_eq!(watchers.len(), 1);
        assert!(watchers.contains_key(&execution_tx_id));
    }

    #[tokio::test]
    async fn process_execution_confirmed_failed_creates_error_respond_request() {
        let backlog = Backlog::new();

        use alloy::primitives::{Address, B256};
        let tx = BidirectionalTx {
            id: BidirectionalTxId(B256::from([2u8; 32]).0),
            sender: [0u8; 32],
            serialized_transaction: vec![1, 2, 3],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 1000,
            path: "test_path".to_string(),
            algo: "ECDSA".to_string(),
            dest: "0x1234567890123456789012345678901234567890".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: [2u8; 32],
            from_address: **Address::ZERO,
            nonce: 0,
        };
        let sign_id = SignId::new(tx.request_id);

        // Insert pending Sign request on source chain
        let args = SignArgs {
            entropy: [2u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(3u64),
            path: "test".to_string(),
            key_version: 1,
        };
        let unix_timestamp_indexed = current_unix_timestamp();
        backlog
            .insert(test_indexed_request(
                sign_id,
                tx.source_chain,
                args.clone(),
                unix_timestamp_indexed,
                SignKind::Sign,
            ))
            .await;

        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        process_execution_confirmed(
            tx.id,
            sign_id,
            tx.source_chain,
            456u64,
            ExecutionOutcome::Failed,
            &backlog,
            sign_tx,
            tx.target_chain,
            true,
        )
        .await
        .unwrap();

        // Watcher removed
        let watchers = backlog.execution_watchers(tx.target_chain).await;
        assert!(watchers.is_empty());

        // Source chain should now wait for final bidirectional response.
        let waiting = backlog
            .pending_generation_bidirectionals(tx.source_chain)
            .await;
        assert!(waiting.contains_key(&sign_id));

        let tx_after = backlog.get(tx.source_chain, &sign_id).await.unwrap();
        assert!(matches!(
            tx_after.request.kind,
            SignKind::RespondBidirectional(_)
        ));

        // A sign request should have been sent
        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => {
                if let mpc_primitives::SignKind::RespondBidirectional(res) = req.kind {
                    assert_eq!(res.tx_id, tx.id);
                    // Expect the serialized output to begin with MAGIC_ERROR_PREFIX
                    assert!(res.output.starts_with(&[0xde, 0xad, 0xbe, 0xef]));
                } else {
                    panic!("Expected RespondBidirectional request");
                }
            }
            _ => panic!("Expected Sign::Request"),
        }
    }

    #[tokio::test]
    async fn process_execution_confirmed_cross_chain_emits_before_target_catchup() {
        let backlog = Backlog::new();

        use alloy::primitives::{Address, B256};
        let tx = BidirectionalTx {
            id: BidirectionalTxId(B256::from([4u8; 32]).0),
            sender: [0u8; 32],
            serialized_transaction: vec![1, 2, 3],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "test_caip2_id".to_string(),
            key_version: 1,
            deposit: 1000,
            path: "test_path".to_string(),
            algo: "ECDSA".to_string(),
            dest: "0x1234567890123456789012345678901234567890".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: [4u8; 32],
            from_address: **Address::ZERO,
            nonce: 0,
        };
        let sign_id = SignId::new(tx.request_id);

        let args = SignArgs {
            entropy: [4u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        backlog
            .insert(test_indexed_request(
                sign_id,
                tx.source_chain,
                args,
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;

        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        process_execution_confirmed(
            tx.id,
            sign_id,
            tx.source_chain,
            789u64,
            ExecutionOutcome::Failed,
            &backlog,
            sign_tx,
            tx.target_chain,
            false,
        )
        .await
        .unwrap();

        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => {
                assert_eq!(req.chain, Chain::Solana);
                assert!(matches!(
                    req.kind,
                    mpc_primitives::SignKind::RespondBidirectional(_)
                ));
            }
            other => panic!("expected cross-chain follow-up request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_execution_confirmed_carries_canton_chain_ctx_to_final_request() {
        let backlog = Backlog::new();
        let mut tx = test_bidirectional_tx(24, Chain::Canton, Chain::Ethereum);
        tx.sender = [7u8; 32];
        let sign_id = SignId::new(tx.request_id);
        let sign_event_contract_id = "#sign-event-cid";

        backlog
            .insert(test_canton_sign_bidirectional_request(
                sign_id,
                sign_event_contract_id,
            ))
            .await;

        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        process_execution_confirmed(
            tx.id,
            sign_id,
            tx.source_chain,
            456u64,
            ExecutionOutcome::Success { output: vec![1] },
            &backlog,
            sign_tx,
            tx.target_chain,
            true,
        )
        .await
        .unwrap();

        let assert_canton_ctx = |ctx_bytes: Option<&[u8]>| {
            let bytes = ctx_bytes.expect("chain_ctx present");
            let decoded: crate::indexer_canton::CantonChainCtx =
                borsh::from_slice(bytes).expect("CantonChainCtx decodes");
            assert_eq!(decoded.sign_event_contract_id, sign_event_contract_id);
        };

        assert!(backlog.execution_watchers(tx.target_chain).await.is_empty());
        let tx_after = backlog.get(tx.source_chain, &sign_id).await.unwrap();
        assert_eq!(
            tx_after.status(),
            SignStatus::PendingGenerationBidirectional
        );
        match &tx_after.request.kind {
            SignKind::RespondBidirectional(res) => {
                assert_eq!(res.tx_id, tx.id);
                assert_eq!(res.output, vec![1]);
                assert_canton_ctx(res.chain_ctx.as_deref());
            }
            other => panic!("Expected RespondBidirectional request, got {other:?}"),
        }

        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => {
                assert_eq!(req.id, sign_id);
                assert_eq!(req.chain, tx.source_chain);
                match req.kind {
                    SignKind::RespondBidirectional(res) => {
                        assert_eq!(res.tx_id, tx.id);
                        assert_eq!(res.output, vec![1]);
                        assert_canton_ctx(res.chain_ctx.as_deref());
                    }
                    other => panic!("Expected RespondBidirectional request, got {other:?}"),
                }
            }
            other => panic!("Expected Sign::Request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn requeue_pending_sign_requests_is_chain_scoped() {
        let backlog = Backlog::new();
        let solana_sign_id = SignId::new([7u8; 32]);
        let ethereum_sign_id = SignId::new([8u8; 32]);
        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        backlog
            .insert(test_indexed_request(
                solana_sign_id,
                Chain::Solana,
                args.clone(),
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;
        backlog
            .insert(test_indexed_request(
                ethereum_sign_id,
                Chain::Ethereum,
                args,
                current_unix_timestamp(),
                SignKind::Sign,
            ))
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        requeue_pending_sign_requests(&backlog, Chain::Solana, sign_tx).await;

        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => assert_eq!(req.id, solana_sign_id),
            other => panic!("unexpected message: {other:?}"),
        }

        let no_extra = timeout(Duration::from_millis(100), sign_rx.recv()).await;
        assert!(
            matches!(no_extra, Err(_) | Ok(None)),
            "expected no cross-chain requeue, got: {no_extra:?}"
        );
    }

    fn respond_event(sign_id: SignId, signature: Signature) -> RespondBidirectionalEvent {
        RespondBidirectionalEvent {
            request_id: sign_id.request_id,
            signature,
            chain: Chain::Solana,
        }
    }
}
