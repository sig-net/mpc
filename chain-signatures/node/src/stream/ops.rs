use crate::backlog::{AnyProgress, Bidirectional, Executing, Final, Initial, Sign, SignEntry};
use crate::sign_bidirectional::SignBidirectionalEventExt;
use crate::stream::StreamContext;
use crate::types::SignCommand;

use anyhow::Context;
use mpc_chain_integration_core::ChainTelemetry;
use mpc_chain_solana::Pubkey;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ExecutionOutcome, IndexedSignRequest,
    RespondBidirectionalEvent, SignBidirectionalEvent, SignId, SignKind, SignatureRespondedEvent,
};
use std::sync::Arc;

pub(crate) async fn process_sign_request(
    sign_request: Arc<IndexedSignRequest>,
    ctx: &StreamContext,
) -> anyhow::Result<bool> {
    if matches!(sign_request.kind, SignKind::RespondBidirectional(_)) {
        anyhow::bail!("Unexpected sign request kind");
    }

    // Reject malformed bidirectional requests at ingestion, running the same
    // deterministic derivations the respond event will need later. A request
    // admitted here but failing there is worse than one never admitted: its entry
    // sticks in pending-publish forever, and every backup's sweep fires into a
    // duplicate-publish retry loop that no cancellation ever ends, because the
    // failing respond processing is where the cancel lives.
    if let SignKind::SignBidirectional(event) = &sign_request.kind {
        event.validate().with_context(|| {
            format!("rejecting bidirectional sign request {:?}", sign_request.id)
        })?;
    }

    let (entry, is_new) = ctx.backlog.insert(sign_request).await;
    ctx.try_enqueue(SignCommand::Request(entry)).await?;

    Ok(is_new)
}

pub(crate) async fn requeue_pending_sign_requests(
    ctx: &StreamContext,
    source_chain: Chain,
) -> anyhow::Result<()> {
    for entry in ctx.backlog.requeueable_requests(source_chain).await {
        let sign_id = entry.sign_id();
        let source_chain = entry.chain();
        ctx.sign_tx
            .send(SignCommand::Request(entry))
            .await
            .with_context(|| {
                format!(
                    "failed to requeue sign request after catchup for sign id {sign_id:?} on chain {source_chain}"
                )
            })?;
    }
    Ok(())
}

pub(crate) async fn resume_pending_publish_requests(ctx: &StreamContext, source_chain: Chain) {
    for entry in ctx.backlog.publishable_requests(source_chain).await {
        if !entry.publish_state().is_proposer {
            continue;
        }

        let sign_id = entry.sign_id();
        ctx.rpc.publish(entry);
        tracing::info!(?sign_id, %source_chain, "resumed pending publish request after catchup");
    }
}

pub(crate) async fn process_respond_event(
    respond_event: SignatureRespondedEvent,
    ctx: &StreamContext,
    root_pk: mpc_primitives::PublicKey,
) -> anyhow::Result<()> {
    let sign_id = SignId::new(respond_event.request_id);
    let source_chain = respond_event.chain;

    let Some(entry) = ctx.backlog.get(source_chain, &sign_id).await else {
        tracing::info!(
            ?sign_id,
            ?source_chain,
            "respond event is already finalized or pruned; skipping"
        );
        return Ok(());
    };

    if let Some(entry) = entry.cast::<Sign<AnyProgress>>() {
        entry.verify_signature(root_pk, &respond_event.signature)?;
        tracing::info!(?sign_id, "sign request completed successfully");
        entry.complete().await;
        ctx.try_enqueue(SignCommand::Completion(sign_id)).await?;
        return Ok(());
    }

    if let Some(entry) = entry.cast::<Bidirectional<Initial<AnyProgress>>>() {
        entry.verify_signature(root_pk, &respond_event.signature)?;
        let event = match &entry.request().kind {
            SignKind::SignBidirectional(event) => event.clone(),
            _ => anyhow::bail!("unexpected sign kind for bidirectional initial entry"),
        };
        return advance_bidirectional_to_execution(entry, &event, respond_event, sign_id, root_pk)
            .await;
    }

    if entry.is::<Bidirectional<Executing>>() {
        tracing::info!(
            ?sign_id,
            ?source_chain,
            "respond event backlog entry is already advanced; treating as processed"
        );
        return Ok(());
    }

    tracing::info!(
        ?sign_id,
        ?source_chain,
        "respond event is already finalized or pruned; skipping"
    );
    Ok(())
}

/// Advance a bidirectional sign request from "signature responded" to
/// "pending execution".
async fn advance_bidirectional_to_execution(
    entry: SignEntry<Bidirectional<Initial<AnyProgress>>>,
    event: &SignBidirectionalEvent,
    respond_event: SignatureRespondedEvent,
    sign_id: SignId,
    root_pk: mpc_primitives::PublicKey,
) -> anyhow::Result<()> {
    let source_chain = respond_event.chain;

    // Admission validates the same derivations, but entries can enter the backlog
    // without passing admission (checkpoint recovery restores them wholesale). One
    // that fails here fails identically on every node and on every replay, so it
    // can never advance: leaving it would park it in pending-publish forever, with
    // every backup's sweep republishing a response that is already on chain.
    // Removing it is deterministic across the network, so checkpoints stay aligned.
    if let Err(err) = event.validate() {
        tracing::error!(
            ?sign_id,
            ?source_chain,
            ?err,
            "quarantining bidirectional request that can never advance"
        );
        entry.complete().await;
        return Ok(());
    }

    tracing::info!(?sign_id, "bidirectional processing initial respond event");
    let target_chain = event
        .target_chain()
        .with_context(|| format!("failed to process respond event for sign id: {sign_id:?}"))?;

    // Get the MPC public key and derive the from_address.
    let epsilon = event.epsilon()?;
    let from_address = crate::sign_bidirectional::derive_user_address(root_pk, epsilon);

    let mpc_sig = respond_event.signature;

    // Sign and hash the transaction to get the correct tx_id and nonce
    let (signed_tx_hash, nonce) = crate::sign_bidirectional::sign_and_hash_transaction(
        &event.serialized_transaction,
        mpc_sig,
    )?;

    let tx_id = BidirectionalTxId(signed_tx_hash);

    let bidirectional_tx = Arc::new(BidirectionalTx {
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
    });

    tracing::info!(
        ?sign_id,
        ?tx_id,
        nonce = ?bidirectional_tx.nonce,
        from_address = ?bidirectional_tx.from_address,
        "bidirectional tx details before advancement",
    );

    entry
        .advance(bidirectional_tx)
        .await
        .with_context(|| {
            format!(
                "advance bidirectional tx to execution failed for sign id {sign_id:?}, tx_id {tx_id:?}, target_chain {target_chain:?}"
            )
        })?;
    tracing::info!(
        ?sign_id,
        ?tx_id,
        ?target_chain,
        "advance bidirectional tx to execution successful"
    );

    Ok(())
}

pub(crate) async fn process_respond_bidirectional_event(
    event: RespondBidirectionalEvent,
    ctx: &StreamContext,
    root_pk: mpc_primitives::PublicKey,
) -> anyhow::Result<()> {
    let sign_id = SignId::new(event.request_id);
    let source_chain = event.chain;
    tracing::info!(?sign_id, "processing RespondBidirectionalEvent");

    let Some(entry) = ctx
        .backlog
        .get_by::<Bidirectional<Final<AnyProgress>>>(source_chain, &sign_id)
        .await
    else {
        tracing::warn!(?sign_id, "bidirectional tx not found on completion");
        return Ok(());
    };

    entry.verify_signature(root_pk, &event.signature)?;

    if entry.complete().await {
        tracing::info!(?sign_id, "bidirectional tx completed");
    } else {
        tracing::warn!(?sign_id, "bidirectional tx not found on completion");
        return Ok(());
    }

    ctx.try_enqueue(SignCommand::Completion(sign_id)).await?;

    Ok(())
}

/// Process an execution confirmation emitted by a chain client.
/// The target chain is the chain where the execution was observed.
pub async fn process_execution_confirmed(
    tx_id: mpc_primitives::BidirectionalTxId,
    sign_id: SignId,
    source_chain: Chain,
    block_height: u64,
    result: ExecutionOutcome,
    ctx: &StreamContext,
    target_chain: Chain,
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
        ctx.backlog.unwatch_execution(target_chain, &tx_id).await
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
    // The watched transaction is the source of truth for the source chain. The
    // follow-up request's chain decides which backlog bucket, publish key, and
    // cancellation key it lives under, and all of them must agree; an execution
    // watcher filling the event's field differently must not split them.
    if source_chain != pending_tx.source_chain {
        tracing::warn!(
            ?tx_id,
            event = ?source_chain,
            watcher = ?pending_tx.source_chain,
            "source_chain mismatch between event and watcher; using the watcher's"
        );
    }
    let source_chain = pending_tx.source_chain;

    let Some(entry) = ctx
        .backlog
        .get_by::<Bidirectional<Executing>>(source_chain, &unwatched_sign_id)
        .await
    else {
        tracing::warn!(
            ?tx_id,
            ?unwatched_sign_id,
            "executing bidirectional entry not found in backlog"
        );
        return Ok(());
    };

    let entry = entry
        .advance(result)
        .await
        .with_context(|| {
            format!(
                "failed to transition pending tx to final response for sign id {unwatched_sign_id:?}, tx_id {tx_id:?}, source_chain {source_chain}"
            )
        })?;
    tracing::info!(
        ?tx_id,
        ?unwatched_sign_id,
        "transitioned transaction to final response"
    );
    let chain = entry.chain;
    // Execution confirmations are observed on the target chain, but the follow-up
    // request belongs to the source chain. Do not let the target chain's catchup
    // barrier strand that follow-up work.
    if ctx.caught_up || chain != target_chain {
        ctx.sign_tx
            .send(SignCommand::Request(entry.into()))
            .await
            .with_context(|| format!("failed to send sign request into queue for chain {chain}"))?;
    }

    Ok(())
}

pub(crate) async fn process_block_event<T: ChainTelemetry>(
    chain: Chain,
    block: u64,
    ctx: &StreamContext,
    telemetry: &T,
) -> anyhow::Result<()> {
    telemetry.block_finalized(block);

    // should not create checkpoint for blocks that are not caught up, as that would
    // try to create signatures for checkpoints where we are not live.
    if !ctx.caught_up {
        return Ok(());
    }
    let Some(checkpoint) = ctx.backlog.set_processed_block(chain, block).await else {
        return Ok(());
    };

    telemetry.checkpoint_created(checkpoint.block_height);

    let digest = checkpoint.digest();
    let checkpoint_digest = mpc_primitives::ConsensusCheckpointDigest {
        chain,
        height: checkpoint.block_height,
        digest,
    };
    tracing::info!(block, ?checkpoint, %chain, ?checkpoint_digest, "created checkpoint");
    ctx.rpc.vote_checkpoint(checkpoint_digest);

    Ok(())
}

/// Decode a [u8; 32] sender into its canonical on-chain address string.
/// Canton and Midnight are intentionally absent. Canton's sender is a
/// variable-length party ID hashed irreversibly into the [u8; 32] slot, so
/// callers with access to the original party string must short-circuit before
/// reaching here; Midnight's sender is a 32-byte contract address whose
/// canonical form is already the lowercase hex of those bytes, so it
/// short-circuits the same way (see `SignBidirectionalEvent::sender_string` /
/// `BidirectionalTx::sender_string`).
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
#[path = "ops_tests.rs"]
mod tests;
