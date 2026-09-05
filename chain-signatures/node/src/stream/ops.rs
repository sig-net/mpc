use std::sync::Arc;

use anyhow::Context;

use crate::backlog::{AnyProgress, Bidirectional, Executing, Final, Initial, Sign, SignEntry};
use crate::protocol::publish_failover::{observe_lag, publish_deadline};
use crate::sign_bidirectional::SignBidirectionalEventExt;
use crate::stream::StreamContext;
use crate::types::SignCommand;
use mpc_chain_integration_core::ChainTelemetry;
use mpc_chain_solana::Pubkey;
use mpc_primitives::{
    Chain, ExecutionOutcome, IndexedSignRequest, RespondBidirectionalEvent, SignId, SignKind,
    SignatureRespondedEvent,
};

pub(crate) async fn process_sign_request(
    sign_request: Arc<IndexedSignRequest>,
    ctx: &StreamContext,
) -> anyhow::Result<bool> {
    match &sign_request.kind {
        SignKind::RespondBidirectional(_) => anyhow::bail!("Unexpected sign request kind"),
        // Reject malformed bidirectional requests at ingestion, running the same
        // deterministic derivations the respond event will need later. A request
        // admitted here but failing there can never advance: its entry sticks in
        // pending-publish forever, and every node publishes a leg-1 response
        // whose second leg will never come.
        SignKind::SignBidirectional(event) => event.validate().with_context(|| {
            format!("rejecting bidirectional sign request {:?}", sign_request.id)
        })?,
        SignKind::Sign => {}
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
        if !entry.is_proposer() {
            continue;
        }

        let sign_id = entry.sign_id();
        // This is the proposer's only retry for a publish that reported success but
        // never landed, so it republishes even if it already dispatched one. Marking
        // stops the sweep from putting a second copy on chain on the next block: the
        // deadline was anchored before the restart, so it is already past.
        entry.mark_publish_dispatched().await;
        ctx.rpc.publish(entry);
        tracing::info!(?sign_id, %source_chain, "resumed pending publish request after catchup");
    }
}

/// Publish entries whose proposer stayed silent past this node's deadline.
///
/// Only one of the `m` participants needs a healthy stream for failover to happen.
pub(crate) async fn publish_failover_due(ctx: &StreamContext, chain: Chain) {
    if !ctx.caught_up {
        return;
    }
    let lag = observe_lag(chain, ctx.observe_lag);

    let me = ctx.contract_watcher.account_id().clone();
    let now = mpc_utils::time::current_unix_timestamp();
    for entry in ctx.backlog.publishable_requests(chain).await {
        if entry.publish_dispatched() {
            continue;
        }
        let Some(deadline) = publish_deadline(&entry.sign_id(), entry.publishing(), &me, lag)
        else {
            continue;
        };
        if now < deadline {
            continue;
        }
        let sign_id = entry.sign_id();
        if !entry.mark_publish_dispatched().await {
            continue;
        }

        tracing::warn!(
            ?sign_id,
            %chain,
            "proposer response not observed in time; publishing failover response"
        );
        ctx.rpc.publish(entry);
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
        return advance_bidirectional_to_execution(entry, respond_event, root_pk).await;
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
    respond_event: SignatureRespondedEvent,
    root_pk: mpc_primitives::PublicKey,
) -> anyhow::Result<()> {
    let sign_id = entry.sign_id();
    let source_chain = entry.chain();
    let event = entry.sign_bidirectional_event();

    // Admission validates the same derivations, but entries can enter the backlog
    // without passing admission (checkpoint recovery restores them wholesale). One
    // that fails here fails identically on every node and on every replay, so it
    // can never advance: leaving it would park it in pending-publish forever, with
    // every node publishing a response that is already on chain.
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

    let tx = Arc::new(event.to_bidirectional_tx(
        respond_event.request_id,
        respond_event.signature,
        root_pk,
    )?);

    entry.advance(tx).await.with_context(|| {
        format!("advance bidirectional tx to execution failed for sign id {sign_id:?}")
    })?;

    tracing::info!(?sign_id, "advance bidirectional tx to execution successful");
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
    entry.complete().await;
    tracing::info!(?sign_id, "bidirectional tx completed");
    ctx.try_enqueue(SignCommand::Completion(sign_id)).await?;

    Ok(())
}

/// Process an execution confirmation emitted by a chain client.
/// The target chain is the chain where the execution was observed.
pub async fn process_execution_confirmed(
    tx_id: mpc_primitives::BidirectionalTxId,
    block_height: u64,
    result: ExecutionOutcome,
    ctx: &StreamContext,
    target_chain: Chain,
) -> anyhow::Result<()> {
    tracing::debug!(
        ?tx_id,
        ?target_chain,
        block_height,
        "received execution confirmation event"
    );

    let Some(entry) = ctx.backlog.unwatch_execution(target_chain, &tx_id).await else {
        tracing::warn!(
            ?tx_id,
            "executing bidirectional entry not found (maybe already processed)"
        );
        return Ok(());
    };

    let sign_id = entry.sign_id();
    let source_chain = entry.chain;
    tracing::info!(
        ?tx_id,
        ?sign_id,
        ?source_chain,
        ?target_chain,
        block_height,
        "handling execution confirmation"
    );

    let entry = entry
        .advance(result)
        .await
        .with_context(|| {
            format!(
                "failed to transition pending tx to final response for sign id {sign_id:?}, tx_id {tx_id:?}, source_chain {source_chain}"
            )
        })?;
    tracing::info!(
        ?tx_id,
        ?sign_id,
        ?source_chain,
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
    let checkpoint_digest = mpc_primitives::CheckpointDigest {
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
        Chain::Hydration => Ok(mpc_chain_hydration::ss58_address_from_account32(sender)),
        _ => anyhow::bail!("Unsupported chain: {source_chain}"),
    }
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
