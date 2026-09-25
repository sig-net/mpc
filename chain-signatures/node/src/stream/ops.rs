use std::sync::Arc;

use anyhow::Context;

use crate::backlog::{AnyProgress, Bidirectional, Executing, Final, Initial, Sign, SignEntry};
use crate::metrics::requests::{record_request_latency, SignRequestStep};
use crate::protocol::publish_failover::{observe_lag, publish_deadline};
use crate::respond_bidirectional::{claims_attestation_key, is_failed_execution_response};
use crate::sign_bidirectional::SignBidirectionalEventExt;
use crate::stream::StreamContext;
use crate::types::SignCommand;
use mpc_chain_integration_core::ChainTelemetry;
use mpc_chain_solana::Pubkey;
use mpc_primitives::{
    Chain, ExecutionOutcome, IndexedSignRequest, RequestKind, RespondBidirectionalEvent, SignId,
    SignKind, SignatureRespondedEvent,
};
use mpc_utils::time::unix_elapsed_checked;

/// Recovered final responses must bind their stored metadata to the signing payload.
fn validate_midnight_signing_request(request: &IndexedSignRequest) -> anyhow::Result<()> {
    if request.chain != Chain::Midnight {
        return Ok(());
    }

    match &request.kind {
        SignKind::RespondBidirectional(_) => {
            mpc_chain_midnight::validate_attestation_response(request)?;
        }
        SignKind::SignBidirectional(_) | SignKind::Sign => {}
    }

    Ok(())
}

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

    // The attestation key is derived from the requesting contract under a fixed
    // path, so a request naming that path forges a response to itself. Here
    // rather than in `validate`, which plain `sign` never reaches.
    anyhow::ensure!(
        !claims_attestation_key(&sign_request),
        "rejecting sign request {:?} on the reserved attestation path",
        sign_request.id
    );

    let sign_id = sign_request.id;
    let (entry, is_new) = ctx.backlog.insert(sign_request).await;
    if !is_new {
        tracing::debug!(?sign_id, "sign request already pending; keeping its entry");
        return Ok(false);
    }
    ctx.try_enqueue(SignCommand::Request(entry)).await?;

    Ok(true)
}

pub(crate) async fn requeue_pending_sign_requests(
    ctx: &StreamContext,
    source_chain: Chain,
) -> anyhow::Result<()> {
    for entry in ctx.backlog.requeueable_requests(source_chain).await {
        let sign_id = entry.sign_id();
        let source_chain = entry.chain();
        if let Err(error) = validate_midnight_signing_request(entry.request()) {
            tracing::error!(?sign_id, %source_chain, ?error, "leaving incompatible restored Midnight request pending without signing");
            continue;
        }
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
        if let Err(error) = validate_midnight_signing_request(entry.request()) {
            tracing::error!(sign_id = ?entry.sign_id(), %source_chain, ?error, "leaving incompatible Midnight publication pending");
            continue;
        }
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
        if let Err(error) = validate_midnight_signing_request(entry.request()) {
            tracing::error!(sign_id = ?entry.sign_id(), %chain, ?error, "leaving incompatible Midnight publication pending");
            continue;
        }
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
        // Sent even during catchup: unlike a request, nothing requeues it later.
        ctx.sign_tx
            .send(SignCommand::Completion(sign_id))
            .await
            .context("sign command channel closed")?;
        return Ok(());
    }

    if let Some(entry) = entry.cast::<Bidirectional<Initial<AnyProgress>>>() {
        entry.verify_signature(root_pk, &respond_event.signature)?;
        return advance_bidirectional_to_execution(entry, respond_event, root_pk, ctx).await;
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
    ctx: &StreamContext,
) -> anyhow::Result<()> {
    let sign_id = entry.sign_id();
    let source_chain = entry.chain();
    let leg_kind = entry.request().request_kind();
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
    // The leg's task runs until told to stop, holding the sign id the next leg
    // reuses. Bypasses the catchup gate: nothing replays a stop event.
    ctx.sign_tx
        .send(SignCommand::LegCompleted {
            sign_id,
            kind: leg_kind,
        })
        .await
        .context("sign command channel closed")?;

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

    if source_chain == Chain::Midnight {
        let expected = mpc_chain_midnight::validate_attestation_response(entry.request())?;
        anyhow::ensure!(
            event.attestation == Some(expected),
            "Midnight event metadata differs from the signed response",
        );
    }
    entry.verify_signature(root_pk, &event.signature)?;

    // The whole round trip, measured against when the initial request was
    // indexed. The origin travels with the final-response request so checkpoint
    // recovery does not change whether this observation is emitted -- but it
    // may therefore carry a peer's clock, so a future origin is skipped rather
    // than saturated to a zero-length round trip.
    if let SignKind::RespondBidirectional(response) = &entry.request.kind {
        if let Some(origin_indexed_at) = response.origin_indexed_at {
            match unix_elapsed_checked(origin_indexed_at) {
                Some(elapsed) => record_request_latency(
                    source_chain,
                    SignRequestStep::BidirectionalTotal,
                    execution_status(is_failed_execution_response(response)),
                    RequestKind::RespondBidirectional,
                    elapsed,
                ),
                None => tracing::warn!(
                    ?sign_id,
                    origin_indexed_at,
                    "skipping end-to-end latency: origin timestamp is ahead of local clock"
                ),
            }
        }
    }

    entry.complete().await;
    tracing::info!(?sign_id, "bidirectional tx completed");
    // Sent even during catchup: unlike a request, nothing requeues it later.
    ctx.sign_tx
        .send(SignCommand::Completion(sign_id))
        .await
        .context("sign command channel closed")?;

    Ok(())
}

fn execution_status(failed: bool) -> &'static str {
    if failed {
        "execution_failed"
    } else {
        "ok"
    }
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

    // Captured before `advance` consumes the entry: the wait ends here, and the
    // outcome is what distinguishes a healthy round trip from a reverted one.
    let awaiting_execution = entry.awaiting_execution();
    if matches!(result, ExecutionOutcome::ExtractionFailed) {
        if source_chain == Chain::Midnight {
            // Destination streams advance independently of Midnight checkpoints.
            // Keep membership until a source-observable transition can settle it.
            tracing::error!(
                ?sign_id,
                ?tx_id,
                ?source_chain,
                "output extraction failed; leaving execution pending without an attestation"
            );
            entry.watch_execution().await;
        } else {
            tracing::error!(
                ?sign_id,
                ?tx_id,
                ?source_chain,
                output_deserialization_schema =
                    %String::from_utf8_lossy(&entry.execution_tx().output_deserialization_schema),
                respond_serialization_schema =
                    %String::from_utf8_lossy(&entry.execution_tx().respond_serialization_schema),
                "bidirectional output extraction failed terminally; resolving the request \
                 without a response, even though the destination transaction executed."
            );
            entry.complete().await;
            // Stop the signing task even during catchup: the removed request
            // cannot produce another completion event.
            ctx.sign_tx
                .send(SignCommand::Completion(sign_id))
                .await
                .context("failed to send completion into queue")?;
        }
        return Ok(());
    }
    let execution_failed = matches!(result, ExecutionOutcome::Failed);

    let entry = entry
        .advance(result, block_height)
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

    if let Some(awaiting_execution) = awaiting_execution {
        record_request_latency(
            source_chain,
            SignRequestStep::AwaitingExecution,
            execution_status(execution_failed),
            RequestKind::RespondBidirectional,
            awaiting_execution,
        );
    }
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

    let checkpoint_digest = mpc_primitives::CheckpointDigest::from(&checkpoint);
    tracing::info!(block, ?checkpoint, %chain, ?checkpoint_digest, "created checkpoint");
    ctx.rpc.vote_checkpoint(checkpoint_digest).await?;

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
