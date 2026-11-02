use std::sync::Arc;

use anyhow::Context;

use crate::backlog::{
    AnyProgress, Backlog, Bidirectional, Executing, Final, Initial, Sign, SignEntry,
};
use crate::metrics::requests::{record_request_latency, SignRequestStep};
use crate::protocol::publish_failover::{observe_lag, publish_deadline};
use crate::respond_bidirectional::{
    claims_attestation_key, published_failure, published_midnight_payload,
    published_midnight_signing_args, published_output_payload, published_output_signing_args,
};
use crate::sign_bidirectional::{
    owned_by_requester, transaction_chain_id, BidirectionalProgress, BidirectionalTxId,
    SignBidirectionalEventExt, SignStatus,
};
use crate::stream::StreamContext;
use crate::types::SignCommand;
use mpc_chain_integration_core::ChainTelemetry;
use mpc_chain_solana::Pubkey;
use mpc_primitives::{
    BidirectionalTx, Chain, ExecutionOutcome, IndexedSignRequest, RequestKind,
    RespondBidirectionalEvent, SignBidirectionalEvent, SignId, SignKind, SignatureRespondedEvent,
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
    root_pk: mpc_primitives::PublicKey,
) -> anyhow::Result<bool> {
    match &sign_request.kind {
        SignKind::RespondBidirectional(_) => anyhow::bail!("Unexpected sign request kind"),
        // Reject malformed bidirectional requests at ingestion, running the same
        // deterministic derivations the respond event will need later. A request
        // admitted here but failing there can never advance: its entry sticks in
        // pending-publish forever, and every node publishes a leg-1 response
        // whose second leg will never come.
        SignKind::SignBidirectional(event) => {
            event.validate().with_context(|| {
                format!("rejecting bidirectional sign request {:?}", sign_request.id)
            })?;
            if let Some((actual, expected)) = network_mismatch(event, ctx.ethereum_chain_id) {
                anyhow::bail!(
                    "rejecting bidirectional sign request {:?}: chain id {actual:?}, \
                     but this node executes on {expected}",
                    sign_request.id
                );
            }
            if let Some(id) = duplicate_destination(event, sign_request.id, &ctx.backlog).await {
                anyhow::bail!(
                    "rejecting bidirectional sign request {:?}: \
                     destination transaction {id:?} already pending",
                    sign_request.id
                );
            }
            if !owned_by_requester(event, root_pk) {
                anyhow::bail!(
                    "rejecting bidirectional sign request {:?}: \
                     owner_address is not the request's derived key",
                    sign_request.id
                );
            }
        }
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

/// Returns the actual and expected chain ids when an Ethereum target names another network.
/// The actual one is `None` when it does not decode as a u64, which no watched network's id exceeds.
/// Returns `None` if the event is not targeting Ethereum or if the chain id matches the expected one.
fn network_mismatch(
    event: &SignBidirectionalEvent,
    expected: Option<u64>,
) -> Option<(Option<u64>, u64)> {
    let expected = expected?;
    if event.target_chain() != Ok(Chain::Ethereum) {
        return None;
    }
    let actual = transaction_chain_id(&event.serialized_transaction);
    (actual != Some(expected)).then_some((actual, expected))
}

/// A flat destination id names one transaction per set of raw bytes: a second
/// request with the same bytes is rejected while the first is pending, or its
/// watch would silently replace the first's. The request's own entry is
/// skipped — an indexer replay of a pending request is absorbed at insert,
/// not rejected. Reads only checkpointed pending state, so the verdict is
/// deterministic across nodes.
async fn duplicate_destination(
    event: &SignBidirectionalEvent,
    sign_id: SignId,
    backlog: &Backlog,
) -> Option<BidirectionalTxId> {
    let id = event.flat_destination_id()?;
    let duplicate = backlog
        .pending_requests(event.chain)
        .await
        .iter()
        .filter(|pending| pending.id != sign_id)
        .filter_map(|pending| match &pending.kind {
            SignKind::SignBidirectional(other) => Some(other),
            _ => None,
        })
        .any(|other| other.flat_destination_id() == Some(id));
    duplicate.then_some(id)
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

    let Some(entry) = ctx.backlog.get(source_chain, &sign_id).await else {
        tracing::warn!(?sign_id, "bidirectional tx not found on completion");
        return Ok(());
    };
    let entry = match entry.try_into::<Bidirectional<Final<AnyProgress>>>() {
        Ok(entry) => entry,
        Err(entry) if source_chain == Chain::Midnight => {
            return settle_unobserved_midnight_response(entry, &event, ctx, root_pk).await;
        }
        Err(entry) => {
            return settle_unobserved_response(entry, &event, ctx, root_pk).await;
        }
    };

    // Check the response the event publishes, not this node's own: then every node removes the
    // request on this event, whatever it computed itself.
    let payload = if source_chain == Chain::Midnight {
        let published = event
            .attestation
            .as_ref()
            .context("Midnight response lacks attestation metadata")?;
        Some(published_midnight_payload(&event.request_id, published)?)
    } else {
        event
            .output
            .as_deref()
            .map(|output| published_output_payload(source_chain, &event.request_id, output))
            .transpose()?
    };
    match payload {
        Some(payload) => {
            let request = entry.request();
            if payload != request.args.payload {
                tracing::warn!(?sign_id, "published response differs from this node's");
            }
            mpc_crypto::verify_signature(root_pk, request.args.epsilon, payload, &event.signature)
                .context("respond event carried invalid signature")?;
        }
        None => entry.verify_signature(root_pk, &event.signature)?,
    }

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
                    execution_status(published_failure(&event, response)),
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

/// Settle a Midnight request whose outcome this node has not observed. The event carries
/// every input of the attestation digest (height, kind, output length and output hash), so
/// every node recomputes it for this request and settles the response at the same source
/// event. A contract's responses under one key version share an attestation key: only that
/// recomputed digest ties the signature to this request.
async fn settle_unobserved_midnight_response(
    entry: SignEntry,
    event: &RespondBidirectionalEvent,
    ctx: &StreamContext,
    root_pk: mpc_primitives::PublicKey,
) -> anyhow::Result<()> {
    let sign_id = entry.sign_id();
    let Some(tx) = unobserved_tx(&entry) else {
        return Ok(());
    };
    let published = event
        .attestation
        .context("Midnight response lacks attestation metadata")?;
    let (epsilon, payload) = published_midnight_signing_args(&tx, &published)?;
    mpc_crypto::verify_signature(root_pk, epsilon, payload, &event.signature).with_context(
        || format!("respond event carried invalid signature for sign id {sign_id:?}"),
    )?;

    settle_unobserved(entry, &tx, ctx).await
}

/// Settle a request whose execution this node has not seen yet, on a source chain other than
/// Midnight. The response is signed over the request id and the output, and the event carries
/// the output, so the node can check the signature without having seen the execution.
async fn settle_unobserved_response(
    entry: SignEntry,
    event: &RespondBidirectionalEvent,
    ctx: &StreamContext,
    root_pk: mpc_primitives::PublicKey,
) -> anyhow::Result<()> {
    let sign_id = entry.sign_id();
    let Some(tx) = unobserved_tx(&entry) else {
        return Ok(());
    };
    let Some(output) = &event.output else {
        tracing::warn!(
            ?sign_id,
            "response carries no output to check; keeping the request"
        );
        return Ok(());
    };
    let (epsilon, payload) = published_output_signing_args(&tx, output)?;
    let verified = mpc_crypto::verify_signature(root_pk, epsilon, payload, &event.signature);
    if verified.is_err() {
        tracing::warn!(?sign_id, "response does not verify; keeping the request");
        return Ok(());
    }

    settle_unobserved(entry, &tx, ctx).await
}

fn unobserved_tx(entry: &SignEntry) -> Option<Arc<BidirectionalTx>> {
    match entry.status() {
        SignStatus::Bidirectional(
            BidirectionalProgress::Executing(tx) | BidirectionalProgress::Parked(tx),
        ) => Some(Arc::clone(tx)),
        _ => {
            tracing::warn!(sign_id = ?entry.sign_id(), "bidirectional tx not found on completion");
            None
        }
    }
}

async fn settle_unobserved(
    entry: SignEntry,
    tx: &BidirectionalTx,
    ctx: &StreamContext,
) -> anyhow::Result<()> {
    let sign_id = entry.sign_id();
    // An unviable transaction is never mined, so no execution event would retire its watch.
    ctx.backlog.unwatch_execution(tx.target_chain, &tx.id).await;
    entry.complete().await;
    tracing::info!(
        ?sign_id,
        "bidirectional tx completed without an observed outcome"
    );
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
        tracing::error!(
            ?sign_id,
            ?tx_id,
            ?source_chain,
            output_deserialization_schema =
                %String::from_utf8_lossy(&entry.execution_tx().output_deserialization_schema),
            respond_serialization_schema =
                %String::from_utf8_lossy(&entry.execution_tx().respond_serialization_schema),
            "bidirectional output extraction failed terminally; parking the request \
             without a response, even though the destination transaction executed."
        );
        // Removing it here, on a target-chain event, would split source checkpoints (#1363).
        entry.park().await?;
        // Sent even during catchup: nothing requeues a parked request.
        ctx.sign_tx
            .send(SignCommand::Completion(sign_id))
            .await
            .context("failed to send completion into queue")?;
        return Ok(());
    }
    let execution_failed = matches!(
        result,
        ExecutionOutcome::Failed | ExecutionOutcome::Unviable
    );

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
    // The follow-up request belongs to the source chain: a node behind on it may
    // hold a request it has already answered. The requeue at its catchup sends it.
    if ctx.backlog.is_caught_up(chain) {
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
