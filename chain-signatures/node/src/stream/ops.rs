use crate::backlog::{Backlog, BacklogTransaction, SignTx};
use crate::indexer_hydration::{
    HydrationRespondBidirectionalEvent, HydrationSignBidirectionalRequestedEvent,
    HydrationSignatureRespondedEvent,
};
use crate::mesh::{wait_threshold_active, MeshState};
use crate::metrics::requests::record_indexing_step_reached;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest, Sign, SignRequestType};
use crate::respond_bidirectional::CompletedTx;
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::{BidirectionalTx, BidirectionalTxId, PendingRequestStatus};
use crate::stream::ExecutionOutcome;

use anchor_lang::prelude::Pubkey;
use k256::Scalar;
use mpc_primitives::{SignId, Signature};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignBidirectionalEvent {
    Solana(signet_program::SignBidirectionalEvent),
    Hydration(HydrationSignBidirectionalRequestedEvent),
}

impl SignBidirectionalEvent {
    pub fn sender(&self) -> [u8; 32] {
        match self {
            SignBidirectionalEvent::Solana(event) => event.sender.to_bytes(),
            SignBidirectionalEvent::Hydration(event) => event.sender,
        }
    }

    pub(crate) fn sender_string(&self) -> anyhow::Result<String> {
        sender_string(self.sender(), self.source_chain())
    }

    pub(crate) fn source_chain(&self) -> Chain {
        match self {
            SignBidirectionalEvent::Solana(_) => Chain::Solana,
            SignBidirectionalEvent::Hydration(_) => Chain::Hydration,
        }
    }

    pub fn path(&self) -> String {
        match self {
            SignBidirectionalEvent::Solana(event) => event.path.clone(),
            SignBidirectionalEvent::Hydration(event) => event.path.clone(),
        }
    }

    pub fn dest(&self) -> String {
        match self {
            SignBidirectionalEvent::Solana(event) => event.dest.clone(),
            SignBidirectionalEvent::Hydration(event) => event.dest.clone(),
        }
    }

    pub(crate) fn algo(&self) -> String {
        match self {
            SignBidirectionalEvent::Solana(event) => event.algo.clone(),
            SignBidirectionalEvent::Hydration(event) => event.algo.clone(),
        }
    }

    pub fn params(&self) -> String {
        match self {
            SignBidirectionalEvent::Solana(event) => event.params.clone(),
            SignBidirectionalEvent::Hydration(event) => event.params.clone(),
        }
    }

    pub fn output_deserialization_schema(&self) -> Vec<u8> {
        match self {
            SignBidirectionalEvent::Solana(event) => event.output_deserialization_schema.clone(),
            SignBidirectionalEvent::Hydration(event) => event.output_deserialization_schema.clone(),
        }
    }

    pub fn respond_serialization_schema(&self) -> Vec<u8> {
        match self {
            SignBidirectionalEvent::Solana(event) => event.respond_serialization_schema.clone(),
            SignBidirectionalEvent::Hydration(event) => event.respond_serialization_schema.clone(),
        }
    }

    pub fn key_version(&self) -> u32 {
        match self {
            SignBidirectionalEvent::Solana(event) => event.key_version,
            SignBidirectionalEvent::Hydration(event) => event.key_version,
        }
    }

    pub(crate) fn deposit(&self) -> u64 {
        match self {
            SignBidirectionalEvent::Solana(event) => event.deposit,
            SignBidirectionalEvent::Hydration(event) => event.deposit,
        }
    }

    pub fn serialized_transaction(&self) -> Vec<u8> {
        match self {
            SignBidirectionalEvent::Solana(event) => event.serialized_transaction.clone(),
            SignBidirectionalEvent::Hydration(event) => event.serialized_transaction.clone(),
        }
    }

    pub fn caip2_id(&self) -> String {
        match self {
            SignBidirectionalEvent::Solana(event) => event.caip2_id.clone(),
            SignBidirectionalEvent::Hydration(event) => event.caip2_id.clone(),
        }
    }

    pub fn epsilon(&self) -> anyhow::Result<Scalar> {
        match self {
            SignBidirectionalEvent::Solana(_) => Ok(mpc_crypto::kdf::derive_epsilon_sol(
                self.key_version(),
                &self.sender_string()?,
                &self.path(),
            )),
            SignBidirectionalEvent::Hydration(_) => Ok(mpc_crypto::kdf::derive_epsilon_hydration(
                self.key_version(),
                &self.sender_string()?,
                &self.path(),
            )),
        }
    }
}

pub enum RespondBidirectionalEvent {
    Solana(signet_program::RespondBidirectionalEvent),
    Hydration(HydrationRespondBidirectionalEvent),
}

impl RespondBidirectionalEvent {
    pub fn request_id(&self) -> [u8; 32] {
        match self {
            RespondBidirectionalEvent::Solana(event) => event.request_id,
            RespondBidirectionalEvent::Hydration(event) => event.request_id,
        }
    }

    pub fn responder(&self) -> [u8; 32] {
        match self {
            RespondBidirectionalEvent::Solana(event) => event.responder.to_bytes(),
            RespondBidirectionalEvent::Hydration(event) => event.responder,
        }
    }

    pub fn serialized_output(&self) -> Vec<u8> {
        match self {
            RespondBidirectionalEvent::Solana(event) => event.serialized_output.clone(),
            RespondBidirectionalEvent::Hydration(event) => event.serialized_output.clone(),
        }
    }

    pub fn signature(&self) -> Signature {
        match self {
            RespondBidirectionalEvent::Solana(event) => {
                crate::indexer_sol::to_mpc_signature(event.signature.clone()).unwrap()
            }
            RespondBidirectionalEvent::Hydration(event) => event.signature.clone(),
        }
    }

    pub fn source_chain(&self) -> Chain {
        match self {
            RespondBidirectionalEvent::Solana(_) => Chain::Solana,
            RespondBidirectionalEvent::Hydration(_) => Chain::Hydration,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthereumSignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: alloy::primitives::Address,
    /// Parsed MPC signature from Ethereum logs.
    pub signature: Signature,
}

#[derive(Clone, Debug)]
pub enum SignatureRespondedEvent {
    Solana(signet_program::SignatureRespondedEvent),
    Hydration(HydrationSignatureRespondedEvent),
    /// Minimal Ethereum respond event representation (used to emit Respond events
    /// from the Ethereum indexer without performing backlog mutations in the client).
    Ethereum(EthereumSignatureRespondedEvent),
}

impl SignatureRespondedEvent {
    pub fn source_chain(&self) -> Chain {
        match self {
            SignatureRespondedEvent::Solana(_) => Chain::Solana,
            SignatureRespondedEvent::Hydration(_) => Chain::Hydration,
            SignatureRespondedEvent::Ethereum(_) => Chain::Ethereum,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        match self {
            SignatureRespondedEvent::Solana(event) => event.request_id,
            SignatureRespondedEvent::Hydration(event) => event.request_id,
            SignatureRespondedEvent::Ethereum(event) => event.request_id,
        }
    }

    /// Convert the contained event into an `mpc_primitives::Signature`.
    pub fn signature(&self) -> Signature {
        match self {
            SignatureRespondedEvent::Solana(event) => {
                crate::indexer_sol::to_mpc_signature(event.signature.clone()).unwrap()
            }
            SignatureRespondedEvent::Hydration(event) => event.signature.clone(),
            SignatureRespondedEvent::Ethereum(event) => event.signature.clone(),
        }
    }
}

pub(crate) trait SignatureEvent: std::fmt::Debug {
    fn generate_request_id(&self) -> [u8; 32];
    fn generate_sign_request(
        &self,
        entropy: [u8; 32],
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest>;
    fn source_chain(&self) -> Chain;
    fn sender_string(&self) -> String;
}

pub(crate) type SignatureEventBox = Box<dyn SignatureEvent + Send>;

pub(crate) async fn process_sign_event(
    sign_event: SignatureEventBox,
    entropy: [u8; 32],
    sign_tx: mpsc::Sender<Sign>,
    total_timeout: Duration,
    backlog: Backlog,
) -> anyhow::Result<()> {
    let sign_request = sign_event.generate_sign_request(entropy, total_timeout)?;

    record_indexing_step_reached(sign_event.source_chain());

    // Insert the transaction into the backlog when we first see the sign request
    let sign_id = sign_request.id;
    let sign_request_type = sign_request.sign_request_type.clone();

    // Create the appropriate BacklogTransaction based on the sign request type
    let backlog_tx = match &sign_request_type {
        SignRequestType::Sign => BacklogTransaction::Sign(SignTx {
            request_id: sign_id.request_id,
            source_chain: sign_event.source_chain(),
            status: PendingRequestStatus::AwaitingResponse,
            args: sign_request.args.clone(),
            unix_timestamp_indexed: sign_request.unix_timestamp_indexed,
        }),
        SignRequestType::SignBidirectional(_event) => {
            // For bidirectional requests, start with a Sign transaction
            // The protocol will advance it to Bidirectional after generating the signature
            BacklogTransaction::Sign(SignTx {
                request_id: sign_id.request_id,
                source_chain: sign_event.source_chain(),
                status: PendingRequestStatus::AwaitingResponse,
                args: sign_request.args.clone(),
                unix_timestamp_indexed: sign_request.unix_timestamp_indexed,
            })
        }
        _ => anyhow::bail!("Unexpected sign request type"),
    };

    backlog
        .insert(
            sign_event.source_chain(),
            sign_id,
            backlog_tx,
            sign_request_type,
        )
        .await;

    if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
        // TODO: handle error to ensure 100% success rate
        let chain = sign_event.source_chain();
        tracing::error!(?err, %chain, "failed to send sign request into queue");
    }

    Ok(())
}

pub(crate) async fn process_sign_request(
    sign_request: IndexedSignRequest,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
) -> anyhow::Result<()> {
    record_indexing_step_reached(sign_request.chain);

    let sign_id = sign_request.id;
    let sign_type = sign_request.sign_request_type.clone();

    let backlog_tx = match &sign_type {
        SignRequestType::Sign => BacklogTransaction::Sign(SignTx {
            request_id: sign_id.request_id,
            source_chain: sign_request.chain,
            status: PendingRequestStatus::AwaitingResponse,
            args: sign_request.args.clone(),
            unix_timestamp_indexed: sign_request.unix_timestamp_indexed,
        }),
        SignRequestType::SignBidirectional(_event) => BacklogTransaction::Sign(SignTx {
            request_id: sign_id.request_id,
            source_chain: sign_request.chain,
            status: PendingRequestStatus::AwaitingResponse,
            args: sign_request.args.clone(),
            unix_timestamp_indexed: sign_request.unix_timestamp_indexed,
        }),
        _ => anyhow::bail!("Unexpected sign request type"),
    };

    backlog
        .insert(sign_request.chain, sign_id, backlog_tx, sign_type)
        .await;

    let chain = sign_request.chain;
    if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
        tracing::error!(?err, %chain, "failed to send sign request into queue");
    }

    Ok(())
}

pub(crate) async fn recover_backlog(
    backlog: &Backlog,
    contract_watcher: &mut ContractStateWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    source_chain: Chain,
    sign_tx: mpsc::Sender<Sign>,
    total_timeout: Duration,
) {
    // Recover backlog before doing anything.
    // Wait for threshold to be available
    let threshold = contract_watcher.wait_threshold().await;
    if threshold == 0 {
        return;
    }
    wait_threshold_active(mesh_state, threshold).await;

    let mesh_state = mesh_state.borrow().clone();
    let mut pending = backlog
        .recover(&mesh_state, node_client, threshold, &[source_chain])
        .await;

    // Re-enqueue any pending sign requests so the node processes them after recovery
    let pending = pending.remove(&source_chain).unwrap_or_default();

    for (sign_id, tx) in pending
        .into_iter()
        .filter(|(_, tx)| matches!(tx.status(), PendingRequestStatus::AwaitingResponse))
    {
        let BacklogTransaction::Sign(sign_tx_entry) = tx else {
            continue;
        };

        let Some(sign_type) = backlog.sign_type(source_chain, &sign_id).await else {
            tracing::warn!(
                ?sign_id,
                ?source_chain,
                "sign type missing during backlog recovery"
            );
            continue;
        };

        let sign_request = IndexedSignRequest {
            id: sign_id,
            args: sign_tx_entry.args.clone(),
            chain: sign_tx_entry.source_chain,
            unix_timestamp_indexed: sign_tx_entry.unix_timestamp_indexed,
            timestamp_created: Instant::now(),
            total_timeout,
            sign_request_type: sign_type,
        };

        if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
            tracing::error!(
                ?err,
                ?sign_id,
                ?source_chain,
                "failed to requeue sign request after recovery"
            );
        }
    }
}

pub(crate) async fn process_respond_event(
    respond_event: SignatureRespondedEvent,
    sign_tx: mpsc::Sender<Sign>,
    contract_watcher: &mut ContractStateWatcher,
    backlog: &Backlog,
) -> anyhow::Result<()> {
    let sign_id = SignId::new(respond_event.request_id());

    let source_chain = respond_event.source_chain();

    let Some(sign_type) = backlog.sign_type(source_chain, &sign_id).await else {
        anyhow::bail!(
            "sign type not found for respond event (may have already been processed): {sign_id:?}"
        )
    };

    let event = match sign_type {
        SignRequestType::SignBidirectional(event) => event,
        SignRequestType::Sign => {
            tracing::info!(?sign_id, "sign request completed successfully");
            backlog.remove(source_chain, &sign_id).await;
            if let Err(err) = sign_tx.send(Sign::Completion(sign_id)).await {
                anyhow::bail!("failed to send completion for respond event: {err:?}");
            }
            return Ok(());
        }
        SignRequestType::RespondBidirectional(_) => {
            anyhow::bail!("RespondBidirectional received respond event?: {sign_id:?}")
        }
    };

    tracing::info!(?sign_id, "bidirectional processing initial respond event");
    let target_chain = Chain::from_str(&event.dest())
        .map_err(|err| anyhow::anyhow!("unable to parse target chain from dest: {err:?}"));
    let target_chain = match target_chain {
        Ok(chain) => chain,
        Err(_) => Chain::Ethereum,
    };

    let Some(BacklogTransaction::Sign(_)) = backlog.get(source_chain, &sign_id).await else {
        anyhow::bail!("bidirectional tx not found for advancement: {sign_id:?}");
    };

    let mpc_sig = respond_event.signature();

    // Sign and hash the transaction to get the correct tx_id and nonce
    let (signed_tx_hash, nonce) = crate::sign_bidirectional::sign_and_hash_transaction(
        &event.serialized_transaction(),
        mpc_sig,
    )?;

    let tx_id = BidirectionalTxId(signed_tx_hash.into());

    // Get the MPC public key and derive the from_address
    let root_public_key = contract_watcher.wait_public_key().await;
    let epsilon = event.epsilon()?;
    let from_address = crate::sign_bidirectional::derive_user_address(root_public_key, epsilon);

    let bidirectional_tx = BidirectionalTx {
        id: tx_id,
        sender: event.sender(),
        serialized_transaction: event.serialized_transaction(),
        source_chain,
        target_chain,
        caip2_id: event.caip2_id(),
        key_version: event.key_version(),
        deposit: event.deposit(),
        path: event.path(),
        algo: event.algo(),
        dest: event.dest(),
        params: event.params(),
        output_deserialization_schema: event.output_deserialization_schema(),
        respond_serialization_schema: event.respond_serialization_schema(),
        request_id: respond_event.request_id(),
        from_address,
        nonce,
        status: PendingRequestStatus::AwaitingResponse,
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
    backlog: &Backlog,
) -> anyhow::Result<()> {
    let sign_id = SignId::new(event.request_id());
    tracing::info!(?sign_id, "processing RespondBidirectionalEvent");
    if backlog
        .remove(event.source_chain(), &sign_id)
        .await
        .is_some()
    {
        tracing::info!(?sign_id, "bidirectional tx completed");
    } else {
        tracing::warn!(?sign_id, "bidirectional tx not found on completion");
    }

    sign_tx
        .send(Sign::Completion(sign_id))
        .await
        .map_err(|err| anyhow::anyhow!("failed to send completion for respond bidirectional: {err:?} for sign id: {sign_id:?}"))?;

    Ok(())
}

/// Process an execution confirmation emitted by a chain client.
/// The target chain is the chain where the execution was observed.
#[allow(clippy::too_many_arguments)]
pub async fn process_execution_confirmed(
    tx_id: crate::sign_bidirectional::BidirectionalTxId,
    sign_id: SignId,
    source_chain: Chain,
    block_height: u64,
    result: ExecutionOutcome,
    backlog: &Backlog,
    sign_tx: mpsc::Sender<Sign>,
    total_timeout: Duration,
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
    let Some((unwatched_sign_id, mut pending_tx)) =
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

    // Update the status on the source chain
    let status = match result {
        ExecutionOutcome::Success { .. } => PendingRequestStatus::Success,
        ExecutionOutcome::Failed => PendingRequestStatus::Failed,
    };

    let set_res = backlog
        .set_status(pending_tx.source_chain, &unwatched_sign_id, status)
        .await;
    let updated_tx = match set_res {
        Some(tx) => tx,
        None => {
            tracing::error!(?tx_id, ?unwatched_sign_id, source_chain = ?pending_tx.source_chain, "failed to set status on pending tx");
            anyhow::bail!("failed to set status for sign id: {unwatched_sign_id:?}");
        }
    };
    tracing::info!(?tx_id, ?unwatched_sign_id, updated_status = ?updated_tx.status(), "set_status returned transaction");

    pending_tx.status = status;
    let completed_tx = CompletedTx::new(pending_tx, block_height);

    let sign_request = match result {
        ExecutionOutcome::Success { output } => completed_tx
            .create_sign_request_from_serialized_output(source_chain, output, total_timeout)?,
        ExecutionOutcome::Failed => {
            completed_tx
                .create_failed_sign_request(source_chain, total_timeout)
                .await?
        }
    };

    let chain = sign_request.chain;
    if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
        tracing::error!(?err, %chain, "failed to send sign request into queue");
    }

    Ok(())
}

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
    use crate::mesh::wait_threshold_active;
    use crate::node_client::NodeClient;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::stream::ops::process_execution_confirmed;
    use crate::util::current_unix_timestamp;
    use cait_sith::protocol::Participant;
    use k256::{ProjectivePoint, Scalar};
    use mpc_primitives::SignArgs;
    use near_primitives::types::AccountId;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    #[test]
    fn ethereum_signature_respond_event_conversion() {
        let big_r = ProjectivePoint::GENERATOR.to_affine();
        let s_scalar = Scalar::from(5u64);
        let recovery_id: u8 = 1;

        let eth_event = EthereumSignatureRespondedEvent {
            request_id: [0u8; 32],
            responder: alloy::primitives::Address::from_slice(&[0u8; 20]),
            signature: Signature::new(big_r, s_scalar, recovery_id),
        };

        // check fields
        let sig = eth_event.signature;
        assert_eq!(sig.recovery_id, recovery_id);
        assert_eq!(sig.s, s_scalar);
        assert_eq!(sig.big_r, big_r);
    }

    #[tokio::test]
    async fn recover_backlog_requeues_pending_signs() {
        // Prepare backlog with a single pending sign request
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
            .insert(
                Chain::Ethereum,
                sign_id,
                BacklogTransaction::Sign(SignTx {
                    request_id: sign_id.request_id,
                    source_chain: Chain::Ethereum,
                    status: PendingRequestStatus::AwaitingResponse,
                    args: args.clone(),
                    unix_timestamp_indexed,
                }),
                SignRequestType::Sign,
            )
            .await;
        backlog.checkpoint(Chain::Ethereum).await;

        let threshold = 1;
        let mut mesh_state = MeshState::default();
        let participant = Participant::from(0u32);
        mesh_state
            .active
            .insert(&participant, ParticipantInfo::new(0));
        mesh_state.stable.insert(participant);
        let (_mesh_tx, mut mesh_rx) = watch::channel(mesh_state);
        wait_threshold_active(&mut mesh_rx, threshold).await;

        let account_id: AccountId = "test.near".parse().unwrap();
        let public_key = ProjectivePoint::GENERATOR.to_affine();
        let participants = Participants::default();
        let (mut contract_watcher, _tx) =
            ContractStateWatcher::with_running(&account_id, public_key, threshold, participants);

        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let node_client = NodeClient::new(&Default::default());

        recover_backlog(
            &backlog,
            &mut contract_watcher,
            &mut mesh_rx,
            &node_client,
            Chain::Ethereum,
            sign_tx,
            Duration::from_secs(5),
        )
        .await;

        // We should receive the recovered sign request
        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .expect("recv should not timeout");

        match msg.expect("sign_rx should contain a message") {
            Sign::Request(req) => {
                assert_eq!(req.id, sign_id);
                assert_eq!(req.args, args);
                assert_eq!(req.chain, Chain::Ethereum);
                assert_eq!(req.sign_request_type, SignRequestType::Sign);
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

        // Create a bidirectional tx and watch it on the target chain
        use alloy::primitives::{Address, B256};
        let tx = BidirectionalTx {
            id: BidirectionalTxId(B256::from([1u8; 32])),
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
            respond_serialization_schema: vec![],
            request_id: [1u8; 32],
            from_address: Address::ZERO,
            nonce: 0,
            status: PendingRequestStatus::PendingExecution,
        };
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
            .insert(
                tx.source_chain,
                sign_id,
                BacklogTransaction::Sign(SignTx {
                    request_id: sign_id.request_id,
                    source_chain: tx.source_chain,
                    status: PendingRequestStatus::AwaitingResponse,
                    args: args.clone(),
                    unix_timestamp_indexed,
                }),
                SignRequestType::Sign,
            )
            .await;

        backlog
            .watch_execution(tx.target_chain, sign_id, tx.clone())
            .await;

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        // Call the handler with a Success and empty output
        let tx_id = tx.id;
        // ensure watcher exists before processing
        let before_watchers = backlog.pending_execution(tx.target_chain).await;
        assert!(before_watchers.contains_key(&tx.id));
        process_execution_confirmed(
            tx_id,
            sign_id,
            tx.source_chain,
            123u64,
            ExecutionOutcome::Success { output: vec![] },
            &backlog,
            sign_tx,
            Duration::from_secs(30),
            tx.target_chain,
        )
        .await
        .unwrap();

        // Watcher should be removed
        let watchers = backlog.pending_execution(tx.target_chain).await;
        tracing::info!(?watchers, "watchers after execution confirmed");
        assert!(watchers.is_empty());

        // Source chain request should be marked Success
        // inspect the transaction to provide more debugging info on failure
        let maybe_tx = backlog.get(tx.source_chain, &sign_id).await;
        assert!(maybe_tx.is_some(), "expected sign tx to still exist");
        let tx_after = maybe_tx.unwrap();
        if tx_after.status() != PendingRequestStatus::Success {
            panic!("expected Success but found status: {:?}", tx_after.status());
        }

        // A sign request should have been sent to the sign queue
        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => {
                if let crate::protocol::SignRequestType::RespondBidirectional(res) =
                    req.sign_request_type
                {
                    assert_eq!(res.tx_id, tx.id);
                } else {
                    panic!("Expected RespondBidirectional request");
                }
            }
            _ => panic!("Expected Sign::Request"),
        }
    }

    #[tokio::test]
    async fn process_execution_confirmed_failed_creates_error_respond_request() {
        let backlog = Backlog::new();

        use alloy::primitives::{Address, B256};
        let tx = BidirectionalTx {
            id: BidirectionalTxId(B256::from([2u8; 32])),
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
            respond_serialization_schema: vec![],
            request_id: [2u8; 32],
            from_address: Address::ZERO,
            nonce: 0,
            status: PendingRequestStatus::PendingExecution,
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
            .insert(
                tx.source_chain,
                sign_id,
                BacklogTransaction::Sign(SignTx {
                    request_id: sign_id.request_id,
                    source_chain: tx.source_chain,
                    status: PendingRequestStatus::AwaitingResponse,
                    args: args.clone(),
                    unix_timestamp_indexed,
                }),
                SignRequestType::Sign,
            )
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
            Duration::from_secs(30),
            tx.target_chain,
        )
        .await
        .unwrap();

        // Watcher removed
        let watchers = backlog.pending_execution(tx.target_chain).await;
        assert!(watchers.is_empty());

        // Source chain should be marked Failed
        let failed = backlog
            .get_by_status(tx.source_chain, PendingRequestStatus::Failed)
            .await;
        assert!(failed.contains_key(&sign_id));

        // A sign request should have been sent
        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => {
                if let crate::protocol::SignRequestType::RespondBidirectional(res) =
                    req.sign_request_type
                {
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
}
