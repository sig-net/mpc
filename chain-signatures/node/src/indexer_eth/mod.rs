pub mod abi;
mod client;
mod config;
pub mod indexer_eth_direct_rpc;
#[cfg(feature = "helios")]
pub mod indexer_eth_helios;
#[cfg(test)]
pub mod test_utils;

use crate::indexer_eth::abi::{ChainSignatures, SignatureRequestedEncoding};
use alloy::consensus::Transaction;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::{Block, BlockId, Log};
use alloy::sol_types::{SolEvent, SolValue};
use anyhow::Context as _;
use async_trait::async_trait;
pub use client::EthereumClient;
pub use config::EthConfig;
use futures_util::stream;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint as K256AffinePoint, EncodedPoint, FieldBytes, Scalar};
use mpc_chain_integration_core::utils::stream::chain_event_channel;
use mpc_chain_integration_core::{
    utils::hashing::hash_payload, ChainIndexer, ChainStream, ChainTelemetry, StateManager,
};
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, IndexedSignRequest,
    SignArgs, SignId, Signature as MpcSignature, SignatureRespondedEvent, LATEST_MPC_KEY_VERSION,
    MAX_SECP256K1_SCALAR,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};
use tokio::time::Duration;

const MAX_LIVE_BLOCK_BUFFER: usize = 16384;
const CATCHUP_BLOCK_BATCH_SIZE: u64 = 32;

fn live_blocks_channel() -> (mpsc::Sender<MaybeBlock>, mpsc::Receiver<MaybeBlock>) {
    mpsc::channel(MAX_LIVE_BLOCK_BUFFER)
}

type BlockNumber = u64;

pub struct CatchupIter {
    client: Arc<EthereumClient>,
    next_block: BlockNumber,
    end_block: BlockNumber,
    buffered_blocks: std::vec::IntoIter<MaybeBlock>,
}

impl CatchupIter {
    fn new(client: Arc<EthereumClient>, start_block: BlockNumber, end_block: BlockNumber) -> Self {
        Self {
            client,
            next_block: start_block,
            end_block,
            buffered_blocks: Vec::new().into_iter(),
        }
    }

    async fn fetch_next_batch(&mut self) {
        if self.next_block >= self.end_block {
            return;
        }

        let batch_end = self
            .next_block
            .saturating_add(CATCHUP_BLOCK_BATCH_SIZE)
            .min(self.end_block);
        let batch_block_ids = (self.next_block..batch_end)
            .map(|block_number| BlockId::Number(BlockNumberOrTag::Number(block_number)))
            .collect::<Vec<_>>();

        self.buffered_blocks = self.client.get_blocks(&batch_block_ids).await.into_iter();
        self.next_block = batch_end;
    }

    pub async fn next(&mut self) -> Option<MaybeBlock> {
        loop {
            if let Some(block) = self.buffered_blocks.next() {
                return Some(block);
            }

            if self.next_block >= self.end_block {
                return None;
            }

            self.fetch_next_batch().await;
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeBlock {
    Block(Block),
    Missing(BlockId),
}

pub struct BlockAndRequests {
    block_number: u64,
    block_hash: alloy::primitives::B256,
    indexed_requests: Vec<IndexedSignRequest>,
    respond_logs: Vec<Log>,
    respond_bidirectional_logs: Vec<Log>,
    execution_events: Vec<ChainEvent>,
}

impl BlockAndRequests {
    fn new(
        block_number: u64,
        block_hash: alloy::primitives::B256,
        indexed_requests: Vec<IndexedSignRequest>,
        respond_logs: Vec<Log>,
        respond_bidirectional_logs: Vec<Log>,
        execution_events: Vec<ChainEvent>,
    ) -> Self {
        Self {
            block_number,
            block_hash,
            indexed_requests,
            respond_logs,
            respond_bidirectional_logs,
            execution_events,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EthSignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

/// Whether a transaction's calldata represents a contract call.
fn is_contract_call(input: &Bytes) -> bool {
    input.len() > 2 && input != &Bytes::from("0x")
}

fn sign_request_from_filtered_log(log: Log) -> Option<IndexedSignRequest> {
    let event = parse_event(&log);
    tracing::debug!("found eth event: {:?}", event);
    if event.deposit == U256::ZERO {
        tracing::warn!("deposit is 0, skipping sign request");
        return None;
    }

    if event.key_version > LATEST_MPC_KEY_VERSION {
        tracing::warn!("unsupported key version: {}", event.key_version);
        return None;
    }

    // Create sign request from event
    let Some(payload) = Scalar::from_bytes(event.payload_hash) else {
        tracing::warn!(
            "eth `sign` did not produce payload hash correctly: {:?}",
            event.payload_hash,
        );
        return None;
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
        return None;
    }

    let epsilon = derive_epsilon_eth(
        event.key_version,
        format!("0x{}", event.requester.encode_hex()).as_str(),
        &event.path,
    );

    // Use transaction hash as entropy
    let entropy = log.transaction_hash.unwrap_or_default();

    let sign_id = SignId::new(event.generate_request_id());
    tracing::info!(?sign_id, "eth signature requested");

    Some(IndexedSignRequest::sign(
        sign_id,
        SignArgs {
            entropy: entropy.into(),
            epsilon,
            payload,
            path: event.path,
            key_version: event.key_version,
        },
        Chain::Ethereum,
        crate::util::current_unix_timestamp(),
    ))
}

// Helper function to parse event logs
fn parse_event(log: &Log) -> SignatureRequestedEvent {
    // Parse data fields
    let data = log.data().data.clone();

    // Parse requester address (20 bytes)
    let requester = Address::from_slice(&data[12..32]);

    // Parse payload hash (32 bytes)
    let mut payload_hash = [0u8; 32];
    payload_hash.copy_from_slice(&data[32..64]);

    let key_version: u32 = U256::from_be_slice(&data[64..96]).to::<u32>();

    let deposit = U256::from_be_slice(&data[96..128]);

    let chain_id = U256::from_be_slice(&data[128..160]);

    let path = parse_string_args(&data, 160);

    let algo = parse_string_args(&data, 192);

    let dest = parse_string_args(&data, 224);

    let params = parse_string_args(&data, 256);

    tracing::info!(
        "Parsed event: requester={}, payload_hash={}, path={}, deposit={}, chain_id={}, algo={}, dest={}, params={}",
        requester,
        hex::encode(payload_hash),
        path,
        deposit,
        chain_id,
        algo,
        dest,
        params
    );

    SignatureRequestedEvent {
        requester,
        payload_hash,
        path,
        key_version,
        deposit,
        chain_id,
        algo,
        dest,
        params,
    }
}

fn parse_string_args(data: &Bytes, offset_start: usize) -> String {
    let offset: usize = U256::from_be_slice(&data[offset_start..offset_start + 32]).to::<usize>();
    let length: usize = U256::from_be_slice(&data[offset..offset + 32]).to::<usize>();
    if length == 0 {
        return String::new();
    }
    let bytes = &data[offset + 32..offset + 32 + length];
    String::from_utf8(bytes.to_vec()).unwrap_or_default()
}

fn parse_filtered_logs(logs: Vec<Log>) -> Vec<IndexedSignRequest> {
    let mut indexed_requests = Vec::new();
    for log in logs {
        tracing::debug!("Parsing Ethereum log: {:?}", log);
        match sign_request_from_filtered_log(log.clone()) {
            Some(request) => indexed_requests.push(request),
            None => tracing::warn!("Failed to parse Ethereum log: {:?}", log),
        }
    }
    if indexed_requests.is_empty() {
        tracing::warn!("No valid Ethereum sign requests found in logs");
    }
    indexed_requests
}

fn sign_bidirectional_request_from_filtered_log(log: Log) -> Option<IndexedSignRequest> {
    let event = match ChainSignatures::SignBidirectional::decode_log(&log.inner) {
        Ok(event) => event.data,
        Err(err) => {
            tracing::warn!(?err, "failed to decode SignBidirectional event");
            return None;
        }
    };
    tracing::debug!("found eth bidirectional event: {:?}", event.caip2Id);

    let sign_id = SignId::new(generate_bidirectional_request_id(&event));

    if event.deposit == U256::ZERO {
        tracing::warn!(?sign_id, "deposit is 0, skipping sign request");
        return None;
    }

    if event.keyVersion > LATEST_MPC_KEY_VERSION {
        tracing::warn!(?sign_id, "unsupported key version: {}", event.keyVersion);
        return None;
    }

    // caip2_id is the mainnet CAIP-2 chain id of the target chain. Skip the
    // event if it is invalid since it cannot be handled downstream anyway.
    if let Err(err) = Chain::from_caip2_chain_id(&event.caip2Id) {
        tracing::warn!(
            ?sign_id,
            "invalid caip2 chain id in sign bidirectional event: {err:?}"
        );
        return None;
    }

    let unsigned_tx_hash = hash_payload(&event.serializedTransaction);
    let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
        tracing::warn!(
            ?sign_id,
            "eth `signBidirectional` did not produce payload hash correctly: {unsigned_tx_hash:?}"
        );
        return None;
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!(?sign_id, ?payload, "payload exceeds secp256k1 curve order");
        return None;
    }

    let epsilon = derive_epsilon_eth(
        event.keyVersion,
        format!("0x{}", event.sender.encode_hex()).as_str(),
        &event.path,
    );

    // Store the sender as its ABI word: 12 zero bytes then the 20-byte address.
    let mut sender = [0u8; 32];
    sender[12..].copy_from_slice(event.sender.as_slice());

    // Use transaction hash as entropy
    let entropy = log.transaction_hash.unwrap_or_default();

    tracing::info!(?sign_id, "eth bidirectional signature requested");

    Some(IndexedSignRequest::sign_bidirectional(
        sign_id,
        SignArgs {
            entropy: entropy.into(),
            epsilon,
            payload,
            path: event.path.clone(),
            key_version: event.keyVersion,
        },
        Chain::Ethereum,
        crate::util::current_unix_timestamp(),
        mpc_primitives::SignBidirectionalEvent {
            sender,
            serialized_transaction: event.serializedTransaction.to_vec(),
            caip2_id: event.caip2Id,
            key_version: event.keyVersion,
            deposit: event.deposit.saturating_to::<u64>(),
            path: event.path,
            algo: event.algo,
            dest: event.dest,
            params: event.params,
            output_deserialization_schema: event.outputDeserializationSchema.to_vec(),
            respond_serialization_schema: event.respondSerializationSchema.to_vec(),
            chain: Chain::Ethereum,
            chain_ctx: None,
        },
    ))
}

fn parse_bidirectional_filtered_logs(logs: Vec<Log>) -> Vec<IndexedSignRequest> {
    let mut indexed_requests = Vec::new();
    for log in logs {
        match sign_bidirectional_request_from_filtered_log(log.clone()) {
            Some(request) => indexed_requests.push(request),
            None => tracing::warn!("Failed to parse Ethereum SignBidirectional log: {:?}", log),
        }
    }
    indexed_requests
}

async fn emit_respond_events(logs: &[Log], events_tx: mpsc::Sender<ChainEvent>) {
    for log in logs {
        let Some(sign_id) = sign_id_from_signature_responded_log(log) else {
            continue;
        };

        let data = &log.data().data;
        if data.len() < 160 {
            tracing::warn!(
                ?sign_id,
                data_len = data.len(),
                "signature event data too short to parse full signature: skipping..."
            );
            continue;
        }

        // signature struct encoding layout:
        // bigR.x at 32..64, bigR.y at 64..96, s at 96..128, recoveryId at 159
        let big_r_x = &data[32..64];
        let big_r_y = &data[64..96];
        let s_bytes: [u8; 32] = data[96..128].try_into().unwrap();
        let recovery_id = data[159];

        let x_field = FieldBytes::from_slice(big_r_x);
        let y_field = FieldBytes::from_slice(big_r_y);
        let encoded_r = EncodedPoint::from_affine_coordinates(x_field, y_field, false);
        let Some(big_r) = K256AffinePoint::from_encoded_point(&encoded_r).into_option() else {
            tracing::warn!(?sign_id, "ethereum respond event, invalid big_r point");
            continue;
        };

        let Some(s) = Scalar::from_bytes(s_bytes) else {
            tracing::warn!(?sign_id, "ethereum respond event, invalid s scalar");
            continue;
        };

        let signature = MpcSignature::new(big_r, s, recovery_id);

        let respond_event = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature,
            chain: Chain::Ethereum,
        };
        tracing::info!(?sign_id, "emitting SignatureResponded event");
        if let Err(err) = events_tx.send(ChainEvent::Respond(respond_event)).await {
            tracing::error!(?err, "failed to emit Respond event");
        }
    }
}

fn sign_id_from_signature_responded_log(log: &Log) -> Option<SignId> {
    if log
        .topic0()
        .is_none_or(|topic| *topic != ChainSignatures::SignatureResponded::SIGNATURE_HASH)
    {
        return None;
    }

    let request_topic = log.topics().get(1)?;
    let request_id: [u8; 32] = (*request_topic).into();
    Some(SignId { request_id })
}

/// Decode a `RespondBidirectional` contract log into the primitives event.
fn respond_bidirectional_event_from_log(
    log: &Log,
) -> Option<mpc_primitives::RespondBidirectionalEvent> {
    let decoded = match ChainSignatures::RespondBidirectional::decode_log(&log.inner) {
        Ok(decoded) => decoded.data,
        Err(err) => {
            tracing::warn!(?err, "failed to decode RespondBidirectional event");
            return None;
        }
    };
    let sign_id = SignId::new(decoded.requestId.into());

    let Some(signature) = mpc_signature_from_abi(&decoded.signature) else {
        tracing::warn!(
            ?sign_id,
            "ethereum respond bidirectional event, invalid signature"
        );
        return None;
    };

    Some(mpc_primitives::RespondBidirectionalEvent {
        request_id: sign_id.request_id,
        signature,
        chain: Chain::Ethereum,
    })
}

/// Convert the contract's ABI signature struct into the MPC signature type.
fn mpc_signature_from_abi(signature: &ChainSignatures::Signature) -> Option<MpcSignature> {
    let x_bytes: [u8; 32] = signature.bigR.x.to_be_bytes();
    let y_bytes: [u8; 32] = signature.bigR.y.to_be_bytes();
    let x_field = FieldBytes::from_slice(&x_bytes);
    let y_field = FieldBytes::from_slice(&y_bytes);
    let encoded_r = EncodedPoint::from_affine_coordinates(x_field, y_field, false);
    let big_r = K256AffinePoint::from_encoded_point(&encoded_r).into_option()?;
    let s = Scalar::from_bytes(signature.s.to_be_bytes())?;
    Some(MpcSignature::new(big_r, s, signature.recoveryId))
}

async fn emit_respond_bidirectional_events(logs: &[Log], events_tx: mpsc::Sender<ChainEvent>) {
    for log in logs {
        let Some(respond_event) = respond_bidirectional_event_from_log(log) else {
            continue;
        };
        let sign_id = SignId::new(respond_event.request_id);
        tracing::info!(?sign_id, "emitting RespondBidirectional event");
        if let Err(err) = events_tx
            .send(ChainEvent::RespondBidirectional(respond_event))
            .await
        {
            tracing::error!(?err, "failed to emit RespondBidirectional event");
        }
    }
}

#[derive(Debug)]
struct SignatureRequestedEvent {
    requester: Address,
    payload_hash: [u8; 32],
    path: String,
    key_version: u32,
    deposit: U256,
    chain_id: U256,
    algo: String,
    dest: String,
    params: String,
}

impl SignatureRequestedEvent {
    fn encode_abi(&self) -> Vec<u8> {
        let signature_requested_event_encoding = SignatureRequestedEncoding {
            sender: self.requester,
            payload: self.payload_hash.into(),
            path: self.path.clone(),
            keyVersion: self.key_version,
            chainId: self.chain_id,
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
        };
        signature_requested_event_encoding.encode_data()
    }

    pub fn generate_request_id(&self) -> [u8; 32] {
        let abi_encoded = self.encode_abi();
        alloy::primitives::keccak256(abi_encoded).into()
    }
}

/// Request id for the `signBidirectional` flow, mirroring the Solana program's
/// packed scheme with the EVM address as the sender:
/// keccak256(abi.encodePacked(sender, serializedTransaction, caip2Id, keyVersion, path, algo, dest, params))
fn generate_bidirectional_request_id(event: &ChainSignatures::SignBidirectional) -> [u8; 32] {
    let encoded = (
        event.sender,
        event.serializedTransaction.clone(),
        event.caip2Id.clone(),
        event.keyVersion,
        event.path.clone(),
        event.algo.clone(),
        event.dest.clone(),
        event.params.clone(),
    )
        .abi_encode_packed();

    alloy::primitives::keccak256(encoded).into()
}

pub struct EthereumIndexer<S: StateManager, T: ChainTelemetry> {
    eth: EthConfig,
    state_manager: S,
    telemetry: T,
    client: Arc<EthereumClient>,
    events_tx: mpsc::Sender<ChainEvent>,
    contract_address: Address,
    catchup_complete: Arc<Notify>,
    live_blocks_rx: Option<mpsc::Receiver<MaybeBlock>>,
}

/// Result of a `backfill_execution_confirmation`. `Observed` carries an
/// optional event; the staleness check skips observed watchers so a mined tx
/// with a failed extraction can stay pending for retry. `NotObserved` covers
/// "no receipt yet" (pending or replaced).
#[allow(clippy::large_enum_variant)] // value is consumed in one match arm; never stored.
enum BackfillOutcome {
    NotObserved,
    Observed { event: Option<ChainEvent> },
}

impl<S: StateManager, T: ChainTelemetry> EthereumIndexer<S, T> {
    pub async fn new(
        eth: EthConfig,
        state_manager: S,
        telemetry: T,
        events_tx: mpsc::Sender<ChainEvent>,
    ) -> anyhow::Result<Self> {
        let client = Arc::new(EthereumClient::new(eth.clone()).await?);
        let contract_address = format!("0x{}", eth.contract_address);
        let contract_address = Address::from_str(&contract_address).with_context(|| {
            format!("failed to parse ethereum contract address: {contract_address}")
        })?;

        Ok(Self {
            eth,
            state_manager,
            telemetry,
            client,
            events_tx,
            contract_address,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        })
    }

    async fn index_live_blocks(
        client: Arc<EthereumClient>,
        catchup_complete: Arc<Notify>,
        start_block_number: u64,
        live_blocks: mpsc::Sender<MaybeBlock>,
    ) {
        tracing::info!("indexing ethereum live blocks");

        // Wait for catchup to complete before starting to index live blocks
        catchup_complete.notified().await;

        let mut current_block_number = start_block_number;

        // Missing ticks is what we want due to retrying on transient errors
        let mut interval = tokio::time::interval(Self::RETRY_DELAY);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;
            let Some(latest_block_number) = client.get_latest_block_number().await else {
                continue;
            };

            while current_block_number <= latest_block_number {
                let Some(block) = client
                    .get_block(BlockId::Number(BlockNumberOrTag::Number(
                        current_block_number,
                    )))
                    .await
                else {
                    tracing::warn!(
                        current_block_number,
                        "ethereum live block not yet available"
                    );
                    break;
                };

                if let Err(err) = live_blocks.send(MaybeBlock::Block(block)).await {
                    tracing::warn!(
                        ?err,
                        current_block_number,
                        "failed to add ethereum live block"
                    );
                    return;
                }

                current_block_number = current_block_number.saturating_add(1);
            }
        }
    }

    /// Process the block and emit relevant ChainEvents from the block.
    async fn process_block(&self, block: &Block) -> anyhow::Result<()> {
        // Emit telemetry for the indexed block number
        self.telemetry.block_indexed(block.header.number);
        let processed = self.parse_block(block).await?;
        self.emit_processed_block(processed).await?;

        Ok(())
    }

    async fn parse_block(&self, block: &Block) -> anyhow::Result<BlockAndRequests> {
        let block_number = block.header.number;
        let block_hash = block.header.hash;

        tracing::info!(
            "Processing block number {} with hash {:?}",
            block_number,
            block_hash
        );
        let block_receipts = self
            .client
            .get_block_receipts(block_number.into())
            .await
            .with_context(|| {
                format!("failed to get block receipts for block number {block_number}")
            })?;

        // Some clients return `None` for blocks with no transactions. We still want to
        // emit a `ChainEvent::Block` for checkpointing and progress tracking, so treat
        // it as an empty receipts list.
        let block_receipts = match block_receipts {
            Some(receipts) => receipts,
            None => {
                tracing::debug!(block_number, "no receipts for block; treating as empty");
                Vec::new()
            }
        };

        let mut sign_requests = Vec::new();

        let relevant_logs: Vec<Log> = block_receipts
            .iter()
            .filter_map(|receipt| receipt.as_ref().as_receipt())
            .flat_map(|receipt| {
                receipt
                    .logs
                    .iter()
                    .filter(|log| log.address() == self.contract_address)
                    .cloned()
            })
            .collect();

        let (respond_logs, rest): (Vec<Log>, Vec<Log>) =
            relevant_logs.into_iter().partition(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::SignatureResponded::SIGNATURE_HASH
                })
            });

        let (respond_bidirectional_logs, rest): (Vec<Log>, Vec<Log>) =
            rest.into_iter().partition(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::RespondBidirectional::SIGNATURE_HASH
                })
            });

        let (bidirectional_request_logs, potential_request_logs): (Vec<Log>, Vec<Log>) =
            rest.into_iter().partition(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::SignBidirectional::SIGNATURE_HASH
                })
            });

        let request_logs: Vec<Log> = potential_request_logs
            .into_iter()
            .filter(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::SignatureRequested::SIGNATURE_HASH
                })
            })
            .collect();

        if !request_logs.is_empty() {
            sign_requests.extend(parse_filtered_logs(request_logs));
        }

        if !bidirectional_request_logs.is_empty() {
            sign_requests.extend(parse_bidirectional_filtered_logs(
                bidirectional_request_logs,
            ));
        }

        // Collect execution confirmations (if any) and emit ExecutionConfirmed events
        let exec_events = self
            .collect_execution_confirmations(block_number, block_receipts)
            .await?;

        // Always forward the processed block to the "finalization" stage so it can emit
        // `ChainEvent::Block` even when there are no relevant contract logs.
        Ok(BlockAndRequests::new(
            block_number,
            block_hash,
            sign_requests,
            respond_logs,
            respond_bidirectional_logs,
            exec_events,
        ))
    }

    /// Extract the output of a successful transaction, either from the trace or from the receipt.
    async fn extract_success_tx_output(
        &self,
        tx_id: alloy::primitives::B256,
        tx: &BidirectionalTx,
    ) -> anyhow::Result<Vec<u8>> {
        let Some(tx_info) = self.client.get_transaction_by_hash(tx_id).await? else {
            anyhow::bail!("Failed to fetch transaction {tx_id:?}");
        };

        if tx_info.inner.to().is_none() {
            anyhow::bail!("unsupported contract deployment (CREATE): {tx_id:?}");
        }

        let data = tx_info.inner.input().clone();
        let is_contract_call = is_contract_call(&data);

        let trace_output = if is_contract_call {
            tracing::info!(
                ?tx_id,
                "Extracting transaction output via debug_traceTransaction"
            );
            Some(self.client.trace_transaction_output(tx_id).await?)
        } else {
            None
        };

        crate::respond_bidirectional::build_serialized_output(
            is_contract_call,
            &tx.output_deserialization_schema,
            trace_output.as_ref(),
            tx.source_chain.respond_serialization_format(),
            &tx.respond_serialization_schema,
        )
    }

    /// Construct a `ChainEvent::ExecutionConfirmed` for a mined transaction, if possible.
    async fn execution_confirmed_event(
        &self,
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &BidirectionalTx,
        block_number: u64,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Option<ChainEvent> {
        let receipt_succeeded = receipt.status();

        tracing::info!(
            ?tx_id,
            ?sign_id,
            block_number,
            "bidirectional execution observed via rpc"
        );

        let result = if receipt_succeeded {
            match self
                .extract_success_tx_output(tx_id.0.into(), pending_tx)
                .await
            {
                Ok(serialized_output) => {
                    tracing::info!(
                        ?tx_id,
                        ?sign_id,
                        "extracted transaction output for bidirectional tx"
                    );
                    ExecutionOutcome::Success {
                        output: serialized_output,
                    }
                }
                Err(err) => {
                    tracing::error!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "Failed to extract transaction output"
                    );
                    return None;
                }
            }
        } else {
            ExecutionOutcome::Failed
        };

        Some(ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            source_chain: pending_tx.source_chain,
            block_height: block_number,
            result,
        })
    }

    async fn backfill_execution_confirmation(
        &self,
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &BidirectionalTx,
        current_block_number: u64,
    ) -> anyhow::Result<BackfillOutcome> {
        let Some(tx) = self.client.get_transaction_by_hash(tx_id.0.into()).await? else {
            return Ok(BackfillOutcome::NotObserved);
        };

        let Some(mined_block_number) = tx.block_number else {
            return Ok(BackfillOutcome::NotObserved);
        };

        if mined_block_number > current_block_number {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                current_block_number,
                "skipping late watcher backfill for future ethereum block"
            );

            return Ok(BackfillOutcome::NotObserved);
        }

        let Some(block_receipts) = self
            .client
            .get_block_receipts(mined_block_number.into())
            .await?
        else {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                "late watcher backfill found mined transaction without block receipts"
            );
            return Ok(BackfillOutcome::NotObserved);
        };

        let Some(receipt) = block_receipts
            .into_iter()
            .find(|receipt| receipt.transaction_hash == tx_id.0)
        else {
            tracing::warn!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                "late watcher backfill could not find transaction receipt in mined block"
            );
            return Ok(BackfillOutcome::NotObserved);
        };

        tracing::info!(
            ?tx_id,
            ?sign_id,
            mined_block_number,
            current_block_number,
            "backfilled execution confirmation for late ethereum watcher"
        );

        let event = self
            .execution_confirmed_event(tx_id, sign_id, pending_tx, mined_block_number, &receipt)
            .await;
        Ok(BackfillOutcome::Observed { event })
    }

    async fn collect_execution_confirmations(
        &self,
        block_number: u64,
        block_receipts: Vec<alloy::rpc::types::TransactionReceipt>,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        let block_receipts: HashMap<
            alloy::primitives::B256,
            alloy::rpc::types::TransactionReceipt,
        > = block_receipts
            .into_iter()
            .map(|receipt| (receipt.transaction_hash, receipt.clone()))
            .collect::<HashMap<_, _>>();

        let mut events = Vec::new();
        let mut resolved_tx_ids = HashSet::new();

        let watchers = self
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;
        tracing::info!(
            watchers_count = watchers.len(),
            block_number,
            "collect_execution_confirmations checking watchers"
        );

        // Watchers whose receipt we saw this call, even if no event was
        // emitted. The staleness check below skips these so a mined tx with
        // a failed extraction stays pending for retry, not flagged Failed.
        let mut observed_tx_ids = HashSet::new();

        for (tx_id, (sign_id, pending_tx)) in watchers {
            tracing::info!(?tx_id, ?sign_id, "querying receipt for bidirectional tx");
            if let Some(receipt) = block_receipts.get(&pending_tx.id.0) {
                observed_tx_ids.insert(tx_id);
                if let Some(event) = self
                    .execution_confirmed_event(tx_id, sign_id, &pending_tx, block_number, receipt)
                    .await
                {
                    events.push(event);
                    resolved_tx_ids.insert(tx_id);
                }
                // `None` means extraction failed — leave pending for retry.
                // `observed_tx_ids` above exempts it from the staleness check.
                continue;
            }

            match self
                .backfill_execution_confirmation(tx_id, sign_id, &pending_tx, block_number)
                .await?
            {
                BackfillOutcome::Observed { event } => {
                    observed_tx_ids.insert(tx_id);
                    if let Some(event) = event {
                        events.push(event);
                        resolved_tx_ids.insert(tx_id);
                    }
                }
                BackfillOutcome::NotObserved => {}
            }
        }

        // Staleness checks (nonce too low)
        let remaining_pending = self
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;

        for (tx_id, (sign_id, tx)) in remaining_pending {
            if resolved_tx_ids.contains(&tx_id) || observed_tx_ids.contains(&tx_id) {
                continue;
            }

            let current_nonce = match self
                .client
                .as_ref()
                .get_nonce(
                    tx.from_address.into(),
                    BlockId::Number(BlockNumberOrTag::Number(block_number)),
                )
                .await
            {
                Ok(nonce) => nonce,
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "Failed to fetch nonce for bidirectional tx"
                    );
                    continue;
                }
            };

            if tx.nonce < current_nonce {
                tracing::warn!(
                    ?sign_id,
                    "Nonce too low for tx {:?}: expected {}, got {}",
                    tx_id,
                    tx.nonce,
                    current_nonce
                );
                events.push(ChainEvent::ExecutionConfirmed {
                    tx_id,
                    sign_id,
                    source_chain: tx.source_chain,
                    block_height: block_number,
                    result: ExecutionOutcome::Failed,
                });
            }
        }

        Ok(events)
    }

    /// Emits the processed block in-order once we reach finality for it.
    async fn emit_processed_block(
        &self,
        BlockAndRequests {
            block_number,
            block_hash,
            indexed_requests,
            respond_logs,
            respond_bidirectional_logs,
            execution_events,
        }: BlockAndRequests,
    ) -> anyhow::Result<()> {
        if !self.eth.optimistic_requests {
            self.wait_for_finalized_block(block_number).await?;
        }

        let Some(block) = self
            .client
            .as_ref()
            .get_block(BlockId::Number(BlockNumberOrTag::Number(block_number)))
            .await
        else {
            anyhow::bail!("ethereum block {block_number} not found during emission");
        };

        if block.header.hash != block_hash {
            // The block was reorged after `process_block` produced this payload.
            // Do not emit stale events for a different canonical block, but also do
            // not return an error that would cause the catchup path to retry this
            // same stale payload forever.
            return Ok(());
        }

        for event in execution_events {
            self.events_tx
                .send(event)
                .await
                .context("failed to emit ExecutionConfirmed event")?;
        }

        for request in indexed_requests {
            self.events_tx
                .send(ChainEvent::SignRequest {
                    request,
                    block_timestamp: Some(block.header.timestamp),
                })
                .await
                .context("failed to emit SignRequest event")?;
        }

        if !respond_logs.is_empty() {
            emit_respond_events(&respond_logs, self.events_tx.clone()).await;
        }

        if !respond_bidirectional_logs.is_empty() {
            emit_respond_bidirectional_events(&respond_bidirectional_logs, self.events_tx.clone())
                .await;
        }

        self.events_tx
            .send(ChainEvent::Block(block_number))
            .await
            .context("failed to emit block event")?;

        Ok(())
    }

    async fn wait_for_finalized_block(&self, block_number: BlockNumber) -> anyhow::Result<()> {
        let retry_interval = Duration::from_millis(self.eth.refresh_finalized_interval);
        let mut last_final_block_number: Option<BlockNumber> = None;

        loop {
            let Some(finalized_block) = self
                .client
                .as_ref()
                .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
                .await
            else {
                tracing::warn!(block_number, "finalized ethereum block not found; retrying");
                tokio::time::sleep(retry_interval).await;
                continue;
            };

            let new_final_block_number = finalized_block.header.number;
            let prev_final_block_number = last_final_block_number.replace(new_final_block_number);

            if prev_final_block_number.is_none_or(|n| new_final_block_number > n) {
                tracing::debug!(
                    new_final_block_number,
                    prev_final_block_number,
                    "New finalized block number"
                );
            }

            if let Some(prev_final_block_number) = prev_final_block_number {
                if new_final_block_number < prev_final_block_number {
                    tracing::warn!(
                        new_final_block_number,
                        prev_final_block_number,
                        "new finalized block number overflowed range of u64 and has wrapped around!"
                    );
                }

                if new_final_block_number == prev_final_block_number {
                    tracing::debug!(new_final_block_number, "no new finalized block");
                }
            }

            // If the finalized block number has advanced past the block we're waiting for,
            // we can proceed with emitting it.
            if new_final_block_number >= block_number {
                return Ok(());
            };

            tokio::time::sleep(retry_interval).await;
        }
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for EthereumIndexer<S, T> {
    const CHAIN: Chain = Chain::Ethereum;
    type Block = MaybeBlock;
    type Iter = std::pin::Pin<Box<dyn stream::Stream<Item = Self::Block> + Send + 'static>>;

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        let start_block_number = loop {
            if let Some(block_number) = self.client.get_latest_block_number().await {
                break block_number.saturating_add(1);
            };
            tokio::time::sleep(Self::RETRY_DELAY).await;
        };

        let (live_blocks_tx, live_blocks_rx) = live_blocks_channel();
        tokio::spawn(Self::index_live_blocks(
            self.client.clone(),
            self.catchup_complete.clone(),
            start_block_number,
            live_blocks_tx,
        ));

        self.live_blocks_rx = Some(live_blocks_rx);
        Ok(Some(start_block_number))
    }

    async fn next(&mut self) -> Option<Self::Block> {
        let rx = self.live_blocks_rx.as_mut()?;
        rx.recv().await
    }

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter {
        // TODO: start from genesis block of contract deployment instead of
        // anchor_height so that we can start from the very beginning of
        // the history of the network in case where we do not have a checkpoint.
        // https://github.com/sig-net/mpc/issues/777
        let current_block = self
            .state_manager
            .get_processed_block(Chain::Ethereum)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(anchor_height);
        let catchup_start = self
            .client
            .clamp_oldest_supported(current_block, anchor_height);

        let catchup_iter = CatchupIter::new(self.client.clone(), catchup_start, anchor_height);

        // Convert the async state machine into a Stream
        let stream = stream::unfold(catchup_iter, |mut state| async move {
            let item = state.next().await;
            item.map(|block| (block, state))
        });

        Box::pin(stream)
    }

    async fn process_catchup(&mut self, block: &Self::Block) -> anyhow::Result<()> {
        // NOTE: oh rust: needed otherwise the block gets dropped before we can use
        // it, since it `block` is of reference type. Maybe the language will let
        // us elide this in the future, but for now we need to introduce a new var.
        let _block;

        let block = match block {
            MaybeBlock::Block(block) => block,
            MaybeBlock::Missing(block_id) => {
                tracing::warn!(
                    ?block_id,
                    "ethereum catchup block missing from batch; refetching"
                );
                let Some(block) = self.client.get_block(*block_id).await else {
                    anyhow::bail!(
                        "ethereum catchup block {block_id:?} is still unavailable after refetch"
                    )
                };
                _block = block;
                &_block
            }
        };

        let height = block.header.number;
        if height.is_multiple_of(10) {
            tracing::info!(height, "processed ethereum catchup block attempt");
        }

        self.process_block(block).await
    }

    async fn process(&mut self, block: &Self::Block) -> anyhow::Result<()> {
        let MaybeBlock::Block(block) = block else {
            anyhow::bail!("ethereum live stream yielded missing block")
        };

        self.process_block(block).await?;
        Ok(())
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        self.events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send catchup completed event")?;
        self.catchup_complete.notify_one();
        Ok(())
    }
}

/// Ethereum indexer stream implementing the `ChainStream` trait.
/// Construction is side-effect free; the shared `run_stream()` loop calls
/// `start()` after recovery has completed.
pub struct EthereumStream<S: StateManager, T: ChainTelemetry> {
    events_rx: Option<mpsc::Receiver<ChainEvent>>,
    start_state: Option<EthereumIndexer<S, T>>,
}

impl<S: StateManager, T: ChainTelemetry> EthereumStream<S, T> {
    pub async fn new(eth: EthConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        tracing::info!(eth_config = ?eth, "creating ethereum indexer stream");
        let (events_tx, events_rx) = chain_event_channel();
        let indexer = EthereumIndexer::new(eth, state_manager, telemetry, events_tx).await?;
        Ok(Self {
            events_rx: Some(events_rx),
            start_state: Some(indexer),
        })
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainStream for EthereumStream<S, T> {
    type Indexer = EthereumIndexer<S, T>;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
        self.start_state
            .take()
            .context("ethereum stream already started")
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        match self.events_rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{test_utils, CatchupIter, EthConfig, EthereumClient, EthereumIndexer, MaybeBlock};
    // TODO: test should rely on StateManager mock instead of Backlog
    use crate::backlog::Backlog;
    #[cfg(feature = "helios")]
    use crate::indexer_eth::indexer_eth_helios;
    use alloy::eips::BlockNumberOrTag;
    use alloy::primitives::{address, b256, hex, Address};
    use alloy::rpc::types::BlockId;
    use mockito::{Matcher, Server};
    use mpc_chain_integration_core::{ChainIndexer, NoopChainTelemetry};
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, SignId,
        LATEST_MPC_KEY_VERSION,
    };
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Notify};

    fn missing_block_response(request_id: u64) -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": null
        })
    }

    #[test]
    fn catchup_start_is_clamped_to_supported_window() {
        let max_catchup_blocks = 8191;
        let anchor_height = 10_000;
        let catchup_end = anchor_height - 1;
        let expected_oldest = catchup_end - max_catchup_blocks;

        assert_eq!(
            EthereumClient::clamp_oldest_supported_with(1, anchor_height, max_catchup_blocks),
            expected_oldest,
        );
    }

    #[tokio::test]
    async fn missing_catchup_block_is_refetched() {
        let mut server = Server::new_async().await;
        let state_manager = Backlog::new();
        let (events_tx, mut events_rx) = mpsc::channel(1);

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["0xc", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, 12).to_string())
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockReceipts",
                "params": ["0xc"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(missing_block_response(2).to_string())
            .create_async()
            .await;

        let mut indexer = EthereumIndexer {
            eth: EthConfig {
                account_sk: String::new(),
                consensus_rpc_http_url: server.url(),
                execution_rpc_http_url: server.url(),
                contract_address: format!("{:x}", Address::ZERO),
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios-test".to_string(),
                refresh_finalized_interval: 100,
                optimistic_requests: true,
                light_client: false,
            },
            state_manager,
            telemetry: NoopChainTelemetry,
            client: Arc::new(test_utils::create_test_ethereum_client(&server.url()).await),
            events_tx,
            contract_address: Address::ZERO,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        };

        indexer
            .process_catchup(&MaybeBlock::Missing(BlockId::Number(
                BlockNumberOrTag::Number(12),
            )))
            .await
            .expect("missing catchup block should be refetched successfully");

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(12))
        ));
    }

    #[tokio::test]
    async fn missing_catchup_block_returns_error_when_refetch_fails() {
        let state_manager = Backlog::new();
        let (events_tx, mut events_rx) = mpsc::channel(1);
        let mut indexer = EthereumIndexer {
            eth: EthConfig {
                account_sk: String::new(),
                consensus_rpc_http_url: String::new(),
                execution_rpc_http_url: String::new(),
                contract_address: format!("{:x}", Address::ZERO),
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios-test".to_string(),
                refresh_finalized_interval: 100,
                optimistic_requests: true,
                light_client: false,
            },
            state_manager,
            telemetry: NoopChainTelemetry,
            client: Arc::new(test_utils::create_test_ethereum_client("http://127.0.0.1:1").await),
            events_tx,
            contract_address: Address::ZERO,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        };

        let err = indexer
            .process_catchup(&MaybeBlock::Missing(BlockId::Number(
                BlockNumberOrTag::Number(12),
            )))
            .await
            .expect_err("missing catchup block should fail when refetch cannot recover it");

        assert!(events_rx.try_recv().is_err());
        assert!(err.to_string().contains("still unavailable after refetch"));
    }

    #[tokio::test]
    async fn ethereum_client_get_blocks_preserves_request_order() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    test_utils::block_response(3, 9),
                    test_utils::block_response(1, 7),
                    missing_block_response(2),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(7)),
            BlockId::Number(BlockNumberOrTag::Number(8)),
            BlockId::Number(BlockNumberOrTag::Number(9)),
        ];

        let blocks = client.get_blocks(&block_ids).await;

        assert_eq!(blocks.len(), 3);
        assert!(matches!(&blocks[0], MaybeBlock::Block(block) if block.header.number == 7));
        assert!(matches!(
            &blocks[1],
            MaybeBlock::Missing(BlockId::Number(BlockNumberOrTag::Number(8)))
        ));
        assert!(matches!(&blocks[2], MaybeBlock::Block(block) if block.header.number == 9));
    }

    #[tokio::test]
    async fn ethereum_client_get_blocks_retries_and_keeps_positions() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "result": "invalid-shape" }).to_string())
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    test_utils::block_response(4, 20),
                    missing_block_response(5),
                    test_utils::block_response(6, 22),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(20)),
            BlockId::Number(BlockNumberOrTag::Number(21)),
            BlockId::Number(BlockNumberOrTag::Number(22)),
        ];

        let blocks = client.get_blocks(&block_ids).await;

        assert_eq!(blocks.len(), 3);
        assert!(matches!(&blocks[0], MaybeBlock::Block(block) if block.header.number == 20));
        assert!(matches!(
            &blocks[1],
            MaybeBlock::Missing(BlockId::Number(BlockNumberOrTag::Number(21)))
        ));
        assert!(matches!(&blocks[2], MaybeBlock::Block(block) if block.header.number == 22));
    }

    #[tokio::test]
    async fn catchup_iter_fetches_batches_lazily() {
        let mut server = Server::new_async().await;

        let first_batch = (10..42)
            .enumerate()
            .map(|(index, block_number)| test_utils::block_response(index as u64 + 1, block_number))
            .collect::<Vec<_>>();
        let second_batch = vec![test_utils::block_response(33, 42)];

        let second_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"0x2a\""#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(second_batch).to_string())
            .create_async()
            .await;

        let first_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"0xa\""#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(first_batch).to_string())
            .create_async()
            .await;

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 10, 43);

        for expected_number in 10..42 {
            let next = iter.next().await;
            assert!(matches!(
                next,
                Some(MaybeBlock::Block(block)) if block.header.number == expected_number
            ));
        }

        assert!(first_batch_mock.matched_async().await);
        assert!(!second_batch_mock.matched_async().await);

        let next = iter.next().await;
        assert!(matches!(next, Some(MaybeBlock::Block(block)) if block.header.number == 42));
        assert!(second_batch_mock.matched_async().await);
        assert!(iter.next().await.is_none());
    }

    #[tokio::test]
    async fn catchup_iter_splits_requests_into_32_32_1_batches() {
        let mut server = Server::new_async().await;

        let first_batch = (0..32)
            .enumerate()
            .map(|(idx, block_number)| test_utils::block_response(idx as u64 + 1, block_number))
            .collect::<Vec<_>>();
        let second_batch = (32..64)
            .enumerate()
            .map(|(idx, block_number)| test_utils::block_response((idx + 33) as u64, block_number))
            .collect::<Vec<_>>();
        let third_batch = vec![test_utils::block_response(65, 64)];

        let first_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"id\":32"#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(first_batch).to_string())
            .create_async()
            .await;

        let second_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"id\":64"#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(second_batch).to_string())
            .create_async()
            .await;

        let third_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"id\":65"#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(third_batch).to_string())
            .create_async()
            .await;

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 0, 65);

        for expected_number in 0..65 {
            let next = iter.next().await;
            assert!(matches!(
                next,
                Some(MaybeBlock::Block(block)) if block.header.number == expected_number
            ));
        }

        assert!(iter.next().await.is_none());
        assert!(first_batch_mock.matched_async().await);
        assert!(second_batch_mock.matched_async().await);
        assert!(third_batch_mock.matched_async().await);
    }

    #[tokio::test]
    async fn late_watcher_backfill_uses_tx_hash_and_mined_block() {
        let mut server = Server::new_async().await;

        let tx_hash = b256!("018b2331d461a4aeedf6a1f9cc37463377578244e6a35216057a8370714e798f");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let to_address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");

        let tx_response = json!({
            "hash": format!("{tx_hash:#x}"),
            "nonce": "0x1",
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x2",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{to_address:#x}"),
            "value": "0x0",
            "gasPrice": "0x3a29f0f8",
            "gas": "0x5208",
            "maxFeePerGas": "0xba43b7400",
            "maxPriorityFeePerGas": "0x5f5e100",
            "input": "0x",
            "r": "0xd309309a59a49021281cb6bb41d164c96eab4e50f0c1bd24c03ca336e7bc2bb7",
            "s": "0x28a7f089143d0a1355ebeb2a1b9f0e5ad9eca4303021c1400d61bc23c9ac5319",
            "v": "0x0",
            "yParity": "0x0",
            "chainId": "0x7a69",
            "accessList": [],
            "type": "0x2"
        });

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x2",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{to_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionByHash",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": tx_response,
                })
                .to_string(),
            )
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockReceipts",
                "params": ["0x2"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": [receipt_response],
                })
                .to_string(),
            )
            .create_async()
            .await;

        let state_manager = Backlog::new();
        let sign_id = SignId::new([0x55; 32]);
        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: sign_id.request_id,
            from_address: **from_address,
            nonce: 0,
        };
        state_manager
            .watch_execution(Chain::Ethereum, sign_id, tx)
            .await;

        let (events_tx, _events_rx) = mpsc::channel(1);
        let indexer = EthereumIndexer {
            eth: EthConfig {
                account_sk: String::new(),
                consensus_rpc_http_url: server.url(),
                execution_rpc_http_url: server.url(),
                contract_address: format!("{:x}", Address::ZERO),
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios-test".to_string(),
                refresh_finalized_interval: 100,
                optimistic_requests: true,
                light_client: false,
            },
            state_manager,
            telemetry: NoopChainTelemetry,
            client: Arc::new(test_utils::create_test_ethereum_client(&server.url()).await),
            events_tx,
            contract_address: Address::ZERO,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        };

        let events = indexer
            .collect_execution_confirmations(5, Vec::new())
            .await
            .expect("late watcher backfill should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id: event_tx_id,
                sign_id: event_sign_id,
                source_chain,
                block_height,
                result,
            } => {
                assert_eq!(*event_tx_id, BidirectionalTxId(tx_hash.0));
                assert_eq!(*event_sign_id, sign_id);
                assert_eq!(*source_chain, Chain::Solana);
                assert_eq!(*block_height, 2);
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }
    }

    #[test]
    fn is_contract_call_detects_calldata() {
        use super::is_contract_call;
        use alloy::primitives::Bytes;
        assert!(!is_contract_call(&Bytes::new()));
        assert!(!is_contract_call(&Bytes::from(vec![0u8; 2])));
        assert!(is_contract_call(&Bytes::from(vec![
            0xa9, 0x05, 0x9c, 0xbb, 0x00
        ])));
    }

    fn golden_sign_bidirectional_event() -> super::abi::ChainSignatures::SignBidirectional {
        use alloy::primitives::{bytes, U256};
        super::abi::ChainSignatures::SignBidirectional {
            sender: address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            serializedTransaction: bytes!("02deadbeef01"),
            caip2Id: "eip155:1".to_string(),
            keyVersion: 1,
            deposit: U256::from(1u64),
            chainId: U256::from(31337u64),
            path: "test-bidirectional-path".to_string(),
            algo: "secp256k1".to_string(),
            dest: "ethereum".to_string(),
            params: "{}".to_string(),
            outputDeserializationSchema: alloy::primitives::Bytes::from_static(
                br#"[{"name":"output","type":"bool"}]"#,
            ),
            respondSerializationSchema: alloy::primitives::Bytes::from_static(
                br#"[{"name":"output","type":"bool"}]"#,
            ),
        }
    }

    #[test]
    fn bidirectional_request_id_matches_signet_evm_program_golden() {
        // Golden from signet-evm-program's generateBidirectionalRequestId (viem).
        let event = golden_sign_bidirectional_event();
        assert_eq!(
            super::generate_bidirectional_request_id(&event),
            b256!("10782cf96bc2f933dbd8a5fda49d31bf5a6b50027eba1aa9a115650cc261d498").0,
        );
    }

    fn rpc_log_from_sign_bidirectional(
        event: &super::abi::ChainSignatures::SignBidirectional,
        tx_hash: alloy::primitives::B256,
    ) -> alloy::rpc::types::Log {
        use alloy::sol_types::SolEvent as _;
        alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: Address::ZERO,
                data: event.encode_log_data(),
            },
            transaction_hash: Some(tx_hash),
            ..Default::default()
        }
    }

    #[test]
    fn decodes_sign_bidirectional_log_into_indexed_request() {
        let event = golden_sign_bidirectional_event();
        let tx_hash = b256!("00000000000000000000000000000000000000000000000000000000000000aa");
        let log = rpc_log_from_sign_bidirectional(&event, tx_hash);

        let request = super::sign_bidirectional_request_from_filtered_log(log)
            .expect("valid SignBidirectional log must decode");

        // Request id golden from signet-evm-program (viem encodePacked).
        assert_eq!(
            request.id.request_id,
            b256!("10782cf96bc2f933dbd8a5fda49d31bf5a6b50027eba1aa9a115650cc261d498").0
        );
        assert_eq!(request.chain, Chain::Ethereum);
        assert_eq!(request.args.path, "test-bidirectional-path");
        assert_eq!(request.args.key_version, 1);
        assert_eq!(request.args.entropy, tx_hash.0);

        // Payload golden: keccak256(0x02deadbeef01).
        let expected_payload =
            b256!("851f5c635201a456296e1f11b98bff2542d846afae32795cb4c64c6891d2980c");
        assert_eq!(
            request.args.payload.to_bytes().as_slice(),
            expected_payload.as_slice()
        );

        let expected_epsilon = mpc_crypto::kdf::derive_epsilon_eth(
            1,
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "test-bidirectional-path",
        );
        assert_eq!(request.args.epsilon, expected_epsilon);

        let mpc_primitives::SignKind::SignBidirectional(inner) = request.kind else {
            panic!("expected SignBidirectional kind");
        };
        assert_eq!(inner.chain, Chain::Ethereum);
        assert_eq!(inner.chain_ctx, None);
        assert_eq!(inner.sender[..12], [0u8; 12]);
        assert_eq!(
            inner.sender[12..],
            address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").into_array()
        );
        assert_eq!(
            inner.serialized_transaction,
            hex::decode("02deadbeef01").unwrap()
        );
        assert_eq!(inner.caip2_id, "eip155:1");
        assert_eq!(inner.deposit, 1);
        assert_eq!(
            inner.respond_serialization_schema,
            br#"[{"name":"output","type":"bool"}]"#.to_vec()
        );
    }

    #[test]
    fn skips_sign_bidirectional_with_zero_deposit() {
        let mut event = golden_sign_bidirectional_event();
        event.deposit = alloy::primitives::U256::ZERO;
        let log = rpc_log_from_sign_bidirectional(&event, alloy::primitives::B256::ZERO);
        assert!(super::sign_bidirectional_request_from_filtered_log(log).is_none());
    }

    #[test]
    fn skips_sign_bidirectional_with_unsupported_key_version() {
        let mut event = golden_sign_bidirectional_event();
        event.keyVersion = LATEST_MPC_KEY_VERSION + 1;
        let log = rpc_log_from_sign_bidirectional(&event, alloy::primitives::B256::ZERO);
        assert!(super::sign_bidirectional_request_from_filtered_log(log).is_none());
    }

    #[test]
    fn skips_sign_bidirectional_with_invalid_caip2() {
        let mut event = golden_sign_bidirectional_event();
        event.caip2Id = "not-a-chain".to_string();
        let log = rpc_log_from_sign_bidirectional(&event, alloy::primitives::B256::ZERO);
        assert!(super::sign_bidirectional_request_from_filtered_log(log).is_none());
    }

    #[test]
    fn decodes_respond_bidirectional_log_into_event() {
        use alloy::primitives::hex as alloy_hex;
        use k256::elliptic_curve::point::AffineCoordinates as _;

        let topics = vec![
            b256!("23a9a92895272f15b4a10136e9902bae33c369c40c448b2d184f9a06e33fc3df"),
            b256!("10782cf96bc2f933dbd8a5fda49d31bf5a6b50027eba1aa9a115650cc261d498"),
        ];
        let data = alloy_hex::decode(
            "000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226\
             600000000000000000000000000000000000000000000000000000000000000c0\
             79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8\
             000000000000000000000000000000000000000000000000000000000000002a\
             0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000020\
             0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let log = alloy::rpc::types::Log {
            inner: alloy::primitives::Log::new(Address::ZERO, topics, data.into())
                .expect("valid log"),
            ..Default::default()
        };

        let event = super::respond_bidirectional_event_from_log(&log)
            .expect("valid RespondBidirectional log must decode");

        assert_eq!(
            event.request_id,
            b256!("10782cf96bc2f933dbd8a5fda49d31bf5a6b50027eba1aa9a115650cc261d498").0
        );
        assert_eq!(event.chain, Chain::Ethereum);
        assert_eq!(event.signature.big_r, k256::AffinePoint::GENERATOR);
        assert_eq!(event.signature.s, k256::Scalar::from(42u64));
        assert_eq!(event.signature.recovery_id, 1);
        // sanity: generator x-coordinate round-trips
        assert_eq!(
            event.signature.big_r.x().as_slice(),
            alloy_hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .as_slice()
        );
    }
}
