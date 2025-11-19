use crate::backlog::Backlog;
use crate::indexer_eth::parse_filtered_logs;
use crate::indexer_eth::process_respond_events;
use crate::indexer_eth::recover_backlog;
use crate::indexer_eth::send_indexed_requests;
use crate::indexer_eth::EthConfig;
use crate::indexer_eth::EthereumClientTrait;
use crate::indexer_eth::SignatureRequested;
use crate::indexer_eth::SignatureResponded;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest};
use crate::respond_bidirectional::{
    CompletedTx, RespondBidirectionalSerializedOutput, SerDeserFormat,
    OUTPUT_DESERIALIZATION_FORMAT, RESPOND_SERIALIZATION_FORMAT,
};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::BidirectionalTx;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::sign_bidirectional::PendingRequestStatus;
use crate::sign_bidirectional::TransactionOutput;
use crate::storage::app_data_storage::AppDataStorage;
use alloy::consensus::BlockHeader;
use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::Log;
use alloy::rpc::types::Transaction;
use alloy::rpc::types::TransactionReceipt;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::time::{sleep, Duration};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    eth: EthConfig,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    backlog: Backlog,
    contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    recover_backlog(&backlog, contract_watcher, mesh_state, node_client).await;

    let client = RpcEthereumClient::new(&eth.execution_rpc_http_url);

    let contract_address = match Address::from_str(&format!("0x{}", eth.contract_address)) {
        Ok(addr) => addr,
        Err(err) => {
            tracing::error!("Failed to parse contract address: {}", err);
            return;
        }
    };

    let total_timeout = Duration::from_secs(eth.total_timeout);

    let mut last_processed_block = app_data_storage
        .last_processed_block_eth()
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("Failed to get last processed block: {err:?}");
            None
        });

    if last_processed_block.is_none() {
        match client.block_number().await {
            Ok(latest) => {
                last_processed_block = Some(latest.saturating_sub(1));
            }
            Err(err) => {
                tracing::warn!("Failed to fetch latest block number: {err:?}");
                last_processed_block = Some(0);
            }
        }
    }

    let mut current_block = last_processed_block.unwrap_or(0);
    tracing::info!("ethereum rpc indexer starting at block {}", current_block);

    loop {
        let latest_block = match client.block_number().await {
            Ok(num) => num,
            Err(err) => {
                tracing::warn!("Failed to fetch latest block number: {err:?}");
                sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        if latest_block <= current_block {
            sleep(Duration::from_millis(500)).await;
            continue;
        }

        for block_number in (current_block + 1)..=latest_block {
            match process_block(
                &client,
                block_number,
                contract_address,
                node_near_account_id.clone(),
                sign_tx.clone(),
                total_timeout,
                &backlog,
            )
            .await
            {
                Ok(_) => {
                    crate::metrics::LATEST_BLOCK_NUMBER
                        .with_label_values(&[
                            Chain::Ethereum.as_str(),
                            node_near_account_id.as_str(),
                        ])
                        .set(block_number as i64);
                    if let Err(err) = app_data_storage
                        .set_last_processed_block_eth(block_number)
                        .await
                    {
                        tracing::warn!("Failed to set last processed block: {err:?}");
                    }
                    current_block = block_number;
                }
                Err(err) => {
                    tracing::warn!("Failed to process block {block_number}: {err:?}");
                    sleep(Duration::from_secs(1)).await;
                    break;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_block(
    client: &RpcEthereumClient,
    block_number: u64,
    contract_address: Address,
    node_near_account_id: AccountId,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    total_timeout: Duration,
    backlog: &Backlog,
) -> anyhow::Result<()> {
    tracing::info!("Processing block number {}", block_number);

    let block = match client.block_by_number(block_number).await? {
        Some(block) => block,
        None => {
            tracing::warn!("Block {block_number} not found via rpc, skipping");
            return Ok(());
        }
    };

    let block_hash = block.header.hash;
    let block_timestamp = block.header.timestamp();

    let mut sign_requests = Vec::new();

    let logs = client.get_logs(block_hash, contract_address).await?;
    let (respond_logs, potential_request_logs): (Vec<Log>, Vec<Log>) =
        logs.into_iter().partition(|log| {
            log.topic0()
                .is_some_and(|topic| *topic == SignatureResponded::SIGNATURE_HASH)
        });

    if !respond_logs.is_empty() {
        process_respond_events(&respond_logs, backlog).await;
    }

    let request_logs: Vec<Log> = potential_request_logs
        .into_iter()
        .filter(|log| {
            log.topic0()
                .is_some_and(|topic| *topic == SignatureRequested::SIGNATURE_HASH)
        })
        .collect();

    if !request_logs.is_empty() {
        sign_requests.extend(parse_filtered_logs(request_logs, total_timeout));
    }

    let respond_requests = process_bidirectional_requests(
        client,
        block_number,
        total_timeout,
        backlog,
        &node_near_account_id,
    )
    .await?;
    sign_requests.extend(respond_requests);

    if !sign_requests.is_empty() {
        let timestamps = sign_requests
            .iter()
            .map(|r| r.unix_timestamp_indexed)
            .collect::<Vec<_>>();

        send_indexed_requests(sign_requests, sign_tx.clone(), node_near_account_id.clone());

        for request_timestamp in timestamps {
            crate::metrics::INDEXER_DELAY
                .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
                .observe(
                    crate::util::duration_between_unix(block_timestamp, request_timestamp).as_secs()
                        as f64,
                );
        }
    }

    // Create checkpoint if one was created at this block height
    if let Some(checkpoint) = backlog
        .set_processed_block(Chain::Ethereum, block_number)
        .await
    {
        tracing::info!(block_number, ?checkpoint, "created Ethereum checkpoint");
    }

    Ok(())
}

async fn process_bidirectional_requests(
    client: &RpcEthereumClient,
    block_number: u64,
    total_timeout: Duration,
    backlog: &Backlog,
    node_near_account_id: &AccountId,
) -> anyhow::Result<Vec<IndexedSignRequest>> {
    let mut respond_requests = Vec::new();

    let watchers = backlog.pending_execution(Chain::Ethereum).await;
    tracing::info!(
        watchers_count = watchers.len(),
        block_number,
        "process_bidirectional_requests checking watchers"
    );

    for (tx_id, (sign_id, pending_tx)) in watchers {
        tracing::info!(?tx_id, ?sign_id, "querying receipt for bidirectional tx");
        let start = Instant::now();
        let receipt = client.transaction_receipt(pending_tx.id).await;
        crate::metrics::ETH_BLOCK_RECEIPT_LATENCY
            .with_label_values(&[node_near_account_id.as_str()])
            .observe(start.elapsed().as_millis() as f64);

        let Some(receipt) = receipt? else {
            continue;
        };

        let status = if receipt.status() {
            PendingRequestStatus::Success
        } else {
            PendingRequestStatus::Failed
        };
        tracing::info!(
            ?tx_id,
            ?sign_id,
            block_number,
            "bidirectional execution observed via rpc"
        );

        let mut updated_tx = pending_tx.clone();
        updated_tx.status = status;

        let completed_tx = CompletedTx::new(updated_tx.clone(), block_number);
        let source_chain = updated_tx.source_chain;
        if status == PendingRequestStatus::Success {
            match extract_success_output_with_rpc(client, &updated_tx, block_number).await {
                Ok(serialized_output) => {
                    tracing::info!(
                        ?tx_id,
                        ?sign_id,
                        "extracted transaction output for bidirectional tx"
                    );
                    match completed_tx.create_sign_request_from_serialized_output(
                        source_chain,
                        serialized_output,
                        total_timeout,
                    ) {
                        Ok(sign_request) => respond_requests.push(sign_request),
                        Err(err) => tracing::warn!(
                            ?tx_id,
                            ?sign_id,
                            ?err,
                            "Failed to build bidirectional respond sign request"
                        ),
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "Failed to extract transaction output for bidirectional tx, using empty output"
                    );
                    // If output extraction fails (e.g., empty schema), use empty output
                    match completed_tx.create_sign_request_from_serialized_output(
                        source_chain,
                        vec![], // empty serialized output
                        total_timeout,
                    ) {
                        Ok(sign_request) => respond_requests.push(sign_request),
                        Err(err) => tracing::warn!(
                            ?tx_id,
                            ?sign_id,
                            ?err,
                            "Failed to build bidirectional respond sign request with empty output"
                        ),
                    }
                }
            }
        } else {
            match completed_tx
                .create_failed_sign_request_without_light_client(source_chain, total_timeout)
                .await
            {
                Ok(sign_request) => respond_requests.push(sign_request),
                Err(err) => tracing::warn!(
                    ?tx_id,
                    ?sign_id,
                    ?err,
                    "Failed to build failed bidirectional sign request"
                ),
            }
        }

        backlog
            .set_status(pending_tx.source_chain, &sign_id, status)
            .await;
        backlog.unwatch_execution(Chain::Ethereum, &tx_id).await;
    }

    let remaining_pending = backlog.pending_execution(Chain::Ethereum).await;

    for (tx_id, (sign_id, tx)) in remaining_pending {
        let current_nonce = match client
            .nonce(
                tx.from_address,
                alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(block_number)),
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
            let mut failed_tx = tx.clone();
            failed_tx.status = PendingRequestStatus::Failed;
            let completed_tx = CompletedTx::new(failed_tx.clone(), block_number);
            match completed_tx
                .create_failed_sign_request_without_light_client(tx.source_chain, total_timeout)
                .await
            {
                Ok(sign_request) => respond_requests.push(sign_request),
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "Failed to build sign request for stale nonce"
                    )
                }
            }
            backlog
                .set_status(tx.source_chain, &sign_id, PendingRequestStatus::Failed)
                .await;
            backlog.unwatch_execution(Chain::Ethereum, &tx_id).await;
        }
    }

    Ok(respond_requests)
}

async fn extract_success_output_with_rpc(
    client: &RpcEthereumClient,
    tx: &BidirectionalTx,
    block_number: u64,
) -> anyhow::Result<RespondBidirectionalSerializedOutput> {
    let Some(tx_info) = client.transaction_by_hash(tx.id.0.into()).await? else {
        anyhow::bail!("Failed to fetch transaction {:?} via rpc", tx.id);
    };

    let data = tx_info.inner.input().clone();
    let is_contract_call = data.len() > 2 && data != Bytes::from("0x");
    let output_deserialization_format = OUTPUT_DESERIALIZATION_FORMAT;
    let output_deserialization_schema = &tx.output_deserialization_schema;

    let transaction_output = match output_deserialization_format {
        SerDeserFormat::Abi if is_contract_call => {
            let to_address = tx_info
                .inner
                .to()
                .ok_or_else(|| anyhow::anyhow!("Transaction {:?} missing destination", tx.id))?;
            let call_block = block_number.saturating_sub(1);
            let call_result = client
                .call(tx.from_address, to_address, data.clone(), call_block)
                .await?;
            TransactionOutput::from_call_result(output_deserialization_schema, &call_result)?
        }
        _ => TransactionOutput::non_function_call_output(),
    };

    let respond_serialization_format = RESPOND_SERIALIZATION_FORMAT;
    let respond_serialization_schema = &tx.respond_serialization_schema;
    let serialized_output = transaction_output
        .output
        .serialize(respond_serialization_format, respond_serialization_schema)?;
    Ok(serialized_output)
}

#[derive(Clone)]
pub struct RpcEthereumClient {
    http: reqwest::Client,
    url: String,
    id: Arc<AtomicU64>,
}

// All fields are Send: reqwest::Client, String, and Arc<AtomicU64> are all Send
unsafe impl Send for RpcEthereumClient {}
unsafe impl Sync for RpcEthereumClient {}

#[async_trait]
impl EthereumClientTrait for RpcEthereumClient {
    async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> Option<alloy::rpc::types::Block> {
        match block_id {
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(number)) => {
                self.block_by_number(number).await.unwrap_or_else(|err| {
                    tracing::warn!("Failed to get block by number {number}: {err:?}");
                    None
                })
            }
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Latest) => self
                .block_by_tag("latest".to_string())
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!("Failed to get block by tag latest: {err:?}");
                    None
                }),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Finalized) => self
                .block_by_tag("finalized".to_string())
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!("Failed to get block by tag finalized: {err:?}");
                    None
                }),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Safe) => self
                .block_by_tag("safe".to_string())
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!("Failed to get block by tag safe: {err:?}");
                    None
                }),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Earliest) => self
                .block_by_tag("earliest".to_string())
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!("Failed to get block by tag earliest: {err:?}");
                    None
                }),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Pending) => self
                .block_by_tag("pending".to_string())
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!("Failed to get block by tag pending: {err:?}");
                    None
                }),
            alloy::rpc::types::BlockId::Hash(hash) => self
                .block_by_hash(hash.block_hash)
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!("Failed to get block by hash {hash:?}: {err:?}");
                    None
                }),
        }
    }

    async fn get_block_receipts(
        &self,
        block_number_or_tag: BlockNumberOrTag,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        match block_number_or_tag {
            BlockNumberOrTag::Number(number) => self.block_receipts_by_number(number).await,
            BlockNumberOrTag::Latest => self.block_receipts_by_tag("latest".to_string()).await,
            BlockNumberOrTag::Finalized => {
                self.block_receipts_by_tag("finalized".to_string()).await
            }
            BlockNumberOrTag::Safe => self.block_receipts_by_tag("safe".to_string()).await,
            BlockNumberOrTag::Earliest => self.block_receipts_by_tag("earliest".to_string()).await,
            BlockNumberOrTag::Pending => self.block_receipts_by_tag("pending".to_string()).await,
        }
    }

    async fn get_nonce(
        &self,
        address: Address,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        self.nonce(address, block_id).await
    }

    async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        self.transaction_by_hash(tx_hash).await
    }
}

impl RpcEthereumClient {
    fn new(endpoint: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: endpoint.to_owned(),
            id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn next_id(&self) -> u64 {
        self.id.fetch_add(1, Ordering::Relaxed)
    }

    async fn rpc_call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> anyhow::Result<T> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": self.next_id(),
            "method": method,
            "params": params,
        });

        let response = self.http.post(&self.url).json(&request).send().await?;
        let value: serde_json::Value = response.json().await?;

        if let Some(error) = value.get("error") {
            anyhow::bail!("rpc {method} failed: {error}");
        }

        let result = value
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(serde_json::from_value(result)?)
    }

    async fn block_number(&self) -> anyhow::Result<u64> {
        let hex: String = self.rpc_call("eth_blockNumber", Vec::new()).await?;
        hex_to_u64(&hex)
    }

    async fn block_by_number(
        &self,
        number: u64,
    ) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        self.rpc_call(
            "eth_getBlockByNumber",
            vec![json!(to_hex_u64(number)), json!(false)],
        )
        .await
    }

    async fn block_by_tag(&self, tag: String) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        self.rpc_call("eth_getBlockByTag", vec![json!(tag)]).await
    }

    async fn block_by_hash(
        &self,
        hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        self.rpc_call("eth_getBlockByHash", vec![json!(format!("{:#x}", hash))])
            .await
    }

    async fn block_receipts_by_number(
        &self,
        number: u64,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.rpc_call(
            "eth_getBlockReceiptsByNumber",
            vec![json!(to_hex_u64(number))],
        )
        .await
    }

    async fn block_receipts_by_tag(
        &self,
        tag: String,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.rpc_call("eth_getBlockReceiptsByTag", vec![json!(tag)])
            .await
    }

    async fn get_logs(
        &self,
        block_hash: alloy::primitives::B256,
        contract_address: Address,
    ) -> anyhow::Result<Vec<Log>> {
        let topic_requested = format!("0x{}", SignatureRequested::SIGNATURE_HASH.encode_hex());
        let topic_responded = format!("0x{}", SignatureResponded::SIGNATURE_HASH.encode_hex());
        let filter = json!({
            "address": format_address(contract_address),
            "blockHash": format!("{:#x}", block_hash),
            "topics": [[topic_requested, topic_responded]],
        });
        self.rpc_call("eth_getLogs", vec![filter]).await
    }

    async fn transaction_receipt(
        &self,
        tx_id: BidirectionalTxId,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.rpc_call(
            "eth_getTransactionReceipt",
            vec![json!(format!("{:#x}", tx_id.0))],
        )
        .await
    }

    async fn transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<Transaction>> {
        self.rpc_call(
            "eth_getTransactionByHash",
            vec![json!(format!("{:#x}", tx_hash))],
        )
        .await
    }

    async fn nonce(
        &self,
        address: Address,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        let block_id_hex = match block_id {
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(number)) => {
                json!(to_hex_u64(number))
            }
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Latest) => json!("latest"),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Finalized) => json!("finalized"),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Safe) => json!("safe"),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Earliest) => json!("earliest"),
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Pending) => json!("pending"),
            alloy::rpc::types::BlockId::Hash(hash) => {
                json!(format!("{:#x}", hash.block_hash))
            }
        };
        self.rpc_call::<serde_json::Value>(
            "eth_getAccount",
            vec![json!(format_address(address)), block_id_hex],
        )
        .await
        .map_err(|err| anyhow::anyhow!("Failed to get nonce: {err}"))?
        .get("nonce")
        .and_then(|nonce| nonce.as_str())
        .and_then(|nonce_str| hex_to_u64(nonce_str).ok())
        .ok_or_else(|| anyhow::anyhow!("Failed to parse nonce"))
    }

    async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        let params = json!({
            "from": format_address(from),
            "to": format_address(to),
            "data": format_bytes(&data),
        });
        let block = json!(to_hex_u64(block_number));
        let result: String = self.rpc_call("eth_call", vec![params, block]).await?;
        let stripped = result.trim_start_matches("0x");
        if stripped.is_empty() {
            return Ok(Bytes::default());
        }
        let decoded = hex::decode(stripped)?;
        Ok(Bytes::from(decoded))
    }
}

fn format_address(address: Address) -> String {
    format!("0x{}", address.encode_hex())
}

fn format_bytes(data: &Bytes) -> String {
    if data.is_empty() {
        "0x".to_string()
    } else {
        format!("0x{}", hex::encode(data))
    }
}

fn to_hex_u64(value: u64) -> String {
    format!("0x{:x}", value)
}

fn hex_to_u64(value: &str) -> anyhow::Result<u64> {
    let trimmed = value.trim_start_matches("0x");
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 16)
        .map_err(|err| anyhow::anyhow!("failed to parse hex value '{value}': {err}"))
}
