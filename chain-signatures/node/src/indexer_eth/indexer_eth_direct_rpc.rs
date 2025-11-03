use alloy::rpc::types::Transaction;

use alloy::rpc::types::TransactionReceipt;

use crate::respond_bidirectional::{
    CompletedTx, RespondBidirectionalSerializedOutput, SerDeserFormat,
    OUTPUT_DESERIALIZATION_FORMAT, RESPOND_SERIALIZATION_FORMAT,
};

use crate::indexer_eth::EthConfig;
use crate::indexer_eth::SignatureRequested;
use crate::protocol::Chain;
use crate::protocol::IndexedSignRequest;
use crate::sign_bidirectional::BidirectionalTx;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::sign_bidirectional::BidirectionalTxStatus;
use crate::sign_bidirectional::TransactionOutput;
use crate::storage::app_data_storage::AppDataStorage;
use alloy::consensus::BlockHeader;
use alloy::consensus::Transaction as _;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::Log;
use alloy_sol_types::SolEvent;
use near_account_id::AccountId;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio::time::Duration;

pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    bidirectional_tx_map: Arc<RwLock<HashMap<BidirectionalTxId, BidirectionalTx>>>,
) {
    let Some(eth) = eth else {
        tracing::warn!("ethereum indexer is disabled");
        return;
    };

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
                &bidirectional_tx_map,
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
    bidirectional_tx_map: &Arc<RwLock<HashMap<BidirectionalTxId, BidirectionalTx>>>,
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
    if !logs.is_empty() {
        sign_requests.extend(crate::indexer_eth::parse_filtered_logs(logs, total_timeout));
    }

    let mut respond_requests = process_bidirectional_requests(
        client,
        block_number,
        total_timeout,
        bidirectional_tx_map,
        &node_near_account_id,
    )
    .await?;

    sign_requests.append(&mut respond_requests);

    if sign_requests.is_empty() {
        return Ok(());
    }

    crate::indexer_eth::send_indexed_requests(
        sign_requests.clone(),
        sign_tx.clone(),
        node_near_account_id.clone(),
    );

    for request in &sign_requests {
        crate::metrics::INDEXER_DELAY
            .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
            .observe(
                crate::util::duration_between_unix(block_timestamp, request.unix_timestamp_indexed)
                    .as_secs() as f64,
            );
    }

    Ok(())
}

async fn process_bidirectional_requests(
    client: &RpcEthereumClient,
    block_number: u64,
    total_timeout: Duration,
    bidirectional_tx_map: &Arc<RwLock<HashMap<BidirectionalTxId, BidirectionalTx>>>,
    node_near_account_id: &AccountId,
) -> anyhow::Result<Vec<IndexedSignRequest>> {
    let pending_txs: HashMap<BidirectionalTxId, BidirectionalTx> = {
        bidirectional_tx_map
            .read()
            .await
            .iter()
            .filter(|(_, tx)| tx.status == BidirectionalTxStatus::Pending)
            .map(|(id, tx)| (*id, tx.clone()))
            .collect()
    };

    let mut respond_requests = Vec::new();

    for (tx_id, pending_tx) in pending_txs {
        let start = Instant::now();
        let receipt = client.transaction_receipt(tx_id).await;
        crate::metrics::ETH_BLOCK_RECEIPT_LATENCY
            .with_label_values(&[node_near_account_id.as_str()])
            .observe(start.elapsed().as_millis() as f64);

        let Some(receipt) = receipt? else {
            continue;
        };

        let status = receipt.status();
        tracing::info!(
            "Tx {:?} found in block {block_number}: {}",
            tx_id,
            if status { "success" } else { "failed" }
        );

        let mut updated_tx = pending_tx.clone();
        updated_tx.status = if status {
            BidirectionalTxStatus::Success
        } else {
            BidirectionalTxStatus::Failed
        };

        let completed_tx = CompletedTx::new(updated_tx.clone(), block_number);
        if status {
            match extract_success_output_with_rpc(client, &updated_tx, block_number).await {
                Ok(serialized_output) => {
                    match completed_tx.create_sign_request_from_serialized_output(
                        serialized_output,
                        total_timeout,
                    ) {
                        Ok(sign_request) => respond_requests.push(sign_request),
                        Err(err) => tracing::warn!(
                            ?tx_id,
                            ?err,
                            "Failed to build bidirectional respond sign request"
                        ),
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?err,
                        "Failed to extract transaction output for bidirectional tx"
                    );
                }
            }
        } else {
            match completed_tx
                .create_failed_sign_request_without_light_client(total_timeout)
                .await
            {
                Ok(sign_request) => respond_requests.push(sign_request),
                Err(err) => tracing::warn!(
                    ?tx_id,
                    ?err,
                    "Failed to build failed bidirectional sign request"
                ),
            }
        }

        bidirectional_tx_map.write().await.insert(tx_id, updated_tx);
    }

    let remaining_pending: HashMap<BidirectionalTxId, BidirectionalTx> = {
        bidirectional_tx_map
            .read()
            .await
            .iter()
            .filter(|(_, tx)| tx.status == BidirectionalTxStatus::Pending)
            .map(|(id, tx)| (*id, tx.clone()))
            .collect()
    };

    for (tx_id, mut tx) in remaining_pending {
        let current_nonce = match client
            .transaction_count(tx.from_address, block_number)
            .await
        {
            Ok(nonce) => nonce,
            Err(err) => {
                tracing::warn!(?tx_id, ?err, "Failed to fetch nonce for bidirectional tx");
                continue;
            }
        };

        if tx.nonce < current_nonce {
            tracing::warn!(
                "Nonce too low for tx {:?}: expected {}, got {}",
                tx_id,
                tx.nonce,
                current_nonce
            );
            tx.status = BidirectionalTxStatus::Failed;
            let completed_tx = CompletedTx::new(tx.clone(), block_number);
            match completed_tx
                .create_failed_sign_request_without_light_client(total_timeout)
                .await
            {
                Ok(sign_request) => respond_requests.push(sign_request),
                Err(err) => {
                    tracing::warn!(?tx_id, ?err, "Failed to build sign request for stale nonce")
                }
            }
            bidirectional_tx_map.write().await.insert(tx_id, tx);
        }
    }

    Ok(respond_requests)
}

async fn extract_success_output_with_rpc(
    client: &RpcEthereumClient,
    tx: &BidirectionalTx,
    block_number: u64,
) -> anyhow::Result<RespondBidirectionalSerializedOutput> {
    let Some(tx_info) = client.transaction_by_hash(tx.id).await? else {
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
struct RpcEthereumClient {
    http: reqwest::Client,
    url: String,
    id: Arc<AtomicU64>,
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
        self.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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

    async fn get_logs(
        &self,
        block_hash: alloy::primitives::B256,
        contract_address: Address,
    ) -> anyhow::Result<Vec<Log>> {
        let topic = format!("0x{}", SignatureRequested::SIGNATURE_HASH.encode_hex());
        let filter = json!({
            "address": format_address(contract_address),
            "blockHash": format!("{:#x}", block_hash),
            "topics": [topic],
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
        tx_id: BidirectionalTxId,
    ) -> anyhow::Result<Option<Transaction>> {
        self.rpc_call(
            "eth_getTransactionByHash",
            vec![json!(format!("{:#x}", tx_id.0))],
        )
        .await
    }

    async fn transaction_count(&self, address: Address, block_number: u64) -> anyhow::Result<u64> {
        let hex: String = self
            .rpc_call(
                "eth_getTransactionCount",
                vec![
                    json!(format_address(address)),
                    json!(to_hex_u64(block_number)),
                ],
            )
            .await?;
        hex_to_u64(&hex)
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
