use backon::{ExponentialBuilder, Retryable};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::RpcBlockConfig;
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::{TransactionDetails, UiConfirmedBlock, UiTransactionEncoding};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use super::SolConfig;

const MAX_SIGNATURES_FOR_FAST_CATCHUP: usize = 1000;

/// The max amount of batches to fetch concurrently
const MAX_CONCURRENT_FETCH: usize = 5;

/// The max chunk size for fetching slots and blocks per batch.
const MAX_CHUNK_SIZE: usize = 50;

/// The max chunk size allowed for fetching concurrently.
pub const MAX_CONCURRENT_CHUNK_SIZE: usize = MAX_CONCURRENT_FETCH * MAX_CHUNK_SIZE;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SolanaCatchupBlock {
    Block(UiConfirmedBlock),
    Missing,
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: usize,
    method: &'static str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    id: usize,
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct SolanaClient {
    pub client: Arc<anchor_client::Client<Arc<Keypair>>>,
    pub rpc_client: Arc<RpcClient>,
    pub rpc_http_url: String,
    pub rpc_ws_url: String,
    pub http_client: reqwest::Client,
    pub program_id: Pubkey,
    pub payer: Arc<Keypair>,
}

impl SolanaClient {
    pub fn from_config(sol: &SolConfig) -> Self {
        let keypair = Keypair::from_base58_string(&sol.account_sk);
        let payer = Arc::new(keypair);
        let cluster =
            anchor_client::Cluster::Custom(sol.rpc_http_url.clone(), sol.rpc_ws_url.clone());
        let client = anchor_client::Client::new_with_options(
            cluster,
            payer.clone(),
            CommitmentConfig::confirmed(),
        );
        let rpc_client = Arc::new(RpcClient::new(sol.rpc_http_url.clone()));
        let program_id = Pubkey::from_str(&sol.program_address)
            .expect("Invalid Solana program address provided in configuration");
        Self {
            client: Arc::new(client),
            rpc_client,
            rpc_http_url: sol.rpc_http_url.clone(),
            rpc_ws_url: sol.rpc_ws_url.clone(),
            http_client: reqwest::Client::new(),
            program_id,
            payer,
        }
    }

    pub fn for_indexer(rpc_http_url: String, rpc_ws_url: String, program_address: Pubkey) -> Self {
        // TODO: we need to move solana client further up the creation stack into cli eventually
        // so we can reuse the same SolanaClient for both indexer and RPC.
        let keypair = Keypair::new(); // Dummy keypair for indexer mode
        let payer = Arc::new(keypair);
        let cluster = anchor_client::Cluster::Custom(rpc_http_url.clone(), rpc_ws_url.clone());
        let client = anchor_client::Client::new_with_options(
            cluster,
            payer.clone(),
            CommitmentConfig::confirmed(),
        );
        let rpc_client = Arc::new(RpcClient::new(rpc_http_url.clone()));
        Self {
            client: Arc::new(client),
            rpc_client,
            rpc_http_url,
            rpc_ws_url,
            http_client: reqwest::Client::new(),
            program_id: program_address,
            payer,
        }
    }

    pub fn block_fetch_config() -> RpcBlockConfig {
        RpcBlockConfig {
            encoding: Some(UiTransactionEncoding::Json),
            transaction_details: Some(TransactionDetails::Full),
            rewards: Some(false),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        }
    }

    pub async fn get_block(&self, slot: u64) -> UiConfirmedBlock {
        let mut attempts = 1;
        let fetch = || async {
            self.rpc_client
                .get_block_with_config(slot, Self::block_fetch_config())
                .await
        };
        fetch
            .retry(
                &ExponentialBuilder::default()
                    .with_min_delay(Duration::from_millis(500))
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(usize::MAX),
            )
            .notify(|err, delay| {
                tracing::warn!(
                    ?err,
                    attempts,
                    slot,
                    "failed to fetch Solana block; retrying in {:?}",
                    delay
                );
                attempts += 1;
            })
            .await
            .expect("Solana get_block eventually succeeded")
    }

    pub async fn fetch_blocks(&self, slots: &[u64]) -> HashMap<u64, UiConfirmedBlock> {
        if slots.is_empty() {
            return HashMap::new();
        }

        let mut attempts = 1;
        let fetch = || async {
            let mut requests = Vec::new();
            for (i, &slot) in slots.iter().enumerate() {
                let config = Self::block_fetch_config();
                let config_val = serde_json::to_value(config)
                    .map_err(|e| anyhow::anyhow!("serialization error: {e}"))?;
                requests.push(JsonRpcRequest {
                    jsonrpc: "2.0",
                    id: i,
                    method: "getBlock",
                    params: json!([slot, config_val]),
                });
            }

            let resp = self
                .http_client
                .post(&self.rpc_http_url)
                .json(&requests)
                .send()
                .await?;
            let responses = resp
                .json::<Vec<JsonRpcResponse<UiConfirmedBlock>>>()
                .await?;

            let mut results = HashMap::new();
            for resp_obj in responses {
                if let Some(block) = resp_obj.result {
                    if resp_obj.id < slots.len() {
                        let slot = slots[resp_obj.id];
                        results.insert(slot, block);
                    }
                } else if let Some(err) = resp_obj.error {
                    let is_skipped = err
                        .get("code")
                        .and_then(|c| c.as_i64())
                        .map(|c| c == -32007)
                        .unwrap_or(false);
                    let slot = slots.get(resp_obj.id);
                    if !is_skipped {
                        tracing::warn!(?err, ?slot, "JSON-RPC batch response error");
                    }
                }
            }
            Ok(results)
        };

        fetch
            .retry(
                &ExponentialBuilder::default()
                    .with_min_delay(Duration::from_millis(500))
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(usize::MAX),
            )
            .notify(|err: &anyhow::Error, delay| {
                tracing::warn!(
                    ?err,
                    attempts,
                    "failed to send batch request or deserialize response; retrying in {:?}",
                    delay
                );
                attempts += 1;
            })
            .await
            .unwrap_or_default()
    }

    pub async fn fetch_signatures_from_latest(
        &self,
        address: &Pubkey,
        before: Option<Signature>,
    ) -> Vec<RpcConfirmedTransactionStatusWithSignature> {
        let mut attempts = 1;
        let fetch = || async {
            let config = GetConfirmedSignaturesForAddress2Config {
                before,
                until: None,
                limit: Some(MAX_SIGNATURES_FOR_FAST_CATCHUP),
                commitment: Some(CommitmentConfig::confirmed()),
            };
            self.rpc_client
                .get_signatures_for_address_with_config(address, config)
                .await
        };
        fetch
            .retry(
                &ExponentialBuilder::default()
                    .with_min_delay(Duration::from_millis(500))
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(usize::MAX),
            )
            .notify(|err, delay| {
                tracing::warn!(
                    ?err,
                    attempts,
                    "failed to fetch signatures for address; retrying in {:?}",
                    delay
                );
                attempts += 1;
            })
            .await
            .expect("Solana fetch_signatures_from_latest eventually succeeded")
    }

    /// Fetch signatures within the range provided [start_slot, end_slot]
    pub async fn fetch_signatures(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> Vec<RpcConfirmedTransactionStatusWithSignature> {
        let mut signatures = Vec::new();
        let mut before = None;
        tracing::trace!(start_slot, end_slot, "fetching signatures in range");

        // We walk back from latest block to start_slot. This way we only need
        // to query the set of blocks that have specific transactions relating
        // to our program. If we queried blocks in ascending order, we would
        // need to query all blocks in the range. This is not efficient if
        // there are large gaps between blocks with transactions.
        loop {
            let batch = self
                .fetch_signatures_from_latest(&self.program_id, before)
                .await;
            if batch.is_empty() {
                tracing::trace!(
                    ?before,
                    "finished signature fetching: no more signatures found."
                );
                break;
            }

            let last = batch.last().unwrap();
            let last_sig = Signature::from_str(&last.signature).ok();

            tracing::trace!(
                batch_len = batch.len(),
                last_slot = last.slot,
                total_acc = signatures.len() + batch.len(),
                "fetched batch of signatures"
            );

            let mut reached_start = false;
            for sig in batch {
                if sig.slot < start_slot {
                    reached_start = true;
                    break;
                }
                if sig.slot <= end_slot {
                    signatures.push(sig);
                }
            }

            if reached_start || last_sig.is_none() {
                tracing::trace!(
                    start_slot,
                    "finished signature fetching: reached start_slot (or no more signatures)"
                );
                break;
            }
            before = last_sig;
        }
        signatures
    }

    /// Fetch slots covered by signatures in the range provided [start_slot, end_slot]
    pub async fn fetch_slots(&self, start_slot: u64, end_slot: u64) -> BTreeSet<u64> {
        self.fetch_signatures(start_slot, end_slot)
            .await
            .into_iter()
            .map(|sig| sig.slot)
            .collect()
    }

    pub async fn fetch_blocks_for_slots(
        &self,
        slots: BTreeSet<u64>,
    ) -> BTreeMap<u64, SolanaCatchupBlock> {
        tracing::trace!(total_slots = slots.len(), "fetching blocks for slots...");
        let slots_vec: Vec<u64> = slots.into_iter().collect();
        let chunks: Vec<Vec<u64>> = slots_vec
            .chunks(MAX_CHUNK_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect();

        let mut stream = futures_util::stream::iter(chunks)
            .map(|chunk| async move {
                let results = self.fetch_blocks(&chunk).await;
                (chunk, results)
            })
            .buffer_unordered(MAX_CONCURRENT_FETCH);

        let mut blocks_by_height = BTreeMap::new();
        let mut count = 0;
        while let Some((chunk, mut results)) = stream.next().await {
            count += chunk.len();
            tracing::trace!(count, "fetched blocks batch progress");
            for slot in chunk {
                let catchup_item = match results.remove(&slot) {
                    Some(block) => SolanaCatchupBlock::Block(block),
                    None => SolanaCatchupBlock::Missing,
                };
                blocks_by_height.insert(slot, catchup_item);
            }
        }

        blocks_by_height
    }
}
