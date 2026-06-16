use std::collections::{HashMap, BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use solana_sdk::{pubkey::Pubkey, signature::Signature, commitment_config::CommitmentConfig};
use solana_sdk::signer::keypair::Keypair;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::RpcBlockConfig;
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_transaction_status::{TransactionDetails, UiConfirmedBlock, UiTransactionEncoding};
use serde::{Deserialize, Serialize};
use serde_json::json;
use futures_util::StreamExt;

const MAX_SIGNATURES_FOR_FAST_CATCHUP: usize = 1000;

#[derive(Clone)]
pub struct SolConfig {
    /// The solana account secret key used to sign solana respond txn.
    pub account_sk: String,
    /// Solana RPC http URL
    pub rpc_http_url: String,
    /// Solana RPC websocket URL
    pub rpc_ws_url: String,
    /// The program address to watch
    pub program_address: String,
}

impl fmt::Debug for SolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolConfig")
            .field("account_sk", &"<hidden>")
            .field("rpc_http_url", &self.rpc_http_url)
            .field("rpc_ws_url", &self.rpc_ws_url)
            .field("program_address", &self.program_address)
            .finish()
    }
}

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
    pub fn new(sol: &SolConfig) -> Self {
        let keypair = Keypair::from_base58_string(&sol.account_sk);
        let payer = Arc::new(keypair);
        let cluster = anchor_client::Cluster::Custom(sol.rpc_http_url.clone(), sol.rpc_ws_url.clone());
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

    pub fn new_indexer(
        rpc_http_url: String,
        rpc_ws_url: String,
        program_address: Pubkey,
    ) -> Self {
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
        let mut attempts = 0;
        let mut delay = Duration::from_millis(500);
        loop {
            attempts += 1;
            match self
                .rpc_client
                .get_block_with_config(slot, Self::block_fetch_config())
                .await
            {
                Ok(block) => return block,
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        attempts,
                        slot,
                        "failed to fetch Solana block; retrying in {:?}",
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_secs(10));
                }
            }
        }
    }

    pub async fn fetch_blocks(
        &self,
        slots: &[u64],
    ) -> HashMap<u64, UiConfirmedBlock> {
        if slots.is_empty() {
            return HashMap::new();
        }

        let mut attempts = 0;
        let mut delay = Duration::from_millis(500);
        loop {
            attempts += 1;
            let mut requests = Vec::new();
            for (i, &slot) in slots.iter().enumerate() {
                let config = Self::block_fetch_config();
                match serde_json::to_value(config) {
                    Ok(config_val) => {
                        requests.push(JsonRpcRequest {
                            jsonrpc: "2.0",
                            id: i,
                            method: "getBlock",
                            params: json!([slot, config_val]),
                        });
                    }
                    Err(err) => {
                        tracing::error!(?err, "failed to serialize RpcBlockConfig");
                        return HashMap::new();
                    }
                }
            }

            match self
                .http_client
                .post(&self.rpc_http_url)
                .json(&requests)
                .send()
                .await
            {
                Ok(resp) => {
                    match resp.json::<Vec<JsonRpcResponse<UiConfirmedBlock>>>().await {
                        Ok(responses) => {
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
                            return results;
                        }
                        Err(err) => {
                            tracing::warn!(
                                ?err,
                                attempts,
                                "failed to deserialize batch response; retrying in {:?}",
                                delay
                            );
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        attempts,
                        "failed to send batch request; retrying in {:?}",
                        delay
                    );
                }
            }

            tokio::time::sleep(delay).await;
            delay = std::cmp::min(delay * 2, Duration::from_secs(10));
        }
    }

    pub async fn fetch_signatures_with_retry(
        &self,
        address: &Pubkey,
        before: Option<Signature>,
    ) -> Vec<RpcConfirmedTransactionStatusWithSignature> {
        let mut attempts = 0;
        let mut delay = Duration::from_millis(500);
        loop {
            attempts += 1;
            let config = GetConfirmedSignaturesForAddress2Config {
                before,
                until: None,
                limit: Some(MAX_SIGNATURES_FOR_FAST_CATCHUP),
                commitment: Some(CommitmentConfig::confirmed()),
            };
            match self
                .rpc_client
                .get_signatures_for_address_with_config(address, config)
                .await
            {
                Ok(res) => return res,
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        attempts,
                        "failed to fetch signatures for address; retrying in {delay:?}",
                    );
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_secs(10));
                }
            }
        }
    }

    pub async fn fetch_signatures_in_range(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> Vec<RpcConfirmedTransactionStatusWithSignature> {
        let mut signatures = Vec::new();
        let mut before = None;
        let mut last_slot = None;
        tracing::trace!(start_slot, end_slot, "fetching signatures in range");
        loop {
            let batch = self.fetch_signatures_with_retry(&self.program_id, before).await;
            if batch.is_empty() {
                if before.is_none() {
                    tracing::trace!("finished signature fetching: no signatures found at all.");
                    break;
                }

                tracing::warn!(
                    last_slot,
                    start_slot,
                    "fetched empty signature batch before reaching start_slot. retrying in 5s..."
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            let last = batch.last().unwrap();
            let last_sig = Signature::from_str(&last.signature).ok();
            last_slot = Some(last.slot);

            tracing::trace!(
                batch_len = batch.len(),
                last_slot = last_slot.unwrap(),
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
                tracing::trace!(start_slot, "finished signature fetching: reached start_slot (or no more signatures)");
                break;
            }
            before = last_sig;
        }
        signatures
    }

    pub async fn fetch_blocks_for_slots(
        &self,
        slots: BTreeSet<u64>,
    ) -> BTreeMap<u64, SolanaCatchupBlock> {
        const MAX_CONCURRENT_FETCH: usize = 5;

        let total_slots = slots.len();
        tracing::trace!("Fetching {} blocks for slots...", total_slots);

        let slots_vec: Vec<u64> = slots.into_iter().collect();
        let chunk_size = 50;
        let chunks: Vec<Vec<u64>> = slots_vec
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        let mut stream = futures_util::stream::iter(chunks.into_iter())
            .map(|chunk| async move {
                let results = self.fetch_blocks(&chunk).await;
                (chunk, results)
            })
            .buffer_unordered(MAX_CONCURRENT_FETCH);

        let mut blocks_by_height = BTreeMap::new();
        let mut count = 0;
        while let Some((chunk, mut results)) = stream.next().await {
            count += chunk.len();
            tracing::trace!(count, total_slots, "fetched blocks batch progress");
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
