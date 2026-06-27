use super::SolConfig;
use futures_util::StreamExt;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_primitives::SignKind;
use serde::{Deserialize, Serialize};
use serde_json::json;
use signet_program::accounts::{
    Respond as SolanaRespondAccount, RespondBidirectional as SolanaRespondBidirectionalAccount,
};
use signet_program::instruction::{
    Respond as SolanaRespond, RespondBidirectional as SolanaRespondBidirectional,
};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::RpcBlockConfig;
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::signature::Signer as SolanaSigner;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, TransactionDetails, UiConfirmedBlock,
    UiTransactionEncoding,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::rpc::{ChainPublisher, PublishAction};
use crate::util::retry::{retry_rpc, RetryConfig};

const MAX_SIGNATURES_FOR_FAST_CATCHUP: usize = 1000;

/// The max amount of batches to fetch concurrently
const MAX_CONCURRENT_FETCH: usize = 5;

/// The max chunk size for fetching slots and blocks per batch.
const MAX_CHUNK_SIZE: usize = 50;

/// The max chunk size allowed for fetching concurrently.
pub const MAX_CONCURRENT_CHUNK_SIZE: usize = MAX_CONCURRENT_FETCH * MAX_CHUNK_SIZE;

const SOL_RPC_TIMEOUT: Duration = Duration::from_secs(2);
const SOL_BATCH_TIMEOUT: Duration = Duration::from_secs(30);
const SOL_RPC_MIN_DELAY: Duration = Duration::from_millis(500);
const SOL_RPC_MAX_DELAY: Duration = Duration::from_secs(10);
const SOL_RPC_MAX_RETRIES: usize = 5;

/// Default retry strategy
fn default_retry_strategy() -> RetryConfig {
    RetryConfig {
        min_delay: SOL_RPC_MIN_DELAY,
        max_delay: SOL_RPC_MAX_DELAY,
        max_times: SOL_RPC_MAX_RETRIES,
        jitter: true,
    }
}

/// Retry strategy with infinite retries, used for get_block, fetch_blocks and fetch_signatures_from_latest (catchup path).
fn catchup_retry_strategy() -> RetryConfig {
    RetryConfig {
        min_delay: SOL_RPC_MIN_DELAY,
        max_delay: SOL_RPC_MAX_DELAY,
        max_times: usize::MAX,
        jitter: true,
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
    /// Retry strategy for RPC calls that are not part of catchup (e.g. get_slot, get_tx)
    rpc_retry: RetryConfig,
    /// Retry strategy for RPC calls that are part of catchup (e.g. get_block, fetch_blocks, fetch_signatures_from_latest)
    catchup_retry: RetryConfig,
    pub rpc_client: Arc<RpcClient>,
    pub rpc_http_url: String,
    pub rpc_ws_url: String,
    pub http_client: reqwest::Client,
    pub program_id: Pubkey,
    pub payer: Arc<Keypair>,
}

impl SolanaClient {
    // TODO: reduce duplication between from_config and for_indexer
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
            rpc_retry: default_retry_strategy(),
            catchup_retry: catchup_retry_strategy(),
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
            rpc_retry: default_retry_strategy(),
            catchup_retry: catchup_retry_strategy(),
            rpc_client,
            rpc_http_url,
            rpc_ws_url,
            http_client: reqwest::Client::new(),
            program_id: program_address,
            payer,
        }
    }

    /// A helper function to create a SolanaClient with a custom retry strategy for testing purposes.
    #[cfg(test)]
    pub(crate) fn with_fast_retry(mut self) -> Self {
        let retry_config = RetryConfig {
            min_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            max_times: 2,
            jitter: true,
        };

        self.rpc_retry = retry_config;
        self.catchup_retry = retry_config;
        self
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

    pub async fn get_slot(&self) -> anyhow::Result<u64> {
        retry_rpc!(SOL_RPC_TIMEOUT, self.rpc_retry, "get_slot", {
            self.rpc_client
                .get_slot()
                .await
                .map_err(|e| anyhow::anyhow!(e))
        })
    }

    pub async fn get_tx(
        &self,
        signature: &Signature,
    ) -> anyhow::Result<EncodedConfirmedTransactionWithStatusMeta> {
        let max_attempts = self.rpc_retry.max_times;
        retry_rpc!(
            SOL_RPC_TIMEOUT,
            self.rpc_retry,
            |attempt, err, sleep| {
                tracing::warn!(
                    operation = %signature,
                    attempt,
                    max_attempts,
                    error = %err,
                    retry_in = ?sleep,
                    "get_tx failed, retrying"
                );
            },
            {
                self.rpc_client
                    .get_transaction_with_config(
                        signature,
                        solana_client::rpc_config::RpcTransactionConfig {
                            encoding: Some(UiTransactionEncoding::JsonParsed),
                            commitment: Some(CommitmentConfig::confirmed()),
                            max_supported_transaction_version: Some(0),
                        },
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            }
        )
    }

    pub async fn get_block(&self, slot: u64) -> anyhow::Result<UiConfirmedBlock> {
        let max_attempts = self.catchup_retry.max_times;
        retry_rpc!(
            SOL_RPC_TIMEOUT,
            self.catchup_retry,
            // Notify on retry with structured logging
            |attempt, err, delay| {
                tracing::warn!(
                    ?err,
                    attempt,
                    max_attempts,
                    ?slot,
                    "failed to fetch Solana block; retrying in {:?}",
                    delay
                );
            },
            {
                self.rpc_client
                    .get_block_with_config(slot, Self::block_fetch_config())
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            }
        )
    }

    // TODO: consider returning a Result instead of swallowing errors and returning an empty map. This would allow the caller to handle errors more explicitly.
    pub async fn fetch_blocks(&self, slots: &[u64]) -> HashMap<u64, UiConfirmedBlock> {
        if slots.is_empty() {
            return HashMap::new();
        }

        let max_attempts = self.catchup_retry.max_times;
        let res = retry_rpc!(
            SOL_BATCH_TIMEOUT,
            self.catchup_retry,
            // Notify on retry with structured logging
            |attempt, err, delay| {
                tracing::warn!(
                    ?err,
                    attempt,
                    max_attempts,
                    "failed to send batch request or deserialize response; retrying in {:?}",
                    delay
                );
            },
            {
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
                Ok::<HashMap<u64, UiConfirmedBlock>, anyhow::Error>(results)
            }
        );

        // If batch fails entirely, return an empty map
        res.unwrap_or_default()
    }

    pub async fn fetch_signatures_from_latest(
        &self,
        address: &Pubkey,
        before: Option<Signature>,
    ) -> anyhow::Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        retry_rpc!(
            SOL_RPC_TIMEOUT,
            self.catchup_retry,
            // Notify on retry with structured logging
            |attempts, err, delay| {
                tracing::warn!(
                    ?err,
                    attempts,
                    "failed to fetch signatures for address; retrying in {:?}",
                    delay
                );
            },
            {
                let config = GetConfirmedSignaturesForAddress2Config {
                    before,
                    until: None,
                    limit: Some(MAX_SIGNATURES_FOR_FAST_CATCHUP),
                    commitment: Some(CommitmentConfig::confirmed()),
                };
                self.rpc_client
                    .get_signatures_for_address_with_config(address, config)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            }
        )
    }

    /// Fetch signatures within the range provided [start_slot, end_slot]
    pub async fn fetch_signatures(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> anyhow::Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
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
                .await?;

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
        Ok(signatures)
    }

    /// Fetch slots covered by signatures in the range provided [start_slot, end_slot]
    pub async fn fetch_slots(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> anyhow::Result<BTreeSet<u64>> {
        let sigs = self.fetch_signatures(start_slot, end_slot).await?;
        Ok(sigs.into_iter().map(|sig| sig.slot).collect())
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

#[async_trait::async_trait]
impl ChainPublisher for SolanaClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let timestamp = action.timestamp;
        let mpc_sig = &action.signature;
        let program = self.client.program(self.program_id)?;

        let sign_id = action.indexed.id;
        let request_ids = vec![action.indexed.id.request_id];
        let big_r = mpc_sig.big_r.to_encoded_point(false);
        let signature = crate::util::mpc_to_sol_signature(mpc_sig, big_r);

        tracing::debug!(
            ?sign_id,
            request_type = ?action.indexed.kind,
            "Solana publish signature: dispatching request"
        );

        match &action.indexed.kind {
            SignKind::Sign | SignKind::SignBidirectional(_) => {
                let (event_authority, _) =
                    Pubkey::find_program_address(&[b"__event_authority"], &self.program_id);
                let tx = program
                    .request()
                    .signer(self.payer.clone())
                    .accounts(SolanaRespondAccount {
                        responder: self.payer.pubkey(),
                        event_authority,
                        program: self.program_id,
                    })
                    .args(SolanaRespond {
                        request_ids,
                        signatures: vec![signature.clone()],
                    })
                    .send()
                    .await
                    .inspect_err(|err| {
                        tracing::error!(
                            sign_id = ?action.indexed.id,
                            error = ?err,
                            "failed to publish solana signature"
                        );
                    })?;

                tracing::info!(
                    ?sign_id,
                    tx_hash = ?tx,
                    elapsed = ?timestamp.elapsed(),
                    "published solana signature successfully"
                );
            }
            SignKind::RespondBidirectional(respond_bidirectional_tx) => {
                tracing::debug!(
                    ?sign_id,
                    request_id = ?request_ids[0],
                    serialized_output_len = respond_bidirectional_tx.output.len(),
                    "Solana publish signature: entering RespondBidirectional arm"
                );
                let respond_bidirectional_serialized_output =
                    respond_bidirectional_tx.output.clone();
                let tx = program
                    .request()
                    .signer(self.payer.clone())
                    .accounts(SolanaRespondBidirectionalAccount {
                        responder: self.payer.pubkey(),
                    })
                    .args(SolanaRespondBidirectional {
                        request_id: request_ids[0],
                        serialized_output: respond_bidirectional_serialized_output,
                        signature: signature.clone(),
                    })
                    .send()
                    .await
                    .inspect_err(|err| {
                        tracing::error!(
                            ?sign_id,
                            error = ?err,
                            "Solana publish signature: failed to publish respond bidirectional solana signature"
                        );
                    })?;

                tracing::info!(
                    ?sign_id,
                    tx_hash = ?tx,
                    elapsed = ?timestamp.elapsed(),
                    "published respond bidirectional solana signature successfully"
                );
            }
            SignKind::Checkpoint(_) => {
                tracing::error!(
                    ?sign_id,
                    "Solana publish signature: checkpoint signature publishing not supported on Solana"
                );
                anyhow::bail!("checkpoint publishing not supported on Solana")
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::Signature;

    /// Helper to create a SolanaClient for testing with mockito
    fn test_client(url: &str) -> SolanaClient {
        SolanaClient::for_indexer(
            url.to_string(),
            url.replace("http", "ws"),
            Pubkey::new_unique(),
        )
        .with_fast_retry()
    }

    /// Helper to create a mock JSON-RPC response for getSlot
    fn slot_response(slot: u64) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{slot}}}"#)
    }

    /// Helper to create a mock JSON-RPC response for getBlock
    fn make_block_response(id: usize, slot: u64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "result": {
                "blockHeight": slot,
                "blockTime": null,
                "blockhash": "11111111111111111111111111111111",
                "parentSlot": slot.saturating_sub(1),
                "previousBlockhash": "11111111111111111111111111111111",
                "transactions": [],
                "rewards": []
            }
        })
    }

    /// Helper to create a mock JSON-RPC response for getSignaturesForAddress
    fn signature_entry(slot: u64, sig: &str) -> serde_json::Value {
        serde_json::json!({
            "signature": sig,
            "slot": slot,
            "err": null,
            "memo": null,
            "blockTime": null,
            "confirmationStatus": "confirmed"
        })
    }

    /// Helper to create a mock JSON-RPC response for getSignaturesForAddress
    fn signatures_response(entries: &[serde_json::Value]) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": entries
        })
        .to_string()
    }

    #[test]
    fn block_fetch_config_fields() {
        let config = SolanaClient::block_fetch_config();
        assert_eq!(config.encoding, Some(UiTransactionEncoding::Json));
        assert_eq!(config.transaction_details, Some(TransactionDetails::Full));
        assert_eq!(config.rewards, Some(false));
        assert_eq!(
            config.commitment.map(|c| c.commitment),
            Some(solana_sdk::commitment_config::CommitmentLevel::Confirmed)
        );
        assert_eq!(config.max_supported_transaction_version, Some(0));
    }

    #[tokio::test]
    async fn get_slot_returns_slot_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(slot_response(42))
            .create_async()
            .await;

        let client = test_client(&server.url());
        assert_eq!(client.get_slot().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn get_slot_retries_on_500_then_succeeds() {
        let mut server = mockito::Server::new_async().await;

        let _fail = server
            .mock("POST", "/")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;

        let _ok = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(slot_response(7))
            .expect(1)
            .create_async()
            .await;

        let client = test_client(&server.url());
        assert_eq!(client.get_slot().await.unwrap(), 7);
    }

    #[tokio::test]
    async fn get_slot_exhausts_retries_on_persistent_500() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .expect(3) // 1 attempt + 2 retries
            .create_async()
            .await;

        let client = test_client(&server.url());
        assert!(client.get_slot().await.is_err());
    }

    #[tokio::test]
    async fn get_tx_returns_transaction_on_200() {
        let mut server = mockito::Server::new_async().await;
        let sig = Signature::new_unique();

        // JSON that mimics EncodedConfirmedTransactionWithStatusMeta
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 42,
                "transaction": {
                    "signatures": ["1111111111111111111111111111111111111111111111111111111111111111"],
                    "message": {
                        "accountKeys": [],
                        "instructions": [],
                        "recentBlockhash": "11111111111111111111111111111111"
                    }
                },
                "meta": { "err": null, "fee": 5000, "preBalances": [], "postBalances": [], "status": {"Ok": null} }
            }
        });

        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response.to_string())
            .create_async()
            .await;

        let client = test_client(&server.url());
        let tx = client.get_tx(&sig).await.unwrap();
        assert_eq!(tx.slot, 42);
    }

    #[tokio::test]
    async fn get_tx_retries_on_failure() {
        let mut server = mockito::Server::new_async().await;
        let sig = Signature::new_unique();

        let _mock_fail = server
            .mock("POST", "/")
            .with_status(500)
            .expect(2) // Allow to fail completely to verify retry loop execution
            .create_async()
            .await;

        let client = test_client(&server.url());
        // Should error out.
        assert!(client.get_tx(&sig).await.is_err());
    }

    #[tokio::test]
    async fn get_block_returns_block_on_200() {
        let mut server = mockito::Server::new_async().await;
        const HEIGHT: u64 = 100;
        const TIME: i64 = 1234567890;

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "blockHeight": HEIGHT,
                "blockTime": TIME,
                "blockhash": "11111111111111111111111111111111",
                "parentSlot": 99,
                "previousBlockhash": "11111111111111111111111111111111",
                "transactions": [],
                "rewards": []
            }
        });

        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response.to_string())
            .create_async()
            .await;

        let client = test_client(&server.url());
        let block = client.get_block(HEIGHT).await.unwrap();
        assert_eq!(block.block_height, Some(HEIGHT));
        assert_eq!(block.block_time, Some(TIME));
    }

    #[tokio::test]
    async fn fetch_blocks_returns_blocks_on_200() {
        const HEIGHT_1: u64 = 100;
        const HEIGHT_2: u64 = 101;
        let mut server = mockito::Server::new_async().await;
        let body = serde_json::json!([
            make_block_response(0, HEIGHT_1),
            make_block_response(1, HEIGHT_2),
        ])
        .to_string();

        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let result = client.fetch_blocks(&[HEIGHT_1, HEIGHT_2]).await;

        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&HEIGHT_1));
        assert!(result.contains_key(&HEIGHT_2));
    }

    #[tokio::test]
    async fn fetch_blocks_returns_empty_for_empty_input() {
        let server = mockito::Server::new_async().await;
        let client = test_client(&server.url());
        // Should short-circuit without any HTTP call
        let result = client.fetch_blocks(&[]).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn fetch_blocks_skips_skipped_slots() {
        const HEIGHT_1: u64 = 100;
        const HEIGHT_2: u64 = 101;
        let mut server = mockito::Server::new_async().await;

        // Slot 101 is skipped (error code -32007), slot 100 is present
        let body = serde_json::json!([
            make_block_response(0, HEIGHT_1),
            { "id": 1, "result": null, "error": { "code": -32007, "message": "Slot was skipped" } }
        ])
        .to_string();

        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let result = client.fetch_blocks(&[HEIGHT_1, HEIGHT_2]).await;

        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&HEIGHT_1));
        assert!(!result.contains_key(&HEIGHT_2));
    }

    #[tokio::test]
    async fn fetch_blocks_returns_empty_on_persistent_failure() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .expect(3) // 1 attempt + 2 retries
            .create_async()
            .await;

        let client = test_client(&server.url());

        // fetch_blocks swallows errors and returns empty map
        let result = client.fetch_blocks(&[100, 101]).await;

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn fetch_blocks_for_slots_chunks_requests_and_handles_missing() {
        let mut server = mockito::Server::new_async().await;

        // Returning an empty array
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .expect_at_least(3) // 110 slots / 50 chunk size = 3 chunks
            .create_async()
            .await;

        let client = test_client(&server.url());

        // Request 110 slots
        let slots: std::collections::BTreeSet<u64> = (1..=110).collect();
        let result = client.fetch_blocks_for_slots(slots).await;

        assert_eq!(result.len(), 110);
        // Because the mock returned an empty array, all 110 requests should map to Missing
        assert!(matches!(
            result.get(&1).unwrap(),
            SolanaCatchupBlock::Missing
        ));
        assert!(matches!(
            result.get(&110).unwrap(),
            SolanaCatchupBlock::Missing
        ));
    }

    #[tokio::test]
    async fn fetch_signatures_from_latest_returns_signatures() {
        const SLOT: u64 = 42;
        let mut server = mockito::Server::new_async().await;
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {
                    "signature": "sig1",
                    "slot": SLOT,
                    "err": null,
                    "memo": null,
                    "blockTime": null,
                    "confirmationStatus": "confirmed"
                }
            ]
        });

        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response.to_string())
            .create_async()
            .await;

        let client = test_client(&server.url());
        let sigs = client
            .fetch_signatures_from_latest(&Pubkey::new_unique(), None)
            .await
            .unwrap();

        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].signature, "sig1");
        assert_eq!(sigs[0].slot, SLOT);
    }

    #[tokio::test]
    async fn fetch_slots_filters_to_range() {
        let mut server = mockito::Server::new_async().await;

        // First page: slots 105, 103, 101, 98
        // Second page: empty → stop
        let sig_a = Signature::new_unique().to_string();
        let sig_b = Signature::new_unique().to_string();
        let sig_c = Signature::new_unique().to_string();
        let sig_d = Signature::new_unique().to_string();

        let page1 = signatures_response(&[
            signature_entry(105, &sig_a),
            signature_entry(103, &sig_b),
            signature_entry(101, &sig_c),
            signature_entry(98, &sig_d), // below start_slot=100, triggers stop
        ]);

        let _mock1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page1)
            .expect(1)
            .create_async()
            .await;

        let client = test_client(&server.url());

        // Range [100, 104]: should include 103, 101 but not 105 (above end) or 98 (below start)
        let slots = client.fetch_slots(100, 104).await.unwrap();

        assert_eq!(slots, BTreeSet::from([101, 103]));
    }

    #[tokio::test]
    async fn fetch_slots_returns_empty_when_no_signatures() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&[]))
            .create_async()
            .await;

        let client = test_client(&server.url());
        let slots = client.fetch_slots(100, 200).await.unwrap();
        assert!(slots.is_empty());
    }

    #[tokio::test]
    async fn fetch_signatures_paginates_until_start_slot() {
        let mut server = mockito::Server::new_async().await;

        let sig_a = Signature::new_unique().to_string();
        let sig_b = Signature::new_unique().to_string();
        let sig_c = Signature::new_unique().to_string();

        // Page 1: slots 200, 150 — both in range [100, 200]
        let page1 =
            signatures_response(&[signature_entry(200, &sig_a), signature_entry(150, &sig_b)]);
        // Page 2: slot 90 — below start_slot, stops pagination
        let page2 = signatures_response(&[signature_entry(90, &sig_c)]);

        let _mock1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page1)
            .expect(1)
            .create_async()
            .await;

        let _mock2 = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page2)
            .expect(1)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let sigs = client.fetch_signatures(100, 200).await.unwrap();

        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].slot, 200);
        assert_eq!(sigs[1].slot, 150);
    }
}
