use anyhow::Context as _;
use futures_util::StreamExt;
use mpc_chain_integration_core::{
    utils::retry::{is_retryable, retry_rpc, RetryConfig, RpcFailure, SharedBackoff},
    PublisherTelemetry,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_client::{
    rpc_config::{RpcBlockConfig, RpcSignaturesForAddressConfig},
    rpc_custom_error::{
        JSON_RPC_SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED, JSON_RPC_SERVER_ERROR_SLOT_SKIPPED,
    },
    rpc_response::RpcConfirmedTransactionStatusWithSignature,
};
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{pubkey::Pubkey, signature::Signature, signer::keypair::Keypair};
use solana_transaction_status::{TransactionDetails, UiConfirmedBlock, UiTransactionEncoding};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use crate::config::SolConfig;
use url::Url;

/// Shared upper bound for signature pages and globally ordered slot chunks.
pub(crate) const CATCHUP_PAGE_SIZE: usize = 1_000;

/// The max amount of batches to fetch concurrently
const MAX_CONCURRENT_FETCH: usize = 5;

/// The max chunk size for fetching slots and blocks per batch.
const MAX_CHUNK_SIZE: usize = 50;

const SOL_RPC_TIMEOUT: Duration = Duration::from_secs(2);
const SOL_BATCH_TIMEOUT: Duration = Duration::from_secs(30);
const SOL_RPC_MIN_DELAY: Duration = Duration::from_millis(500);
const SOL_RPC_MAX_DELAY: Duration = Duration::from_secs(10);
const SOL_RPC_MAX_RETRIES: usize = 5;

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

/// Slot-unavailable codes (solana-rpc-client-api 3.1.14 custom_error.rs):
/// "skipped, or missing due to ledger jump to recent snapshot" (-32007) /
/// "skipped, or missing in long-term storage" (-32009) — backend-local gaps.
fn slot_skipped(code: i64) -> bool {
    matches!(
        code,
        JSON_RPC_SERVER_ERROR_SLOT_SKIPPED | JSON_RPC_SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED
    )
}

/// The carried slot-unavailable code, if any.
pub(crate) fn skipped_code(err: &anyhow::Error) -> Option<i64> {
    err.chain()
        .find_map(|c| c.downcast_ref::<RpcFailure>())
        .and_then(RpcFailure::code)
        .filter(|&code| slot_skipped(code))
}

/// Read carrier for a bare reqwest error.
fn read_carrier(e: &reqwest::Error) -> RpcFailure {
    match e.status() {
        Some(status) => RpcFailure::read_status(status, format!("{e:#}")),
        // statusless (connection): explicit retryable so the fallback
        // can't misread a ":429" port
        None => RpcFailure::retryable(format!("{e:#}")),
    }
}

/// The batch fetch bypasses the solana client, so its errors arrive bare.
// TODO: transitional boundary helper — disappears with Phase 4's typed verdict enums.
fn classify_batch(e: reqwest::Error) -> anyhow::Error {
    anyhow::Error::new(read_carrier(&e))
}

/// JSON-RPC body error to carrier: skipped slots are terminal with their
/// code, everything else retryable (another LB backend may serve it).
fn classify_body_error(error: serde_json::Value) -> anyhow::Error {
    let code = error.get("code").and_then(serde_json::Value::as_i64);
    let message = error
        .get("message")
        .and_then(|m| m.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| error.to_string());
    match code {
        Some(code) if slot_skipped(code) => {
            anyhow::Error::new(RpcFailure::terminal_code(code, message))
        }
        _ => anyhow::Error::new(RpcFailure::retryable(message)),
    }
}

#[derive(Debug, Clone, PartialEq)]
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

/// Represents a JSON-RPC response, which can either be a successful result or an error.
/// `id: Option` — the spec permits `null`, and a decode failure must not
/// swallow the error side's verdict.
#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    id: Option<usize>,
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct SolanaClient {
    pub client: Arc<anchor_client::Client<Arc<Keypair>>>,
    /// Retry strategy for RPC calls that are not part of catchup (e.g. get_slot_finalized)
    rpc_retry: RetryConfig,
    /// Retry strategy for RPC calls that are part of catchup (e.g. get_block, fetch_blocks, fetch_signatures_from_latest)
    catchup_retry: RetryConfig,
    /// Shared 429 cooldown across all RPC call sites
    shared_backoff: SharedBackoff,
    pub rpc_http_url: Url,
    pub http_client: reqwest::Client,
    pub program_id: Pubkey,
    pub payer: Arc<Keypair>,
    pub telemetry: Arc<dyn PublisherTelemetry>,
}

impl SolanaClient {
    // TODO: reduce duplication between from_config and for_indexer
    pub fn from_config(sol: &SolConfig, telemetry: Arc<dyn PublisherTelemetry>) -> Self {
        let keypair = Keypair::from_base58_string(&sol.account_sk);
        let payer = Arc::new(keypair);
        // Empty ws slot: nothing subscribes (the indexer polls finalized blocks).
        let cluster = anchor_client::Cluster::Custom(sol.rpc_http_url.to_string(), String::new());
        let client = anchor_client::Client::new_with_options(
            cluster,
            payer.clone(),
            CommitmentConfig::confirmed(),
        );
        Self {
            client: Arc::new(client),
            rpc_retry: default_retry_strategy(),
            catchup_retry: catchup_retry_strategy(),
            // TODO: `from_config` retakes the stack gate once publish gating
            // moves inside the client
            shared_backoff: SharedBackoff::new(),
            rpc_http_url: sol.rpc_http_url.clone(),
            http_client: reqwest::Client::new(),
            program_id: sol.program_address,
            payer,
            telemetry,
        }
    }

    pub fn for_indexer(
        rpc_http_url: Url,
        program_address: Pubkey,
        telemetry: Arc<dyn PublisherTelemetry>,
        shared_backoff: SharedBackoff,
    ) -> Self {
        let keypair = Keypair::new(); // Dummy keypair for indexer mode
        let payer = Arc::new(keypair);
        // Empty ws slot: nothing subscribes.
        let cluster = anchor_client::Cluster::Custom(rpc_http_url.to_string(), String::new());
        let client = anchor_client::Client::new_with_options(
            cluster,
            payer.clone(),
            CommitmentConfig::finalized(),
        );
        Self {
            client: Arc::new(client),
            rpc_retry: default_retry_strategy(),
            catchup_retry: catchup_retry_strategy(),
            // the stack's gate: indexer reads share one cooldown window with
            // publishes (and vice versa)
            shared_backoff,
            rpc_http_url,
            http_client: reqwest::Client::new(),
            program_id: program_address,
            payer,
            telemetry,
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
            encoding: Some(UiTransactionEncoding::JsonParsed),
            transaction_details: Some(TransactionDetails::Full),
            rewards: Some(false),
            commitment: Some(CommitmentConfig::finalized()),
            max_supported_transaction_version: Some(1),
        }
    }

    /// Single JSON-RPC call over raw reqwest, like `fetch_blocks`: statuses
    /// and body error codes arrive typed. The vendored client hides 429s
    /// behind its internal retry loop and surfaces them as timeouts.
    async fn rpc_call<T: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<T> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 0,
            method,
            params,
        };
        let resp = self
            .http_client
            .post(self.rpc_http_url.clone())
            .json(&request)
            .send()
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(classify_batch)?;
        let resp = resp
            .json::<JsonRpcResponse<T>>()
            .await
            .map_err(classify_batch)?;
        match (resp.result, resp.error) {
            // error wins over a paired result, like the batch envelope
            (_, Some(error)) => Err(classify_body_error(error)),
            (Some(result), None) => Ok(result),
            // null result: retryable, matching the vendored client's
            // decode failure
            (None, None) => Err(anyhow::Error::new(RpcFailure::retryable(format!(
                "{method} returned no result"
            )))),
        }
    }

    /// Get the latest finalized slot from the Solana RPC.
    /// This is used to determine the upper bound for catchup.
    pub async fn get_slot_finalized(&self) -> anyhow::Result<u64> {
        retry_rpc!(
            SOL_RPC_TIMEOUT,
            self.rpc_retry,
            self.shared_backoff,
            "get_slot_finalized",
            {
                #[cfg(feature = "bench")]
                crate::bench::rpc_inc("getSlot");
                self.rpc_call::<u64>("getSlot", json!([CommitmentConfig::finalized()]))
                    .await
            }
        )
    }

    pub async fn get_block(&self, slot: u64) -> anyhow::Result<UiConfirmedBlock> {
        let max_attempts = self.catchup_retry.max_times;
        retry_rpc!(
            SOL_RPC_TIMEOUT,
            self.catchup_retry,
            self.shared_backoff,
            "get_block",
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
                #[cfg(feature = "bench")]
                crate::bench::rpc_inc("getBlock(refetch)");
                let block_config = serde_json::to_value(Self::block_fetch_config())
                    .context("serializing the getBlock config")?;
                self.rpc_call::<UiConfirmedBlock>("getBlock", json!([slot, block_config]))
                    .await
            }
        )
    }

    pub async fn fetch_blocks(
        &self,
        slots: &[u64],
    ) -> anyhow::Result<HashMap<u64, UiConfirmedBlock>> {
        if slots.is_empty() {
            return Ok(HashMap::new());
        }

        let max_attempts = self.catchup_retry.max_times;
        let block_config = serde_json::to_value(Self::block_fetch_config())
            .context("serializing the getBlock config")?;
        let res = retry_rpc!(
            SOL_BATCH_TIMEOUT,
            self.catchup_retry,
            self.shared_backoff,
            "fetch_blocks",
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
                #[cfg(feature = "bench")]
                crate::bench::rpc_inc_n("getBlock(batch)", slots.len() as u64);
                let mut requests = Vec::new();
                for (i, &slot) in slots.iter().enumerate() {
                    requests.push(JsonRpcRequest {
                        jsonrpc: "2.0",
                        id: i,
                        method: "getBlock",
                        params: json!([slot, block_config.clone()]),
                    });
                }

                let resp = self
                    .http_client
                    .post(self.rpc_http_url.clone())
                    .json(&requests)
                    .send()
                    .await
                    .and_then(|resp| resp.error_for_status())
                    .map_err(classify_batch)?;
                let responses = resp
                    .json::<Vec<JsonRpcResponse<UiConfirmedBlock>>>()
                    .await
                    .map_err(classify_batch)?;

                let mut results = HashMap::new();
                for resp in responses {
                    match (resp.result, resp.error) {
                        // error present ⇒ the error side wins, both-field
                        // envelopes included; Only network-skipped slots are
                        // silent — node-local absence warns because
                        // `process_catchup_item` refetch-retries it
                        (_, Some(error)) => {
                            let skipped = error
                                .get("code")
                                .and_then(serde_json::Value::as_i64)
                                .is_some_and(slot_skipped);
                            let slot = resp.id.and_then(|id| slots.get(id)).copied();
                            if !skipped {
                                tracing::warn!(?error, ?slot, "JSON-RPC batch response error");
                            }
                        }
                        (Some(block), None) => {
                            if let Some(slot) = resp.id.and_then(|id| slots.get(id)).copied() {
                                results.insert(slot, block);
                            }
                        }
                        // null result: absent block — the per-slot refetch resolves it
                        (None, None) => {}
                    }
                }
                Ok::<HashMap<u64, UiConfirmedBlock>, anyhow::Error>(results)
            }
        );

        match res {
            Ok(results) => Ok(results),
            // swallowed terminal failures fan out into a per-slot refetch storm
            Err(e) if !is_retryable(&e) => Err(e),
            // a per-slot refetch can succeed where the batch failed; reachable
            // only under a finite budget — catchup's usize::MAX never exhausts
            Err(e) => {
                tracing::warn!(
                    error = %format_args!("{e:#}"),
                    "batch block fetch failed; degrading to per-slot refetch"
                );
                Ok(HashMap::new())
            }
        }
    }

    pub async fn fetch_signatures_from_latest(
        &self,
        address: &Pubkey,
        before: Option<Signature>,
    ) -> anyhow::Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        retry_rpc!(
            SOL_RPC_TIMEOUT,
            self.catchup_retry,
            self.shared_backoff,
            "fetch_signatures",
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
                #[cfg(feature = "bench")]
                crate::bench::rpc_inc("getSignaturesForAddress");
                let config = serde_json::to_value(RpcSignaturesForAddressConfig {
                    before: before.map(|sig| sig.to_string()),
                    until: None,
                    limit: Some(CATCHUP_PAGE_SIZE),
                    commitment: Some(CommitmentConfig::finalized()),
                    min_context_slot: None,
                })
                .context("serializing the getSignaturesForAddress config")?;
                self.rpc_call::<Vec<RpcConfirmedTransactionStatusWithSignature>>(
                    "getSignaturesForAddress",
                    json!([address.to_string(), config]),
                )
                .await
                .inspect(|_batch| {
                    #[cfg(feature = "bench")]
                    crate::bench::inc_sig_page(_batch.len() as u64);
                })
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
    ) -> anyhow::Result<BTreeMap<u64, SolanaCatchupBlock>> {
        tracing::trace!(total_slots = slots.len(), "fetching blocks for slots...");
        #[cfg(feature = "bench")]
        let started_at = std::time::Instant::now();
        let slots_vec: Vec<u64> = slots.into_iter().collect();
        let chunks: Vec<Vec<u64>> = slots_vec
            .chunks(MAX_CHUNK_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect();

        let mut stream = futures_util::stream::iter(chunks)
            .map(|chunk| async move {
                let results = self.fetch_blocks(&chunk).await?;
                Ok::<_, anyhow::Error>((chunk, results))
            })
            .buffer_unordered(MAX_CONCURRENT_FETCH);

        let mut blocks_by_height = BTreeMap::new();
        let mut count = 0;
        while let Some(res) = stream.next().await {
            let (chunk, mut results) = res?;
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

        #[cfg(feature = "bench")]
        crate::bench::add_batch_fetch_time(started_at.elapsed());

        Ok(blocks_by_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{signature_entry, signatures_response};
    use mpc_chain_integration_core::{
        utils::retry::{is_provider_throttled, is_retryable},
        NoopPublisherTelemetry,
    };
    use solana_client::rpc_custom_error::{
        JSON_RPC_SERVER_ERROR_BLOCK_CLEANED_UP, JSON_RPC_SERVER_ERROR_BLOCK_NOT_AVAILABLE,
        JSON_RPC_SERVER_ERROR_BLOCK_STATUS_NOT_AVAILABLE_YET,
        JSON_RPC_SERVER_ERROR_LONG_TERM_STORAGE_UNREACHABLE, JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY,
        JSON_RPC_SERVER_ERROR_TRANSACTION_HISTORY_NOT_AVAILABLE,
    };
    use solana_sdk::{pubkey::Pubkey, signature::Signature};

    /// Helper to create a SolanaClient for testing with mockito
    fn test_client(url: &str) -> SolanaClient {
        test_client_with_gate(url, SharedBackoff::new())
    }

    /// Helper to create a SolanaClient bound to an observable gate
    fn test_client_with_gate(url: &str, shared_backoff: SharedBackoff) -> SolanaClient {
        SolanaClient::for_indexer(
            url.parse().unwrap(),
            Pubkey::new_unique(),
            Arc::new(NoopPublisherTelemetry),
            shared_backoff,
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

    #[test]
    fn block_fetch_config_fields() {
        let config = SolanaClient::block_fetch_config();
        assert_eq!(config.encoding, Some(UiTransactionEncoding::JsonParsed));
        assert_eq!(config.transaction_details, Some(TransactionDetails::Full));
        assert_eq!(config.rewards, Some(false));
        assert_eq!(
            config.commitment.map(|c| c.commitment),
            Some(solana_commitment_config::CommitmentLevel::Finalized)
        );
        assert_eq!(config.max_supported_transaction_version, Some(1));
    }

    #[tokio::test]
    async fn get_slot_finalized_returns_slot_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            // the vendored client's exact request
            // (solana-rpc-client 3.1.14, rpc_client.rs:1848)
            .match_body(mockito::Matcher::Json(json!({
                "jsonrpc": "2.0", "id": 0, "method": "getSlot",
                "params": [{ "commitment": "finalized" }]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(slot_response(42))
            .create_async()
            .await;

        let client = test_client(&server.url());
        assert_eq!(client.get_slot_finalized().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn get_slot_finalized_retries_on_500_then_succeeds() {
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
        assert_eq!(client.get_slot_finalized().await.unwrap(), 7);
    }

    #[tokio::test]
    async fn get_slot_finalized_exhausts_retries_on_persistent_500() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .expect(3) // 1 attempt + 2 retries
            .create_async()
            .await;

        let client = test_client(&server.url());
        assert!(client.get_slot_finalized().await.is_err());
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
            // the vendored client's exact request (rpc_client.rs:2457)
            .match_body(mockito::Matcher::Json(json!({
                "jsonrpc": "2.0", "id": 0, "method": "getBlock",
                "params": [HEIGHT, {
                    "encoding": "jsonParsed",
                    "transactionDetails": "full",
                    "rewards": false,
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 1
                }]
            })))
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
        let result = client.fetch_blocks(&[HEIGHT_1, HEIGHT_2]).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&HEIGHT_1));
        assert!(result.contains_key(&HEIGHT_2));
    }

    #[tokio::test]
    async fn fetch_blocks_returns_empty_for_empty_input() {
        let server = mockito::Server::new_async().await;
        let client = test_client(&server.url());
        // Should short-circuit without any HTTP call
        let result = client.fetch_blocks(&[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn fetch_blocks_skips_skipped_slots() {
        const HEIGHT_1: u64 = 100;
        const HEIGHT_2: u64 = 101;
        const HEIGHT_3: u64 = 102;
        let mut server = mockito::Server::new_async().await;

        // Slot 101 skipped (-32007), 102 skipped in long-term storage
        // (-32009); slot 100 present
        let body = serde_json::json!([
            make_block_response(0, HEIGHT_1),
            { "id": 1, "result": null, "error": { "code": JSON_RPC_SERVER_ERROR_SLOT_SKIPPED, "message": "Slot was skipped" } },
            { "id": 2, "result": null, "error": { "code": JSON_RPC_SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED, "message": "Slot was skipped because it is in long-term storage" } }
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
        let result = client
            .fetch_blocks(&[HEIGHT_1, HEIGHT_2, HEIGHT_3])
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&HEIGHT_1));
        assert!(!result.contains_key(&HEIGHT_2));
        assert!(!result.contains_key(&HEIGHT_3));
    }

    #[tokio::test]
    async fn retryable_batch_failures_degrade_to_a_refetch() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .expect(3) // 1 attempt + 2 retries
            .create_async()
            .await;

        let client = test_client(&server.url());

        // fetch_blocks swallows errors and returns empty map
        let result = client.fetch_blocks(&[100, 101]).await.unwrap();

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
        let result = client.fetch_blocks_for_slots(slots).await.unwrap();

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
        let address = Pubkey::new_unique();
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
            // the vendored client's exact request
            // (rpc_client.rs:2786); None fields serialize as null
            .match_body(mockito::Matcher::Json(json!({
                "jsonrpc": "2.0", "id": 0, "method": "getSignaturesForAddress",
                "params": [address.to_string(), {
                    "before": null, "until": null, "limit": CATCHUP_PAGE_SIZE,
                    "commitment": "finalized", "minContextSlot": null
                }]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response.to_string())
            .create_async()
            .await;

        let client = test_client(&server.url());
        let sigs = client
            .fetch_signatures_from_latest(&address, None)
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
        let program_id = Pubkey::new_unique();

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
            // page 2 carries page 1's last signature as the cursor — the
            // Some arm of the config conversion
            .match_body(mockito::Matcher::Json(json!({
                "jsonrpc": "2.0", "id": 0, "method": "getSignaturesForAddress",
                "params": [program_id.to_string(), {
                    "before": sig_b, "until": null, "limit": CATCHUP_PAGE_SIZE,
                    "commitment": "finalized", "minContextSlot": null
                }]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page2)
            .expect(1)
            .create_async()
            .await;

        let client = SolanaClient::for_indexer(
            server.url().parse().unwrap(),
            program_id,
            Arc::new(NoopPublisherTelemetry),
            SharedBackoff::new(),
        )
        .with_fast_retry();
        let sigs = client.fetch_signatures(100, 200).await.unwrap();

        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].slot, 200);
        assert_eq!(sigs[1].slot, 150);
    }

    #[tokio::test]
    async fn node_unhealthy_renders_do_not_invert_the_default() {
        // "behind by 401/429 slots" in the body message must not reach
        // the string fallback
        for slots_behind in [401u64, 429] {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({
                        "jsonrpc": "2.0", "id": 0,
                        "error": {
                            "code": JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY,
                            "message": format!("Node is behind by {slots_behind} slots")
                        }
                    })
                    .to_string(),
                )
                .expect(3)
                .create_async()
                .await;

            let client = test_client(&server.url());
            let err = client.get_slot_finalized().await.unwrap_err();
            assert!(is_retryable(&err), "{slots_behind}: {err:#}");
            assert!(!is_provider_throttled(&err), "{slots_behind}: {err:#}");
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn missing_signatures_history_stays_retryable() {
        // deterministic per node, but another LB backend may keep history
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "error": {
                        "code": JSON_RPC_SERVER_ERROR_TRANSACTION_HISTORY_NOT_AVAILABLE,
                        "message": "Transaction history is not available from this node"
                    }
                })
                .to_string(),
            )
            .expect(3)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let err = client
            .fetch_signatures_from_latest(&Pubkey::new_unique(), None)
            .await
            .unwrap_err();
        assert!(is_retryable(&err), "{err:#}");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn null_results_map_to_absent() {
        // null is a legal success for absent blocks; one null item must not
        // fail the batch — usize::MAX retries would stall the drain
        const HEIGHT_1: u64 = 100;
        const NULL_SLOT: u64 = 101;
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([make_block_response(0, HEIGHT_1), {"id": 1, "result": null}]).to_string(),
            )
            .expect(1) // the null item is not a batch failure
            .create_async()
            .await;

        let client = test_client(&server.url());
        let blocks = client
            .fetch_blocks_for_slots(BTreeSet::from([HEIGHT_1, NULL_SLOT]))
            .await
            .unwrap();
        assert!(matches!(
            blocks.get(&HEIGHT_1),
            Some(SolanaCatchupBlock::Block(_))
        ));
        assert!(matches!(
            blocks.get(&NULL_SLOT),
            Some(SolanaCatchupBlock::Missing)
        ));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn undecodable_batch_bodies_retry() {
        // a misrouted gateway answering 200 with HTML: the decode failure is
        // statusless and must classify retryable, not terminal
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "text/html")
            .with_body("<html>502 Bad Gateway</html>")
            .expect(3)
            .create_async()
            .await;

        let client = test_client(&server.url());
        assert!(client.fetch_blocks(&[100]).await.unwrap().is_empty());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn both_field_envelopes_classify_by_their_error() {
        // invalid per JSON-RPC 2.0, but "error present ⇒ Err" is total — the
        // paired result must not deliver the block
        const HEIGHT_1: u64 = 100;
        const CONTESTED: u64 = 101;
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    {
                        "id": 0,
                        "result": make_block_response(0, CONTESTED)["result"],
                        "error": {
                            "code": JSON_RPC_SERVER_ERROR_SLOT_SKIPPED,
                            "message": "Slot was skipped"
                        }
                    },
                    make_block_response(1, HEIGHT_1)
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let result = client.fetch_blocks(&[CONTESTED, HEIGHT_1]).await.unwrap();
        assert_eq!(result.len(), 1, "the error side must win the envelope");
        assert!(result.contains_key(&HEIGHT_1));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn network_skipped_slots_are_terminal_with_their_code() {
        for (code, message) in [
            (JSON_RPC_SERVER_ERROR_SLOT_SKIPPED, "Slot was skipped"),
            (
                JSON_RPC_SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED,
                "Slot was skipped because it is in long-term storage",
            ),
        ] {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}})
                        .to_string(),
                )
                // a retry can never produce the block on any backend
                .expect(1)
                .create_async()
                .await;

            let client = test_client(&server.url());
            let err = client.get_block(1234).await.unwrap_err();
            assert!(
                !is_retryable(&err),
                "code {code} should be terminal: {err:#}"
            );
            let carried = err
                .chain()
                .find_map(|c| c.downcast_ref::<RpcFailure>())
                .and_then(|f| f.code());
            assert_eq!(carried, Some(code));
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn null_id_error_envelopes_keep_their_verdict() {
        // JSON-RPC 2.0 permits id: null on error responses; the decode
        // must not swallow the terminal code into a retryable
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": null,
                    "error": {
                        "code": JSON_RPC_SERVER_ERROR_SLOT_SKIPPED,
                        "message": "Slot was skipped"
                    }
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let err = client.get_block(1234).await.unwrap_err();
        assert!(!is_retryable(&err), "{err:#}");
        assert_eq!(skipped_code(&err), Some(JSON_RPC_SERVER_ERROR_SLOT_SKIPPED));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn node_local_absence_stays_retryable() {
        // another LB backend may still serve these
        for (code, message) in [
            (
                JSON_RPC_SERVER_ERROR_BLOCK_NOT_AVAILABLE,
                "Block not available for slot 1234",
            ),
            (JSON_RPC_SERVER_ERROR_BLOCK_CLEANED_UP, "Block cleaned up"),
            (
                JSON_RPC_SERVER_ERROR_LONG_TERM_STORAGE_UNREACHABLE,
                "Failed to query long-term storage; please try again",
            ),
            (
                JSON_RPC_SERVER_ERROR_BLOCK_STATUS_NOT_AVAILABLE_YET,
                "Block status not yet available",
            ),
        ] {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}})
                        .to_string(),
                )
                .expect(3) // 1 attempt + 2 retries
                .create_async()
                .await;

            let client = test_client(&server.url());
            let err = client.get_block(1234).await.unwrap_err();
            assert!(
                is_retryable(&err),
                "code {code} should be retryable: {err:#}"
            );
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn read_statuses_follow_the_read_partition() {
        // 409 is send-terminal; the read partition retries it
        let mut server = mockito::Server::new_async().await;
        let conflict = server
            .mock("POST", "/")
            .with_status(409)
            .expect(3) // full budget: 1 attempt + 2 retries
            .create_async()
            .await;
        let client = test_client(&server.url());
        let err = client.get_slot_finalized().await.unwrap_err();
        assert!(is_retryable(&err), "{err:#}");
        conflict.assert_async().await;

        // classic client errors are terminal reads
        let mut server = mockito::Server::new_async().await;
        let not_found = server
            .mock("POST", "/")
            .with_status(404)
            .expect(1)
            .create_async()
            .await;
        let gate = SharedBackoff::new();
        let client = test_client_with_gate(&server.url(), gate.clone());
        let err = client.get_slot_finalized().await.unwrap_err();
        assert!(!is_retryable(&err), "{err:#}");
        assert_eq!(gate.remaining(), Duration::ZERO);
        not_found.assert_async().await;
    }

    #[tokio::test]
    async fn batch_throttling_engages_the_shared_gate() {
        let mut server = mockito::Server::new_async().await;
        let throttled = server
            .mock("POST", "/")
            .with_status(429)
            .expect(3)
            .create_async()
            .await;

        // cooldowns above backon's 1-10ms delays, so the gated waits are observable
        let gate =
            SharedBackoff::with_cooldowns(Duration::from_millis(300), Duration::from_millis(600));
        let client = test_client_with_gate(&server.url(), gate.clone());
        let start = std::time::Instant::now();
        let blocks = client.fetch_blocks(&[100, 101]).await.unwrap();
        assert!(blocks.is_empty());
        // attempts 2 and 3 waited out the 300ms and 600ms windows
        assert!(
            start.elapsed() >= Duration::from_millis(800),
            "gated retries must wait out the cooldowns, took {:?}",
            start.elapsed()
        );
        assert!(gate.remaining() > Duration::ZERO);
        throttled.assert_async().await;
    }

    #[tokio::test]
    async fn read_throttling_engages_the_shared_gate() {
        // a 429 used to surface as the vendored sender's timeout, so the
        // gate never engaged on reads
        let mut server = mockito::Server::new_async().await;
        let throttled = server
            .mock("POST", "/")
            .with_status(429)
            .expect(3) // 1 attempt + 2 retries
            .create_async()
            .await;

        let gate =
            SharedBackoff::with_cooldowns(Duration::from_millis(300), Duration::from_millis(600));
        let client = test_client_with_gate(&server.url(), gate.clone());
        let start = std::time::Instant::now();
        let err = client.get_slot_finalized().await.unwrap_err();
        assert!(is_retryable(&err), "{err:#}");
        assert!(is_provider_throttled(&err), "{err:#}");
        assert!(
            start.elapsed() >= Duration::from_millis(800),
            "gated retries must wait out the cooldowns, took {:?}",
            start.elapsed()
        );
        assert!(gate.remaining() > Duration::ZERO);
        throttled.assert_async().await;
    }

    #[tokio::test]
    async fn batch_statuses_follow_the_read_partition() {
        // 409 is send-terminal — the read table must retry it to exhaustion
        let mut server = mockito::Server::new_async().await;
        let conflict = server
            .mock("POST", "/")
            .with_status(409)
            .expect(3)
            .create_async()
            .await;

        let client = test_client(&server.url());
        assert!(client.fetch_blocks(&[100]).await.unwrap().is_empty());
        conflict.assert_async().await;
    }

    #[tokio::test]
    async fn terminal_batch_failures_propagate() {
        let mut server = mockito::Server::new_async().await;
        let not_found = server
            .mock("POST", "/")
            .with_status(404)
            .expect(1)
            .create_async()
            .await;

        let gate = SharedBackoff::new();
        let client = test_client_with_gate(&server.url(), gate.clone());
        let err = client.fetch_blocks(&[100]).await.unwrap_err();
        assert!(!is_retryable(&err), "{err:#}");
        assert_eq!(gate.remaining(), Duration::ZERO);
        not_found.assert_async().await;
    }

    #[tokio::test]
    async fn terminal_batch_failures_propagate_through_for_slots() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("POST", "/")
            .with_status(401)
            .expect(1)
            .create_async()
            .await;

        let client = test_client(&server.url());
        // Err, not an Ok full of Missing — no per-slot refetch fan-out
        let err = client
            .fetch_blocks_for_slots(BTreeSet::from([100, 101]))
            .await
            .unwrap_err();
        assert!(!is_retryable(&err), "{err:#}");
        unauthorized.assert_async().await;
    }

    #[tokio::test]
    async fn statusless_failures_are_retryable_and_never_throttled() {
        // the ":429" port renders in the error; the explicit retryable
        // carrier keeps the string fallback from reading it as a throttle
        let client = test_client("http://127.0.0.1:429");
        let err = client.get_slot_finalized().await.unwrap_err();
        assert!(is_retryable(&err), "{err:#}");
        assert!(!is_provider_throttled(&err), "{err:#}");

        let reqwest_err = reqwest::Client::new()
            .post("http://127.0.0.1:429")
            .send()
            .await
            .unwrap_err();
        let err = classify_batch(reqwest_err);
        assert!(is_retryable(&err));
        assert!(!is_provider_throttled(&err));
    }

    #[tokio::test]
    async fn null_block_results_classify_retryable() {
        // providers send null for absent blocks; the vendored client also
        // treated it as a retryable decode failure
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":0,"result":null}"#)
            .expect(3) // 1 attempt + 2 retries
            .create_async()
            .await;

        let client = test_client(&server.url());
        let err = client.get_block(1234).await.unwrap_err();
        assert!(is_retryable(&err), "{err:#}");
        assert!(!is_provider_throttled(&err), "{err:#}");
        mock.assert_async().await;
    }
}
