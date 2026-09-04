use crate::abi::ChainSignatures;
use crate::config::{GasConfig, PublisherConfig};
use crate::EthConfig;
use alloy::network::EthereumWallet;
use alloy::primitives::{B256, U256};
use alloy::providers::{
    fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    Provider, ProviderBuilder, RootProvider, WalletProvider,
};
use alloy::rpc::types::TransactionReceipt;
use k256::elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint};
use mpc_chain_integration_core::{
    utils::retry::{retry_rpc_gated, SharedBackoff},
    ChainPublisher, PublishAction, PublisherTelemetry,
};
use mpc_primitives::{SignId, Signature};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

type EthContractFillProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

/// Convert MPC Signature to ChainSignatures::Signature
impl From<&Signature> for ChainSignatures::Signature {
    fn from(mpc_sig: &Signature) -> Self {
        ChainSignatures::Signature {
            bigR: ChainSignatures::AffinePoint {
                x: U256::from_be_slice(&mpc_sig.big_r.x()),
                y: U256::from_be_slice(mpc_sig.big_r.to_encoded_point(false).y().unwrap()),
            },
            s: U256::from_be_slice(&mpc_sig.s.to_bytes()),
            recoveryId: mpc_sig.recovery_id,
        }
    }
}

/// An Ethereum client that implements the `ChainPublisher` trait for publishing signatures to an Ethereum smart contract.
/// This client is separate from the client used by the indexer (separation of concerns: read vs write).
#[derive(Clone)]
pub struct EthClient {
    /// Channel used to send actions to the background batching task
    batch_tx: mpsc::Sender<PublishAction>,
}

/// Publishing machinery for the background batching task.
///
/// Kept separate from `EthClient` so the spawned task owns no channel sender —
/// otherwise the channel could never close and the batching loop could never
/// shut down. Once every `EthClient` clone is dropped, the channel closes and
/// the loop flushes any leftover batch and exits.
#[derive(Clone)]
struct BatchPublisher {
    /// The contract instance for interacting with the ChainSignatures contract
    contract: ChainSignatures::ChainSignaturesInstance<EthContractFillProvider>,
    /// Telemetry interface for recording metrics related to publishing signatures
    telemetry: Arc<dyn PublisherTelemetry>,
    /// Gas configuration for estimating and clamping gas limits
    gas: GasConfig,
    /// Publisher configuration for controlling batching and retry behavior
    config: PublisherConfig,
    /// Node-wide 429 cooldown gate shared with the indexer's read client
    shared_backoff: SharedBackoff,
}

impl EthClient {
    pub fn new(
        eth: &EthConfig,
        telemetry: Arc<dyn PublisherTelemetry>,
        shared_backoff: SharedBackoff,
    ) -> Self {
        let (batch_tx, batch_rx) = mpsc::channel(eth.publisher.channel_capacity);

        // Spawn the background batching loop; it owns no sender, so it can shut
        // down once every EthClient is dropped.
        let batcher = BatchPublisher::new(eth, telemetry, shared_backoff);
        tokio::spawn(async move {
            batcher.run_batch_respond(batch_rx).await;
        });

        Self { batch_tx }
    }
}

impl BatchPublisher {
    fn new(
        eth: &EthConfig,
        telemetry: Arc<dyn PublisherTelemetry>,
        shared_backoff: SharedBackoff,
    ) -> Self {
        let wallet = EthereumWallet::from(eth.account_sk.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(eth.execution_rpc_http_url.clone());

        Self {
            contract: ChainSignatures::new(eth.contract_address, provider),
            telemetry,
            gas: eth.gas.clone(),
            config: eth.publisher.clone(),
            shared_backoff,
        }
    }

    /// Run the background batching loop that collects publish actions and sends them in batches to the Ethereum contract.
    ///
    /// A batch is flushed once it reaches `max_batch_size`, or `batch_flush_interval` after its
    /// first action was queued.
    async fn run_batch_respond(self, mut actions_rx: mpsc::Receiver<PublishAction>) {
        let mut actions_batch: Vec<PublishAction> = Vec::with_capacity(self.config.max_batch_size);
        // Starts with a sleep of Duration::MAX, which will be reset when the first action is received.
        let flush_timer = tokio::time::sleep(Duration::MAX);
        tokio::pin!(flush_timer);

        loop {
            // Check if the batch is empty before receiving new actions.
            let is_empty = actions_batch.is_empty();

            // Determine the capacity for receiving new actions based on the current batch size and max batch size.
            let capacity = self
                .config
                .max_batch_size
                .saturating_sub(actions_batch.len())
                .max(1);

            tokio::select! {
                // Receive new actions from the channel and add them to the batch.
                received = actions_rx.recv_many(&mut actions_batch, capacity) => {
                    if received == 0 {
                        // All senders dropped: flush what's left and shut down.
                        if !actions_batch.is_empty() {
                            self.execute_batch_publish(&mut actions_batch).await;
                        }
                        return;
                    }
                    if is_empty {
                        flush_timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + self.config.batch_flush_interval);
                    }
                }
                // Flush the batch if the flush timer has elapsed and the batch is not empty.
                _ = &mut flush_timer, if !actions_batch.is_empty() => {
                    self.execute_batch_publish(&mut actions_batch).await;
                }
            }

            // Flush the batch if it has reached the maximum batch size.
            if actions_batch.len() >= self.config.max_batch_size {
                self.execute_batch_publish(&mut actions_batch).await;
            }
        }
    }

    /// Execute a batch publish of signatures to the Ethereum contract, with retry logic.
    async fn execute_batch_publish(&self, actions: &mut Vec<PublishAction>) {
        tracing::info!(
            num_requests = actions.len(),
            "publishing batch of ethereum signatures",
        );
        let signatures: HashMap<SignId, Signature> = actions
            .iter()
            .map(|action| (action.request.id, action.signature))
            .collect();

        let res = retry_rpc_gated!(
            Duration::MAX, // Prevent from timing out
            self.config.batch_publish_retry,
            self.shared_backoff,
            |attempt, err, sleep| {
                tracing::warn!(
                    "batch publish failed (attempt {attempt}): {err}, retrying in {sleep:?}"
                );
            },
            { self.batch_publish_signatures(actions, &signatures).await }
        );

        // Log metrics for successful publishes, or log an error if all retries failed
        if res.is_ok() {
            for action in actions.iter() {
                self.telemetry.record_publish_metrics(action);
            }
        } else {
            tracing::error!("exceeded max retries, trashing publish request");
        }

        actions.clear();
    }

    /// Wait for transaction receipt with the configured attempts and exponential delay backoff
    async fn wait_for_transaction_receipt(
        &self,
        tx_hash: B256,
        sign_ids: &[SignId],
    ) -> anyhow::Result<TransactionReceipt> {
        retry_rpc_gated!(
            self.config.receipt_timeout,
            self.config.receipt_retry,
            self.shared_backoff,
            // Log the error and retry attempt
            |attempt, err, sleep| {
                tracing::error!(
                    ?sign_ids,
                    attempt,
                    "failed to get eth signature respond transaction receipt: {err}, retrying in {sleep:?}"
                );
            },
            // Try to get the transaction receipt
            {
                match self
                    .contract
                    .provider()
                    .get_transaction_receipt(tx_hash)
                    .await
                {
                    Ok(Some(receipt)) => {
                        tracing::info!(
                            ?sign_ids,
                            "eth signature respond transaction receipt found"
                        );
                        Ok(receipt)
                    }
                    Ok(None) => Err(anyhow::anyhow!("Receipt not ready yet")),
                    Err(e) => Err(anyhow::anyhow!("RPC Error: {e}")),
                }
            }
        )
    }

    async fn send_responses(
        &self,
        responses: Vec<ChainSignatures::Response>,
        gas: u64,
        sign_ids: &[SignId],
    ) -> anyhow::Result<B256> {
        retry_rpc_gated!(
            self.config.send_timeout,
            self.config.send_retry,
            self.shared_backoff,
            |attempt, err, sleep| {
                tracing::warn!(
                    ?sign_ids,
                    attempt,
                    "send eth tx failed: {err}, retrying in {sleep:?}"
                );
            },
            {
                // TODO: fetching nonce from RPC is slow and expensive, consider better approach (fetch once, increment locally, etc.)
                // Fetch nonce here in the retry loop, otherwise we may get the same nonce on retry
                let nonce = self
                    .contract
                    .provider()
                    .get_transaction_count(self.contract.provider().default_signer_address())
                    .pending()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to fetch nonce: {e}"))?;

                tracing::info!(
                    nonce,
                    "will send eth tx with nonce {nonce} for sign_ids: {:?}",
                    sign_ids
                );

                self.contract
                    .respond(responses.clone()) // Need to clone because closure has to implement `FnMut` (otherwise it's `FnOnce`)
                    .gas(gas)
                    .nonce(nonce)
                    .send()
                    .await
                    .map(|pending| *pending.tx_hash())
                    .map_err(|e| anyhow::anyhow!("RPC Error: {e}"))
            }
        )
    }

    /// Shared logic to send the transaction, wait for the receipt, and verify success.
    async fn execute_publish(
        &self,
        responses: Vec<ChainSignatures::Response>,
        gas: u64,
        sign_ids: &[SignId],
    ) -> anyhow::Result<()> {
        let tx_hash = self.send_responses(responses, gas, sign_ids).await?;
        let receipt = self.wait_for_transaction_receipt(tx_hash, sign_ids).await?;

        if !receipt.status() {
            tracing::error!(?sign_ids, ?tx_hash, "ethereum transaction failed");
            anyhow::bail!("Ethereum transaction reverted");
        }

        tracing::info!(
            ?sign_ids,
            ?tx_hash,
            "ethereum transaction published successfully"
        );
        Ok(())
    }

    /// Estimate the gas limit for a batch of responses.
    ///
    /// Uses the node's `eth_estimateGas` then applies the configured buffer to
    /// absorb variance. On failure falls back to a conservative static
    /// heuristic based on the batch size.
    async fn estimate_batch_gas(
        &self,
        responses: &[ChainSignatures::Response],
        num_requests: u64,
    ) -> u64 {
        let call = self.contract.respond(responses.to_vec());
        match call.estimate_gas().await {
            Ok(est) => self.gas.clamp_estimate(est),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    num_requests,
                    "dynamic gas estimation failed, falling back to static heuristic"
                );
                self.gas.fallback_gas(num_requests)
            }
        }
    }

    async fn batch_publish_signatures(
        &self,
        actions: &[PublishAction],
        signatures: &HashMap<SignId, Signature>,
    ) -> anyhow::Result<()> {
        let num_requests = actions.len();
        let sign_ids: Vec<_> = actions.iter().map(|a| a.request.id).collect();

        let responses: Vec<ChainSignatures::Response> = actions
            .iter()
            .map(|action| {
                let mpc_sig = signatures
                    .get(&action.request.id)
                    .expect("signature not found");
                ChainSignatures::Response {
                    requestId: action.request.id.request_id.into(),
                    signature: mpc_sig.into(),
                }
            })
            .collect();

        let gas = self
            .estimate_batch_gas(&responses, num_requests as u64)
            .await;

        self.execute_publish(responses, gas, &sign_ids).await?;

        tracing::info!(num_requests, "batch publish complete");
        Ok(())
    }
}

#[async_trait::async_trait]
impl ChainPublisher for EthClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        // Push to internal batching queue
        self.batch_tx
            .send(action.clone())
            .await
            .map_err(|e| anyhow::anyhow!("eth: batch channel closed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256, U256};
    use k256::{AffinePoint, Scalar};
    use mockito::{Matcher, Mock, Server};
    use mpc_chain_integration_core::utils::retry::RetryConfig;
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_chain_integration_core::NoopPublisherTelemetry;
    use mpc_primitives::{Chain, SignKind};
    use serde_json::json;

    fn mock_publish_action(id: u8) -> PublishAction {
        make_publish_action(Chain::Ethereum, SignKind::Sign, SignId::new([id; 32]))
    }

    /// Poll until `mock` has been hit the expected number of times, or panic.
    async fn wait_for_hits(mock: &Mock, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while !mock.matched_async().await {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for expected mock hits"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Mocks the full happy-path publish pipeline: nonce fetch, tx send and a success receipt.
    /// Returns the send mock for hit-count assertions.
    async fn mock_publish_pipeline(
        server: &mut Server,
        tx_hash: B256,
        expected_sends: usize,
    ) -> Mock {
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionCount"}),
            ))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string())
            .expect_at_least(expected_sends)
            .create_async()
            .await;

        let send_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_sendRawTransaction"}),
            ))
            .with_status(200)
            .with_body(
                json!({"jsonrpc": "2.0", "id": 1, "result": format!("{tx_hash:#x}")}).to_string(),
            )
            .expect(expected_sends)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionReceipt"}),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": mock_receipt_json(tx_hash, "0x1")
                })
                .to_string(),
            )
            .expect(expected_sends)
            .create_async()
            .await;

        send_mock
    }

    fn create_test_signature() -> mpc_primitives::Signature {
        mpc_primitives::Signature::new(AffinePoint::GENERATOR, Scalar::from(42u64), 1)
    }

    fn mock_config(url: &str) -> EthConfig {
        EthConfig {
            account_sk: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .parse()
                .unwrap(),
            execution_rpc_http_url: url.parse().unwrap(),
            contract_address: "1234567890123456789012345678901234567890".parse().unwrap(),
            consensus_rpc_http_url: "".to_string(),
            network: "sepolia".to_string(),
            helios_data_path: "".to_string(),
            refresh_finalized_interval: 1000,
            optimistic_requests: false,
            light_client: false,
            rpc: Default::default(),
            gas: Default::default(),
            publisher: Default::default(),
            indexer: Default::default(),
        }
    }

    fn mock_receipt_json(tx_hash: B256, status: &str) -> serde_json::Value {
        json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "status": status,
            "blockHash": format!("{:#x}", B256::repeat_byte(0xbb)),
            "blockNumber": "0x2",
            "transactionIndex": "0x0",
            "from": format!("{:#x}", Address::ZERO),
            "to": format!("{:#x}", Address::ZERO),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": []
        })
    }

    /// Alloy's FillProvider automatically queries the network to estimate gas and fees
    /// before submitting a transaction. We must mock these to prevent mockito from panicking.
    async fn mock_alloy_background_rpcs(server: &mut Server) {
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"method": "eth_chainId"})))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string())
            .expect_at_least(0)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"method": "eth_feeHistory"})))
            .with_status(200)
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": {
                        "oldestBlock": "0x1",
                        "reward": [["0x1"]],
                        "baseFeePerGas": ["0x1", "0x1"],
                        "gasUsedRatio": [0.5]
                    }
                })
                .to_string(),
            )
            .expect_at_least(0)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getBlockByNumber"}),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": {
                        "number": "0x1",
                        "baseFeePerGas": "0x1",
                        "timestamp": "0x1"
                    }
                })
                .to_string(),
            )
            .expect_at_least(0)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"method": "eth_estimateGas"})))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x5208"}).to_string())
            .expect_at_least(0)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_maxPriorityFeePerGas"}),
            ))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string())
            .expect_at_least(0)
            .create_async()
            .await;
    }

    fn test_publisher(url: &str) -> BatchPublisher {
        BatchPublisher::new(
            &mock_config(url),
            Arc::new(NoopPublisherTelemetry),
            SharedBackoff::new(),
        )
    }

    #[tokio::test]
    async fn publisher_429_engages_shared_backoff_gate() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/")
            // 1 initial + max_times(2) retries per op, 2 concurrent ops.
            // Ungated, all 6 would fire within ~25ms of local backoff.
            .expect(6)
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        let mut cfg = mock_config(&server.url());
        cfg.publisher.send_retry = RetryConfig {
            min_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            max_times: 2,
            jitter: false,
        };
        let gate =
            SharedBackoff::with_cooldowns(Duration::from_millis(50), Duration::from_millis(200));
        let publisher = BatchPublisher::new(&cfg, Arc::new(NoopPublisherTelemetry), gate);

        let start = std::time::Instant::now();
        let ids1 = [SignId::new([1u8; 32])];
        let ids2 = [SignId::new([2u8; 32])];
        let (r1, r2) = tokio::join!(
            publisher.send_responses(vec![], 21000, &ids1),
            publisher.send_responses(vec![], 21000, &ids2),
        );

        assert!(r1.is_err() && r2.is_err());
        assert!(r1.unwrap_err().to_string().contains("429"));
        // The gate forces retries into separate >= 50ms cooldown windows.
        assert!(start.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn test_signature_to_abi_conversion() {
        let mpc_sig = create_test_signature();
        let abi_sig: ChainSignatures::Signature = (&mpc_sig).into();

        assert_eq!(abi_sig.recoveryId, 1);
        assert_eq!(abi_sig.s, U256::from(42));
        assert_eq!(abi_sig.bigR.x, U256::from_be_slice(&mpc_sig.big_r.x()));
        assert_eq!(
            abi_sig.bigR.y,
            U256::from_be_slice(mpc_sig.big_r.to_encoded_point(false).y().unwrap())
        );
    }

    #[tokio::test]
    async fn test_wait_for_transaction_receipt_retries_on_null() {
        let mut server = Server::new_async().await;
        let tx_hash = B256::repeat_byte(0xcc);

        // First call returns null (pending in mempool)
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionReceipt"}),
            ))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": null}).to_string())
            .expect(1)
            .create_async()
            .await;

        // Second call returns reverted receipt
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionReceipt"}),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 2,
                    "result": mock_receipt_json(tx_hash, "0x0")
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let publisher = test_publisher(&server.url());
        let receipt = publisher
            .wait_for_transaction_receipt(tx_hash, &[SignId::new([2u8; 32])])
            .await
            .unwrap();

        // Assert it fetched successfully and caught the reverted status
        assert!(!receipt.status());
    }

    #[tokio::test]
    async fn test_send_eth_responses_refetches_nonce_on_retry() {
        let mut server = Server::new_async().await;
        mock_alloy_background_rpcs(&mut server).await;

        // Mock the nonce fetch.
        // We use expect_at_least(2) to prove the retry mechanism successfully fires and refetches.
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionCount"}),
            ))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string())
            .expect_at_least(2)
            .create_async()
            .await;

        // Mock the transaction send failing every time
        let send_mock = server.mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"method": "eth_sendRawTransaction"})))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "mock error"}}).to_string())
            .expect_at_least(2)
            .create_async().await;

        let publisher = test_publisher(&server.url());

        // Attempt to send
        let result = publisher
            .send_responses(vec![], 21000, &[SignId::new([3u8; 32])])
            .await;

        // Verify it failed completely
        assert!(result.is_err());

        // Assert that `eth_getTransactionCount` was called multiple times.
        nonce_mock.assert_async().await;
        send_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_execute_publish_fails_on_reverted_tx() {
        let mut server = Server::new_async().await;
        let tx_hash = B256::repeat_byte(0xaa);
        mock_alloy_background_rpcs(&mut server).await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionCount"}),
            ))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string())
            .create_async()
            .await;

        // Mock send succeeding
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_sendRawTransaction"}),
            ))
            .with_status(200)
            .with_body(
                json!({"jsonrpc": "2.0", "id": 1, "result": format!("{tx_hash:#x}")}).to_string(),
            )
            .create_async()
            .await;

        // Mock receipt showing a reverted transaction (status: "0x0")
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionReceipt"}),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": mock_receipt_json(tx_hash, "0x0")
                })
                .to_string(),
            )
            .create_async()
            .await;

        let publisher = test_publisher(&server.url());

        // Execute the full publish pipeline
        let result = publisher
            .execute_publish(vec![], 21000, &[SignId::new([4u8; 32])])
            .await;

        // It should return Err(()) because the receipt status was 0x0
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_publish_success() {
        let mut server = Server::new_async().await;
        let tx_hash = B256::repeat_byte(0x77);
        mock_alloy_background_rpcs(&mut server).await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionCount"}),
            ))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string())
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_sendRawTransaction"}),
            ))
            .with_status(200)
            .with_body(
                json!({"jsonrpc": "2.0", "id": 1, "result": format!("{tx_hash:#x}")}).to_string(),
            )
            .create_async()
            .await;

        // Mock the receipt confirming the transaction was mined successfully (status: "0x1")
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(
                json!({"method": "eth_getTransactionReceipt"}),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": mock_receipt_json(tx_hash, "0x1")
                })
                .to_string(),
            )
            .create_async()
            .await;

        let publisher = test_publisher(&server.url());

        let result = publisher
            .execute_publish(vec![], 21000, &[SignId::new([5u8; 32])])
            .await;

        // Assert the happy path returns Ok
        assert!(
            result.is_ok(),
            "The happy path should complete successfully"
        );
    }

    #[tokio::test]
    async fn test_estimate_batch_gas_uses_dynamic_estimate_with_buffer() {
        let mut server = Server::new_async().await;
        mock_alloy_background_rpcs(&mut server).await;

        // Node reports 500_000 gas for the `respond` call.
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"method": "eth_estimateGas"})))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x7a120"}).to_string())
            .expect(1)
            .create_async()
            .await;

        let publisher = test_publisher(&server.url());

        // 500_000 * 12 / 10 == 600_000
        let gas = publisher.estimate_batch_gas(&[], 1).await;
        assert_eq!(gas, 600_000);
    }

    #[tokio::test]
    async fn test_estimate_batch_gas_clamps_to_base_limit() {
        let mut server = Server::new_async().await;
        mock_alloy_background_rpcs(&mut server).await;

        // A suspiciously tiny estimate (well below the configured base gas limit) should be
        // lifted to the base limit so the tx is never under-funded.
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"method": "eth_estimateGas"})))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string())
            .expect(1)
            .create_async()
            .await;

        let publisher = test_publisher(&server.url());

        let gas = publisher.estimate_batch_gas(&[], 1).await;
        assert_eq!(gas, GasConfig::default().base_gas_limit);
    }

    #[tokio::test]
    async fn test_estimate_batch_gas_falls_back_on_estimation_error() {
        let mut server = Server::new_async().await;
        mock_alloy_background_rpcs(&mut server).await;

        // Node rejects the estimate (e.g. contract would revert).
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"method": "eth_estimateGas"})))
            .with_status(200)
            .with_body(
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "error": {"code": -32000, "message": "execution reverted"}
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let publisher = test_publisher(&server.url());

        // 3 requests -> static heuristic = max(40_000, 20_000 * 3) = 60_000.
        let gas = publisher.estimate_batch_gas(&[], 3).await;
        assert_eq!(gas, 60_000);
    }

    #[tokio::test]
    async fn test_run_batch_respond_flushes_full_batches_immediately() {
        let mut server = Server::new_async().await;
        let tx_hash = B256::repeat_byte(0x21);
        mock_alloy_background_rpcs(&mut server).await;
        let send_mock = mock_publish_pipeline(&mut server, tx_hash, 2).await;

        let mut batcher = test_publisher(&server.url());
        batcher.config.max_batch_size = 10;
        // Disable the interval so only batch-fullness triggers a flush.
        batcher.config.batch_flush_interval = Duration::from_secs(3600);

        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(batcher.run_batch_respond(rx));

        // 20 actions: two full batches must be published without waiting on the interval.
        for i in 0u8..20 {
            tx.send(mock_publish_action(i)).await.unwrap();
        }

        wait_for_hits(&send_mock, Duration::from_millis(1500)).await;
    }

    #[tokio::test]
    async fn test_run_batch_respond_flushes_partial_batch_after_interval() {
        let mut server = Server::new_async().await;
        let tx_hash = B256::repeat_byte(0x22);
        mock_alloy_background_rpcs(&mut server).await;
        let send_mock = mock_publish_pipeline(&mut server, tx_hash, 1).await;

        let mut batcher = test_publisher(&server.url());
        batcher.config.max_batch_size = 10;
        batcher.config.batch_flush_interval = Duration::from_millis(200);

        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(batcher.run_batch_respond(rx));

        // Fewer actions than a full batch: must still flush once the interval elapses.
        for i in 0u8..3 {
            tx.send(mock_publish_action(i)).await.unwrap();
        }

        wait_for_hits(&send_mock, Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn test_run_batch_respond_flushes_on_channel_close() {
        let mut server = Server::new_async().await;
        let tx_hash = B256::repeat_byte(0x23);
        mock_alloy_background_rpcs(&mut server).await;
        let send_mock = mock_publish_pipeline(&mut server, tx_hash, 1).await;

        let mut batcher = test_publisher(&server.url());
        batcher.config.max_batch_size = 10;
        // Interval longer than the test: only the channel close may trigger the flush.
        batcher.config.batch_flush_interval = Duration::from_secs(3600);

        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(batcher.run_batch_respond(rx));

        tx.send(mock_publish_action(1)).await.unwrap();
        // Drop the only sender: the channel closes, so the loop must flush the
        // leftover batch and exit.
        drop(tx);

        wait_for_hits(&send_mock, Duration::from_secs(5)).await;
    }
}
