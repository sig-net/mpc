use super::{ChainPublisher, PublishAction};
use crate::indexer_eth::abi::ChainSignatures;
use crate::indexer_eth::EthConfig;
use crate::util::retry::{retry_rpc, RetryConfig};
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{
    fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    Provider, ProviderBuilder, RootProvider, WalletProvider,
};
use alloy::rpc::types::TransactionReceipt;
use alloy_signer_local::PrivateKeySigner;
use k256::elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint};
use mpc_primitives::{SignId, Signature};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};
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

// Send Ethereum tx retry constants
const ETH_SEND_MAX_ATTEMPTS: usize = 3;
const ETH_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const ETH_SEND_MIN_DELAY: Duration = Duration::from_millis(500);
const ETH_SEND_MAX_DELAY: Duration = Duration::from_secs(10);

// Polling Receipt
const ETH_RECEIPT_TIMEOUT: Duration = Duration::from_secs(2);
const ETH_RECEIPT_MIN_DELAY: Duration = Duration::from_secs(1);
const ETH_RECEIPT_MAX_DELAY: Duration = Duration::from_secs(20);

// Ethereum gas limits
const ETH_BASE_GAS_LIMIT: u64 = 40_000;
const ETH_BATCH_GAS_PER_REQUEST: u64 = 20_000;

/// The maximum number of attempts to fetch eth tx and its receipt
const ETH_TX_RECEIPT_MAX_ATTEMPTS: usize = 6;

/// The interval to batch send Ethereum responses
const ETH_RESPOND_BATCH_INTERVAL: Duration = Duration::from_millis(2000);
/// The batch size for Ethereum responses
const ETH_RESPOND_BATCH_SIZE: usize = 10;

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

/// TODO: this should probably get merged with the client used by indexer
#[derive(Clone)]
pub struct EthClient {
    // The contract instance for interacting with the ChainSignatures contract
    contract: ChainSignatures::ChainSignaturesInstance<EthContractFillProvider>,
    // Channel used to send actions to the background batching task
    batch_tx: mpsc::Sender<PublishAction>,
}

impl EthClient {
    pub fn new(eth: &EthConfig) -> Self {
        let signer: PrivateKeySigner = eth
            .account_sk
            .parse()
            .expect("cannot parse Eth account sk into PrivateKeySigner");
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(eth.execution_rpc_http_url.parse().unwrap());

        // Build the contract instance
        let address = Address::from_str(&format!("0x{}", eth.contract_address)).unwrap();
        let contract = ChainSignatures::new(address, provider);

        let (batch_tx, batch_rx) = mpsc::channel(super::MAX_CONCURRENT_RPC_REQUESTS);

        let client = Self { contract, batch_tx };

        // Spawn the background batching loop
        let client_clone = client.clone();
        tokio::spawn(async move {
            client_clone.run_batch_respond(batch_rx).await;
        });

        client
    }

    /// Run the background batching loop that collects publish actions and sends them in batches to the Ethereum contract.
    async fn run_batch_respond(self, mut actions_rx: mpsc::Receiver<PublishAction>) {
        let mut start = Instant::now();
        let mut actions_batch: Vec<PublishAction> = vec![];
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if (start.elapsed() > ETH_RESPOND_BATCH_INTERVAL
                || actions_batch.len() >= ETH_RESPOND_BATCH_SIZE)
                && !actions_batch.is_empty()
            {
                tracing::info!(
                    num_requests = actions_batch.len(),
                    "publishing batch of ethereum signatures",
                );
                self.execute_batch_publish(&mut actions_batch).await;
                start = Instant::now();
            }
            if let Ok(action) = actions_rx.try_recv() {
                actions_batch.push(action);
            }
        }
    }

    /// Execute a batch publish of signatures to the Ethereum contract, with retry logic.
    async fn execute_batch_publish(&self, actions: &mut Vec<PublishAction>) {
        let signatures: HashMap<SignId, Signature> = actions
            .iter()
            .map(|action| (action.indexed.id, action.signature))
            .collect();

        let retry_config = RetryConfig {
            max_times: usize::MAX,
            min_delay: super::BATCH_PUBLISH_MIN_DELAY,
            max_delay: super::BATCH_PUBLISH_MAX_DELAY,
            jitter: true,
        };

        let res = retry_rpc!(
            Duration::MAX, // Prevent from timing out
            retry_config,
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
                super::record_publish_metrics(action);
            }
        } else {
            tracing::error!("exceeded max retries, trashing publish request");
        }

        actions.clear();
    }

    /// Wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
    async fn wait_for_transaction_receipt(
        &self,
        tx_hash: B256,
        sign_ids: &[SignId],
    ) -> anyhow::Result<TransactionReceipt> {
        let retry_config = RetryConfig {
            max_times: ETH_TX_RECEIPT_MAX_ATTEMPTS,
            min_delay: ETH_RECEIPT_MIN_DELAY,
            max_delay: ETH_RECEIPT_MAX_DELAY,
            jitter: true,
        };

        retry_rpc!(
            ETH_RECEIPT_TIMEOUT,
            retry_config,
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
        let send_retry = RetryConfig {
            max_times: ETH_SEND_MAX_ATTEMPTS,
            min_delay: ETH_SEND_MIN_DELAY,
            max_delay: ETH_SEND_MAX_DELAY,
            jitter: true,
        };

        retry_rpc!(
            ETH_SEND_TIMEOUT,
            send_retry,
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

    pub async fn batch_publish_signatures(
        &self,
        actions: &[PublishAction],
        signatures: &HashMap<SignId, Signature>,
    ) -> anyhow::Result<()> {
        let num_requests = actions.len();
        let sign_ids: Vec<_> = actions.iter().map(|a| a.indexed.id).collect();

        let responses: Vec<ChainSignatures::Response> = actions
            .iter()
            .map(|action| {
                let mpc_sig = signatures
                    .get(&action.indexed.id)
                    .expect("signature not found");
                ChainSignatures::Response {
                    requestId: action.indexed.id.request_id.into(),
                    signature: mpc_sig.into(),
                }
            })
            .collect();

        // TODO: Consider using a more accurate dynamic gas estimation
        let gas = std::cmp::max(
            ETH_BASE_GAS_LIMIT,
            ETH_BATCH_GAS_PER_REQUEST * num_requests as u64,
        );

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
    use alloy::primitives::{B256, U256};
    use k256::{AffinePoint, Scalar};
    use mockito::{Matcher, Server};
    use serde_json::json;

    fn create_test_signature() -> mpc_primitives::Signature {
        mpc_primitives::Signature::new(AffinePoint::GENERATOR, Scalar::from(42u64), 1)
    }

    fn mock_config(url: &str) -> EthConfig {
        EthConfig {
            account_sk: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            execution_rpc_http_url: url.to_string(),
            contract_address: "1234567890123456789012345678901234567890".to_string(),
            consensus_rpc_http_url: "".to_string(),
            network: "sepolia".to_string(),
            helios_data_path: "".to_string(),
            refresh_finalized_interval: 1000,
            optimistic_requests: false,
            light_client: false,
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

        let client = EthClient::new(&mock_config(&server.url()));
        let receipt = client
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

        let client = EthClient::new(&mock_config(&server.url()));

        // Attempt to send
        let result = client
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

        let client = EthClient::new(&mock_config(&server.url()));

        // Execute the full publish pipeline
        let result = client
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

        let client = EthClient::new(&mock_config(&server.url()));

        let result = client
            .execute_publish(vec![], 21000, &[SignId::new([5u8; 32])])
            .await;

        // Assert the happy path returns Ok
        assert!(
            result.is_ok(),
            "The happy path should complete successfully"
        );
    }
}
