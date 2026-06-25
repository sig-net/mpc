use super::PublishAction;
use crate::indexer_eth::abi::ChainSignatures;
use crate::indexer_eth::EthConfig;
use crate::util::retry::{retry_rpc, RetryConfig};
use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::primitives::U256;
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::ProviderBuilder;
use alloy::providers::{Provider, RootProvider, WalletProvider};
use alloy::rpc::types::{Transaction, TransactionReceipt};
use alloy_signer_local::PrivateKeySigner;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_primitives::{Chain, SignId, Signature};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};

type EthContractFillProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<
                alloy::providers::fillers::GasFiller,
                JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

// Get nonce retry constants
const ETH_NONCE_MAX_ATTEMPTS: usize = 3;
const ETH_NONCE_TIMEOUT: Duration = Duration::from_secs(2);
const ETH_NONCE_MIN_DELAY: Duration = Duration::from_millis(500);
const ETH_NONCE_MAX_DELAY: Duration = Duration::from_secs(5);

// Send Ethereum tx retry constants
const ETH_SEND_MAX_ATTEMPTS: usize = 3;
const ETH_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const ETH_SEND_MIN_DELAY: Duration = Duration::from_millis(500);
const ETH_SEND_MAX_DELAY: Duration = Duration::from_secs(10);

// Polling Mempool
const ETH_MEMPOOL_TIMEOUT: Duration = Duration::from_secs(5);
const ETH_MEMPOOL_MIN_DELAY: Duration = Duration::from_secs(1);
const ETH_MEMPOOL_MAX_DELAY: Duration = Duration::from_secs(10);

// Polling Receipt
const ETH_RECEIPT_TIMEOUT: Duration = Duration::from_secs(2);
const ETH_RECEIPT_MIN_DELAY: Duration = Duration::from_secs(1);
const ETH_RECEIPT_MAX_DELAY: Duration = Duration::from_secs(20);

// Ethereum gas limits
const ETH_BASE_GAS_LIMIT: u64 = 40_000;
const ETH_BATCH_GAS_PER_REQUEST: u64 = 20_000;

/// The maximum number of attempts to fetch eth tx and its receipt
const ETH_TX_RECEIPT_MAX_ATTEMPTS: usize = 6;

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

#[derive(Clone)]
pub struct EthClient {
    contract: ChainSignatures::ChainSignaturesInstance<EthContractFillProvider>,
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

        Self { contract }
    }
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_pending_tx(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<Transaction, ()> {
    let retry_config = RetryConfig {
        max_times: max_attempts,
        min_delay: ETH_MEMPOOL_MIN_DELAY,
        max_delay: ETH_MEMPOOL_MAX_DELAY,
        jitter: true,
    };

    retry_rpc!(
        ETH_MEMPOOL_TIMEOUT,
        retry_config,
        // Log the error and retry attempt
        |attempt, err, sleep| {
            tracing::error!(
                ?sign_ids,
                attempt,
                "failed to get eth signature respond pending transaction: {err}, retrying in {sleep:?}"
            );
        },
        // Try to get the pending transaction
        {
            match provider.get_transaction_by_hash(tx_hash).await {
                Ok(Some(tx)) => {
                    tracing::info!(?sign_ids, "eth signature respond pending transaction found");
                    Ok(tx)
                }
                Ok(None) => Err(anyhow::anyhow!("Transaction not in mempool yet")),
                Err(e) => Err(anyhow::anyhow!("RPC Error: {e}")),
            }
        }
    ).map_err(|_| ())
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_transaction_receipt(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<TransactionReceipt, ()> {
    let retry_config = RetryConfig {
        max_times: max_attempts,
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
            match provider.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => {
                    tracing::info!(?sign_ids, "eth signature respond transaction receipt found");
                    Ok(receipt)
                }
                Ok(None) => Err(anyhow::anyhow!("Receipt not ready yet")),
                Err(e) => Err(anyhow::anyhow!("RPC Error: {e}")),
            }
        }
    ).map_err(|_| ())
}

async fn send_eth_responses(
    contract: &ChainSignatures::ChainSignaturesInstance<EthContractFillProvider>,
    responses: Vec<ChainSignatures::Response>,
    gas: u64,
    sign_ids: &[SignId],
) -> Result<alloy::primitives::B256, ()> {
    // TODO: fetching nonce from RPC is slow and expensive, consider better approach (fetch once, increment locally, etc.)
    // 1. Fetch Nonce
    let nonce_retry = RetryConfig {
        max_times: ETH_NONCE_MAX_ATTEMPTS,
        min_delay: ETH_NONCE_MIN_DELAY,
        max_delay: ETH_NONCE_MAX_DELAY,
        jitter: true,
    };

    let nonce = match retry_rpc!(
        ETH_NONCE_TIMEOUT,
        nonce_retry,
        // Log the error and retry attempt
        |attempt, err, sleep| {
            tracing::warn!(
                ?sign_ids,
                attempt,
                "get_nonce failed: {err}, retrying in {sleep:?}"
            );
        },
        // Try to get the nonce
        {
            contract
                .provider()
                .get_transaction_count(contract.provider().default_signer_address())
                .pending()
                .await
                .map_err(|e| anyhow::anyhow!("RPC Error: {e}"))
        }
    ) {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(
                ?sign_ids,
                ?err,
                "failed to get nonce: retry attempts exhausted"
            );
            return Err(());
        }
    };

    tracing::info!(nonce, "will send eth tx with nonce");

    // 2. Send Tx
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
            contract
                .respond(responses.clone()) // Need to clone because closure has to implement `FnMut` (otherwise it's `FnOnce`)
                .gas(gas)
                .nonce(nonce)
                .send()
                .await
                .map(|pending| *pending.tx_hash())
                .map_err(|e| anyhow::anyhow!("RPC Error: {e}"))
        }
    )
    .map_err(|err| {
        tracing::error!(
            ?sign_ids,
            ?err,
            "failed to send ethereum signature transaction: retry attempts exhausted"
        );
    })
}

pub async fn try_publish_eth(
    eth: &EthClient,
    action: &PublishAction,
    timestamp: &Instant,
    mpc_sig: &mpc_primitives::Signature,
) -> Result<(), ()> {
    let sign_id = action.indexed.id;

    let response = ChainSignatures::Response {
        requestId: action.indexed.id.request_id.into(),
        signature: mpc_sig.into(),
    };

    let tx_hash = send_eth_responses(
        &eth.contract,
        vec![response],
        ETH_BASE_GAS_LIMIT,
        std::slice::from_ref(&action.indexed.id),
    )
    .await?;

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
        vec![action.indexed.id],
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    // Check if transaction was successful
    if !receipt.status() {
        tracing::error!(
            ?sign_id,
            tx_hash = ?receipt.transaction_hash,
            "transaction failed"
        );
        return Err(());
    }

    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        ?sign_id,
        tx_hash = ?tx_hash,
        elapsed = ?timestamp.elapsed(),
        "published ethereum signature successfully"
    );
    Ok(())
}

pub async fn try_batch_publish_eth(
    eth: &EthClient,
    actions: &Vec<PublishAction>,
    signatures: &HashMap<SignId, Signature>,
) -> Result<(), ()> {
    let chain = Chain::Ethereum;
    let num_requests = actions.len();
    let sign_ids = actions
        .iter()
        .map(|action| action.indexed.id)
        .collect::<Vec<_>>();

    tracing::info!(?sign_ids, "will send eth batch tx");

    // Map to typed ABI structs
    let responses: Vec<ChainSignatures::Response> = actions
        .iter()
        .map(|action| {
            let mpc_sig = signatures
                .get(&action.indexed.id)
                .expect("signature not found in map");

            ChainSignatures::Response {
                requestId: action.indexed.id.request_id.into(),
                signature: mpc_sig.into(),
            }
        })
        .collect();

    // Calculate Gas
    let gas = std::cmp::max(
        ETH_BASE_GAS_LIMIT,
        ETH_BATCH_GAS_PER_REQUEST * num_requests as u64,
    );

    // Send Transaction with typed ABI Call
    let tx_hash = send_eth_responses(&eth.contract, responses, gas, &sign_ids).await?;

    tracing::info!(?tx_hash, "sent eth tx");

    // Wait for mempool
    let tx = wait_for_pending_tx(
        eth.contract.provider(),
        tx_hash,
        sign_ids.clone(),
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    tracing::info!(?tx, "tx found in mempool");

    // Wait for receipt
    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
        sign_ids.clone(),
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    // Check status
    if !receipt.status() {
        tracing::error!(
            ?sign_ids,
            tx_hash = ?receipt.transaction_hash,
            "eth batch transaction failed"
        );
        return Err(());
    }

    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        ?chain,
        ?sign_ids,
        ?tx_hash,
        num_requests,
        "eth batch published ethereum signatures successfully"
    );
    Ok(())
}
