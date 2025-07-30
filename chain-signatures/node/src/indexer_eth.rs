use crate::protocol::{Chain, IndexedSignRequest};
use crate::storage::app_data_storage::AppDataStorage;
use crate::storage::sign_respond_tx_storage::SignRespondTxStorage;
use alloy::consensus::BlockHeader;
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::Log;
use alloy::sol_types::{sol, SolEvent};
use helios::common::types::{SubscriptionEvent, SubscriptionType};
use helios::ethereum::{config::networks::Network, EthereumClient, EthereumClientBuilder};
use k256::Scalar;
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::{fmt, path::PathBuf, str::FromStr, sync::LazyLock, time::Instant};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::time::Duration;

pub(crate) static MAX_SECP256K1_SCALAR: LazyLock<Scalar> = LazyLock::new(|| {
    Scalar::from_bytes(
        hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
});

type BlockNumber = u64;

#[derive(Clone)]
pub struct EthConfig {
    /// The ethereum account secret key used to sign eth respond txn.
    pub account_sk: String,
    /// Ethereum consensus HTTP RPC URL
    pub consensus_rpc_http_url: String,
    /// Ethereum excution HTTP RPC URL
    pub execution_rpc_http_url: String,
    /// The contract address to watch without the `0x` prefix
    pub contract_address: String,
    /// must be one of sepolia, mainnet
    pub network: String,
    /// path to store helios data
    pub helios_data_path: String,
    /// refresh finalized block interval in milliseconds
    pub refresh_finalized_interval: u64,
    /// total timeout for a sign request starting from indexed time in seconds
    pub total_timeout: u64,
}

impl fmt::Debug for EthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthConfig")
            .field("account_sk", &"<hidden>")
            .field("consensus_rpc_http_url", &self.consensus_rpc_http_url)
            .field("execution_rpc_http_url", &self.execution_rpc_http_url)
            .field("contract_address", &self.contract_address)
            .field("network", &self.network)
            .field("helios_data_path", &self.helios_data_path)
            .field(
                "refresh_finalized_interval",
                &self.refresh_finalized_interval,
            )
            .field("total_timeout", &self.total_timeout)
            .finish()
    }
}

/// Configures Ethereum indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_eth_options")]
pub struct EthArgs {
    /// The ethereum account secret key used to sign eth respond txn.
    #[arg(long, env("MPC_ETH_ACCOUNT_SK"))]
    pub eth_account_sk: Option<String>,
    /// Ethereum WebSocket RPC URL
    #[clap(
        long,
        env("MPC_ETH_CONSENSUS_RPC_HTTP_URL"),
        requires = "eth_account_sk"
    )]
    pub eth_consensus_rpc_http_url: Option<String>,
    /// Ethereum EXECUTION RPC URL
    #[clap(
        long,
        env("MPC_ETH_EXECUTION_RPC_HTTP_URL"),
        requires = "eth_account_sk"
    )]
    pub eth_execution_rpc_http_url: Option<String>,
    /// The contract address to watch without the `0x` prefix
    #[clap(long, env("MPC_ETH_CONTRACT_ADDRESS"), requires = "eth_account_sk")]
    pub eth_contract_address: Option<String>,
    /// the network that the eth indexer is running on. Either "sepolia"/"mainnet"
    #[clap(
        long,
        env("MPC_ETH_NETWORK"),
        requires = "eth_account_sk",
        default_value = "sepolia",
        value_parser = ["sepolia", "mainnet"],
    )]
    pub eth_network: Option<String>,
    /// helios light client data path
    #[clap(
        long,
        env("MPC_ETH_HELIOS_DATA_PATH"),
        requires = "eth_account_sk",
        default_value = "/helios/sepolia"
    )]
    pub eth_helios_data_path: Option<String>,
    /// refresh finalized block interval in milliseconds
    #[clap(
        long,
        env("MPC_ETH_REFRESH_FINALIZED_INTERVAL"),
        default_value = "10000"
    )]
    pub eth_refresh_finalized_interval: Option<u64>,
    /// total timeout for a sign request starting from indexed time in seconds
    #[clap(long, env("MPC_ETH_TOTAL_TIMEOUT"), default_value = "1500")]
    pub eth_total_timeout: Option<u64>,
}

impl EthArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(10);
        if let Some(eth_account_sk) = self.eth_account_sk {
            args.extend(["--eth-account-sk".to_string(), eth_account_sk]);
        }
        if let Some(eth_consensus_rpc_http_url) = self.eth_consensus_rpc_http_url {
            args.extend([
                "--eth-consensus-rpc-http-url".to_string(),
                eth_consensus_rpc_http_url,
            ]);
        }
        if let Some(eth_execution_rpc_http_url) = self.eth_execution_rpc_http_url {
            args.extend([
                "--eth-execution-rpc-http-url".to_string(),
                eth_execution_rpc_http_url,
            ]);
        }
        if let Some(eth_contract_address) = self.eth_contract_address {
            args.extend(["--eth-contract-address".to_string(), eth_contract_address]);
        }
        if let Some(eth_network) = self.eth_network {
            args.extend(["--eth-network".to_string(), eth_network]);
        }
        if let Some(eth_helios_data_path) = self.eth_helios_data_path {
            args.extend(["--eth-helios-data-path".to_string(), eth_helios_data_path]);
        }
        if let Some(eth_refresh_finalized_interval) = self.eth_refresh_finalized_interval {
            args.extend([
                "--eth-refresh-finalized-interval".to_string(),
                eth_refresh_finalized_interval.to_string(),
            ]);
        }
        if let Some(eth_total_timeout) = self.eth_total_timeout {
            args.extend([
                "--eth-total-timeout".to_string(),
                eth_total_timeout.to_string(),
            ]);
        }
        args
    }

    pub fn into_config(self) -> Option<EthConfig> {
        Some(EthConfig {
            account_sk: self.eth_account_sk?,
            consensus_rpc_http_url: self.eth_consensus_rpc_http_url?,
            execution_rpc_http_url: self.eth_execution_rpc_http_url?,
            contract_address: self.eth_contract_address?,
            network: self.eth_network?,
            helios_data_path: self.eth_helios_data_path?,
            refresh_finalized_interval: self.eth_refresh_finalized_interval?,
            total_timeout: self.eth_total_timeout?,
        })
    }

    pub fn from_config(config: Option<EthConfig>) -> Self {
        match config {
            Some(config) if !config.account_sk.is_empty() => Self {
                eth_account_sk: Some(config.account_sk),
                eth_consensus_rpc_http_url: Some(config.consensus_rpc_http_url),
                eth_execution_rpc_http_url: Some(config.execution_rpc_http_url),
                eth_contract_address: Some(config.contract_address),
                eth_network: Some(config.network),
                eth_helios_data_path: Some(config.helios_data_path),
                eth_refresh_finalized_interval: Some(config.refresh_finalized_interval),
                eth_total_timeout: Some(config.total_timeout),
            },
            _ => Self {
                eth_account_sk: None,
                eth_consensus_rpc_http_url: None,
                eth_execution_rpc_http_url: None,
                eth_contract_address: None,
                eth_network: None,
                eth_helios_data_path: None,
                eth_refresh_finalized_interval: None,
                eth_total_timeout: None,
            },
        }
    }
}

pub enum BlockToProcess {
    Catchup(BlockNumber),
    NewBlock(BlockNumberAndHash),
}

#[derive(Clone)]
pub struct BlockAndRequests {
    block_number: u64,
    block_hash: alloy::primitives::B256,
    indexed_requests: Vec<IndexedSignRequest>,
}

impl BlockAndRequests {
    fn new(
        block_number: u64,
        block_hash: alloy::primitives::B256,
        indexed_requests: Vec<IndexedSignRequest>,
    ) -> Self {
        Self {
            block_number,
            block_hash,
            indexed_requests,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EthSignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

sol! {
    event SignatureRequested(
        address sender,
        bytes32 payload,
        uint32 keyVersion,
        uint256 deposit,
        uint256 chainId,
        string path,
        string algo,
        string dest,
        string params
    );

    event SignatureRequestedEncoding(
        address sender,
        bytes payload,
        string path,
        uint32 keyVersion,
        uint256 chainId,
        string algo,
        string dest,
        string params
    );
}

fn sign_request_from_filtered_log(
    log: Log,
    total_timeout: Duration,
) -> anyhow::Result<IndexedSignRequest> {
    let event = parse_event(&log)?;
    tracing::debug!("found eth event: {:?}", event);
    if event.deposit == U256::ZERO {
        tracing::warn!("deposit is 0, skipping sign request");
        return Err(anyhow::anyhow!("deposit is 0"));
    }

    if event.key_version != 0 {
        tracing::warn!("unsupported key version: {}", event.key_version);
        return Err(anyhow::anyhow!("unsupported key version"));
    }

    // Create sign request from event
    let Some(payload) = Scalar::from_bytes(event.payload_hash) else {
        tracing::warn!(
            "eth `sign` did not produce payload hash correctly: {:?}",
            event.payload_hash,
        );
        return Err(anyhow::anyhow!(
            "failed to convert event payload hash to scalar"
        ));
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
        anyhow::bail!("payload exceeds secp256k1 curve order");
    }

    let epsilon = derive_epsilon_eth(format!("0x{}", event.requester.encode_hex()), &event.path);

    // Use transaction hash as entropy
    let entropy = log.transaction_hash.unwrap_or_default();

    let sign_id = SignId::new(calculate_request_id(&event));
    tracing::info!(?sign_id, "eth signature requested");

    Ok(IndexedSignRequest {
        id: sign_id,
        args: SignArgs {
            entropy: entropy.into(),
            epsilon,
            payload,
            path: event.path,
            key_version: 0,
        },
        chain: Chain::Ethereum,
        unix_timestamp_indexed: crate::util::current_unix_timestamp(),
        timestamp_sign_queue: None,
        total_timeout,
    })
}

fn encode_abi(event: &SignatureRequestedEvent) -> Vec<u8> {
    let signature_requested_event_encoding = SignatureRequestedEncoding {
        sender: event.requester,
        payload: event.payload_hash.to_vec().into(),
        path: event.path.clone(),
        keyVersion: event.key_version,
        chainId: event.chain_id,
        algo: event.algo.clone(),
        dest: event.dest.clone(),
        params: event.params.clone(),
    };
    signature_requested_event_encoding.encode_data()
}

fn calculate_request_id(event: &SignatureRequestedEvent) -> [u8; 32] {
    let abi_encoded = encode_abi(event);
    alloy::primitives::keccak256(abi_encoded).into()
}

// Helper function to parse event logs
fn parse_event(log: &Log) -> anyhow::Result<SignatureRequestedEvent> {
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

    Ok(SignatureRequestedEvent {
        requester,
        payload_hash,
        path,
        key_version,
        deposit,
        chain_id,
        algo,
        dest,
        params,
    })
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

const MAX_BLOCKS_TO_PROCESS: usize = 10000;
fn blocks_to_process_channel() -> (mpsc::Sender<BlockToProcess>, mpsc::Receiver<BlockToProcess>) {
    mpsc::channel(MAX_BLOCKS_TO_PROCESS)
}

const MAX_INDEXED_REQUESTS: usize = 1024;
fn indexed_channel() -> (
    mpsc::Sender<BlockAndRequests>,
    mpsc::Receiver<BlockAndRequests>,
) {
    mpsc::channel(MAX_INDEXED_REQUESTS)
}

type BlockNumberAndHash = (u64, alloy::primitives::B256);
const MAX_FAILED_BLOCKS: usize = 1024;
fn failed_blocks_channel() -> (
    mpsc::Sender<BlockNumberAndHash>,
    mpsc::Receiver<BlockNumberAndHash>,
) {
    mpsc::channel(MAX_FAILED_BLOCKS)
}

const MAX_FINALIZED_BLOCKS: usize = 1024;
fn finalized_block_channel() -> (mpsc::Sender<BlockNumber>, mpsc::Receiver<BlockNumber>) {
    mpsc::channel(MAX_FINALIZED_BLOCKS)
}

const MAX_CATCHUP_BLOCKS: u64 = 8191;

pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    sign_respond_tx_storage: SignRespondTxStorage,
) {
    let Some(eth) = eth else {
        tracing::warn!("ethereum indexer is disabled");
        return;
    };

    let last_processed_block = app_data_storage
        .last_processed_block_eth()
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("Failed to get last processed block: {err:?}");
            None
        });

    let Ok(network) = Network::from_str(eth.network.as_str()) else {
        tracing::error!("Network input incorrect: {}", eth.network);
        return;
    };

    let client: EthereumClient = {
        let builder = match EthereumClientBuilder::new()
            .network(network)
            .consensus_rpc(&eth.consensus_rpc_http_url)
        {
            Ok(builder) => builder,
            Err(err) => {
                tracing::error!("Failed to build consensus RPC: {err:?}");
                return;
            }
        };

        let builder = match builder.execution_rpc(&eth.execution_rpc_http_url) {
            Ok(builder) => builder,
            Err(err) => {
                tracing::error!("Failed to build execution RPC: {err:?}");
                return;
            }
        };

        match builder
            .data_dir(PathBuf::from(&eth.helios_data_path))
            .with_file_db()
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                tracing::error!("Failed to build Helios client: {err:?}");
                return;
            }
        }
    };

    tracing::info!("Built Helios client on network {}", network);

    client.wait_synced().await;

    tracing::info!("running ethereum indexer");

    let mut block_heads_rx = match client.subscribe(SubscriptionType::NewHeads).await {
        Ok(block_heads_rx) => block_heads_rx,
        Err(err) => {
            tracing::error!("Failed to subscribe to new block heads: {err:?}");
            return;
        }
    };

    let Ok(eth_contract_addr) = Address::from_str(&format!("0x{}", eth.contract_address)) else {
        tracing::error!("Failed to parse contract address: {}", eth.contract_address);
        return;
    };
    let total_timeout = Duration::from_secs(eth.total_timeout);

    let (blocks_failed_send, blocks_failed_recv) = failed_blocks_channel();

    let (requests_indexed_send, requests_indexed_recv) = indexed_channel();

    let (finalized_block_send, finalized_block_recv) = finalized_block_channel();

    let (blocks_to_process_send, mut blocks_to_process_recv) = blocks_to_process_channel();

    let client = Arc::new(client);

    let client_clone = Arc::clone(&client);
    tokio::spawn(async move {
        tracing::info!("Spawned task to refresh the latest finalized block");
        refresh_finalized_block(
            &client_clone,
            finalized_block_send.clone(),
            eth.refresh_finalized_interval,
        )
        .await;
    });

    let near_account_id_clone = node_near_account_id.clone();
    let client_clone = Arc::clone(&client);
    tokio::spawn(async move {
        tracing::info!("Spawned task to send indexed requests to send queue");
        send_requests_when_final(
            &client_clone,
            requests_indexed_recv,
            finalized_block_recv,
            sign_tx.clone(),
            app_data_storage.clone(),
            near_account_id_clone.clone(),
        )
        .await;
    });

    let near_account_id_clone = node_near_account_id.clone();
    let requests_indexed_send_clone = requests_indexed_send.clone();
    let blocks_failed_send_clone = blocks_failed_send.clone();
    let client_clone = Arc::clone(&client);
    let sign_respond_tx_storage_clone = sign_respond_tx_storage.clone();
    tokio::spawn(async move {
        tracing::info!("Spawned task to retry failed blocks");
        retry_failed_blocks(
            blocks_failed_recv,
            blocks_failed_send_clone,
            &client_clone,
            eth_contract_addr,
            near_account_id_clone,
            requests_indexed_send_clone,
            total_timeout,
            sign_respond_tx_storage_clone,
        )
        .await;
    });

    let blocks_to_process_send_clone = blocks_to_process_send.clone();
    if let Some(last_processed_block) = last_processed_block {
        let Ok(SubscriptionEvent::NewHeads(latest_block)) = block_heads_rx.recv().await else {
            tracing::warn!("Failed to receive latest block head");
            return;
        };
        let end_block_number = latest_block.header.number;
        add_catchup_blocks_to_process(
            blocks_to_process_send_clone,
            last_processed_block,
            end_block_number,
        )
        .await;
    }

    let blocks_to_process_send_clone = blocks_to_process_send.clone();
    tokio::spawn(async move {
        tracing::info!("Spawned task to add new blocks to process");
        add_new_block_to_process(block_heads_rx, blocks_to_process_send_clone).await;
    });

    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let requests_indexed_send_clone = requests_indexed_send.clone();
    loop {
        let Some(block_to_process) = blocks_to_process_recv.recv().await else {
            interval.tick().await;
            continue;
        };
        let (block_number, block_hash, is_catchup) = match block_to_process {
            BlockToProcess::Catchup(block_number) => {
                let block = fetch_block(
                    &client,
                    BlockId::Number(BlockNumberOrTag::Number(block_number)),
                    5,
                    Duration::from_millis(200),
                )
                .await;
                if let Some(block) = block {
                    (block.header.number, block.header.hash, true)
                } else {
                    continue;
                }
            }
            BlockToProcess::NewBlock((block_number, block_hash)) => {
                (block_number, block_hash, false)
            }
        };
        let sign_respond_tx_storage_clone = sign_respond_tx_storage.clone();
        if let Err(err) = process_block(
            block_number,
            block_hash,
            &client,
            eth_contract_addr,
            node_near_account_id.clone(),
            requests_indexed_send_clone.clone(),
            total_timeout,
            sign_respond_tx_storage_clone,
        )
        .await
        {
            tracing::warn!("Eth indexer failed to process block number {block_number}: {err:?}");
            add_failed_block(blocks_failed_send.clone(), block_number, block_hash).await;
            continue;
        }
        if block_number % 10 == 0 {
            if is_catchup {
                tracing::info!("Processed catchup block number {block_number}");
            } else {
                tracing::info!("Processed new block number {block_number}");
            }
        }
        crate::metrics::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
            .set(block_number as i64);
    }
}

#[allow(clippy::too_many_arguments)]
async fn retry_failed_blocks(
    mut blocks_failed_rx: mpsc::Receiver<BlockNumberAndHash>,
    blocks_failed_tx: mpsc::Sender<BlockNumberAndHash>,
    client: &Arc<EthereumClient>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
    total_timeout: Duration,
    sign_respond_tx_storage: SignRespondTxStorage,
) {
    loop {
        let Some((block_number, block_hash)) = blocks_failed_rx.recv().await else {
            tracing::warn!("Failed to receive block and requests from requests_indexed");
            break;
        };
        if let Err(err) = process_block(
            block_number,
            block_hash,
            client,
            eth_contract_addr,
            node_near_account_id.clone(),
            requests_indexed.clone(),
            total_timeout,
            sign_respond_tx_storage.clone(),
        )
        .await
        {
            tracing::warn!("Retry failed for block {block_number}: {err:?}");
            add_failed_block(blocks_failed_tx.clone(), block_number, block_hash).await;
        } else {
            tracing::info!("Successfully retried block: {block_number}");
        }
    }
}

async fn add_failed_block(
    blocks_failed: mpsc::Sender<BlockNumberAndHash>,
    block_number: u64,
    block_hash: alloy::primitives::B256,
) {
    blocks_failed
        .send((block_number, block_hash))
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("Failed to send failed block: {:?}", err);
        });
}

async fn add_new_block_to_process(
    mut block_heads_rx: tokio::sync::broadcast::Receiver<
        SubscriptionEvent<helios::ethereum::spec::Ethereum>,
    >,
    blocks_to_process: mpsc::Sender<BlockToProcess>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let mut receiver_state_update_timestamp = Instant::now();
    loop {
        interval.tick().await;
        if block_heads_rx.is_empty()
            && receiver_state_update_timestamp.elapsed() > Duration::from_secs(60)
        {
            tracing::warn!("No new block heads received for 60 seconds, waiting...");
            receiver_state_update_timestamp = Instant::now();
        }
        let new_block_head = match block_heads_rx.recv().await {
            Ok(new_block_head) => new_block_head,
            Err(RecvError::Lagged(lagged_count)) => {
                tracing::warn!(
                    "Eth indexer failed to receive latest block header: block heads stream lagged too far behind, lagged count: {lagged_count}"
                );
                continue;
            }
            Err(RecvError::Closed) => {
                tracing::error!(
                    "Eth indexer failed to receive latest block header: block heads stream closed"
                );
                // TODO: add a retry mechanism for closed block heads stream
                break;
            }
        };
        receiver_state_update_timestamp = Instant::now();
        let SubscriptionEvent::NewHeads(new_block) = new_block_head;
        let block_number = new_block.header.number;
        let block_hash = new_block.header.hash;
        if block_number % 10 == 0 {
            tracing::info!("Received new block head: {block_number}");
        }
        if let Err(err) = blocks_to_process
            .send(BlockToProcess::NewBlock((block_number, block_hash)))
            .await
        {
            tracing::warn!("Failed to send block to process: {err:?}");
        }
    }
}

async fn add_catchup_blocks_to_process(
    blocks_to_process: mpsc::Sender<BlockToProcess>,
    start_block_number: u64,
    end_block_number: u64,
) {
    // helios can only go back maximum MAX_CATCHUP_BLOCKS blocks, so we need to adjust the start block number if it's too far behind
    let helios_oldest_block_number = end_block_number.saturating_sub(MAX_CATCHUP_BLOCKS);
    let start_block_number = if start_block_number < helios_oldest_block_number {
        tracing::warn!(
            "Start block number {start_block_number} is too far behind the latest block {end_block_number}, adjusting to {helios_oldest_block_number}"
        );
        helios_oldest_block_number
    } else {
        start_block_number
    };

    for block_number in start_block_number..=end_block_number {
        if let Err(err) = blocks_to_process
            .send(BlockToProcess::Catchup(block_number))
            .await
        {
            tracing::warn!("Failed to send block to process: {err:?}");
        }
    }
}

// retry getting block from helios with exponential backoff
async fn fetch_block(
    helios_client: &Arc<EthereumClient>,
    block_id: BlockId,
    max_retries: u8,
    base_delay: Duration,
) -> Option<alloy::rpc::types::Block> {
    let mut retries = 0;
    loop {
        match helios_client.get_block(block_id, false).await {
            Ok(Some(block)) => return Some(block),
            Ok(None) => {
                tracing::warn!("Block {block_id} not found from Helios client");
                return None;
            }
            Err(e) => {
                if retries < max_retries {
                    retries += 1;
                    let delay = base_delay * 2u32.pow((retries - 1) as u32);
                    tracing::warn!(
                        "Failed to fetch block number {block_id} from Helios client: {:?}, retrying",
                        e
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                tracing::warn!(
                    "Failed to fetch block number {block_id} from Helios client: {:?}, exceeded maximum retry",
                    e
                );
                return None;
            }
        }
    }
}

/// Polls for the latest finalized block and update finalized block channel.
async fn refresh_finalized_block(
    helios_client: &Arc<EthereumClient>,
    finalized_block_send: mpsc::Sender<BlockNumber>,
    refresh_finalized_interval: u64,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(refresh_finalized_interval));
    let mut final_block_number: Option<BlockNumber> = None;

    loop {
        interval.tick().await;
        tracing::info!("Refreshing finalized epoch");

        let new_finalized_block = match fetch_block(
            helios_client,
            BlockId::Number(BlockNumberOrTag::Finalized),
            5,
            Duration::from_millis(200),
        )
        .await
        {
            Some(block) => block,
            None => {
                continue;
            }
        };

        let new_final_block_number = new_finalized_block.header.number;
        tracing::info!(
            "New finalized block number: {new_final_block_number}, last finalized block number: {final_block_number:?}"
        );

        if final_block_number.is_none_or(|n| new_final_block_number > n) {
            tracing::info!("Found new finalized block!");
            if let Err(err) = finalized_block_send.send(new_final_block_number).await {
                tracing::warn!("Failed to send finalized block: {err:?}");
                continue;
            }
            final_block_number.replace(new_final_block_number);
            continue;
        }

        let Some(last_final_block_number) = final_block_number else {
            continue;
        };

        if new_final_block_number < last_final_block_number {
            tracing::warn!(
                "New finalized block number overflowed range of u64 and has wrapped around!"
            );
        }

        if last_final_block_number == new_final_block_number {
            tracing::info!("No new finalized block");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_block(
    block_number: u64,
    block_hash: alloy::primitives::B256,
    client: &Arc<EthereumClient>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
    total_timeout: Duration,
    sign_respond_tx_storage: SignRespondTxStorage,
) -> anyhow::Result<()> {
    tracing::info!(
        "Processing block number {} with hash {:?}",
        block_number,
        block_hash
    );
    let start = Instant::now();
    let block_receipts_result = client
        .get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(block_number)))
        .await;
    crate::metrics::ETH_BLOCK_RECEIPT_LATENCY
        .with_label_values(&[node_near_account_id.as_str()])
        .observe(start.elapsed().as_millis() as f64);
    let Some(block_receipts) = block_receipts_result.map_err(|err| {
        anyhow::anyhow!(
            "Failed to get block receipts for block number {block_number}: {:?}",
            err
        )
    })?
    else {
        tracing::info!("no receipts for block number {block_number}");
        return Ok(());
    };

    let block_receipts_clone = block_receipts.clone();
    let pending_txs: HashSet<_> = sign_respond_tx_storage
        .fetch_pending()
        .await
        .into_iter()
        .collect();
    for receipt in block_receipts_clone {
        if pending_txs.contains(&receipt.transaction_hash.into()) {
            let status = receipt.status();
            println!(
                "Tx {} found in block {}: {}",
                receipt.transaction_hash,
                block_number,
                if status { "✅ success" } else { "❌ failed" }
            );
            let sign_respond_tx_storage = sign_respond_tx_storage.clone();
            tokio::spawn(async move {
                sign_respond_tx_storage
                    .complete(receipt.transaction_hash.into())
                    .await;
            });
        }
    }

    let filtered_logs: Vec<Log> = block_receipts
        .into_iter()
        .filter_map(|receipt| receipt.as_ref().as_receipt().cloned())
        .flat_map(|receipt| {
            receipt.logs.into_iter().filter(|log| {
                log.address() == eth_contract_addr
                    && log
                        .topic0()
                        .is_some_and(|topic0| *topic0 == SignatureRequested::SIGNATURE_HASH)
            })
        })
        .collect();

    if filtered_logs.is_empty() {
        return Ok(());
    }

    let indexed_requests = parse_filtered_logs(filtered_logs, total_timeout);
    requests_indexed
        .send(BlockAndRequests::new(
            block_number,
            block_hash,
            indexed_requests.clone(),
        ))
        .await
        .map_err(|err| anyhow::anyhow!("Failed to send indexed requests: {:?}", err))?;

    let block_timestamp = client
        .get_block(
            BlockId::Number(BlockNumberOrTag::Number(block_number)),
            false,
        )
        .await
        .ok()
        .and_then(|block| block.map(|b| b.header.timestamp()));

    for request in &indexed_requests {
        if let Some(block_timestamp) = block_timestamp {
            crate::metrics::INDEXER_DELAY
                .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
                .observe(
                    crate::util::duration_between_unix(
                        block_timestamp,
                        request.unix_timestamp_indexed,
                    )
                    .as_secs() as f64,
                );
        }
    }

    Ok(())
}

/// Sends a request to the sign queue when the block where the request is in is finalized.
async fn send_requests_when_final(
    helios_client: &Arc<EthereumClient>,
    mut requests_indexed: mpsc::Receiver<BlockAndRequests>,
    mut finalized_block_rx: mpsc::Receiver<BlockNumber>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
) {
    let mut finalized_block_number: Option<BlockNumber> = None;
    let mut last_processed_block: Option<BlockNumber> = app_data_storage
        .last_processed_block_eth()
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("Failed to fetch last processed block: {err:?}, setting to None");
            None
        });

    loop {
        let Some(BlockAndRequests {
            block_number,
            block_hash,
            indexed_requests,
        }) = requests_indexed.recv().await
        else {
            tracing::error!("Failed to receive indexed requests");
            return;
        };

        // Wait for finalized block if needed
        while finalized_block_number.is_none_or(|n| block_number > n) {
            let Some(new_finalized_block) = finalized_block_rx.recv().await else {
                tracing::error!("Failed to receive finalized blocks");
                return;
            };
            finalized_block_number.replace(new_finalized_block);
        }

        // Verify block hash and send requests
        let block = fetch_block(
            helios_client,
            block_number.into(),
            5,
            Duration::from_millis(200),
        )
        .await;

        let Some(block) = block else {
            tracing::warn!("Block {block_number} not found from Helios client, skipping this block and its requests");
            continue;
        };

        if block.header.hash == block_hash {
            tracing::info!("Block {block_number} is finalized!");
            send_indexed_requests(
                indexed_requests,
                sign_tx.clone(),
                node_near_account_id.clone(),
            );
            if last_processed_block.is_none_or(|n| n < block_number) {
                if let Err(err) = app_data_storage
                    .set_last_processed_block_eth(block_number)
                    .await
                {
                    tracing::warn!("Failed to set last processed block: {err:?}");
                }
                last_processed_block.replace(block_number);
            }
        } else {
            // no special handling for chain reorg, just log the error
            // This is because when such chain reorg happens, the new canonical chain will have already been emitted by helios's block header stream, and we can safely skip this block here.
            tracing::error!(
                "Block {block_number} hash mismatch: expected {block_hash:?}, got {:?}. Chain re-orged.",
                block.header.hash
            );
        }
    }
}

fn parse_filtered_logs(logs: Vec<Log>, total_timeout: Duration) -> Vec<IndexedSignRequest> {
    let mut indexed_requests = Vec::new();
    for log in logs {
        tracing::debug!("Parsing Ethereum log: {:?}", log);
        match sign_request_from_filtered_log(log.clone(), total_timeout) {
            Ok(request) => indexed_requests.push(request),
            Err(err) => {
                tracing::warn!(?log, ?err, "Failed to parse Ethereum log");
            }
        }
    }
    if indexed_requests.is_empty() {
        tracing::warn!("No valid Ethereum sign requests found in logs");
    }
    indexed_requests
}

fn send_indexed_requests(
    requests: Vec<IndexedSignRequest>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
) {
    for request in requests {
        let sign_tx = sign_tx.clone();
        let node_near_account_id = node_near_account_id.clone();
        tokio::spawn(async move {
            let request = IndexedSignRequest {
                id: request.id,
                chain: request.chain,
                args: request.args,
                unix_timestamp_indexed: request.unix_timestamp_indexed,
                timestamp_sign_queue: Some(Instant::now()),
                total_timeout: request.total_timeout,
            };
            match sign_tx.send(request).await {
                Ok(_) => {
                    crate::metrics::NUM_SIGN_REQUESTS
                        .with_label_values(&[
                            Chain::Ethereum.as_str(),
                            node_near_account_id.as_str(),
                        ])
                        .inc();
                }
                Err(err) => {
                    tracing::error!(?err, "Failed to send ETH sign request into queue");
                }
            }
        });
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
