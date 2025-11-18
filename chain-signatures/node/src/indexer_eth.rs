use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Instant;

use crate::backlog::Backlog;
use crate::mesh::{wait_threshold_active, MeshState};
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest, Sign, SignRequestType};
use crate::rpc::ContractStateWatcher;
#[cfg(not(feature = "light_client"))]
use crate::sign_bidirectional::BidirectionalTx;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::sign_bidirectional::PendingRequestStatus;
use crate::storage::app_data_storage::AppDataStorage;

use alloy::consensus::BlockHeader;
#[cfg(not(feature = "light_client"))]
use alloy::consensus::Transaction as _;
#[cfg(feature = "light_client")]
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::Log;
#[cfg(not(feature = "light_client"))]
use alloy::rpc::types::Transaction;
#[cfg(not(feature = "light_client"))]
use alloy::rpc::types::TransactionReceipt;
use tokio::sync::watch;

#[cfg(not(feature = "light_client"))]
use crate::respond_bidirectional::{
    CompletedTx, RespondBidirectionalSerializedOutput, SerDeserFormat,
    OUTPUT_DESERIALIZATION_FORMAT, RESPOND_SERIALIZATION_FORMAT,
};
#[cfg(not(feature = "light_client"))]
use crate::sign_bidirectional::TransactionOutput;

use alloy::sol_types::{sol, SolEvent};
#[cfg(feature = "light_client")]
use helios::common::types::{SubscriptionEvent, SubscriptionType};
#[cfg(feature = "light_client")]
use helios::ethereum::{config::networks::Network, EthereumClient, EthereumClientBuilder};
use k256::Scalar;
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use near_account_id::AccountId;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
#[cfg(feature = "light_client")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "light_client")]
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

pub(crate) static MAX_SECP256K1_SCALAR: LazyLock<Scalar> = LazyLock::new(|| {
    Scalar::from_bytes(
        hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
});
// This is the maximum number of blocks that Helios can look back to
#[cfg(feature = "light_client")]
const MAX_CATCHUP_BLOCKS: u64 = 8191;

#[cfg(feature = "light_client")]
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
    /// Enable the indexer to just send requests optimistically instead waiting for final.
    pub optimistic_requests: bool,
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
            .field("optimistic_requests", &self.optimistic_requests)
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
    /// Enable the indexer to just send requests optimistically instead waiting for final.
    /// Useful for testing where we do not want to reach finality due to how long it takes.
    #[clap(long, env("MPC_ETH_OPTIMISTIC_REQUESTS"), default_value = "false")]
    pub eth_optimistic_requests: bool,
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
        if self.eth_optimistic_requests {
            args.push("--eth-optimistic-requests".to_string());
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
            optimistic_requests: self.eth_optimistic_requests,
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
                eth_optimistic_requests: config.optimistic_requests,
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
                eth_optimistic_requests: false,
            },
        }
    }
}

#[cfg(feature = "light_client")]
pub enum BlockToProcess {
    Catchup(BlockNumber),
    NewBlock(BlockNumberAndHash),
}

#[cfg(feature = "light_client")]
#[derive(Clone)]
pub struct BlockAndRequests {
    block_number: u64,
    block_hash: alloy::primitives::B256,
    indexed_requests: Vec<IndexedSignRequest>,
}

#[cfg(feature = "light_client")]
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

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    event SignatureResponded(
        bytes32 indexed requestId,
        address responder,
        Signature signature
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
        anyhow::bail!("deposit is 0");
    }

    if event.key_version > LATEST_MPC_KEY_VERSION {
        tracing::warn!("unsupported key version: {}", event.key_version);
        anyhow::bail!("unsupported key version");
    }

    // Create sign request from event
    let Some(payload) = Scalar::from_bytes(event.payload_hash) else {
        tracing::warn!(
            "eth `sign` did not produce payload hash correctly: {:?}",
            event.payload_hash,
        );
        anyhow::bail!("failed to convert event payload hash to scalar");
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
        anyhow::bail!("payload exceeds secp256k1 curve order");
    }

    let epsilon = derive_epsilon_eth(
        event.key_version,
        format!("0x{}", event.requester.encode_hex()).as_str(),
        &event.path,
    );

    // Use transaction hash as entropy
    let entropy = log.transaction_hash.unwrap_or_default();

    let sign_id = SignId::new(event.generate_request_id());
    tracing::info!(?sign_id, "eth signature requested");

    Ok(IndexedSignRequest {
        id: sign_id,
        args: SignArgs {
            entropy: entropy.into(),
            epsilon,
            payload,
            path: event.path,
            key_version: event.key_version,
        },
        chain: Chain::Ethereum,
        unix_timestamp_indexed: crate::util::current_unix_timestamp(),
        timestamp_sign_queue: Instant::now(),
        total_timeout,
        sign_request_type: SignRequestType::Sign,
    })
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

#[cfg(feature = "light_client")]
const MAX_BLOCKS_TO_PROCESS: usize = 10000;
#[cfg(feature = "light_client")]
fn blocks_to_process_channel() -> (mpsc::Sender<BlockToProcess>, mpsc::Receiver<BlockToProcess>) {
    mpsc::channel(MAX_BLOCKS_TO_PROCESS)
}

#[cfg(feature = "light_client")]
const MAX_INDEXED_REQUESTS: usize = 1024;
#[cfg(feature = "light_client")]
fn indexed_channel() -> (
    mpsc::Sender<BlockAndRequests>,
    mpsc::Receiver<BlockAndRequests>,
) {
    mpsc::channel(MAX_INDEXED_REQUESTS)
}

#[cfg(feature = "light_client")]
type BlockNumberAndHash = (u64, alloy::primitives::B256);
#[cfg(feature = "light_client")]
const MAX_FAILED_BLOCKS: usize = 1024;
#[cfg(feature = "light_client")]
fn failed_blocks_channel() -> (
    mpsc::Sender<BlockNumberAndHash>,
    mpsc::Receiver<BlockNumberAndHash>,
) {
    mpsc::channel(MAX_FAILED_BLOCKS)
}

#[cfg(feature = "light_client")]
const MAX_FINALIZED_BLOCKS: usize = 1024;
#[cfg(feature = "light_client")]
fn finalized_block_channel() -> (mpsc::Sender<BlockNumber>, mpsc::Receiver<BlockNumber>) {
    mpsc::channel(MAX_FINALIZED_BLOCKS)
}

#[cfg(feature = "light_client")]
pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<Sign>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    let Some(eth) = eth else {
        tracing::warn!("ethereum indexer is disabled");
        return;
    };

    // Wait for threshold to be available
    let threshold = contract_watcher.wait_threshold().await;
    if threshold > 0 {
        let mesh_state = mesh_state.borrow().clone();
        backlog
            .recover(&mesh_state, &node_client, threshold, &[Chain::Ethereum])
            .await;
    }

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

    tokio::spawn(send_requests_when_final(
        Arc::clone(&client),
        requests_indexed_recv,
        finalized_block_recv,
        sign_tx.clone(),
        app_data_storage.clone(),
        node_near_account_id.clone(),
        eth.optimistic_requests,
        backlog.clone(),
    ));

    tokio::spawn(retry_failed_blocks(
        blocks_failed_recv,
        blocks_failed_send.clone(),
        Arc::clone(&client),
        eth_contract_addr,
        node_near_account_id.clone(),
        requests_indexed_send.clone(),
        sign_tx.clone(),
        total_timeout,
        backlog.clone(),
    ));

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
        if let Err(err) = process_block(
            block_number,
            block_hash,
            &client,
            eth_contract_addr,
            node_near_account_id.clone(),
            requests_indexed_send_clone.clone(),
            sign_tx.clone(),
            total_timeout,
            backlog.clone(),
            &near_client,
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

#[cfg(feature = "light_client")]
#[allow(clippy::too_many_arguments)]
async fn retry_failed_blocks(
    mut blocks_failed_rx: mpsc::Receiver<BlockNumberAndHash>,
    blocks_failed_tx: mpsc::Sender<BlockNumberAndHash>,
    client: Arc<EthereumClient>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
    sign_tx: mpsc::Sender<Sign>,
    total_timeout: Duration,
    backlog: Backlog,
) {
    loop {
        let Some((block_number, block_hash)) = blocks_failed_rx.recv().await else {
            tracing::warn!("Failed to receive block and requests from requests_indexed");
            break;
        };
        if let Err(err) = process_block(
            block_number,
            block_hash,
            &client,
            eth_contract_addr,
            node_near_account_id.clone(),
            requests_indexed.clone(),
            sign_tx.clone(),
            total_timeout,
            backlog.clone(),
            &near_client,
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

#[cfg(feature = "light_client")]
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

#[cfg(feature = "light_client")]
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

#[cfg(feature = "light_client")]
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
#[cfg(feature = "light_client")]
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
#[cfg(feature = "light_client")]
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

#[cfg(feature = "light_client")]
#[allow(clippy::too_many_arguments)]
async fn process_block(
    block_number: u64,
    block_hash: alloy::primitives::B256,
    client: &Arc<EthereumClient>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
    sign_tx: mpsc::Sender<Sign>,
    total_timeout: Duration,
    backlog: Backlog,
    near_client: &NearClient,
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

    let pending_watchers = backlog.pending_execution(Chain::Ethereum).await;

    tracing::info!(
        pending_watchers_count = pending_watchers.len(),
        block_number,
        "checking pending watchers for bidirectional execution"
    );

    let mut respond_bidirectional_requests: Vec<IndexedSignRequest> = Vec::new();

    for receipt in &block_receipts {
        let tx_id: BidirectionalTxId = receipt.transaction_hash.into();
        tracing::debug!(?tx_id, "checking receipt against pending watchers");
        let Some((sign_id, pending_tx)) = pending_watchers.get(&tx_id).cloned() else {
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
            "observed bidirectional execution on destination chain"
        );

        let mut updated_tx = pending_tx.clone();
        updated_tx.status = status;

        let completed_tx =
            crate::respond_bidirectional::CompletedTx::new(updated_tx.clone(), block_number);

        if let Some(respond_request) = completed_tx
            .create_sign_request_from_completed_tx(client, Chain::Ethereum, 6, total_timeout)
            .await
        {
            respond_bidirectional_requests.push(respond_request);
        } else {
            tracing::warn!(
                ?tx_id,
                ?sign_id,
                "failed to create respond_bidirectional request from executed tx"
            );
        }

        backlog
            .set_status(pending_tx.source_chain, &sign_id, status)
            .await;
        backlog.unwatch_execution(Chain::Ethereum, &tx_id).await;
    }

    let remaining_watchers = backlog.pending_execution(Chain::Ethereum).await;

    for (tx_id, (sign_id, tx)) in remaining_watchers {
        let current_nonce = match client
            .get_nonce(
                tx.from_address,
                BlockId::Number(BlockNumberOrTag::Number(block_number)),
            )
            .await
        {
            Ok(nonce) => nonce,
            Err(err) => {
                tracing::warn!(?tx_id, ?sign_id, ?err, "failed to get current nonce");
                continue;
            }
        };

        if tx.nonce < current_nonce {
            tracing::warn!(
                ?tx_id,
                ?sign_id,
                expected_nonce = tx.nonce,
                actual_nonce = current_nonce,
                "nonce too low for tx",
            );

            let mut failed_tx = tx.clone();
            failed_tx.status = PendingRequestStatus::Failed;
            let completed_tx =
                crate::respond_bidirectional::CompletedTx::new(failed_tx.clone(), block_number);

            if let Some(request) = completed_tx
                .create_sign_request_from_completed_tx(client, Chain::Ethereum, 6, total_timeout)
                .await
            {
                respond_bidirectional_requests.push(request);
            } else {
                tracing::warn!(
                    ?tx_id,
                    ?sign_id,
                    "failed to create sign request from completed tx"
                );
            }

            backlog
                .set_status(tx.source_chain, &sign_id, PendingRequestStatus::Failed)
                .await;
            backlog.unwatch_execution(Chain::Ethereum, &tx_id).await;
        }
    }

    let relevant_logs: Vec<Log> = block_receipts
        .into_iter()
        .filter_map(|receipt| receipt.as_ref().as_receipt().cloned())
        .flat_map(|receipt| {
            receipt
                .logs
                .into_iter()
                .filter(|log| log.address() == eth_contract_addr)
        })
        .collect();

    let (respond_logs, potential_request_logs): (Vec<Log>, Vec<Log>) =
        relevant_logs.into_iter().partition(|log| {
            log.topic0()
                .is_some_and(|topic| *topic == SignatureResponded::SIGNATURE_HASH)
        });

    if !respond_logs.is_empty() {
        process_respond_events(&respond_logs, &backlog, &sign_tx).await;
    }

    let request_logs: Vec<Log> = potential_request_logs
        .into_iter()
        .filter(|log| {
            log.topic0()
                .is_some_and(|topic| *topic == SignatureRequested::SIGNATURE_HASH)
        })
        .collect();

    let mut all_sign_requests = Vec::new();
    if !request_logs.is_empty() {
        all_sign_requests.extend(parse_filtered_logs(request_logs, total_timeout));
    }
    if !respond_bidirectional_requests.is_empty() {
        all_sign_requests.extend(respond_bidirectional_requests);
    }

    if all_sign_requests.is_empty() {
        return Ok(());
    }

    requests_indexed
        .send(BlockAndRequests::new(
            block_number,
            block_hash,
            all_sign_requests.clone(),
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

    for request in &all_sign_requests {
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
#[cfg(feature = "light_client")]
async fn send_requests_when_final(
    helios_client: Arc<EthereumClient>,
    mut requests_indexed: mpsc::Receiver<BlockAndRequests>,
    mut finalized_block_rx: mpsc::Receiver<BlockNumber>,
    sign_tx: mpsc::Sender<Sign>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    optimistic_requests: bool,
    backlog: Backlog,
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

        if !optimistic_requests {
            // Wait for finalized block if needed
            while finalized_block_number.is_none_or(|n| block_number > n) {
                let Some(new_finalized_block) = finalized_block_rx.recv().await else {
                    tracing::error!("Failed to receive finalized blocks");
                    return;
                };
                finalized_block_number.replace(new_finalized_block);
            }
        }

        // Verify block hash and send requests
        let block = fetch_block(
            &helios_client,
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
            backlog
                .set_processed_block(Chain::Ethereum, block_number)
                .await;
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

async fn process_respond_events(logs: &[Log], backlog: &Backlog, sign_tx: &mpsc::Sender<Sign>) {
    for log in logs {
        if let Some(sign_id) = sign_id_from_signature_responded_log(log) {
            if let Err(err) = sign_tx.send(Sign::Completion(sign_id)).await {
                tracing::error!(
                    ?sign_id,
                    ?err,
                    "failed to send completion for respond event"
                );
            }

            // Check the sign request type to determine if it's a bidirectional request
            if let Some(sign_type) = backlog.sign_type(Chain::Ethereum, &sign_id).await {
                match sign_type {
                    SignRequestType::SignBidirectional(_) => {
                        // This is a bidirectional request, keep it in the backlog.
                        // It will be removed when we receive the respond_bidirectional event.
                        tracing::info!(
                            ?sign_id,
                            "observed SignatureResponded event for bidirectional request, keeping in backlog"
                        );
                    }
                    SignRequestType::Sign => {
                        tracing::info!(
                            ?sign_id,
                            "observed SignatureResponded event for regular sign request, removing from backlog"
                        );
                        backlog.remove(Chain::Ethereum, &sign_id).await;
                    }
                    SignRequestType::RespondBidirectional(_) => {
                        tracing::warn!(
                            ?sign_id,
                            "observed SignatureResponded event for respond_bidirectional request, which should not happen"
                        );
                    }
                }
            } else {
                // If we don't have the type tracked, just remove it (fallback behavior for backward compatibility)
                tracing::debug!(
                    ?sign_id,
                    "sign request type not found, removing from backlog"
                );
                backlog.remove(Chain::Ethereum, &sign_id).await;
            }
        }
    }
}

fn sign_id_from_signature_responded_log(log: &Log) -> Option<SignId> {
    if log
        .topic0()
        .is_none_or(|topic| *topic != SignatureResponded::SIGNATURE_HASH)
    {
        return None;
    }

    let request_topic = log.topics().get(1)?;
    let request_id: [u8; 32] = (*request_topic).into();
    Some(SignId { request_id })
}

fn send_indexed_requests(
    requests: Vec<IndexedSignRequest>,
    sign_tx: mpsc::Sender<Sign>,
    node_near_account_id: AccountId,
) {
    for request in requests {
        let sign_tx = sign_tx.clone();
        let node_near_account_id = node_near_account_id.clone();
        tokio::spawn(async move {
            match sign_tx.send(Sign::Request(request)).await {
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

impl SignatureRequestedEvent {
    fn encode_abi(&self) -> Vec<u8> {
        let signature_requested_event_encoding = SignatureRequestedEncoding {
            sender: self.requester,
            payload: self.payload_hash.into(),
            path: self.path.clone(),
            keyVersion: self.key_version,
            chainId: self.chain_id,
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
        };
        signature_requested_event_encoding.encode_data()
    }

    pub fn generate_request_id(&self) -> [u8; 32] {
        let abi_encoded = self.encode_abi();
        alloy::primitives::keccak256(abi_encoded).into()
    }
}

#[cfg(not(feature = "light_client"))]
#[allow(clippy::too_many_arguments)]
pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<Sign>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    let Some(eth) = eth else {
        tracing::warn!("ethereum indexer is disabled");
        return;
    };

    // Recover backlog before doing anything.
    // Wait for threshold to be available
    let threshold = contract_watcher.wait_threshold().await;
    if threshold > 0 {
        wait_threshold_active(&mut mesh_state, threshold).await;

        let mesh_state = mesh_state.borrow().clone();
        backlog
            .recover(&mesh_state, &node_client, threshold, &[Chain::Ethereum])
            .await;
    }

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

#[cfg(not(feature = "light_client"))]
#[allow(clippy::too_many_arguments)]
async fn process_block(
    client: &RpcEthereumClient,
    block_number: u64,
    contract_address: Address,
    node_near_account_id: AccountId,
    sign_tx: mpsc::Sender<Sign>,
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
        process_respond_events(&respond_logs, backlog, &sign_tx).await;
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

#[cfg(not(feature = "light_client"))]
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
            .transaction_count(tx.from_address, block_number)
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

#[cfg(not(feature = "light_client"))]
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

#[cfg(not(feature = "light_client"))]
#[derive(Clone)]
struct RpcEthereumClient {
    http: reqwest::Client,
    url: String,
    id: Arc<AtomicU64>,
}

#[cfg(not(feature = "light_client"))]
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

#[cfg(not(feature = "light_client"))]
fn format_address(address: Address) -> String {
    format!("0x{}", address.encode_hex())
}

#[cfg(not(feature = "light_client"))]
fn format_bytes(data: &Bytes) -> String {
    if data.is_empty() {
        "0x".to_string()
    } else {
        format!("0x{}", hex::encode(data))
    }
}

#[cfg(not(feature = "light_client"))]
fn to_hex_u64(value: u64) -> String {
    format!("0x{:x}", value)
}

#[cfg(not(feature = "light_client"))]
fn hex_to_u64(value: &str) -> anyhow::Result<u64> {
    let trimmed = value.trim_start_matches("0x");
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 16)
        .map_err(|err| anyhow::anyhow!("failed to parse hex value '{value}': {err}"))
}
