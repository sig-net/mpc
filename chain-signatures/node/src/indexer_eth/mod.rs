pub mod indexer_eth_direct_rpc;
pub mod indexer_eth_helios;

use crate::backlog::Backlog;
use crate::mesh::MeshState;

use crate::metrics::requests::{record_request_latency, SignRequestStep};
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest, Sign, SignRequestType};
use crate::respond_bidirectional::CompletedTx;
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::PendingRequestStatus;
use crate::storage::app_data_storage::AppDataStorage;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::Log;
use alloy::sol_types::{sol, SolEvent};
use k256::Scalar;
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::watch;
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

// This is the maximum number of blocks that Helios can look back to
const MAX_CATCHUP_BLOCKS: u64 = 8191;

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

const MAX_FAILED_BLOCKS: usize = 1024;

fn failed_blocks_channel() -> (
    mpsc::Sender<alloy::rpc::types::Block>,
    mpsc::Receiver<alloy::rpc::types::Block>,
) {
    mpsc::channel(MAX_FAILED_BLOCKS)
}

const MAX_FINALIZED_BLOCKS: usize = 1024;

fn finalized_block_channel() -> (mpsc::Sender<BlockNumber>, mpsc::Receiver<BlockNumber>) {
    mpsc::channel(MAX_FINALIZED_BLOCKS)
}

type BlockNumber = u64;

pub enum BlockToProcess {
    Catchup(BlockNumber),
    NewBlock(Box<alloy::rpc::types::Block>),
}

#[derive(Clone)]
pub struct BlockAndRequests {
    block_number: u64,
    block_hash: alloy::primitives::B256,
    indexed_requests: Vec<IndexedSignRequest>,
    respond_logs: Vec<Log>,
}

impl BlockAndRequests {
    fn new(
        block_number: u64,
        block_hash: alloy::primitives::B256,
        indexed_requests: Vec<IndexedSignRequest>,
        respond_logs: Vec<Log>,
    ) -> Self {
        Self {
            block_number,
            block_hash,
            indexed_requests,
            respond_logs,
        }
    }
}

#[derive(Clone)]
pub struct EthConfig {
    /// The ethereum account secret key used to sign eth respond txn.
    pub account_sk: String,
    /// Ethereum consensus HTTP RPC URL
    pub consensus_rpc_http_url: String,
    /// Ethereum execution HTTP RPC URL
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
    /// light client is true if using helios, false if using direct rpc
    pub light_client: bool,
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
            .field("light_client", &self.light_client)
            .finish()
    }
}

// Configures Ethereum indexer.
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
    /// light client is true if using helios, false if using direct rpc
    #[clap(long, env("MPC_ETH_LIGHT_CLIENT"), default_value = "false")]
    pub eth_light_client: bool,
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
        if self.eth_light_client {
            args.push("--eth-light-client".to_string());
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
            light_client: self.eth_light_client,
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
                eth_light_client: config.light_client,
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
                eth_light_client: false,
            },
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

fn sign_request_from_filtered_log(log: Log, total_timeout: Duration) -> Option<IndexedSignRequest> {
    let event = parse_event(&log);
    tracing::debug!("found eth event: {:?}", event);
    if event.deposit == U256::ZERO {
        tracing::warn!("deposit is 0, skipping sign request");
        return None;
    }

    if event.key_version > LATEST_MPC_KEY_VERSION {
        tracing::warn!("unsupported key version: {}", event.key_version);
        return None;
    }

    // Create sign request from event
    let Some(payload) = Scalar::from_bytes(event.payload_hash) else {
        tracing::warn!(
            "eth `sign` did not produce payload hash correctly: {:?}",
            event.payload_hash,
        );
        return None;
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
        return None;
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

    Some(IndexedSignRequest {
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
        timestamp_created: Instant::now(),
        total_timeout,
        sign_request_type: SignRequestType::Sign,
    })
}
// Helper function to parse event logs
fn parse_event(log: &Log) -> SignatureRequestedEvent {
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

    SignatureRequestedEvent {
        requester,
        payload_hash,
        path,
        key_version,
        deposit,
        chain_id,
        algo,
        dest,
        params,
    }
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

fn parse_filtered_logs(logs: Vec<Log>, total_timeout: Duration) -> Vec<IndexedSignRequest> {
    let mut indexed_requests = Vec::new();
    for log in logs {
        tracing::debug!("Parsing Ethereum log: {:?}", log);
        match sign_request_from_filtered_log(log.clone(), total_timeout) {
            Some(request) => indexed_requests.push(request),
            None => tracing::warn!("Failed to parse Ethereum log: {:?}", log),
        }
    }
    if indexed_requests.is_empty() {
        tracing::warn!("No valid Ethereum sign requests found in logs");
    }
    indexed_requests
}

async fn process_respond_events(logs: &[Log], backlog: &Backlog, sign_tx: mpsc::Sender<Sign>) {
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

fn send_indexed_requests_to_sign_queue(
    requests: Vec<IndexedSignRequest>,
    sign_tx: mpsc::Sender<Sign>,
) {
    for request in requests {
        let sign_tx = sign_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = sign_tx.send(Sign::Request(request)).await {
                tracing::error!(?err, "Failed to send ETH sign request into queue");
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

#[derive(Clone)]
pub enum EthereumClient {
    Helios(indexer_eth_helios::HeliosEthereumClient),
    DirectRpc(indexer_eth_direct_rpc::RpcEthereumClient),
}

impl EthereumClient {
    pub async fn new(eth: EthConfig) -> anyhow::Result<EthereumClient> {
        if eth.light_client {
            Ok(EthereumClient::Helios(
                indexer_eth_helios::build_client(eth.clone()).await?,
            ))
        } else {
            Ok(EthereumClient::DirectRpc(
                indexer_eth_direct_rpc::RpcEthereumClient::new(&eth.execution_rpc_http_url),
            ))
        }
    }

    async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> Option<alloy::rpc::types::Block> {
        match self {
            EthereumClient::Helios(client) => client.get_block(block_id).await,
            EthereumClient::DirectRpc(client) => client.get_block(block_id).await,
        }
    }

    async fn get_block_receipts(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        match self {
            EthereumClient::Helios(client) => client.get_block_receipts(block_id).await,
            EthereumClient::DirectRpc(client) => client.get_block_receipts(block_id).await,
        }
    }

    async fn get_nonce(
        &self,
        address: Address,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        match self {
            EthereumClient::Helios(client) => client.get_nonce(address, block_id).await,
            EthereumClient::DirectRpc(client) => client.get_nonce(address, block_id).await,
        }
    }

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        match self {
            EthereumClient::Helios(client) => client.get_transaction_by_hash(tx_hash).await,
            EthereumClient::DirectRpc(client) => client.get_transaction_by_hash(tx_hash).await,
        }
    }

    pub async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        match self {
            EthereumClient::Helios(client) => client.call(from, to, data, block_number).await,
            EthereumClient::DirectRpc(client) => client.call(from, to, data, block_number).await,
        }
    }

    async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        match self {
            EthereumClient::Helios(client) => client.get_latest_block_number().await,
            EthereumClient::DirectRpc(client) => client.get_latest_block_number().await,
        }
    }
}

#[derive(Clone)]
pub struct EthereumIndexer {
    eth: EthConfig,
    sign_tx: mpsc::Sender<Sign>,
    app_data_storage: AppDataStorage,
    backlog: Backlog,
    contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    client: EthereumClient,
}

impl EthereumIndexer {
    pub async fn new(
        eth: Option<EthConfig>,
        sign_tx: mpsc::Sender<Sign>,
        app_data_storage: AppDataStorage,
        backlog: Backlog,
        contract_watcher: ContractStateWatcher,
        mesh_state: watch::Receiver<MeshState>,
        node_client: NodeClient,
    ) -> anyhow::Result<Self> {
        let Some(eth) = eth else {
            tracing::warn!("ethereum indexer is disabled");
            return Err(anyhow::anyhow!("ethereum indexer is disabled"));
        };

        let client = EthereumClient::new(eth.clone()).await?;

        Ok(Self {
            eth,
            sign_tx,
            app_data_storage,
            backlog,
            contract_watcher,
            mesh_state,
            node_client,
            client,
        })
    }

    pub async fn run(self) {
        let backlog = self.backlog;
        let mut contract_watcher = self.contract_watcher;
        let mut mesh_state = self.mesh_state;
        let node_client = self.node_client;
        let app_data_storage = self.app_data_storage;
        let client = self.client;
        let eth = self.eth;
        let sign_tx = self.sign_tx;

        let total_timeout = Duration::from_secs(eth.total_timeout);

        crate::indexer_common::recover_backlog(
            &backlog,
            &mut contract_watcher,
            &mut mesh_state,
            &node_client,
            Chain::Ethereum,
            sign_tx.clone(),
            total_timeout,
        )
        .await;

        let last_processed_block = Self::get_last_processed_block(&app_data_storage).await;

        let client = Arc::new(client);

        tracing::info!("running ethereum indexer");

        let eth_config_clone = eth.clone();

        let Ok(contract_address) =
            Address::from_str(&format!("0x{}", eth_config_clone.contract_address))
        else {
            tracing::error!(
                "Failed to parse contract address: {}",
                eth_config_clone.contract_address
            );
            return;
        };
        let (blocks_failed_send, blocks_failed_recv) = failed_blocks_channel();

        let (requests_indexed_send, requests_indexed_recv) = indexed_channel();

        let (finalized_block_send, finalized_block_recv) = finalized_block_channel();

        let (blocks_to_process_send, mut blocks_to_process_recv) = blocks_to_process_channel();

        let client_clone = Arc::clone(&client);
        let finalized_block_send_clone = finalized_block_send.clone();
        let refresh_interval = eth.refresh_finalized_interval;
        tokio::spawn(async move {
            tracing::info!("Spawned task to refresh the latest finalized block");
            Self::refresh_finalized_block(
                client_clone,
                finalized_block_send_clone,
                refresh_interval,
            )
            .await;
        });

        let backlog_clone = backlog.clone();
        let client_clone = Arc::clone(&client);
        let optimistic_requests = eth.optimistic_requests;
        let sign_tx_clone = sign_tx.clone();
        tokio::spawn(async move {
            Self::send_requests_when_final(
                client_clone,
                requests_indexed_recv,
                finalized_block_recv,
                sign_tx_clone,
                app_data_storage.clone(),
                optimistic_requests,
                backlog_clone,
            )
            .await;
        });

        let blocks_failed_send_clone = blocks_failed_send.clone();
        let requests_indexed_send_clone = requests_indexed_send.clone();
        let backlog_clone2 = backlog.clone();
        let client_clone = Arc::clone(&client);
        tokio::spawn(async move {
            Self::retry_failed_blocks(
                client_clone,
                blocks_failed_recv,
                blocks_failed_send_clone,
                contract_address,
                requests_indexed_send_clone,
                total_timeout,
                backlog_clone2,
            )
            .await;
        });

        let blocks_to_process_send_clone = blocks_to_process_send.clone();
        if let Some(last_processed_block) = last_processed_block {
            match Self::catchup_end_block_number(Arc::clone(&client)).await {
                Ok(end_block_number) => {
                    Self::add_catchup_blocks_to_process(
                        blocks_to_process_send_clone,
                        last_processed_block,
                        end_block_number,
                    )
                    .await
                }
                Err(err) => {
                    tracing::error!("Failed to get catchup end block number: {err:?}");
                }
            }
        }

        tokio::spawn(Self::add_new_block_to_process(
            Arc::clone(&client),
            blocks_to_process_send.clone(),
        ));

        let mut interval = tokio::time::interval(Duration::from_millis(200));
        let requests_indexed_send_clone = requests_indexed_send.clone();
        loop {
            let Some(block_to_process) = blocks_to_process_recv.recv().await else {
                interval.tick().await;
                continue;
            };
            let (block, is_catchup) = match block_to_process {
                BlockToProcess::Catchup(block_number) => {
                    let block = client
                        .get_block(alloy::rpc::types::BlockId::Number(
                            BlockNumberOrTag::Number(block_number),
                        ))
                        .await;
                    if let Some(block) = block {
                        (block, true)
                    } else {
                        tracing::warn!("Block {block_number} not found from Ethereum client");
                        continue;
                    }
                }
                BlockToProcess::NewBlock(block) => ((*block).clone(), false),
            };
            let block_number = block.header.number;
            if let Err(err) = Self::process_block(
                client.clone(),
                block.clone(),
                contract_address,
                requests_indexed_send_clone.clone(),
                total_timeout,
                backlog.clone(),
            )
            .await
            {
                tracing::warn!(
                    "Eth indexer failed to process block number {block_number}: {err:?}"
                );
                Self::add_failed_block(blocks_failed_send.clone(), block).await;
                continue;
            }
            if block_number % 10 == 0 {
                if is_catchup {
                    tracing::info!("Processed catchup block number {block_number}");
                } else {
                    tracing::info!("Processed new block number {block_number}");
                }
            }
            crate::metrics::indexers::LATEST_BLOCK_NUMBER
                .with_label_values(&[Chain::Ethereum.as_str(), "indexed"])
                .set(block_number as i64);
        }
    }

    async fn add_new_block_to_process(
        client: Arc<EthereumClient>,
        blocks_to_process: mpsc::Sender<BlockToProcess>,
    ) {
        tracing::info!("Adding new blocks to process...");
        let mut current_block = 0;
        loop {
            let Some(latest_block) = client
                .get_block(alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Latest))
                .await
            else {
                continue;
            };
            let block_number = latest_block.header.number;
            if block_number <= current_block {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            if let Err(err) = blocks_to_process
                .send(BlockToProcess::NewBlock(Box::new(latest_block)))
                .await
            {
                tracing::warn!("Failed to send new block to process: {err:?}");
            }
            current_block = block_number;
        }
    }
    async fn catchup_end_block_number(client: Arc<EthereumClient>) -> anyhow::Result<BlockNumber> {
        client.get_latest_block_number().await
    }

    async fn process_block(
        client: Arc<EthereumClient>,
        block: alloy::rpc::types::Block,
        contract_address: Address,
        requests_indexed: mpsc::Sender<BlockAndRequests>,
        total_timeout: Duration,
        backlog: Backlog,
    ) -> anyhow::Result<()> {
        let block_number = block.header.number;
        let block_hash = block.header.hash;
        let block_timestamp = block.header.timestamp;
        tracing::info!(
            "Processing block number {} with hash {:?}",
            block_number,
            block_hash
        );
        let block_receipts = client
            .get_block_receipts(block_number.into())
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "Failed to get block receipts for block number {block_number}: {:?}",
                    err
                )
            })?;

        let Some(block_receipts) = block_receipts else {
            tracing::info!("no receipts for block number {block_number}");
            return Ok(());
        };

        let mut sign_requests = Vec::new();

        let relevant_logs: Vec<Log> = block_receipts
            .clone()
            .into_iter()
            .filter_map(|receipt| receipt.as_ref().as_receipt().cloned())
            .flat_map(|receipt| {
                receipt
                    .logs
                    .into_iter()
                    .filter(|log| log.address() == contract_address)
            })
            .collect();

        let (respond_logs, potential_request_logs): (Vec<Log>, Vec<Log>) =
            relevant_logs.into_iter().partition(|log| {
                log.topic0()
                    .is_some_and(|topic| *topic == SignatureResponded::SIGNATURE_HASH)
            });

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

        let respond_requests = Self::process_bidirectional_requests(
            &client,
            block_number,
            total_timeout,
            &backlog,
            block_receipts,
        )
        .await?;
        sign_requests.extend(respond_requests);

        if !sign_requests.is_empty() || !respond_logs.is_empty() {
            for _request in &sign_requests {
                record_request_latency(
                    Chain::Ethereum,
                    SignRequestStep::Indexing,
                    "ok",
                    block_timestamp,
                );
            }
            requests_indexed
                .send(BlockAndRequests::new(
                    block_number,
                    block_hash,
                    sign_requests.clone(),
                    respond_logs,
                ))
                .await
                .map_err(|err| anyhow::anyhow!("Failed to send indexed requests: {:?}", err))?;
        }

        Ok(())
    }

    async fn process_bidirectional_requests(
        client: &Arc<EthereumClient>,
        block_number: u64,
        total_timeout: Duration,
        backlog: &Backlog,
        block_receipts: Vec<alloy::rpc::types::TransactionReceipt>,
    ) -> anyhow::Result<Vec<IndexedSignRequest>> {
        let block_receipts: std::collections::HashMap<
            alloy::primitives::B256,
            alloy::rpc::types::TransactionReceipt,
        > = block_receipts
            .into_iter()
            .map(|receipt| (receipt.transaction_hash, receipt.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        let mut respond_requests = Vec::new();

        let watchers = backlog.pending_execution(Chain::Ethereum).await;
        tracing::info!(
            watchers_count = watchers.len(),
            block_number,
            "process_bidirectional_requests checking watchers"
        );

        for (tx_id, (sign_id, pending_tx)) in watchers {
            tracing::info!(?tx_id, ?sign_id, "querying receipt for bidirectional tx");
            let Some(receipt) = block_receipts.get(&pending_tx.id.0) else {
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
                match completed_tx.extract_success_tx_output(client).await {
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
                            Ok(sign_request) => {
                                tracing::info!(
                                    ?tx_id,
                                    ?sign_id,
                                    ?sign_request,
                                    "sign_request from serialized output"
                                );
                                respond_requests.push(sign_request);
                            }
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
                    .create_failed_sign_request(source_chain, total_timeout)
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
                .as_ref()
                .get_nonce(
                    tx.from_address,
                    alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(block_number)),
                )
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
                    .create_failed_sign_request(tx.source_chain, total_timeout)
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

    /// Sends a request to the sign queue when the block where the request is in is finalized.
    async fn send_requests_when_final(
        client: Arc<EthereumClient>,
        mut requests_indexed: mpsc::Receiver<BlockAndRequests>,
        mut finalized_block_rx: mpsc::Receiver<BlockNumber>,
        sign_tx: mpsc::Sender<Sign>,
        app_data_storage: AppDataStorage,
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
                respond_logs,
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
            let block = client
                .as_ref()
                .get_block(alloy::rpc::types::BlockId::Number(
                    BlockNumberOrTag::Number(block_number),
                ))
                .await;

            let Some(block) = block else {
                tracing::warn!("Block {block_number} not found from Ethereum client, skipping this block and its requests");
                continue;
            };

            if block.header.hash == block_hash {
                tracing::info!("Block {block_number} is finalized!");
                send_indexed_requests_to_sign_queue(indexed_requests, sign_tx.clone());

                if !respond_logs.is_empty() {
                    process_respond_events(&respond_logs, &backlog, sign_tx.clone()).await;
                }
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

    async fn retry_failed_blocks(
        client: Arc<EthereumClient>,
        mut blocks_failed_rx: mpsc::Receiver<alloy::rpc::types::Block>,
        blocks_failed_tx: mpsc::Sender<alloy::rpc::types::Block>,
        contract_address: Address,
        requests_indexed: mpsc::Sender<BlockAndRequests>,
        total_timeout: Duration,
        backlog: Backlog,
    ) {
        loop {
            let Some(block) = blocks_failed_rx.recv().await else {
                tracing::warn!("Failed to receive block and requests from requests_indexed");
                break;
            };
            let block_number = block.header.number;
            if let Err(err) = Self::process_block(
                client.clone(),
                block.clone(),
                contract_address,
                requests_indexed.clone(),
                total_timeout,
                backlog.clone(),
            )
            .await
            {
                tracing::warn!("Retry failed for block {block_number}: {err:?}");
                Self::add_failed_block(blocks_failed_tx.clone(), block).await;
            } else {
                tracing::info!("Successfully retried block: {block_number}");
            }
        }
    }

    async fn add_failed_block(
        blocks_failed: mpsc::Sender<alloy::rpc::types::Block>,
        block: alloy::rpc::types::Block,
    ) {
        blocks_failed.send(block).await.unwrap_or_else(|err| {
            tracing::warn!("Failed to send failed block: {:?}", err);
        });
    }

    /// Polls for the latest finalized block and update finalized block channel.
    async fn refresh_finalized_block(
        client: Arc<EthereumClient>,
        finalized_block_send: mpsc::Sender<BlockNumber>,
        refresh_finalized_interval: u64,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(refresh_finalized_interval));
        let mut final_block_number: Option<BlockNumber> = None;

        loop {
            interval.tick().await;
            tracing::info!("Refreshing finalized epoch");

            let new_finalized_block = match client
                .as_ref()
                .get_block(alloy::rpc::types::BlockId::Number(
                    BlockNumberOrTag::Finalized,
                ))
                .await
            {
                Some(block) => block,
                None => {
                    tracing::warn!("Finalized block not found from Ethereum client");
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
                crate::metrics::indexers::LATEST_BLOCK_NUMBER
                    .with_label_values(&[Chain::Ethereum.as_str(), "finalized"])
                    .set(new_final_block_number as i64);
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

    async fn get_last_processed_block(app_data_storage: &AppDataStorage) -> Option<BlockNumber> {
        app_data_storage
            .last_processed_block_eth()
            .await
            .unwrap_or_else(|err| {
                tracing::warn!("Failed to get last processed block: {err:?}");
                None
            })
    }
}
