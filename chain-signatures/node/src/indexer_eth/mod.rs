pub mod indexer_eth_direct_rpc;
pub mod indexer_eth_helios;

use crate::backlog::Backlog;
use crate::stream::ops::{EthereumSignatureRespondedEvent, SignatureRespondedEvent};

use crate::metrics::requests::{record_request_latency, SignRequestStep};
use crate::protocol::{Chain, IndexedSignRequest};
use crate::respond_bidirectional::CompletedTx;
use crate::sign_bidirectional::SignStatus;
use crate::stream::{ChainEvent, ChainStream, ExecutionOutcome};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::Log;
use alloy::sol_types::{sol, SolEvent};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint as K256AffinePoint, EncodedPoint, FieldBytes, Scalar};
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{SignArgs, SignId, Signature as MpcSignature, LATEST_MPC_KEY_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
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
            .field("optimistic_requests", &self.optimistic_requests)
            .field("light_client", &self.light_client)
            .finish()
    }
}

// Configures Ethereum indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_eth_options")]
pub struct EthArgs {
    // -- Core --
    /// The ethereum account secret key used to sign eth respond txn.
    #[arg(
        long,
        env("MPC_ETH_ACCOUNT_SK"),
        requires_all = ["eth_execution_rpc_http_url", "eth_contract_address"]
    )]
    pub eth_account_sk: Option<String>,
    /// The contract address to watch without the `0x` prefix
    #[clap(long, env("MPC_ETH_CONTRACT_ADDRESS"), requires = "eth_account_sk")]
    pub eth_contract_address: Option<String>,

    // -- RPC endpoints --
    /// Ethereum execution RPC URL
    #[clap(
        long,
        env("MPC_ETH_EXECUTION_RPC_HTTP_URL"),
        requires = "eth_account_sk"
    )]
    pub eth_execution_rpc_http_url: Option<String>,

    // -- Helios light-client --
    /// Use Helios light client instead of direct RPC
    #[clap(
        long,
        env("MPC_ETH_LIGHT_CLIENT"),
        default_value = "false",
        requires_if("true", "eth_consensus_rpc_http_url")
    )]
    pub eth_light_client: bool,
    /// Ethereum consensus RPC URL (required when --eth-light-client is set)
    #[clap(
        long,
        env("MPC_ETH_CONSENSUS_RPC_HTTP_URL"),
        requires = "eth_account_sk"
    )]
    pub eth_consensus_rpc_http_url: Option<String>,
    /// The network that the eth indexer is running on. Either "sepolia"/"mainnet"
    #[clap(
        long,
        env("MPC_ETH_NETWORK"),
        requires = "eth_account_sk",
        default_value = "sepolia",
        value_parser = ["sepolia", "mainnet"],
    )]
    pub eth_network: Option<String>,
    /// Helios light client data path
    #[clap(
        long,
        env("MPC_ETH_HELIOS_DATA_PATH"),
        requires = "eth_account_sk",
        default_value = "/helios/sepolia"
    )]
    pub eth_helios_data_path: Option<String>,

    // -- Behaviour --
    /// Refresh finalized block interval in milliseconds
    #[clap(
        long,
        env("MPC_ETH_REFRESH_FINALIZED_INTERVAL"),
        default_value = "10000"
    )]
    pub eth_refresh_finalized_interval: Option<u64>,
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
            consensus_rpc_http_url: self.eth_consensus_rpc_http_url.unwrap_or_default(),
            execution_rpc_http_url: self.eth_execution_rpc_http_url.unwrap(),
            contract_address: self.eth_contract_address.unwrap(),
            network: self.eth_network.unwrap_or_default(),
            helios_data_path: self.eth_helios_data_path.unwrap_or_default(),
            refresh_finalized_interval: self.eth_refresh_finalized_interval.unwrap(),
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

    struct AffinePoint {
        uint256 x;
        uint256 y;
    }

    struct Signature {
        AffinePoint bigR;
        uint256 s;
        uint8 recoveryId;
    }

    event SignatureResponded(bytes32 indexed requestId, address responder, Signature signature);
}

fn sign_request_from_filtered_log(log: Log) -> Option<IndexedSignRequest> {
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

    Some(IndexedSignRequest::sign(
        sign_id,
        SignArgs {
            entropy: entropy.into(),
            epsilon,
            payload,
            path: event.path,
            key_version: event.key_version,
        },
        Chain::Ethereum,
        crate::util::current_unix_timestamp(),
    ))
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

fn parse_filtered_logs(logs: Vec<Log>) -> Vec<IndexedSignRequest> {
    let mut indexed_requests = Vec::new();
    for log in logs {
        tracing::debug!("Parsing Ethereum log: {:?}", log);
        match sign_request_from_filtered_log(log.clone()) {
            Some(request) => indexed_requests.push(request),
            None => tracing::warn!("Failed to parse Ethereum log: {:?}", log),
        }
    }
    if indexed_requests.is_empty() {
        tracing::warn!("No valid Ethereum sign requests found in logs");
    }
    indexed_requests
}

async fn emit_respond_events(logs: &[Log], events_tx: mpsc::Sender<ChainEvent>) {
    for log in logs {
        let Some(sign_id) = sign_id_from_signature_responded_log(log) else {
            continue;
        };

        let data = &log.data().data;
        if data.len() < 160 {
            tracing::warn!(
                ?sign_id,
                data_len = data.len(),
                "signature event data too short to parse full signature: skipping..."
            );
            continue;
        }

        // responder: offset 0..32 (address right-padded)
        let responder_addr = Address::from_slice(&data[12..32]);
        // signature struct encoding layout:
        // bigR.x at 32..64, bigR.y at 64..96, s at 96..128, recoveryId at 159
        let big_r_x = &data[32..64];
        let big_r_y = &data[64..96];
        let s_bytes: [u8; 32] = data[96..128].try_into().unwrap();
        let recovery_id = data[159];

        let x_field = FieldBytes::from_slice(big_r_x);
        let y_field = FieldBytes::from_slice(big_r_y);
        let encoded_r = EncodedPoint::from_affine_coordinates(x_field, y_field, false);
        let Some(big_r) = K256AffinePoint::from_encoded_point(&encoded_r).into_option() else {
            tracing::warn!(?sign_id, "ethereum respond event, invalid big_r point");
            continue;
        };

        let Some(s) = Scalar::from_bytes(s_bytes) else {
            tracing::warn!(?sign_id, "ethereum respond event, invalid s scalar");
            continue;
        };

        let signature = MpcSignature::new(big_r, s, recovery_id);

        let eth_event = EthereumSignatureRespondedEvent {
            request_id: sign_id.request_id,
            responder: responder_addr,
            signature,
        };

        let respond_event = SignatureRespondedEvent::Ethereum(eth_event);
        tracing::info!(?sign_id, "emitting SignatureResponded event");
        if let Err(err) = events_tx.send(ChainEvent::Respond(respond_event)).await {
            tracing::error!(?err, "failed to emit Respond event");
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

    fn client_name(&self) -> &str {
        match self {
            EthereumClient::Helios(_) => "Helios",
            EthereumClient::DirectRpc(_) => "DirectRpc",
        }
    }

    async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> Option<alloy::rpc::types::Block> {
        // Configure retry behaviour and delegate to shared retry_async helper.
        let retry_config = crate::util::retry::RetryConfig::default();
        let get_block_op = |_attempt: usize| async {
            match self {
                EthereumClient::Helios(client) => client.get_block(block_id).await,
                EthereumClient::DirectRpc(client) => client.get_block(block_id).await,
            }
        };

        let res = crate::util::retry::retry_async(
            retry_config,
            get_block_op,
            |_attempt, _reason| true,
            |attempt, reason, sleep_duration| match reason {
                crate::util::retry::RetryReason::Error(e) => {
                    tracing::warn!(
                        client = self.client_name(),
                        "get_block failed (attempt {attempt}) for {block_id:?}: {e:#}; retrying in {sleep_duration:?}"
                    );
                }
                crate::util::retry::RetryReason::Timeout(t) => {
                    tracing::warn!(
                        client = self.client_name(),
                        "get_block timed out after {t:?} (attempt {attempt}) for {block_id:?}; retrying in {sleep_duration:?}"
                    );
                }
            },
        )
        .await;

        match res {
            Ok(Some(block)) => Some(block),
            Ok(None) => {
                tracing::warn!(client = self.client_name(), "Block {block_id:?} not found");
                None
            }
            Err(crate::util::retry::RetryError::Exhausted {
                attempts,
                last_error,
            }) => {
                tracing::warn!(
                    client = self.client_name(),
                    "get_block failed for {block_id:?}: {last_error:#}; exhausted after {attempts} attempts"
                );
                None
            }
            Err(crate::util::retry::RetryError::TimeoutExhausted {
                attempts,
                last_timeout,
            }) => {
                tracing::warn!(
                    client = self.client_name(),
                    "get_block timed out for {block_id:?} (last timeout {last_timeout:?}); exhausted after {attempts} attempts"
                );
                None
            }
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

    async fn get_latest_block_number(&self) -> Option<u64> {
        self.get_block(alloy::rpc::types::BlockId::Number(
            alloy::rpc::types::BlockNumberOrTag::Latest,
        ))
        .await
        .map(|block| block.header.number)
    }
}

#[derive(Clone)]
pub struct EthereumIndexer {
    eth: EthConfig,
    backlog: Backlog,
    client: EthereumClient,
}

impl EthereumIndexer {
    pub async fn new(eth: EthConfig, backlog: Backlog) -> anyhow::Result<Self> {
        let client = EthereumClient::new(eth.clone()).await?;

        Ok(Self {
            eth,
            backlog,
            client,
        })
    }

    pub async fn run(self, events_tx: mpsc::Sender<ChainEvent>) {
        let backlog = self.backlog;
        let eth = self.eth;
        let client = Arc::new(self.client);

        tracing::info!("running ethereum indexer");
        let Ok(contract_address) = Address::from_str(&format!("0x{}", eth.contract_address)) else {
            tracing::error!("Failed to parse contract address: {}", eth.contract_address);
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

        let client_clone = Arc::clone(&client);
        let optimistic_requests = eth.optimistic_requests;
        tokio::spawn(Self::send_requests_when_final(
            client_clone,
            requests_indexed_recv,
            finalized_block_recv,
            events_tx.clone(),
            optimistic_requests,
        ));

        tokio::spawn(Self::retry_failed_blocks(
            Arc::clone(&client),
            blocks_failed_recv,
            blocks_failed_send.clone(),
            contract_address,
            requests_indexed_send.clone(),
            backlog.clone(),
            events_tx.clone(),
        ));

        let last_processed_block = backlog.processed_block(Chain::Ethereum).await;
        let mut expected_catchup_blocks = 0usize;
        let mut processed_catchup_blocks = HashSet::new();
        let mut catchup_completed_emitted = false;

        let blocks_to_process_send_clone = blocks_to_process_send.clone();
        if let Some(last_processed_block) = last_processed_block {
            match Self::catchup_end_block_number(Arc::clone(&client)).await {
                Some(end_block_number) => {
                    expected_catchup_blocks = end_block_number
                        .saturating_sub(last_processed_block)
                        .saturating_add(1) as usize;
                    Self::add_catchup_blocks_to_process(
                        blocks_to_process_send_clone,
                        last_processed_block,
                        end_block_number,
                    )
                    .await
                }
                None => {
                    tracing::error!("Failed to get catchup end block number");
                }
            }
        }

        if expected_catchup_blocks == 0 {
            if let Err(err) = events_tx.send(ChainEvent::CatchupCompleted).await {
                tracing::warn!(?err, "failed to emit ethereum catchup completion event");
            } else {
                catchup_completed_emitted = true;
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
                backlog.clone(),
                events_tx.clone(),
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

            if is_catchup && !catchup_completed_emitted {
                processed_catchup_blocks.insert(block_number);
                if processed_catchup_blocks.len() >= expected_catchup_blocks {
                    if let Err(err) = events_tx.send(ChainEvent::CatchupCompleted).await {
                        tracing::warn!(?err, "failed to emit ethereum catchup completion event");
                    } else {
                        catchup_completed_emitted = true;
                    }
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
    async fn catchup_end_block_number(client: Arc<EthereumClient>) -> Option<BlockNumber> {
        client.get_latest_block_number().await
    }

    async fn process_block(
        client: Arc<EthereumClient>,
        block: alloy::rpc::types::Block,
        contract_address: Address,
        requests_indexed: mpsc::Sender<BlockAndRequests>,
        backlog: Backlog,
        events_tx: mpsc::Sender<ChainEvent>,
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

        // Some clients return `None` for blocks with no transactions. We still want to
        // emit a `ChainEvent::Block` for checkpointing and progress tracking, so treat
        // it as an empty receipts list.
        let block_receipts = match block_receipts {
            Some(receipts) => receipts,
            None => {
                tracing::debug!(block_number, "no receipts for block; treating as empty");
                Vec::new()
            }
        };

        let mut sign_requests = Vec::new();

        let relevant_logs: Vec<Log> = block_receipts
            .iter()
            .filter_map(|receipt| receipt.as_ref().as_receipt())
            .flat_map(|receipt| {
                receipt
                    .logs
                    .iter()
                    .filter(|log| log.address() == contract_address)
                    .cloned()
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
            sign_requests.extend(parse_filtered_logs(request_logs));
        }

        // Collect execution confirmations (if any) and emit ExecutionConfirmed events
        let exec_events = Self::collect_execution_confirmations(
            &client,
            block_number,
            &backlog,
            block_receipts.clone(),
        )
        .await?;
        for ev in exec_events {
            if let Err(err) = events_tx.send(ev).await {
                tracing::error!(?err, "failed to emit ExecutionConfirmed event");
            }
        }

        for _request in &sign_requests {
            record_request_latency(
                Chain::Ethereum,
                SignRequestStep::Indexing,
                "ok",
                block_timestamp,
            );
        }

        // Always forward the processed block to the "finalization" stage so it can emit
        // `ChainEvent::Block` even when there are no relevant contract logs.
        requests_indexed
            .send(BlockAndRequests::new(
                block_number,
                block_hash,
                sign_requests,
                respond_logs,
            ))
            .await
            .map_err(|err| anyhow::anyhow!("Failed to send indexed requests: {:?}", err))?;

        Ok(())
    }

    async fn collect_execution_confirmations(
        client: &Arc<EthereumClient>,
        block_number: u64,
        backlog: &Backlog,
        block_receipts: Vec<alloy::rpc::types::TransactionReceipt>,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        let block_receipts: std::collections::HashMap<
            alloy::primitives::B256,
            alloy::rpc::types::TransactionReceipt,
        > = block_receipts
            .into_iter()
            .map(|receipt| (receipt.transaction_hash, receipt.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        let mut events = Vec::new();

        let watchers = backlog.pending_execution(Chain::Ethereum).await;
        tracing::info!(
            watchers_count = watchers.len(),
            block_number,
            "collect_execution_confirmations checking watchers"
        );

        for (tx_id, (sign_id, pending_tx)) in watchers {
            tracing::info!(?tx_id, ?sign_id, "querying receipt for bidirectional tx");
            let Some(receipt) = block_receipts.get(&pending_tx.id.0) else {
                continue;
            };

            let status = if receipt.status() {
                SignStatus::Success
            } else {
                SignStatus::Failed
            };

            tracing::info!(
                ?tx_id,
                ?sign_id,
                block_number,
                "bidirectional execution observed via rpc"
            );

            let source_chain = pending_tx.source_chain;

            let result = if status == SignStatus::Success {
                let completed_tx = CompletedTx::new(pending_tx.clone(), block_number);
                match completed_tx.extract_success_tx_output(client).await {
                    Ok(serialized_output) => {
                        tracing::info!(
                            ?tx_id,
                            ?sign_id,
                            "extracted transaction output for bidirectional tx"
                        );
                        ExecutionOutcome::Success {
                            output: serialized_output,
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            ?tx_id,
                            ?sign_id,
                            ?err,
                            "Failed to extract transaction output for bidirectional tx, using empty output"
                        );
                        ExecutionOutcome::Success { output: vec![] }
                    }
                }
            } else {
                ExecutionOutcome::Failed
            };

            events.push(ChainEvent::ExecutionConfirmed {
                tx_id,
                sign_id,
                source_chain,
                block_height: block_number,
                result,
            });
        }

        // Staleness checks (nonce too low)
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
                events.push(ChainEvent::ExecutionConfirmed {
                    tx_id,
                    sign_id,
                    source_chain: tx.source_chain,
                    block_height: block_number,
                    result: ExecutionOutcome::Failed,
                });
            }
        }

        Ok(events)
    }

    /// Sends a request to the sign queue when the block where the request is in is finalized.
    async fn send_requests_when_final(
        client: Arc<EthereumClient>,
        mut requests_indexed: mpsc::Receiver<BlockAndRequests>,
        mut finalized_block_rx: mpsc::Receiver<BlockNumber>,
        events_tx: mpsc::Sender<ChainEvent>,
        optimistic_requests: bool,
    ) {
        let mut finalized_block_number: Option<BlockNumber> = None;

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

                for req in indexed_requests.clone() {
                    if let Err(err) = events_tx.send(ChainEvent::SignRequest(req)).await {
                        tracing::error!(?err, "failed to emit SignRequest event");
                    }
                }

                if !respond_logs.is_empty() {
                    emit_respond_events(&respond_logs, events_tx.clone()).await;
                }

                if let Err(err) = events_tx.send(ChainEvent::Block(block_number)).await {
                    tracing::error!(?err, "failed to emit block event");
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

    #[allow(clippy::too_many_arguments)]
    async fn retry_failed_blocks(
        client: Arc<EthereumClient>,
        mut blocks_failed_rx: mpsc::Receiver<alloy::rpc::types::Block>,
        blocks_failed_tx: mpsc::Sender<alloy::rpc::types::Block>,
        contract_address: Address,
        requests_indexed: mpsc::Sender<BlockAndRequests>,
        backlog: Backlog,
        events_tx: mpsc::Sender<ChainEvent>,
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
                backlog.clone(),
                events_tx.clone(),
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
            tracing::debug!("Refreshing finalized epoch");

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
            tracing::debug!(
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
                tracing::debug!("No new finalized block");
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
}

/// Ethereum indexer stream implementing the `ChainStream` trait.
/// Construction is side-effect free; the shared `run_stream()` loop calls
/// `start()` after recovery has completed.
pub struct EthereumStream {
    events_rx: mpsc::Receiver<ChainEvent>,
    indexer: Option<(EthereumIndexer, mpsc::Sender<ChainEvent>)>,
    tasks: Vec<JoinHandle<()>>,
}

impl EthereumStream {
    pub async fn new(eth: Option<EthConfig>, backlog: Backlog) -> anyhow::Result<Self> {
        let Some(eth) = eth else {
            tracing::warn!(
                "ethereum indexer is disabled: no EthConfig provided \
                 (check that all --eth-* CLI flags were supplied)"
            );
            return Err(anyhow::anyhow!(
                "ethereum indexer is disabled: no EthConfig provided"
            ));
        };
        tracing::info!(
            eth_config = ?eth,
            "creating ethereum indexer stream"
        );

        let indexer = EthereumIndexer::new(eth, backlog).await?;

        let (events_tx, events_rx) = crate::stream::channel();

        Ok(Self {
            events_rx,
            indexer: Some((indexer, events_tx)),
            tasks: Vec::new(),
        })
    }

    pub fn start(&mut self) {
        let Some((indexer, events_tx)) = self.indexer.take() else {
            return;
        };

        let t_indexer: JoinHandle<()> = tokio::spawn(async move {
            indexer.run(events_tx).await;
        });

        self.tasks.push(t_indexer);
    }
}

impl Drop for EthereumStream {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl ChainStream for EthereumStream {
    const CHAIN: Chain = Chain::Ethereum;

    async fn start(&mut self) {
        self.start();
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        self.events_rx.recv().await
    }
}
