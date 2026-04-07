pub mod indexer_eth_direct_rpc;
pub mod indexer_eth_helios;

use crate::backlog::Backlog;
use crate::stream::ops::{EthereumSignatureRespondedEvent, SignatureRespondedEvent};

use crate::metrics::requests::{record_request_latency, SignRequestStep};
use crate::protocol::{Chain, IndexedSignRequest};
use crate::respond_bidirectional::CompletedTx;
use crate::sign_bidirectional::SignStatus;
use crate::stream::{ChainBufferedStream, ChainEvent, ChainStream, ExecutionOutcome};

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
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
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

fn live_blocks_channel() -> (
    mpsc::Sender<alloy::rpc::types::Block>,
    mpsc::Receiver<alloy::rpc::types::Block>,
) {
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
    #[cfg(test)]
    Test(TestEthereumClient),
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
            #[cfg(test)]
            EthereumClient::Test(_) => "Test",
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
                #[cfg(test)]
                EthereumClient::Test(client) => client.get_block(block_id).await,
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
            #[cfg(test)]
            EthereumClient::Test(client) => client.get_block_receipts(block_id).await,
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
            #[cfg(test)]
            EthereumClient::Test(client) => client.get_nonce(address, block_id).await,
        }
    }

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        match self {
            EthereumClient::Helios(client) => client.get_transaction_by_hash(tx_hash).await,
            EthereumClient::DirectRpc(client) => client.get_transaction_by_hash(tx_hash).await,
            #[cfg(test)]
            EthereumClient::Test(client) => client.get_transaction_by_hash(tx_hash).await,
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
            #[cfg(test)]
            EthereumClient::Test(client) => client.call(from, to, data, block_number).await,
        }
    }
}


#[cfg(test)]
#[derive(Clone)]
pub struct TestEthereumClient {
    latest_sequence: Arc<Mutex<std::collections::VecDeque<u64>>>,
    blocks: Arc<std::collections::HashMap<u64, alloy::rpc::types::Block>>,
}

#[cfg(test)]
impl TestEthereumClient {
    fn new(latest_sequence: impl IntoIterator<Item = u64>, blocks: Vec<alloy::rpc::types::Block>) -> Self {
        let blocks = blocks
            .into_iter()
            .map(|block| (block.header.number, block))
            .collect();

        Self {
            latest_sequence: Arc::new(Mutex::new(latest_sequence.into_iter().collect())),
            blocks: Arc::new(blocks),
        }
    }

    async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        let block_number = match block_id {
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Latest) => {
                let mut latest_sequence = self.latest_sequence.lock().unwrap();
                match latest_sequence.len() {
                    0 => return Ok(None),
                    1 => *latest_sequence.front().unwrap(),
                    _ => latest_sequence.pop_front().unwrap(),
                }
            }
            alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(block_number)) => {
                block_number
            }
            alloy::rpc::types::BlockId::Number(_) | alloy::rpc::types::BlockId::Hash(_) => {
                return Ok(None);
            }
        };

        Ok(self.blocks.get(&block_number).cloned())
    }

    async fn get_block_receipts(
        &self,
        _block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        Ok(Some(Vec::new()))
    }

    async fn get_nonce(
        &self,
        _address: Address,
        _block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        Ok(0)
    }

    async fn get_transaction_by_hash(
        &self,
        _tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        Ok(None)
    }

    async fn call(
        &self,
        _from: Address,
        _to: Address,
        _data: Bytes,
        _block_number: u64,
    ) -> anyhow::Result<Bytes> {
        Ok(Bytes::default())
    }
}

#[derive(Clone)]
pub struct EthereumIndexer {
    client: EthereumClient,
}

impl EthereumIndexer {
    pub async fn new(eth: EthConfig, _backlog: Backlog) -> anyhow::Result<Self> {
        let client = EthereumClient::new(eth.clone()).await?;

        Ok(Self { client })
    }

    async fn poll_live_blocks(
        client: Arc<EthereumClient>,
        live_blocks: mpsc::Sender<alloy::rpc::types::Block>,
    ) {
        tracing::info!("polling ethereum live blocks");
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
            if let Err(err) = live_blocks.send(latest_block).await {
                tracing::warn!("Failed to buffer live block: {err:?}");
                return;
            }
            current_block = block_number;
        }
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
}

#[derive(Clone)]
struct EthereumBlockProcessor {
    client: Arc<EthereumClient>,
    contract_address: Address,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
    blocks_failed: mpsc::Sender<alloy::rpc::types::Block>,
    backlog: Backlog,
    events_tx: mpsc::Sender<ChainEvent>,
}

impl EthereumBlockProcessor {
    async fn process_live_block(&self, block: alloy::rpc::types::Block) {
        self.process_block(block, false).await;
    }

    async fn process_catchup_block(&self, block_number: u64) {
        let Some(block) = self
            .client
            .get_block(alloy::rpc::types::BlockId::Number(
                BlockNumberOrTag::Number(block_number),
            ))
            .await
        else {
            tracing::warn!("Block {block_number} not found from Ethereum client");
            return;
        };

        self.process_block(block, true).await;
    }

    async fn process_block(&self, block: alloy::rpc::types::Block, is_catchup: bool) {
        let block_number = block.header.number;
        if let Err(err) = EthereumIndexer::process_block(
            Arc::clone(&self.client),
            block.clone(),
            self.contract_address,
            self.requests_indexed.clone(),
            self.backlog.clone(),
            self.events_tx.clone(),
        )
        .await
        {
            tracing::warn!("Eth indexer failed to process block number {block_number}: {err:?}");
            EthereumIndexer::add_failed_block(self.blocks_failed.clone(), block).await;
            return;
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

#[derive(Default)]
struct BufferedLiveState {
    initial_block: Option<alloy::rpc::types::Block>,
    replay_initial_block: bool,
}

pub struct EthereumBufferedStream {
    live_state: Arc<Mutex<BufferedLiveState>>,
    live_blocks_rx: mpsc::Receiver<alloy::rpc::types::Block>,
    processor: EthereumBlockProcessor,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ChainBufferedStream for EthereumBufferedStream {
    async fn initial_block_height(&mut self) -> Option<u64> {
        if let Some(block) = self.live_state.lock().unwrap().initial_block.as_ref() {
            return Some(block.header.number);
        }

        if let Some(block) = self.live_blocks_rx.recv().await {
            let block_number = block.header.number;
            let mut live_state = self.live_state.lock().unwrap();
            live_state.initial_block = Some(block);
            live_state.replay_initial_block = true;
            return Some(block_number);
        }

        None
    }

    async fn run(self) {
        let processor = self.processor.clone();
        let mut live_blocks_rx = self.live_blocks_rx;
        let initial_block = {
            let mut live_state = self.live_state.lock().unwrap();
            if live_state.replay_initial_block {
                live_state.initial_block.take()
            } else {
                live_state.initial_block = None;
                None
            }
        };
        let task = tokio::spawn(async move {
            if let Some(initial_block) = initial_block {
                processor.process_live_block(initial_block).await;
            }

            while let Some(block) = live_blocks_rx.recv().await {
                processor.process_live_block(block).await;
            }
        });

        self.tasks.lock().unwrap().push(task);
    }
}

/// Ethereum indexer stream implementing the `ChainStream` trait.
pub struct EthereumStream {
    backlog: Backlog,
    client: Arc<EthereumClient>,
    events_rx: mpsc::Receiver<ChainEvent>,
    processor: EthereumBlockProcessor,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    live_state: Option<Arc<Mutex<BufferedLiveState>>>,
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

        let indexer = EthereumIndexer::new(eth.clone(), backlog.clone()).await?;
        let client = Arc::new(indexer.client);
        let contract_address = Address::from_str(&format!("0x{}", eth.contract_address))
            .map_err(|_| anyhow::anyhow!("Failed to parse contract address: {}", eth.contract_address))?;

        let (events_tx, events_rx) = crate::stream::channel();
        let (blocks_failed_send, blocks_failed_recv) = failed_blocks_channel();
        let (requests_indexed_send, requests_indexed_recv) = indexed_channel();
        let (finalized_block_send, finalized_block_recv) = finalized_block_channel();
        let tasks = Arc::new(Mutex::new(Vec::new()));

        let processor = EthereumBlockProcessor {
            client: Arc::clone(&client),
            contract_address,
            requests_indexed: requests_indexed_send.clone(),
            blocks_failed: blocks_failed_send.clone(),
            backlog: backlog.clone(),
            events_tx: events_tx.clone(),
        };

        let refresh_task = tokio::spawn(EthereumIndexer::refresh_finalized_block(
            Arc::clone(&client),
            finalized_block_send,
            eth.refresh_finalized_interval,
        ));
        tasks.lock().unwrap().push(refresh_task);

        let finalized_task = tokio::spawn(EthereumIndexer::send_requests_when_final(
            Arc::clone(&client),
            requests_indexed_recv,
            finalized_block_recv,
            events_tx.clone(),
            eth.optimistic_requests,
        ));
        tasks.lock().unwrap().push(finalized_task);

        let retry_task = tokio::spawn(EthereumIndexer::retry_failed_blocks(
            Arc::clone(&client),
            blocks_failed_recv,
            blocks_failed_send,
            contract_address,
            requests_indexed_send,
            backlog.clone(),
            events_tx,
        ));
        tasks.lock().unwrap().push(retry_task);

        Ok(Self {
            backlog,
            client,
            events_rx,
            processor,
            tasks,
            live_state: None,
        })
    }

    fn catchup_start_block(end_block_number: u64, start_block_number: u64) -> u64 {
        let helios_oldest_block_number = end_block_number.saturating_sub(MAX_CATCHUP_BLOCKS);
        if start_block_number < helios_oldest_block_number {
            tracing::warn!(
                "Start block number {start_block_number} is too far behind the latest block {end_block_number}, adjusting to {helios_oldest_block_number}"
            );
            helios_oldest_block_number
        } else {
            start_block_number
        }
    }
}

impl Drop for EthereumStream {
    fn drop(&mut self) {
        let mut tasks = self.tasks.lock().unwrap();
        for t in tasks.iter() {
            t.abort();
        }
        tasks.clear();
    }
}

impl ChainStream for EthereumStream {
    const CHAIN: Chain = Chain::Ethereum;

    type BufferedStream = EthereumBufferedStream;

    async fn livestream(&mut self) -> Self::BufferedStream {
        let (live_blocks_tx, live_blocks_rx) = live_blocks_channel();
        let task = tokio::spawn(EthereumIndexer::poll_live_blocks(
            Arc::clone(&self.client),
            live_blocks_tx,
        ));
        self.tasks.lock().unwrap().push(task);

        let live_state = Arc::new(Mutex::new(BufferedLiveState {
            initial_block: None,
            replay_initial_block: true,
        }));
        self.live_state = Some(Arc::clone(&live_state));

        EthereumBufferedStream {
            live_state,
            live_blocks_rx,
            processor: self.processor.clone(),
            tasks: Arc::clone(&self.tasks),
        }
    }

    async fn catchup(&mut self, anchor_height: u64) {
        let Some(last_processed_block) = self.backlog.processed_block(Chain::Ethereum).await else {
            return;
        };

        let start_block = Self::catchup_start_block(anchor_height, last_processed_block);
        for block_number in start_block..=anchor_height {
            self.processor.process_catchup_block(block_number).await;
        }

        if let Some(live_state) = &self.live_state {
            live_state.lock().unwrap().replay_initial_block = false;
        }
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        self.events_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::Header as ConsensusHeader;
    use alloy::primitives::{Address, Bloom, B64, B256};
    use std::time::Duration;
    use tokio::time::timeout;

    fn test_block_hash(number: u64) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&number.to_be_bytes());
        B256::from(bytes)
    }

    fn test_block(number: u64) -> alloy::rpc::types::Block {
        alloy::rpc::types::Block {
            header: alloy::rpc::types::Header {
                hash: test_block_hash(number),
                inner: ConsensusHeader {
                    parent_hash: test_block_hash(number.saturating_sub(1)),
                    ommers_hash: B256::ZERO,
                    beneficiary: Address::ZERO,
                    state_root: B256::ZERO,
                    transactions_root: B256::ZERO,
                    receipts_root: B256::ZERO,
                    withdrawals_root: None,
                    number,
                    gas_used: 0,
                    gas_limit: 30_000_000,
                    extra_data: Vec::<u8>::new().into(),
                    logs_bloom: Bloom::default(),
                    timestamp: number,
                    difficulty: U256::ZERO,
                    mix_hash: B256::ZERO,
                    nonce: B64::ZERO,
                    base_fee_per_gas: None,
                    blob_gas_used: None,
                    excess_blob_gas: None,
                    parent_beacon_block_root: None,
                    requests_hash: None,
                },
                total_difficulty: None,
                size: None,
            },
            uncles: vec![],
            transactions: Vec::<alloy::rpc::types::Transaction>::new().into(),
            withdrawals: None,
        }
    }

    fn test_stream(
        latest_sequence: impl IntoIterator<Item = u64>,
        backlog: Backlog,
        blocks: Vec<alloy::rpc::types::Block>,
    ) -> (EthereumStream, mpsc::Receiver<BlockAndRequests>) {
        let (events_tx, events_rx) = crate::stream::channel();
        let (requests_indexed, requests_indexed_rx) = indexed_channel();
        let (failed_blocks, _failed_blocks_rx) = failed_blocks_channel();
        let client = Arc::new(EthereumClient::Test(TestEthereumClient::new(
            latest_sequence,
            blocks,
        )));

        let processor = EthereumBlockProcessor {
            client: Arc::clone(&client),
            contract_address: Address::ZERO,
            requests_indexed,
            blocks_failed: failed_blocks,
            backlog: backlog.clone(),
            events_tx,
        };

        (
            EthereumStream {
                backlog,
                client,
                events_rx,
                processor,
                tasks: Arc::new(Mutex::new(Vec::new())),
                live_state: None,
            },
            requests_indexed_rx,
        )
    }

    async fn recv_block_numbers(
        requests_indexed_rx: &mut mpsc::Receiver<BlockAndRequests>,
        expected: usize,
    ) -> Vec<u64> {
        let mut block_numbers = Vec::with_capacity(expected);
        for _ in 0..expected {
            let block = timeout(Duration::from_secs(1), requests_indexed_rx.recv())
                .await
                .unwrap()
                .unwrap();
            block_numbers.push(block.block_number);
        }
        block_numbers
    }

    #[tokio::test]
    async fn ethereum_stream_catchup_replays_from_persisted_block_to_anchor_in_order() {
        let backlog = Backlog::new();
        backlog.set_processed_block(Chain::Ethereum, 100).await;
        let (mut stream, mut requests_indexed_rx) = test_stream(
            [],
            backlog,
            (100..=103).map(test_block).collect(),
        );

        stream.catchup(103).await;

        assert_eq!(
            recv_block_numbers(&mut requests_indexed_rx, 4).await,
            vec![100, 101, 102, 103]
        );
    }

    #[tokio::test]
    async fn ethereum_stream_defers_buffered_live_blocks_until_after_catchup() {
        let backlog = Backlog::new();
        backlog.set_processed_block(Chain::Ethereum, 100).await;
        let (mut stream, mut requests_indexed_rx) = test_stream(
            [103, 104, 105],
            backlog,
            (100..=105).map(test_block).collect(),
        );

        let buffered = stream.livestream().await;
        let mut buffered = buffered;
        assert_eq!(buffered.initial_block_height().await, Some(103));

        stream.catchup(103).await;

        assert_eq!(
            recv_block_numbers(&mut requests_indexed_rx, 4).await,
            vec![100, 101, 102, 103]
        );

        match timeout(Duration::from_millis(100), requests_indexed_rx.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(block)) => panic!("unexpected live block before buffered stream run: {}", block.block_number),
        }

        buffered.run().await;

        assert_eq!(
            recv_block_numbers(&mut requests_indexed_rx, 2).await,
            vec![104, 105]
        );
    }

    #[tokio::test]
    async fn ethereum_stream_processes_buffered_blocks_in_original_arrival_order() {
        let backlog = Backlog::new();
        let (mut stream, mut requests_indexed_rx) = test_stream(
            [103, 104, 105],
            backlog,
            (103..=105).map(test_block).collect(),
        );

        let mut buffered = stream.livestream().await;
        assert_eq!(buffered.initial_block_height().await, Some(103));
        buffered.run().await;

        assert_eq!(
            recv_block_numbers(&mut requests_indexed_rx, 3).await,
            vec![103, 104, 105]
        );
    }

    #[tokio::test]
    async fn ethereum_stream_does_not_duplicate_anchor_block() {
        let backlog = Backlog::new();
        backlog.set_processed_block(Chain::Ethereum, 100).await;
        let (mut stream, mut requests_indexed_rx) = test_stream(
            [103, 104],
            backlog,
            (100..=104).map(test_block).collect(),
        );

        let mut buffered = stream.livestream().await;
        assert_eq!(buffered.initial_block_height().await, Some(103));
        stream.catchup(103).await;
        buffered.run().await;

        assert_eq!(
            recv_block_numbers(&mut requests_indexed_rx, 5).await,
            vec![100, 101, 102, 103, 104]
        );

        match timeout(Duration::from_millis(100), requests_indexed_rx.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(block)) => panic!("unexpected duplicate anchor block: {}", block.block_number),
        }
    }

    #[tokio::test]
    async fn ethereum_stream_skips_catchup_when_no_persisted_block_exists() {
        let backlog = Backlog::new();
        let (mut stream, mut requests_indexed_rx) = test_stream(
            [103, 104],
            backlog,
            (103..=104).map(test_block).collect(),
        );

        let mut buffered = stream.livestream().await;
        assert_eq!(buffered.initial_block_height().await, Some(103));
        stream.catchup(103).await;
        buffered.run().await;

        assert_eq!(
            recv_block_numbers(&mut requests_indexed_rx, 2).await,
            vec![103, 104]
        );
    }

    #[test]
    fn ethereum_stream_adjusts_catchup_start_when_backlog_is_too_old() {
        assert_eq!(EthereumStream::catchup_start_block(1_000, 990), 990);
        assert_eq!(
            EthereumStream::catchup_start_block(MAX_CATCHUP_BLOCKS + 10, 1),
            10
        );
    }

    #[tokio::test]
    async fn ethereum_buffered_stream_initial_block_height_is_stable() {
        let backlog = Backlog::new();
        let (mut stream, mut requests_indexed_rx) = test_stream(
            [103, 104],
            backlog,
            (103..=104).map(test_block).collect(),
        );

        let mut buffered = stream.livestream().await;
        assert_eq!(buffered.initial_block_height().await, Some(103));
        assert_eq!(buffered.initial_block_height().await, Some(103));

        buffered.run().await;

        assert_eq!(
            recv_block_numbers(&mut requests_indexed_rx, 2).await,
            vec![103, 104]
        );
    }
}
