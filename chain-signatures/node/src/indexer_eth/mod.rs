pub mod indexer_eth_direct_rpc;
pub mod indexer_eth_helios;

use crate::backlog::Backlog;
use crate::stream::ops::{EthereumSignatureRespondedEvent, SignatureRespondedEvent};

use crate::metrics::requests::{record_request_latency, SignRequestStep};
use crate::protocol::{Chain, IndexedSignRequest};
use crate::respond_bidirectional::CompletedTx;
use crate::sign_bidirectional::SignStatus;
use crate::stream::{
    ChainBufferedStream, ChainEvent, ChainIndexer, ChainStream, ExecutionOutcome,
};
use async_trait::async_trait;

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

// This is the maximum number of blocks that Helios can look back to
const MAX_CATCHUP_BLOCKS: u64 = 8191;

const MAX_LIVE_BLOCK_BUFFER: usize = 16384;

fn live_blocks_channel() -> (
    mpsc::Sender<alloy::rpc::types::Block>,
    mpsc::Receiver<alloy::rpc::types::Block>,
) {
    mpsc::channel(MAX_LIVE_BLOCK_BUFFER)
}

type BlockNumber = u64;

pub struct BlockAndRequests {
    block_number: u64,
    block_hash: alloy::primitives::B256,
    indexed_requests: Vec<IndexedSignRequest>,
    respond_logs: Vec<Log>,
    execution_events: Vec<ChainEvent>,
}

impl BlockAndRequests {
    fn new(
        block_number: u64,
        block_hash: alloy::primitives::B256,
        indexed_requests: Vec<IndexedSignRequest>,
        respond_logs: Vec<Log>,
        execution_events: Vec<ChainEvent>,
    ) -> Self {
        Self {
            block_number,
            block_hash,
            indexed_requests,
            respond_logs,
            execution_events,
        }
    }
}

pub struct EthereumBufferedStream {
    live_blocks_rx: mpsc::Receiver<alloy::rpc::types::Block>,
}

#[async_trait]
impl ChainBufferedStream for EthereumBufferedStream {
    type Item = alloy::rpc::types::Block;

    async fn initial(&mut self) -> Option<Self::Item> {
        self.live_blocks_rx.recv().await
    }

    async fn next(&mut self) -> Option<Self::Item> {
        self.live_blocks_rx.recv().await
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
    events_tx: mpsc::Sender<ChainEvent>,
}

impl EthereumIndexer {
    pub async fn new(
        eth: EthConfig,
        backlog: Backlog,
        events_tx: mpsc::Sender<ChainEvent>,
    ) -> anyhow::Result<Self> {
        let client = EthereumClient::new(eth.clone()).await?;

        Ok(Self {
            eth,
            backlog,
            client,
            events_tx,
        })
    }

    async fn buffer_live_blocks(
        client: Arc<EthereumClient>,
        live_blocks: mpsc::Sender<alloy::rpc::types::Block>,
    ) {
        tracing::info!("buffering ethereum live blocks");
        let mut next_block_number: Option<u64> = None;

        loop {
            let Some(latest_block_number) = client.get_latest_block_number().await else {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };

            let mut block_number = next_block_number.unwrap_or(latest_block_number);
            if block_number > latest_block_number {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }

            while block_number <= latest_block_number {
                let Some(block) = client
                    .get_block(alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(
                        block_number,
                    )))
                    .await
                else {
                    tracing::warn!(block_number, "ethereum live block not yet available");
                    break;
                };

                if let Err(err) = live_blocks.send(block).await {
                    tracing::warn!(?err, block_number, "failed to buffer ethereum live block");
                    return;
                }

                next_block_number = Some(block_number.saturating_add(1));
                block_number = block_number.saturating_add(1);
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    fn catchup_start_block_number(
        last_processed_block: Option<u64>,
        anchor_height: BlockNumber,
    ) -> BlockNumber {
        let requested_start = last_processed_block
            .map(|height| height.saturating_add(1))
            .unwrap_or(anchor_height);

        let catchup_end = anchor_height.saturating_sub(1);
        let oldest_supported = catchup_end.saturating_sub(MAX_CATCHUP_BLOCKS);

        if requested_start < oldest_supported {
            tracing::warn!(
                requested_start,
                anchor_height,
                oldest_supported,
                "ethereum catchup start is older than supported range; clamping"
            );
            oldest_supported
        } else {
            requested_start
        }
    }

    async fn process_height(&self, block_number: u64) -> anyhow::Result<()> {
        let Some(block) = self
            .client
            .get_block(alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(
                block_number,
            )))
            .await
        else {
            anyhow::bail!("ethereum block {block_number} not found");
        };

        self.process_live_block(block).await
    }

    async fn process_live_block(&self, block: alloy::rpc::types::Block) -> anyhow::Result<()> {
        let block_number = block.header.number;
        let contract_address = Address::from_str(&format!("0x{}", self.eth.contract_address))
            .map_err(|_| {
                anyhow::anyhow!(
                    "failed to parse ethereum contract address: {}",
                    self.eth.contract_address
                )
            })?;

        let processed = Self::process_block(
            Arc::new(self.client.clone()),
            block,
            contract_address,
            self.backlog.clone(),
        )
        .await?;

        Self::emit_processed_block(
            Arc::new(self.client.clone()),
            self.events_tx.clone(),
            &self.eth,
            processed,
        )
        .await?;

        crate::metrics::indexers::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Ethereum.as_str(), "indexed"])
            .set(block_number as i64);

        Ok(())
    }

    async fn process_block(
        client: Arc<EthereumClient>,
        block: alloy::rpc::types::Block,
        contract_address: Address,
        backlog: Backlog,
    ) -> anyhow::Result<BlockAndRequests> {
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
        Ok(BlockAndRequests::new(
            block_number,
            block_hash,
            sign_requests,
            respond_logs,
            exec_events,
        ))
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

    /// Emits the processed block in-order once the configured buffer policy allows it.
    async fn emit_processed_block(
        client: Arc<EthereumClient>,
        events_tx: mpsc::Sender<ChainEvent>,
        eth: &EthConfig,
        BlockAndRequests {
            block_number,
            block_hash,
            indexed_requests,
            respond_logs,
            execution_events,
        }: BlockAndRequests,
    ) -> anyhow::Result<()> {
        if !eth.optimistic_requests {
            Self::wait_for_finalized_block(
                Arc::clone(&client),
                eth.refresh_finalized_interval,
                block_number,
            )
            .await?;
        }

        let Some(block) = client
            .as_ref()
            .get_block(alloy::rpc::types::BlockId::Number(
                BlockNumberOrTag::Number(block_number),
            ))
            .await
        else {
            anyhow::bail!("ethereum block {block_number} not found during emission");
        };

        if block.header.hash != block_hash {
            anyhow::bail!(
                "block {block_number} hash mismatch: expected {block_hash:?}, got {:?}",
                block.header.hash
            );
        }

        for event in execution_events {
            events_tx
                .send(event)
                .await
                .map_err(|err| anyhow::anyhow!("failed to emit ExecutionConfirmed event: {err:?}"))?;
        }

        for req in indexed_requests {
            events_tx
                .send(ChainEvent::SignRequest(req))
                .await
                .map_err(|err| anyhow::anyhow!("failed to emit SignRequest event: {err:?}"))?;
        }

        if !respond_logs.is_empty() {
            emit_respond_events(&respond_logs, events_tx.clone()).await;
        }

        events_tx
            .send(ChainEvent::Block(block_number))
            .await
            .map_err(|err| anyhow::anyhow!("failed to emit block event: {err:?}"))?;

        Ok(())
    }

    async fn wait_for_finalized_block(
        client: Arc<EthereumClient>,
        refresh_finalized_interval: u64,
        block_number: BlockNumber,
    ) -> anyhow::Result<()> {
        let mut last_finalized_block_number: Option<BlockNumber> = None;

        loop {
            let Some(finalized_block) = client
                .as_ref()
                .get_block(alloy::rpc::types::BlockId::Number(
                    BlockNumberOrTag::Finalized,
                ))
                .await
            else {
                tracing::warn!(block_number, "finalized ethereum block not found; retrying");
                tokio::time::sleep(Duration::from_millis(refresh_finalized_interval)).await;
                continue;
            };

            let finalized_block_number = finalized_block.header.number;
            if last_finalized_block_number.is_none_or(|n| finalized_block_number > n) {
                last_finalized_block_number = Some(finalized_block_number);
                crate::metrics::indexers::LATEST_BLOCK_NUMBER
                    .with_label_values(&[Chain::Ethereum.as_str(), "finalized"])
                    .set(finalized_block_number as i64);
            }

            if finalized_block_number >= block_number {
                return Ok(());
            };

            tokio::time::sleep(Duration::from_millis(refresh_finalized_interval)).await;
        }
    }
}

#[async_trait]
impl ChainIndexer for EthereumIndexer {
    type BufferedStream = EthereumBufferedStream;

    async fn livestream(&mut self) -> anyhow::Result<Option<Self::BufferedStream>> {
        let (live_blocks_tx, live_blocks_rx) = live_blocks_channel();
        tokio::spawn(EthereumIndexer::buffer_live_blocks(
            Arc::new(self.client.clone()),
            live_blocks_tx,
        ));

        Ok(Some(EthereumBufferedStream { live_blocks_rx }))
    }

    fn buffered_item_height(item: &<Self::BufferedStream as ChainBufferedStream>::Item) -> u64 {
        item.header.number
    }

    async fn catchup_range(&mut self, anchor_height: u64) -> anyhow::Result<std::ops::Range<u64>> {
        let catchup_start = EthereumIndexer::catchup_start_block_number(
            self.backlog.processed_block(Chain::Ethereum).await,
            anchor_height,
        );

        Ok(catchup_start..anchor_height)
    }

    async fn process_catchup_height(&mut self, height: u64) -> anyhow::Result<()> {
        if height % 10 == 0 {
            tracing::info!(height, "processed ethereum catchup height attempt");
        }

        self.process_height(height).await
    }

    async fn process_buffered_item(
        &mut self,
        item: <Self::BufferedStream as ChainBufferedStream>::Item,
    ) -> anyhow::Result<()> {
        self.process_live_block(item).await
    }

    fn retry_delay(&self) -> Duration {
        Duration::from_millis(500)
    }

}

/// Ethereum indexer stream implementing the `ChainStream` trait.
/// Construction is side-effect free; the shared `run_stream()` loop calls
/// `start()` after recovery has completed.
pub struct EthereumStream {
    events_rx: Option<mpsc::Receiver<ChainEvent>>,
    start_state: Option<EthereumIndexer>,
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

        let (events_tx, events_rx) = crate::stream::channel();
        let indexer = EthereumIndexer::new(eth, backlog, events_tx).await?;

        Ok(Self {
            events_rx: Some(events_rx),
            start_state: Some(indexer),
        })
    }
}

#[async_trait]
impl ChainStream for EthereumStream {
    const CHAIN: Chain = Chain::Ethereum;
    type Indexer = EthereumIndexer;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
        self.start_state
            .take()
            .ok_or_else(|| anyhow::anyhow!("ethereum stream already started"))
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        match self.events_rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::EthereumIndexer;

    #[test]
    fn catchup_starts_after_processed_height() {
        assert_eq!(EthereumIndexer::catchup_start_block_number(Some(41), 50), 42);
    }

    #[test]
    fn catchup_without_checkpoint_starts_from_anchor() {
        assert_eq!(EthereumIndexer::catchup_start_block_number(None, 50), 50);
    }

    #[test]
    fn catchup_start_is_clamped_to_supported_window() {
        let anchor_height = 10_000;
        let catchup_end = anchor_height - 1;
        let expected_oldest = catchup_end - super::MAX_CATCHUP_BLOCKS;

        assert_eq!(
            EthereumIndexer::catchup_start_block_number(Some(1), anchor_height),
            expected_oldest,
        );
    }
}
