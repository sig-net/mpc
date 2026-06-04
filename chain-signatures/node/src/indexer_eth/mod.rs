pub mod abi;
pub mod indexer_eth_direct_rpc;
#[cfg(feature = "helios")]
pub mod indexer_eth_helios;

use crate::backlog::Backlog;
use crate::indexer_eth::abi::{ChainSignatures, SignatureRequestedEncoding};
use crate::metrics::requests::{record_request_latency_since, SignRequestStep};
use crate::protocol::{Chain, IndexedSignRequest};
use crate::respond_bidirectional::CompletedTx;
use crate::stream::ops::SignatureRespondedEvent;
use crate::stream::{AsyncCatchupIter, ChainEvent, ChainIndexer, ChainStream, ExecutionOutcome};
use crate::util::retry;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::{Block, BlockId, Log};
use alloy::sol_types::SolEvent;
use anyhow::Context as _;
use async_trait::async_trait;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint as K256AffinePoint, EncodedPoint, FieldBytes, Scalar};
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{
    SignArgs, SignId, Signature as MpcSignature, LATEST_MPC_KEY_VERSION, MAX_SECP256K1_SCALAR,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};
use tokio::time::Duration;

const MAX_LIVE_BLOCK_BUFFER: usize = 16384;
const CATCHUP_BLOCK_BATCH_SIZE: u64 = 32;

fn live_blocks_channel() -> (mpsc::Sender<MaybeBlock>, mpsc::Receiver<MaybeBlock>) {
    mpsc::channel(MAX_LIVE_BLOCK_BUFFER)
}

type BlockNumber = u64;

pub struct CatchupIter {
    client: Arc<EthereumClient>,
    next_block: BlockNumber,
    end_block: BlockNumber,
    buffered_blocks: std::vec::IntoIter<MaybeBlock>,
}

impl CatchupIter {
    fn new(client: Arc<EthereumClient>, start_block: BlockNumber, end_block: BlockNumber) -> Self {
        Self {
            client,
            next_block: start_block,
            end_block,
            buffered_blocks: Vec::new().into_iter(),
        }
    }

    async fn fetch_next_batch(&mut self) {
        if self.next_block >= self.end_block {
            return;
        }

        let batch_end = self
            .next_block
            .saturating_add(CATCHUP_BLOCK_BATCH_SIZE)
            .min(self.end_block);
        let batch_block_ids = (self.next_block..batch_end)
            .map(|block_number| BlockId::Number(BlockNumberOrTag::Number(block_number)))
            .collect::<Vec<_>>();

        self.buffered_blocks = self.client.get_blocks(&batch_block_ids).await.into_iter();
        self.next_block = batch_end;
    }
}

#[async_trait]
impl AsyncCatchupIter for CatchupIter {
    type Item = MaybeBlock;

    async fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(block) = Iterator::next(&mut self.buffered_blocks) {
                return Some(block);
            }

            if self.next_block >= self.end_block {
                return None;
            }

            self.fetch_next_batch().await;
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeBlock {
    Block(Block),
    Missing(BlockId),
}

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
        #[cfg(not(feature = "helios"))]
        if self.eth_light_client {
            tracing::warn!(
                "ignoring ethereum light client request because mpc-node was built without helios feature"
            );
        }

        Some(EthConfig {
            account_sk: self.eth_account_sk?,
            consensus_rpc_http_url: self.eth_consensus_rpc_http_url.unwrap_or_default(),
            execution_rpc_http_url: self.eth_execution_rpc_http_url.unwrap(),
            contract_address: self.eth_contract_address.unwrap(),
            network: self.eth_network.unwrap_or_default(),
            helios_data_path: self.eth_helios_data_path.unwrap_or_default(),
            refresh_finalized_interval: self.eth_refresh_finalized_interval.unwrap(),
            optimistic_requests: self.eth_optimistic_requests,
            #[cfg(feature = "helios")]
            light_client: self.eth_light_client,
            #[cfg(not(feature = "helios"))]
            light_client: false,
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

        let respond_event = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature,
            chain: Chain::Ethereum,
        };
        tracing::info!(?sign_id, "emitting SignatureResponded event");
        if let Err(err) = events_tx.send(ChainEvent::Respond(respond_event)).await {
            tracing::error!(?err, "failed to emit Respond event");
        }
    }
}

fn sign_id_from_signature_responded_log(log: &Log) -> Option<SignId> {
    if log
        .topic0()
        .is_none_or(|topic| *topic != ChainSignatures::SignatureResponded::SIGNATURE_HASH)
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
    #[cfg(feature = "helios")]
    Helios(indexer_eth_helios::HeliosEthereumClient),
    DirectRpc(indexer_eth_direct_rpc::RpcEthereumClient),
}

impl EthereumClient {
    pub async fn new(eth: EthConfig) -> anyhow::Result<EthereumClient> {
        if eth.light_client {
            #[cfg(feature = "helios")]
            {
                return Ok(EthereumClient::Helios(
                    indexer_eth_helios::build_client(eth.clone()).await?,
                ));
            }

            #[cfg(not(feature = "helios"))]
            {
                anyhow::bail!(
                    "ethereum light client requested, but mpc-node was built without helios feature"
                );
            }
        }

        {
            Ok(EthereumClient::DirectRpc(
                indexer_eth_direct_rpc::RpcEthereumClient::new(&eth.execution_rpc_http_url),
            ))
        }
    }

    fn client_name(&self) -> &str {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(_) => "Helios",
            EthereumClient::DirectRpc(_) => "DirectRpc",
        }
    }

    async fn get_block(&self, block_id: BlockId) -> Option<Block> {
        // Configure retry behaviour and delegate to shared retry_async helper.
        let retry_config = retry::RetryConfig::default();
        let get_block_op = |_attempt: usize| async {
            match self {
                #[cfg(feature = "helios")]
                EthereumClient::Helios(client) => client.get_block(block_id).await,
                EthereumClient::DirectRpc(client) => client.get_block(block_id).await,
            }
        };

        let res = retry::retry_async(
            retry_config,
            get_block_op,
            |_attempt, _reason| true,
            |attempt, reason, sleep_duration| match reason {
                retry::RetryReason::Error(e) => {
                    tracing::warn!(
                        client = self.client_name(),
                        "get_block failed (attempt {attempt}) for {block_id:?}: {e:#}; retrying in {sleep_duration:?}"
                    );
                }
                retry::RetryReason::Timeout(t) => {
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
            Err(retry::RetryError::Exhausted {
                attempts,
                last_error,
            }) => {
                tracing::warn!(
                    client = self.client_name(),
                    "get_block failed for {block_id:?}: {last_error:#}; exhausted after {attempts} attempts"
                );
                None
            }
            Err(retry::RetryError::TimeoutExhausted {
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

    async fn get_blocks(&self, block_ids: &[BlockId]) -> Vec<MaybeBlock> {
        if block_ids.is_empty() {
            return Vec::new();
        }

        let retry_config = retry::RetryConfig::default();
        let block_ids = block_ids.to_vec();
        let get_blocks_op = |_attempt: usize| {
            let block_ids = block_ids.clone();
            async move {
                match self {
                    #[cfg(feature = "helios")]
                    EthereumClient::Helios(client) => client.get_blocks(&block_ids).await,
                    EthereumClient::DirectRpc(client) => client.get_blocks(&block_ids).await,
                }
            }
        };

        match retry::retry_async(
            retry_config,
            get_blocks_op,
            |_attempt, _reason| true,
            |attempt, reason, sleep_duration| match reason {
                retry::RetryReason::Error(e) => {
                    tracing::warn!(
                        client = self.client_name(),
                        num_blocks = block_ids.len(),
                        "get_blocks failed (attempt {attempt}): {e:#}; retrying in {sleep_duration:?}"
                    );
                }
                retry::RetryReason::Timeout(t) => {
                    tracing::warn!(
                        client = self.client_name(),
                        num_blocks = block_ids.len(),
                        "get_blocks timed out after {t:?} (attempt {attempt}); retrying in {sleep_duration:?}"
                    );
                }
            },
        )
        .await
        {
            Ok(blocks) => blocks,
            Err(retry::RetryError::Exhausted { attempts, last_error }) => {
                tracing::warn!(
                    client = self.client_name(),
                    num_blocks = block_ids.len(),
                    "get_blocks failed: {last_error:#}; exhausted after {attempts} attempts"
                );
                block_ids.iter().copied().map(MaybeBlock::Missing).collect()
            }
            Err(retry::RetryError::TimeoutExhausted { attempts, last_timeout }) => {
                tracing::warn!(
                    client = self.client_name(),
                    num_blocks = block_ids.len(),
                    "get_blocks timed out (last timeout {last_timeout:?}); exhausted after {attempts} attempts"
                );
                block_ids.iter().copied().map(MaybeBlock::Missing).collect()
            }
        }
    }

    async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.get_block_receipts(block_id).await,
            EthereumClient::DirectRpc(client) => client.get_block_receipts(block_id).await,
        }
    }

    async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.get_nonce(address, block_id).await,
            EthereumClient::DirectRpc(client) => client.get_nonce(address, block_id).await,
        }
    }

    pub fn block_number_from_id(block_id: BlockId) -> BlockNumber {
        match block_id {
            BlockId::Number(BlockNumberOrTag::Number(block_number)) => block_number,
            BlockId::Number(tag) => panic!("expected numbered block id, got {tag:?}"),
            BlockId::Hash(hash) => panic!("expected numbered block id, got hash {hash:?}"),
        }
    }

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.get_transaction_by_hash(tx_hash).await,
            EthereumClient::DirectRpc(client) => client.get_transaction_by_hash(tx_hash).await,
        }
    }

    pub async fn trace_transaction_output(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<alloy::primitives::Bytes> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.trace_transaction_output(tx_hash).await,
            EthereumClient::DirectRpc(client) => client.trace_transaction_output(tx_hash).await,
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
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.call(from, to, data, block_number).await,
            EthereumClient::DirectRpc(client) => client.call(from, to, data, block_number).await,
        }
    }

    async fn get_latest_block_number(&self) -> Option<u64> {
        self.get_block(BlockId::Number(alloy::rpc::types::BlockNumberOrTag::Latest))
            .await
            .map(|block| block.header.number)
    }

    fn clamp_oldest_supported(
        &self,
        requested_start: u64,
        anchor_height: BlockNumber,
    ) -> BlockNumber {
        let max_catchup_blocks = match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(_) => indexer_eth_helios::MAX_CATCHUP_BLOCKS,
            EthereumClient::DirectRpc(_) => indexer_eth_direct_rpc::MAX_CATCHUP_BLOCKS,
        };
        Self::clamp_oldest_supported_with(requested_start, anchor_height, max_catchup_blocks)
    }

    fn clamp_oldest_supported_with(
        requested_start: u64,
        anchor_height: BlockNumber,
        max_catchup_blocks: u64,
    ) -> BlockNumber {
        let catchup_end = anchor_height.saturating_sub(1);
        let oldest_supported = catchup_end.saturating_sub(max_catchup_blocks);

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
}

pub struct EthereumIndexer {
    eth: EthConfig,
    backlog: Backlog,
    client: Arc<EthereumClient>,
    events_tx: mpsc::Sender<ChainEvent>,
    contract_address: Address,
    catchup_complete: Arc<Notify>,
    live_blocks_rx: Option<mpsc::Receiver<MaybeBlock>>,
}

/// Result of a `backfill_execution_confirmation`. `Observed` carries an
/// optional event; the staleness check skips observed watchers so a mined tx
/// with a failed extraction can stay pending for retry. `NotObserved` covers
/// "no receipt yet" (pending or replaced).
#[allow(clippy::large_enum_variant)] // value is consumed in one match arm; never stored.
enum BackfillOutcome {
    NotObserved,
    Observed { event: Option<ChainEvent> },
}

impl EthereumIndexer {
    pub async fn new(
        eth: EthConfig,
        backlog: Backlog,
        events_tx: mpsc::Sender<ChainEvent>,
    ) -> anyhow::Result<Self> {
        let client = Arc::new(EthereumClient::new(eth.clone()).await?);
        let contract_address = format!("0x{}", eth.contract_address);
        let contract_address = Address::from_str(&contract_address).with_context(|| {
            format!("failed to parse ethereum contract address: {contract_address}")
        })?;

        Ok(Self {
            eth,
            backlog,
            client,
            events_tx,
            contract_address,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        })
    }

    async fn index_live_blocks(
        client: Arc<EthereumClient>,
        catchup_complete: Arc<Notify>,
        start_block_number: u64,
        live_blocks: mpsc::Sender<MaybeBlock>,
    ) {
        tracing::info!("indexing ethereum live blocks");

        // Wait for catchup to complete before starting to index live blocks
        catchup_complete.notified().await;

        let mut current_block_number = start_block_number;

        // Missing ticks is what we want due to retrying on transient errors
        let mut interval = tokio::time::interval(Self::RETRY_DELAY);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;
            let Some(latest_block_number) = client.get_latest_block_number().await else {
                continue;
            };

            while current_block_number <= latest_block_number {
                let Some(block) = client
                    .get_block(BlockId::Number(BlockNumberOrTag::Number(
                        current_block_number,
                    )))
                    .await
                else {
                    tracing::warn!(
                        current_block_number,
                        "ethereum live block not yet available"
                    );
                    break;
                };

                if let Err(err) = live_blocks.send(MaybeBlock::Block(block)).await {
                    tracing::warn!(
                        ?err,
                        current_block_number,
                        "failed to add ethereum live block"
                    );
                    return;
                }

                current_block_number = current_block_number.saturating_add(1);
            }
        }
    }

    /// Process the block and emit relevant ChainEvents from the block.
    async fn process_block(&self, block: &Block) -> anyhow::Result<()> {
        let block_number = block.header.number;
        crate::metrics::indexers::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Ethereum.as_str(), "indexed"])
            .set(block_number as i64);

        let processed = self.parse_block(block).await?;
        self.emit_processed_block(processed).await?;

        Ok(())
    }

    async fn parse_block(&self, block: &Block) -> anyhow::Result<BlockAndRequests> {
        let block_number = block.header.number;
        let block_hash = block.header.hash;
        let block_timestamp = block.header.timestamp;
        tracing::info!(
            "Processing block number {} with hash {:?}",
            block_number,
            block_hash
        );
        let block_receipts = self
            .client
            .get_block_receipts(block_number.into())
            .await
            .with_context(|| {
                format!("failed to get block receipts for block number {block_number}")
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
                    .filter(|log| log.address() == self.contract_address)
                    .cloned()
            })
            .collect();

        let (respond_logs, potential_request_logs): (Vec<Log>, Vec<Log>) =
            relevant_logs.into_iter().partition(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::SignatureResponded::SIGNATURE_HASH
                })
            });

        let request_logs: Vec<Log> = potential_request_logs
            .into_iter()
            .filter(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::SignatureRequested::SIGNATURE_HASH
                })
            })
            .collect();

        if !request_logs.is_empty() {
            sign_requests.extend(parse_filtered_logs(request_logs));
        }

        // Collect execution confirmations (if any) and emit ExecutionConfirmed events
        let exec_events = self
            .collect_execution_confirmations(block_number, block_receipts)
            .await?;

        for _request in &sign_requests {
            record_request_latency_since(
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

    async fn execution_confirmed_event(
        &self,
        tx_id: crate::sign_bidirectional::BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &crate::sign_bidirectional::BidirectionalTx,
        block_number: u64,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Option<ChainEvent> {
        let receipt_succeeded = receipt.status();

        tracing::info!(
            ?tx_id,
            ?sign_id,
            block_number,
            "bidirectional execution observed via rpc"
        );

        let result = if receipt_succeeded {
            let completed_tx = CompletedTx::new(pending_tx.clone());
            match completed_tx.extract_success_tx_output(&self.client).await {
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
                    // Return `None` to retry on the next block; fabricating
                    // `Success { output: vec![] }` here would silently sign a
                    // wrong response. The caller tracks observed-but-unresolved
                    // watchers so the staleness check below skips them.
                    tracing::error!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "Failed to extract transaction output for bidirectional \
                         tx; leaving watcher pending for retry. Common causes: \
                         trace RPC unavailable, malformed trace response, or \
                         invalid output/response serialization schema."
                    );
                    return None;
                }
            }
        } else {
            ExecutionOutcome::Failed
        };

        Some(ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            source_chain: pending_tx.source_chain,
            block_height: block_number,
            result,
        })
    }

    async fn backfill_execution_confirmation(
        &self,
        tx_id: crate::sign_bidirectional::BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &crate::sign_bidirectional::BidirectionalTx,
        current_block_number: u64,
    ) -> anyhow::Result<BackfillOutcome> {
        let Some(tx) = self.client.get_transaction_by_hash(tx_id.0).await? else {
            return Ok(BackfillOutcome::NotObserved);
        };

        let Some(mined_block_number) = tx.block_number else {
            return Ok(BackfillOutcome::NotObserved);
        };

        if mined_block_number > current_block_number {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                current_block_number,
                "skipping late watcher backfill for future ethereum block"
            );
            return Ok(BackfillOutcome::NotObserved);
        }

        let Some(block_receipts) = self
            .client
            .get_block_receipts(mined_block_number.into())
            .await?
        else {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                "late watcher backfill found mined transaction without block receipts"
            );
            return Ok(BackfillOutcome::NotObserved);
        };

        let Some(receipt) = block_receipts
            .into_iter()
            .find(|receipt| receipt.transaction_hash == tx_id.0)
        else {
            tracing::warn!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                "late watcher backfill could not find transaction receipt in mined block"
            );
            return Ok(BackfillOutcome::NotObserved);
        };

        tracing::info!(
            ?tx_id,
            ?sign_id,
            mined_block_number,
            current_block_number,
            "backfilled execution confirmation for late ethereum watcher"
        );

        let event = self
            .execution_confirmed_event(tx_id, sign_id, pending_tx, mined_block_number, &receipt)
            .await;
        Ok(BackfillOutcome::Observed { event })
    }

    async fn collect_execution_confirmations(
        &self,
        block_number: u64,
        block_receipts: Vec<alloy::rpc::types::TransactionReceipt>,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        let block_receipts: HashMap<
            alloy::primitives::B256,
            alloy::rpc::types::TransactionReceipt,
        > = block_receipts
            .into_iter()
            .map(|receipt| (receipt.transaction_hash, receipt.clone()))
            .collect::<HashMap<_, _>>();

        let mut events = Vec::new();
        let mut resolved_tx_ids = HashSet::new();

        let watchers = self.backlog.execution_watchers(Chain::Ethereum).await;
        tracing::info!(
            watchers_count = watchers.len(),
            block_number,
            "collect_execution_confirmations checking watchers"
        );

        // Watchers whose receipt we saw this call, even if no event was
        // emitted. The staleness check below skips these so a mined tx with
        // a failed extraction stays pending for retry, not flagged Failed.
        let mut observed_tx_ids = HashSet::new();

        for (tx_id, (sign_id, pending_tx)) in watchers {
            tracing::info!(?tx_id, ?sign_id, "querying receipt for bidirectional tx");
            if let Some(receipt) = block_receipts.get(&pending_tx.id.0) {
                observed_tx_ids.insert(tx_id);
                if let Some(event) = self
                    .execution_confirmed_event(tx_id, sign_id, &pending_tx, block_number, receipt)
                    .await
                {
                    events.push(event);
                    resolved_tx_ids.insert(tx_id);
                }
                // `None` means extraction failed — leave pending for retry.
                // `observed_tx_ids` above exempts it from the staleness check.
                continue;
            }

            match self
                .backfill_execution_confirmation(tx_id, sign_id, &pending_tx, block_number)
                .await?
            {
                BackfillOutcome::Observed { event } => {
                    observed_tx_ids.insert(tx_id);
                    if let Some(event) = event {
                        events.push(event);
                        resolved_tx_ids.insert(tx_id);
                    }
                }
                BackfillOutcome::NotObserved => {}
            }
        }

        // Staleness checks (nonce too low)
        let remaining_pending = self.backlog.execution_watchers(Chain::Ethereum).await;

        for (tx_id, (sign_id, tx)) in remaining_pending {
            if resolved_tx_ids.contains(&tx_id) || observed_tx_ids.contains(&tx_id) {
                continue;
            }

            let current_nonce = match self
                .client
                .as_ref()
                .get_nonce(
                    tx.from_address,
                    BlockId::Number(BlockNumberOrTag::Number(block_number)),
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

    /// Emits the processed block in-order once we reach finality for it.
    async fn emit_processed_block(
        &self,
        BlockAndRequests {
            block_number,
            block_hash,
            indexed_requests,
            respond_logs,
            execution_events,
        }: BlockAndRequests,
    ) -> anyhow::Result<()> {
        if !self.eth.optimistic_requests {
            self.wait_for_finalized_block(block_number).await?;
        }

        let Some(block) = self
            .client
            .as_ref()
            .get_block(BlockId::Number(BlockNumberOrTag::Number(block_number)))
            .await
        else {
            anyhow::bail!("ethereum block {block_number} not found during emission");
        };

        if block.header.hash != block_hash {
            // The block was reorged after `process_block` produced this payload.
            // Do not emit stale events for a different canonical block, but also do
            // not return an error that would cause the catchup path to retry this
            // same stale payload forever.
            return Ok(());
        }

        for event in execution_events {
            self.events_tx
                .send(event)
                .await
                .context("failed to emit ExecutionConfirmed event")?;
        }

        for req in indexed_requests {
            self.events_tx
                .send(ChainEvent::SignRequest(req))
                .await
                .context("failed to emit SignRequest event")?;
        }

        if !respond_logs.is_empty() {
            emit_respond_events(&respond_logs, self.events_tx.clone()).await;
        }

        self.events_tx
            .send(ChainEvent::Block(block_number))
            .await
            .context("failed to emit block event")?;

        Ok(())
    }

    async fn wait_for_finalized_block(&self, block_number: BlockNumber) -> anyhow::Result<()> {
        let retry_interval = Duration::from_millis(self.eth.refresh_finalized_interval);
        let mut last_final_block_number: Option<BlockNumber> = None;

        loop {
            let Some(finalized_block) = self
                .client
                .as_ref()
                .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
                .await
            else {
                tracing::warn!(block_number, "finalized ethereum block not found; retrying");
                tokio::time::sleep(retry_interval).await;
                continue;
            };

            let new_final_block_number = finalized_block.header.number;
            let prev_final_block_number = last_final_block_number.replace(new_final_block_number);

            if prev_final_block_number.is_none_or(|n| new_final_block_number > n) {
                tracing::debug!(
                    new_final_block_number,
                    prev_final_block_number,
                    "New finalized block number"
                );
            }

            if let Some(prev_final_block_number) = prev_final_block_number {
                if new_final_block_number < prev_final_block_number {
                    tracing::warn!(
                        new_final_block_number,
                        prev_final_block_number,
                        "new finalized block number overflowed range of u64 and has wrapped around!"
                    );
                }

                if new_final_block_number == prev_final_block_number {
                    tracing::debug!(new_final_block_number, "no new finalized block");
                }
            }

            // If the finalized block number has advanced past the block we're waiting for,
            // we can proceed with emitting it.
            if new_final_block_number >= block_number {
                return Ok(());
            };

            tokio::time::sleep(retry_interval).await;
        }
    }
}

#[async_trait]
impl ChainIndexer for EthereumIndexer {
    const CHAIN: Chain = Chain::Ethereum;
    type Block = MaybeBlock;
    type Iter = CatchupIter;

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        let start_block_number = loop {
            if let Some(block_number) = self.client.get_latest_block_number().await {
                break block_number.saturating_add(1);
            };
            tokio::time::sleep(Self::RETRY_DELAY).await;
        };

        let (live_blocks_tx, live_blocks_rx) = live_blocks_channel();
        tokio::spawn(Self::index_live_blocks(
            self.client.clone(),
            self.catchup_complete.clone(),
            start_block_number,
            live_blocks_tx,
        ));

        self.live_blocks_rx = Some(live_blocks_rx);
        Ok(Some(start_block_number))
    }

    async fn next(&mut self) -> Option<Self::Block> {
        let rx = self.live_blocks_rx.as_mut()?;
        rx.recv().await
    }

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter {
        // TODO: start from genesis block of contract deployment instead of
        // anchor_height so that we can start from the very beginning of
        // the history of the network in case where we do not have a checkpoint.
        // https://github.com/sig-net/mpc/issues/777
        let current_block = self
            .backlog
            .processed_block(Chain::Ethereum)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(anchor_height);
        let catchup_start = self
            .client
            .clamp_oldest_supported(current_block, anchor_height);

        CatchupIter::new(self.client.clone(), catchup_start, anchor_height)
    }

    async fn process_catchup(&mut self, block: &Self::Block) -> anyhow::Result<()> {
        // NOTE: oh rust: needed otherwise the block gets dropped before we can use
        // it, since it `block` is of reference type. Maybe the language will let
        // us elide this in the future, but for now we need to introduce a new var.
        let _block;

        let block = match block {
            MaybeBlock::Block(block) => block,
            MaybeBlock::Missing(block_id) => {
                tracing::warn!(
                    ?block_id,
                    "ethereum catchup block missing from batch; refetching"
                );
                let Some(block) = self.client.get_block(*block_id).await else {
                    anyhow::bail!(
                        "ethereum catchup block {block_id:?} is still unavailable after refetch"
                    )
                };
                _block = block;
                &_block
            }
        };

        let height = block.header.number;
        if height.is_multiple_of(10) {
            tracing::info!(height, "processed ethereum catchup block attempt");
        }

        self.process_block(block).await
    }

    async fn process(&mut self, block: &Self::Block) -> anyhow::Result<()> {
        let MaybeBlock::Block(block) = block else {
            anyhow::bail!("ethereum live stream yielded missing block")
        };

        self.process_block(block).await?;
        Ok(())
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        self.events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send catchup completed event")?;
        self.catchup_complete.notify_one();
        Ok(())
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
            anyhow::bail!("ethereum indexer is disabled: no EthConfig provided");
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
    type Indexer = EthereumIndexer;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
        self.start_state
            .take()
            .context("ethereum stream already started")
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
    use super::{CatchupIter, EthConfig, EthereumClient, EthereumIndexer, MaybeBlock};
    use crate::backlog::Backlog;
    #[cfg(feature = "helios")]
    use crate::indexer_eth::indexer_eth_helios;
    use crate::protocol::Chain;
    use crate::sign_bidirectional::{BidirectionalTx, BidirectionalTxId};
    use crate::stream::{AsyncCatchupIter, ChainEvent, ChainIndexer, ExecutionOutcome};
    use alloy::eips::BlockNumberOrTag;
    use alloy::primitives::{address, b256, Address};
    use alloy::rpc::types::BlockId;
    use mockito::{Matcher, Server};
    use mpc_primitives::{SignId, LATEST_MPC_KEY_VERSION};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Notify};

    fn block_response(request_id: u64, number: u64) -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "number": format!("0x{number:x}"),
                "hash": format!("0x{:064x}", number),
                "parentHash": format!("0x{:064x}", number.saturating_sub(1)),
                "sha3Uncles": format!("0x{:064x}", 1),
                "logsBloom": format!("0x{}", "0".repeat(512)),
                "transactionsRoot": format!("0x{:064x}", 2),
                "stateRoot": format!("0x{:064x}", 3),
                "receiptsRoot": format!("0x{:064x}", 4),
                "miner": format!("0x{:040x}", 5),
                "difficulty": "0x0",
                "totalDifficulty": "0x0",
                "extraData": "0x",
                "size": "0x1",
                "gasLimit": "0x1c9c380",
                "gasUsed": "0x0",
                "timestamp": "0x1",
                "uncles": [],
                "nonce": "0x0000000000000000",
                "mixHash": format!("0x{:064x}", 9),
                "baseFeePerGas": "0x1",
                "transactions": []
            }
        })
    }

    fn missing_block_response(request_id: u64) -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": null
        })
    }

    #[test]
    fn catchup_start_is_clamped_to_supported_window() {
        let max_catchup_blocks = 8191;
        let anchor_height = 10_000;
        let catchup_end = anchor_height - 1;
        let expected_oldest = catchup_end - max_catchup_blocks;

        assert_eq!(
            EthereumClient::clamp_oldest_supported_with(1, anchor_height, max_catchup_blocks),
            expected_oldest,
        );
    }

    #[tokio::test]
    async fn missing_catchup_block_is_refetched() {
        let mut server = Server::new_async().await;
        let backlog = Backlog::new();
        let (events_tx, mut events_rx) = mpsc::channel(1);

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["0xc", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(block_response(1, 12).to_string())
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockReceipts",
                "params": ["0xc"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(missing_block_response(2).to_string())
            .create_async()
            .await;

        let mut indexer = EthereumIndexer {
            eth: EthConfig {
                account_sk: String::new(),
                consensus_rpc_http_url: server.url(),
                execution_rpc_http_url: server.url(),
                contract_address: format!("{:x}", Address::ZERO),
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios-test".to_string(),
                refresh_finalized_interval: 100,
                optimistic_requests: true,
                light_client: false,
            },
            backlog,
            client: Arc::new(EthereumClient::DirectRpc(
                super::indexer_eth_direct_rpc::RpcEthereumClient::new(&server.url()),
            )),
            events_tx,
            contract_address: Address::ZERO,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        };

        indexer
            .process_catchup(&MaybeBlock::Missing(BlockId::Number(
                BlockNumberOrTag::Number(12),
            )))
            .await
            .expect("missing catchup block should be refetched successfully");

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(12))
        ));
    }

    #[tokio::test]
    async fn missing_catchup_block_returns_error_when_refetch_fails() {
        let backlog = Backlog::new();
        let (events_tx, mut events_rx) = mpsc::channel(1);
        let mut indexer = EthereumIndexer {
            eth: EthConfig {
                account_sk: String::new(),
                consensus_rpc_http_url: String::new(),
                execution_rpc_http_url: String::new(),
                contract_address: format!("{:x}", Address::ZERO),
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios-test".to_string(),
                refresh_finalized_interval: 100,
                optimistic_requests: true,
                light_client: false,
            },
            backlog,
            client: Arc::new(EthereumClient::DirectRpc(
                super::indexer_eth_direct_rpc::RpcEthereumClient::new("http://127.0.0.1:1"),
            )),
            events_tx,
            contract_address: Address::ZERO,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        };

        let err = indexer
            .process_catchup(&MaybeBlock::Missing(BlockId::Number(
                BlockNumberOrTag::Number(12),
            )))
            .await
            .expect_err("missing catchup block should fail when refetch cannot recover it");

        assert!(events_rx.try_recv().is_err());
        assert!(err.to_string().contains("still unavailable after refetch"));
    }

    #[tokio::test]
    async fn ethereum_client_get_blocks_preserves_request_order() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    block_response(3, 9),
                    block_response(1, 7),
                    missing_block_response(2),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = EthereumClient::DirectRpc(
            super::indexer_eth_direct_rpc::RpcEthereumClient::new(&server.url()),
        );
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(7)),
            BlockId::Number(BlockNumberOrTag::Number(8)),
            BlockId::Number(BlockNumberOrTag::Number(9)),
        ];

        let blocks = client.get_blocks(&block_ids).await;

        assert_eq!(blocks.len(), 3);
        assert!(matches!(&blocks[0], MaybeBlock::Block(block) if block.header.number == 7));
        assert!(matches!(
            &blocks[1],
            MaybeBlock::Missing(BlockId::Number(BlockNumberOrTag::Number(8)))
        ));
        assert!(matches!(&blocks[2], MaybeBlock::Block(block) if block.header.number == 9));
    }

    #[tokio::test]
    async fn ethereum_client_get_blocks_retries_and_keeps_positions() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "result": "invalid-shape" }).to_string())
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    block_response(4, 20),
                    missing_block_response(5),
                    block_response(6, 22),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = EthereumClient::DirectRpc(
            super::indexer_eth_direct_rpc::RpcEthereumClient::new(&server.url()),
        );
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(20)),
            BlockId::Number(BlockNumberOrTag::Number(21)),
            BlockId::Number(BlockNumberOrTag::Number(22)),
        ];

        let blocks = client.get_blocks(&block_ids).await;

        assert_eq!(blocks.len(), 3);
        assert!(matches!(&blocks[0], MaybeBlock::Block(block) if block.header.number == 20));
        assert!(matches!(
            &blocks[1],
            MaybeBlock::Missing(BlockId::Number(BlockNumberOrTag::Number(21)))
        ));
        assert!(matches!(&blocks[2], MaybeBlock::Block(block) if block.header.number == 22));
    }

    #[tokio::test]
    async fn catchup_iter_fetches_batches_lazily() {
        let mut server = Server::new_async().await;

        let first_batch = (10..42)
            .enumerate()
            .map(|(index, block_number)| block_response(index as u64 + 1, block_number))
            .collect::<Vec<_>>();
        let second_batch = vec![block_response(33, 42)];

        let second_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"0x2a\""#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(second_batch).to_string())
            .create_async()
            .await;

        let first_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"0xa\""#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(first_batch).to_string())
            .create_async()
            .await;

        let client = Arc::new(EthereumClient::DirectRpc(
            super::indexer_eth_direct_rpc::RpcEthereumClient::new(&server.url()),
        ));
        let mut iter = CatchupIter::new(client, 10, 43);

        for expected_number in 10..42 {
            let next = iter.next().await;
            assert!(matches!(
                next,
                Some(MaybeBlock::Block(block)) if block.header.number == expected_number
            ));
        }

        assert!(first_batch_mock.matched_async().await);
        assert!(!second_batch_mock.matched_async().await);

        let next = iter.next().await;
        assert!(matches!(next, Some(MaybeBlock::Block(block)) if block.header.number == 42));
        assert!(second_batch_mock.matched_async().await);
        assert!(iter.next().await.is_none());
    }

    #[tokio::test]
    async fn catchup_iter_splits_requests_into_32_32_1_batches() {
        let mut server = Server::new_async().await;

        let first_batch = (0..32)
            .enumerate()
            .map(|(idx, block_number)| block_response(idx as u64 + 1, block_number))
            .collect::<Vec<_>>();
        let second_batch = (32..64)
            .enumerate()
            .map(|(idx, block_number)| block_response((idx + 33) as u64, block_number))
            .collect::<Vec<_>>();
        let third_batch = vec![block_response(65, 64)];

        let first_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"id\":32"#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(first_batch).to_string())
            .create_async()
            .await;

        let second_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"id\":64"#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(second_batch).to_string())
            .create_async()
            .await;

        let third_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"\"id\":65"#.to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(third_batch).to_string())
            .create_async()
            .await;

        let client = Arc::new(EthereumClient::DirectRpc(
            super::indexer_eth_direct_rpc::RpcEthereumClient::new(&server.url()),
        ));
        let mut iter = CatchupIter::new(client, 0, 65);

        for expected_number in 0..65 {
            let next = iter.next().await;
            assert!(matches!(
                next,
                Some(MaybeBlock::Block(block)) if block.header.number == expected_number
            ));
        }

        assert!(iter.next().await.is_none());
        assert!(first_batch_mock.matched_async().await);
        assert!(second_batch_mock.matched_async().await);
        assert!(third_batch_mock.matched_async().await);
    }

    #[tokio::test]
    async fn late_watcher_backfill_uses_tx_hash_and_mined_block() {
        let mut server = Server::new_async().await;

        let tx_hash = b256!("018b2331d461a4aeedf6a1f9cc37463377578244e6a35216057a8370714e798f");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let to_address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");

        let tx_response = json!({
            "hash": format!("{tx_hash:#x}"),
            "nonce": "0x1",
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x2",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{to_address:#x}"),
            "value": "0x0",
            "gasPrice": "0x3a29f0f8",
            "gas": "0x5208",
            "maxFeePerGas": "0xba43b7400",
            "maxPriorityFeePerGas": "0x5f5e100",
            "input": "0x",
            "r": "0xd309309a59a49021281cb6bb41d164c96eab4e50f0c1bd24c03ca336e7bc2bb7",
            "s": "0x28a7f089143d0a1355ebeb2a1b9f0e5ad9eca4303021c1400d61bc23c9ac5319",
            "v": "0x0",
            "yParity": "0x0",
            "chainId": "0x7a69",
            "accessList": [],
            "type": "0x2"
        });

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x2",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{to_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionByHash",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": tx_response,
                })
                .to_string(),
            )
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockReceipts",
                "params": ["0x2"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": [receipt_response],
                })
                .to_string(),
            )
            .create_async()
            .await;

        let backlog = Backlog::new();
        let sign_id = SignId::new([0x55; 32]);
        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: sign_id.request_id,
            from_address,
            nonce: 0,
        };
        backlog.watch_execution(Chain::Ethereum, sign_id, tx).await;

        let (events_tx, _events_rx) = mpsc::channel(1);
        let indexer = EthereumIndexer {
            eth: EthConfig {
                account_sk: String::new(),
                consensus_rpc_http_url: server.url(),
                execution_rpc_http_url: server.url(),
                contract_address: format!("{:x}", Address::ZERO),
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios-test".to_string(),
                refresh_finalized_interval: 100,
                optimistic_requests: true,
                light_client: false,
            },
            backlog,
            client: Arc::new(EthereumClient::DirectRpc(
                super::indexer_eth_direct_rpc::RpcEthereumClient::new(&server.url()),
            )),
            events_tx,
            contract_address: Address::ZERO,
            catchup_complete: Arc::new(Notify::new()),
            live_blocks_rx: None,
        };

        let events = indexer
            .collect_execution_confirmations(5, Vec::new())
            .await
            .expect("late watcher backfill should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id: event_tx_id,
                sign_id: event_sign_id,
                source_chain,
                block_height,
                result,
            } => {
                assert_eq!(*event_tx_id, BidirectionalTxId(tx_hash));
                assert_eq!(*event_sign_id, sign_id);
                assert_eq!(*source_chain, Chain::Solana);
                assert_eq!(*block_height, 2);
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }
    }
}
