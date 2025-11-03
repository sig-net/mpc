pub mod indexer_eth_direct_rpc;
pub mod indexer_eth_helios;

use crate::protocol::{Chain, IndexedSignRequest, SignRequestType};
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::Log;

use crate::sign_bidirectional::BidirectionalTx;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::storage::app_data_storage::AppDataStorage;
use alloy::sol_types::{sol, SolEvent};
use k256::Scalar;
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::{fmt, sync::LazyLock, time::Instant};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
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

type BlockNumberAndHash = (u64, alloy::primitives::B256);

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
        timestamp_sign_queue: None,
        total_timeout,
        sign_request_type: SignRequestType::Sign,
        participants: None,
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
                sign_request_type: request.sign_request_type,
                participants: request.participants,
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

impl SignatureRequestedEvent {
    fn encode_abi(&self) -> Vec<u8> {
        let signature_requested_event_encoding = SignatureRequestedEncoding {
            sender: self.requester,
            payload: self.payload_hash.to_vec().into(),
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

pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    bidirectional_tx_map: Arc<RwLock<HashMap<BidirectionalTxId, BidirectionalTx>>>,
    helios: bool,
) {
    if helios {
        indexer_eth_helios::run(
            eth,
            sign_tx,
            app_data_storage,
            node_near_account_id,
            bidirectional_tx_map,
        )
        .await;
    } else {
        indexer_eth_direct_rpc::run(
            eth,
            sign_tx,
            app_data_storage,
            node_near_account_id,
            bidirectional_tx_map,
        )
        .await;
    }
}
