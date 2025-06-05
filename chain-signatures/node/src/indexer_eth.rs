use crate::protocol::{Chain, IndexedSignRequest};
use alloy::consensus::BlockHeader;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::Log;
use alloy::sol_types::{sol, SolEvent};
use alloy::transports::http::Client as AlloyClient;
use alloy::transports::http::Http;
use anyhow::anyhow;
use helios::common::types::{BlockTag, SubscriptionEvent, SubscriptionType};
use helios::ethereum::{
    config::networks::Network, database::FileDB, EthereumClient, EthereumClientBuilder,
};
use k256::Scalar;
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::{fmt, path::PathBuf, str::FromStr, sync::LazyLock, time::Instant};
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
            },
            _ => Self {
                eth_account_sk: None,
                eth_consensus_rpc_http_url: None,
                eth_execution_rpc_http_url: None,
                eth_contract_address: None,
                eth_network: None,
                eth_helios_data_path: None,
                eth_refresh_finalized_interval: None,
            },
        }
    }
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

fn sign_request_from_filtered_log(log: Log) -> anyhow::Result<IndexedSignRequest> {
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

const MAX_INDEXED_REQUESTS: usize = 1024;
pub fn indexed_channel() -> (
    mpsc::Sender<BlockAndRequests>,
    mpsc::Receiver<BlockAndRequests>,
) {
    mpsc::channel(MAX_INDEXED_REQUESTS)
}

type BlockNumberAndHash = (u64, alloy::primitives::B256);
const MAX_FAILED_BLOCKS: usize = 1024;
pub fn failed_blocks_channel() -> (
    mpsc::Sender<BlockNumberAndHash>,
    mpsc::Receiver<BlockNumberAndHash>,
) {
    mpsc::channel(MAX_FAILED_BLOCKS)
}

type BlockNumberToHashMap = HashMap<u64, alloy::primitives::B256>;
const MAX_FINALIZED_BLOCKS: usize = 1024;
pub fn finalized_blocks_channel() -> (
    mpsc::Sender<BlockNumberToHashMap>,
    mpsc::Receiver<BlockNumberToHashMap>,
) {
    mpsc::channel(MAX_FINALIZED_BLOCKS)
}

pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    let Some(eth) = eth else {
        tracing::warn!("ethereum indexer is disabled");
        return Ok(());
    };

    let network = Network::from_str(eth.network.as_str())
        .map_err(|err| anyhow::anyhow!("Network input incorrect: {:?}", err))?;

    let mut client: EthereumClient<FileDB> = EthereumClientBuilder::new()
        .network(network)
        .consensus_rpc(&eth.consensus_rpc_http_url)
        .execution_rpc(&eth.execution_rpc_http_url)
        .data_dir(PathBuf::from(&eth.helios_data_path))
        .build()
        .map_err(|err| anyhow::anyhow!("Failed to build Ethereum Helios client: {:?}", err))?;

    tracing::info!("Built Helios client on network {}", network);

    client
        .start()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to start Ethereum Helios client: {:?}", err))?;

    client.wait_synced().await;

    let untrusted_rpc_client: RootProvider<alloy::transports::http::Http<AlloyClient>> =
        ProviderBuilder::new().on_http(url::Url::parse(&eth.execution_rpc_http_url).unwrap());

    tracing::info!("running ethereum indexer");

    let eth_contract_addr = Address::from_str(&format!("0x{}", eth.contract_address))?;

    let mut block_heads_rx = client
        .subscribe(SubscriptionType::NewHeads)
        .await
        .map_err(|err| anyhow::anyhow!("Failed to subscribe to new block heads: {:?}", err))?;

    let (blocks_failed_send, blocks_failed_recv) = failed_blocks_channel();

    let (requests_indexed_send, requests_indexed_recv) = indexed_channel();

    let (finalized_blocks_send, finalized_blocks_recv) = finalized_blocks_channel();

    let client = Arc::new(client);
    let client_clone = Arc::clone(&client);
    tokio::spawn(async move {
        tracing::info!("Spawned task to refresh finalized epoch's blocks");
        refresh_finalized_epoch(
            &client_clone,
            &untrusted_rpc_client,
            finalized_blocks_send.clone(),
            eth.refresh_finalized_interval,
        )
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("Failed to refresh finalized epoch: {:?}", err);
        });
    });

    let near_account_id_clone = node_near_account_id.clone();
    tokio::spawn(async move {
        tracing::info!("Spawned task to send indexed requests to send queue");
        send_requests_when_final(
            requests_indexed_recv,
            finalized_blocks_recv,
            sign_tx.clone(),
            near_account_id_clone.clone(),
        )
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("Failed to send requests when final: {:?}", err);
        });
    });

    let near_account_id_clone = node_near_account_id.clone();
    let requests_indexed_send_clone = requests_indexed_send.clone();
    let blocks_failed_send_clone = blocks_failed_send.clone();
    let client_clone = Arc::clone(&client);
    tokio::spawn(async move {
        tracing::info!("Spawned task to retry failed blocks");
        retry_failed_blocks(
            blocks_failed_recv,
            blocks_failed_send_clone,
            &client_clone,
            eth_contract_addr,
            near_account_id_clone,
            requests_indexed_send_clone,
        )
        .await;
    });

    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let requests_indexed_send_clone = requests_indexed_send.clone();
    let mut receiver_state_update_timestamp = Instant::now();
    loop {
        interval.tick().await;
        if block_heads_rx.is_empty() {
            if receiver_state_update_timestamp.elapsed() > Duration::from_secs(60) {
                tracing::warn!("No new block heads received for 60 seconds, waiting...");
                receiver_state_update_timestamp = Instant::now();
            }
            continue;
        }
        let Ok(new_block_head) = block_heads_rx.recv().await.inspect_err(|err| {
            tracing::warn!(
                "Eth indexer failed to receive latest block header: {:?}",
                err
            );
        }) else {
            break;
        };
        receiver_state_update_timestamp = Instant::now();
        let SubscriptionEvent::NewHeads(new_block) = new_block_head;
        let block_number = new_block.header.number;
        let block_hash = new_block.header.hash;
        if block_number % 10 == 0 {
            tracing::info!("Received new block head: {block_number}");
        }
        if let Err(err) = process_block(
            block_number,
            block_hash,
            &client,
            eth_contract_addr,
            node_near_account_id.clone(),
            requests_indexed_send_clone.clone(),
        )
        .await
        {
            tracing::warn!(
                "Eth indexer failed to process block number {}: {:?}",
                block_number,
                err
            );
            add_failed_block(blocks_failed_send.clone(), block_number, block_hash).await;
            continue;
        }
        crate::metrics::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
            .set(block_number as i64);
    }
    Ok(())
}

async fn retry_failed_blocks(
    mut blocks_failed_rx: mpsc::Receiver<BlockNumberAndHash>,
    blocks_failed_tx: mpsc::Sender<BlockNumberAndHash>,
    client: &Arc<EthereumClient<FileDB>>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
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
        )
        .await
        {
            tracing::warn!("Retry failed for block {block_number}: {:?}", err);
            add_failed_block(blocks_failed_tx.clone(), block_number, block_hash).await;
        } else {
            tracing::info!("Successfully retried block: {}", block_number);
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

async fn get_finalized_block_from_helios_with_retry(
    helios_client: &Arc<EthereumClient<FileDB>>,
    max_retries: u8,
) -> anyhow::Result<alloy::rpc::types::Block> {
    let mut retries = 0;
    loop {
        match helios_client
            .get_block_by_number(BlockTag::Finalized, false)
            .await
        {
            Ok(Some(block)) => return Ok(block),
            Ok(None) => {
                let err_msg = "Latest finalized block not found from Helios client";
                return Err(anyhow::anyhow!(err_msg));
            }
            Err(e) => {
                if retries < max_retries {
                    retries += 1;
                    tracing::warn!(
                        "Failed to get latest finalized block from Helios client: {:?}, retrying",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "Failed to get finalized block from Helios client: {:?}, exceeded maximum retry",
                    e
                ));
            }
        }
    }
}

/// Polls for the latest finalized block and update the latest finalized blocks.
/// Once finalized block gets updated, we fetch the blocks in the epoch ending with the finalized block.
/// To ensure the blocks we fetched are proven, we fetch the latest finalized block from Helios.
/// Then using an unstrusted RPC client, we go backwards to fetch the blocks in the epoch and check that the hash of the block's header == its next block's parent_hash.
/// This is proven because the finalized block is already proven by helios, and by checking current block hash == next block's parent hash, we prove that each block is indeed included in the chain.
async fn refresh_finalized_epoch(
    helios_client: &Arc<EthereumClient<FileDB>>,
    untrusted_rpc_client: &RootProvider<Http<AlloyClient>>,
    finalized_epoch_send: mpsc::Sender<HashMap<u64, alloy::primitives::B256>>,
    refresh_finalized_interval: u64,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_millis(refresh_finalized_interval));
    let mut finalized_epoch: BlockNumberToHashMap = BlockNumberToHashMap::new();
    let mut final_block_number: Option<u64> = None;
    loop {
        interval.tick().await;
        tracing::info!("Refreshing finalized epoch");

        let new_finalized_bock =
            match get_finalized_block_from_helios_with_retry(helios_client, 5).await {
                Ok(block) => block,
                Err(e) => {
                    tracing::warn!("Failed to get finalized block: {:?}", e);
                    continue;
                }
            };

        tracing::info!(
            "New finalized block number: {}, last finalized block number: {:?}",
            new_finalized_bock.header.number,
            final_block_number
        );

        let new_final_block_number = new_finalized_bock.header.number;

        let Some(last_final_block_number) = final_block_number else {
            tracing::info!("Last finalized block was None");
            final_block_number.replace(new_final_block_number);
            continue;
        };

        if new_final_block_number < last_final_block_number {
            let err_msg =
                "New finalized block number overflowed range of u64 and has wrapped around!";
            tracing::warn!(err_msg);
            continue;
        }

        if last_final_block_number == new_final_block_number {
            tracing::info!("No new finalized block");
            continue;
        }

        finalized_epoch.insert(new_final_block_number, new_finalized_bock.header.hash);

        let mut parent_hash = new_finalized_bock.header.inner.parent_hash;

        let Some(start) = last_final_block_number.checked_add(1) else {
            let err_msg = "Last finalized block number + 1 overflowed range of u64!";
            tracing::warn!(err_msg);
            continue;
        };
        let Some(end) = new_final_block_number.checked_sub(1) else {
            let err_msg = "New finalized block number - 1 overflowed range of u64!";
            tracing::warn!(err_msg);
            continue;
        };

        let mut epoch_update_err = false;
        // go backwards from latest_finalized_block_number - 1, and check that each block's hash == next block's parent hash
        for i in (start..=end).rev() {
            tracing::info!("Fetching block {i} from untrusted RPC client");

            let cur_block =
                match get_block_from_untrusted_rpc_with_retry(untrusted_rpc_client, i, 5).await {
                    Ok(block) => block,
                    Err(e) => {
                        tracing::warn!("Error fetching finalized block {i}: {:?}", e);
                        break;
                    }
                };

            let cur_block_hash = cur_block.header.hash_slow();

            if cur_block_hash == parent_hash {
                finalized_epoch.insert(i, cur_block_hash);
                parent_hash = cur_block.header.inner.parent_hash;
            } else {
                tracing::warn!(
                    "Block {i} hash mismatch: expected {}, got {}, untrusted RPC returned invalid block",
                    parent_hash,
                    cur_block_hash
                );
                epoch_update_err = true;
                break;
            }
        }
        if epoch_update_err {
            tracing::warn!("Finalized epoch update failed on some blocks, retrying");
            continue;
        }
        final_block_number.replace(new_final_block_number);
        tracing::info!("Sending finalized blocks to finalized epoch");
        finalized_epoch_send
            .send(finalized_epoch.clone())
            .await
            .map_err(|err| anyhow!("Failed to send finalized block: {:?}", err))?;
    }
}

async fn get_block_from_untrusted_rpc_with_retry(
    untrusted_rpc_client: &RootProvider<Http<AlloyClient>>,
    block_number: u64,
    max_retries: u8,
) -> anyhow::Result<alloy::rpc::types::Block> {
    let mut retries = 0;
    loop {
        match untrusted_rpc_client
            .get_block_by_number(
                alloy::eips::BlockNumberOrTag::Number(block_number),
                alloy::rpc::types::BlockTransactionsKind::Hashes,
            )
            .await
        {
            Ok(Some(block)) => return Ok(block),
            Ok(None) => {
                let err_msg = format!("Block {block_number} not found from untrusted RPC client");
                return Err(anyhow::anyhow!(err_msg));
            }
            Err(e) => {
                if retries < max_retries {
                    retries += 1;
                    tracing::warn!(
                        "Failed to get block {block_number} from untrusted RPC client: {:?}, retrying",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "Failed to get block {block_number} from untrusted RPC client: {:?}, exceeded maximum retry",
                    e
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_block(
    block_number: u64,
    block_hash: alloy::primitives::B256,
    client: &Arc<EthereumClient<FileDB>>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
) -> anyhow::Result<()> {
    tracing::info!(
        "Processing block number {} with hash {:?}",
        block_number,
        block_hash
    );
    let start = Instant::now();
    let block_receipts_result = client
        .get_block_receipts(BlockTag::Number(block_number))
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

    let indexed_requests = parse_filtered_logs(filtered_logs);
    requests_indexed
        .send(BlockAndRequests::new(
            block_number,
            block_hash,
            indexed_requests.clone(),
        ))
        .await
        .map_err(|err| anyhow::anyhow!("Failed to send indexed requests: {:?}", err))?;

    let block_timestamp = client
        .get_block_by_number(BlockTag::Number(block_number), false)
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
/// This assumes that the requests_indexed are ordered by block number.
/// Whenever there are requests in requests_indexed, function will keep polling if the block where the first request is in has finalized, if finalized, it will send this request to the sign queue.
async fn send_requests_when_final(
    mut requests_indexed: mpsc::Receiver<BlockAndRequests>,
    mut finalized_epoch: mpsc::Receiver<BlockNumberToHashMap>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    loop {
        let mut finalized_blocks_map: BlockNumberToHashMap = HashMap::new();
        while let Some(BlockAndRequests {
            block_number,
            block_hash,
            indexed_requests,
        }) = requests_indexed.recv().await
        {
            loop {
                if let Some(finalized_block_hash) = finalized_blocks_map.get(&block_number) {
                    if *finalized_block_hash == block_hash {
                        tracing::info!("Block {block_number} is finalized!");
                        send_indexed_requests(
                            indexed_requests.clone(),
                            sign_tx.clone(),
                            node_near_account_id.clone(),
                        );
                        break;
                    } else {
                        tracing::error!(
                            "Block {block_number} hash mismatch: expected {block_hash:?}, got {finalized_block_hash:?}. Chain re-orged."
                        );
                        //TODO: handle the block reorg case
                        break;
                    }
                } else {
                    tracing::warn!(
                        "Block number {block_number} with hash: {block_hash:?} not in finalized epoch. "
                    );
                    if !finalized_blocks_map.is_empty()
                        && finalized_blocks_map.keys().all(|&k| k > block_number)
                    {
                        tracing::error!("Block {block_number} is in history");
                        //TODO: handle the block in history case which happens when a block is retried
                        break;
                    } else {
                        let Some(received_map) = finalized_epoch.recv().await else {
                            tracing::warn!("Failed to receive finalized blocks");
                            return Err(anyhow::anyhow!("Failed to receive finalized blocks"));
                        };
                        finalized_blocks_map.clear();
                        finalized_blocks_map.extend(received_map);
                    }
                }
            }
        }
    }
}

fn parse_filtered_logs(logs: Vec<Log>) -> Vec<IndexedSignRequest> {
    let mut indexed_requests = Vec::new();
    for log in logs {
        tracing::debug!("Parsing Ethereum log: {:?}", log);
        match sign_request_from_filtered_log(log.clone()) {
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
