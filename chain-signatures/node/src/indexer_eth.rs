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
use std::{collections::HashMap, sync::Arc};
use std::{collections::VecDeque, fmt, path::PathBuf, str::FromStr, sync::LazyLock, time::Instant};
use tokio::sync::{mpsc, RwLock};
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

    let blocks_failed: Arc<RwLock<VecDeque<(u64, alloy::primitives::B256)>>> =
        Arc::new(RwLock::new(VecDeque::new()));

    let requests_indexed: Arc<RwLock<VecDeque<BlockAndRequests>>> =
        Arc::new(RwLock::new(VecDeque::new()));

    let finalized_epoch: Arc<RwLock<HashMap<u64, alloy::primitives::B256>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let finalized_block: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));

    let client = Arc::new(client);
    let client_clone = Arc::clone(&client);
    let finalized_block_clone = Arc::clone(&finalized_block);
    let finalized_epoch_clone = Arc::clone(&finalized_epoch);
    tokio::spawn(async move {
        tracing::info!("Spawned refresh task started");
        loop {
            refresh_finalized_epoch(
                &client_clone,
                &untrusted_rpc_client,
                &finalized_block_clone,
                &finalized_epoch_clone,
            )
            .await
            .unwrap_or_else(|err| {
                tracing::warn!("Failed to refresh finalized epoch: {:?}", err);
            });
            tokio::time::sleep(Duration::from_millis(eth.refresh_finalized_interval)).await;
        }
    });

    let finalized_block_clone = Arc::clone(&finalized_block);
    let finalized_epoch_clone = Arc::clone(&finalized_epoch);
    let near_account_id_clone = node_near_account_id.clone();
    let requests_indexed_clone = Arc::clone(&requests_indexed);
    tokio::spawn(async move {
        tracing::info!("Spawned task to send indexed requests to send queue");
        loop {
            send_requests_when_final(
                &Arc::clone(&requests_indexed_clone),
                &finalized_block_clone,
                &finalized_epoch_clone,
                sign_tx.clone(),
                near_account_id_clone.clone(),
            )
            .await
            .unwrap_or_else(|err| {
                tracing::warn!("Failed to send requests when final: {:?}", err);
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    let blocks_failed_clone = Arc::clone(&blocks_failed);
    let client_clone = Arc::clone(&client);
    let requests_indexed_clone = Arc::clone(&requests_indexed);
    let near_account_id_clone = node_near_account_id.clone();
    tokio::spawn(async move {
        tracing::info!("Spawned task to retry failed blocks");
        loop {
            retry_failed_blocks(
                Arc::clone(&blocks_failed_clone),
                Arc::clone(&client_clone),
                eth_contract_addr,
                near_account_id_clone.clone(),
                Arc::clone(&requests_indexed_clone),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    loop {
        if block_heads_rx.is_empty() {
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
        let SubscriptionEvent::NewHeads(new_block) = new_block_head;
        let block_number = new_block.header.number;
        let block_hash = new_block.header.hash;
        if let Err(err) = process_block(
            block_number,
            block_hash,
            &client,
            eth_contract_addr,
            node_near_account_id.clone(),
            &requests_indexed,
        )
        .await
        {
            tracing::warn!(
                "Eth indexer failed to process block number {}: {:?}",
                block_number,
                err
            );
            add_failed_block(&blocks_failed, block_number, block_hash).await;
            continue;
        }
        crate::metrics::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
            .set(block_number as i64);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

async fn retry_failed_blocks(
    blocks_failed: Arc<RwLock<VecDeque<(u64, alloy::primitives::B256)>>>,
    client: Arc<EthereumClient<FileDB>>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: Arc<RwLock<VecDeque<BlockAndRequests>>>,
) {
    if blocks_failed.read().await.is_empty() {
        return;
    }
    while { blocks_failed.read().await.len() } > 0 {
        let (block_number, block_hash) = { blocks_failed.write().await.pop_front().unwrap() };
        if let Err(err) = process_block(
            block_number,
            block_hash,
            &client,
            eth_contract_addr,
            node_near_account_id.clone(),
            &requests_indexed,
        )
        .await
        {
            tracing::warn!("Retry failed for block {block_number}: {:?}", err);
            add_failed_block(&blocks_failed, block_number, block_hash).await;
        } else {
            tracing::info!("Successfully retried block: {}", block_number);
        }
    }
}

async fn add_failed_block(
    blocks_failed: &Arc<RwLock<VecDeque<(u64, alloy::primitives::B256)>>>,
    block_number: u64,
    block_hash: alloy::primitives::B256,
) {
    let mut blocks_failed_write = blocks_failed.write().await;
    if let Some(pos) = blocks_failed_write
        .iter()
        .position(|&(num, _)| num >= block_number)
    {
        blocks_failed_write.insert(pos, (block_number, block_hash));
    } else {
        blocks_failed_write.push_back((block_number, block_hash));
    }
}

async fn refresh_finalized_epoch(
    helios_client: &Arc<EthereumClient<FileDB>>,
    untrusted_rpc_client: &RootProvider<Http<AlloyClient>>,
    finalized_block: &Arc<RwLock<u64>>,
    finalized_epoch: &Arc<RwLock<HashMap<u64, alloy::primitives::B256>>>,
) -> anyhow::Result<()> {
    tracing::info!("Refreshing finalized epoch");

    let Some(cur_finalized_block) = helios_client
        .get_block_by_number(BlockTag::Finalized, false)
        .await
        .map_err(|err| anyhow!("Failed to fetch latest finalized block: {:?}", err))?
    else {
        return Err(anyhow!("Fetching finalized block return None"));
    };

    let last_finalized_block_number = {
        let mut finalized_block_write = finalized_block.write().await;
        if *finalized_block_write == 0 {
            *finalized_block_write = cur_finalized_block.header.number;
        }
        *finalized_block_write
    };

    tracing::info!(
        "Current finalized block number: {}, last finalized block number: {}",
        cur_finalized_block.header.number,
        last_finalized_block_number
    );

    if cur_finalized_block.header.number == last_finalized_block_number {
        return Ok(());
    }

    {
        *finalized_block.write().await = cur_finalized_block.header.number;
    }

    let latest_finalized_block_number = cur_finalized_block.header.number;

    {
        let mut epoch_write = finalized_epoch.write().await;
        epoch_write.clear();
        epoch_write.insert(
            latest_finalized_block_number,
            cur_finalized_block.header.inner.parent_hash,
        );

        let mut parent_hash = cur_finalized_block.header.inner.parent_hash;

        for i in (last_finalized_block_number + 1..=latest_finalized_block_number - 1).rev() {
            tracing::info!("Fetching block {i} from untrusted RPC client");
            let cur_block = untrusted_rpc_client
                .get_block_by_number(
                    alloy::eips::BlockNumberOrTag::Number(i),
                    alloy::rpc::types::BlockTransactionsKind::Hashes,
                )
                .await;
            let Ok(Some(cur_block)) = cur_block else {
                tracing::warn!("Failed to get block {i} from untrusted RPC client");
                return Err(anyhow::anyhow!(
                    "Failed to get block {i} from untrusted RPC client"
                ));
            };
            let cur_block_hash = cur_block.header.hash_slow();
            if cur_block_hash == parent_hash {
                epoch_write.insert(i, cur_block_hash);
                parent_hash = cur_block.header.inner.parent_hash;
            } else {
                tracing::warn!(
                    "Block {i} hash mismatch: expected {}, got {}",
                    parent_hash,
                    cur_block_hash
                );
                return Err(anyhow::anyhow!(
                    "Block {i} hash mismatch: expected {}, got {}",
                    parent_hash,
                    cur_block_hash
                ));
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_block(
    block_number: u64,
    block_hash: alloy::primitives::B256,
    client: &Arc<EthereumClient<FileDB>>,
    eth_contract_addr: Address,
    node_near_account_id: AccountId,
    requests_indexed: &Arc<RwLock<VecDeque<BlockAndRequests>>>,
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
    {
        let mut requests_indexed = requests_indexed.write().await;
        requests_indexed.push_back(BlockAndRequests::new(
            block_number,
            block_hash,
            indexed_requests.clone(),
        ));
    }

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

async fn send_requests_when_final(
    requests_indexed: &Arc<RwLock<VecDeque<BlockAndRequests>>>,
    finalized_block: &Arc<RwLock<u64>>,
    finalized_epoch: &Arc<RwLock<HashMap<u64, alloy::primitives::B256>>>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    while let Some(BlockAndRequests {
        block_number,
        block_hash,
        indexed_requests,
    }) = {
        let requests_read = requests_indexed.read().await;
        requests_read.clone().pop_front()
    } {
        if poll_block_finalized(
            block_number,
            block_hash,
            finalized_block.clone(),
            finalized_epoch.clone(),
        )
        .await
        {
            send_indexed_requests(
                indexed_requests,
                sign_tx.clone(),
                node_near_account_id.clone(),
            );
        } else {
            tracing::warn!(
                ?block_hash,
                block_number,
                "Block was not finalized, chain got reorg-ed."
            );
        }
        {
            let mut requests_indexed_write = requests_indexed.write().await;
            requests_indexed_write.pop_front();
        }
    }
    Ok(())
}

async fn poll_block_finalized(
    block_number: u64,
    block_hash: alloy::primitives::B256,
    finalized_block: Arc<RwLock<u64>>,
    finalized_epoch: Arc<RwLock<HashMap<u64, alloy::primitives::B256>>>,
) -> bool {
    let mut last_logged_finalized_block = 0;

    loop {
        let current_finalized_block = { *finalized_block.read().await };

        if current_finalized_block >= block_number {
            let finalized_epoch = { finalized_epoch.read().await.clone() };
            if let Some(finalized_block_hash) = finalized_epoch.get(&block_number) {
                if *finalized_block_hash == block_hash {
                    tracing::info!("Block {block_number} is finalized!");
                    return true;
                } else {
                    tracing::warn!(
                        "Block {block_number} hash mismatch: expected {block_hash:?}, got {finalized_block_hash:?}"
                    );
                    return false;
                }
            } else {
                tracing::warn!("Block {block_number} not found in finalized epoch");
                return false;
            }
        }

        if current_finalized_block > last_logged_finalized_block {
            last_logged_finalized_block = current_finalized_block;
            tracing::info!(
                "Block {block_number} not finalized yet, current finalized block: {last_logged_finalized_block}"
            );
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
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
