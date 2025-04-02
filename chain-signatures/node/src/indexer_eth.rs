use crate::protocol::{Chain, IndexedSignRequest};
use alloy::{
    primitives::{
        hex::{self, ToHexExt},
        Address, Bytes, U256,
    },
    rpc::types::Log,
    sol_types::{sol, SolEvent},
};
use helios::common::types::{BlockTag, SubscriptionEvent, SubscriptionType};
use helios::ethereum::{
    config::networks::Network, database::FileDB, EthereumClient, EthereumClientBuilder,
};
use k256::Scalar;
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, fmt, path::PathBuf, str::FromStr, sync::LazyLock, time::Instant};
use tokio::{
    sync::mpsc,
    time::{interval, Duration},
};

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
}

impl fmt::Debug for EthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthConfig")
            .field("account_sk", &"<hidden>")
            .field("consensus_rpc_http_url", &self.consensus_rpc_http_url)
            .field("execution_rpc_http_url", &self.execution_rpc_http_url)
            .field("contract_address", &self.contract_address)
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
    /// Ethereum HTTP RPC URL
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
        requires = "eth_network",
        default_value = "sepolia"
    )]
    pub eth_network: Option<String>,
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
        args
    }

    pub fn into_config(self) -> Option<EthConfig> {
        Some(EthConfig {
            account_sk: self.eth_account_sk?,
            consensus_rpc_http_url: self.eth_consensus_rpc_http_url?,
            execution_rpc_http_url: self.eth_execution_rpc_http_url?,
            contract_address: self.eth_contract_address?,
            network: self.eth_network?,
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
            },
            _ => Self {
                eth_account_sk: None,
                eth_consensus_rpc_http_url: None,
                eth_execution_rpc_http_url: None,
                eth_contract_address: None,
                eth_network: None,
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

fn sign_request_from_filtered_log(log: Log) -> anyhow::Result<IndexedSignRequest> {
    let event = parse_event(&log)?;
    tracing::debug!("found eth event: {:?}", event);
    if event.deposit == U256::from_str("0").unwrap() {
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
        // TODO: use indexer timestamp instead.
        timestamp: Instant::now(),
        unix_timestamp: crate::util::current_unix_timestamp(),
    })
}

fn encode_abi(event: &SignatureRequestedEvent) -> Vec<u8> {
    let signature_requested_event_encoding = SignatureRequestedEncoding {
        sender: event.requester,
        payload: event.payload_hash.into(),
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

    let path = parse_string_args(data.clone(), 160);

    let algo = parse_string_args(data.clone(), 192);

    let dest = parse_string_args(data.clone(), 224);

    let params = parse_string_args(data.clone(), 256);

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

fn parse_string_args(data: Bytes, offset_start: usize) -> String {
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
        .data_dir(PathBuf::from("/tmp/helios"))
        .build()
        .map_err(|err| anyhow::anyhow!("Failed to build Ethereum Helios client: {:?}", err))?;

    tracing::info!("Built Helios client on network {}", network);

    client
        .start()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to start Ethereum Helios client: {:?}", err))?;

    client.wait_synced().await;

    tracing::info!("running ethereum indexer");

    let eth_contract_addr = Address::from_str(&format!("0x{}", eth.contract_address))?;

    let mut block_heads_rx = client
        .subscribe(SubscriptionType::NewHeads)
        .await
        .map_err(|err| anyhow::anyhow!("Failed to subscribe to new block heads: {:?}", err))?;

    let mut interval = interval(Duration::from_millis(100));
    let mut blocks_failed: VecDeque<u64> = VecDeque::new();
    const MAX_BLOCK_RETRIES_PER_TICK: usize = 10;
    loop {
        for _ in 0..blocks_failed.len().min(MAX_BLOCK_RETRIES_PER_TICK) {
            if let Some(block_number) = blocks_failed.pop_front() {
                if let Err(err) = process_block(
                    block_number,
                    &client,
                    eth_contract_addr,
                    sign_tx.clone(),
                    node_near_account_id.clone(),
                )
                .await
                {
                    tracing::warn!("Retry failed for block {block_number}: {:?}", err);
                    blocks_failed.push_back(block_number);
                } else {
                    tracing::info!("Successfully retried block: {}", block_number);
                }
            }
        }
        interval.tick().await;
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
        if let Err(err) = process_block(
            block_number,
            &client,
            eth_contract_addr,
            sign_tx.clone(),
            node_near_account_id.clone(),
        )
        .await
        {
            tracing::warn!(
                "Eth indexer failed to process block number {}: {:?}",
                block_number,
                err
            );
            blocks_failed.push_back(block_number);
            continue;
        }
        crate::metrics::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
            .set(block_number as i64);
    }
    Ok(())
}

async fn process_block(
    block_number: u64,
    client: &EthereumClient<FileDB>,
    eth_contract_addr: Address,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    let Some(block_receipts) = client
        .get_block_receipts(BlockTag::Number(block_number))
        .await
        .map_err(|err| {
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

    for log in filtered_logs.into_iter() {
        if let Err(err) =
            process_filtered_log(log.clone(), sign_tx.clone(), node_near_account_id.clone())
        {
            tracing::warn!(?log, ?err, "Failed to process Ethereum log");
        }
    }
    Ok(())
}

fn process_filtered_log(
    log: Log,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
    ws: &Web3<WebSocket>,
) -> anyhow::Result<()> {
    tracing::info!("Received new Ethereum sign request: {:?}", log);

    let sign_request = match sign_request_from_filtered_log(log.clone()) {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!("Failed to parse Ethereum sign request: {:?}", err);
            return Err(err);
        }
    };

    let block_number = log.block_number.map(|bn| bn.as_u64());
    let indexed_unix_timestamp = sign_request.unix_timestamp;

    let ws_clone = ws.clone();
    tokio::spawn(async move {
        if let Err(err) = sign_tx.send(sign_request).await {
            tracing::error!(?err, "Failed to send ETH sign request into queue");
        } else {
            crate::metrics::NUM_SIGN_REQUESTS
                .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
                .inc();
        }

        if let Some(block_number) = block_number {
            observe_indexer_latency(
                &ws_clone,
                block_number,
                indexed_unix_timestamp,
                &node_near_account_id,
            )
            .await;
        }
    });

    Ok(())
}

async fn observe_indexer_latency(
    ws: &Web3<WebSocket>,
    block_number: u64,
    indexed_unix_timestamp: u64,
    node_near_account_id: &AccountId,
) {
    if let Ok(Some(block)) = ws
        .eth()
        .block(web3::types::BlockId::Number(BlockNumber::Number(
            block_number.into(),
        )))
        .await
    {
        let block_time = block.timestamp.as_u64();
        crate::metrics::INDEXER_DELAY
            .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
            .observe(
                crate::util::duration_between_unix(block_time, indexed_unix_timestamp).as_secs()
                    as f64,
            );
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
