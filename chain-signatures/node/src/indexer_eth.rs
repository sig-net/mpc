use crate::gcp::error::DatastoreStorageError;
use crate::gcp::GcpService;
use crate::indexer::ContractSignRequest;
use crate::protocol::{Chain, SignQueue, SignRequest};
use crate::types::EthLatestBlockHeight;
use crypto_shared::kdf::derive_epsilon_eth;
use crypto_shared::{derive_epsilon, ScalarExt};
use k256::Scalar;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use web3::{
    contract::Contract,
    types::{BlockNumber, FilterBuilder, Log, H160, H256, U256},
    Web3,
};

/// Configures Ethereum indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_eth_options")]
pub struct Options {
    /// Ethereum RPC URL
    #[clap(long, env("MPC_INDEXER_ETH_RPC_URL"))]
    pub eth_rpc_url: String,

    /// The contract address to watch
    #[clap(long, env("MPC_INDEXER_ETH_CONTRACT_ADDRESS"))]
    pub eth_contract_address: String,

    /// The block height to start indexing from
    #[clap(long, env("MPC_INDEXER_ETH_START_BLOCK"), default_value = "0")]
    pub eth_start_block_height: u64,

    /// The amount of time before we consider the indexer behind
    #[clap(long, env("MPC_INDEXER_ETH_BEHIND_THRESHOLD"), default_value = "180")]
    pub eth_behind_threshold: u64,

    /// The threshold to check if indexer needs restart
    #[clap(long, env("MPC_INDEXER_ETH_RUNNING_THRESHOLD"), default_value = "300")]
    pub eth_running_threshold: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::new();
        args.extend([
            "--eth-rpc-url".to_string(),
            self.eth_rpc_url,
            "--eth-contract-address".to_string(),
            self.eth_contract_address,
            "--eth-start-block-height".to_string(),
            self.eth_start_block_height.to_string(),
            "--eth-behind-threshold".to_string(),
            self.eth_behind_threshold.to_string(),
            "--eth-running-threshold".to_string(),
            self.eth_running_threshold.to_string(),
        ]);
        args
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EthSignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Debug, Clone)]
pub struct EthIndexer {
    latest_block_height: Arc<RwLock<EthLatestBlockHeight>>,
    last_updated_timestamp: Arc<RwLock<Instant>>,
    running_threshold: Duration,
    behind_threshold: Duration,
}

impl EthIndexer {
    fn new(latest_block_height: EthLatestBlockHeight, options: &Options) -> Self {
        tracing::info!(
            "creating new ethereum indexer, latest block height: {}",
            latest_block_height.block_height
        );
        Self {
            latest_block_height: Arc::new(RwLock::new(latest_block_height)),
            last_updated_timestamp: Arc::new(RwLock::new(Instant::now())),
            running_threshold: Duration::from_secs(options.eth_running_threshold),
            behind_threshold: Duration::from_secs(options.eth_behind_threshold),
        }
    }

    pub async fn latest_block_height(&self) -> u64 {
        self.latest_block_height.read().await.block_height
    }

    pub async fn is_on_track(&self) -> bool {
        self.last_updated_timestamp.read().await.elapsed() <= self.behind_threshold
    }

    pub async fn is_running(&self) -> bool {
        self.last_updated_timestamp.read().await.elapsed() <= self.running_threshold
    }

    pub async fn is_behind(&self) -> bool {
        self.last_updated_timestamp.read().await.elapsed() > self.behind_threshold
    }

    async fn update_block_height(
        &self,
        block_height: u64,
        gcp: &GcpService,
    ) -> Result<(), DatastoreStorageError> {
        tracing::debug!(block_height, "eth indexer update_block_height");
        *self.last_updated_timestamp.write().await = Instant::now();
        self.latest_block_height
            .write()
            .await
            .set(block_height)
            .store(gcp)
            .await
    }
}

#[derive(Clone)]
struct Context {
    contract_address: H160,
    web3: Web3<web3::transports::Http>,
    gcp_service: GcpService,
    queue: Arc<RwLock<SignQueue>>,
    indexer: EthIndexer,
}

async fn handle_block(block_number: u64, ctx: &Context) -> anyhow::Result<()> {
    tracing::debug!(block_height = block_number, "handle eth block");

    // Create filter for the specific block and SignatureRequested event
    let signature_requested_topic = H256::from_slice(&web3::signing::keccak256(
        b"SignatureRequested(bytes32,address,uint256,uint256,string)",
    ));

    let filter = FilterBuilder::default()
        .from_block(BlockNumber::Number(block_number.into()))
        .to_block(BlockNumber::Number(block_number.into()))
        .address(vec![ctx.contract_address])
        .topics(Some(vec![signature_requested_topic]), None, None, None)
        .build();

    let mut pending_requests = Vec::new();
    // Get logs using filter
    let logs = ctx.web3.eth().logs(filter).await?;
    for log in logs {
        let event = parse_event(&log)?;
        tracing::info!("Found eth event: {:?}", event);
        // Create sign request from event
        let Some(payload) = Scalar::from_bytes(event.payload_hash) else {
            tracing::warn!(
                "eth `sign` did not produce payload hash correctly: {:?}",
                event.payload_hash,
            );
            continue;
        };
        let request = ContractSignRequest {
            payload,
            path: event.path,
            key_version: 0,
        };
        let epsilon = derive_epsilon_eth(event.requester.to_string(), &request.path);
        let entropy = [0u8; 32]; // TODO
        let sign_request = SignRequest {
            request_id: event.request_id,
            request,
            epsilon,
            entropy,
            // TODO: use indexer timestamp instead.
            time_added: Instant::now(),
            chain: Chain::Ethereum,
        };

        pending_requests.push(sign_request);
    }
    let mut queue = ctx.queue.write().await;
    for sign_request in pending_requests {
        queue.add(sign_request);
    }
    drop(queue);

    ctx.indexer
        .update_block_height(block_number, &ctx.gcp_service)
        .await?;

    Ok(())
}
// Helper function to parse event logs
fn parse_event(log: &Log) -> anyhow::Result<SignatureRequestedEvent> {
    // Ensure we have enough topics
    if log.topics.len() < 2 {
        anyhow::bail!("Invalid number of topics");
    }

    // Parse request_id from topics[1]
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&log.topics[1].as_bytes());

    // Parse data fields
    let data = log.data.0.as_slice();

    // Parse requester address (20 bytes)
    let requester = H160::from_slice(&data[12..32]);

    // Parse epsilon (32 bytes)
    let epsilon = U256::from_big_endian(&data[32..64]);

    // Parse payload hash (32 bytes)
    let mut payload_hash = [0u8; 32];
    payload_hash.copy_from_slice(&data[64..96]);

    // Parse path string
    let path_offset = U256::from_big_endian(&data[96..128]).as_usize();
    let path_length = U256::from_big_endian(&data[path_offset..path_offset + 32]).as_usize();
    let path_bytes = &data[path_offset + 32..path_offset + 32 + path_length];
    let path = String::from_utf8(path_bytes.to_vec())?;

    Ok(SignatureRequestedEvent {
        request_id,
        requester,
        epsilon,
        payload_hash,
        path,
    })
}

pub fn run(
    options: &Options,
    node_account_id: &AccountId,
    queue: &Arc<RwLock<SignQueue>>,
    gcp_service: &GcpService,
    rt: &tokio::runtime::Runtime,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, EthIndexer)> {
    let transport = web3::transports::Http::new(&options.eth_rpc_url)?;
    let web3 = Web3::new(transport);

    let contract_address = H160::from_str(&options.eth_contract_address)?;

    let latest_block_height = rt.block_on(async {
        match EthLatestBlockHeight::fetch(gcp_service).await {
            Ok(latest) => latest,
            Err(err) => {
                tracing::warn!(%err, "failed to fetch eth latest block height; using start_block_height={} instead", options.eth_start_block_height);
                EthLatestBlockHeight {
                    account_id: node_account_id.clone(),
                    block_height: options.eth_start_block_height,
                }
            }
        }
    });

    let indexer = EthIndexer::new(latest_block_height, options);
    let context = Context {
        contract_address,
        web3,
        gcp_service: gcp_service.clone(),
        queue: queue.clone(),
        indexer: indexer.clone(),
    };

    let join_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            loop {
                let latest_block = context.web3.eth().block_number().await?;
                let current_block = context.indexer.latest_block_height().await;

                if current_block < latest_block.as_u64() {
                    handle_block(current_block, &context).await?;
                } else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        })
    });

    Ok((join_handle, indexer))
}

#[derive(Debug)]
struct SignatureRequestedEvent {
    request_id: [u8; 32],
    requester: H160,
    epsilon: U256,
    payload_hash: [u8; 32],
    path: String,
}
