use crate::gcp::error::DatastoreStorageError;
use crate::gcp::GcpService;
use crate::protocol::{SignQueue, SignRequest};
use crate::types::EthLatestBlockHeight;
use crypto_shared::{derive_epsilon, ScalarExt};
use ethers::prelude::*;
use k256::Scalar;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use web3::{
    contract::{Contract, Options},
    types::{BlockNumber, FilterBuilder, Log, H160, H256},
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
    fn new(latest_block_height: LatestBlockHeight, options: &Options) -> Self {
        tracing::info!(
            "creating new ethereum indexer, latest block height: {}",
            latest_block_height.block_height
        );
        Self {
            latest_block_height: Arc::new(RwLock::new(latest_block_height)),
            last_updated_timestamp: Arc::new(RwLock::new(Instant::now())),
            running_threshold: Duration::from_secs(options.running_threshold),
            behind_threshold: Duration::from_secs(options.behind_threshold),
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
    contract: Contract<web3::transports::Http>,
    gcp_service: GcpService,
    queue: Arc<RwLock<SignQueue>>,
    indexer: EthIndexer,
}

async fn handle_block(
    block_number: u64,
    ctx: &Context,
) -> anyhow::Result<()> {
    tracing::debug!(block_height = block_number, "handle eth block");

    // Create filter for the specific block and SignatureRequested event
    let signature_requested_topic = H256::from_slice(&web3::signing::keccak256(b"SignatureRequested(bytes32,address,uint256,uint256,string)"))?;
    
    let filter = FilterBuilder::default()
        .from_block(BlockNumber::Number(block_number.into()))
        .to_block(BlockNumber::Number(block_number.into()))
        .address(vec![ctx.contract_address])
        .topic0(vec![signature_requested_topic]) // Filter for SignatureRequested event only
        .build();

    // Get logs using filter
    let logs = ctx.web3.eth().logs(filter).await?;
    
    for log in logs {
        let event = parse_event(&log)?;
        tracing::info!("Found eth event: {:?}", event);
        // Create sign request from event
        let sign_request = EthSignRequest {
            payload: event.message_hash,
            path: format!("eth/{}", event.request_id),
            key_version: 0,
        };

        // Add to queue
        ctx.queue.write().await.push(SignRequest::Eth(sign_request));
    }

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

    // Parse requester address from topics[1]
    let requester = H160::from_slice(&log.topics[1].as_fixed_bytes()[12..]);
    
    // Parse request_id and message_hash from data
    let data = log.data.0.as_slice();
    let request_id = web3::types::U256::from_big_endian(&data[0..32]);
    let mut message_hash = [0u8; 32];
    message_hash.copy_from_slice(&data[32..64]);

    Ok(SignatureRequestedEvent {
        requester,
        request_id,
        message_hash,
    })
}

pub fn run(
    options: &Options,
    queue: &Arc<RwLock<SignQueue>>,
    gcp_service: &GcpService,
    rt: &tokio::runtime::Runtime,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, EthIndexer)> {
    let transport = web3::transports::Http::new(&options.eth_rpc_url)?;
    let web3 = Web3::new(transport);
    
    let contract_address = H160::from_str(&options.eth_contract_address)?;
    
    // Load contract ABI
    let contract = Contract::from_json(
        web3.eth(),
        contract_address,
        include_bytes!("../abi/YourContract.json")
    )?;

    let context = Context {
        contract_address,
        web3,
        contract,
        gcp_service: gcp_service.clone(),
        queue: queue.clone(),
        indexer: indexer.clone(),
    };
    
    let latest_block_height = rt.block_on(async {
        match EthLatestBlockHeight::fetch(gcp_service).await {
            Ok(latest) => latest,
            Err(err) => {
                tracing::warn!(%err, "failed to fetch eth latest block height; using start_block_height={} instead", options.start_block_height);
                EthLatestBlockHeight {
                    account_id: node_account_id.clone(),
                    block_height: options.start_block_height,
                }
            }
        }
    });

    let indexer = EthIndexer::new(latest_block_height, options);

    let options = options.clone();
    let join_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let provider = Provider::<Http>::try_from(options.eth_rpc_url.as_str())?;
            
            loop {
                let latest_block = provider.get_block_number().await?;
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
    requester: H160,
    request_id: web3::types::U256,
    message_hash: [u8; 32],
} 