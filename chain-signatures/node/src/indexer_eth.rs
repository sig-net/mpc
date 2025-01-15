use crate::indexer::ContractSignRequest;
use crate::protocol::Chain::Ethereum;
use crate::protocol::SignRequest;
use crate::storage::app_data_storage::AppDataStorage;
use crypto_shared::kdf::derive_epsilon_eth;
use crypto_shared::ScalarExt;
use hex::ToHex;
use k256::Scalar;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use web3::{
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

#[derive(Clone)]
pub struct EthIndexer {
    app_data_storage: AppDataStorage,
    last_updated_timestamp: Arc<RwLock<Instant>>,
    latest_block_timestamp: Arc<RwLock<Option<u64>>>,
    running_threshold: Duration,
    behind_threshold: Duration,
}

impl EthIndexer {
    fn new(app_data_storage: AppDataStorage, options: &Options) -> Self {
        Self {
            app_data_storage: app_data_storage.clone(),
            last_updated_timestamp: Arc::new(RwLock::new(Instant::now())),
            latest_block_timestamp: Arc::new(RwLock::new(None)),
            running_threshold: Duration::from_secs(options.eth_running_threshold),
            behind_threshold: Duration::from_secs(options.eth_behind_threshold),
        }
    }

    pub async fn last_processed_block(&self) -> Option<u64> {
        match self.app_data_storage.last_processed_block_eth().await {
            Ok(Some(block_height)) => Some(block_height),
            Ok(None) => {
                tracing::warn!("no last processed eth block found");
                None
            }
            Err(err) => {
                tracing::warn!(%err, "failed to get last processed eth block");
                None
            }
        }
    }

    pub async fn set_last_processed_block(&self, block_height: u64) {
        if let Err(err) = self
            .app_data_storage
            .set_last_processed_block_eth(block_height)
            .await
        {
            tracing::error!(%err, "failed to set last processed eth block");
        }
    }

    /// Check whether the indexer is on track with the latest block height from the chain.
    pub async fn is_running(&self) -> bool {
        self.last_updated_timestamp.read().await.elapsed() <= self.running_threshold
    }

    /// Check whether the indexer is behind with the latest block height from the chain.
    pub async fn is_behind(&self) -> bool {
        if let Some(latest_block_timestamp) = *self.latest_block_timestamp.read().await {
            crate::util::is_elapsed_longer_than_timeout(
                latest_block_timestamp,
                self.behind_threshold.as_millis() as u64,
            )
        } else {
            true
        }
    }

    pub async fn is_stable(&self) -> bool {
        !self.is_behind().await && self.is_running().await
    }

    async fn update_block_height_and_timestamp(&self, block_height: u64, block_timestamp: u64) {
        tracing::debug!(block_height, "update_block_height_and_timestamp eth");
        self.set_last_processed_block(block_height).await;
        *self.last_updated_timestamp.write().await = Instant::now();
        *self.latest_block_timestamp.write().await = Some(block_timestamp);
    }
}

#[derive(Clone)]
struct Context {
    contract_address: H160,
    web3: Web3<web3::transports::Http>,
    sign_tx: mpsc::Sender<SignRequest>,
    indexer: EthIndexer,
}

async fn handle_block(block_number: u64, ctx: &Context) -> anyhow::Result<()> {
    tracing::debug!(block_height = block_number, "handle eth block");

    let signature_requested_topic = H256::from_slice(&web3::signing::keccak256(
        b"SignatureRequested(bytes32,address,uint256,uint256,string)",
    ));

    let filter = FilterBuilder::default()
        .from_block(BlockNumber::Number(block_number.into()))
        .to_block(BlockNumber::Number(block_number.into()))
        .address(vec![ctx.contract_address])
        .topics(Some(vec![signature_requested_topic]), None, None, None)
        .build();

    let block = ctx
        .web3
        .eth()
        .block(web3::types::BlockId::Number(block_number.into()))
        .await?
        .ok_or_else(|| anyhow::anyhow!("eth block {block_number} not found"))?;

    let block_timestamp = block.timestamp.as_u64();

    let logs = ctx.web3.eth().logs(filter).await?;
    tracing::debug!("found {} filtered logs", logs.len());

    let mut pending_requests = Vec::new();
    // Get logs using filter
    for log in logs {
        let event = parse_event(&log)?;
        tracing::debug!("found eth event: {:?}", event);
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
            chain: Ethereum,
        };

        let epsilon = derive_epsilon_eth(
            format!("0x{}", event.requester.encode_hex::<String>()),
            &request.path,
        );
        let mut event_epsilon_bytes: [u8; 32] = [0; 32];
        event.epsilon.to_big_endian(&mut event_epsilon_bytes);
        let event_epsilon_scalar = Scalar::from_bytes(event_epsilon_bytes)
            .ok_or(anyhow::anyhow!("failed to convert event epsilon to scalar"))?;
        if epsilon != event_epsilon_scalar {
            tracing::warn!(
                "epsilon mismatch: derived={:?}, event={:?}",
                epsilon,
                event.epsilon
            );
            continue;
        }
        tracing::debug!(
            "from epsilon: {:?} event epsilon: {:?}",
            epsilon,
            event.epsilon
        );
        // Use transaction hash as entropy
        let entropy = log
            .transaction_hash
            .map(|h| *h.as_fixed_bytes())
            .unwrap_or([0u8; 32]);

        let sign_request = SignRequest {
            request_id: event.request_id,
            request,
            epsilon,
            entropy,
            // TODO: use indexer timestamp instead.
            time_added: Instant::now(),
        };

        pending_requests.push(sign_request);
    }

    for request in pending_requests {
        if let Err(err) = ctx.sign_tx.send(request).await {
            tracing::error!(?err, "failed to send the eth sign request into sign queue");
        }
    }

    ctx.indexer
        .update_block_height_and_timestamp(block_number, block_timestamp)
        .await;

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
    sign_tx: mpsc::Sender<SignRequest>,
    app_data_storage: AppDataStorage,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, EthIndexer)> {
    let transport = web3::transports::Http::new(&options.eth_rpc_url)?;
    let web3 = Web3::new(transport);

    let contract_address = H160::from_str(&options.eth_contract_address)?;

    let indexer = EthIndexer::new(app_data_storage, options);
    let context = Context {
        contract_address,
        web3,
        sign_tx,
        indexer: indexer.clone(),
    };

    let start_block_height = options.eth_start_block_height;

    let join_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            loop {
                let latest_block = match context.web3.eth().block_number().await {
                    Ok(block) => block,
                    Err(err) => {
                        tracing::warn!(%err, "failed to get latest eth block number");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };
                let latest_handled_block = context
                    .indexer
                    .last_processed_block()
                    .await
                    .unwrap_or(start_block_height);
                tracing::debug!(
                    "eth latest_block {} latest_handled_block {}",
                    latest_block,
                    latest_handled_block
                );

                if latest_handled_block < latest_block.as_u64() {
                    if let Err(err) = handle_block(latest_handled_block + 1, &context).await {
                        tracing::warn!(%err, "failed to handle eth block");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                } else {
                    tokio::time::sleep(Duration::from_secs(5)).await;
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
