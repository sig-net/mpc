use crate::protocol::{SignQueue, SignRequest};
use crate::storage::app_data_storage::AppDataStorage;
use crypto_shared::{derive_epsilon, ScalarExt};
use k256::Scalar;
use near_account_id::AccountId;
use near_lake_framework::{LakeBuilder, LakeContext};
use near_lake_primitives::actions::ActionMetaDataExt;
use near_lake_primitives::receipts::ExecutionStatus;

use near_primitives::types::BlockHeight;
use serde::{Deserialize, Serialize};
use std::ops::Mul;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configures indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_options")]
pub struct Options {
    /// AWS S3 bucket name for NEAR Lake Indexer
    #[clap(
        long,
        env("MPC_INDEXER_S3_BUCKET"),
        default_value = "near-lake-data-testnet"
    )]
    pub s3_bucket: String,

    /// AWS S3 region name for NEAR Lake Indexer
    #[clap(long, env("MPC_INDEXER_S3_REGION"), default_value = "eu-central-1")]
    pub s3_region: String,

    /// AWS S3 URL for NEAR Lake Indexer (can be used to point to LocalStack)
    #[clap(long, env("MPC_INDEXER_S3_URL"))]
    pub s3_url: Option<String>,

    /// The amount of time before we should that our indexer is behind.
    #[clap(long, env("MPC_INDEXER_BEHIND_THRESHOLD"), default_value = "200")]
    pub behind_threshold: u64,

    /// The threshold in seconds to check if the indexer needs to be restarted due to it stalling.
    #[clap(long, env("MPC_INDEXER_RUNNING_THRESHOLD"), default_value = "300")]
    pub running_threshold: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut opts = vec![
            "--s3-bucket".to_string(),
            self.s3_bucket,
            "--s3-region".to_string(),
            self.s3_region,
            "--behind-threshold".to_string(),
            self.behind_threshold.to_string(),
            "--running-threshold".to_string(),
            self.running_threshold.to_string(),
        ];

        if let Some(s3_url) = self.s3_url {
            opts.extend(vec!["--s3-url".to_string(), s3_url]);
        }

        opts
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct SignArguments {
    request: UnvalidatedContractSignRequest,
}

/// What is recieved when sign is called
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct UnvalidatedContractSignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

/// A validated version of the sign request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContractSignRequest {
    pub payload: Scalar,
    pub path: String,
    pub key_version: u32,
}

#[derive(Clone)]
pub struct Indexer {
    app_data_storage: AppDataStorage,
    last_updated_timestamp: Arc<RwLock<Instant>>,
    latest_block_timestamp_nanosec: Arc<RwLock<Option<u64>>>,
    running_threshold: Duration,
    behind_threshold: Duration,
}

impl Indexer {
    fn new(app_data_storage: AppDataStorage, options: &Options) -> Self {
        Self {
            app_data_storage: app_data_storage.clone(),
            last_updated_timestamp: Arc::new(RwLock::new(Instant::now())),
            latest_block_timestamp_nanosec: Arc::new(RwLock::new(None)),
            running_threshold: Duration::from_secs(options.running_threshold),
            behind_threshold: Duration::from_secs(options.behind_threshold),
        }
    }

    pub async fn last_processed_block(&self) -> Option<BlockHeight> {
        match self.app_data_storage.last_processed_block().await {
            Ok(Some(block_height)) => Some(block_height),
            Ok(None) => {
                tracing::warn!("no last processed block found");
                None
            }
            Err(err) => {
                tracing::warn!(%err, "failed to get last processed block");
                None
            }
        }
    }

    pub async fn set_last_processed_block(&self, block_height: BlockHeight) {
        if let Err(err) = self
            .app_data_storage
            .set_last_processed_block(block_height)
            .await
        {
            tracing::error!(%err, "failed to set last processed block");
        }
    }

    /// Check whether the indexer is on track with the latest block height from the chain.
    pub async fn is_running(&self) -> bool {
        self.last_updated_timestamp.read().await.elapsed() <= self.running_threshold
    }

    /// Check whether the indexer is behind with the latest block height from the chain.
    pub async fn is_behind(&self) -> bool {
        if let Some(latest_block_timestamp_nanosec) =
            *self.latest_block_timestamp_nanosec.read().await
        {
            crate::util::is_elapsed_longer_than_timeout(
                latest_block_timestamp_nanosec / 1_000_000_000,
                self.behind_threshold.as_millis() as u64,
            )
        } else {
            true
        }
    }

    pub async fn is_stable(&self) -> bool {
        !self.is_behind().await && self.is_running().await
    }

    async fn update_block_height_and_timestamp(
        &self,
        block_height: BlockHeight,
        block_timestamp_nanosec: u64,
    ) {
        tracing::debug!(block_height, "update_block_height_and_timestamp");
        self.set_last_processed_block(block_height).await;
        *self.last_updated_timestamp.write().await = Instant::now();
        *self.latest_block_timestamp_nanosec.write().await = Some(block_timestamp_nanosec);
    }
}

#[derive(Clone, LakeContext)]
struct Context {
    mpc_contract_id: AccountId,
    node_account_id: AccountId,
    queue: Arc<RwLock<SignQueue>>,
    indexer: Indexer,
}

async fn handle_block(
    mut block: near_lake_primitives::block::Block,
    ctx: &Context,
) -> anyhow::Result<()> {
    tracing::debug!(block_height = block.block_height(), "handle_block");
    let mut pending_requests = Vec::new();
    for action in block.actions().cloned().collect::<Vec<_>>() {
        if action.receiver_id() == ctx.mpc_contract_id {
            tracing::debug!("got action targeting {}", ctx.mpc_contract_id);
            let Some(receipt) = block.receipt_by_id(&action.receipt_id()) else {
                let err = format!(
                    "indexer unable to find block for receipt_id={}",
                    action.receipt_id()
                );
                tracing::warn!("{err}");
                anyhow::bail!(err);
            };
            let ExecutionStatus::SuccessReceiptId(receipt_id) = receipt.status() else {
                continue;
            };
            let Some(function_call) = action.as_function_call() else {
                continue;
            };
            if function_call.method_name() == "sign" {
                tracing::debug!("found `sign` function call");
                let arguments =
                    match serde_json::from_slice::<'_, SignArguments>(function_call.args()) {
                        Ok(arguments) => arguments,
                        Err(err) => {
                            tracing::warn!(%err, "failed to parse `sign` arguments");
                            continue;
                        }
                    };

                if receipt.logs().is_empty() {
                    tracing::warn!("`sign` did not produce entropy");
                    continue;
                }

                let Some(payload) = Scalar::from_bytes(arguments.request.payload) else {
                    tracing::warn!(
                        "`sign` did not produce payload correctly: {:?}",
                        arguments.request.payload,
                    );
                    continue;
                };

                let entropy_log_index = 1;
                let Ok(entropy) =
                    serde_json::from_str::<'_, [u8; 32]>(&receipt.logs()[entropy_log_index])
                else {
                    tracing::warn!(
                        "`sign` did not produce entropy correctly: {:?}",
                        receipt.logs()[entropy_log_index]
                    );
                    continue;
                };
                let epsilon = derive_epsilon(&action.predecessor_id(), &arguments.request.path);
                tracing::info!(
                    receipt_id = %receipt_id,
                    caller_id = receipt.predecessor_id().to_string(),
                    our_account = ctx.node_account_id.to_string(),
                    payload = hex::encode(arguments.request.payload),
                    key_version = arguments.request.key_version,
                    entropy = hex::encode(entropy),
                    "indexed new `sign` function call"
                );
                let request = ContractSignRequest {
                    payload,
                    path: arguments.request.path,
                    key_version: arguments.request.key_version,
                };
                pending_requests.push(SignRequest {
                    request_id: receipt_id.0,
                    request,
                    epsilon,
                    entropy,
                    // TODO: use indexer timestamp instead.
                    time_added: Instant::now(),
                });
            }
        }
    }

    ctx.indexer
        .update_block_height_and_timestamp(block.block_height(), block.header().timestamp_nanosec())
        .await;

    crate::metrics::LATEST_BLOCK_HEIGHT
        .with_label_values(&[ctx.node_account_id.as_str()])
        .set(block.block_height() as i64);

    // Add the requests after going through the whole block to avoid partial processing if indexer fails somewhere.
    // This way we can revisit the same block if we failed while not having added the requests partially.
    let mut queue = ctx.queue.write().await;
    for request in pending_requests {
        queue.add(request);
        crate::metrics::NUM_SIGN_REQUESTS
            .with_label_values(&[ctx.node_account_id.as_str()])
            .inc();
    }
    drop(queue);

    let log_indexing_interval = 1000;
    if block.block_height() % log_indexing_interval == 0 {
        tracing::info!(
            "indexed another {} blocks, latest: {}",
            log_indexing_interval,
            block.block_height()
        );
    }

    Ok(())
}

pub fn run(
    options: &Options,
    mpc_contract_id: &AccountId,
    node_account_id: &AccountId,
    queue: &Arc<RwLock<SignQueue>>,
    app_data_storage: AppDataStorage,
    rpc_client: near_fetch::Client,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, Indexer)> {
    tracing::info!(
        s3_bucket = options.s3_bucket,
        s3_region = options.s3_region,
        s3_url = options.s3_url,
        %mpc_contract_id,
        "starting indexer"
    );

    let indexer = Indexer::new(app_data_storage.clone(), options);
    let context = Context {
        mpc_contract_id: mpc_contract_id.clone(),
        node_account_id: node_account_id.clone(),
        queue: queue.clone(),
        indexer: indexer.clone(),
    };

    let options = options.clone();
    let join_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        // If indexer fails for whatever reason, let's spin it back up:
        let mut i = 0;
        loop {
            if i > 0 {
                tracing::warn!("restarting indexer after failure: restart count={i}");
            }
            i += 1;

            let Ok(lake) = rt.block_on(async {
                update_last_processed_block(rpc_client.clone(), app_data_storage.clone()).await?;

                if let Some(latest) = context.indexer.last_processed_block().await {
                    if i > 0 {
                        tracing::warn!("indexer latest height {latest}, restart count={i}");
                    }
                    let mut lake_builder = LakeBuilder::default()
                        .s3_bucket_name(&options.s3_bucket)
                        .s3_region_name(&options.s3_region)
                        .start_block_height(latest);

                    if let Some(s3_url) = &options.s3_url {
                        let aws_config = aws_config::from_env().load().await;
                        let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
                            .endpoint_url(s3_url)
                            .build();
                        lake_builder = lake_builder.s3_config(s3_config);
                    }
                    let lake = lake_builder.build()?;
                    anyhow::Ok(lake)
                } else {
                    tracing::warn!("indexer failed to get last processed block");
                    Err(anyhow::anyhow!("failed to get last processed block"))
                }
            }) else {
                tracing::error!(?options, "indexer failed to build");
                backoff(i, 1, 120);
                continue;
            };

            // TODO/NOTE: currently indexer does not have any interrupt handlers and will never yield back
            // as successful. We can add interrupt handlers in the future but this is not important right
            // now since we managing nodes through integration tests that can kill it or through docker.
            let join_handle = {
                let context = context.clone();
                rt.spawn(async move { lake.run_with_context_async(handle_block, &context).await })
            };
            let outcome = rt.block_on(async {
                if i > 0 {
                    // give it some time to catch up
                    tracing::debug!("giving indexer some time to catch up");
                    backoff(i, 10, 300);
                }
                // while running, we will keep the task spinning, and check every so often if
                // the indexer has errored out.
                while context.indexer.is_running().await {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    if join_handle.is_finished() {
                        break;
                    }
                }

                // Abort the indexer task if it's still running.
                if !join_handle.is_finished() {
                    tracing::debug!("aborting indexer task");
                    join_handle.abort();
                }

                join_handle.await
            });

            match outcome {
                Ok(Ok(())) => {
                    tracing::warn!("indexer finished successfully? -- this should not happen");
                    break;
                }
                Ok(Err(err)) => {
                    tracing::warn!(%err, "indexer failed");
                }
                Err(err) => {
                    tracing::warn!(%err, "indexer join handle failed");
                }
            }

            backoff(i, 1, 120)
        }
        Ok(())
    });

    Ok((join_handle, indexer))
}

/// This function ensures we do not go back in time a lot when restarting the node
async fn update_last_processed_block(
    rpc_client: near_fetch::Client,
    app_data_storage: AppDataStorage,
) -> anyhow::Result<()> {
    let last_processed_block = match app_data_storage.last_processed_block().await {
        Ok(Some(block_height)) => block_height,
        Ok(None) => 0,
        Err(err) => {
            tracing::warn!(%err, "failed to get last processed block");
            return Err(err);
        }
    };

    let latest_block: u64 = rpc_client.view_block().await?.header.height;

    if last_processed_block > latest_block {
        let error_message = format!(
            "last processed block is greater than latest block: last_processed_block={}, latest_block={}",
            last_processed_block, latest_block
        );
        tracing::error!("{}", error_message);
        Err(anyhow::anyhow!(error_message))?;
    }

    const MAX_YIELD_RESUME_BLOCKS: u64 = 200;
    let starting_block: u64 = {
        if latest_block - last_processed_block < MAX_YIELD_RESUME_BLOCKS {
            last_processed_block
        } else {
            latest_block.saturating_sub(MAX_YIELD_RESUME_BLOCKS)
        }
    };
    app_data_storage
        .set_last_processed_block(starting_block)
        .await?;

    tracing::info!(
        "set last processed block to {} to start indexer with, previous last processed: {}, latest block: {}",
        starting_block,
        last_processed_block,
        latest_block,
    );
    Ok(())
}

fn backoff(i: u32, multiplier: u32, max: u64) {
    // Exponential backoff with max delay of max seconds
    let delay: u64 = std::cmp::min(2u64.pow(i).mul(multiplier as u64), max);
    std::thread::sleep(std::time::Duration::from_secs(delay));
}
