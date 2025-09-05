use crate::protocol::Chain;
use crate::protocol::IndexedSignRequest;
use crate::storage::app_data_storage::AppDataStorage;
use k256::Scalar;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use near_primitives::types::BlockHeight;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

/// Configures indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_options")]
pub struct Options {
    /// The threshold in seconds to check if the indexer needs to be restarted due to it stalling.
    #[clap(long, env("MPC_INDEXER_RUNNING_THRESHOLD"), default_value = "300")]
    pub running_threshold: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--running-threshold".to_string(),
            self.running_threshold.to_string(),
        ]
    }
}

/// Contract PendingRequest structure that matches the smart contract
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContractPendingRequest {
    pub index: Option<ContractYieldIndex>,
    pub payload: [u8; 32], // Scalar serialized as bytes
    pub epsilon: [u8; 32], // Scalar serialized as bytes
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContractYieldIndex {
    pub data_id: [u8; 32],
}

/// What is received when extracting sign requests from pending_requests_data
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct ProcessedSignRequest {
    pub id: SignId,
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
    pub entropy: [u8; 32],
}

#[derive(Clone)]
pub struct NearIndexer {
    app_data_storage: AppDataStorage,
    last_updated_timestamp: Arc<RwLock<Instant>>,
    running_threshold: Duration,
    processed_requests: Arc<RwLock<HashMap<SignId, Instant>>>,
}

impl NearIndexer {
    fn new(app_data_storage: AppDataStorage, options: &Options) -> Self {
        Self {
            app_data_storage: app_data_storage.clone(),
            last_updated_timestamp: Arc::new(RwLock::new(Instant::now())),
            running_threshold: Duration::from_secs(options.running_threshold),
            processed_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check whether the indexer is on track with polling.
    pub async fn is_running(&self) -> bool {
        self.last_updated_timestamp.read().await.elapsed() <= self.running_threshold
    }

    async fn update_timestamp(&self) {
        *self.last_updated_timestamp.write().await = Instant::now();
    }

    async fn is_request_processed(&self, sign_id: &SignId) -> bool {
        self.processed_requests.read().await.contains_key(sign_id)
    }

    async fn mark_request_processed(&self, sign_id: SignId) {
        self.processed_requests.write().await.insert(sign_id, Instant::now());
    }

    async fn cleanup_old_processed_requests(&self) {
        let mut processed = self.processed_requests.write().await;
        let cutoff = Instant::now() - Duration::from_secs(3600); // Keep for 1 hour
        processed.retain(|_, timestamp| *timestamp > cutoff);
    }

    /// Fetch pending requests from the smart contract
    async fn fetch_pending_requests(
        &self,
        rpc_client: &near_fetch::Client,
        contract_id: &AccountId,
    ) -> anyhow::Result<BTreeMap<String, ContractPendingRequest>> {
        let response = rpc_client
            .view(contract_id, "pending_requests_data")
            .await?;
        
        let pending_requests: BTreeMap<String, ContractPendingRequest> = response.json()?;
        Ok(pending_requests)
    }

    /// Convert contract pending request to indexed sign request
    fn convert_to_indexed_request(
        &self,
        sign_id_str: &str, 
        pending_request: &ContractPendingRequest,
    ) -> anyhow::Result<IndexedSignRequest> {
        // Parse the sign_id from string format back to SignId
        let sign_id: SignId = serde_json::from_str(&format!("\"{}\"", sign_id_str))?;
        
        // Extract payload and epsilon as Scalars directly from the contract data
        let Some(payload) = Scalar::from_bytes(pending_request.payload) else {
            anyhow::bail!("Invalid payload in pending request: {:?}", pending_request.payload);
        };
        
        let Some(epsilon) = Scalar::from_bytes(pending_request.epsilon) else {
            anyhow::bail!("Invalid epsilon in pending request: {:?}", pending_request.epsilon);
        };

        // LIMITATION: We cannot extract the original path, key_version, and predecessor_id 
        // from the SignId hash or the contract's PendingRequest structure.
        // The contract only stores payload and epsilon, but the original transaction data
        // contained path, key_version, and predecessor_id which are now lost.
        // 
        // Possible solutions:
        // 1. Modify the contract to store additional fields in PendingRequest (requires contract change)
        // 2. Use default values (current approach)
        // 3. Maintain a separate mapping of SignId to original request details
        //
        // For now, we'll use placeholder values and log this limitation
        tracing::warn!(
            sign_id = ?sign_id,
            "Using default values for path and key_version due to contract data limitations. \
             Original transaction details are not available in pending_requests_data."
        );
        
        let path = "unknown".to_string();
        let key_version = 0u32;
        
        // Generate entropy deterministically from the sign_id since we can't get it from transaction logs
        let entropy = self.derive_entropy_from_sign_id(&sign_id);

        Ok(IndexedSignRequest {
            id: sign_id,
            args: SignArgs {
                entropy,
                epsilon,
                payload,
                path,
                key_version,
            },
            chain: Chain::NEAR,
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            timestamp_sign_queue: Some(Instant::now()),
            total_timeout: Duration::from_secs(200),
        })
    }

    /// Derive entropy deterministically from sign_id
    fn derive_entropy_from_sign_id(&self, sign_id: &SignId) -> [u8; 32] {
        use k256::sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", sign_id).as_bytes());
        hasher.finalize().into()
    }

    /// Compatibility method for web module
    pub async fn last_processed_block(&self) -> Option<BlockHeight> {
        // Since we're no longer tracking block heights in the polling approach,
        // we return a default value. The web module uses this for status reporting.
        Some(0)
    }
}

#[derive(Clone)]
struct Context {
    mpc_contract_id: AccountId,
    node_account_id: AccountId,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    indexer: NearIndexer,
    rpc_client: near_fetch::Client,
}

async fn poll_pending_requests(ctx: &Context) -> anyhow::Result<()> {
    tracing::debug!("polling pending requests from contract");
    
    // Fetch pending requests from the contract
    let pending_requests = ctx.indexer
        .fetch_pending_requests(&ctx.rpc_client, &ctx.mpc_contract_id)
        .await?;

    let mut new_requests = Vec::new();
    
    for (sign_id_str, pending_request) in pending_requests.iter() {
        // Parse sign_id to check if we've already processed this request
        let sign_id: SignId = match serde_json::from_str(&format!("\"{}\"", sign_id_str)) {
            Ok(id) => id,
            Err(err) => {
                tracing::warn!(%err, sign_id_str = %sign_id_str, "failed to parse sign_id");
                continue;
            }
        };

        // Skip if we've already processed this request
        if ctx.indexer.is_request_processed(&sign_id).await {
            continue;
        }

        // Convert to IndexedSignRequest
        match ctx.indexer.convert_to_indexed_request(sign_id_str, pending_request) {
            Ok(indexed_request) => {
                tracing::info!(
                    sign_id = ?indexed_request.id,
                    payload = hex::encode(indexed_request.args.payload.to_bytes()),
                    entropy = hex::encode(indexed_request.args.entropy),
                    epsilon = hex::encode(indexed_request.args.epsilon.to_bytes()),
                    "found new sign request"
                );
                new_requests.push(indexed_request);
                ctx.indexer.mark_request_processed(sign_id).await;
            }
            Err(err) => {
                tracing::warn!(%err, sign_id_str = %sign_id_str, "failed to convert pending request");
                continue;
            }
        }
    }

    // Update timestamp to indicate we're still running
    ctx.indexer.update_timestamp().await;

    // Update metrics
    crate::metrics::LATEST_BLOCK_NUMBER
        .with_label_values(&[Chain::NEAR.as_str(), ctx.node_account_id.as_str()])
        .set(crate::util::current_unix_timestamp() as i64);

    // Send all new requests
    for request in new_requests {
        tracing::info!(
            sign_id = ?request.id,
            "sending new sign request to processing queue"
        );
        if let Err(err) = ctx.sign_tx.send(request).await {
            tracing::error!(?err, "failed to send the sign request into sign queue");
        } else {
            crate::metrics::NUM_SIGN_REQUESTS
                .with_label_values(&[Chain::NEAR.as_str(), ctx.node_account_id.as_str()])
                .inc();
        }
    }

    // Cleanup old processed requests periodically
    ctx.indexer.cleanup_old_processed_requests().await;

    Ok(())
}

pub fn run(
    options: &Options,
    mpc_contract_id: &AccountId,
    node_account_id: &AccountId,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    app_data_storage: AppDataStorage,
    rpc_client: near_fetch::Client,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, NearIndexer)> {
    tracing::info!(
        %mpc_contract_id,
        %node_account_id,
        "starting contract polling indexer"
    );

    let indexer = NearIndexer::new(app_data_storage.clone(), options);
    let context = Context {
        mpc_contract_id: mpc_contract_id.clone(),
        node_account_id: node_account_id.clone(),
        sign_tx,
        indexer: indexer.clone(),
        rpc_client,
    };

    let _options = options.clone();
    let join_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let mut start = Instant::now();
        // If indexer fails for whatever reason, let's spin it back up:
        let mut i = 0;
        loop {
            if i > 0 {
                tracing::warn!(
                    restart_count = i,
                    elapsed = ?start.elapsed(),
                    "restarting indexer after failure",
                );
                start = Instant::now();
            }
            i += 1;

            let join_handle = rt.spawn({
                let context = context.clone();
                async move { run_polling_loop(&context).await }
            });

            let outcome = rt.block_on(async {
                if i > 0 {
                    // give it some time to settle
                    tracing::debug!("giving indexer some time to settle");
                    backoff(i, 10, 60).await;
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

            backoff_thread(i, 1, 120);
        }
        Ok(())
    });

    Ok((join_handle, indexer))
}

async fn run_polling_loop(context: &Context) -> anyhow::Result<()> {
    tracing::info!("starting polling loop for pending requests");
    
    loop {
        match poll_pending_requests(context).await {
            Ok(()) => {
                tracing::debug!("successfully polled pending requests");
            }
            Err(err) => {
                tracing::error!(%err, "failed to poll pending requests");
                // Continue polling even if one iteration fails
            }
        }

        // Poll every 3 seconds as requested
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn backoff(i: u32, multiplier: u32, max: u64) {
    // Exponential backoff with max delay of max seconds
    let delay: u64 = std::cmp::min(2u64.pow(i).saturating_mul(multiplier as u64), max);
    tokio::time::sleep(Duration::from_secs(delay)).await;
}

fn backoff_thread(i: u32, multiplier: u32, max: u64) {
    // Exponential backoff with max delay of max seconds
    let delay: u64 = std::cmp::min(2u64.pow(i).saturating_mul(multiplier as u64), max);
    std::thread::sleep(Duration::from_secs(delay));
}
