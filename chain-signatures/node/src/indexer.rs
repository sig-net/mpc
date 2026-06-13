use crate::backlog::Backlog;

use crate::protocol::{Chain, Sign};

use mpc_contract::primitives::PendingRequest;
use mpc_primitives::{IndexedSignRequest, SignArgs, SignId};
use near_account_id::AccountId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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

pub struct NearIndexer {
    last_updated_timestamp: Instant,
    running_threshold: Duration,
    processed_requests: HashMap<SignId, Instant>,
}

impl NearIndexer {
    fn new(options: &Options) -> Self {
        Self {
            last_updated_timestamp: Instant::now(),
            running_threshold: Duration::from_secs(options.running_threshold),
            processed_requests: HashMap::new(),
        }
    }

    /// Check whether the indexer is on track with polling.
    pub fn is_running(&self) -> bool {
        self.last_updated_timestamp.elapsed() <= self.running_threshold
    }

    fn update_timestamp(&mut self) {
        self.last_updated_timestamp = Instant::now();
    }

    fn seen_request(&self, sign_id: &SignId) -> bool {
        self.processed_requests.contains_key(sign_id)
    }

    fn mark_request_seen(&mut self, sign_id: SignId) {
        self.processed_requests.insert(sign_id, Instant::now());
    }

    async fn cleanup_old_requests(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(3600); // Keep for 1 hour
        self.processed_requests
            .retain(|_, timestamp| *timestamp > cutoff);
    }

    fn completed_requests(&mut self, currently_pending: &HashSet<SignId>) -> Vec<SignId> {
        let mut completed = Vec::new();

        self.processed_requests.retain(|sign_id, _| {
            if currently_pending.contains(sign_id) {
                true
            } else {
                completed.push(*sign_id);
                false
            }
        });

        completed
    }

    /// Fetch pending requests from the smart contract
    async fn fetch_pending_requests(
        &self,
        rpc_client: &near_fetch::Client,
        contract_id: &AccountId,
    ) -> anyhow::Result<Vec<(SignId, PendingRequest)>> {
        let response = rpc_client
            .view(contract_id, "pending_requests_data")
            .await?;

        Ok(response.json()?)
    }

    /// Convert contract pending request to indexed sign request
    fn convert_to_indexed_request(
        &self,
        sign_id: SignId,
        pending_request: PendingRequest,
    ) -> IndexedSignRequest {
        let payload = pending_request.payload;
        let epsilon = pending_request.epsilon;

        // no longer taking entropy from logs, but this is merely for integration tests, so
        // it doesn't matter as much as long as the IT nodes agree on the entropy.
        let entropy = self.derive_entropy_from_sign_id(&sign_id);
        // NOTE: path is not used at all currently in signature.rs during signing, so hardcoding
        // it here won't matter.
        let path = "integration-tests".to_string();
        let key_version = 0u32;

        IndexedSignRequest::sign(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path,
                key_version,
            },
            Chain::NEAR,
            crate::util::current_unix_timestamp(),
        )
    }

    /// Derive entropy deterministically from sign_id
    fn derive_entropy_from_sign_id(&self, sign_id: &SignId) -> [u8; 32] {
        use k256::sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", sign_id).as_bytes());
        hasher.finalize().into()
    }
}

struct Context {
    mpc_contract_id: AccountId,
    sign_tx: mpsc::Sender<Sign>,
    indexer: NearIndexer,
    rpc_client: near_fetch::Client,
    backlog: Backlog,
}

async fn poll_pending_requests(ctx: &mut Context) -> anyhow::Result<()> {
    let latest_block = ctx.rpc_client.view_block().await?;
    let latest_height = latest_block.header.height;

    // Fetch pending requests from the contract
    let pending_requests = ctx
        .indexer
        .fetch_pending_requests(&ctx.rpc_client, &ctx.mpc_contract_id)
        .await?;

    let mut new_requests = Vec::new();
    let mut current_pending = HashSet::new();

    for (sign_id, pending_request) in pending_requests.into_iter() {
        current_pending.insert(sign_id);

        if ctx.indexer.seen_request(&sign_id) {
            continue;
        }

        let indexed_request = ctx
            .indexer
            .convert_to_indexed_request(sign_id, pending_request);

        tracing::info!(
            sign_id = ?indexed_request.id,
            payload = hex::encode(indexed_request.args.payload.to_bytes()),
            entropy = hex::encode(indexed_request.args.entropy),
            epsilon = hex::encode(indexed_request.args.epsilon.to_bytes()),
            "found new sign request"
        );

        new_requests.push(indexed_request);
        ctx.indexer.mark_request_seen(sign_id);
    }

    let completed_requests = ctx.indexer.completed_requests(&current_pending);

    // Update timestamp to indicate we're still running
    ctx.indexer.update_timestamp();

    // Update metrics
    crate::metrics::indexers::LATEST_BLOCK_NUMBER
        .with_label_values(&[Chain::NEAR.as_str(), "indexed"])
        .set(latest_height as i64);

    // Send all new requests
    for request in new_requests {
        tracing::info!(
            sign_id = ?request.id,
            "sending new sign request to processing queue"
        );
        if let Err(err) = ctx.sign_tx.send(Sign::Request(request)).await {
            tracing::error!(?err, "failed to send the sign request into sign queue");
        }
    }

    for sign_id in completed_requests {
        tracing::info!(?sign_id, "detected completed NEAR sign request");
        if let Err(err) = ctx.sign_tx.send(Sign::Completion(sign_id)).await {
            tracing::error!(
                ?err,
                ?sign_id,
                "failed to send completion event into sign queue"
            );
        }
    }

    ctx.backlog
        .set_processed_block(Chain::NEAR, latest_height)
        .await;

    // Cleanup old processed requests periodically
    ctx.indexer.cleanup_old_requests().await;

    Ok(())
}

pub fn run(
    options: &Options,
    mpc_contract_id: &AccountId,
    node_account_id: &AccountId,
    sign_tx: mpsc::Sender<Sign>,
    rpc_client: near_fetch::Client,
    backlog: Backlog,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    tracing::info!(
        %mpc_contract_id,
        %node_account_id,
        "starting contract polling indexer"
    );

    let indexer = NearIndexer::new(options);
    let mut context = Context {
        mpc_contract_id: mpc_contract_id.clone(),
        sign_tx,
        indexer,
        rpc_client,
        backlog,
    };

    Ok(tokio::spawn(async move {
        tracing::info!("starting polling loop for pending requests");

        let mut interval = tokio::time::interval(Duration::from_millis(750));
        loop {
            interval.tick().await;
            if let Err(err) = poll_pending_requests(&mut context).await {
                tracing::error!(%err, "failed to poll pending requests");
            }
        }
    }))
}
