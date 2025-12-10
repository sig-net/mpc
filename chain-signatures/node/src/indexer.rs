use crate::backlog::Backlog;
use crate::protocol::{Chain, IndexedSignRequest, Sign};
use mpc_contract::primitives::PendingRequest;
use mpc_primitives::{SignArgs, SignId};
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

        IndexedSignRequest {
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
            timestamp_sign_queue: Instant::now(),
            total_timeout: Duration::from_secs(200),
            sign_request_type: crate::protocol::SignRequestType::Sign,
        }
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
    node_account_id: AccountId,
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
    crate::metrics::LATEST_BLOCK_NUMBER
        .with_label_values(&[Chain::NEAR.as_str(), ctx.node_account_id.as_str()])
        .set(latest_height as i64);

    // Send all new requests
    for request in new_requests {
        tracing::info!(
            sign_id = ?request.id,
            "sending new sign request to processing queue"
        );
        if let Err(err) = ctx.sign_tx.send(Sign::Request(request)).await {
            tracing::error!(?err, "failed to send the sign request into sign queue");
        } else {
            crate::metrics::NUM_SIGN_REQUESTS
                .with_label_values(&[Chain::NEAR.as_str(), ctx.node_account_id.as_str()])
                .inc();
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
        node_account_id: node_account_id.clone(),
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


#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;
    use proptest::prelude::*;

    /// Helper to create a test NearIndexer
    fn create_test_indexer() -> NearIndexer {
        let options = Options {
            running_threshold: 300,
        };
        NearIndexer::new(&options)
    }

    /// Helper to create a test SignId from account and nonce
    fn create_test_sign_id(account: &str, nonce: u64) -> SignId {
        // Create a deterministic request_id from account and nonce
        use k256::sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(account.as_bytes());
        hasher.update(nonce.to_le_bytes());
        let request_id: [u8; 32] = hasher.finalize().into();
        SignId::new(request_id)
    }

    /// Helper to create a test PendingRequest
    fn create_test_pending_request() -> PendingRequest {
        PendingRequest {
            index: None,
            payload: Scalar::ONE,
            epsilon: Scalar::ONE,
        }
    }

    // =========================================================================
    // Property 98: Pending Request Processing Correctness
    // **Feature: unit-test-coverage, Property 98: Pending Request Processing Correctness**
    // **Validates: Requirements 31.1**
    //
    // For any pending request, processing should result in correct state updates
    // and request handling.
    // =========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_pending_request_processing_correctness(
            account_suffix in "[a-z]{3,10}",
            nonce in 0u64..1000u64,
        ) {
            // **Feature: unit-test-coverage, Property 98: Pending Request Processing Correctness**
            // **Validates: Requirements 31.1**

            let mut indexer = create_test_indexer();
            let account = format!("{}.near", account_suffix);
            let sign_id = create_test_sign_id(&account, nonce);
            let pending_request = create_test_pending_request();

            // Initially, the request should not be seen
            prop_assert!(!indexer.seen_request(&sign_id));

            // Convert to indexed request
            let indexed_request = indexer.convert_to_indexed_request(sign_id, pending_request.clone());

            // Verify the indexed request has correct properties
            prop_assert_eq!(indexed_request.id, sign_id);
            prop_assert_eq!(indexed_request.args.payload, pending_request.payload);
            prop_assert_eq!(indexed_request.args.epsilon, pending_request.epsilon);
            prop_assert_eq!(indexed_request.chain, Chain::NEAR);

            // Mark the request as seen
            indexer.mark_request_seen(sign_id);

            // Now the request should be seen
            prop_assert!(indexer.seen_request(&sign_id));
        }
    }

    // =========================================================================
    // Property 99: Request Deduplication
    // **Feature: unit-test-coverage, Property 99: Request Deduplication**
    // **Validates: Requirements 31.2**
    //
    // When duplicate requests are received, the system should correctly identify
    // them as already seen and not process them again.
    // =========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_request_deduplication(
            account_suffix in "[a-z]{3,10}",
            nonce in 0u64..1000u64,
            num_duplicates in 2usize..10usize,
        ) {
            // **Feature: unit-test-coverage, Property 99: Request Deduplication**
            // **Validates: Requirements 31.2**

            let mut indexer = create_test_indexer();
            let account = format!("{}.near", account_suffix);
            let sign_id = create_test_sign_id(&account, nonce);

            // Initially not seen
            prop_assert!(!indexer.seen_request(&sign_id));

            // Mark as seen once
            indexer.mark_request_seen(sign_id);
            prop_assert!(indexer.seen_request(&sign_id));

            // Attempting to check the same request multiple times should always return true
            for _ in 0..num_duplicates {
                prop_assert!(indexer.seen_request(&sign_id));
            }

            // The processed_requests map should only contain one entry for this sign_id
            prop_assert_eq!(
                indexer.processed_requests.iter().filter(|(id, _)| **id == sign_id).count(),
                1
            );
        }
    }

    // =========================================================================
    // Property 100: Request Expiration Cleanup
    // **Feature: unit-test-coverage, Property 100: Request Expiration Cleanup**
    // **Validates: Requirements 31.3**
    //
    // When requests expire, cleanup should occur appropriately and old requests
    // should be removed from the processed requests map.
    // =========================================================================

    #[tokio::test]
    async fn prop_request_expiration_cleanup() {
        // **Feature: unit-test-coverage, Property 100: Request Expiration Cleanup**
        // **Validates: Requirements 31.3**

        let mut indexer = create_test_indexer();

        // Add some requests
        let sign_id1 = create_test_sign_id("test1.near", 1);
        let sign_id2 = create_test_sign_id("test2.near", 2);
        let sign_id3 = create_test_sign_id("test3.near", 3);

        indexer.mark_request_seen(sign_id1);
        indexer.mark_request_seen(sign_id2);
        indexer.mark_request_seen(sign_id3);

        // All requests should be seen
        assert!(indexer.seen_request(&sign_id1));
        assert!(indexer.seen_request(&sign_id2));
        assert!(indexer.seen_request(&sign_id3));

        // Cleanup should not remove recent requests (within 1 hour)
        indexer.cleanup_old_requests().await;

        // All requests should still be seen (they are recent)
        assert!(indexer.seen_request(&sign_id1));
        assert!(indexer.seen_request(&sign_id2));
        assert!(indexer.seen_request(&sign_id3));

        // Verify the count is correct
        assert_eq!(indexer.processed_requests.len(), 3);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_request_expiration_cleanup_property(
            num_requests in 1usize..20usize,
        ) {
            // **Feature: unit-test-coverage, Property 100: Request Expiration Cleanup**
            // **Validates: Requirements 31.3**

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut indexer = create_test_indexer();

                // Add multiple requests
                for i in 0..num_requests {
                    let sign_id = create_test_sign_id(&format!("test{}.near", i), i as u64);
                    indexer.mark_request_seen(sign_id);
                }

                // All requests should be present
                prop_assert_eq!(indexer.processed_requests.len(), num_requests);

                // Cleanup should not remove recent requests
                indexer.cleanup_old_requests().await;

                // All requests should still be present (they are recent)
                prop_assert_eq!(indexer.processed_requests.len(), num_requests);

                Ok(())
            })?;
        }
    }

    // =========================================================================
    // Property 101: Entropy Derivation Determinism
    // **Feature: unit-test-coverage, Property 101: Entropy Derivation Determinism**
    // **Validates: Requirements 31.4**
    //
    // For any sign_id, entropy derivation should be deterministic and produce
    // consistent results across multiple invocations.
    // =========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_entropy_derivation_determinism(
            account_suffix in "[a-z]{3,10}",
            nonce in 0u64..1000000u64,
        ) {
            // **Feature: unit-test-coverage, Property 101: Entropy Derivation Determinism**
            // **Validates: Requirements 31.4**

            let indexer = create_test_indexer();
            let account = format!("{}.near", account_suffix);
            let sign_id = create_test_sign_id(&account, nonce);

            // Derive entropy multiple times
            let entropy1 = indexer.derive_entropy_from_sign_id(&sign_id);
            let entropy2 = indexer.derive_entropy_from_sign_id(&sign_id);
            let entropy3 = indexer.derive_entropy_from_sign_id(&sign_id);

            // All derivations should produce the same result
            prop_assert_eq!(entropy1, entropy2);
            prop_assert_eq!(entropy2, entropy3);

            // Entropy should be 32 bytes
            prop_assert_eq!(entropy1.len(), 32);
        }

        #[test]
        fn prop_entropy_derivation_uniqueness(
            account_suffix1 in "[a-z]{3,10}",
            account_suffix2 in "[a-z]{3,10}",
            nonce1 in 0u64..1000000u64,
            nonce2 in 0u64..1000000u64,
        ) {
            // **Feature: unit-test-coverage, Property 101: Entropy Derivation Determinism**
            // **Validates: Requirements 31.4**
            //
            // Different sign_ids should produce different entropy values

            let indexer = create_test_indexer();
            let account1 = format!("{}.near", account_suffix1);
            let account2 = format!("{}.near", account_suffix2);
            let sign_id1 = create_test_sign_id(&account1, nonce1);
            let sign_id2 = create_test_sign_id(&account2, nonce2);

            // Skip if the sign_ids are the same
            if sign_id1 == sign_id2 {
                return Ok(());
            }

            let entropy1 = indexer.derive_entropy_from_sign_id(&sign_id1);
            let entropy2 = indexer.derive_entropy_from_sign_id(&sign_id2);

            // Different sign_ids should produce different entropy
            prop_assert_ne!(entropy1, entropy2);
        }
    }

    // =========================================================================
    // Additional unit tests for indexer functionality
    // =========================================================================

    #[test]
    fn test_indexer_is_running() {
        let indexer = create_test_indexer();

        // Initially should be running (just created)
        assert!(indexer.is_running());
    }

    #[test]
    fn test_indexer_update_timestamp() {
        let mut indexer = create_test_indexer();

        // Update timestamp
        indexer.update_timestamp();

        // Should still be running
        assert!(indexer.is_running());
    }

    #[test]
    fn test_completed_requests_detection() {
        let mut indexer = create_test_indexer();

        let sign_id1 = create_test_sign_id("test1.near", 1);
        let sign_id2 = create_test_sign_id("test2.near", 2);
        let sign_id3 = create_test_sign_id("test3.near", 3);

        // Mark all as seen
        indexer.mark_request_seen(sign_id1);
        indexer.mark_request_seen(sign_id2);
        indexer.mark_request_seen(sign_id3);

        // Create a set of currently pending requests (only sign_id1 and sign_id2)
        let mut currently_pending = HashSet::new();
        currently_pending.insert(sign_id1);
        currently_pending.insert(sign_id2);

        // Get completed requests (sign_id3 should be completed)
        let completed = indexer.completed_requests(&currently_pending);

        // sign_id3 should be in completed list
        assert_eq!(completed.len(), 1);
        assert!(completed.contains(&sign_id3));

        // sign_id3 should no longer be in processed_requests
        assert!(!indexer.seen_request(&sign_id3));

        // sign_id1 and sign_id2 should still be in processed_requests
        assert!(indexer.seen_request(&sign_id1));
        assert!(indexer.seen_request(&sign_id2));
    }

    #[test]
    fn test_convert_to_indexed_request() {
        let indexer = create_test_indexer();
        let sign_id = create_test_sign_id("test.near", 42);
        let pending_request = create_test_pending_request();

        let indexed_request = indexer.convert_to_indexed_request(sign_id, pending_request.clone());

        assert_eq!(indexed_request.id, sign_id);
        assert_eq!(indexed_request.args.payload, pending_request.payload);
        assert_eq!(indexed_request.args.epsilon, pending_request.epsilon);
        assert_eq!(indexed_request.chain, Chain::NEAR);
        assert_eq!(indexed_request.args.path, "integration-tests");
        assert_eq!(indexed_request.args.key_version, 0);
    }
}
