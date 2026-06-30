mod canton;
mod ethereum;
mod hydration;
mod near;
#[cfg(test)]
mod test_utils;

use crate::config::Config;
use crate::metrics::requests::{record_request_latency_since, SignRequestStep};
use crate::protocol::contract::primitives::{ParticipantMap, Participants};
use crate::protocol::contract::RunningContractState;
use crate::protocol::{Chain, IndexedSignRequest, ProtocolState};
use crate::util::retry::{retry_rpc, RetryConfig};
use enum_map::EnumMap;
use std::collections::BTreeSet;
use std::sync::Arc;

// TODO: move clients elsewhere
pub use canton::CantonClient;
pub use ethereum::EthClient;
pub use hydration::HydrationClient;

use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
pub use mpc_contract::primitives::{Read, View};
use mpc_primitives::{CheckpointDigest, Signature};
pub use near::NearClient;

use near_account_id::AccountId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// The maximum number of concurrent RPC requests the system can make
const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
/// The update interval to fetch and update the contract's state
const UPDATE_INTERVAL: Duration = Duration::from_secs(10);

// Publish retry constants
const PUBLISH_MIN_DELAY: Duration = Duration::from_secs(5);
const PUBLISH_MAX_DELAY: Duration = Duration::from_secs(60); // Cap to 1 min so backoff doesn't get too long for infinite retries
const BATCH_PUBLISH_MIN_DELAY: Duration = Duration::from_secs(1);
const BATCH_PUBLISH_MAX_DELAY: Duration = Duration::from_secs(10);

/// Trait for publishing signatures to different blockchains (single attempt, caller handles retries).
#[async_trait::async_trait]
pub trait ChainPublisher: Send + Sync + 'static {
    /// Accepts a publish action. The publisher encapsulates how this is executed
    /// (e.g., immediate spawn, or pushing to an internal batching queue).
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()>;
}

#[derive(Clone)]
pub struct PublishAction {
    pub public_key: mpc_crypto::PublicKey,
    pub indexed: IndexedSignRequest,
    pub signature: Signature,
    pub participants: Vec<Participant>,
    pub timestamp: Instant,
}

impl PublishAction {
    pub fn new(
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) -> Option<Self> {
        let expected_public_key = mpc_crypto::derive_key(public_key, indexed.args.epsilon);
        let signature = crate::kdf::into_signature(
            &expected_public_key,
            &output.big_r,
            &output.s,
            indexed.args.payload,
        )
        .ok()?;
        Some(Self {
            public_key,
            indexed,
            signature,
            participants,
            timestamp: Instant::now(),
        })
    }
}

pub enum RpcAction {
    Publish(PublishAction),
}

#[derive(Debug, Clone)]
pub struct GovernanceInfo {
    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub public_key: mpc_crypto::PublicKey,
    pub participants: BTreeSet<Participant>,
    pub is_running: bool,
}

#[derive(Clone)]
pub struct RpcChannel {
    pub tx: mpsc::Sender<RpcAction>,
}

impl RpcChannel {
    pub fn publish(
        &self,
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) {
        let sign_id = indexed.id;
        let Some(action) = PublishAction::new(public_key, indexed, output, participants) else {
            tracing::error!(
                ?sign_id,
                "failed to validate signature; trashing publish request",
            );
            return;
        };
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc.tx.send(RpcAction::Publish(action)).await {
                tracing::error!(%err, "failed to send publish action");
            }
        });
    }

    pub fn publish_signature(
        &self,
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        signature: Signature,
        participants: Vec<Participant>,
    ) {
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc
                .tx
                .send(RpcAction::Publish(PublishAction {
                    public_key,
                    indexed,
                    signature,
                    participants,
                    timestamp: Instant::now(),
                }))
                .await
            {
                tracing::error!(%err, "failed to send publish action");
            }
        });
    }
}

#[derive(Clone)]
pub struct ContractStateWatcher {
    account_id: AccountId,
    contract_state: watch::Receiver<Option<ProtocolState>>,
}

impl ContractStateWatcher {
    pub fn new(id: &AccountId) -> (Self, watch::Sender<Option<ProtocolState>>) {
        let (tx, rx) = watch::channel(None);
        (
            Self {
                account_id: id.clone(),
                contract_state: rx,
            },
            tx,
        )
    }

    pub fn with(
        id: &AccountId,
        state: ProtocolState,
    ) -> (Self, watch::Sender<Option<ProtocolState>>) {
        // Set the initial state to be None so that `changed()` will pick up the first state change.
        let (tx, rx) = watch::channel(None);
        let _ = tx.send(Some(state));
        (
            Self {
                account_id: id.clone(),
                contract_state: rx,
            },
            tx,
        )
    }

    pub fn with_running(
        node_id: &AccountId,
        public_key: AffinePoint,
        threshold: usize,
        participants: Participants,
    ) -> (Self, watch::Sender<Option<ProtocolState>>) {
        Self::with(
            node_id,
            ProtocolState::Running(RunningContractState {
                epoch: 0,
                public_key,
                participants,
                candidates: Default::default(),
                join_votes: Default::default(),
                leave_votes: Default::default(),
                threshold,
            }),
        )
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn borrow_state(&self) -> watch::Ref<'_, Option<ProtocolState>> {
        self.contract_state.borrow()
    }

    pub fn state(&self) -> Option<ProtocolState> {
        self.borrow_state().clone()
    }

    pub fn governance(&self) -> Option<GovernanceInfo> {
        self.state()?.governance(&self.account_id)
    }

    pub async fn wait_governance(&mut self) -> GovernanceInfo {
        loop {
            if let Some(governance) = self.governance() {
                return governance;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn next_state(&mut self) -> Option<ProtocolState> {
        let _ = self.contract_state.changed().await;
        self.contract_state.borrow_and_update().clone()
    }

    pub fn mark_changed(&mut self) {
        self.contract_state.mark_changed();
    }

    pub fn participants(&self) -> Option<Participants> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(state) => Some(state.candidates.clone().into()),
            ProtocolState::Running(state) => Some(state.participants.clone()),
            ProtocolState::Resharing(state) => Some(state.new_participants.clone()),
        }
    }

    pub async fn me(&self) -> Option<Participant> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => state
                .participants
                .find_participant(&self.account_id)
                .copied(),
            ProtocolState::Resharing(state) => state
                .new_participants
                .find_participant(&self.account_id)
                .copied(),
        }
    }

    pub async fn threshold(&self) -> Option<usize> {
        match self.state()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some(state.threshold),
            ProtocolState::Resharing(state) => Some(state.threshold),
        }
    }

    /// Wait until the MPC threshold is available and return it
    pub async fn wait_threshold(&mut self) -> usize {
        loop {
            if let Some(threshold) = self.threshold().await {
                return threshold;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn public_key(&self) -> Option<AffinePoint> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some(state.public_key),
            ProtocolState::Resharing(_) => None,
        }
    }

    /// Wait until the public key is available and return it
    pub async fn wait_public_key(&mut self) -> AffinePoint {
        loop {
            if let Some(pk) = self.public_key().await {
                return pk;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn info(&self) -> Option<(usize, Participant)> {
        match self.state()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some((
                state.threshold,
                *state.participants.find_participant(&self.account_id)?,
            )),
            ProtocolState::Resharing(state) => Some((
                state.threshold,
                *state.new_participants.find_participant(&self.account_id)?,
            )),
        }
    }

    pub async fn wait_info(&mut self) -> (usize, Participant) {
        loop {
            if let Some((threshold, participant)) = self.info().await {
                return (threshold, participant);
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn participant_map(&self) -> ParticipantMap {
        let Some(state) = self.state().clone() else {
            return ParticipantMap::Zero;
        };

        match state {
            ProtocolState::Initializing(state) => {
                ParticipantMap::One(state.candidates.clone().into())
            }
            ProtocolState::Running(state) => ParticipantMap::One(state.participants.clone()),
            ProtocolState::Resharing(state) => ParticipantMap::Two(
                state.new_participants.clone(),
                state.old_participants.clone(),
            ),
        }
    }

    /// Waits till the contract is in the running state.
    pub async fn wait_running(&mut self) -> RunningContractState {
        loop {
            if let Some(ProtocolState::Running(state)) = self.borrow_state().as_ref() {
                return state.clone();
            }
            let _ = self.contract_state.changed().await;
        }
    }

    /// Create a list of contract states that share a single channel but use different account ids.
    #[cfg(feature = "test-feature")]
    pub fn test_batch(
        ids: &[AccountId],
        state: ProtocolState,
    ) -> (Vec<Self>, watch::Sender<Option<ProtocolState>>) {
        let (tx, rx) = watch::channel(Some(state));
        let selfs = ids
            .iter()
            .map(|id| Self {
                account_id: id.clone(),
                contract_state: rx.clone(),
            })
            .collect();
        (selfs, tx)
    }
}

pub struct RpcExecutor {
    /// The NEAR client used to fetch contract state and config.
    near: NearClient,
    /// The publishers for each chain.
    publishers: HashMap<Chain, Arc<dyn ChainPublisher>>,
    /// The receiver for incoming RPC actions.
    action_rx: mpsc::Receiver<RpcAction>,
}

impl RpcExecutor {
    pub async fn new(
        near: NearClient,
        publishers: HashMap<Chain, Arc<dyn ChainPublisher>>,
    ) -> (RpcChannel, Self) {
        let (tx, action_rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        (
            RpcChannel { tx },
            Self {
                near,
                publishers,
                action_rx,
            },
        )
    }

    pub async fn run(
        mut self,
        contract: watch::Sender<Option<ProtocolState>>,
        config: watch::Sender<Config>,
        checkpoints: EnumMap<Chain, watch::Sender<CheckpointDigest>>,
    ) {
        // Spin up update task for updating contract state, config and checkpoints
        let near = self.near.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPDATE_INTERVAL);
            loop {
                interval.tick().await;
                tokio::spawn(update_contract_data(
                    near.clone(),
                    contract.clone(),
                    config.clone(),
                    checkpoints.clone(),
                ));
            }
        });

        Self::dispatch_loop(&self.publishers, &mut self.action_rx).await;
    }

    /// Dispatches incoming RPC actions to the appropriate chain publishers.
    async fn dispatch_loop(
        publishers: &HashMap<Chain, Arc<dyn ChainPublisher>>,
        action_rx: &mut mpsc::Receiver<RpcAction>,
    ) {
        loop {
            let Some(RpcAction::Publish(action)) = action_rx.recv().await else {
                tracing::error!("rpc channel closed unexpectedly");
                return;
            };

            let chain = action.indexed.chain;

            // Check if a publisher is configured for the chain. If not, log a warning and continue to the next action.
            let Some(publisher) = publishers.get(&chain) else {
                tracing::warn!(?chain, "no publisher configured for chain");
                continue;
            };

            // Spawn a task to execute the publish action.
            let publisher = publisher.clone();
            tokio::spawn(async move {
                execute_publish(publisher, action).await;
            });
        }
    }
}

async fn update_contract_data(
    near: NearClient,
    contract: watch::Sender<Option<ProtocolState>>,
    config: watch::Sender<Config>,
    checkpoints: EnumMap<Chain, watch::Sender<CheckpointDigest>>,
) {
    let reads = vec![Read::State, Read::Config, Read::Checkpoints];
    let views = match near.read(reads).await {
        Ok(views) => views,
        Err(error) => {
            tracing::error!(?error, "could not fetch contract data via read");
            return;
        }
    };

    let mut state_view = None;
    let mut config_view = None;
    let mut checkpoints_view = None;

    for view in views {
        match view {
            View::State(s) => state_view = Some(s),
            View::Config(c) => config_view = Some(c),
            View::Checkpoints(cp) => checkpoints_view = Some(cp),
        }
    }

    if let Some(state) = state_view {
        if let Ok(protocol_state) = ProtocolState::try_from(state) {
            contract.send_if_modified(|old_state| {
                if let Some(old_state) = old_state {
                    if *old_state == protocol_state {
                        return false;
                    }
                }
                *old_state = Some(protocol_state);
                true
            });
        }
    }

    if let Some(contract_config) = config_view {
        if let Ok(config_val) = serde_json::to_value(contract_config) {
            if let Ok(node_config) =
                serde_json::from_value::<crate::config::ContractConfig>(config_val)
            {
                config.send_if_modified(|c| c.update(node_config));
            }
        }
    }

    if let Some(signed_checkpoints) = checkpoints_view {
        for (chain, sc) in signed_checkpoints {
            let new_digest = CheckpointDigest {
                height: sc.checkpoint.height,
                digest: sc.checkpoint.digest,
            };
            let tx = &checkpoints[chain];
            tx.send_if_modified(|old| {
                if *old == new_digest {
                    return false;
                }
                *old = new_digest;
                true
            });
        }
    }
}

/// Publish the signature and retry if it fails, logging the error and retry attempt. Shared by all chain publishers.
pub async fn execute_publish(publisher: Arc<dyn ChainPublisher>, action: PublishAction) {
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;

    tracing::info!(
        ?sign_id,
        ?chain,
        started_at = ?action.timestamp.elapsed(),
        "trying to publish signature",
    );

    let retry_config = RetryConfig {
        max_times: usize::MAX,
        min_delay: PUBLISH_MIN_DELAY,
        max_delay: PUBLISH_MAX_DELAY,
        jitter: true,
    };

    let publish_res = retry_rpc!(
        Duration::MAX, // Prevent from timing out
        retry_config,
        // Log the error and retry attempt
        |attempt, err, sleep| {
            tracing::warn!(
                ?sign_id,
                retry_count = attempt,
                elapsed = ?action.timestamp.elapsed(),
                ?chain,
                "failed to publish ({err}), retrying in {sleep:?}"
            );
        },
        // Try to publish the signature
        { publisher.publish_signature(&action).await }
    );

    // TODO: Consider adding a metric update for failed publish attempts here, if needed.
    // Log error if the publish failed after all retries
    if publish_res.is_err() {
        tracing::error!(
            ?sign_id,
            elapsed = ?action.timestamp.elapsed(),
            "exceeded max retries, trashing publish request"
        );
    }
}

/// Helper to record metrics when a signature is successfully published to a chain.
pub fn record_publish_metrics(action: &PublishAction) {
    let chain = action.indexed.chain;
    let elapsed_secs = crate::util::unix_elapsed(action.indexed.unix_timestamp_indexed).as_secs();

    if elapsed_secs <= chain.expected_response_time_secs() {
        record_request_latency_since(
            chain,
            SignRequestStep::Total,
            "in_time",
            action.indexed.unix_timestamp_indexed,
        );
    } else {
        record_request_latency_since(
            chain,
            SignRequestStep::Total,
            "expired",
            action.indexed.unix_timestamp_indexed,
        );
    }
    record_request_latency_since(chain, SignRequestStep::Responding, "ok", action.timestamp);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::test_utils::{make_indexed, make_publish_action, make_signature, scalar};
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::contract::{ResharingContractState, RunningContractState};
    use crate::protocol::ProtocolState;
    use cait_sith::protocol::Participant;
    use mpc_primitives::SignKind;

    /// A publisher that counts the number of times it has been called.
    struct CountingPublisher {
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ChainPublisher for CountingPublisher {
        async fn publish_signature(&self, _action: &PublishAction) -> anyhow::Result<()> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A publisher that always fails to publish a signature.
    struct FailingPublisher;

    #[async_trait::async_trait]
    impl ChainPublisher for FailingPublisher {
        async fn publish_signature(&self, _action: &PublishAction) -> anyhow::Result<()> {
            anyhow::bail!("publisher failed")
        }
    }

    fn test_participants() -> Participants {
        let mut participants = Participants::default();
        participants.insert(&Participant::from(0), ParticipantInfo::new(0));
        participants.insert(&Participant::from(1), ParticipantInfo::new(1));
        participants.insert(&Participant::from(2), ParticipantInfo::new(2));
        participants
    }

    #[tokio::test]
    async fn wait_governance_tracks_resharing_state() {
        let account_id: AccountId = "p-0".parse().unwrap();
        let participants = test_participants();
        let (mut watcher, tx) = ContractStateWatcher::new(&account_id);

        let initial = RunningContractState {
            epoch: 0,
            public_key: AffinePoint::default(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 2,
        };
        tx.send(Some(ProtocolState::Running(initial))).unwrap();

        let governance = watcher.governance().expect("running governance");
        assert_eq!(governance.epoch, 0);
        assert_eq!(governance.threshold, 2);
        assert_eq!(governance.me, Participant::from(0));

        let resharing = ResharingContractState {
            old_epoch: 0,
            old_participants: participants.clone(),
            new_participants: participants.clone(),
            threshold: 2,
            public_key: AffinePoint::default(),
            finished_votes: Default::default(),
            cancel_votes: Default::default(),
        };
        tx.send(Some(ProtocolState::Resharing(resharing))).unwrap();

        let paused = watcher.governance().expect("resharing governance");
        assert_eq!(paused.epoch, 1);
        assert_eq!(paused.threshold, 2);
        assert_eq!(paused.me, Participant::from(0));

        let running = RunningContractState {
            epoch: 1,
            public_key: AffinePoint::default(),
            participants,
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 2,
        };
        tx.send(Some(ProtocolState::Running(running))).unwrap();

        let resumed = watcher.wait_governance().await;
        assert_eq!(resumed.epoch, 1);
        assert_eq!(resumed.threshold, 2);
        assert_eq!(resumed.me, Participant::from(0));
    }

    #[test]
    fn publish_action_accepts_valid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let output = make_signature(&sk, epsilon, payload);
        let indexed = make_indexed(Chain::NEAR, epsilon, payload, SignKind::Sign);

        assert!(PublishAction::new(pk, indexed, output, vec![]).is_some());
    }

    #[test]
    fn publish_action_rejects_invalid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let mut output = make_signature(&sk, epsilon, payload);
        output.s += k256::Scalar::ONE;
        let indexed = make_indexed(Chain::NEAR, epsilon, payload, SignKind::Sign);

        assert!(PublishAction::new(pk, indexed, output, vec![]).is_none());
    }

    #[tokio::test]
    async fn executor_dispatches_to_configured_publisher() {
        let call_count = Arc::new(AtomicUsize::new(0));

        // Create a publisher for Ethereum that counts the number of times it has been called.
        let mut publishers: HashMap<Chain, Arc<dyn ChainPublisher>> = HashMap::new();
        publishers.insert(
            Chain::Ethereum,
            Arc::new(CountingPublisher {
                call_count: call_count.clone(),
            }),
        );

        let (tx, mut rx) = mpsc::channel(16);
        // Send a publish action to the executor.
        tx.send(RpcAction::Publish(make_publish_action(
            Chain::Ethereum,
            SignKind::Sign,
        )))
        .await
        .unwrap();

        // Closing the channel will cause dispatch_loop to return
        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, &mut rx).await;

        // Give spawned tasks a chance to complete
        tokio::task::yield_now().await;

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn executor_ignores_action_for_unconfigured_chain() {
        let call_count = Arc::new(AtomicUsize::new(0));

        // Create a publisher for Canton
        let mut publishers: HashMap<Chain, Arc<dyn ChainPublisher>> = HashMap::new();
        publishers.insert(
            Chain::Canton,
            Arc::new(CountingPublisher {
                call_count: call_count.clone(),
            }),
        );

        let (tx, mut rx) = mpsc::channel(16);

        // Send a publish action for Ethereum (not configured)
        tx.send(RpcAction::Publish(make_publish_action(
            Chain::Ethereum,
            SignKind::Sign,
        )))
        .await
        .unwrap();

        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, &mut rx).await;
        tokio::task::yield_now().await;

        assert_eq!(call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn executor_continues_after_publisher_error() {
        let call_count = Arc::new(AtomicUsize::new(0));

        // Create a publisher for NEAR that always fails, and a publisher for Solana that counts calls.
        let mut publishers: HashMap<Chain, Arc<dyn ChainPublisher>> = HashMap::new();
        publishers.insert(Chain::NEAR, Arc::new(FailingPublisher));
        publishers.insert(
            Chain::Solana,
            Arc::new(CountingPublisher {
                call_count: call_count.clone(),
            }),
        );

        let (tx, mut rx) = mpsc::channel(16);

        // Send a publish action for NEAR (which will fail) and then for Solana (which should succeed)
        tx.send(RpcAction::Publish(make_publish_action(
            Chain::NEAR,
            SignKind::Sign,
        )))
        .await
        .unwrap();
        tx.send(RpcAction::Publish(make_publish_action(
            Chain::Solana,
            SignKind::Sign,
        )))
        .await
        .unwrap();

        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, &mut rx).await;

        // Yield enough times to let both spawned tasks complete.
        // Each task calls publish_signature once and returns immediately.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn executor_dispatches_to_correct_publishers() {
        const NEAR_ACTION_COUNT: usize = 3;
        const SOL_ACTION_COUNT: usize = 2;

        let near_count = Arc::new(AtomicUsize::new(0));
        let sol_count = Arc::new(AtomicUsize::new(0));

        // Create publishers for NEAR and Solana that count the number of times they have been called.
        let mut publishers: HashMap<Chain, Arc<dyn ChainPublisher>> = HashMap::new();

        publishers.insert(
            Chain::NEAR,
            Arc::new(CountingPublisher {
                call_count: near_count.clone(),
            }),
        );
        publishers.insert(
            Chain::Solana,
            Arc::new(CountingPublisher {
                call_count: sol_count.clone(),
            }),
        );

        let (tx, mut rx) = mpsc::channel(16);

        // Send multiple publish actions for NEAR and Solana
        for _ in 0..NEAR_ACTION_COUNT {
            tx.send(RpcAction::Publish(make_publish_action(
                Chain::NEAR,
                SignKind::Sign,
            )))
            .await
            .unwrap();
        }

        for _ in 0..SOL_ACTION_COUNT {
            tx.send(RpcAction::Publish(make_publish_action(
                Chain::Solana,
                SignKind::Sign,
            )))
            .await
            .unwrap();
        }

        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, &mut rx).await;
        tokio::task::yield_now().await;

        assert_eq!(near_count.load(Ordering::SeqCst), NEAR_ACTION_COUNT);
        assert_eq!(sol_count.load(Ordering::SeqCst), SOL_ACTION_COUNT);
    }
}
