mod hydration;
mod near_governance;

use crate::config::Config;
use crate::protocol::contract::primitives::{ParticipantMap, Participants};
use crate::protocol::contract::RunningContractState;
use crate::protocol::{Chain, IndexedSignRequest, ProtocolState};
use crate::sign_bidirectional::PublishState;
use enum_map::EnumMap;
use std::collections::BTreeSet;
use std::sync::Arc;

// TODO: move clients elsewhere
pub use hydration::HydrationClient;
pub use near_governance::{CheckpointVoteOutcome, NearGovernanceClient};

use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use dashmap::DashSet;
use k256::{AffinePoint, Secp256k1};
use mpc_chain_integration_core::{
    utils::retry::{retry_rpc, RetryConfig},
    ChainPublisher, PublishAction,
};
pub use mpc_contract::primitives::{Read, View};
use mpc_primitives::{CheckpointDigest, ConsensusCheckpointDigest, SignId, Signature};

use near_account_id::AccountId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// The maximum number of concurrent RPC requests the system can make
const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
/// The update interval to fetch and update the contract's state
const UPDATE_INTERVAL: Duration = Duration::from_secs(10);

// Publish retry constants
const PUBLISH_MIN_DELAY: Duration = Duration::from_secs(5);
const PUBLISH_MAX_DELAY: Duration = Duration::from_secs(60); // Cap to 1 min so backoff doesn't get too long for infinite retries

/// The maximum time to wait for a checkpoint vote to complete before retrying
const VOTE_CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(30);
const VOTE_CHECKPOINT_RETRY: RetryConfig = RetryConfig {
    max_times: usize::MAX,
    min_delay: PUBLISH_MIN_DELAY,
    max_delay: PUBLISH_MAX_DELAY,
    jitter: true,
};

// `PublishAction` makes this enum relatively large, but boxing it is not worth
// the indirection: the RPC channel is bounded to 1024 actions (under 1 MiB of
// enum storage), and these values are not copied on a performance-critical path.
#[allow(clippy::large_enum_variant)]
pub enum RpcAction {
    Publish(PublishAction),
    VoteCheckpoint {
        checkpoint: ConsensusCheckpointDigest,
        created_at: Instant,
    },
    AbortCheckpoints(Chain),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn vote_checkpoint(&self, checkpoint: ConsensusCheckpointDigest) {
        let tx = self.tx.clone();
        let created_at = Instant::now();
        tokio::spawn(async move {
            if let Err(err) = tx
                .send(RpcAction::VoteCheckpoint {
                    checkpoint,
                    created_at,
                })
                .await
            {
                tracing::error!(%err, ?checkpoint, "failed to send checkpoint vote");
            }
        });
    }

    pub async fn abort_checkpoints(&self, chain: Chain) {
        if let Err(err) = self.tx.send(RpcAction::AbortCheckpoints(chain)).await {
            tracing::error!(%err, ?chain, "failed to send RPC chain abort");
        }
    }

    pub fn publish(
        &self,
        public_key: mpc_crypto::PublicKey,
        request: Arc<IndexedSignRequest>,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) {
        let sign_id = request.id;
        let Some(action) = PublishAction::new(public_key, request, output, participants) else {
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
        request: Arc<IndexedSignRequest>,
        signature: Signature,
        participants: Vec<Participant>,
    ) {
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc
                .tx
                .send(RpcAction::Publish(PublishAction {
                    request,
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

    pub fn publish_with_state(&self, request: Arc<IndexedSignRequest>, publish: &PublishState) {
        self.publish_signature(request, publish.signature, publish.participants.clone());
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
                leave_votes: Default::default(),
                threshold,
                threshold_votes: Default::default(),
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

    pub async fn next_governance(&mut self, current: GovernanceInfo) -> Option<GovernanceInfo> {
        loop {
            if self.contract_state.changed().await.is_err() {
                return None;
            }
            let Some(state) = self.contract_state.borrow_and_update().clone() else {
                continue;
            };
            let next = state.governance(&self.account_id).unwrap_or_else(|| {
                let mut stale = current.clone();
                stale.is_running = false;
                stale
            });
            if next != current {
                tracing::info!(old = ?current, new = ?next, "signing governance changed");
                return Some(next);
            }
        }
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
    /// The NEAR governance client used to fetch contract state and config.
    near: NearGovernanceClient,
    /// The publishers for each chain.
    publishers: HashMap<Chain, Arc<dyn ChainPublisher>>,
    /// The receiver for incoming RPC actions.
    action_rx: mpsc::Receiver<RpcAction>,
}

impl RpcExecutor {
    pub async fn new(
        near: NearGovernanceClient,
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
        checkpoints: EnumMap<Chain, watch::Sender<Option<CheckpointDigest>>>,
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

        Self::dispatch_loop(
            &self.publishers,
            Some(self.near.clone()),
            &mut self.action_rx,
        )
        .await;
    }

    /// Dispatches incoming RPC actions to the appropriate chain publishers.
    async fn dispatch_loop(
        publishers: &HashMap<Chain, Arc<dyn ChainPublisher>>,
        near: Option<NearGovernanceClient>,
        action_rx: &mut mpsc::Receiver<RpcAction>,
    ) {
        let mut checkpoint_cancellation_tokens = HashMap::<Chain, CancellationToken>::new();
        let mut checkpoint_abort_times = HashMap::<Chain, Instant>::new();
        // Keep track of in-flight publish requests to avoid duplicate publishes for the same sign_id.
        let in_flight: Arc<DashSet<SignId>> = Arc::new(DashSet::new());
        loop {
            let Some(action) = action_rx.recv().await else {
                tracing::error!("rpc channel closed unexpectedly");
                return;
            };

            match action {
                RpcAction::Publish(action) => {
                    let chain = action.request.chain;
                    let Some(publisher) = publishers.get(&chain) else {
                        tracing::warn!(?chain, "no publisher configured for chain");
                        continue;
                    };

                    let sign_id = action.request.id;
                    if !in_flight.insert(sign_id) {
                        tracing::info!(
                            ?sign_id,
                            ?chain,
                            "publish already in flight; skipping duplicate"
                        );
                        continue;
                    }

                    let publisher = publisher.clone();
                    let in_flight = in_flight.clone();
                    tokio::spawn(async move {
                        let _guard = InFlightGuard {
                            in_flight,
                            id: sign_id,
                        };
                        execute_publish(publisher, action).await;
                    });
                }
                RpcAction::VoteCheckpoint {
                    checkpoint,
                    created_at,
                } => {
                    let chain = checkpoint.chain;
                    if checkpoint_abort_times
                        .get(&chain)
                        .is_some_and(|abort_time| *abort_time >= created_at)
                    {
                        tracing::info!(?chain, ?checkpoint, "discarding stale checkpoint vote");
                        continue;
                    }

                    let Some(near) = near.clone() else {
                        tracing::error!(?checkpoint, "checkpoint vote has no governance client");
                        continue;
                    };

                    let cancellation = checkpoint_cancellation_tokens
                        .entry(chain)
                        .or_default()
                        .clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = cancellation.cancelled() => {
                                tracing::info!(?chain, ?checkpoint, "cancelled checkpoint vote");
                            }
                            _ = execute_vote_checkpoint(near, checkpoint) => {}
                        }
                    });
                }
                RpcAction::AbortCheckpoints(chain) => {
                    checkpoint_abort_times.insert(chain, Instant::now());
                    checkpoint_cancellation_tokens
                        .entry(chain)
                        .or_default()
                        .cancel();
                    checkpoint_cancellation_tokens.insert(chain, CancellationToken::new());
                    tracing::info!(?chain, "cancelled checkpoint vote tasks");
                }
            }
        }
    }
}

async fn update_contract_data(
    near: NearGovernanceClient,
    contract: watch::Sender<Option<ProtocolState>>,
    config: watch::Sender<Config>,
    checkpoints: EnumMap<Chain, watch::Sender<Option<CheckpointDigest>>>,
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
        for (chain, tx) in &checkpoints {
            let new_digest = signed_checkpoints.get(&chain).map(|sc| CheckpointDigest {
                height: sc.height,
                digest: sc.digest,
            });
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

/// Releases a `SignId` from the dispatch loop's in-flight set when dropped,
/// including during a panic unwind, so the slot is always freed for re-publish.
struct InFlightGuard {
    in_flight: Arc<DashSet<SignId>>,
    id: SignId,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.in_flight.remove(&self.id);
    }
}

/// Publish the signature and retry if it fails, logging the error and retry attempt. Shared by all chain publishers.
pub async fn execute_publish(publisher: Arc<dyn ChainPublisher>, action: PublishAction) {
    let chain = action.request.chain;
    let sign_id = action.request.id;

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

async fn execute_vote_checkpoint(
    near: NearGovernanceClient,
    checkpoint: ConsensusCheckpointDigest,
) {
    vote_checkpoint_with_retry(
        &checkpoint,
        VOTE_CHECKPOINT_TIMEOUT,
        VOTE_CHECKPOINT_RETRY,
        || near.vote_checkpoint(&checkpoint),
    )
    .await
}

/// Submit a checkpoint vote under a bounded retry policy.
async fn vote_checkpoint_with_retry<F, Fut>(
    checkpoint: &ConsensusCheckpointDigest,
    timeout: Duration,
    retry_config: RetryConfig,
    vote: F,
) where
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = anyhow::Result<CheckpointVoteOutcome>> + Send,
{
    let result = retry_rpc!(
        timeout,
        retry_config,
        |attempt, err, sleep| {
            tracing::warn!(
                ?checkpoint,
                retry_count = attempt,
                ?err,
                ?sleep,
                "failed to vote for checkpoint, retrying"
            );
        },
        { vote().await }
    );

    match result {
        Ok(CheckpointVoteOutcome::Submitted { threshold_reached }) => {
            tracing::info!(?checkpoint, threshold_reached, "checkpoint vote submitted");
        }
        Ok(CheckpointVoteOutcome::Behind) => {
            tracing::info!(
                ?checkpoint,
                "checkpoint vote ignored because checkpoint is behind the latest checkpoint"
            );
        }
        Ok(CheckpointVoteOutcome::Conflicting) => {
            tracing::warn!(
                ?checkpoint,
                "checkpoint vote ignored because a conflicting checkpoint is finalized"
            );
        }
        Err(err) => {
            tracing::error!(?checkpoint, ?err, "checkpoint vote failed permanently");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::contract::{ResharingContractState, RunningContractState};
    use crate::protocol::ProtocolState;
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_primitives::{SignId, SignKind};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn vote_checkpoint_with_retry_terminates_when_rpc_hangs() {
        let checkpoint = ConsensusCheckpointDigest {
            chain: Chain::Ethereum,
            height: 1,
            digest: [0; 32],
        };
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let vote = move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<anyhow::Result<CheckpointVoteOutcome>>().await
            }
        };

        let timeout = Duration::from_millis(20);
        let retry = RetryConfig {
            min_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
            max_times: 2,
            jitter: false,
        };

        vote_checkpoint_with_retry(&checkpoint, timeout, retry, vote).await;

        // 1 initial attempt + 2 retries, each cut off by the per-attempt timeout.
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    /// Vote churn must be absorbed without completing; real governance changes
    /// and leaving the running state must be delivered.
    #[tokio::test]
    async fn next_governance_filters_non_governance_changes() {
        let account_id: AccountId = "p-0".parse().unwrap();
        let mut participants = Participants::default();
        participants.insert(&Participant::from(0), ParticipantInfo::new(0));
        let (mut watcher, tx) = ContractStateWatcher::with_running(
            &account_id,
            k256::AffinePoint::default(),
            1,
            participants.clone(),
        );
        let governance = watcher.governance().unwrap();

        let running = |epoch, leave_votes| RunningContractState {
            epoch,
            public_key: k256::AffinePoint::default(),
            participants: participants.clone(),
            leave_votes,
            threshold: 1,
            threshold_votes: Default::default(),
        };

        // Vote churn: state changed, governance content did not.
        let churn = crate::protocol::contract::primitives::Votes {
            votes: [("p-1".parse().unwrap(), Default::default())].into(),
        };
        tx.send(Some(ProtocolState::Running(running(0, churn))))
            .unwrap();
        let pending = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            watcher.next_governance(governance.clone()),
        )
        .await;
        assert!(pending.is_err(), "vote churn must not wake next_governance");

        // Epoch bump: a real governance change is delivered.
        tx.send(Some(ProtocolState::Running(running(1, Default::default()))))
            .unwrap();
        let next = watcher.next_governance(governance.clone()).await.unwrap();
        assert_eq!(next.epoch, 1);

        // Leaving the running state is reported as is_running = false.
        let resharing = ResharingContractState {
            old_epoch: 1,
            old_participants: participants.clone(),
            new_participants: participants.clone(),
            threshold: 1,
            new_threshold: 1,
            public_key: k256::AffinePoint::default(),
            finished_votes: Default::default(),
            cancel_votes: Default::default(),
        };
        tx.send(Some(ProtocolState::Resharing(resharing))).unwrap();
        let next = watcher.next_governance(next).await.unwrap();
        assert!(!next.is_running);

        // Channel closed.
        drop(tx);
        assert!(watcher.next_governance(next).await.is_none());
    }

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
            leave_votes: Default::default(),
            threshold: 2,
            threshold_votes: Default::default(),
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
            new_threshold: 2,
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
            leave_votes: Default::default(),
            threshold: 2,
            threshold_votes: Default::default(),
        };
        tx.send(Some(ProtocolState::Running(running))).unwrap();

        let resumed = watcher.wait_governance().await;
        assert_eq!(resumed.epoch, 1);
        assert_eq!(resumed.threshold, 2);
        assert_eq!(resumed.me, Participant::from(0));
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
            SignId::new([0u8; 32]),
        )))
        .await
        .unwrap();

        // Closing the channel will cause dispatch_loop to return
        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, None, &mut rx).await;

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
            SignId::new([0u8; 32]),
        )))
        .await
        .unwrap();

        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, None, &mut rx).await;
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
            SignId::new([0u8; 32]),
        )))
        .await
        .unwrap();
        tx.send(RpcAction::Publish(make_publish_action(
            Chain::Solana,
            SignKind::Sign,
            SignId::new([1u8; 32]),
        )))
        .await
        .unwrap();

        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, None, &mut rx).await;

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
        for i in 0..NEAR_ACTION_COUNT {
            tx.send(RpcAction::Publish(make_publish_action(
                Chain::NEAR,
                SignKind::Sign,
                SignId::new([i as u8; 32]),
            )))
            .await
            .unwrap();
        }

        for i in 0..SOL_ACTION_COUNT {
            tx.send(RpcAction::Publish(make_publish_action(
                Chain::Solana,
                SignKind::Sign,
                SignId::new([(NEAR_ACTION_COUNT + i) as u8; 32]),
            )))
            .await
            .unwrap();
        }

        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, None, &mut rx).await;
        tokio::task::yield_now().await;

        assert_eq!(near_count.load(Ordering::SeqCst), NEAR_ACTION_COUNT);
        assert_eq!(sol_count.load(Ordering::SeqCst), SOL_ACTION_COUNT);
    }

    #[tokio::test]
    async fn executor_aborts_checkpoint_vote_on_abort_checkpoints() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(500)
            .expect_at_least(1)
            .expect_at_most(2)
            .create_async()
            .await;

        let account_id: AccountId = "node.testnet".parse().unwrap();
        let sign_sk = near_crypto::SecretKey::from_seed(
            near_crypto::KeyType::ED25519,
            "rpc-cancellation-test",
        );
        let signer =
            match near_crypto::InMemorySigner::from_secret_key(account_id.clone(), sign_sk.clone())
            {
                near_crypto::Signer::InMemory(s) => s,
                _ => unreachable!(),
            };
        let cipher_sk = mpc_keys::hpke::SecretKey::from_bytes(&[0; 32]);
        let my_addr = "http://127.0.0.1:3000".parse().unwrap();
        let contract_id: AccountId = "contract.testnet".parse().unwrap();
        let near = NearGovernanceClient::new(
            &server.url(),
            &my_addr,
            &sign_sk,
            &cipher_sk,
            &contract_id,
            signer,
        );

        let (tx, mut rx) = mpsc::channel(16);
        let publishers = HashMap::new();
        let dispatch = tokio::spawn(async move {
            RpcExecutor::dispatch_loop(&publishers, Some(near), &mut rx).await;
        });

        tx.send(RpcAction::VoteCheckpoint {
            checkpoint: ConsensusCheckpointDigest {
                chain: Chain::Ethereum,
                height: 10,
                digest: [7; 32],
            },
            created_at: Instant::now(),
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send(RpcAction::AbortCheckpoints(Chain::Ethereum))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;

        drop(tx);
        dispatch.await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn executor_dedupes_concurrent_publishes_with_the_same_sign_id() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let mut publishers: HashMap<Chain, Arc<dyn ChainPublisher>> = HashMap::new();
        publishers.insert(
            Chain::Ethereum,
            Arc::new(CountingPublisher {
                call_count: call_count.clone(),
            }),
        );

        let (tx, mut rx) = mpsc::channel(16);
        let sign_id = SignId::new([7u8; 32]);

        // Multiple publishes for the SAME SignId
        for _ in 0..5 {
            tx.send(RpcAction::Publish(make_publish_action(
                Chain::Ethereum,
                SignKind::Sign,
                sign_id,
            )))
            .await
            .unwrap();
        }

        drop(tx);

        RpcExecutor::dispatch_loop(&publishers, None, &mut rx).await;

        // Let the single in-flight publish finish.
        tokio::task::yield_now().await;

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
