use crate::protocol::signature::{GenerateCtx, PendingPresignature, SignError, SignGenerator};

use crate::backlog::Backlog;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::metrics::requests::{
    record_request_latency, record_request_latency_since, SignRequestStep, SIGN_REQUEST_LOOPS,
};
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::message::{MessageChannel, PositMessage, PositProtocolId};
use crate::protocol::posit::{PositAction, PositRejectReason, SinglePositCounter};
use crate::protocol::presignature::PresignatureId;
use crate::protocol::{Chain, ProtocolState};
use crate::rpc::{ContractStateWatcher, GovernanceInfo, RpcChannel};
use crate::storage::presignature_storage::PresignatureReservation;
use crate::storage::PresignatureStorage;
use crate::util::{JoinMap, TimeoutBudget};

use cait_sith::protocol::Participant;
use lru::LruCache;
use mpc_contract::config::ProtocolConfig;
use mpc_primitives::{IndexedSignRequest, SignCommand, SignId, SignKind};
use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

mod limiter;
mod metrics;
mod organize;
mod posit;
mod state;
mod task;
mod work_queue;

use limiter::SignLimiter;
use task::SignTask;

pub(crate) use work_queue::{SignPositWorkQueue, SignTaskMessage};

/// How many rounds ahead the organizing phase searches for an active proposer.
const PROPOSER_SEARCH_WINDOW: usize = 512;

/// Max number of concurrent proposers, with unlimited deliberators.
const MAX_CONCURRENT_PROPOSERS: usize = 4;

/// Timeout budget for organizing and posit phases (shorter under test for speed).
const ORGANIZE_POSIT_TIMEOUT: Duration = Duration::from_secs(if cfg!(feature = "test-feature") {
    5
} else {
    20
});

/// A proposer tries to include all eligible deliberators but will go ahead with
/// a subset after this timeout, if above the minimum threshold.
const ACCEPT_POSIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Upper bound on the number of recently-completed/aborted sign IDs we remember
/// so that late-arriving peer posit messages do not re-create orphan queues.
const MAX_DEAD_IDS: usize = 4096;

/// Router and lifecycle owner for all in-flight sign tasks: one task per
/// `sign_id`, plus the posit queues, delayed-response watchers, and dedup state
/// that outlive individual tasks. (TODO: needs refactoring)
pub struct SignatureSpawner {
    contract: ContractStateWatcher,
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Consolidated signature tasks - one per sign_id, each task is an async task handling complete lifecycle
    tasks: JoinMap<SignId, Result<(), SignError>>,
    /// Per-sign posit queues; also buffer messages that arrive before their
    /// task spawns.
    posit_queues: HashMap<SignId, Arc<SignPositWorkQueue>>,
    /// Watchers that increment the delayed metric when response time exceeds expected.
    delayed_watchers: HashMap<SignId, JoinHandle<()>>,
    /// Maps in-flight tasks to their chain, enabling bulk abort on checkpoint regression.
    task_chains: HashMap<SignId, Chain>,
    /// Recently completed/aborted sign IDs; prevents late peer posit messages from recreating orphan queues.
    dead_ids: LruCache<SignId, ()>,
    mesh_state: watch::Receiver<MeshState>,
    /// Caps concurrent sign-task progress so requests don't flood the system's compute.
    limiter: SignLimiter,

    msg: MessageChannel,
    rpc: RpcChannel,
    backlog: Backlog,
    node_account_id: near_account_id::AccountId,
}

impl SignatureSpawner {
    fn observe_queue_size(&self) {
        crate::metrics::requests::SIGN_QUEUE_SIZE.set(self.tasks.len() as i64);
    }

    /// Spawn a signature task that internally handles the organize, posit, and generation phases.
    fn spawn_task(
        &mut self,
        governance: &GovernanceInfo,
        request: IndexedSignRequest,
        cfg: ProtocolConfig,
    ) {
        let sign_id = request.id;
        // Ensure we don't retain the dead tag from a prior incarnation of this
        // sign ID (e.g. after regression recovery re-queues a completed request).
        self.dead_ids.pop(&sign_id);
        self.task_chains.insert(sign_id, request.chain);
        tracing::info!(?sign_id, "spawning signature task");

        // Watcher that increments the delayed metric if not completed within the expected response time.
        let chain = request.chain;
        let unix_timestamp_indexed = request.unix_timestamp_indexed;
        let expected_response_time_secs = chain.expected_response_time_secs();
        let already_elapsed = crate::util::unix_elapsed(unix_timestamp_indexed);
        let remaining_time =
            Duration::from_secs(expected_response_time_secs).saturating_sub(already_elapsed);
        let is_proposer = Arc::new(AtomicBool::new(false));
        // prevent incrementing delayed metric for already delayed requests
        if remaining_time > Duration::from_secs(0)
            && !matches!(request.kind, SignKind::Checkpoint(_))
        {
            let is_proposer = Arc::clone(&is_proposer);
            let watcher = tokio::spawn(async move {
                tokio::time::sleep(remaining_time).await;
                let elapsed = crate::util::unix_elapsed(unix_timestamp_indexed);
                tracing::warn!(
                    ?sign_id,
                    ?chain,
                    elapsed_secs = elapsed.as_secs(),
                    expected_secs = expected_response_time_secs,
                    "signature request delayed beyond expected response time"
                );

                if is_proposer.load(Ordering::Relaxed) {
                    crate::metrics::requests::SIGN_REQUEST_DELAYED
                        .with_label_values(&[chain.as_str()])
                        .inc();
                }
            });
            self.delayed_watchers.insert(sign_id, watcher);
        }

        // Take (or create) the posit queue; it may already hold messages
        // that arrived before this task spawned.
        let posit_queue = Arc::clone(
            self.posit_queues
                .entry(sign_id)
                .or_insert_with(SignPositWorkQueue::new),
        );

        let task = SignTask {
            governance: governance.clone(),
            sign_id,
            presignatures: self.presignatures.clone(),
            msg: self.msg.clone(),
            rpc: self.rpc.clone(),
            backlog: self.backlog.clone(),
            cfg,
            contract: self.contract.clone(),
            is_proposer,
            limiter: self.limiter.clone(),
            node_account_id: self.node_account_id.clone(),
        };

        // Spawn the async task with organizing loop
        self.tasks.spawn(
            sign_id,
            task.run(request, self.mesh_state.clone(), posit_queue),
        );
    }

    /// Handle a posit message - routes to existing task or buffers if task not yet created
    fn handle_posit(
        &mut self,
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        round: usize,
        from: Participant,
        action: PositAction,
    ) {
        // Ignore messages from ourselves
        if from == me {
            return;
        }
        // Drop late-arriving posits for already-completed/aborted sign IDs
        // to prevent re-creating orphan queues.
        if self.dead_ids.contains(&sign_id) {
            return;
        }
        self.posit_queues
            .entry(sign_id)
            .or_insert_with(SignPositWorkQueue::new)
            .push(SignTaskMessage::PositMessage {
                presignature_id,
                round,
                from,
                action,
            });
    }

    /// A peer/chain reported this signature done: tear down and abort our task.
    fn handle_completion(&mut self, sign_id: SignId) {
        self.retire_task(sign_id, "completion");
        if self.tasks.abort(sign_id) {
            tracing::info!(?sign_id, "aborting signature task due to completion event");
        } else {
            tracing::info!(?sign_id, "task already completed or unable to be aborted");
        }
    }

    /// A task's `JoinMap` entry finished (or was cancelled): tear down and log.
    fn handle_task_exit(&mut self, result: Result<(SignId, Result<(), SignError>), SignId>) {
        self.observe_queue_size();
        let (sign_id, result) = match result {
            Ok(outcome) => outcome,
            Err(sign_id) => {
                tracing::warn!(?sign_id, "signature task interrupted");
                self.retire_task(sign_id, "interruption");
                return;
            }
        };
        self.retire_task(sign_id, "task completion");
        match result {
            Ok(()) => {
                tracing::info!(?sign_id, "signature task completed successfully");
            }
            Err(SignError::Aborted) => {
                tracing::warn!(?sign_id, "signature task terminated");
            }
        }
    }

    /// Record a sign ID as dead so that late-arriving peer posits are dropped
    /// instead of recreating an orphan queue. Automatically LRU-evicts the
    /// stalest entry when the cache exceeds [`MAX_DEAD_IDS`].
    fn mark_dead(&mut self, sign_id: SignId) {
        self.dead_ids.put(sign_id, ());
    }

    /// Cancel the delayed-response watcher for a task that ended in time.
    fn abort_delayed_watcher(&mut self, sign_id: SignId, reason: &str) {
        if let Some(watcher) = self.delayed_watchers.remove(&sign_id) {
            tracing::info!(?sign_id, reason = %reason, "aborting delayed watcher");
            watcher.abort();
        } else {
            tracing::debug!(?sign_id, reason = %reason, "no delayed watcher to abort");
        }
    }

    /// Common teardown when a sign task ends: forget the id, drop its queue and
    /// its delayed watcher. Does not touch `tasks` (aborting varies per caller).
    fn retire_task(&mut self, sign_id: SignId, reason: &str) {
        self.mark_dead(sign_id);
        self.task_chains.remove(&sign_id);
        self.posit_queues.remove(&sign_id);
        self.abort_delayed_watcher(sign_id, reason);
    }

    fn handle_sign(
        &mut self,
        governance: &GovernanceInfo,
        sign: SignCommand,
        cfg: &ProtocolConfig,
    ) {
        match sign {
            SignCommand::Completion(sign_id) => {
                self.handle_completion(sign_id);
            }
            SignCommand::Request(request) | SignCommand::Checkpoint(request) => {
                let sign_id = request.id;

                // Skip if we already have a task handling this request.
                // Use tasks instead of the queue map since it may already contain buffered messages
                // (e.g. a Propose arriving before the indexer notifies us), so we must only look
                // at the task map to decide whether the request is truly a duplicate.
                if self.tasks.contains_key(&sign_id) {
                    tracing::info!(?sign_id, "skipping duplicate sign request");
                    return;
                }

                record_request_latency_since(
                    request.chain,
                    SignRequestStep::AwaitingGeneration,
                    "ok",
                    request.unix_timestamp_indexed,
                );

                self.spawn_task(governance, request, cfg.clone());
            }
            SignCommand::AbortChain(chain) => {
                tracing::warn!(
                    ?chain,
                    "aborting all in-flight signature tasks on chain regression"
                );
                let to_abort: Vec<SignId> = self
                    .task_chains
                    .iter()
                    .filter(|(_, c)| **c == chain)
                    .map(|(id, _)| *id)
                    .collect();
                for sign_id in to_abort {
                    self.retire_task(sign_id, "chain aborted");
                    self.tasks.abort(sign_id);
                }
            }
        }

        self.observe_queue_size();
    }

    /// Main loop: multiplex incoming requests, posit messages, task exits, config
    /// changes, and governance updates until the request channel closes.
    async fn run(
        mut self,
        mut sign_rx: mpsc::Receiver<SignCommand>,
        mut cfg: watch::Receiver<Config>,
    ) {
        let mut posits = self.msg.subscribe_signature_posit().await;
        let mut protocol = cfg.borrow().protocol.clone();

        let mut contract_watcher = self.contract.clone();

        // GUARANTEE: contract is in a running state with valid governance info
        // before we start processing any messages
        let mut governance = contract_watcher.wait_governance().await;

        loop {
            tokio::select! {
                sign = sign_rx.recv() => {
                    let Some(sign) = sign else {
                        tracing::warn!("signature spawner sign_rx closed, terminating");
                        break;
                    };
                    self.handle_sign(&governance, sign, &protocol);
                }
                Some((sign_id, presignature_id, round, from, action)) = posits.recv() => {
                    self.handle_posit(governance.me, sign_id, presignature_id, round, from, action);
                }
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    self.handle_task_exit(result);
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
                }
                Some(state) = contract_watcher.next_state() => {
                    if let Some(new_governance) = state.governance(&self.node_account_id) {
                        governance = new_governance;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
impl SignatureSpawner {
    fn test_dead_ids_contains(&self, sign_id: &SignId) -> bool {
        self.dead_ids.contains(sign_id)
    }

    fn test_posit_queues_contains(&self, sign_id: &SignId) -> bool {
        self.posit_queues.contains_key(sign_id)
    }

    fn test_tasks_contains(&self, sign_id: SignId) -> bool {
        self.tasks.contains_key(&sign_id)
    }

    fn test_task_chains_contains(&self, sign_id: &SignId) -> bool {
        self.task_chains.contains_key(sign_id)
    }
}

impl Drop for SignatureSpawner {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        tokio::spawn(msg.unsubscribe_signature_posit());
    }
}

pub struct SignatureSpawnerTask {
    handle: JoinHandle<()>,
}

impl SignatureSpawnerTask {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        my_account_id: near_account_id::AccountId,
        sign_rx: mpsc::Receiver<SignCommand>,
        contract: ContractStateWatcher,
        config: watch::Receiver<Config>,
        presignature_storage: PresignatureStorage,
        mesh_state: watch::Receiver<MeshState>,
        msg_channel: MessageChannel,
        rpc_channel: RpcChannel,
        backlog: Backlog,
    ) -> Self {
        let spawner = SignatureSpawner {
            contract,
            tasks: JoinMap::new(),
            posit_queues: HashMap::new(),
            delayed_watchers: HashMap::new(),
            task_chains: HashMap::new(),
            dead_ids: LruCache::new(NonZeroUsize::new(MAX_DEAD_IDS).unwrap()),
            presignatures: presignature_storage,
            mesh_state,
            limiter: SignLimiter::new(MAX_CONCURRENT_PROPOSERS),
            msg: msg_channel,
            rpc: rpc_channel,
            backlog,
            node_account_id: my_account_id,
        };

        Self {
            handle: tokio::spawn(spawner.run(sign_rx, config)),
        }
    }

    pub fn abort(&self) {
        // Aborting the loop drops the SignatureSpawner, whose JoinMap aborts every
        // in-flight sign task. Important on resharing so we don't leak tasks and
        // waste compute.
        self.handle.abort();
    }
}

impl Drop for SignatureSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(feature = "test-feature")]
pub fn organize_posit_timeout() -> Duration {
    ORGANIZE_POSIT_TIMEOUT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::presignature::Presignature;

    use cait_sith::protocol::Participant;
    use deadpool_redis::Runtime;

    #[tokio::test]
    async fn test_abort_chain_dead_ids_lifecycle() {
        let account_id: near_account_id::AccountId = "p-0".parse().unwrap();
        let mut participants = Participants::default();
        participants.insert(&Participant::from(0), ParticipantInfo::new(0));

        let governance = GovernanceInfo {
            me: Participant::from(0),
            threshold: 1,
            epoch: 0,
            public_key: k256::AffinePoint::default(),
            participants: [Participant::from(0)].into_iter().collect(),
            is_running: true,
        };

        let redis_cfg = deadpool_redis::Config::from_url("redis://127.0.0.1/");
        let pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
        let presignatures = Presignature::storage(&pool, &account_id);
        let (_inbox, _outbox, msg_channel) = MessageChannel::new();
        let (rpc_tx, _rpc_rx) = mpsc::channel(1);
        let rpc_channel = RpcChannel { tx: rpc_tx };
        let (contract, _tx) = ContractStateWatcher::with_running(
            &account_id,
            k256::AffinePoint::default(),
            1,
            participants.clone(),
        );
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());

        let mut spawner = SignatureSpawner {
            contract,
            presignatures,
            tasks: JoinMap::new(),
            posit_queues: HashMap::new(),
            delayed_watchers: HashMap::new(),
            task_chains: HashMap::new(),
            dead_ids: LruCache::new(NonZeroUsize::new(MAX_DEAD_IDS).unwrap()),
            mesh_state: mesh_rx,
            limiter: SignLimiter::new(MAX_CONCURRENT_PROPOSERS),
            msg: msg_channel,
            rpc: rpc_channel,
            backlog: Backlog::new(),
            node_account_id: account_id,
        };

        let cfg = ProtocolConfig::default();
        let sign_id = SignId::new([42u8; 32]);
        let args = mpc_primitives::SignArgs {
            entropy: [1u8; 32],
            epsilon: k256::Scalar::from(1u64),
            payload: k256::Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        let request = IndexedSignRequest::sign(sign_id, args, Chain::Solana, 0);

        // Step 1: Spawn → queue created, task_chains populated, not dead
        spawner.spawn_task(&governance, request.clone(), cfg.clone());
        assert!(spawner.test_tasks_contains(sign_id));
        assert!(spawner.test_posit_queues_contains(&sign_id));
        assert!(spawner.test_task_chains_contains(&sign_id));
        assert!(!spawner.test_dead_ids_contains(&sign_id));

        // Step 2: Abort chain → queue removed, task_chains cleared, marked dead
        spawner.handle_sign(&governance, SignCommand::AbortChain(Chain::Solana), &cfg);
        assert!(!spawner.test_tasks_contains(sign_id));
        assert!(!spawner.test_posit_queues_contains(&sign_id));
        assert!(!spawner.test_task_chains_contains(&sign_id));
        assert!(spawner.test_dead_ids_contains(&sign_id));

        // Step 3: Late posit → dropped (dead_id check), queue NOT recreated
        spawner.handle_posit(
            Participant::from(0),
            sign_id,
            0,
            0,
            Participant::from(1),
            PositAction::Propose,
        );
        assert!(!spawner.test_posit_queues_contains(&sign_id));

        // Step 4: Re-spawn → dead cleared, task_chains repopulated
        spawner.spawn_task(&governance, request, cfg.clone());
        assert!(spawner.test_tasks_contains(sign_id));
        assert!(!spawner.test_dead_ids_contains(&sign_id));

        // Step 5: Posit after re-spawn → accepted, queue re-created
        spawner.handle_posit(
            Participant::from(0),
            sign_id,
            0,
            0,
            Participant::from(1),
            PositAction::Propose,
        );
        assert!(spawner.test_posit_queues_contains(&sign_id));
    }
}
