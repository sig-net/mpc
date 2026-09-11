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
use crate::protocol::Chain;
use crate::rpc::{ContractStateWatcher, GovernanceInfo, RpcChannel};
use crate::storage::presignature_storage::PresignatureReservation;
use crate::storage::PresignatureStorage;
use mpc_utils::{
    task::JoinMap,
    time::{unix_elapsed, TimeoutBudget},
};

use cait_sith::protocol::Participant;
use lru::LruCache;
use mpc_contract::config::ProtocolConfig;
use mpc_primitives::{ChainConfig as _, IndexedSignRequest, SignCommand, SignId};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

mod delay_monitor;
mod mailbox;
mod metrics;
mod organize;
mod posit;
mod queue;
mod state;
mod task;

use delay_monitor::DelayMonitor;
use queue::{live_by_chain, LivePhase, LiveSlot, Steal};
use task::SignTask;

pub(crate) use mailbox::{PositMailbox, SignPositMessage};
pub use queue::SignQueue;

/// Max number of live sign tasks (any role). Cold-start fill only admits
/// round-0 proposers; deliberators enter via posit-wake.
const MAX_LIVE_TASKS: usize = 4;

/// Timeout budget for the organizing and posit phases of round 0 (shorter under
/// test for speed). Later rounds follow [`round_timeout`], which may exceed this.
const ORGANIZE_POSIT_TIMEOUT: Duration = Duration::from_secs(if cfg!(feature = "test-feature") {
    5
} else {
    20
});

/// A proposer tries to include all eligible deliberators but will go ahead with
/// a subset after this timeout, if above the minimum threshold.
const ACCEPT_POSIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Shortest a round may be. A round has to fit a Propose broadcast plus accept
/// gathering, and an accepted deliberator keeps waiting twice
/// [`ACCEPT_POSIT_TIMEOUT`] no matter what the budget says. Below that, a round
/// cannot complete and rotating through it is pure churn.
const ROUND_TIMEOUT_FLOOR: Duration = ACCEPT_POSIT_TIMEOUT
    .saturating_mul(2)
    .saturating_add(Duration::from_secs(1));

/// Per-round growth factor of 1.15 (=23/20).
///
/// Nodes that index a request at different times enter the same round at
/// different moments, and can only transact while both are inside it.
/// Thus, a round length has to exceed that skew before the request
/// can be processed.
/// Any factor above 1 eventually crosses the skew, so the value is chosen
/// for what it costs the other case: rotating past inactive proposers
/// benefits from short rounds. At 1.15 the round length doubles after five rounds.
const ROUND_TIMEOUT_GROWTH_NUM: u32 = 23;
const ROUND_TIMEOUT_GROWTH_DEN: u32 = 20;

/// Longest a round may be. High enough that any plausible indexing skew is
/// crossed, low enough that a wedged request keeps rotating visibly instead of
/// disappearing into a multi-hour round.
/// tolerable skew < ROUND_TIMEOUT_CEILING - ROUND_TIMEOUT_FLOOR
const ROUND_TIMEOUT_CEILING: Duration = Duration::from_secs(if cfg!(feature = "test-feature") {
    30
} else {
    600
});

/// Timeout for round `r`: round 0 gets [`ORGANIZE_POSIT_TIMEOUT`], later rounds
/// start at [`ROUND_TIMEOUT_FLOOR`] and grow geometrically to
/// [`ROUND_TIMEOUT_CEILING`]. Depends only on `r`, so peers that agree on the
/// round agree on the deadline.
fn round_timeout(round: usize) -> Duration {
    if round == 0 {
        return ORGANIZE_POSIT_TIMEOUT;
    }
    // Saturates at the ceiling within ~16 iterations, which bounds the loop:
    // `round` derives from `highest_seen_round`, so a peer can make it huge.
    let mut timeout = ROUND_TIMEOUT_FLOOR;
    for _ in 1..round {
        if timeout >= ROUND_TIMEOUT_CEILING {
            return ROUND_TIMEOUT_CEILING;
        }
        timeout = timeout * ROUND_TIMEOUT_GROWTH_NUM / ROUND_TIMEOUT_GROWTH_DEN;
    }
    timeout.min(ROUND_TIMEOUT_CEILING)
}

/// Upper bound on the number of recently-completed/aborted sign IDs we remember
/// so that late-arriving peer posit messages do not re-create orphan mailboxes.
const MAX_DEAD_IDS: usize = 4096;

/// Router and lifecycle owner for live sign tasks. Parked requests live in
/// [`SignQueue`]; this type admits at most [`MAX_LIVE_TASKS`] at a time.
pub struct SignatureSpawner {
    contract: ContractStateWatcher,
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Consolidated signature tasks - one per sign_id, each task is an async task handling complete lifecycle
    tasks: JoinMap<SignId, Result<(), SignError>>,
    /// Per-sign posit mailboxes; also buffer messages that arrive before their
    /// task spawns.
    posit_mailboxes: HashMap<SignId, Arc<PositMailbox>>,
    /// Monitor alerting when signature requests exceed their expected response time.
    delay_monitor: DelayMonitor,
    /// Admitted in-flight requests (≤ [`MAX_LIVE_TASKS`]).
    live: HashMap<SignId, LiveSlot>,
    /// Recently completed/aborted sign IDs; prevents late peer posit messages from recreating orphan mailboxes.
    dead_ids: LruCache<SignId, ()>,
    mesh_state: watch::Receiver<MeshState>,
    /// Chains that have finished catchup (proposer fill allowed).
    live_chains: HashSet<Chain>,
    /// Per-chain flag cloned into tasks so a catchup deliberator that
    /// reorganizes does not start proposing until the chain is live.
    chain_live: HashMap<Chain, Arc<AtomicBool>>,

    msg: MessageChannel,
    rpc: RpcChannel,
    queue: SignQueue,
    node_account_id: near_account_id::AccountId,
}

impl SignatureSpawner {
    fn observe_queue_size(&self) {
        crate::metrics::requests::SIGN_QUEUE_SIZE.set(self.tasks.len() as i64);
    }

    fn chain_live_flag(&mut self, chain: Chain) -> Arc<AtomicBool> {
        self.chain_live
            .entry(chain)
            .or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone()
    }

    /// Admit `request` into the live set and spawn its task.
    fn admit(
        &mut self,
        governance: &GovernanceInfo,
        request: Arc<IndexedSignRequest>,
        cfg: ProtocolConfig,
    ) {
        let sign_id = request.id;
        if self.live.contains_key(&sign_id) {
            return;
        }
        if self.live.len() >= MAX_LIVE_TASKS {
            return;
        }
        if !governance.is_running {
            tracing::info!(?sign_id, "holding sign request until governance is running");
            return;
        }

        self.dead_ids.pop(&sign_id);
        let is_proposer = Arc::new(AtomicBool::new(false));
        let round = Arc::new(AtomicUsize::new(0));
        self.live.insert(
            sign_id,
            LiveSlot {
                request: Arc::clone(&request),
                is_proposer: Arc::clone(&is_proposer),
                round: Arc::clone(&round),
                phase: LivePhase::Organizing,
            },
        );

        let chain = request.chain;
        let unix_timestamp_indexed = request.unix_timestamp_indexed;
        let already_elapsed = unix_elapsed(unix_timestamp_indexed);
        let remaining_time = Duration::from_secs(chain.expected_response_time_secs())
            .saturating_sub(already_elapsed);
        self.delay_monitor.watch(
            sign_id,
            chain,
            unix_timestamp_indexed,
            remaining_time,
            Arc::clone(&is_proposer),
        );

        self.spawn_task(governance, request, cfg);
    }

    fn spawn_task(
        &mut self,
        governance: &GovernanceInfo,
        request: Arc<IndexedSignRequest>,
        cfg: ProtocolConfig,
    ) {
        let sign_id = request.id;
        tracing::info!(?sign_id, "spawning signature task");

        let (is_proposer, round) = self
            .live
            .get(&sign_id)
            .map(|slot| (Arc::clone(&slot.is_proposer), Arc::clone(&slot.round)))
            .expect("live slot must exist when spawning its task");

        let mailbox = Arc::clone(
            self.posit_mailboxes
                .entry(sign_id)
                .or_insert_with(PositMailbox::new),
        );
        let chain_live = self.chain_live_flag(request.chain);

        let task = SignTask {
            governance: governance.clone(),
            sign_id,
            presignatures: self.presignatures.clone(),
            msg: self.msg.clone(),
            rpc: self.rpc.clone(),
            backlog: self.queue.backlog().clone(),
            cfg,
            is_proposer,
            round,
            chain_live,
            node_account_id: self.node_account_id.clone(),
        };

        self.tasks
            .spawn(sign_id, task.run(request, self.mesh_state.clone(), mailbox));
    }

    /// Respawn every live task after a governance change. Parked stay parked.
    fn spawn_tasks(&mut self, governance: &GovernanceInfo, cfg: &ProtocolConfig) {
        let requests: Vec<Arc<IndexedSignRequest>> = self
            .live
            .values()
            .map(|slot| Arc::clone(&slot.request))
            .collect();
        tracing::info!(
            count = requests.len(),
            "respawning live sign tasks under new governance"
        );
        for request in requests {
            self.spawn_task(governance, request, cfg.clone());
        }
    }

    async fn fill_proposers(&mut self, governance: &GovernanceInfo, cfg: &ProtocolConfig) {
        if !governance.is_running {
            return;
        }
        let n = SignQueue::free_slots(self.live.len());
        if n == 0 {
            return;
        }
        let me = governance.me;
        let participants: Vec<_> = governance.participants.iter().copied().collect();
        let live_ids: HashSet<SignId> = self.live.keys().copied().collect();
        let by_chain = live_by_chain(&self.live);
        let picked = self
            .queue
            .next_proposers(
                n,
                me,
                &participants,
                &live_ids,
                &by_chain,
                &self.live_chains,
            )
            .await;
        for request in picked {
            record_request_latency_since(
                request.chain,
                SignRequestStep::AwaitingGeneration,
                "ok",
                request.unix_timestamp_indexed,
            );
            self.admit(governance, request, cfg.clone());
        }
        self.observe_queue_size();
    }

    async fn wake_deliberator(
        &mut self,
        governance: &GovernanceInfo,
        request: Arc<IndexedSignRequest>,
        cfg: &ProtocolConfig,
    ) {
        let sign_id = request.id;
        if self.live.contains_key(&sign_id) || !governance.is_running {
            return;
        }
        match Steal::for_admit(&self.live, sign_id) {
            Steal::None => return,
            Steal::Organizing(victim) => {
                tracing::info!(?victim, waking = ?sign_id, "stealing organizing slot for deliberator");
                self.release_live(victim, "stolen");
                self.tasks.abort(victim);
            }
            Steal::Slot => {}
        }
        self.admit(governance, request, cfg.clone());
        self.observe_queue_size();
    }

    async fn admit_buffered(&mut self, governance: &GovernanceInfo, cfg: &ProtocolConfig) {
        let pending: Vec<SignId> = self
            .posit_mailboxes
            .keys()
            .copied()
            .filter(|id| !self.live.contains_key(id) && !self.dead_ids.contains(id))
            .collect();
        for sign_id in pending {
            let Some(request) = self.queue.get(&sign_id).await else {
                continue;
            };
            self.wake_deliberator(governance, request, cfg).await;
        }
    }

    async fn handle_posit(
        &mut self,
        governance: &GovernanceInfo,
        cfg: &ProtocolConfig,
        sign_id: SignId,
        presignature_id: PresignatureId,
        round: usize,
        from: Participant,
        action: PositAction,
        stale_round: Option<usize>,
    ) {
        if self.dead_ids.contains(&sign_id) {
            return;
        }
        self.posit_mailboxes
            .entry(sign_id)
            .or_insert_with(PositMailbox::new)
            .push(SignPositMessage {
                presignature_id,
                round,
                from,
                action,
                stale_round,
            });
        if self.live.contains_key(&sign_id) {
            return;
        }
        let Some(request) = self.queue.get(&sign_id).await else {
            return;
        };
        self.wake_deliberator(governance, request, cfg).await;
    }

    fn handle_completion(&mut self, sign_id: SignId) {
        self.retire_task(sign_id, "completion");
        if self.tasks.abort(sign_id) {
            tracing::info!(?sign_id, "aborting signature task due to completion event");
        } else {
            tracing::info!(?sign_id, "task already completed or unable to be aborted");
        }
    }

    fn handle_task_exit(&mut self, result: Result<(SignId, Result<(), SignError>), SignId>) {
        self.observe_queue_size();
        let (sign_id, result) = match result {
            Ok(outcome) => outcome,
            Err(sign_id) => {
                tracing::warn!(?sign_id, "signature task interrupted");
                self.release_live(sign_id, "interruption");
                return;
            }
        };
        self.release_live(sign_id, "task completion");
        match result {
            Ok(()) => {
                tracing::info!(?sign_id, "signature task completed successfully");
            }
            Err(SignError::Aborted) => {
                tracing::warn!(?sign_id, "signature task terminated");
            }
        }
    }

    fn mark_dead(&mut self, sign_id: SignId) {
        self.dead_ids.put(sign_id, ());
    }

    /// Drop a live slot without marking the id dead (steal / task exit).
    fn release_live(&mut self, sign_id: SignId, reason: &'static str) {
        self.live.remove(&sign_id);
        self.posit_mailboxes.remove(&sign_id);
        self.delay_monitor.unwatch(sign_id, reason);
    }

    /// Teardown on completion / abort: live slot + mailbox, and remember the id.
    fn retire_task(&mut self, sign_id: SignId, reason: &'static str) {
        self.mark_dead(sign_id);
        self.release_live(sign_id, reason);
    }

    async fn handle_sign(
        &mut self,
        governance: &GovernanceInfo,
        sign: SignCommand,
        cfg: &ProtocolConfig,
    ) {
        match sign {
            SignCommand::Completion(sign_id) => {
                self.handle_completion(sign_id);
            }
            SignCommand::AbortChain(chain) => {
                tracing::warn!(
                    ?chain,
                    "aborting all in-flight signature tasks on chain regression"
                );
                self.live_chains.remove(&chain);
                if let Some(flag) = self.chain_live.get(&chain) {
                    flag.store(false, Ordering::Relaxed);
                }
                let to_abort: Vec<SignId> = self
                    .live
                    .iter()
                    .filter(|(_, slot)| slot.request.chain == chain)
                    .map(|(id, _)| *id)
                    .collect();
                for sign_id in to_abort {
                    self.retire_task(sign_id, "chain aborted");
                    self.tasks.abort(sign_id);
                }
            }
            SignCommand::Request(request) => {
                if self.live.contains_key(&request.id) {
                    tracing::info!(sign_id = ?request.id, "skipping duplicate sign request");
                    return;
                }
                record_request_latency_since(
                    request.chain,
                    SignRequestStep::AwaitingGeneration,
                    "ok",
                    request.unix_timestamp_indexed,
                );
                // Stream only enqueues after catchup; Near has no catchup
                // barrier. Either way, a Request means this chain may fill.
                self.live_chains.insert(request.chain);
                self.chain_live_flag(request.chain)
                    .store(true, Ordering::Relaxed);
                self.queue.park(Arc::clone(&request)).await;
                if self.posit_mailboxes.contains_key(&request.id) {
                    self.wake_deliberator(governance, request, cfg).await;
                }
                self.fill_proposers(governance, cfg).await;
            }
            SignCommand::ChainLive(chain) => {
                self.live_chains.insert(chain);
                self.chain_live_flag(chain).store(true, Ordering::Relaxed);
                tracing::info!(?chain, "chain live; filling proposer slots");
                self.fill_proposers(governance, cfg).await;
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
        let mut indexed = self.queue.subscribe_index();

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
                    self.handle_sign(&governance, sign, &protocol).await;
                }
                Some((sign_id, presignature_id, round, from, action, stale_round)) = posits.recv() => {
                    self.handle_posit(
                        &governance,
                        &protocol,
                        sign_id,
                        presignature_id,
                        round,
                        from,
                        action,
                        stale_round,
                    )
                    .await;
                }
                Ok(()) = indexed.changed() => {
                    self.admit_buffered(&governance, &protocol).await;
                    self.fill_proposers(&governance, &protocol).await;
                }
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    self.handle_task_exit(result);
                    self.fill_proposers(&governance, &protocol).await;
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
                }
                Some(new_governance) = contract_watcher.next_governance(governance.clone()) => {
                    governance = new_governance;
                    self.tasks.abort_all();
                    if governance.is_running {
                        self.spawn_tasks(&governance, &protocol);
                    } else {
                        tracing::info!(
                            count = self.live.len(),
                            "governance not running; holding live sign requests"
                        );
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

    fn test_posit_mailboxes_contains(&self, sign_id: &SignId) -> bool {
        self.posit_mailboxes.contains_key(sign_id)
    }

    fn test_tasks_contains(&self, sign_id: SignId) -> bool {
        self.tasks.contains_key(&sign_id)
    }
    fn test_live_contains(&self, sign_id: &SignId) -> bool {
        self.live.contains_key(sign_id)
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
        let delay_monitor = DelayMonitor::spawn();
        let spawner = SignatureSpawner {
            contract,
            tasks: JoinMap::new(),
            posit_mailboxes: HashMap::new(),
            delay_monitor,
            live: HashMap::new(),
            dead_ids: LruCache::new(NonZeroUsize::new(MAX_DEAD_IDS).unwrap()),
            presignatures: presignature_storage,
            mesh_state,
            live_chains: HashSet::new(),
            chain_live: HashMap::new(),
            msg: msg_channel,
            rpc: rpc_channel,
            queue: SignQueue::new(backlog),
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
    use tokio::sync::Notify;

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

        let delay_monitor = DelayMonitor::spawn();
        let mut spawner = SignatureSpawner {
            contract,
            presignatures,
            tasks: JoinMap::new(),
            posit_mailboxes: HashMap::new(),
            delay_monitor,
            live: HashMap::new(),
            dead_ids: LruCache::new(NonZeroUsize::new(MAX_DEAD_IDS).unwrap()),
            mesh_state: mesh_rx,
            live_chains: HashSet::from([Chain::Solana]),
            chain_live: HashMap::from([(Chain::Solana, Arc::new(AtomicBool::new(true)))]),
            msg: msg_channel,
            rpc: rpc_channel,
            queue: SignQueue::new(Backlog::new()),
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
        let request = Arc::new(IndexedSignRequest::sign(sign_id, args, Chain::Solana, 0));

        let probe_id = SignId::new([43u8; 32]);
        let probe_request = IndexedSignRequest::sign(
            probe_id,
            request.args.clone(),
            Chain::Solana,
            request.unix_timestamp_indexed,
        );
        let dropped = Arc::new(Notify::new());
        struct DropProbe(Arc<Notify>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let probe = DropProbe(Arc::clone(&dropped));
        spawner.live.insert(
            probe_id,
            LiveSlot {
                request: Arc::new(probe_request),
                is_proposer: Arc::new(AtomicBool::new(false)),
                round: Arc::new(AtomicUsize::new(0)),
                phase: LivePhase::Organizing,
            },
        );
        spawner.tasks.spawn(probe_id, async move {
            let _probe = probe;
            std::future::pending::<Result<(), SignError>>().await
        });

        // Step 1: Admit → task spawned, live, not dead
        spawner.admit(&governance, Arc::clone(&request), cfg.clone());
        assert!(spawner.test_tasks_contains(sign_id));
        assert!(spawner.test_live_contains(&sign_id));
        assert!(!spawner.test_dead_ids_contains(&sign_id));

        // Step 2: Abort chain → live dropped, marked dead, tasks cancelled
        spawner
            .handle_sign(&governance, SignCommand::AbortChain(Chain::Solana), &cfg)
            .await;
        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("aborting a chain should cancel its sign tasks");
        assert!(!spawner.test_tasks_contains(sign_id));
        assert!(!spawner.test_posit_mailboxes_contains(&sign_id));
        assert!(!spawner.test_live_contains(&sign_id));
        assert!(spawner.test_dead_ids_contains(&sign_id));

        // Step 3: Late posit → dropped (dead_id check), mailbox NOT recreated
        spawner
            .handle_posit(
                &governance,
                &cfg,
                sign_id,
                0,
                0,
                Participant::from(1),
                PositAction::Propose,
                None,
            )
            .await;
        assert!(!spawner.test_posit_mailboxes_contains(&sign_id));

        // Step 4: Re-admit → dead cleared, live again
        spawner.admit(&governance, Arc::clone(&request), cfg.clone());
        assert!(spawner.test_tasks_contains(sign_id));
        assert!(!spawner.test_dead_ids_contains(&sign_id));

        // Step 5: Posit after re-admit → accepted, mailbox re-created
        spawner
            .handle_posit(
                &governance,
                &cfg,
                sign_id,
                0,
                0,
                Participant::from(1),
                PositAction::Propose,
                None,
            )
            .await;
        assert!(spawner.test_posit_mailboxes_contains(&sign_id));

        // Step 6: Governance respawn → task swapped in place, nothing retired,
        // and the new incarnation resumes from the slot's carried round.
        let carried = Arc::new(AtomicUsize::new(7));
        spawner.live.get_mut(&sign_id).unwrap().round = Arc::clone(&carried);
        spawner.tasks.abort_all();
        spawner.spawn_tasks(&governance, &cfg);
        assert!(spawner.test_tasks_contains(sign_id));
        assert!(spawner.test_live_contains(&sign_id));
        assert!(spawner.test_posit_mailboxes_contains(&sign_id));
        assert!(!spawner.test_dead_ids_contains(&sign_id));
        assert!(
            Arc::strong_count(&carried) >= 3,
            "respawned task must share the slot's round, not a fresh one"
        );
        assert!(carried.load(Ordering::Relaxed) >= 7);
    }

    #[test]
    fn round_timeout_schedule() {
        // Every round must outlast a propose broadcast (<1s) plus accept
        // gathering inside.  For r >= 1 this holds by construction today;
        // the test serves as a guard so the code can't silently drift.
        for r in 0..64usize {
            assert!(
                round_timeout(r) >= ROUND_TIMEOUT_FLOOR,
                "round {r} is too short to complete"
            );
        }

        // Growth is monotonic from round 1, so a request that keeps failing gets
        // more time rather than retrying forever on equally short rounds.
        for r in 1..64usize {
            assert!(
                round_timeout(r + 1) >= round_timeout(r),
                "round {r} is longer than round {}",
                r + 1
            );
        }

        // Rounds must grow past a late node's indexing skew, or the two never
        // overlap: both advance at the same rate, so a fixed ceiling below the
        // skew leaves them permanently offset.
        // In addition, the overlap of the two nodes in the same round must fit a
        // Propose broadcast plus accept gathering inside (`ROUND_TIMEOUT_FLOOR`).
        let settling_overlap = |skew: Duration| {
            (1..1024usize)
                .map(round_timeout)
                .find(|&t| t.saturating_sub(skew) > ROUND_TIMEOUT_FLOOR)
                .map(|t| t - skew)
                .expect("schedule must clear the skew by a full round")
        };

        let skew = ORGANIZE_POSIT_TIMEOUT;
        let wider = 4 * skew;

        // The shared window has to scale with the skew
        // (up to some ceiling to avoid rounds that last hours).
        // `settling_overlap` needs a round that clears the skew by more than
        // ROUND_TIMEOUT_FLOOR. No round exceeds the ceiling, so that's only
        // reachable while the skew leaves enough room under it.
        assert!(
            wider < ROUND_TIMEOUT_CEILING - ROUND_TIMEOUT_FLOOR,
            "the skews compared here must leave a full round of room under the ceiling"
        );
        assert!(
            settling_overlap(wider) > settling_overlap(skew),
            "a 4x larger skew must leave a wider window, not the same floor-sized one"
        );

        // A wedged request keeps rotating rather than vanishing into an
        // unbounded round. `round` derives from a peer-supplied value, so it
        // may be arbitrary.
        assert_eq!(round_timeout(1024), ROUND_TIMEOUT_CEILING);
        assert_eq!(round_timeout(usize::MAX), ROUND_TIMEOUT_CEILING);
    }
}
