use super::concurrency::{ConcurrencyController, TriplePermit};
use super::message::{MessageChannel, PositMessage, PositProtocolId, TripleMessage};
use super::posit::{PositAction, PositInternalAction, Posits};
use super::MpcSignProtocol;
use crate::config::Config;
use crate::mesh::MeshState;

use crate::protocol::posit::Positor;
use crate::storage::triple_storage::{TriplePair, TriplePairSlot, TripleStorage};
use crate::types::TripleProtocol;
use crate::util::{AffinePointExt, JoinMap};

use mpc_contract::config::ProtocolConfig;

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::triples::{TriplePub, TripleShare};
use chrono::Utc;
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Unique number used to identify a specific ongoing triple generation protocol.
/// Without `TripleId` it would be unclear where to route incoming cait-sith triple generation
/// messages.
pub type TripleId = u64;

/// A completed triple.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Triple {
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

struct TripleGenerator {
    id: TripleId,
    me: Participant,
    owner: Participant,
    participants: Vec<Participant>,
    /// Option to temporarily move it to a blocking task. Must be Some in all
    /// other circumstances.
    protocol: Option<TripleProtocol>,
    timeout: Duration,
    slot: TriplePairSlot,
    created: Instant,
    inbox: mpsc::Receiver<TripleMessage>,
    msg: MessageChannel,
    #[cfg(feature = "debug-page")]
    debug_view: crate::web::debug::DebugPageTaskHandle,
}

impl TripleGenerator {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        id: TripleId,
        me: Participant,
        owner: Participant,
        threshold: usize,
        participants: &[Participant],
        timeout: Duration,
        slot: TriplePairSlot,
        msg: &MessageChannel,
        _node_account_id: &str,
    ) -> Result<Self, InitializationError> {
        #[cfg(feature = "debug-page")]
        let node_account_id = _node_account_id;
        #[cfg(not(feature = "debug-page"))]
        let _ = _node_account_id;

        let mut participants = participants.to_vec();
        // Participants can be out of order, so let's sort them before doing anything.
        participants.sort();

        let protocol =
            cait_sith::triples::generate_triple_many::<Secp256k1, 2>(&participants, me, threshold)?;

        let inbox = msg.subscribe_triple(id).await;
        Ok(Self {
            id,
            me,
            owner,
            participants,
            protocol: Some(Box::new(protocol)),
            timeout,
            slot,
            created: Instant::now(),
            inbox,
            msg: msg.clone(),
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                node_account_id.to_string(),
                format!("TripleGenerator {id:#?}"),
            ),
        })
    }

    /// Receive the next message for the triple protocol; error out on the timeout being reached
    /// or the channel having been closed (aborted).
    async fn recv(&mut self) -> Option<TripleMessage> {
        match tokio::time::timeout(
            self.timeout.saturating_sub(self.created.elapsed()),
            self.inbox.recv(),
        )
        .await
        {
            Ok(Some(msg)) => Some(msg),
            Ok(None) => {
                tracing::warn!(id = self.id, "triple generation aborted");
                None
            }
            Err(_err) => {
                tracing::warn!(id = self.id, "triple generation timeout");
                None
            }
        }
    }

    async fn run(mut self, epoch: u64) {
        let start_time = Instant::now();
        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        crate::metrics::protocols::TRIPLE_BEFORE_POKE_DELAY
            .observe(self.created.elapsed().as_millis() as f64);

        loop {
            let poke_start_time = Instant::now();
            // Temporarily move protocol into blocking task and restore it immediately after.
            let mut protocol = self.protocol.take().expect("must be always be Some");

            let poke_result =
                match tokio::task::spawn_blocking(move || (protocol.poke(), protocol)).await {
                    Ok((res, protocol)) => {
                        self.protocol = Some(protocol);
                        res
                    }
                    Err(err) => {
                        crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
                        if self.owner == self.me {
                            crate::metrics::protocols::TRIPLE_GENERATOR_OWNED_FAILURES.inc();
                        }
                        tracing::warn!(
                            id = self.id,
                            ?err,
                            elapsed = ?start_time.elapsed(),
                            "triple generation failed in a spawned blocking task",
                        );
                        return;
                    }
                };

            let action = match poke_result {
                Ok(action) => action,
                Err(err) => {
                    crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
                    if self.owner == self.me {
                        crate::metrics::protocols::TRIPLE_GENERATOR_OWNED_FAILURES.inc();
                    }
                    tracing::warn!(
                        id = self.id,
                        ?err,
                        elapsed = ?start_time.elapsed(),
                        "triple generation failed",
                    );
                    break;
                }
            };

            total_wait += poke_start_time - poke_last_time;
            total_pokes += 1;
            poke_last_time = Instant::now();
            crate::metrics::protocols::TRIPLE_POKE_CPU_TIME
                .observe(poke_start_time.elapsed().as_millis() as f64);
            #[cfg(feature = "debug-page")]
            self.render_debug(total_pokes);

            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let Some(msg) = self.recv().await else {
                        crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
                        if self.owner == self.me {
                            crate::metrics::protocols::TRIPLE_GENERATOR_OWNED_FAILURES.inc();
                        }
                        break;
                    };
                    self.protocol
                        .as_mut()
                        .expect("must always be Some")
                        .message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
                    for to in &self.participants {
                        if *to == self.me {
                            continue;
                        }

                        let message = TripleMessage {
                            id: self.id,
                            epoch,
                            from: self.me,
                            data: data.clone(),
                            timestamp: Utc::now().timestamp() as u64,
                        };
                        self.msg.send(self.me, *to, message).await;
                    }
                }
                Action::SendPrivate(to, data) => {
                    let message = TripleMessage {
                        id: self.id,
                        epoch,
                        from: self.me,
                        data: data.clone(),
                        timestamp: Utc::now().timestamp() as u64,
                    };
                    self.msg.send(self.me, to, message).await;
                }
                Action::Return(outputs) => {
                    crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS.inc();
                    crate::metrics::protocols::TRIPLE_LATENCY
                        .observe(start_time.elapsed().as_secs_f64());
                    // this measures from generator creation to finishing. TRIPLE_LATENCY instead starts from the first poke() on the generator
                    crate::metrics::protocols::TRIPLE_LATENCY_TOTAL
                        .observe(self.created.elapsed().as_secs_f64());
                    crate::metrics::protocols::TRIPLE_ACCRUED_WAIT_DELAY
                        .observe(total_wait.as_millis() as f64);
                    crate::metrics::protocols::TRIPLE_POKES_CNT.observe(total_pokes as f64);

                    // Assuming outputs is Vec<(TripleShare, TriplePub)> with 2 elements
                    let [first, second, ..] = &outputs[..] else {
                        tracing::warn!(
                            id = self.id,
                            triples = outputs.len(),
                            "unexpected, not enough triples to make pair"
                        );
                        break;
                    };
                    let first = Triple {
                        share: first.0.clone(),
                        public: first.1.clone(),
                    };
                    let second = Triple {
                        share: second.0.clone(),
                        public: second.1.clone(),
                    };

                    let pair_is_mine = self.owner == self.me;

                    tracing::debug!(
                        id = ?self.id,
                        me = ?self.me,
                        owner = ?self.owner,
                        pair_is_mine,
                        participants = ?self.participants,
                        big_a0 = ?first.public.big_a.to_base58(),
                        big_a1 = ?second.public.big_a.to_base58(),
                        elapsed = ?self.created.elapsed(),
                        "completed triple pair generation"
                    );

                    if pair_is_mine {
                        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_OWNED_SUCCESS.inc();
                    }
                    let pair = TriplePair {
                        id: self.id,
                        triple0: first,
                        triple1: second,
                        holders: Some(self.participants.clone()),
                    };
                    self.slot.insert(pair, self.owner).await;
                    break;
                }
            }
        }
    }

    #[cfg(feature = "debug-page")]
    fn render_debug(&self, total_pokes: i32) {
        let markup = maud::html! {
            p { (format!("{total_pokes} pokes")) }
        };
        self.debug_view.send(markup);
    }
}

impl Drop for TripleGenerator {
    fn drop(&mut self) {
        let id = self.id;
        let msg = self.msg.clone();
        tokio::spawn(async move {
            msg.unsubscribe_triple(id).await;
            msg.filter_triple(id).await;
        });
    }
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct TripleSpawner {
    /// Triple Storage that contains all triples that were generated by the us + others.
    triple_storage: TripleStorage,

    /// The set of all ongoing triple generation protocols. This is a map of `TripleId` to
    /// the `JoinHandle` of the triple generation task. Calling `join_next` will wait on
    /// the next task to complete and return the result of the task. This is only restricted
    /// through max introduction and concurrent generation in the system.
    ongoing: JoinMap<TripleId, ()>,

    /// The set of ongoing triples that are owned by the current node.
    ongoing_owned: HashSet<TripleId>,

    /// The protocol posits that are currently in progress.
    posits: Posits<TripleId, TriplePermit>,

    me: Participant,
    threshold: usize,
    epoch: u64,
    msg: MessageChannel,
    node_account_id: String,
    concurrency_controller: Arc<ConcurrencyController>,

    #[cfg(feature = "debug-page")]
    posits_debug_view: crate::web::debug::DebugPageTaskHandle,
}

impl fmt::Debug for TripleSpawner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleSpawner")
            .field("me", &self.me)
            .field("threshold", &self.threshold)
            .field("epoch", &self.epoch)
            .field("ongoing_owned", &self.ongoing_owned)
            .finish()
    }
}

impl TripleSpawner {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        storage: &TripleStorage,
        msg: MessageChannel,
        node_account_id: String,
        concurrency_controller: Arc<ConcurrencyController>,
    ) -> Self {
        #[cfg(feature = "debug-page")]
        let posits_debug_view = crate::web::debug::register_task(
            node_account_id.clone(),
            "Posits TripleSpawner".to_string(),
        );
        Self {
            me,
            threshold,
            epoch,
            triple_storage: storage.clone(),
            ongoing: JoinMap::new(),
            ongoing_owned: HashSet::new(),
            posits: Posits::new(me),
            msg,
            node_account_id,
            concurrency_controller,
            #[cfg(feature = "debug-page")]
            posits_debug_view,
        }
    }

    pub async fn contains(&self, id: TripleId) -> bool {
        self.triple_storage.contains(id).await
    }

    pub async fn contains_mine(&self, id: TripleId) -> bool {
        self.triple_storage.contains_by_owner(id, self.me).await
    }

    pub fn contains_ongoing(&self, id: TripleId) -> bool {
        self.ongoing.contains_key(&id)
    }

    /// Returns the number of unspent triples assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.triple_storage.len_by_owner(self.me).await
    }

    pub fn len_ongoing(&self) -> usize {
        self.ongoing.len()
    }

    pub fn len_introduced(&self) -> usize {
        self.posits.len_proposed() + self.ongoing_owned.len()
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        self.triple_storage.len_generated().await + self.ongoing.len()
    }

    async fn process_posit(
        &mut self,
        id: TripleId,
        from: Participant,
        action: PositAction,
        timeout: Duration,
    ) {
        let internal_action = if self.contains_ongoing(id) {
            tracing::warn!(id, ?from, ?action, "triple already generating");
            PositInternalAction::Reply(PositAction::Reject)
        } else if self.contains(id).await {
            tracing::warn!(id, ?from, ?action, "triple already generated");
            PositInternalAction::Reply(PositAction::Reject)
        } else {
            let internal_action = self.posits.act(id, from, self.threshold, &action);
            #[cfg(feature = "debug-page")]
            self.posits_debug_view
                .send(self.posits.render_debug(self.threshold));
            internal_action
        };

        match internal_action {
            PositInternalAction::None => {}
            PositInternalAction::Abort => {}
            PositInternalAction::Reply(action) => {
                self.msg
                    .send(
                        self.me,
                        from,
                        PositMessage {
                            id: PositProtocolId::Triple(id),
                            from: self.me,
                            action,
                        },
                    )
                    .await;
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                self.start_generation(id, participants, positor, timeout)
                    .await;
            }
        }
    }

    /// Propose a new triple generation protocol to the network.
    async fn propose_posit(&mut self, active: &[Participant], permit: TriplePermit) {
        let pair_id = rand::random();
        self.posits.propose(pair_id, permit, active);
        for &p in active.iter() {
            if p == self.me {
                continue;
            }

            self.msg
                .send(
                    self.me,
                    p,
                    PositMessage {
                        id: PositProtocolId::Triple(pair_id),
                        from: self.me,
                        action: PositAction::Propose,
                    },
                )
                .await;
        }
    }

    async fn start_generation(
        &mut self,
        id: TripleId,
        participants: Vec<Participant>,
        positor: Positor<TriplePermit>,
        timeout: Duration,
    ) {
        let is_proposer = positor.is_proposer();
        let owner = positor.id();

        if is_proposer {
            for &to in &participants {
                if to == self.me {
                    continue;
                }
                self.msg
                    .send(
                        self.me,
                        to,
                        PositMessage {
                            id: PositProtocolId::Triple(id),
                            from: self.me,
                            action: PositAction::Start(participants.clone()),
                        },
                    )
                    .await;
            }
            self.ongoing_owned.insert(id);
        }

        let reserved_permit = match positor {
            Positor::Proposer(_, permit) => Some(permit),
            Positor::Deliberator(_) => None,
        };

        if let Err(err) = self
            .generate_with_id(id, &participants, owner, timeout, reserved_permit)
            .await
        {
            self.ongoing_owned.remove(&id);
            tracing::warn!(
                id,
                ?participants,
                is_proposer,
                ?err,
                "unable to start triple generation on START"
            );
        }
    }

    async fn generate_with_id(
        &mut self,
        id: TripleId,
        participants: &[Participant],
        owner: Participant,
        timeout: Duration,
        reserved_permit: Option<TriplePermit>,
    ) -> Result<(), InitializationError> {
        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        let Some(slot) = self.triple_storage.create_slot(id, owner).await else {
            return Err(InitializationError::BadParameters(format!(
                "triple {id} is already generating, in use, or stored"
            )));
        };

        tracing::info!(?id, "starting protocol to generate a new triple");
        let generator = TripleGenerator::new(
            id,
            self.me,
            owner,
            self.threshold,
            participants,
            timeout,
            slot,
            &self.msg,
            &self.node_account_id,
        )
        .await?;

        let epoch = self.epoch;
        let controller = Arc::clone(&self.concurrency_controller);
        self.ongoing.spawn(id, async move {
            let _permit = match reserved_permit {
                Some(permit) => permit,
                None => controller.triple_permits().acquire().await,
            };
            generator.run(epoch).await;
        });
        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS.inc();

        Ok(())
    }

    /// Generate new triples if this node owns fewer than the per-node minimum
    /// (`min_triples`) and the network-wide total hasn't reached the cap (`max_triples`).
    async fn should_stockpile(&self, cfg: &ProtocolConfig) -> bool {
        if self.len_potential().await >= cfg.triple.max_triples as usize {
            return false;
        }

        self.len_mine().await < cfg.triple.min_triples as usize
            && self.len_introduced() < cfg.max_concurrent_introduction as usize
    }

    async fn run(
        mut self,
        mut mesh_state: watch::Receiver<MeshState>,
        mut cfg: watch::Receiver<Config>,
        ongoing_gen_tx: watch::Sender<usize>,
    ) {
        let mut expiration_interval = tokio::time::interval(Duration::from_secs(1));
        let mut posits = self.msg.subscribe_triple_posit().await;

        let mut active = mesh_state.borrow().active().keys_vec();
        let mut protocol = cfg.borrow().protocol.clone();
        let mut last_active_warn = None;
        let triple_permits = self.concurrency_controller.triple_permits();

        loop {
            let try_stockpile = active.len() >= self.threshold;
            tokio::select! {
                _ = expiration_interval.tick() => {
                    for action in self.posits.expire_and_start(self.threshold, Duration::from_secs(10), Duration::from_secs(2)) {
                        match action {
                            (id, PositInternalAction::StartProtocol(participants, positor)) => {
                                let timeout = Duration::from_millis(protocol.triple.generation_timeout);
                                self.start_generation(id, participants, positor, timeout).await;
                            }
                            (_id, PositInternalAction::Abort) => {}
                            _ => {}
                        }
                    }
                }
                Some((id, from, action)) = posits.recv() => {
                    let timeout = Duration::from_millis(protocol.triple.generation_timeout);
                    self.process_posit(id, from, action, timeout).await;
                }
                permit = triple_permits.acquire(), if try_stockpile => {
                    if self.should_stockpile(&protocol).await {
                        self.propose_posit(&active, permit).await;
                    }
                }
                // `join_next` returns None on the set being empty, so don't handle that case
                Some(result) = self.ongoing.join_next(), if !self.ongoing.is_empty() => {
                    let id = match result {
                        Ok((id, ())) => id,
                        Err(id) => {
                            tracing::warn!(id, "triple generation task interrupted");
                            id
                        }
                    };
                    self.ongoing_owned.remove(&id);
                    let _ = ongoing_gen_tx.send(self.ongoing.len());
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
                }
                Ok(()) = mesh_state.changed() => {
                    active = mesh_state.borrow().active().keys_vec();
                }
                else => {}
            }

            if active.len() >= self.threshold {
                last_active_warn = None;
                let _ = ongoing_gen_tx.send(self.ongoing.len());

                crate::metrics::storage::NUM_TRIPLES_MINE.set(self.len_mine().await as i64);
                crate::metrics::storage::NUM_TRIPLES_TOTAL
                    .set(self.triple_storage.len_generated().await as i64);
                crate::metrics::protocols::NUM_TRIPLE_GENERATORS_INTRODUCED
                    .set(self.len_introduced() as i64);
                crate::metrics::protocols::NUM_TRIPLE_GENERATORS_TOTAL
                    .set(self.len_ongoing() as i64);
            } else if last_active_warn
                .is_none_or(|i: Instant| i.elapsed() > Duration::from_secs(60))
            {
                tracing::warn!(
                    ?active,
                    threshold = self.threshold,
                    "not enough active participants to generate triples"
                );
                last_active_warn = Some(Instant::now());
            }
        }
    }
}

impl Drop for TripleSpawner {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        tokio::spawn(msg.unsubscribe_triple_posit());
    }
}

pub struct TripleSpawnerTask {
    ongoing_gen_rx: watch::Receiver<usize>,
    handle: JoinHandle<()>,
}

impl TripleSpawnerTask {
    pub fn run(
        me: Participant,
        threshold: usize,
        epoch: u64,
        ctx: &MpcSignProtocol,
        concurrency_controller: Arc<ConcurrencyController>,
    ) -> Self {
        let (ongoing_gen_tx, ongoing_gen_rx) = watch::channel(0);
        let manager = TripleSpawner::new(
            me,
            threshold,
            epoch,
            &ctx.triple_storage,
            ctx.msg_channel.clone(),
            ctx.my_account_id.to_string(),
            concurrency_controller,
        );

        Self {
            ongoing_gen_rx,
            handle: tokio::spawn(manager.run(
                ctx.mesh_state.clone(),
                ctx.config.clone(),
                ongoing_gen_tx,
            )),
        }
    }

    pub fn len_ongoing(&self) -> usize {
        // NOTE: no need to call `changed` or `borrow_and_update` here, since we only want to
        // observe whatever is the latest value in the channel. This is not meant to wait for
        // the next updated value.
        *self.ongoing_gen_rx.borrow()
    }

    pub fn abort(&self) {
        // NOTE: since dropping the handle here, TripleSpawner will drop their JoinSet/JoinMap
        // which will also abort all ongoing triple generation tasks. This is important to note
        // since we do not want to leak any triple generation tasks when we are resharing, and
        // potentially wasting compute.
        self.handle.abort();
    }
}

impl Drop for TripleSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::rpc::ContractStateWatcher;
    use deadpool_redis::Runtime;
    use k256::AffinePoint;
    use near_sdk::AccountId;
    use tokio::time::timeout;

    fn test_controller(initial_slots: usize, max_slots: usize) -> Arc<ConcurrencyController> {
        let mut protocol = ProtocolConfig::default();
        protocol.other.insert(
            "adaptive_concurrency".to_string(),
            serde_json::json!({
                "initial_slots": initial_slots,
                "max_slots": max_slots,
            })
            .into(),
        );
        ConcurrencyController::from_protocol(&protocol)
    }

    fn test_protocol_config() -> ProtocolConfig {
        let mut protocol = ProtocolConfig::default();
        protocol.max_concurrent_introduction = 4;
        protocol.triple.min_triples = 1;
        protocol.triple.max_triples = 8;
        protocol
    }

    fn test_account_id(label: &str) -> AccountId {
        format!(
            "{label}-{}.near",
            Utc::now().timestamp_nanos_opt().unwrap_or_default().unsigned_abs()
        )
        .parse()
        .unwrap()
    }

    fn test_participants(ids: &[u32]) -> Participants {
        let mut participants = Participants::default();
        for id in ids {
            let participant = Participant::from(*id);
            participants.insert(&participant, ParticipantInfo::new(*id));
        }
        participants
    }

    fn test_storage(label: &str, me: Participant) -> (TripleStorage, AccountId) {
        let redis_cfg = deadpool_redis::Config::from_url("redis://127.0.0.1/");
        let pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
        let account_id = test_account_id(label);
        let storage = TriplePair::storage(&pool, &account_id);
        storage.set_me(me);
        (storage, account_id)
    }

    #[tokio::test]
    async fn start_generation_uses_reserved_proposer_permit_without_waiting() {
        let me = Participant::from(0u32);
        let other = Participant::from(1u32);
        let controller = test_controller(2, 2);
        let active_before = controller.triple_active_for_test();
        let waiting_before = controller.waiting_triples_for_test();
        let reserved = controller.triple_permits().acquire().await;
        let blocker = controller.triple_permits().acquire().await;

        let (triple_storage, account_id) = test_storage("triple-start", me);
        let (inbox, _outbox, msg) = MessageChannel::new();
        let (_cfg_tx, cfg_rx) = watch::channel(Config::default());
        let (contract, _contract_tx) = ContractStateWatcher::with_running(
            &account_id,
            AffinePoint::default(),
            1,
            test_participants(&[0, 1]),
        );
        let inbox_task = tokio::spawn(inbox.run(cfg_rx, contract));

        let mut spawner = TripleSpawner::new(
            me,
            1,
            0,
            &triple_storage,
            msg,
            account_id.to_string(),
            Arc::clone(&controller),
        );
        let id = 42;

        spawner
            .start_generation(
                id,
                vec![me, other],
                Positor::Proposer(me, reserved),
                Duration::from_secs(5),
            )
            .await;

        timeout(Duration::from_secs(1), async {
            while !spawner.contains_ongoing(id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("triple generator should start without waiting for a second permit");

        assert_eq!(controller.waiting_triples_for_test(), waiting_before);
        assert_eq!(controller.triple_active_for_test(), active_before + 2);

        assert!(spawner.ongoing.abort(id));
        drop(blocker);
        drop(spawner);

        timeout(Duration::from_secs(1), async {
            while controller.triple_active_for_test() != active_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reserved permit should be released when the spawner task is aborted");

        inbox_task.abort();
    }

    #[tokio::test]
    async fn abort_and_expire_paths_release_reserved_proposer_permits() {
        let me = Participant::from(0u32);
        let other = Participant::from(1u32);
        let controller = test_controller(1, 1);
        let active_before = controller.triple_active_for_test();
        let (triple_storage, account_id) = test_storage("triple-abort-expire", me);
        let (_inbox, _outbox, msg) = MessageChannel::new();
        let mut spawner = TripleSpawner::new(
            me,
            2,
            0,
            &triple_storage,
            msg,
            account_id.to_string(),
            Arc::clone(&controller),
        );
        let participants = [me, other];

        let abort_permit = controller.triple_permits().acquire().await;
        spawner.posits.propose(100, abort_permit, &participants);
        assert_eq!(controller.triple_active_for_test(), active_before + 1);

        spawner
            .process_posit(100, other, PositAction::Reject, Duration::from_secs(1))
            .await;

        assert_eq!(spawner.len_introduced(), 0);
        timeout(Duration::from_secs(1), async {
            while controller.triple_active_for_test() != active_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abort path should release the proposer permit");

        let expire_permit = controller.triple_permits().acquire().await;
        spawner.posits.propose(101, expire_permit, &participants);
        assert_eq!(controller.triple_active_for_test(), active_before + 1);

        let actions = spawner
            .posits
            .expire_and_start(2, Duration::ZERO, Duration::ZERO);
        let (expired_id, action) = actions.into_iter().next().expect("expected one expired posit");
        assert_eq!(expired_id, 101);
        assert!(matches!(action, PositInternalAction::Abort));

        timeout(Duration::from_secs(1), async {
            while controller.triple_active_for_test() != active_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expire path should release the proposer permit");
    }

    #[tokio::test]
    async fn stockpile_wait_wakes_on_permit_availability_without_timer() {
        let me = Participant::from(0u32);
        let controller = test_controller(1, 1);
        let waiting_before = controller.waiting_triples_for_test();
        let active_before = controller.triple_active_for_test();
        let held = controller.triple_permits().acquire().await;
        let (triple_storage, account_id) = test_storage("triple-stockpile", me);
        let (_inbox, _outbox, msg) = MessageChannel::new();
        let mut spawner = TripleSpawner::new(
            me,
            1,
            0,
            &triple_storage,
            msg,
            account_id.to_string(),
            Arc::clone(&controller),
        );
        let active = vec![me];
        let protocol = test_protocol_config();

        {
            let stockpile = async {
                let permit = spawner.concurrency_controller.triple_permits().acquire().await;
                if spawner.should_stockpile(&protocol).await {
                    spawner.propose_posit(&active, permit).await;
                }
            };
            tokio::pin!(stockpile);

            assert!(timeout(Duration::from_millis(50), &mut stockpile).await.is_err());
            assert_eq!(controller.waiting_triples_for_test(), waiting_before + 1);

            drop(held);
            timeout(Duration::from_secs(1), &mut stockpile)
                .await
                .expect("stockpile branch should wake as soon as the permit becomes available");
        }

        assert_eq!(spawner.len_introduced(), 1);
        assert_eq!(controller.waiting_triples_for_test(), waiting_before);

        drop(spawner);
        timeout(Duration::from_secs(1), async {
            while controller.triple_active_for_test() != active_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stored stockpile permit should be released when the spawner drops");
    }
}
