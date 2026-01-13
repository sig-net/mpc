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
use highway::{HighwayHash, HighwayHasher};
use k256::elliptic_curve::group::GroupEncoding;
use k256::Secp256k1;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use std::collections::HashSet;
use std::fmt;
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
    proposer: Participant,
    participants: Vec<Participant>,
    protocol: TripleProtocol,
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
        proposer: Participant,
        threshold: usize,
        participants: &[Participant],
        timeout: Duration,
        slot: TriplePairSlot,
        msg: &MessageChannel,
        _my_account_id: &AccountId,
    ) -> Result<Self, InitializationError> {
        let mut participants = participants.to_vec();
        // Participants can be out of order, so let's sort them before doing anything. Critical
        // for the triple_is_mine check:
        participants.sort();

        let protocol =
            cait_sith::triples::generate_triple_many::<Secp256k1, 2>(&participants, me, threshold)?;

        let inbox = msg.subscribe_triple(id).await;
        Ok(Self {
            id,
            me,
            proposer,
            participants,
            protocol: Box::new(protocol),
            timeout,
            slot,
            created: Instant::now(),
            inbox,
            msg: msg.clone(),
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                _my_account_id.to_string(),
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

    async fn run(mut self, my_account_id: AccountId, epoch: u64) {
        let before_first_poke_delay = crate::metrics::protocols::TRIPLE_BEFORE_POKE_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let accrued_wait_delay = crate::metrics::protocols::TRIPLE_ACCRUED_WAIT_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let runtime_latency =
            crate::metrics::protocols::TRIPLE_LATENCY.with_label_values(&[my_account_id.as_str()]);
        let total_latency = crate::metrics::protocols::TRIPLE_LATENCY_TOTAL
            .with_label_values(&[my_account_id.as_str()]);
        let poke_latency = crate::metrics::protocols::TRIPLE_POKE_CPU_TIME
            .with_label_values(&[my_account_id.as_str()]);
        let poke_counts = crate::metrics::protocols::TRIPLE_POKES_CNT
            .with_label_values(&[my_account_id.as_str()]);
        let success_owned_counts =
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let success_total_counts =
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let failure_counts = crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES
            .with_label_values(&[my_account_id.as_str()]);
        let failure_mine_counts = crate::metrics::protocols::TRIPLE_GENERATOR_MINE_FAILURES
            .with_label_values(&[my_account_id.as_str()]);

        let start_time = Instant::now();
        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        before_first_poke_delay.observe(self.created.elapsed().as_millis() as f64);

        loop {
            let poke_start_time = Instant::now();
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    failure_counts.inc();
                    if self.proposer == self.me {
                        failure_mine_counts.inc();
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
            poke_latency.observe(poke_start_time.elapsed().as_millis() as f64);
            #[cfg(feature = "debug-page")]
            self.render_debug(total_pokes);

            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let Some(msg) = self.recv().await else {
                        failure_counts.inc();
                        if self.proposer == self.me {
                            failure_mine_counts.inc();
                        }
                        break;
                    };
                    self.protocol.message(msg.from, msg.data);
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
                    success_total_counts.inc();
                    runtime_latency.observe(start_time.elapsed().as_secs_f64());
                    // this measures from generator creation to finishing. TRIPLE_LATENCY instead starts from the first poke() on the generator
                    total_latency.observe(self.created.elapsed().as_secs_f64());
                    accrued_wait_delay.observe(total_wait.as_millis() as f64);
                    poke_counts.observe(total_pokes as f64);

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

                    // For simplicity, assign both triples to the same owner based on the first triple
                    let triple_owner = {
                        let big_c = first.public.big_c;
                        let entropy = HighwayHasher::default().hash64(&big_c.to_bytes()) as usize;
                        let num_participants = self.participants.len();
                        self.participants[entropy % num_participants]
                    };
                    let pair_is_mine = triple_owner == self.me;

                    tracing::debug!(
                        id = self.id,
                        me = ?self.me,
                        ?triple_owner,
                        pair_is_mine,
                        participants = ?self.participants,
                        big_a0 = ?first.public.big_a.to_base58(),
                        big_a1 = ?second.public.big_a.to_base58(),
                        elapsed = ?self.created.elapsed(),
                        "completed triple pair generation"
                    );

                    if pair_is_mine {
                        success_owned_counts.inc();
                    }

                    let pair = TriplePair {
                        id: self.id,
                        triple0: first,
                        triple1: second,
                    };
                    self.slot.insert(pair, triple_owner).await;
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

    /// The set of ongoing triples that were introduced to the system by the current node.
    ongoing_introduced: HashSet<TripleId>,

    /// The protocol posits that are currently in progress.
    posits: Posits<TripleId, ()>,

    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
    msg: MessageChannel,
}

impl fmt::Debug for TripleSpawner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleSpawner")
            .field("me", &self.me)
            .field("threshold", &self.threshold)
            .field("epoch", &self.epoch)
            .field("my_account_id", &self.my_account_id)
            .field("ongoing_introduced", &self.ongoing_introduced)
            .finish()
    }
}

impl TripleSpawner {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        my_account_id: &AccountId,
        storage: &TripleStorage,
        msg: MessageChannel,
    ) -> Self {
        Self {
            me,
            threshold,
            epoch,
            triple_storage: storage.clone(),
            ongoing: JoinMap::new(),
            ongoing_introduced: HashSet::new(),
            posits: Posits::new(me),
            my_account_id: my_account_id.clone(),
            msg,
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

    pub async fn contains_used(&self, id: TripleId) -> bool {
        self.triple_storage.contains_used(id).await
    }

    /// Returns the number of unspent triples assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.triple_storage.len_by_owner(self.me).await
    }

    pub fn len_ongoing(&self) -> usize {
        self.ongoing.len()
    }

    pub fn len_introduced(&self) -> usize {
        self.posits.len_proposed() + self.ongoing_introduced.len()
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
            self.posits.act(id, from, self.threshold, &action)
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
    async fn propose_posit(&mut self, active: &[Participant]) {
        let pair_id = rand::random();
        self.posits.propose(pair_id, (), active);
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
        positor: Positor<()>,
        timeout: Duration,
    ) {
        if positor.is_proposer() {
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
            self.ongoing_introduced.insert(id);
        }

        if let Err(err) = self
            .generate_with_id(id, &participants, positor.id(), timeout)
            .await
        {
            self.ongoing_introduced.remove(&id);
            tracing::warn!(
                id,
                ?participants,
                is_proposer = positor.is_proposer(),
                ?err,
                "unable to start triple generation on START"
            );
        }
    }

    async fn generate_with_id(
        &mut self,
        id: TripleId,
        participants: &[Participant],
        proposer: Participant,
        timeout: Duration,
    ) -> Result<(), InitializationError> {
        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        let Some(slot) = self.triple_storage.reserve(id).await else {
            return Err(InitializationError::BadParameters(format!(
                "id collision: pair_id={id}"
            )));
        };

        tracing::info!(id, "starting protocol to generate a new triple");
        let generator = TripleGenerator::new(
            id,
            self.me,
            proposer,
            self.threshold,
            participants,
            timeout,
            slot,
            &self.msg,
            &self.my_account_id,
        )
        .await?;

        self.ongoing
            .spawn(id, generator.run(self.my_account_id.clone(), self.epoch));
        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();

        Ok(())
    }

    /// Stockpile triples if the amount of unspent triples is below the minimum
    /// and the maximum number of all ongoing generation protocols is below the maximum.
    async fn stockpile(&mut self, participants: &[Participant], cfg: &ProtocolConfig) {
        if participants.len() < self.threshold {
            return;
        }

        let not_enough_triples = {
            // Stopgap to prevent too many triples in the system. This should be around min_triple*nodes*2
            // for good measure so that we have enough triples to do presig generation while also maintain
            // the minimum number of triples where a single node can't flood the system.
            if self.len_potential().await >= cfg.triple.max_triples as usize {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.len_mine().await < cfg.triple.min_triples as usize
                    && self.len_introduced() < cfg.max_concurrent_introduction as usize
                    && self.ongoing.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_triples {
            self.propose_posit(participants).await;
        }
    }

    async fn run(
        mut self,
        mut mesh_state: watch::Receiver<MeshState>,
        mut cfg: watch::Receiver<Config>,
        ongoing_gen_tx: watch::Sender<usize>,
    ) {
        let mut stockpile_interval = tokio::time::interval(Duration::from_millis(100));
        let mut expiration_interval = tokio::time::interval(Duration::from_secs(60));
        let mut posits = self.msg.subscribe_triple_posit().await;

        let mut active = mesh_state.borrow().active.keys_vec();
        let mut protocol = cfg.borrow().protocol.clone();

        loop {
            tokio::select! {
                _ = expiration_interval.tick() => {
                    for action in self.posits.expire_and_start(self.threshold, Duration::from_secs(60)) {
                        let (id, PositInternalAction::StartProtocol(participants, positor)) = action else {
                            continue;
                        };
                        let timeout = Duration::from_millis(protocol.triple.generation_timeout);
                        self.start_generation(id, participants, positor, timeout).await;
                    }
                }
                Some((id, from, action)) = posits.recv() => {
                    let timeout = Duration::from_millis(protocol.triple.generation_timeout);
                    self.process_posit(id, from, action, timeout).await;
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
                    self.ongoing_introduced.remove(&id);
                    let _ = ongoing_gen_tx.send(self.ongoing.len());
                }
                _ = stockpile_interval.tick(), if active.len() >= self.threshold => {
                    self.stockpile(&active, &protocol).await;
                    let _ = ongoing_gen_tx.send(self.ongoing.len());

                    crate::metrics::storage::NUM_TRIPLES_MINE
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_mine().await as i64);
                    crate::metrics::storage::NUM_TRIPLES_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.triple_storage.len_generated().await as i64);
                    crate::metrics::protocols::NUM_TRIPLE_GENERATORS_INTRODUCED
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_introduced() as i64);
                    crate::metrics::protocols::NUM_TRIPLE_GENERATORS_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_ongoing() as i64);
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
                }
                Ok(()) = mesh_state.changed() => {
                    active = mesh_state.borrow().active.keys_vec();
                }
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
    pub fn run(me: Participant, threshold: usize, epoch: u64, ctx: &MpcSignProtocol) -> Self {
        let (ongoing_gen_tx, ongoing_gen_rx) = watch::channel(0);
        let manager = TripleSpawner::new(
            me,
            threshold,
            epoch,
            &ctx.my_account_id,
            &ctx.triple_storage,
            ctx.msg_channel.clone(),
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
