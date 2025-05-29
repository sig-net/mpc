use super::message::{MessageChannel, TripleMessage};
use super::MpcSignProtocol;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::storage::triple_storage::{TripleSlot, TripleStorage};
use crate::types::TripleProtocol;
use crate::util::{AffinePointExt, JoinMap};

use mpc_contract::config::ProtocolConfig;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::triples::{TripleGenerationOutput, TriplePub, TripleShare};
use chrono::Utc;
use highway::{HighwayHash, HighwayHasher};
use k256::elliptic_curve::group::GroupEncoding;
use k256::Secp256k1;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
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
#[derive(Serialize, Deserialize, Debug)]
pub struct Triple {
    pub id: TripleId,
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

struct TripleGenerator {
    id: TripleId,
    me: Participant,
    participants: Vec<Participant>,
    protocol: TripleProtocol,
    timestamp: Option<Instant>,
    timeout: Duration,
    slot: TripleSlot,
    poked_latest: Option<(Instant, Duration, u64)>,
    generator_created: Instant,
    inbox: mpsc::Receiver<TripleMessage>,
    msg: MessageChannel,
}

impl TripleGenerator {
    pub async fn new(
        id: TripleId,
        me: Participant,
        threshold: usize,
        participants: &[Participant],
        timeout: u64,
        slot: TripleSlot,
        msg: &MessageChannel,
    ) -> Result<Self, InitializationError> {
        let mut participants = participants.to_vec();
        // Participants can be out of order, so let's sort them before doing anything. Critical
        // for the triple_is_mine check:
        participants.sort();

        let protocol =
            match cait_sith::triples::generate_triple::<Secp256k1>(&participants, me, threshold) {
                Ok(protocol) => Box::new(protocol),
                Err(e) => {
                    slot.unreserve().await;
                    return Err(e);
                }
            };

        let inbox = msg.subscribe_triple(id).await;

        Ok(Self {
            id,
            me,
            participants,
            protocol,
            timestamp: None,
            timeout: Duration::from_millis(timeout),
            slot,
            poked_latest: None,
            generator_created: Instant::now(),
            inbox,
            msg: msg.clone(),
        })
    }

    async fn poke(&mut self) -> Result<Action<TripleGenerationOutput<Secp256k1>>, ProtocolError> {
        let timestamp = self.timestamp.get_or_insert_with(Instant::now);
        let elapsed = timestamp.elapsed();
        if elapsed > self.timeout {
            tracing::warn!(id = self.id, ?elapsed, "triple protocol timed out");
            return Err(ProtocolError::Other(
                anyhow::anyhow!("triple protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }

    async fn run(mut self, my_account_id: AccountId, epoch: u64) {
        let triple_generator_failures_metric =
            crate::metrics::TRIPLE_GENERATOR_FAILURES.with_label_values(&[my_account_id.as_str()]);
        let triple_before_poke_delay_metric =
            crate::metrics::TRIPLE_BEFORE_POKE_DELAY.with_label_values(&[my_account_id.as_str()]);
        let triple_accrued_wait_delay_metric =
            crate::metrics::TRIPLE_ACCRUED_WAIT_DELAY.with_label_values(&[my_account_id.as_str()]);
        let triple_pokes_cnt_metric =
            crate::metrics::TRIPLE_POKES_CNT.with_label_values(&[my_account_id.as_str()]);
        let triple_latency_metric =
            crate::metrics::TRIPLE_LATENCY.with_label_values(&[my_account_id.as_str()]);
        let triple_latency_total_metric =
            crate::metrics::TRIPLE_LATENCY_TOTAL.with_label_values(&[my_account_id.as_str()]);
        let triple_generator_success_mine_metric =
            crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let triple_generator_success_metric =
            crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let triple_poke_cpu_time_metric =
            crate::metrics::TRIPLE_POKE_CPU_TIME.with_label_values(&[my_account_id.as_str()]);

        loop {
            let generator_poke_time = Instant::now();
            let action = match self.poke().await {
                Ok(action) => action,
                Err(e) => {
                    triple_generator_failures_metric.inc();
                    if let Some(start_time) = self.timestamp {
                        tracing::warn!(
                            id = self.id,
                            err = ?e,
                            elapsed = ?start_time.elapsed(),
                            "triple generation failed",
                        );
                    }

                    self.slot.unreserve().await;
                    break;
                }
            };

            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let Some(msg) = self.inbox.recv().await else {
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
                    let (total_wait, total_pokes) =
                        if let Some((last_poked, total_wait, total_pokes)) = self.poked_latest {
                            (
                                total_wait + (generator_poke_time - last_poked),
                                total_pokes + 1,
                            )
                        } else {
                            let start_time = self.generator_created;
                            triple_before_poke_delay_metric
                                .observe((generator_poke_time - start_time).as_millis() as f64);
                            (Duration::from_millis(0), 1)
                        };
                    self.poked_latest = Some((Instant::now(), total_wait, total_pokes));
                    triple_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);
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

                    let (total_wait, total_pokes) =
                        if let Some((last_poked, total_wait, total_pokes)) = self.poked_latest {
                            (
                                total_wait + (generator_poke_time - last_poked),
                                total_pokes + 1,
                            )
                        } else {
                            let start_time = self.generator_created;
                            triple_before_poke_delay_metric
                                .observe((generator_poke_time - start_time).as_millis() as f64);
                            (Duration::from_millis(0), 1)
                        };
                    self.poked_latest = Some((Instant::now(), total_wait, total_pokes));
                    triple_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);
                }
                Action::Return(output) => {
                    let now = Instant::now();
                    let elapsed = self.timestamp.map(|t| now - t).unwrap_or_default();

                    triple_latency_metric.observe(elapsed.as_secs_f64());

                    // this measures from generator creation to finishing. TRIPLE_LATENCY instead starts from the first poke() on the generator
                    triple_latency_total_metric
                        .observe((now - self.generator_created).as_secs_f64());

                    triple_generator_success_metric.inc();

                    let triple = Triple {
                        id: self.id,
                        share: output.0,
                        public: output.1,
                    };

                    // After creation the triple is assigned to a random node, which is NOT necessarily the one that initiated it's creation
                    let triple_owner = {
                        // This is an entirely unpredictable value to all participants because it's a combination of big_c_i
                        // It is the same value across all participants
                        let big_c = triple.public.big_c;

                        // We turn this into a u64 in a way not biased to the structure of the byte serialisation so we hash it
                        // We use Highway Hash because the DefaultHasher doesn't guarantee a consistent output across versions
                        let entropy = HighwayHasher::default().hash64(&big_c.to_bytes()) as usize;

                        let num_participants = self.participants.len();
                        // This has a *tiny* bias towards lower indexed participants, they're up to (1 + num_participants / u64::MAX)^2 times more likely to be selected
                        // This is acceptably small that it will likely never result in a biased selection happening
                        self.participants[entropy % num_participants]
                    };
                    let triple_is_mine = triple_owner == self.me;

                    tracing::debug!(
                        id = self.id,
                        me = ?self.me,
                        ?triple_owner,
                        triple_is_mine,
                        participants = ?self.participants,
                        big_a = ?triple.public.big_a.to_base58(),
                        big_b = ?triple.public.big_b.to_base58(),
                        big_c = ?triple.public.big_c.to_base58(),
                        ?elapsed,
                        "completed triple generation"
                    );

                    if triple_is_mine {
                        triple_generator_success_mine_metric.inc();
                    }

                    self.msg.filter_triple(self.id).await;
                    self.slot.insert(triple, triple_owner).await;
                    if let Some((last_poked, total_wait, total_pokes)) = self.poked_latest {
                        let elapsed = generator_poke_time - last_poked;
                        let total_wait = total_wait + elapsed;
                        let total_pokes = total_pokes + 1;
                        triple_accrued_wait_delay_metric.observe(total_wait.as_millis() as f64);
                        triple_pokes_cnt_metric.observe(total_pokes as f64);
                    }
                    triple_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);

                    break;
                }
            }
        }
    }
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct TripleSpawner {
    /// Triple Storage that contains all triples that were generated by the us + others.
    triple_storage: TripleStorage,

    /// The set of triples that were introduced to the system by the current node.
    introduced: HashSet<TripleId>,

    /// The set of all ongoing triple generation protocols. This is a map of `TripleId` to
    /// the `JoinHandle` of the triple generation task. Calling `join_next` will wait on
    /// the next task to complete and return the result of the task. This is only restricted
    /// through max introduction and concurrent generation in the system.
    ongoing: JoinMap<TripleId, ()>,

    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
    msg: MessageChannel,
}

impl fmt::Debug for TripleSpawner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleSpawner")
            .field("introduced", &self.introduced)
            .field("me", &self.me)
            .field("threshold", &self.threshold)
            .field("epoch", &self.epoch)
            .field("my_account_id", &self.my_account_id)
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
            introduced: HashSet::new(),
            ongoing: JoinMap::new(),
            my_account_id: my_account_id.clone(),
            msg,
        }
    }

    async fn reserve(&self, id: TripleId) -> Option<TripleSlot> {
        self.triple_storage.reserve(id).await
    }

    pub async fn contains(&self, id: TripleId) -> bool {
        self.triple_storage.contains(id).await
    }

    pub async fn contains_mine(&self, id: TripleId) -> bool {
        self.triple_storage.contains_by_owner(id, self.me).await
    }

    pub async fn contains_used(&self, id: TripleId) -> bool {
        self.triple_storage.contains_used(id).await
    }

    /// Returns the number of unspent triples assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.triple_storage.len_by_owner(self.me).await
    }

    pub async fn len_ongoing(&self) -> usize {
        self.ongoing.len()
    }

    pub async fn len_introduced(&self) -> usize {
        self.introduced.len()
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        self.triple_storage.len_generated().await + self.ongoing.len()
    }

    /// Starts a new Beaver triple generation protocol.
    async fn generate(
        &mut self,
        participants: &[Participant],
        timeout: u64,
    ) -> Result<TripleId, InitializationError> {
        let id = rand::random();
        self.generate_with_id(id, participants, timeout).await?;
        Ok(id)
    }

    async fn generate_with_id(
        &mut self,
        id: TripleId,
        participants: &[Participant],
        timeout: u64,
    ) -> Result<(), InitializationError> {
        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        let Some(slot) = self.reserve(id).await else {
            tracing::warn!(id, "triple id collision");
            return Err(InitializationError::BadParameters(format!(
                "id collision: triple_id={id}"
            )));
        };

        tracing::info!(id, "starting protocol to generate a new triple");
        let generator = TripleGenerator::new(
            id,
            self.me,
            self.threshold,
            participants,
            timeout,
            slot,
            &self.msg,
        )
        .await?;

        self.ongoing
            .spawn(id, generator.run(self.my_account_id.clone(), self.epoch));
        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();

        Ok(())
    }

    /// Check if the triple id is present in the system. This includes ongoing generation protocols
    /// and the triple storage.
    pub async fn contains_id(&self, id: TripleId) -> bool {
        self.ongoing.contains_key(&id) || self.triple_storage.contains(id).await
    }

    /// Stockpile triples if the amount of unspent triples is below the minimum
    /// and the maximum number of all ongoing generation protocols is below the maximum.
    async fn stockpile(&mut self, participants: &[Participant], cfg: &ProtocolConfig) {
        let not_enough_triples = {
            // Stopgap to prevent too many triples in the system. This should be around min_triple*nodes*2
            // for good measure so that we have enough triples to do presig generation while also maintain
            // the minimum number of triples where a single node can't flood the system.
            if self.len_potential().await >= cfg.triple.max_triples as usize {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.len_mine().await < cfg.triple.min_triples as usize
                    && self.introduced.len() < cfg.max_concurrent_introduction as usize
                    && self.ongoing.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_triples {
            match self
                .generate(participants, cfg.triple.generation_timeout)
                .await
            {
                Ok(id) => {
                    self.introduced.insert(id);
                }
                Err(err) => {
                    tracing::warn!(?err, "failed to stockpile triple");
                }
            }
        }
    }

    async fn run(mut self, mesh_state: Arc<RwLock<MeshState>>, config: Arc<RwLock<Config>>) {
        let mut stockpile_interval = tokio::time::interval(Duration::from_millis(100));
        let mut start = self.msg.subscribe_triple_start().await;

        loop {
            tokio::select! {
                Some(id) = start.recv() => {
                    // TODO: with posits, this will also have the list of participants, but for now
                    // will use the mesh state.
                    let active = mesh_state.read().await.active.keys_vec();
                    let timeout = config.read().await.protocol.triple.generation_timeout;
                    if let Err(err) = self.generate_with_id(id, &active, timeout).await {
                        tracing::warn!(id, ?err, "unable to start triple generation on START");
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
                    self.introduced.remove(&id);
                }
                _ = stockpile_interval.tick() => {
                    let active = mesh_state.read().await.active.keys_vec();
                    let protocol = config.read().await.protocol.clone();
                    self.stockpile(&active, &protocol).await;

                    crate::metrics::NUM_TRIPLES_MINE
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_mine().await as i64);
                    crate::metrics::NUM_TRIPLES_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.triple_storage.len_generated().await as i64);
                    crate::metrics::NUM_TRIPLE_GENERATORS_INTRODUCED
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_introduced().await as i64);
                    crate::metrics::NUM_TRIPLE_GENERATORS_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_ongoing().await as i64);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct TripleSpawnerTask {
    handle: Arc<JoinHandle<()>>,
}

impl TripleSpawnerTask {
    pub fn run(me: Participant, threshold: usize, epoch: u64, ctx: &MpcSignProtocol) -> Self {
        let manager = TripleSpawner::new(
            me,
            threshold,
            epoch,
            &ctx.my_account_id,
            &ctx.triple_storage,
            ctx.msg_channel.clone(),
        );
        Self {
            handle: Arc::new(tokio::spawn(
                manager.run(ctx.mesh_state.clone(), ctx.config.clone()),
            )),
        }
    }

    pub fn abort(&self) {
        // NOTE: since dropping the handle here, TripleSpawner will drop their JoinSet/JoinMap
        // which will also abort all ongoing triple generation tasks. This is important to note
        // since we do not want to leak any triple generation tasks when we are resharing, and
        // potentially wasting compute.
        self.handle.abort();
    }
}
