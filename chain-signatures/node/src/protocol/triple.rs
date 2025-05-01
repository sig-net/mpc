use super::cryptography::CryptographicError;
use super::message::{MessageChannel, TripleMessage};
use crate::protocol::error::GenerationError;
use crate::storage::triple_storage::{TripleSlot, TripleStorage, TriplesTaken};
use crate::types::TripleProtocol;
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, InitializationError, MessageData, Participant, ProtocolError};
use cait_sith::triples::{TripleGenerationOutput, TriplePub, TripleShare};
use chrono::Utc;
use highway::{HighwayHash, HighwayHasher};
use k256::elliptic_curve::group::GroupEncoding;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use near_account_id::AccountId;

/// Unique number used to identify a specific ongoing triple generation protocol.
/// Without `TripleId` it would be unclear where to route incoming cait-sith triple generation
/// messages.
pub type TripleId = u64;

type GeneratorOutcome = (TripleId, Result<bool, ProtocolError>);

/// A completed triple.
#[derive(Serialize, Deserialize, Debug)]
pub struct Triple {
    pub id: TripleId,
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

#[derive(Clone)]
pub struct TripleGenerator {
    pub id: TripleId,
    pub participants: Vec<Participant>,
    pub protocol: Arc<TripleProtocol>,
    pub timestamp: Arc<RwLock<Option<Instant>>>,
    pub timeout: Duration,
    slot: TripleSlot,
    poked_latest: Arc<RwLock<Option<(Instant, Duration, u64)>>>,
    generator_created: Instant,
}

impl TripleGenerator {
    pub async fn new(
        id: TripleId,
        me: Participant,
        threshold: usize,
        participants: &[Participant],
        timeout: u64,
        slot: TripleSlot,
    ) -> Result<Self, InitializationError> {
        let mut participants = participants.to_vec();

        // Participants can be out of order, so let's sort them before doing anything. Critical
        // for the triple_is_mine check:
        participants.sort();
        let protocol =
            match cait_sith::triples::generate_triple::<Secp256k1>(&participants, me, threshold) {
                Ok(protocol) => protocol,
                Err(e) => {
                    slot.unreserve().await;
                    return Err(e);
                }
            };
        let protocol = Arc::new(RwLock::new(protocol));

        Ok(Self {
            id,
            participants,
            protocol,
            timestamp: Arc::new(RwLock::new(None)),
            timeout: Duration::from_millis(timeout),
            slot,
            poked_latest: Arc::new(RwLock::new(None)),
            generator_created: Instant::now(),
        })
    }

    pub async fn message(&self, from: Participant, data: MessageData) {
        let mut protocol = self.protocol.write().await;
        protocol.message(from, data);
    }

    pub async fn messages(&self, from: Participant, data: Vec<MessageData>) {
        let mut protocol = self.protocol.write().await;
        for data in data {
            protocol.message(from, data);
        }
    }

    pub fn spawn_execution(
        &self,
        me: Participant,
        my_account_id: &AccountId,
        epoch: u64,
        channel: MessageChannel,
    ) -> JoinHandle<GeneratorOutcome> {
        tokio::task::spawn({
            let mut generator = self.clone();
            let my_account_id = my_account_id.clone();
            async move { generator.execute(me, &my_account_id, epoch, channel).await }
        })
    }

    async fn poke(&mut self) -> Result<Action<TripleGenerationOutput<Secp256k1>>, ProtocolError> {
        let elapsed = {
            let mut timestamp = self.timestamp.write().await;
            let timestamp = timestamp.get_or_insert_with(Instant::now);
            timestamp.elapsed()
        };
        if elapsed > self.timeout {
            tracing::warn!(id = self.id, ?elapsed, "triple protocol timed out");
            return Err(ProtocolError::Other(
                anyhow::anyhow!("triple protocol timed out").into(),
            ));
        }

        let mut protocol = self.protocol.write().await;
        protocol.poke()
    }

    async fn execute(
        &mut self,
        me: Participant,
        my_account_id: &AccountId,
        epoch: u64,
        msg: MessageChannel,
    ) -> GeneratorOutcome {
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

                    {
                        let timestamp = self.timestamp.read().await;
                        if let Some(start_time) = &*timestamp {
                            tracing::warn!(
                                id = self.id,
                                err = ?e,
                                elapsed = ?start_time.elapsed(),
                                "triple failed"
                            );
                        }
                    }

                    self.slot.unreserve().await;
                    break (self.id, Err(e));
                }
            };

            match action {
                Action::Wait => {
                    // Retain protocol until we are finished
                    break (self.id, Ok(false));
                }
                Action::SendMany(data) => {
                    for to in &self.participants {
                        if *to == me {
                            continue;
                        }

                        msg.send(
                            me,
                            *to,
                            TripleMessage {
                                id: self.id,
                                epoch,
                                from: me,
                                data: data.clone(),
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                    }
                    {
                        let mut poked_latest = self.poked_latest.write().await;
                        let (total_wait, total_pokes) =
                            if let Some((last_poked, total_wait, total_pokes)) = *poked_latest {
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
                        *poked_latest = Some((Instant::now(), total_wait, total_pokes));
                    }
                    triple_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);
                }
                Action::SendPrivate(to, data) => {
                    msg.send(
                        me,
                        to,
                        TripleMessage {
                            id: self.id,
                            epoch,
                            from: me,
                            data: data.clone(),
                            timestamp: Utc::now().timestamp() as u64,
                        },
                    )
                    .await;
                    {
                        let mut poked_latest = self.poked_latest.write().await;
                        let (total_wait, total_pokes) =
                            if let Some((last_poked, total_wait, total_pokes)) = *poked_latest {
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
                        *poked_latest = Some((Instant::now(), total_wait, total_pokes));
                    }
                    triple_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);
                }
                Action::Return(output) => {
                    let now = Instant::now();
                    let elapsed = {
                        let timestamp = self.timestamp.read().await;
                        timestamp.map(|t| now - t).unwrap_or_default()
                    };

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
                    let triple_is_mine = triple_owner == me;

                    tracing::info!(
                        id = self.id,
                        ?me,
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

                    msg.filter_triple(self.id).await;
                    self.slot.insert(triple, triple_owner).await;
                    {
                        let poked_latest = self.poked_latest.read().await;
                        if let Some((last_poked, total_wait, total_pokes)) = *poked_latest {
                            let elapsed = generator_poke_time - last_poked;
                            let total_wait = total_wait + elapsed;
                            let total_pokes = total_pokes + 1;
                            triple_accrued_wait_delay_metric.observe(total_wait.as_millis() as f64);
                            triple_pokes_cnt_metric.observe(total_pokes as f64);
                        }
                    }
                    triple_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);

                    break (self.id, Ok(true));
                }
            }
        }
    }
}

pub struct TripleTasks {
    /// The maximum amount of time the whole of the triple tasks can take before yielding
    /// back to the main loop.
    protocol_budget: Duration,

    /// The threshold for the number of participants required to generate a triple. This is
    /// the same as the threshold for signing: we maintain a copy here for easy access.
    threshold: usize,
    msg: MessageChannel,

    storage: TripleStorage,

    /// The pool of triple protocols that have yet to be completed.
    pub generators: HashMap<TripleId, TripleGenerator>,

    /// Triples that are queued to be poked. If these generators sit for too long in
    /// the queue, they will be removed due to triple generation timeout.
    pub queued: VecDeque<TripleId>,

    /// Ongoing triple generation protocols. Once added here, they will not be removed until
    /// they are completed or timed out.
    pub ongoing: HashSet<TripleId>,

    /// The set of ongoing triple generation tasks.
    pub ongoing_tasks: VecDeque<(TripleId, JoinHandle<GeneratorOutcome>)>,

    /// The set of triples that were introduced to the system by the current node.
    pub introduced: HashSet<TripleId>,
}

impl std::fmt::Debug for TripleTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleTasks")
            .field("generators", &self.generators.keys().collect::<Vec<_>>())
            .field("queued", &self.queued)
            .field("ongoing", &self.ongoing)
            .field("introduced", &self.introduced)
            .finish()
    }
}

impl TripleTasks {
    pub fn new(
        threshold: usize,
        protocol_budget: Duration,
        msg: &MessageChannel,
        storage: &TripleStorage,
    ) -> Self {
        Self {
            protocol_budget,
            threshold,
            msg: msg.clone(),
            storage: storage.clone(),
            generators: HashMap::new(),
            queued: VecDeque::new(),
            ongoing: HashSet::new(),
            ongoing_tasks: VecDeque::new(),
            introduced: HashSet::new(),
        }
    }

    fn remove(&mut self, id: TripleId) {
        self.generators.remove(&id);
        self.ongoing.remove(&id);
        self.introduced.remove(&id);
    }

    pub async fn entry(
        &mut self,
        me: Participant,
        id: TripleId,
        potential_len: usize,
        cfg: &ProtocolConfig,
        participants: &[Participant],
        my_account_id: &AccountId,
    ) -> Result<Option<TripleGenerator>, CryptographicError> {
        match self.generators.entry(id) {
            Entry::Vacant(e) => {
                if potential_len >= cfg.triple.max_triples as usize {
                    // We are at the maximum amount of triples, we cannot generate more. So just in case a node
                    // sends more triple generation requests, reject them and have them tiemout.
                    return Ok(None);
                }

                let Some(slot) = self.storage.reserve(id).await else {
                    return Ok(None);
                };

                tracing::info!(id, "joining protocol to generate a new triple");
                let generator = e.insert(
                    TripleGenerator::new(
                        id,
                        me,
                        self.threshold,
                        participants,
                        cfg.triple.generation_timeout,
                        slot,
                    )
                    .await?,
                );
                self.queued.push_back(id);
                crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
                Ok(Some(generator.clone()))
            }
            Entry::Occupied(e) => Ok(Some(e.get().clone())),
        }
    }

    pub async fn poke(
        &mut self,
        me: Participant,
        my_account_id: &AccountId,
        epoch: u64,
        cfg: &ProtocolConfig,
    ) -> HashMap<TripleId, ProtocolError> {
        // Add more protocols to the ongoing pool if there is space.
        let to_generate_len = cfg.max_concurrent_generation as usize - self.ongoing.len();
        if !self.queued.is_empty() && to_generate_len > 0 {
            for _ in 0..to_generate_len {
                if let Some(id) = self.queued.pop_front() {
                    self.ongoing.insert(id);
                    let generator = self.generators.get(&id).unwrap();
                    self.ongoing_tasks.push_back((
                        id,
                        generator.spawn_execution(me, my_account_id, epoch, self.msg.clone()),
                    ));
                }
            }
        }

        // spawn these tasks again if they already completed with Action::Wait:
        for id in &self.ongoing {
            if !self
                .ongoing_tasks
                .iter()
                .any(|(running_id, _)| running_id == id)
            {
                let generator = self.generators.get(id).unwrap();
                self.ongoing_tasks.push_back((
                    *id,
                    generator.spawn_execution(me, my_account_id, epoch, self.msg.clone()),
                ));
            }
        }

        let mut errors = HashMap::new();

        let mut interval = tokio::time::interval(Duration::from_millis(5));
        let started = Instant::now();

        // Go through each running task and see if it's done. This will apply a protocol_budget which will
        // yield back control to the main loop if the time is up. If it is done, remove it from the ongoing_tasks.
        // If the TripleGenerator is not done after this, a new task will be spawned in the next iteration
        // in the case that the TripleGenerator is waiting.
        while let Some((id, task)) = self.ongoing_tasks.pop_front() {
            interval.tick().await;
            if started.elapsed() > self.protocol_budget {
                self.ongoing_tasks.push_back((id, task));
                break;
            }
            if !task.is_finished() {
                self.ongoing_tasks.push_back((id, task));
                continue;
            }

            let outcome = match task.await {
                Ok((_, result)) => result,
                Err(e) => {
                    tracing::info!(id, ?e, "triple completed with cancellation");
                    self.remove(id);
                    errors.insert(id, ProtocolError::Other(e.into()));
                    continue;
                }
            };
            match outcome {
                Ok(done) => {
                    if done {
                        self.remove(id);
                    }
                }
                Err(e) => {
                    tracing::info!(id, ?e, "triple completed with error");
                    self.remove(id);
                    errors.insert(id, e);
                }
            }
        }

        errors
    }
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
#[derive(Clone)]
pub struct TripleManager {
    /// Triple Storage
    triple_storage: TripleStorage,

    /// The set of ongoing triple generation protocols.
    tasks: Arc<RwLock<TripleTasks>>,

    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
    msg: MessageChannel,
}

impl fmt::Debug for TripleManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleManager")
            .field("tasks", &self.tasks)
            .field("me", &self.me)
            .field("threshold", &self.threshold)
            .field("epoch", &self.epoch)
            .field("my_account_id", &self.my_account_id)
            .finish()
    }
}

impl TripleManager {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        my_account_id: &AccountId,
        storage: &TripleStorage,
        msg: MessageChannel,
    ) -> Self {
        Self {
            tasks: Arc::new(RwLock::new(TripleTasks::new(
                threshold,
                Duration::from_millis(100),
                &msg,
                storage,
            ))),
            me,
            threshold,
            epoch,
            triple_storage: storage.clone(),
            my_account_id: my_account_id.clone(),
            msg,
        }
    }

    pub async fn reserve(&self, id: TripleId) -> Option<TripleSlot> {
        self.triple_storage.reserve(id).await
    }

    pub async fn contains(&self, id: TripleId) -> bool {
        self.triple_storage.contains(id).await
    }

    pub async fn contains_mine(&self, id: TripleId) -> bool {
        self.triple_storage.contains_mine(id, self.me).await
    }

    pub async fn contains_used(&self, id: TripleId) -> bool {
        self.triple_storage.contains_used(id).await
    }

    /// Take two unspent triple by theirs id with no way to return it. Only takes
    /// if both of them are present.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two(
        &self,
        id0: TripleId,
        id1: TripleId,
        owner: Participant,
    ) -> Result<TriplesTaken, GenerationError> {
        {
            let tasks = self.tasks.read().await;
            if tasks.generators.contains_key(&id0) {
                return Err(GenerationError::TripleIsGenerating(id0));
            } else if tasks.generators.contains_key(&id1) {
                return Err(GenerationError::TripleIsGenerating(id1));
            }
        }

        let triples = self
            .triple_storage
            .take_two(id0, id1, owner, self.me)
            .await
            .ok_or(GenerationError::TripleIsMissing(id0, id1))?;

        tracing::debug!(
            id0 = triples.triple0.id,
            id1 = triples.triple1.id,
            "took two triples"
        );
        Ok(triples)
    }

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&self) -> Option<TriplesTaken> {
        let triples = self.triple_storage.take_two_mine(self.me).await?;
        tracing::debug!(
            id0 = triples.triple0.id,
            id1 = triples.triple1.id,
            "took two mine triples"
        );
        Some(triples)
    }

    /// Returns the number of unspent triples available in the manager.
    pub async fn len_generated(&self) -> usize {
        self.triple_storage.len_generated().await.unwrap_or(0)
    }

    /// Returns the number of unspent triples assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.triple_storage.len_mine(self.me).await.unwrap_or(0)
    }

    pub async fn len_ongoing(&self) -> usize {
        self.tasks.read().await.ongoing.len()
    }

    pub async fn len_introduced(&self) -> usize {
        self.tasks.read().await.introduced.len()
    }

    /// Returns if there's any unspent triple in the manager.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        self.len_generated().await + self.tasks.read().await.generators.len()
    }

    pub async fn has_min_triples(&self, cfg: &ProtocolConfig) -> bool {
        self.len_mine().await >= cfg.triple.min_triples as usize
    }

    /// Starts a new Beaver triple generation protocol.
    pub async fn generate(
        &self,
        participants: &[Participant],
        timeout: u64,
    ) -> Result<(), InitializationError> {
        let id = rand::random();
        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        let Some(slot) = self.reserve(id).await else {
            tracing::warn!(id, "triple id collision");
            return Err(InitializationError::BadParameters(format!(
                "id collision: triple_id={id}"
            )));
        };

        tracing::info!(id, "starting protocol to generate a new triple");
        {
            let mut tasks = self.tasks.write().await;
            tasks.generators.insert(
                id,
                TripleGenerator::new(id, self.me, self.threshold, participants, timeout, slot)
                    .await?,
            );
            tasks.queued.push_back(id);
            tasks.introduced.insert(id);
        }
        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        Ok(())
    }

    /// Check if the triple id is present in the system. This includes ongoing generation protocols
    /// and the triple storage.
    pub async fn contains_id(&self, id: TripleId) -> bool {
        self.tasks.read().await.generators.contains_key(&id) || self.contains(id).await
    }

    /// Stockpile triples if the amount of unspent triples is below the minimum
    /// and the maximum number of all ongoing generation protocols is below the maximum.
    pub async fn stockpile(&self, participants: &[Participant], cfg: &ProtocolConfig) {
        let not_enough_triples = {
            // Stopgap to prevent too many triples in the system. This should be around min_triple*nodes*2
            // for good measure so that we have enough triples to do presig generation while also maintain
            // the minimum number of triples where a single node can't flood the system.
            if self.len_potential().await >= cfg.triple.max_triples as usize {
                false
            } else {
                let tasks = self.tasks.read().await;
                // We will always try to generate a new triple if we have less than the minimum
                self.len_mine().await < cfg.triple.min_triples as usize
                    && tasks.introduced.len() < cfg.max_concurrent_introduction as usize
                    && tasks.generators.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_triples {
            if let Err(err) = self
                .generate(participants, cfg.triple.generation_timeout)
                .await
            {
                tracing::warn!(?err, "failed to stockpile triple");
            }
        }
    }

    /// Ensures that the triple with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`
    // TODO: What if the triple completed generation and is already spent?
    pub async fn get_or_start_generation(
        &self,
        id: TripleId,
        participants: &[Participant],
        cfg: &ProtocolConfig,
    ) -> Result<Option<TripleGenerator>, CryptographicError> {
        if self.contains(id).await {
            Ok(None)
        } else {
            let potential_len = self.len_potential().await;
            let mut tasks = self.tasks.write().await;
            tasks
                .entry(
                    self.me,
                    id,
                    potential_len,
                    cfg,
                    participants,
                    &self.my_account_id,
                )
                .await
        }
    }

    pub async fn poke(&self, cfg: &ProtocolConfig) {
        let errors = {
            let mut tasks = self.tasks.write().await;
            tasks
                .poke(self.me, &self.my_account_id, self.epoch, cfg)
                .await
        };

        for (id, err) in errors.into_iter() {
            tracing::warn!(id, ?err, "failed to generate triple");
            self.msg.filter_triple(id).await;
        }
    }

    pub fn execute(self, active: &[Participant], protocol_cfg: &ProtocolConfig) -> JoinHandle<()> {
        let active = active.to_vec();
        let protocol_cfg = protocol_cfg.clone();

        tokio::task::spawn(async move {
            self.stockpile(&active, &protocol_cfg).await;
            self.poke(&protocol_cfg).await;

            crate::metrics::NUM_TRIPLES_MINE
                .with_label_values(&[self.my_account_id.as_str()])
                .set(self.len_mine().await as i64);
            crate::metrics::NUM_TRIPLES_TOTAL
                .with_label_values(&[self.my_account_id.as_str()])
                .set(self.len_generated().await as i64);
            crate::metrics::NUM_TRIPLE_GENERATORS_INTRODUCED
                .with_label_values(&[self.my_account_id.as_str()])
                .set(self.len_introduced().await as i64);
            crate::metrics::NUM_TRIPLE_GENERATORS_TOTAL
                .with_label_values(&[self.my_account_id.as_str()])
                .set(self.len_ongoing().await as i64);
        })
    }
}
