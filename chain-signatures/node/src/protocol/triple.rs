use super::contract::primitives::Participants;
use super::cryptography::CryptographicError;
use super::message::TripleMessage;
use super::presignature::GenerationError;
use crate::storage::triple_storage::TripleStorage;
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

type GeneratorOutcome = (
    TripleId,
    Result<(Vec<(Participant, TripleMessage)>, Option<(Triple, bool)>), ProtocolError>,
);

// TODO: why do we have Clone here? Triples can not be reused.
/// A completed triple.
#[derive(Clone, Serialize, Deserialize, Debug)]
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
}

impl TripleGenerator {
    pub fn new(
        me: Participant,
        threshold: usize,
        id: TripleId,
        participants: Vec<Participant>,
        timeout: u64,
    ) -> Result<Self, InitializationError> {
        let protocol = Arc::new(RwLock::new(
            cait_sith::triples::generate_triple::<Secp256k1>(&participants, me, threshold)?,
        ));

        Ok(Self {
            id,
            participants,
            protocol,
            timestamp: Arc::new(RwLock::new(None)),
            timeout: Duration::from_millis(timeout),
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
    ) -> JoinHandle<GeneratorOutcome> {
        tokio::task::spawn({
            let mut generator = self.clone();
            let my_account_id = my_account_id.clone();
            async move { generator.execute(me, &my_account_id, epoch).await }
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
    ) -> GeneratorOutcome {
        let mut messages = Vec::new();
        loop {
            let action = match self.poke().await {
                Ok(action) => action,
                Err(e) => {
                    crate::metrics::TRIPLE_GENERATOR_FAILURES
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();

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

                    break (self.id, Err(e));
                }
            };

            match action {
                Action::Wait => {
                    tracing::debug!("triple: waiting");
                    // Retain protocol until we are finished
                    break (self.id, Ok((messages, None)));
                }
                Action::SendMany(data) => {
                    for p in &self.participants {
                        messages.push((
                            *p,
                            TripleMessage {
                                id: self.id,
                                epoch,
                                from: me,
                                data: data.clone(),
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        ))
                    }
                }
                Action::SendPrivate(p, data) => messages.push((
                    p,
                    TripleMessage {
                        id: self.id,
                        epoch,
                        from: me,
                        data,
                        timestamp: Utc::now().timestamp() as u64,
                    },
                )),
                Action::Return(output) => {
                    // elapsed = ?generator.timestamp.unwrap().elapsed(),
                    tracing::info!(
                        id = self.id,
                        ?me,
                        big_a = ?output.1.big_a.to_base58(),
                        big_b = ?output.1.big_b.to_base58(),
                        big_c = ?output.1.big_c.to_base58(),
                        "completed triple generation"
                    );

                    {
                        let timestamp = self.timestamp.read().await;
                        if let Some(start_time) = &*timestamp {
                            crate::metrics::TRIPLE_LATENCY
                                .with_label_values(&[my_account_id.as_str()])
                                .observe(start_time.elapsed().as_secs_f64());
                        }
                    }

                    crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();

                    let triple = Triple {
                        id: self.id,
                        share: output.0,
                        public: output.1,
                    };

                    // After creation the triple is assigned to a random node, which is NOT necessarily the one that initiated it's creation
                    let triple_is_mine = {
                        // This is an entirely unpredictable value to all participants because it's a combination of big_c_i
                        // It is the same value across all participants
                        let big_c = triple.public.big_c;

                        // We turn this into a u64 in a way not biased to the structure of the byte serialisation so we hash it
                        // We use Highway Hash because the DefaultHasher doesn't guarantee a consistent output across versions
                        let entropy = HighwayHasher::default().hash64(&big_c.to_bytes()) as usize;

                        let num_participants = self.participants.len();
                        // This has a *tiny* bias towards lower indexed participants, they're up to (1 + num_participants / u64::MAX)^2 times more likely to be selected
                        // This is acceptably small that it will likely never result in a biased selection happening
                        let triple_owner = self.participants[entropy % num_participants];

                        triple_owner == me
                    };

                    if triple_is_mine {
                        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS
                            .with_label_values(&[my_account_id.as_str()])
                            .inc();
                    }

                    break (self.id, Ok((messages, Some((triple, triple_is_mine)))));
                }
            }
        }
    }
}

pub struct TripleTasks {
    /// The maximum amount of time the whole of the triple tasks can take before yielding
    /// back to the main loop.
    protocol_budget: Duration,

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
    pub fn new(budget: Duration) -> Self {
        Self {
            protocol_budget: budget,
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

    pub fn entry(
        &mut self,
        me: Participant,
        threshold: usize,
        id: TripleId,
        potential_len: usize,
        cfg: &ProtocolConfig,
        participants: &Participants,
        my_account_id: &AccountId,
    ) -> Result<Option<TripleGenerator>, CryptographicError> {
        match self.generators.entry(id) {
            Entry::Vacant(e) => {
                if potential_len >= cfg.triple.max_triples as usize {
                    // We are at the maximum amount of triples, we cannot generate more. So just in case a node
                    // sends more triple generation requests, reject them and have them tiemout.
                    return Ok(None);
                }

                tracing::info!(id, "joining protocol to generate a new triple");
                let participants = participants.keys_vec();
                let generator = e.insert(TripleGenerator::new(
                    me,
                    threshold,
                    id,
                    participants,
                    cfg.triple.generation_timeout,
                )?);
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
    ) -> (
        Vec<(Triple, bool)>,
        Vec<(Participant, TripleMessage)>,
        HashMap<TripleId, ProtocolError>,
    ) {
        // Add more protocols to the ongoing pool if there is space.
        let to_generate_len = cfg.max_concurrent_generation as usize - self.ongoing.len();
        if !self.queued.is_empty() && to_generate_len > 0 {
            for _ in 0..to_generate_len {
                if let Some(id) = self.queued.pop_front() {
                    tracing::info!(id, "spawning triple generation task");
                    self.ongoing.insert(id);
                    let generator = self.generators.get(&id).unwrap();
                    self.ongoing_tasks
                        .push_back((id, generator.spawn_execution(me, my_account_id, epoch)));
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
                let generator = self.generators.get(&id).unwrap();
                self.ongoing_tasks
                    .push_back((*id, generator.spawn_execution(me, my_account_id, epoch)));
            }
        }

        let mut triples = Vec::new();
        let mut messages = Vec::new();
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
                Ok((mut msgs, triple)) => {
                    if let Some((triple, mine)) = triple {
                        self.remove(id);
                        triples.push((triple, mine));
                    }
                    messages.append(&mut msgs);
                }
                Err(e) => {
                    tracing::info!(id, ?e, "triple completed with error");
                    self.remove(id);
                    errors.insert(id, e);
                }
            }
        }

        (triples, messages, errors)
    }
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
#[derive(Clone)]
pub struct TripleManager {
    /// Triple Storage
    pub triple_storage: TripleStorage,

    /// The set of ongoing triple generation protocols.
    pub tasks: Arc<RwLock<TripleTasks>>,

    // poke_task: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// The set of triple ids that were already taken or failed. This will be maintained for at most
    /// triple timeout period just so messages are cycled through the system.
    pub gc: Arc<RwLock<HashMap<TripleId, Instant>>>,

    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub my_account_id: AccountId,
}

impl fmt::Debug for TripleManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleManager")
            .field("tasks", &self.tasks)
            .field("gc", &self.gc)
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
    ) -> Self {
        Self {
            tasks: Arc::new(RwLock::new(TripleTasks::new(Duration::from_millis(100)))),
            gc: Arc::new(RwLock::new(HashMap::new())),
            me,
            threshold,
            epoch,
            triple_storage: storage.clone(),
            my_account_id: my_account_id.clone(),
        }
    }

    pub async fn insert(&self, triple: Triple, mine: bool) {
        let id = triple.id;
        tracing::debug!(id, mine, "inserting triple");
        if let Err(e) = self.triple_storage.insert(triple, mine).await {
            tracing::warn!(?e, mine, "failed to insert triple");
        } else {
            self.gc.write().await.remove(&id);
        }
    }

    pub async fn contains(&self, id: &TripleId) -> bool {
        self.triple_storage
            .contains(id)
            .await
            .map_err(|e| tracing::warn!(?e, "failed to check if triple exists"))
            .unwrap_or(false)
    }

    pub async fn contains_mine(&self, id: &TripleId) -> bool {
        self.triple_storage
            .contains_mine(id)
            .await
            .map_err(|e| tracing::warn!(?e, "failed to check if mine triple exists"))
            .unwrap_or(false)
    }

    async fn take(&self, id: &TripleId) -> Result<Triple, GenerationError> {
        if self.contains_mine(id).await {
            tracing::error!(?id, "cannot take mine triple as foreign owned");
            return Err(GenerationError::TripleDenied(
                *id,
                "cannot take mine triple as foreign owned",
            ));
        }

        match self.triple_storage.take(id).await {
            Ok(result) => {
                self.gc.write().await.insert(*id, Instant::now());
                Ok(result)
            }
            Err(store_err) => {
                let tasks = self.tasks.read().await;
                if tasks.generators.contains_key(id) {
                    tracing::warn!(id, ?store_err, "triple is generating");
                    Err(GenerationError::TripleIsGenerating(*id))
                } else if self.gc.read().await.contains_key(id) {
                    tracing::warn!(id, ?store_err, "triple is garbage collected");
                    Err(GenerationError::TripleIsGarbageCollected(*id))
                } else {
                    tracing::warn!(id, ?store_err, "triple is missing");
                    Err(GenerationError::TripleIsMissing(*id))
                }
            }
        }
    }

    /// Take two unspent triple by theirs id with no way to return it. Only takes
    /// if both of them are present.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two(
        &self,
        id0: TripleId,
        id1: TripleId,
    ) -> Result<(Triple, Triple), GenerationError> {
        let triple_0 = self.take(&id0).await?;
        let triple_1 = match self.take(&id1).await {
            Ok(triple) => triple,
            Err(err) => {
                self.insert(triple_0, false).await;
                return Err(err);
            }
        };
        tracing::debug!(id0, id1, "took two triples");

        Ok((triple_0, triple_1))
    }

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&self) -> Option<(Triple, Triple)> {
        let triples = &self.triple_storage;
        if triples.len_mine().await.unwrap_or(0) < 2 {
            tracing::debug!("not enough mine triples");
            return None;
        }
        let triple_0 = match triples.take_mine().await {
            Ok(triple) => triple,
            Err(store_err) => {
                tracing::warn!(?store_err, "failed to take mine triple");
                return None;
            }
        };
        let triple_1 = match triples.take_mine().await {
            Ok(triple) => triple,
            Err(e) => {
                tracing::warn!(?e, "failed to take mine triple");
                self.insert(triple_0, true).await;
                return None;
            }
        };

        {
            let mut gc = self.gc.write().await;
            gc.insert(triple_0.id, Instant::now());
            gc.insert(triple_1.id, Instant::now());
        }

        tracing::debug!(triple_0.id, triple_1.id, "took two mine triples");

        Some((triple_0, triple_1))
    }

    /// Returns the number of unspent triples available in the manager.
    pub async fn len_generated(&self) -> usize {
        self.triple_storage.len_generated().await.unwrap_or(0)
    }

    /// Returns the number of unspent triples assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.triple_storage.len_mine().await.unwrap_or(0)
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

    /// Clears an entry from failed triples if that triple protocol was created more than 2 hrs ago
    pub async fn garbage_collect(&self, cfg: &ProtocolConfig) {
        let mut gc = self.gc.write().await;
        let before = gc.len();
        gc.retain(|_, timestamp| timestamp.elapsed() < Duration::from_millis(cfg.garbage_timeout));
        let garbage_collected = before.saturating_sub(gc.len());
        if garbage_collected > 0 {
            tracing::debug!("garbage collected {} triples", garbage_collected);
        }
    }

    /// Refresh item in the garbage collection. If it is present, return true and update internally
    /// the timestamp for gabage collection.
    pub async fn refresh_gc(&self, id: TripleId) -> bool {
        let mut gc = self.gc.write().await;
        let entry = gc.entry(id).and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }

    /// Starts a new Beaver triple generation protocol.
    pub async fn generate(
        &self,
        participants: &Participants,
        timeout: u64,
    ) -> Result<(), InitializationError> {
        let id = rand::random();
        let id_collision = {
            let tasks = self.tasks.read().await;
            tasks.generators.contains_key(&id)
                || self.contains(&id).await
                || self.gc.read().await.contains_key(&id)
        };

        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        if id_collision {
            tracing::warn!(id, "triple id collision");
            return Err(InitializationError::BadParameters(format!(
                "id collision: triple_id={id}"
            )));
        }

        tracing::debug!(id, "starting protocol to generate a new triple");
        let participants: Vec<_> = participants.keys().cloned().collect();
        {
            let mut tasks = self.tasks.write().await;
            tasks.generators.insert(
                id,
                TripleGenerator::new(self.me, self.threshold, id, participants, timeout)?,
            );
            tasks.queued.push_back(id);
            tasks.introduced.insert(id);
        }
        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        Ok(())
    }

    /// Stockpile triples if the amount of unspent triples is below the minimum
    /// and the maximum number of all ongoing generation protocols is below the maximum.
    pub async fn stockpile(
        &self,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Result<(), InitializationError> {
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
            tracing::debug!("not enough triples, generating");
            self.generate(participants, cfg.triple.generation_timeout)
                .await?;
        }
        Ok(())
    }

    /// Ensures that the triple with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`
    // TODO: What if the triple completed generation and is already spent?
    pub async fn get_or_start_generation(
        &self,
        id: TripleId,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Result<Option<TripleGenerator>, CryptographicError> {
        if self.contains(&id).await || self.gc.read().await.contains_key(&id) {
            Ok(None)
        } else {
            let potential_len = self.len_potential().await;
            let mut tasks = self.tasks.write().await;
            tasks.entry(
                self.me,
                self.threshold,
                id,
                potential_len,
                cfg,
                participants,
                &self.my_account_id,
            )
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub async fn poke(&self, cfg: &ProtocolConfig) -> Vec<(Participant, TripleMessage)> {
        let (triples, messages, errors) = {
            let mut tasks = self.tasks.write().await;
            tasks
                .poke(self.me, &self.my_account_id, self.epoch, cfg)
                .await
        };

        {
            let mut gc = self.gc.write().await;
            for (id, err) in errors.into_iter() {
                tracing::warn!(id, ?err, "failed to generate triple");
                gc.insert(id, Instant::now());
            }
        }

        for (triple, mine) in triples {
            self.insert(triple, mine).await;
        }

        messages
    }
}
