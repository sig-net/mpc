use super::message::{MessageChannel, PositMessage, PositProtocolId, TripleMessage};
use super::posit::{PositAction, PositInternalAction, PositManager};
use super::MpcSignProtocol;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::storage::triple_storage::{TripleSlot, TripleStorage};
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

use std::collections::{HashMap, HashSet};
use std::fmt;
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

enum GeneratorMessage {
    Posit(Participant, PositAction),
    Triple(TripleMessage),
}

struct TripleGenerator {
    id: TripleId,
    me: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    protocol: Option<TripleProtocol>,
    timeout: Duration,
    slot: Option<TripleSlot>,
    created: Instant,
    posit_manager: PositManager<()>,
    inbox: mpsc::Receiver<GeneratorMessage>,
    triple_inbox: Option<mpsc::Receiver<TripleMessage>>,
    msg: MessageChannel,
}

impl TripleGenerator {
    pub async fn new_proposer(
        id: TripleId,
        me: Participant,
        threshold: usize,
        participants: &[Participant],
        timeout: Duration,
        msg: &MessageChannel,
        inbox: mpsc::Receiver<GeneratorMessage>,
    ) -> Self {
        let mut sorted_participants = participants.to_vec();
        sorted_participants.sort();

        let posit_manager = PositManager::new_proposer(me, (), participants);

        // Subscribe to triple protocol messages for this specific ID
        let triple_inbox = msg.subscribe_triple(id).await;

        Self {
            id,
            me,
            threshold,
            participants: sorted_participants,
            protocol: None,
            timeout,
            slot: None,
            created: Instant::now(),
            posit_manager,
            inbox,
            triple_inbox: Some(triple_inbox),
            msg: msg.clone(),
        }
    }

    pub async fn new_deliberator(
        id: TripleId,
        me: Participant,
        threshold: usize,
        timeout: Duration,
        msg: &MessageChannel,
        inbox: mpsc::Receiver<GeneratorMessage>,
    ) -> Self {
        let posit_manager = PositManager::new_deliberator(me, threshold);

        // Subscribe to triple protocol messages for this specific ID
        let triple_inbox = msg.subscribe_triple(id).await;

        Self {
            id,
            me,
            threshold,
            participants: Vec::new(),
            protocol: None,
            timeout,
            slot: None,
            created: Instant::now(),
            posit_manager,
            inbox,
            triple_inbox: Some(triple_inbox),
            msg: msg.clone(),
        }
    }

    /// Receive the next message for the triple protocol; error out on the timeout being reached
    /// or the channel having been closed (aborted).
    async fn recv(&mut self) -> Option<GeneratorMessage> {
        let timeout_duration = self.timeout.saturating_sub(self.created.elapsed());
        
        tokio::select! {
            result = tokio::time::timeout(timeout_duration, self.inbox.recv()) => {
                match result {
                    Ok(Some(msg)) => Some(msg),
                    Ok(None) => {
                        tracing::warn!(id = self.id, "generator posit channel closed");
                        None
                    }
                    Err(_) => {
                        tracing::warn!(id = self.id, "triple generation timeout");
                        None
                    }
                }
            }
            result = async {
                match &mut self.triple_inbox {
                    Some(inbox) => inbox.recv().await.map(GeneratorMessage::Triple),
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Some(msg) => Some(msg),
                    None => {
                        tracing::warn!(id = self.id, "generator triple channel closed");
                        None
                    }
                }
            }
        }
    }

    /// Handle a posit message. Returns true if we should start protocol generation.
    async fn handle_posit(&mut self, from: Participant, action: &PositAction, epoch: u64) -> bool {
        let internal_action = self.posit_manager.act(from, action);

        match internal_action {
            PositInternalAction::None => false,
            PositInternalAction::Abort => {
                tracing::warn!(id = self.id, "triple posit aborted");
                false
            }
            PositInternalAction::Reply(reply_action) => {
                self.msg
                    .send(
                        self.me,
                        from,
                        PositMessage {
                            id: PositProtocolId::Triple(self.id),
                            from: self.me,
                            action: reply_action,
                        },
                    )
                    .await;
                false
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                tracing::info!(
                    id = self.id,
                    is_proposer = positor.is_proposer(),
                    "triple posit reached consensus, starting protocol"
                );
                
                // If we're the proposer, send Start messages to all participants
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
                                    id: PositProtocolId::Triple(self.id),
                                    from: self.me,
                                    action: PositAction::Start(participants.clone()),
                                },
                            )
                            .await;
                    }
                }
                
                self.participants = participants;
                self.participants.sort();
                true
            }
        }
    }

    /// Initialize the cait-sith protocol and reserve a storage slot.
    async fn initialize_protocol(&mut self, storage: &TripleStorage) -> Result<(), InitializationError> {
        // Reserve storage slot
        let Some(slot) = storage.reserve(self.id).await else {
            return Err(InitializationError::BadParameters(format!(
                "id collision: triple_id={}",
                self.id
            )));
        };
        self.slot = Some(slot);

        // Initialize cait-sith protocol
        let protocol = cait_sith::triples::generate_triple::<Secp256k1>(
            &self.participants,
            self.me,
            self.threshold,
        )?;
        self.protocol = Some(Box::new(protocol));

        tracing::info!(id = self.id, "initialized triple generation protocol");
        Ok(())
    }

    async fn run(mut self, my_account_id: AccountId, epoch: u64, storage: TripleStorage) {
        // Phase 1: Posit consensus
        loop {
            let Some(msg) = self.recv().await else {
                tracing::warn!(id = self.id, "triple generator timeout during posit phase");
                return;
            };

            match msg {
                GeneratorMessage::Posit(from, action) => {
                    if self.handle_posit(from, &action, epoch).await {
                        // Posit consensus reached, move to protocol phase
                        break;
                    }
                }
                GeneratorMessage::Triple(_) => {
                    tracing::warn!(
                        id = self.id,
                        "received triple message before posit consensus, ignoring"
                    );
                }
            }
        }

        // Phase 2: Initialize protocol
        if let Err(err) = self.initialize_protocol(&storage).await {
            tracing::warn!(
                id = self.id,
                ?err,
                "failed to initialize triple protocol after posit consensus"
            );
            return;
        }

        // Phase 3: Run cait-sith protocol
        let before_first_poke_delay =
            crate::metrics::TRIPLE_BEFORE_POKE_DELAY.with_label_values(&[my_account_id.as_str()]);
        let accrued_wait_delay =
            crate::metrics::TRIPLE_ACCRUED_WAIT_DELAY.with_label_values(&[my_account_id.as_str()]);
        let runtime_latency =
            crate::metrics::TRIPLE_LATENCY.with_label_values(&[my_account_id.as_str()]);
        let total_latency =
            crate::metrics::TRIPLE_LATENCY_TOTAL.with_label_values(&[my_account_id.as_str()]);
        let poke_latency =
            crate::metrics::TRIPLE_POKE_CPU_TIME.with_label_values(&[my_account_id.as_str()]);
        let poke_counts =
            crate::metrics::TRIPLE_POKES_CNT.with_label_values(&[my_account_id.as_str()]);
        let success_owned_counts =
            crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let success_total_counts = crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS
            .with_label_values(&[my_account_id.as_str()]);
        let failure_counts =
            crate::metrics::TRIPLE_GENERATOR_FAILURES.with_label_values(&[my_account_id.as_str()]);

        let start_time = Instant::now();
        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        before_first_poke_delay.observe(self.created.elapsed().as_millis() as f64);

        loop {
            let poke_start_time = Instant::now();
            let action = match self.protocol.as_mut().expect("protocol initialized").poke() {
                Ok(action) => {
                    tracing::debug!(id = self.id, ?action, "protocol poke returned action");
                    action
                }
                Err(err) => {
                    failure_counts.inc();
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

            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let Some(msg) = self.recv().await else {
                        failure_counts.inc();
                        break;
                    };
                    
                    match msg {
                        GeneratorMessage::Triple(triple_msg) => {
                            tracing::debug!(
                                id = self.id,
                                from = ?triple_msg.from,
                                "received triple protocol message"
                            );
                            self.protocol.as_mut().expect("protocol initialized").message(triple_msg.from, triple_msg.data);
                        }
                        GeneratorMessage::Posit(from, _) => {
                            tracing::debug!(
                                id = self.id,
                                ?from,
                                "received posit message during protocol execution, ignoring"
                            );
                        }
                    }
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
                Action::Return(output) => {
                    success_total_counts.inc();
                    runtime_latency.observe(start_time.elapsed().as_secs_f64());
                    // this measures from generator creation to finishing. TRIPLE_LATENCY instead starts from the first poke() on the generator
                    total_latency.observe(self.created.elapsed().as_secs_f64());
                    accrued_wait_delay.observe(total_wait.as_millis() as f64);
                    poke_counts.observe(total_pokes as f64);

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
                        elapsed = ?self.created.elapsed(),
                        "completed triple generation"
                    );

                    if triple_is_mine {
                        success_owned_counts.inc();
                    }

                    let mut slot = self.slot.take().expect("slot initialized");
                    slot.insert(triple, triple_owner).await;
                    break;
                }
            }
        }
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

    /// Generator message channels for routing posit and triple messages.
    /// Each generator has a sender that we use to route messages to it.
    generator_channels: HashMap<TripleId, mpsc::Sender<GeneratorMessage>>,

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
            generator_channels: HashMap::new(),
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
        self.ongoing_introduced.len()
    }

    /// Route a posit message to the appropriate generator, creating one if needed.
    async fn route_posit_message(&mut self, id: TripleId, from: Participant, action: PositAction, timeout: Duration) {
        // Get or create the generator channel
        if !self.generator_channels.contains_key(&id) {
            // First time seeing this triple ID - create a new generator
            self.spawn_generator(id, from, &action, timeout).await;
        }

        // Route the message to the generator
        if let Some(tx) = self.generator_channels.get(&id) {
            if tx.send(GeneratorMessage::Posit(from, action)).await.is_err() {
                tracing::warn!(id, "failed to route posit message, generator channel closed");
                self.generator_channels.remove(&id);
            }
        }
    }

    /// Spawn a new generator task for this triple ID.
    async fn spawn_generator(&mut self, id: TripleId, from: Participant, action: &PositAction, timeout: Duration) {
        let (tx, rx) = mpsc::channel(128);
        
        let generator = if matches!(action, PositAction::Propose) && from == self.me {
            // We're proposing this triple
            tracing::info!(id, "spawning triple generator as proposer");
            let participants: Vec<Participant> = match action {
                PositAction::Start(parts) => parts.clone(),
                _ => {
                    tracing::warn!(id, "proposer received non-Start action, using empty participants");
                    vec![]
                }
            };
            
            self.ongoing_introduced.insert(id);
            TripleGenerator::new_proposer(
                id,
                self.me,
                self.threshold,
                &participants,
                Duration::from_millis(timeout.as_millis() as u64),
                &self.msg,
                rx,
            ).await
        } else {
            // We're a deliberator
            tracing::info!(id, ?from, "spawning triple generator as deliberator");
            TripleGenerator::new_deliberator(
                id,
                self.me,
                self.threshold,
                Duration::from_millis(timeout.as_millis() as u64),
                &self.msg,
                rx,
            ).await
        };

        self.generator_channels.insert(id, tx);
        self.ongoing.spawn(
            id,
            generator.run(self.my_account_id.clone(), self.epoch, self.triple_storage.clone()),
        );
        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
    }

    /// Propose a new triple generation protocol to the network.
    async fn propose_triple(&mut self, active: &[Participant], timeout: Duration) {
        let id = rand::random();
        
        // Spawn proposer generator
        let (tx, rx) = mpsc::channel(128);
        let generator = TripleGenerator::new_proposer(
            id,
            self.me,
            self.threshold,
            active,
            timeout,
            &self.msg,
            rx,
        ).await;
        
        self.generator_channels.insert(id, tx.clone());
        self.ongoing_introduced.insert(id);
        self.ongoing.spawn(
            id,
            generator.run(self.my_account_id.clone(), self.epoch, self.triple_storage.clone()),
        );
        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();

        // Send initial Propose messages to all participants
        for &p in active.iter() {
            if p == self.me {
                // Send to ourselves through the channel
                let _ = tx.send(GeneratorMessage::Posit(self.me, PositAction::Propose)).await;
            } else {
                self.msg
                    .send(
                        self.me,
                        p,
                        PositMessage {
                            id: PositProtocolId::Triple(id),
                            from: self.me,
                            action: PositAction::Propose,
                        },
                    )
                    .await;
            }
        }
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        self.triple_storage.len_generated().await + self.ongoing.len()
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
            let timeout = Duration::from_millis(cfg.triple.generation_timeout);
            self.propose_triple(participants, timeout).await;
        }
    }

    async fn run(
        mut self,
        mesh_state: watch::Receiver<MeshState>,
        config: watch::Receiver<Config>,
        ongoing_gen_tx: watch::Sender<usize>,
    ) {
        let mut stockpile_interval = tokio::time::interval(Duration::from_millis(100));
        let mut posit_messages = self.msg.subscribe_triple_posit().await;

        loop {
            tokio::select! {
                // Route posit messages to generators
                Some((id, from, action)) = posit_messages.recv() => {
                    let timeout = config.borrow().protocol.triple.generation_timeout;
                    self.route_posit_message(id, from, action, Duration::from_millis(timeout)).await;
                }
                // Handle completed generators
                Some(result) = self.ongoing.join_next(), if !self.ongoing.is_empty() => {
                    let id = match result {
                        Ok((id, ())) => {
                            tracing::info!(id, "triple generation completed successfully");
                            id
                        }
                        Err(id) => {
                            tracing::warn!(id, "triple generation task interrupted");
                            id
                        }
                    };
                    self.ongoing_introduced.remove(&id);
                    self.generator_channels.remove(&id);
                    let _ = ongoing_gen_tx.send(self.ongoing.len());
                }
                // Stockpile triples periodically
                _ = stockpile_interval.tick() => {
                    let active = mesh_state.borrow().active.keys_vec();
                    let protocol = config.borrow().protocol.clone();
                    self.stockpile(&active, &protocol).await;
                    let _ = ongoing_gen_tx.send(self.ongoing.len());

                    crate::metrics::NUM_TRIPLES_MINE
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_mine().await as i64);
                    crate::metrics::NUM_TRIPLES_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.triple_storage.len_generated().await as i64);
                    crate::metrics::NUM_TRIPLE_GENERATORS_INTRODUCED
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_introduced() as i64);
                    crate::metrics::NUM_TRIPLE_GENERATORS_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_ongoing() as i64);
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
