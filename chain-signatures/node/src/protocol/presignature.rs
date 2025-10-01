use super::message::{MessageChannel, PositMessage, PositProtocolId, PresignatureMessage};
use super::posit::{PositAction, PositInternalAction, PositManager};
use super::triple::{Triple, TripleId};
use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::MpcSignProtocol;
use crate::storage::presignature_storage::{PresignatureSlot, PresignatureStorage};
use crate::storage::triple_storage::{TriplesTaken, TriplesTakenDropper};
use crate::storage::TripleStorage;
use crate::types::{PresignatureProtocol, SecretKeyShare};
use crate::util::{AffinePointExt, JoinMap};

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::PublicKey;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time;

use near_account_id::AccountId;

/// Unique number used to identify a specific ongoing presignature generation protocol.
/// Without `PresignatureId` it would be unclear where to route incoming cait-sith presignature
/// generation messages.
pub type PresignatureId = u64;

/// The full presignature id. This encompasses the presignature id and the two triples
/// that were used to generate it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FullPresignatureId {
    id: PresignatureId,
    t0: TripleId,
    t1: TripleId,
}

impl FullPresignatureId {
    pub fn from_triples(t0: TripleId, t1: TripleId) -> Self {
        let id = hash_as_id(t0, t1);
        Self { id, t0, t1 }
    }

    pub fn validate(&self) -> bool {
        self.id == hash_as_id(self.t0, self.t1)
    }
}

/// A completed presignature.
pub struct Presignature {
    pub id: PresignatureId,
    pub output: PresignOutput<Secp256k1>,
    pub participants: Vec<Participant>,
}

impl fmt::Debug for Presignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presignature")
            .field("id", &self.id)
            .field("participants", &self.participants)
            .finish()
    }
}

impl Serialize for Presignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Presignature", 5)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("output_big_r", &self.output.big_r)?;
        state.serialize_field("output_k", &self.output.k)?;
        state.serialize_field("output_sigma", &self.output.sigma)?;
        state.serialize_field("participants", &self.participants)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Presignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PresignatureFields {
            id: PresignatureId,
            output_big_r: AffinePoint,
            output_k: Scalar,
            output_sigma: Scalar,
            participants: Vec<Participant>,
        }

        let fields = PresignatureFields::deserialize(deserializer)?;

        Ok(Self {
            id: fields.id,
            output: PresignOutput {
                big_r: fields.output_big_r,
                k: fields.output_k,
                sigma: fields.output_sigma,
            },
            participants: fields.participants,
        })
    }
}

enum GeneratorMessage {
    Posit(Participant, PositAction),
    Presignature(PresignatureMessage),
}

/// An ongoing presignature generator.
struct PresignatureGenerator {
    id: PresignatureId,
    me: Participant,
    owner: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    protocol: Option<PresignatureProtocol>,
    pending_triples: Option<PendingTriples>,
    dropper: Option<TriplesTakenDropper>,
    created: Instant,
    timeout: Duration,
    slot: Option<PresignatureSlot>,
    posit_manager: PositManager<(TripleId, TripleId)>,
    inbox: mpsc::Receiver<GeneratorMessage>,
    presignature_inbox: Option<mpsc::Receiver<PresignatureMessage>>,
    msg: MessageChannel,
}

impl PresignatureGenerator {
    pub async fn new_proposer(
        id: PresignatureId,
        me: Participant,
        threshold: usize,
        triples: TriplesTaken,
        participants: &[Participant],
        timeout: Duration,
        slot: PresignatureSlot,
        msg: &MessageChannel,
        inbox: mpsc::Receiver<GeneratorMessage>,
    ) -> Self {
        let mut sorted_participants = participants.to_vec();
        sorted_participants.sort();

        // Extract triple IDs for posit protocol
        let triple_ids = (triples.triple0.id, triples.triple1.id);
        let posit_manager = PositManager::new_proposer(me, triple_ids, participants);
        let presignature_inbox = msg.subscribe_presignature(id).await;

        Self {
            id,
            me,
            owner: me,
            threshold,
            participants: sorted_participants,
            protocol: None,
            pending_triples: Some(PendingTriples::Available(triples)),
            dropper: None,
            created: Instant::now(),
            timeout,
            slot: Some(slot),
            posit_manager,
            inbox,
            presignature_inbox: Some(presignature_inbox),
            msg: msg.clone(),
        }
    }

    pub async fn new_deliberator(
        id: PresignatureId,
        me: Participant,
        threshold: usize,
        full_id: FullPresignatureId,
        owner: Participant,
        triple_storage: TripleStorage,
        timeout: Duration,
        slot: PresignatureSlot,
        msg: &MessageChannel,
        inbox: mpsc::Receiver<GeneratorMessage>,
    ) -> Self {
        let posit_manager = PositManager::new_deliberator(me, threshold);
        let presignature_inbox = msg.subscribe_presignature(id).await;

        Self {
            id,
            me,
            owner,
            threshold,
            participants: Vec::new(),
            protocol: None,
            pending_triples: Some(PendingTriples::InStorage(full_id.t0, full_id.t1, triple_storage)),
            dropper: None,
            created: Instant::now(),
            timeout,
            slot: Some(slot),
            posit_manager,
            inbox,
            presignature_inbox: Some(presignature_inbox),
            msg: msg.clone(),
        }
    }

    /// Receive the next message for the presignature protocol; error out on the timeout being reached
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
                        tracing::warn!(id = self.id, "presignature generation timeout");
                        None
                    }
                }
            }
            result = async {
                match &mut self.presignature_inbox {
                    Some(inbox) => inbox.recv().await.map(GeneratorMessage::Presignature),
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Some(msg) => Some(msg),
                    None => {
                        tracing::warn!(id = self.id, "generator presignature channel closed");
                        None
                    }
                }
            }
        }
    }

    /// Handle a posit message. Returns true if we should proceed to the next phase.
    async fn handle_posit(&mut self, from: Participant, action: &PositAction, _epoch: u64) -> bool {
        let internal_action = self.posit_manager.act(from, action);

        match internal_action {
            PositInternalAction::None => false,
            PositInternalAction::Abort => {
                tracing::warn!(id = self.id, "presignature posit aborted");
                false
            }
            PositInternalAction::Reply(reply_action) => {
                self.msg
                    .send(
                        self.me,
                        from,
                        PositMessage {
                            id: PositProtocolId::Presignature(FullPresignatureId {
                                id: self.id,
                                t0: 0, // We don't know triple IDs as deliberator yet
                                t1: 0,
                            }),
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
                    "presignature posit reached consensus, starting protocol"
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
                                    id: PositProtocolId::Presignature(FullPresignatureId {
                                        id: self.id,
                                        t0: 0, // Will be filled in by message
                                        t1: 0,
                                    }),
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

    /// Wait for triples to become available
    async fn wait_for_triples(&mut self) -> Option<(Triple, Triple, TriplesTakenDropper)> {
        let pending = self.pending_triples.take()?;
        let triples = pending.fetch(self.me, self.owner, self.timeout).await?;
        Some(triples.take())
    }

    /// Initialize the cait-sith protocol
    async fn initialize_protocol(
        &mut self,
        triple0: Triple,
        triple1: Triple,
        dropper: TriplesTakenDropper,
        keygen_out: KeygenOutput<Secp256k1>,
    ) -> Result<(), InitializationError> {
        self.dropper = Some(dropper);

        let protocol = cait_sith::presign(
            &self.participants,
            self.me,
            &self.participants,
            self.me,
            PresignArguments {
                triple0: (triple0.share, triple0.public),
                triple1: (triple1.share, triple1.public),
                keygen_out,
                threshold: self.threshold,
            },
        )?;
        self.protocol = Some(Box::new(protocol));

        tracing::info!(id = self.id, "initialized presignature generation protocol");
        Ok(())
    }

    pub async fn run(mut self, my_account_id: AccountId, epoch: u64, keygen_out: KeygenOutput<Secp256k1>) {
        // Phase 1: Posit consensus
        loop {
            let Some(msg) = self.recv().await else {
                tracing::warn!(id = self.id, "presignature generator timeout during posit phase");
                return;
            };

            match msg {
                GeneratorMessage::Posit(from, action) => {
                    if self.handle_posit(from, &action, epoch).await {
                        // Posit consensus reached, move to triple waiting phase
                        break;
                    }
                }
                GeneratorMessage::Presignature(_) => {
                    tracing::warn!(
                        id = self.id,
                        "received presignature message before posit consensus, ignoring"
                    );
                }
            }
        }

        // Phase 2: Wait for triples to be available
        let Some((triple0, triple1, dropper)) = self.wait_for_triples().await else {
            tracing::warn!(
                id = self.id,
                "failed to acquire triples for presignature generation"
            );
            return;
        };

        // Phase 3: Initialize protocol
        if let Err(err) = self.initialize_protocol(triple0, triple1, dropper, keygen_out).await {
            tracing::warn!(
                id = self.id,
                ?err,
                "failed to initialize presignature protocol after posit consensus"
            );
            return;
        };

        // Phase 4: Run cait-sith protocol
        let me = self.me;
        let failure_counts = crate::metrics::PRESIGNATURE_GENERATOR_FAILURES
            .with_label_values(&[my_account_id.as_str()]);
        let before_first_poke_delay = crate::metrics::PRESIGNATURE_BEFORE_POKE_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let accrued_wait_delay = crate::metrics::PRESIGNATURE_ACCRUED_WAIT_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let poke_counts =
            crate::metrics::PRESIGNATURE_POKES_CNT.with_label_values(&[my_account_id.as_str()]);
        let runtime_latency =
            crate::metrics::PRESIGNATURE_LATENCY.with_label_values(&[my_account_id.as_str()]);
        let success_owned_counts: prometheus::core::GenericCounter<prometheus::core::AtomicF64> =
            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let success_total_counts =
            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let poke_latency =
            crate::metrics::PRESIGNATURE_POKE_CPU_TIME.with_label_values(&[my_account_id.as_str()]);

        let start_time = Instant::now();
        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        before_first_poke_delay.observe(self.created.elapsed().as_millis() as f64);

        loop {
            let poke_start_time = Instant::now();
            let action = match self.protocol.as_mut().expect("protocol initialized").poke() {
                Ok(action) => action,
                Err(err) => {
                    failure_counts.inc();
                    tracing::warn!(
                        id = self.id,
                        owner = ?self.owner,
                        ?err,
                        elapsed = ?start_time.elapsed(),
                        "presignature generation failed",
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
                        GeneratorMessage::Presignature(presig_msg) => {
                            self.protocol.as_mut().expect("protocol initialized").message(presig_msg.from, presig_msg.data);
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
                    let dropper = self.dropper.as_ref().expect("dropper initialized");
                    for to in &self.participants {
                        if *to == me {
                            continue;
                        }
                        self.msg
                            .send(
                                me,
                                *to,
                                PresignatureMessage {
                                    id: self.id,
                                    triple0: dropper.id0,
                                    triple1: dropper.id1,
                                    epoch,
                                    from: me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            )
                            .await;
                    }
                }
                Action::SendPrivate(to, data) => {
                    let dropper = self.dropper.as_ref().expect("dropper initialized");
                    self.msg
                        .send(
                            me,
                            to,
                            PresignatureMessage {
                                id: self.id,
                                triple0: dropper.id0,
                                triple1: dropper.id1,
                                epoch,
                                from: me,
                                data,
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                }
                Action::Return(output) => {
                    runtime_latency.observe(start_time.elapsed().as_secs_f64());
                    success_total_counts.inc();
                    accrued_wait_delay.observe(total_wait.as_millis() as f64);
                    poke_counts.observe(total_pokes as f64);

                    tracing::info!(
                        id = self.id,
                        ?me,
                        owner = ?self.owner,
                        big_r = ?output.big_r.to_base58(),
                        elapsed = ?self.created.elapsed(),
                        "completed presignature generation"
                    );
                    let presignature = Presignature {
                        id: self.id,
                        output,
                        participants: self.participants.clone(),
                    };
                    if self.owner == me {
                        tracing::info!(id = self.id, "assigning presignature to myself");
                        success_owned_counts.inc();
                    }
                    self.slot.as_mut().expect("slot initialized").insert(presignature, self.owner).await;
                    break;
                }
            }
        }
    }
}

impl Drop for PresignatureGenerator {
    fn drop(&mut self) {
        let id = self.id;
        let msg = self.msg.clone();
        tokio::spawn(async move {
            msg.unsubscribe_presignature(id).await;
            msg.filter_presignature(id).await;
        });
    }
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct PresignatureSpawner {
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    /// Ongoing presignature generation protocols.
    ongoing: JoinMap<PresignatureId, ()>,
    ongoing_owned: HashSet<PresignatureId>,

    /// Generator message channels for routing posit and presignature messages.
    /// Each generator has a sender that we use to route messages to it.
    generator_channels: HashMap<PresignatureId, mpsc::Sender<GeneratorMessage>>,

    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
    private_share: SecretKeyShare,
    public_key: PublicKey,
    msg: MessageChannel,
}

impl PresignatureSpawner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        private_share: &SecretKeyShare,
        public_key: &PublicKey,
        my_account_id: &AccountId,
        triples: &TripleStorage,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
    ) -> Self {
        Self {
            triples: triples.clone(),
            presignatures: presignatures.clone(),
            ongoing: JoinMap::new(),
            ongoing_owned: HashSet::new(),
            generator_channels: HashMap::new(),
            me,
            threshold,
            epoch,
            private_share: *private_share,
            public_key: *public_key,
            my_account_id: my_account_id.clone(),
            msg,
        }
    }

    /// Returns true if the presignature with the given id is already generated
    pub async fn contains(&self, id: PresignatureId) -> bool {
        self.presignatures.contains(id).await
    }

    /// Returns true if the mine presignature with the given id is already generated
    pub async fn contains_mine(&self, id: PresignatureId) -> bool {
        self.presignatures.contains_by_owner(id, self.me).await
    }

    /// Returns true if the presignature with the given id is already ongoing
    pub fn contains_ongoing(&self, id: PresignatureId) -> bool {
        self.ongoing.contains_key(&id)
    }

    pub async fn contains_used(&self, id: PresignatureId) -> bool {
        self.presignatures.contains_used(id).await
    }

    /// Returns the number of unspent presignatures available in the manager.
    pub async fn len_generated(&self) -> usize {
        self.presignatures.len_generated().await
    }

    /// Returns the number of unspent presignatures assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.presignatures.len_by_owner(self.me).await
    }

    pub fn len_ongoing(&self) -> usize {
        self.ongoing.len()
    }

    pub fn len_introduced(&self) -> usize {
        self.ongoing_owned.len()
    }

    /// Returns the number of unspent presignatures we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        let complete_presignatures = self.len_generated().await;
        let ongoing_generators = self.ongoing.len();
        complete_presignatures + ongoing_generators
    }

    async fn process_posit(
        &mut self,
        id: FullPresignatureId,
        from: Participant,
        action: PositAction,
        timeout: Duration,
    ) {
        // Route the message to the appropriate generator, creating one if needed
        self.route_posit_message(id, from, action, timeout).await;
    }

    /// Route a posit message to the appropriate generator, creating one if needed.
    async fn route_posit_message(&mut self, id: FullPresignatureId, from: Participant, action: PositAction, timeout: Duration) {
        // Get or create the generator channel
        if !self.generator_channels.contains_key(&id.id) {
            // First time seeing this presignature ID - create a new generator
            self.spawn_generator(id, from, &action, timeout).await;
        }

        // Route the message to the generator
        if let Some(tx) = self.generator_channels.get(&id.id) {
            if tx.send(GeneratorMessage::Posit(from, action)).await.is_err() {
                tracing::warn!(id = id.id, "failed to route posit message, generator channel closed");
                self.generator_channels.remove(&id.id);
            }
        }
    }

    /// Spawn a new generator task for this presignature ID.
    async fn spawn_generator(&mut self, id: FullPresignatureId, from: Participant, action: &PositAction, timeout: Duration) {
        // Validation 1: ID hash validation
        if !id.validate() {
            tracing::error!(
                ?id,
                "presignature id does not match the expected hash, ignoring"
            );
            return;
        }

        // Validation 2: Check if already generating
        if self.contains_ongoing(id.id) {
            tracing::warn!(
                ?id,
                "presignature already generating, ignoring"
            );
            return;
        }

        // Validation 3: Check if already exists
        if self.contains(id.id).await {
            tracing::warn!(
                ?id,
                "presignature already generated, ignoring"
            );
            return;
        }

        // Validation 4: Check required triples exist
        let triples_available = (self.triples.contains_reserved(id.t0).await
                || self.triples.contains(id.t0).await)
            && (self.triples.contains_reserved(id.t1).await
                || self.triples.contains(id.t1).await);

        if !triples_available {
            tracing::warn!(
                ?id,
                "presignature required triples are not available, ignoring"
            );
            return;
        }

        let (tx, rx) = mpsc::channel(128);
        
        let generator = if matches!(action, PositAction::Propose) && from == self.me {
            // We're proposing this presignature - need to get the triples
            tracing::info!(id = id.id, "spawning presignature generator as proposer");
            
            let Some(triples) = self.triples.take_two(id.t0, id.t1, self.me, self.me).await else {
                tracing::warn!(id = id.id, "failed to take triples for presignature");
                return;
            };

            let participants: Vec<Participant> = match action {
                PositAction::Start(parts) => parts.clone(),
                _ => {
                    tracing::warn!(id = id.id, "proposer received non-Start action, using empty participants");
                    vec![]
                }
            };

            let Some(slot) = self.presignatures.reserve(id.id).await else {
                tracing::error!(id = id.id, "id collision: failed to reserve presignature slot");
                return;
            };
            
            self.ongoing_owned.insert(id.id);
            PresignatureGenerator::new_proposer(
                id.id,
                self.me,
                self.threshold,
                triples,
                &participants,
                timeout,
                slot,
                &self.msg,
                rx,
            ).await
        } else {
            // We're a deliberator
            tracing::info!(id = id.id, ?from, "spawning presignature generator as deliberator");
            
            let Some(slot) = self.presignatures.reserve(id.id).await else {
                tracing::error!(id = id.id, "id collision: failed to reserve presignature slot");
                return;
            };

            PresignatureGenerator::new_deliberator(
                id.id,
                self.me,
                self.threshold,
                id,
                from,  // owner is the proposer
                self.triples.clone(),
                timeout,
                slot,
                &self.msg,
                rx,
            ).await
        };

        let keygen_out = KeygenOutput {
            private_share: self.private_share,
            public_key: self.public_key,
        };

        self.generator_channels.insert(id.id, tx);
        self.ongoing.spawn(
            id.id,
            generator.run(self.my_account_id.clone(), self.epoch, keygen_out),
        );
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        if from == self.me {
            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE
                .with_label_values(&[self.my_account_id.as_str()])
                .inc();
        }
    }

    /// Starts a new presignature generation protocol.
    async fn propose_posit(&mut self, active: &[Participant], timeout: Duration) {
        // To ensure there is no contention between different nodes we are only using triples
        // that we proposed. This way in a non-BFT environment we are guaranteed to never try
        // to use the same triple as any other node.
        let Some(triples) = self.triples.take_two_mine(self.me).await else {
            return;
        };

        let t0 = triples.triple0.id;
        let t1 = triples.triple1.id;
        let participants = intersect_vec(&[
            active,
            &triples.triple0.public.participants,
            &triples.triple1.public.participants,
        ]);
        if participants.len() < self.threshold {
            tracing::warn!(
                intersection = ?participants,
                ?participants,
                triple0 = ?(t0, &triples.triple0.public.participants),
                triple1 = ?(t1, &triples.triple1.public.participants),
                "intersection < threshold, trashing two triples"
            );
            return;
        }

        let id = FullPresignatureId::from_triples(t0, t1);
        tracing::info!(
            ?id,
            t0,
            t1,
            "proposing protocol to generate a new presignature"
        );

        // Create the generator channel and spawn the proposer
        let (tx, rx) = mpsc::channel(128);
        
        let Some(slot) = self.presignatures.reserve(id.id).await else {
            tracing::error!(id = id.id, "id collision: failed to reserve presignature slot");
            return;
        };

        let generator = PresignatureGenerator::new_proposer(
            id.id,
            self.me,
            self.threshold,
            triples,
            &participants,
            timeout,
            slot,
            &self.msg,
            rx,
        ).await;

        let keygen_out = KeygenOutput {
            private_share: self.private_share,
            public_key: self.public_key,
        };

        self.generator_channels.insert(id.id, tx.clone());
        self.ongoing_owned.insert(id.id);
        self.ongoing.spawn(
            id.id,
            generator.run(self.my_account_id.clone(), self.epoch, keygen_out),
        );
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();

        // Send initial Propose messages to all participants
        for &p in participants.iter() {
            if p == self.me {
                // Send to ourselves through the channel
                let _ = tx.send(GeneratorMessage::Posit(self.me, PositAction::Propose)).await;
            } else {
                self.msg
                    .send(
                        self.me,
                        p,
                        PositMessage {
                            id: PositProtocolId::Presignature(id),
                            from: self.me,
                            action: PositAction::Propose,
                        },
                    )
                    .await;
            }
        }
    }

    async fn stockpile(&mut self, active: &[Participant], cfg: &ProtocolConfig) {
        let not_enough_presignatures = {
            // Stopgap to prevent too many presignatures in the system. This should be around min_presig*nodes*2
            // for good measure so that we have enough presignatures to do sig generation while also maintain
            // the minimum number of presignature where a single node can't flood the system.
            if self.len_potential().await >= cfg.presignature.max_presignatures as usize {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.len_mine().await < cfg.presignature.min_presignatures as usize
                    && self.len_introduced() < cfg.max_concurrent_introduction as usize
                    && self.ongoing.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_presignatures {
            tracing::debug!("not enough presignatures, generating");
            self.propose_posit(active, Duration::from_millis(cfg.presignature.generation_timeout)).await;
        }
    }

    async fn run(
        mut self,
        mesh_state: watch::Receiver<MeshState>,
        config: watch::Receiver<Config>,
        ongoing_gen_tx: watch::Sender<usize>,
    ) {
        let mut stockpile_interval = time::interval(Duration::from_millis(100));
        let mut _expiration_interval = tokio::time::interval(Duration::from_secs(20));
        let mut posits = self.msg.subscribe_presignature_posit().await;

        loop {
            tokio::select! {
                Some((id, from, action)) = posits.recv() => {
                    let timeout = config.borrow().protocol.presignature.generation_timeout;
                    self.process_posit(id, from, action, Duration::from_millis(timeout)).await;
                }
                // `join_next` returns None on the set being empty, so don't handle that case
                Some(result) = self.ongoing.join_next(), if !self.ongoing.is_empty() => {
                    let id = match result {
                        Ok((id, ())) => id,
                        Err(id) => {
                            tracing::warn!(id, "presignature generation task interrupted");
                            id
                        }
                    };
                    // Clean up the generator channel
                    self.generator_channels.remove(&id);
                    self.ongoing_owned.remove(&id);
                    let _ = ongoing_gen_tx.send(self.ongoing.len());
                }
                _ = stockpile_interval.tick() => {
                    let active = mesh_state.borrow().active.keys_vec();
                    let protocol_cfg = config.borrow().protocol.clone();
                    self.stockpile(&active, &protocol_cfg).await;
                    let _ = ongoing_gen_tx.send(self.ongoing.len());

                    crate::metrics::NUM_PRESIGNATURES_MINE
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_mine().await as i64);
                    crate::metrics::NUM_PRESIGNATURES_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_generated().await as i64);
                    crate::metrics::NUM_PRESIGNATURE_GENERATORS_TOTAL
                        .with_label_values(&[self.my_account_id.as_str()])
                        .set(self.len_potential().await as i64 - self.len_generated().await as i64);
                }
            }
        }
    }
}

impl Drop for PresignatureSpawner {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        tokio::spawn(msg.unsubscribe_presignature_posit());
    }
}

pub fn hash_as_id(triple0: TripleId, triple1: TripleId) -> PresignatureId {
    let mut hasher = Sha3_256::new();
    hasher.update(triple0.to_le_bytes());
    hasher.update(triple1.to_le_bytes());
    let id: [u8; 32] = hasher.finalize().into();
    let id = u64::from_le_bytes(crate::util::first_8_bytes(id));

    PresignatureId::from(id)
}

pub struct PresignatureSpawnerTask {
    ongoing_gen_rx: watch::Receiver<usize>,
    handle: JoinHandle<()>,
}

impl PresignatureSpawnerTask {
    pub fn run(
        me: Participant,
        threshold: usize,
        epoch: u64,
        ctx: &MpcSignProtocol,
        private_share: &SecretKeyShare,
        public_key: &PublicKey,
    ) -> Self {
        let (ongoing_gen_tx, ongoing_gen_rx) = watch::channel(0);
        let spawner = PresignatureSpawner::new(
            me,
            threshold,
            epoch,
            private_share,
            public_key,
            &ctx.my_account_id,
            &ctx.triple_storage,
            &ctx.presignature_storage,
            ctx.msg_channel.clone(),
        );

        Self {
            ongoing_gen_rx,
            handle: tokio::spawn(spawner.run(
                ctx.mesh_state.clone(),
                ctx.config.clone(),
                ongoing_gen_tx,
            )),
        }
    }

    pub fn len_ongoing(&self) -> usize {
        // NOTE: no need to call `chaned` or `borrow_and_update` here, since we only want to
        // observe whatever is the latest value in the channel. This is not meant to wait for
        // the next updated value.
        *self.ongoing_gen_rx.borrow()
    }

    pub fn abort(&self) {
        // NOTE: since dropping the handle here, PresignatureSpawner will drop their JoinSet/JoinMap
        // which will also abort all ongoing presignature generation tasks. This is important to note
        // since we do not want to leak any presignature generation tasks when we are resharing, and
        // potentially wasting compute.
        self.handle.abort();
    }
}

impl Drop for PresignatureSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Represents two triples that are either available immediately or will eventually be available within
/// the storage, in which case the `fetch` method will block until they are available alongside a timeout.
#[allow(clippy::large_enum_variant)]
enum PendingTriples {
    Available(TriplesTaken),
    InStorage(TripleId, TripleId, TripleStorage),
}

impl PendingTriples {
    async fn fetch(
        self,
        me: Participant,
        owner: Participant,
        timeout: Duration,
    ) -> Option<TriplesTaken> {
        let (id0, id1, storage) = match self {
            Self::InStorage(id0, id1, storage) => (id0, id1, storage),
            Self::Available(triples) => return Some(triples),
        };

        let triples = tokio::time::timeout(timeout, async {
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            loop {
                interval.tick().await;
                if let Some(triples) = storage.take_two(id0, id1, owner, me).await {
                    break triples;
                };
            }
        })
        .await;

        match triples {
            Ok(triples) => Some(triples),
            Err(_) => {
                tracing::warn!(id0, id1, "timeout waiting for triples to be available");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use cait_sith::{protocol::Participant, PresignOutput};
    use k256::{elliptic_curve::CurveArithmetic, Secp256k1};

    use crate::protocol::presignature::Presignature;

    #[tokio::test]
    async fn test_presignature_serialize_deserialize() {
        let presignature = Presignature {
            id: 1,
            output: PresignOutput {
                big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
                k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
                sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
            },
            participants: vec![Participant::from(1), Participant::from(2)],
        };

        // Serialize Presignature to JSON
        let serialized =
            serde_json::to_string(&presignature).expect("Failed to serialize Presignature");

        // Deserialize JSON back to Presignature
        let deserialized: Presignature =
            serde_json::from_str(&serialized).expect("Failed to deserialize Presignature");

        // Assert that the original and deserialized Presignature are equal
        assert_eq!(presignature.id, deserialized.id);
        assert_eq!(presignature.output.big_r, deserialized.output.big_r);
        assert_eq!(presignature.output.k, deserialized.output.k);
        assert_eq!(presignature.output.sigma, deserialized.output.sigma);
        assert_eq!(presignature.participants, deserialized.participants);
    }
}
