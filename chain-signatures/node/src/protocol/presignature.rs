use super::message::{MessageChannel, PositMessage, PositProtocolId, PresignatureMessage};
use super::posit::{Posit, PositAction, Positor};
use super::triple::TripleId;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::posit::PositInternalAction;
use crate::protocol::MpcSignProtocol;
use crate::storage::presignature_storage::{PresignatureSlot, PresignatureStorage};
use crate::storage::triple_storage::{TriplesTaken, TriplesTakenDropper};
use crate::storage::TripleStorage;
use crate::types::{PresignatureProtocol, SecretKeyShare};
use crate::util::{AffinePointExt, JoinMap};

use cait_sith::protocol::{Action, Participant};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::PublicKey;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
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

#[derive(Debug)]
enum PresignatureTaskAction {
    Initiate {
        triples: TriplesTaken,
        participants: Vec<Participant>,
        timeout: Duration,
    },
    Posit {
        from: Participant,
        action: PositAction,
        timeout: Duration,
    },
}

#[derive(Clone)]
struct PresignatureTaskChannel {
    id: PresignatureId,
    tx: mpsc::Sender<PresignatureTaskAction>,
}

impl PresignatureTaskChannel {
    async fn send(&self, cmd: PresignatureTaskAction) {
        if self.tx.send(cmd).await.is_err() {
            tracing::debug!(id = self.id, "presignature task aborted or channel dropped");
        }
    }
}

enum PresignatureTaskStep {
    Generate(PresignatureGenerator),
    Continue,
    Complete,
}

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

/// An ongoing presignature generator.
pub struct PresignatureGenerator {
    id: PresignatureId,
    owner: Participant,
    participants: Vec<Participant>,
    protocol: PresignatureProtocol,
    dropper: TriplesTakenDropper,
    created: Instant,
    timeout: Duration,
    slot: PresignatureSlot,
    inbox: mpsc::Receiver<PresignatureMessage>,
    msg: MessageChannel,
}

struct PresignatureTask {
    id: FullPresignatureId,
    me: Participant,
    threshold: usize,
    epoch: u64,
    private_share: SecretKeyShare,
    public_key: PublicKey,
    my_account_id: AccountId,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    msg: MessageChannel,
    action_rx: mpsc::Receiver<PresignatureTaskAction>,
    posit: Posit<FullPresignatureId, TriplesTaken>,
    generation_timeout: Option<Duration>,
    generation_started: bool,
}

impl PresignatureTask {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        id: FullPresignatureId,
        me: Participant,
        threshold: usize,
        epoch: u64,
        private_share: SecretKeyShare,
        public_key: PublicKey,
        my_account_id: &AccountId,
        triples: &TripleStorage,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
    ) -> (
        PresignatureTaskChannel,
        impl std::future::Future<Output = ()>,
    ) {
        let (tx, rx) = mpsc::channel(32);
        let handle = PresignatureTaskChannel { id: id.id, tx };
        let task = Self {
            id,
            me,
            threshold,
            epoch,
            private_share,
            public_key,
            my_account_id: my_account_id.clone(),
            triples: triples.clone(),
            presignatures: presignatures.clone(),
            msg,
            action_rx: rx,
            posit: Posit::new(me),
            generation_timeout: None,
            generation_started: false,
        };

        (handle, task.run())
    }

    async fn run(mut self) {
        let mut expiration_interval = tokio::time::interval(Duration::from_secs(20));
        let generator = loop {
            let step = tokio::select! {
                action = self.action_rx.recv() => match action {
                    Some(action) => self.handle_action(action).await,
                    None => {
                        tracing::warn!(id = ?self.id, "presignature task aborted");
                        return
                    },
                },
                _ = expiration_interval.tick(), if !self.posit.is_empty() => {
                    self.handle_expiration().await
                }
            };

            match step {
                PresignatureTaskStep::Generate(generator) => {
                    break generator;
                }
                PresignatureTaskStep::Continue => continue,
                PresignatureTaskStep::Complete => return,
            }
        };

        self.generation_started = true;
        generator
            .run(&self.my_account_id, self.me, self.epoch)
            .await;
    }

    async fn handle_action(&mut self, action: PresignatureTaskAction) -> PresignatureTaskStep {
        match action {
            PresignatureTaskAction::Initiate {
                triples,
                participants,
                timeout,
            } => {
                self.generation_timeout = Some(timeout);
                self.handle_initiate(triples, participants, timeout).await
            }
            PresignatureTaskAction::Posit {
                from,
                action,
                timeout,
            } => {
                self.generation_timeout = Some(timeout);
                self.handle_posit(from, action, timeout).await
            }
        }
    }

    async fn handle_initiate(
        &mut self,
        triples: TriplesTaken,
        participants: Vec<Participant>,
        timeout: Duration,
    ) -> PresignatureTaskStep {
        tracing::info!(
            id = self.id.id,
            triple0 = self.id.t0,
            triple1 = self.id.t1,
            "initiating presignature posit"
        );

        let action = self.posit.propose(self.id, triples, &participants);
        if matches!(action, PositAction::Reject) {
            tracing::warn!(
                id = self.id.id,
                "duplicate presignature posit proposal ignored"
            );
            return PresignatureTaskStep::Continue;
        }

        self.broadcast_posit(&participants, PositAction::Propose)
            .await;
        // Reuse timeout to keep behavior identical to previous implementation for expirations.
        self.generation_timeout = Some(timeout);
        PresignatureTaskStep::Continue
    }

    async fn handle_posit(
        &mut self,
        from: Participant,
        action: PositAction,
        timeout: Duration,
    ) -> PresignatureTaskStep {
        tracing::debug!(
            id = self.id.id,
            ?from,
            ?action,
            "processing presignature posit"
        );

        if self.generation_started {
            tracing::warn!(id = self.id.id, "presignature generation already started");
            if !matches!(action, PositAction::Accept) {
                self.send_posit(from, PositAction::Reject).await;
            }
            return PresignatureTaskStep::Continue;
        }

        if matches!(action, PositAction::Propose) {
            if self.presignatures.contains(self.id.id).await {
                tracing::warn!(id = self.id.id, "presignature already generated");
                self.send_posit(from, PositAction::Reject).await;
                return PresignatureTaskStep::Continue;
            }

            if !self.has_required_triples().await {
                tracing::warn!(
                    id = self.id.id,
                    triple0 = self.id.t0,
                    triple1 = self.id.t1,
                    "presignature required triples are not known"
                );
                self.send_posit(from, PositAction::Reject).await;
                return PresignatureTaskStep::Continue;
            }
        }

        let internal = self.posit.act(self.id, from, self.threshold, &action);
        self.handle_internal_action(from, internal, timeout).await
    }

    async fn handle_internal_action(
        &mut self,
        target: Participant,
        internal: PositInternalAction<TriplesTaken>,
        timeout: Duration,
    ) -> PresignatureTaskStep {
        match internal {
            PositInternalAction::None => PresignatureTaskStep::Continue,
            PositInternalAction::Abort => {
                tracing::warn!(id = self.id.id, "presignature posit aborted");
                PresignatureTaskStep::Complete
            }
            PositInternalAction::Reply(action) => {
                self.send_posit(target, action).await;
                PresignatureTaskStep::Continue
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                self.start_generation(participants, positor, timeout).await
            }
        }
    }

    async fn handle_expiration(&mut self) -> PresignatureTaskStep {
        let Some((id, action)) = self
            .posit
            .expire_and_start(self.threshold, Duration::from_secs(60))
        else {
            return PresignatureTaskStep::Continue;
        };

        if id != self.id {
            return PresignatureTaskStep::Continue;
        }

        match action {
            PositInternalAction::None => PresignatureTaskStep::Continue,
            PositInternalAction::Abort => {
                tracing::warn!(id = self.id.id, "presignature posit expired");
                PresignatureTaskStep::Complete
            }
            PositInternalAction::Reply(reply) => {
                tracing::debug!(
                    id = self.id.id,
                    ?reply,
                    "posit expiration produced reply without participant"
                );
                PresignatureTaskStep::Continue
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                let timeout = self.generation_timeout.unwrap_or(Duration::from_millis(1));
                self.start_generation(participants, positor, timeout).await
            }
        }
    }

    async fn start_generation(
        &mut self,
        participants: Vec<Participant>,
        positor: Positor<TriplesTaken>,
        timeout: Duration,
    ) -> PresignatureTaskStep {
        if self.generation_started {
            tracing::warn!(id = self.id.id, "presignature generation already started");
            return PresignatureTaskStep::Continue;
        }

        let timeout = self
            .generation_timeout
            .unwrap_or(timeout)
            .max(Duration::from_millis(1));

        if positor.is_proposer() {
            self.broadcast_posit(&participants, PositAction::Start(participants.clone()))
                .await;
        }

        let owner = positor.id();
        let pending = match positor {
            Positor::Proposer(_, triples) => PendingTriples::Available(triples),
            Positor::Deliberator(_) => {
                PendingTriples::InStorage(self.id.t0, self.id.t1, self.triples.clone())
            }
        };

        match self
            .prepare_generation(owner, &participants, pending, timeout)
            .await
        {
            Some(generator) => PresignatureTaskStep::Generate(generator),
            None => {
                tracing::warn!(
                    id = self.id.id,
                    owner = ?owner,
                    "unable to start presignature generation"
                );
                PresignatureTaskStep::Complete
            }
        }
    }

    async fn prepare_generation(
        &self,
        owner: Participant,
        participants: &[Participant],
        pending: PendingTriples,
        timeout: Duration,
    ) -> Option<PresignatureGenerator> {
        let slot = self.presignatures.reserve(self.id.id).await?;

        let Some(triples) = pending.fetch(self.me, owner, timeout).await else {
            let _ = slot.unreserve();
            return None;
        };

        let (triple0, triple1, dropper) = triples.take();

        let mut participants_sorted = participants.to_vec();
        participants_sorted.sort();

        let keygen_out = KeygenOutput {
            private_share: self.private_share,
            public_key: self.public_key,
        };

        let protocol = match cait_sith::presign(
            &participants_sorted,
            self.me,
            &participants_sorted,
            self.me,
            PresignArguments {
                triple0: (triple0.share, triple0.public),
                triple1: (triple1.share, triple1.public),
                keygen_out,
                threshold: self.threshold,
            },
        ) {
            Ok(protocol) => Box::new(protocol),
            Err(err) => {
                tracing::warn!(
                    id = self.id.id,
                    ?err,
                    "failed to initialize presignature protocol"
                );
                let _ = slot.unreserve();
                return None;
            }
        };

        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        if owner == self.me {
            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE
                .with_label_values(&[self.my_account_id.as_str()])
                .inc();
        }

        let inbox = self.msg.subscribe_presignature(self.id.id).await;

        Some(PresignatureGenerator {
            id: self.id.id,
            owner,
            participants: participants_sorted,
            protocol,
            dropper,
            created: Instant::now(),
            timeout,
            slot,
            inbox,
            msg: self.msg.clone(),
        })
    }

    async fn broadcast_posit(&self, participants: &[Participant], action: PositAction) {
        for &to in participants {
            if to == self.me {
                continue;
            }
            let action_to_send = match &action {
                PositAction::Propose => PositAction::Propose,
                PositAction::Start(participants) => PositAction::Start(participants.clone()),
                PositAction::Accept => PositAction::Accept,
                PositAction::Reject => PositAction::Reject,
            };
            self.send_posit(to, action_to_send).await;
        }
    }

    async fn send_posit(&self, to: Participant, action: PositAction) {
        self.msg
            .send(
                self.me,
                to,
                PositMessage {
                    id: PositProtocolId::Presignature(self.id),
                    from: self.me,
                    action,
                },
            )
            .await;
    }

    async fn has_required_triples(&self) -> bool {
        let triple0_ready = self.triples.contains_reserved(self.id.t0).await
            || self.triples.contains(self.id.t0).await;
        let triple1_ready = self.triples.contains_reserved(self.id.t1).await
            || self.triples.contains(self.id.t1).await;
        triple0_ready && triple1_ready
    }
}

impl PresignatureGenerator {
    /// Receive the next message for the presignature protocol; error out on the timeout being reached
    /// or the channel having been closed (aborted).
    async fn recv(&mut self) -> Option<PresignatureMessage> {
        match tokio::time::timeout(
            self.timeout.saturating_sub(self.created.elapsed()),
            self.inbox.recv(),
        )
        .await
        {
            Ok(Some(msg)) => Some(msg),
            Ok(None) => {
                tracing::warn!(
                    id = self.id,
                    owner = ?self.owner,
                    "presignature generation aborted",
                );
                None
            }
            Err(_err) => {
                tracing::warn!(
                    id = self.id,
                    owner = ?self.owner,
                    "presignature generation timeout",
                );
                None
            }
        }
    }

    pub async fn run(mut self, my_account_id: &AccountId, me: Participant, epoch: u64) {
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
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    failure_counts.inc();
                    tracing::warn!(
                        id = ?self.id,
                        owner = ?self.owner,
                        ?err,
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
                    self.protocol.message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
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
                                    triple0: self.dropper.id0,
                                    triple1: self.dropper.id1,
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
                    self.msg
                        .send(
                            me,
                            to,
                            PresignatureMessage {
                                id: self.id,
                                triple0: self.dropper.id0,
                                triple1: self.dropper.id1,
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
                    self.slot.insert(presignature, self.owner).await;
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
    ongoing: JoinMap<PresignatureId, (), PresignatureTaskChannel>,
    /// Presignatures introduced by the current node (pending or running).
    ongoing_introduced: HashSet<PresignatureId>,

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
            ongoing_introduced: HashSet::new(),
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
        self.ongoing_introduced.len()
    }

    /// Returns the number of unspent presignatures we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        let complete_presignatures = self.len_generated().await;
        let ongoing_generators = self.ongoing.len();
        complete_presignatures + ongoing_generators
    }

    /// Gets an existing presignature task or spawns a new one if it doesn't exist.
    fn get_or_spawn(&mut self, id: FullPresignatureId) -> PresignatureTaskChannel {
        if let Some(handle) = self.ongoing.get(&id.id) {
            return handle.clone();
        }

        let (handle, fut) = PresignatureTask::spawn(
            id,
            self.me,
            self.threshold,
            self.epoch,
            self.private_share,
            self.public_key,
            &self.my_account_id,
            &self.triples,
            &self.presignatures,
            self.msg.clone(),
        );
        self.ongoing.spawn_and_map(id.id, handle.clone(), fut);
        handle
    }

    async fn forward_posit(
        &mut self,
        id: FullPresignatureId,
        from: Participant,
        action: PositAction,
        timeout: Duration,
    ) {
        if !id.validate() {
            tracing::error!(
                ?id,
                ?from,
                ?action,
                "presignature id does not match expected hash"
            );
            self.send_reject(id, from).await;
            return;
        }

        if self.presignatures.contains(id.id).await {
            tracing::warn!(?id, ?from, ?action, "presignature already generated");
            self.send_reject(id, from).await;
            return;
        }

        if matches!(action, PositAction::Propose) && !self.have_required_triples(&id).await {
            tracing::warn!(
                ?id,
                ?from,
                ?action,
                "presignature required triples are not known"
            );
            self.send_reject(id, from).await;
            return;
        }

        let handle = self.get_or_spawn(id);
        handle
            .send(PresignatureTaskAction::Posit {
                from,
                action,
                timeout,
            })
            .await;
    }

    async fn send_reject(&self, id: FullPresignatureId, to: Participant) {
        self.msg
            .send(
                self.me,
                to,
                PositMessage {
                    id: PositProtocolId::Presignature(id),
                    from: self.me,
                    action: PositAction::Reject,
                },
            )
            .await;
    }

    /// Starts a new presignature generation protocol.
    async fn propose_posit(&mut self, active: &[Participant], timeout: Duration) {
        // To ensure there is no contention between different nodes we are only using triples
        // that we proposed. This way in a non-BFT environment we are guaranteed to never try
        // to use the same triple as any other node.
        // TODO: have all this part be a separate task such that finding a pair of triples is done in parallel instead
        // of waiting for storage to respond here.
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
            ?triples,
            "proposing protocol to generate a new presignature"
        );

        let handle = self.get_or_spawn(id);
        self.ongoing_introduced.insert(id.id);
        handle
            .send(PresignatureTaskAction::Initiate {
                triples,
                participants: participants.clone(),
                timeout,
            })
            .await;
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
            let timeout = Duration::from_millis(cfg.presignature.generation_timeout);
            self.propose_posit(active, timeout).await;
        }
    }

    async fn have_required_triples(&self, id: &FullPresignatureId) -> bool {
        let triple0_ready =
            self.triples.contains_reserved(id.t0).await || self.triples.contains(id.t0).await;
        let triple1_ready =
            self.triples.contains_reserved(id.t1).await || self.triples.contains(id.t1).await;
        triple0_ready && triple1_ready
    }

    async fn run(
        mut self,
        mesh_state: watch::Receiver<MeshState>,
        config: watch::Receiver<Config>,
        ongoing_gen_tx: watch::Sender<usize>,
    ) {
        let mut stockpile_interval = time::interval(Duration::from_millis(100));
        let mut posits = self.msg.subscribe_presignature_posit().await;

        loop {
            tokio::select! {
                Some((id, from, action)) = posits.recv() => {
                    let timeout = config.borrow().protocol.presignature.generation_timeout;
                    self.forward_posit(id, from, action, Duration::from_millis(timeout)).await;
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
                    self.ongoing_introduced.remove(&id);
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
