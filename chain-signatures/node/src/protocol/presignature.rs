use super::message::{MessageChannel, PositMessage, PositProtocolId, PresignatureMessage};
use super::posit::{PositAction, Positor, Posits};
use super::triple::TripleId;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::metrics::node_account_id;
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::posit::PositInternalAction;
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
use std::collections::HashSet;
use std::fmt;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time;

/// Unique number used to identify a specific ongoing presignature generation protocol.
/// Without `PresignatureId` it would be unclear where to route incoming cait-sith presignature
/// generation messages.
pub type PresignatureId = u64;

/// The full presignature id. This encompasses the presignature id and the triple pair
/// that was used to generate it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FullPresignatureId {
    pub id: PresignatureId,
    pub pair_id: TripleId,
}

impl FullPresignatureId {
    pub fn from_pair(pair_id: TripleId) -> Self {
        let id = hash_as_id(pair_id);
        Self { id, pair_id }
    }

    pub fn validate(&self) -> bool {
        self.id == hash_as_id(self.pair_id)
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
    #[cfg(feature = "debug-page")]
    debug_view: crate::web::debug::DebugPageTaskHandle,
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

    pub async fn run(mut self, me: Participant, epoch: u64) {
        let failure_counts = crate::metrics::protocols::PRESIGNATURE_GENERATOR_FAILURES
            .with_label_values(&[node_account_id()]);
        let failure_mine_counts = crate::metrics::protocols::PRESIGNATURE_GENERATOR_MINE_FAILURES
            .with_label_values(&[node_account_id()]);
        let before_first_poke_delay = crate::metrics::protocols::PRESIGNATURE_BEFORE_POKE_DELAY
            .with_label_values(&[node_account_id()]);
        let accrued_wait_delay = crate::metrics::protocols::PRESIGNATURE_ACCRUED_WAIT_DELAY
            .with_label_values(&[node_account_id()]);
        let poke_counts = crate::metrics::protocols::PRESIGNATURE_POKES_CNT
            .with_label_values(&[node_account_id()]);
        let runtime_latency =
            crate::metrics::protocols::PRESIGNATURE_LATENCY.with_label_values(&[node_account_id()]);
        let success_owned_counts: prometheus::core::GenericCounter<prometheus::core::AtomicF64> =
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS
                .with_label_values(&[node_account_id()]);
        let success_total_counts =
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS
                .with_label_values(&[node_account_id()]);
        let poke_latency = crate::metrics::protocols::PRESIGNATURE_POKE_CPU_TIME
            .with_label_values(&[node_account_id()]);

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
                    if self.owner == me {
                        failure_mine_counts.inc();
                    }
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
            #[cfg(feature = "debug-page")]
            self.render_debug(total_pokes);

            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let Some(msg) = self.recv().await else {
                        failure_counts.inc();
                        if self.owner == me {
                            failure_mine_counts.inc();
                        }
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
                                    pair_id: self.dropper.id,
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
                                pair_id: self.dropper.id,
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

    #[cfg(feature = "debug-page")]
    fn render_debug(&self, total_pokes: i32) {
        let markup = maud::html! {
            p { (format!("{total_pokes} pokes")) }
        };
        self.debug_view.send(markup);
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
    /// The protocol posits that are currently in progress.
    posits: Posits<FullPresignatureId, TriplesTaken>,

    me: Participant,
    threshold: usize,
    epoch: u64,
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
        triples: &TripleStorage,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
    ) -> Self {
        Self {
            triples: triples.clone(),
            presignatures: presignatures.clone(),
            ongoing: JoinMap::new(),
            ongoing_owned: HashSet::new(),
            posits: Posits::new(me),
            me,
            threshold,
            epoch,
            private_share: *private_share,
            public_key: *public_key,
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
        self.posits.len_proposed() + self.ongoing_owned.len()
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
        let internal_action = if !id.validate() {
            tracing::error!(
                ?id,
                ?from,
                ?action,
                "presignature id does not match the expected hash"
            );
            PositInternalAction::Reply(PositAction::Reject)
        } else if self.contains_ongoing(id.id) {
            tracing::warn!(?id, ?from, ?action, "presignature already generating");
            PositInternalAction::Reply(PositAction::Reject)
        } else if self.contains(id.id).await {
            tracing::warn!(?id, ?from, ?action, "presignature already generated");
            PositInternalAction::Reply(PositAction::Reject)
        } else if !{
            // TODO: we can potentially wait for the triples to exist first to then be able to accept.
            // whereas we just blatantly reject here. The problem with waiting is that the other side
            // might expire their posit first.
            self.triples.contains_reserved(id.pair_id).await
                || self.triples.contains(id.pair_id).await
        } {
            tracing::warn!(
                ?id,
                ?from,
                ?action,
                "presignature required triples are not known"
            );
            PositInternalAction::Reply(PositAction::Reject)
        } else {
            self.posits.act(id, from, self.threshold, &action)
        };

        match internal_action {
            PositInternalAction::None => {}
            PositInternalAction::Abort => {
                tracing::warn!(?id, "presignature posit aborted due to too many rejections");
            }
            PositInternalAction::Reply(action) => {
                self.msg
                    .send(
                        self.me,
                        from,
                        PositMessage {
                            id: PositProtocolId::Presignature(id),
                            from: self.me,
                            action,
                        },
                    )
                    .await;
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                self.start_generation(id, positor, participants, timeout)
                    .await;
            }
        }
    }

    /// Starts a new presignature generation protocol.
    async fn propose_posit(&mut self, active: &[Participant]) {
        // To ensure there is no contention between different nodes we are only using triples
        // that we proposed. This way in a non-BFT environment we are guaranteed to never try
        // to use the same triple as any other node.
        // TODO: have all this part be a separate task such that finding a pair of triples is done in parallel instead
        // of waiting for storage to respond here.
        let Some(triples) = self.triples.take_mine(self.me).await else {
            return;
        };

        let pair_id = triples.artifact.id;
        // note: only one of the pair's participants is needed since they are the same.
        let participants = intersect_vec(&[active, &triples.artifact.triple0.public.participants]);
        if participants.len() < self.threshold {
            tracing::warn!(
                pair_id,
                ?active,
                ?participants,
                "intersection < threshold, trashing triple pair"
            );
            return;
        }

        let id = FullPresignatureId::from_pair(pair_id);
        tracing::info!(?id, "proposing protocol to generate a new presignature");

        self.posits.propose(id, triples, &participants);
        for &p in participants.iter() {
            if p == self.me {
                continue;
            }

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
            self.propose_posit(active).await;
        }
    }

    async fn generate(
        &mut self,
        id: FullPresignatureId,
        positor: Positor<TriplesTaken>,
        participants: &[Participant],
        timeout: Duration,
    ) -> Result<(), InitializationError> {
        let (owner, triples) = match positor {
            Positor::Proposer(proposer, triples) => (proposer, PendingTriples::Available(triples)),
            Positor::Deliberator(proposer) => (
                proposer,
                PendingTriples::InStorage(id.pair_id, self.triples.clone()),
            ),
        };
        tracing::info!(
            ?id,
            ?owner,
            "starting protocol to generate a new presignature",
        );

        let Some(slot) = self.presignatures.reserve(id.id).await else {
            return Err(InitializationError::BadParameters(format!(
                "id collision: presignature_id={id:?}"
            )));
        };

        let mut participants = participants.to_vec();
        participants.sort();

        let me = self.me;
        let threshold = self.threshold;
        let epoch = self.epoch;
        let msg = self.msg.clone();
        let keygen_out = KeygenOutput {
            private_share: self.private_share,
            public_key: self.public_key,
        };

        let task = async move {
            let Some(triples) = triples.fetch(owner, timeout).await else {
                return;
            };

            let (pair, dropper) = triples.take();
            let protocol = match cait_sith::presign(
                &participants,
                me,
                // These paramaters appear to be to make it easier to use different indexing schemes for triples
                // Introduced in this PR https://github.com/LIT-Protocol/cait-sith/pull/7
                &participants,
                me,
                PresignArguments {
                    triple0: (pair.triple0.share, pair.triple0.public),
                    triple1: (pair.triple1.share, pair.triple1.public),
                    keygen_out,
                    threshold,
                },
            ) {
                Ok(protocol) => Box::new(protocol),
                Err(err) => {
                    tracing::warn!(?id, ?err, "failed to initialize presignature protocol");
                    return;
                }
            };

            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
                .with_label_values(&[node_account_id()])
                .inc();
            if owner == me {
                crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE
                    .with_label_values(&[node_account_id()])
                    .inc();
            }

            let inbox = msg.subscribe_presignature(id.id).await;
            let generator = PresignatureGenerator {
                id: id.id,
                owner,
                participants,
                protocol,
                dropper,
                created: Instant::now(),
                timeout,
                slot,
                inbox,
                msg,
                #[cfg(feature = "debug-page")]
                debug_view: crate::web::debug::register_task(
                    node_account_id().to_string(),
                    format!("PresignatureGenerator {id:#?}"),
                ),
            };
            generator.run(me, epoch).await;
        };

        self.ongoing.spawn(id.id, task);
        if owner == me {
            self.ongoing_owned.insert(id.id);
        }

        Ok(())
    }

    async fn start_generation(
        &mut self,
        id: FullPresignatureId,
        positor: Positor<TriplesTaken>,
        participants: Vec<Participant>,
        timeout: Duration,
    ) {
        if positor.is_proposer() {
            for &p in &participants {
                if p == self.me {
                    continue;
                }
                self.msg
                    .send(
                        self.me,
                        p,
                        PositMessage {
                            id: PositProtocolId::Presignature(id),
                            from: self.me,
                            action: PositAction::Start(participants.clone()),
                        },
                    )
                    .await;
            }
        }

        let is_proposer = positor.is_proposer();
        if let Err(err) = self.generate(id, positor, &participants, timeout).await {
            self.ongoing_owned.remove(&id.id);
            tracing::warn!(
                ?id,
                ?participants,
                is_proposer,
                ?err,
                "unable to start presignature generation on START"
            );
        }
    }

    async fn run(
        mut self,
        mut mesh_state: watch::Receiver<MeshState>,
        mut cfg: watch::Receiver<Config>,
        ongoing_gen_tx: watch::Sender<usize>,
    ) {
        let mut stockpile_interval = time::interval(Duration::from_millis(100));
        let mut expiration_interval = tokio::time::interval(Duration::from_secs(20));
        let mut posits = self.msg.subscribe_presignature_posit().await;

        let mut protocol = cfg.borrow().protocol.clone();
        let mut active = mesh_state.borrow().active.keys_vec();

        loop {
            tokio::select! {
                _ = expiration_interval.tick() => {
                    for (id, action) in self.posits.expire_and_start(self.threshold, Duration::from_secs(60)) {
                        let PositInternalAction::StartProtocol(participants, positor) = action else {
                            tracing::warn!(
                                ?id,
                                "presignature posit expired: insufficient accepts"
                            );
                            continue;
                        };
                        let timeout = Duration::from_millis(protocol.presignature.generation_timeout);
                        self.start_generation(id, positor, participants, timeout).await;
                    }
                }
                Some((id, from, action)) = posits.recv() => {
                    let timeout = Duration::from_millis(protocol.presignature.generation_timeout);
                    self.process_posit(id, from, action, timeout).await;
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
                    self.ongoing_owned.remove(&id);
                    let _ = ongoing_gen_tx.send(self.ongoing.len());
                }
                _ = stockpile_interval.tick(), if active.len() >= self.threshold => {
                    self.stockpile(&active, &protocol).await;
                    let _ = ongoing_gen_tx.send(self.ongoing.len());

                    crate::metrics::storage::NUM_PRESIGNATURES_MINE
                        .with_label_values(&[node_account_id()])
                        .set(self.len_mine().await as i64);
                    crate::metrics::storage::NUM_PRESIGNATURES_TOTAL
                        .with_label_values(&[node_account_id()])
                        .set(self.len_generated().await as i64);
                    crate::metrics::protocols::NUM_PRESIGNATURE_GENERATORS_TOTAL
                        .with_label_values(&[node_account_id()])
                        .set(
                            self.len_potential().await as i64 - self.len_generated().await as i64,
                        );
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

impl Drop for PresignatureSpawner {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        tokio::spawn(msg.unsubscribe_presignature_posit());
    }
}

pub fn hash_as_id(pair_id: TripleId) -> PresignatureId {
    let mut hasher = Sha3_256::new();
    hasher.update(pair_id.to_le_bytes());
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

/// Represents a triple pair that is either available immediately or will eventually be available within
/// the storage, in which case the `fetch` method will block until they are available alongside a timeout.
#[allow(clippy::large_enum_variant)]
enum PendingTriples {
    Available(TriplesTaken),
    InStorage(TripleId, TripleStorage),
}

impl PendingTriples {
    async fn fetch(self, owner: Participant, timeout: Duration) -> Option<TriplesTaken> {
        let (pair_id, storage) = match self {
            Self::InStorage(pair_id, storage) => (pair_id, storage),
            Self::Available(triples) => return Some(triples),
        };

        let triples = tokio::time::timeout(timeout, async {
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            loop {
                interval.tick().await;
                if let Some(triples) = storage.take(pair_id, owner).await {
                    break triples;
                };
            }
        })
        .await;

        match triples {
            Ok(triples) => Some(triples),
            Err(_) => {
                tracing::warn!(pair_id, "timeout waiting for triple pair to be available");
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
