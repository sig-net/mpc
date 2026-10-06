use std::collections::HashSet;
use std::fmt;
use std::time::{Duration, Instant};

use cait_sith::protocol::{InitializationError, Participant};
use cait_sith::KeygenOutput;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::PublicKey;
use mpc_utils::task::JoinMap;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time;

use super::message::{MessageChannel, PositMessage, PositProtocolId};
use super::posit::{PositAction, PositInternalAction, PositRejectReason, Positor, Posits};
use super::presignature::{FullPresignatureId, PresignatureGenerator, PresignatureId};
use super::triple::TripleGenerator;
use super::MpcSignProtocol;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::storage::presignature_storage::PresignatureStorage;
use crate::types::SecretKeyShare;

/// Unified spawner that coordinates stacked Beaver triple and Cait-Sith presignature generation.
pub struct ProtocolSpawner {
    me: Participant,
    threshold: usize,
    epoch: u64,
    private_share: SecretKeyShare,
    public_key: PublicKey,
    presignatures: PresignatureStorage,

    ongoing: JoinMap<PresignatureId, ()>,
    ongoing_owned: HashSet<PresignatureId>,
    posits: Posits<FullPresignatureId, ()>,

    msg: MessageChannel,
    ongoing_triples_tx: watch::Sender<usize>,
    ongoing_presignatures_tx: watch::Sender<usize>,
    #[cfg_attr(not(feature = "debug-page"), allow(dead_code))]
    node_account_id: String,

    #[cfg(feature = "debug-page")]
    posits_debug_view: crate::web::debug::DebugPageTaskHandle,
}

impl fmt::Debug for ProtocolSpawner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolSpawner")
            .field("me", &self.me)
            .field("threshold", &self.threshold)
            .field("epoch", &self.epoch)
            .field("ongoing_count", &self.ongoing.len())
            .finish()
    }
}

impl ProtocolSpawner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        private_share: &SecretKeyShare,
        public_key: &PublicKey,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
        ongoing_triples_tx: watch::Sender<usize>,
        ongoing_presignatures_tx: watch::Sender<usize>,
        node_account_id: String,
    ) -> Self {
        #[cfg(feature = "debug-page")]
        let posits_debug_view = crate::web::debug::register_task(
            node_account_id.clone(),
            "Posits ProtocolSpawner".to_string(),
        );

        Self {
            me,
            threshold,
            epoch,
            private_share: *private_share,
            public_key: *public_key,
            presignatures: presignatures.clone(),
            ongoing: JoinMap::new(),
            ongoing_owned: HashSet::new(),
            posits: Posits::new(me),
            msg,
            ongoing_triples_tx,
            ongoing_presignatures_tx,
            node_account_id,
            #[cfg(feature = "debug-page")]
            posits_debug_view,
        }
    }

    pub async fn contains_mine(&self, id: PresignatureId) -> bool {
        self.presignatures.contains_by_owner(id, self.me).await
    }

    pub async fn len_potential(&self) -> usize {
        self.presignatures.len_generated().await + self.ongoing.len()
    }

    pub async fn len_mine(&self) -> usize {
        self.presignatures.len_by_owner(self.me).await + self.ongoing_owned.len()
    }

    pub fn len_introduced(&self) -> usize {
        self.posits.len_proposed() + self.ongoing_owned.len()
    }

    /// Merged stockpile logic: monitors inventory against {min, max}_artifacts.
    async fn stockpile(&mut self, active: &[Participant], cfg: &ProtocolConfig) {
        let min_artifacts =
            (cfg.presignature.min_presignatures as usize).max(cfg.triple.min_triples as usize);
        let max_artifacts =
            (cfg.presignature.max_presignatures as usize).max(cfg.triple.max_triples as usize);

        let potential = self.len_potential().await;
        let mine = self.len_mine().await;
        let not_enough_artifacts = {
            if potential >= max_artifacts {
                false
            } else {
                mine < min_artifacts
                    && self.len_introduced() < cfg.max_concurrent_introduction as usize
                    && self.ongoing.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_artifacts {
            tracing::debug!(
                min_artifacts,
                max_artifacts,
                mine,
                potential,
                "not enough artifacts in stockpile, proposing posit"
            );
            self.propose_posit(active, cfg).await;
        }
    }

    async fn propose_posit(&mut self, active: &[Participant], _cfg: &ProtocolConfig) {
        let id = FullPresignatureId::new(rand::random());
        let mut participants = active.to_vec();
        participants.sort();

        tracing::info!(?id, "proposing protocol to generate a new artifact");
        self.posits.propose(id, (), &participants);

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

    async fn process_posit(
        &mut self,
        id: FullPresignatureId,
        from: Participant,
        action: PositAction,
        timeout: Duration,
    ) {
        if let PositAction::Propose = &action {
            if !id.validate() {
                tracing::warn!(?id, "ignoring invalid artifact posit id");
                return;
            }

            if self.presignatures.contains(id.id).await || self.ongoing.contains_key(&id.id) {
                self.msg
                    .send(
                        self.me,
                        from,
                        PositMessage {
                            id: PositProtocolId::Presignature(id),
                            from: self.me,
                            action: PositAction::RejectWithReason(
                                PositRejectReason::AlreadyGenerating,
                            ),
                        },
                    )
                    .await;
                return;
            }
        }

        let internal_action = self.posits.act(id, from, self.threshold, &action);
        #[cfg(feature = "debug-page")]
        self.posits_debug_view
            .send(self.posits.render_debug(self.threshold));

        match internal_action {
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
            PositInternalAction::Abort => {
                tracing::warn!(?id, "artifact posit aborted due to too many rejections");
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                if let Err(err) = self
                    .start_generation(id, positor, participants, timeout)
                    .await
                {
                    tracing::warn!(?id, ?err, "failed to start artifact generation");
                }
            }
            PositInternalAction::None => {}
        }
    }

    async fn start_generation(
        &mut self,
        id: FullPresignatureId,
        positor: Positor<()>,
        participants: Vec<Participant>,
        timeout: Duration,
    ) -> Result<(), InitializationError> {
        if positor.is_proposer() {
            self.ongoing_owned.insert(id.id);
        }
        let owner = positor.id();

        let Some(slot) = self.presignatures.create_slot(id.id, owner).await else {
            return Err(InitializationError::BadParameters(format!(
                "artifact {} is already generating, in use, or stored",
                id.id
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

        #[cfg(feature = "debug-page")]
        let node_account_id = self.node_account_id.clone();
        #[cfg(not(feature = "debug-page"))]
        let node_account_id = String::new();

        let triple_gen = TripleGenerator::new(
            id.id,
            me,
            owner,
            threshold,
            &participants,
            timeout,
            &msg,
            self.ongoing_triples_tx.clone(),
            &node_account_id,
        )?;

        let presign_gen = PresignatureGenerator::new(
            id,
            me,
            owner,
            threshold,
            &participants,
            keygen_out,
            timeout,
            slot,
            &msg,
            self.ongoing_presignatures_tx.clone(),
            &node_account_id,
        );

        let task = ProtocolTask::new(id, epoch, triple_gen, presign_gen, msg);

        self.ongoing.spawn(id.id, task.run());

        Ok(())
    }

    pub async fn run(
        mut self,
        mut mesh_state: watch::Receiver<MeshState>,
        mut cfg: watch::Receiver<Config>,
    ) {
        let mut stockpile_interval = time::interval(Duration::from_millis(100));
        stockpile_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let mut protocol = cfg.borrow().protocol.clone();
        let mut active = mesh_state.borrow().active().keys_vec();
        let mut posits = self.msg.subscribe_presignature_posit().await;
        let mut last_active_warn: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = stockpile_interval.tick() => {
                    if active.len() >= self.threshold {
                        self.stockpile(&active, &protocol).await;

                        for (id, action) in self.posits.expire_and_start(
                            self.threshold,
                            Duration::from_millis(protocol.message_timeout),
                            Duration::from_millis(protocol.garbage_timeout),
                        ) {
                            let PositInternalAction::StartProtocol(participants, positor) = action else {
                                tracing::warn!(?id, "posit expired: insufficient accepts");
                                continue;
                            };
                            let timeout = Duration::from_millis(protocol.triple.generation_timeout.max(protocol.presignature.generation_timeout));
                            if let Err(err) = self.start_generation(id, positor, participants, timeout).await {
                                tracing::warn!(?id, ?err, "failed to start generation from expired posit");
                            }
                        }

                        crate::metrics::storage::NUM_PRESIGNATURES_MINE
                            .set(self.len_mine().await as i64);
                        crate::metrics::storage::NUM_PRESIGNATURES_TOTAL
                            .set(self.presignatures.len_generated().await as i64);
                    } else if last_active_warn.is_none_or(|i: Instant| i.elapsed() > Duration::from_secs(60)) {
                        tracing::warn!(
                            ?active,
                            threshold = self.threshold,
                            "not enough active participants to generate artifacts"
                        );
                        last_active_warn = Some(Instant::now());
                    }
                }
                Some((id, from, action)) = posits.recv() => {
                    let timeout = Duration::from_millis(protocol.triple.generation_timeout.max(protocol.presignature.generation_timeout));
                    self.process_posit(id, from, action, timeout).await;
                }
                Some(result) = self.ongoing.join_next(), if !self.ongoing.is_empty() => {
                    let (id, ()) = match result {
                        Ok(item) => item,
                        Err(err) => {
                            tracing::warn!(?err, "artifact generation panicked or failed to join");
                            continue;
                        }
                    };
                    self.ongoing_owned.remove(&id);
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
                }
                Ok(()) = mesh_state.changed() => {
                    active = mesh_state.borrow().active().keys_vec();
                }
            }
        }
    }
}

impl Drop for ProtocolSpawner {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        tokio::spawn(msg.unsubscribe_presignature_posit());
    }
}

/// Runs the stacked in-memory pipeline: Beaver triples in RAM -> Cait-Sith presign in RAM -> Store presignature.
pub struct ProtocolTask {
    pub id: FullPresignatureId,
    pub epoch: u64,
    pub triple_gen: TripleGenerator,
    pub presign_gen: PresignatureGenerator,
    pub msg: MessageChannel,
}

impl ProtocolTask {
    pub fn new(
        id: FullPresignatureId,
        epoch: u64,
        triple_gen: TripleGenerator,
        presign_gen: PresignatureGenerator,
        msg: MessageChannel,
    ) -> Self {
        Self {
            id,
            epoch,
            triple_gen,
            presign_gen,
            msg,
        }
    }

    pub async fn run(self) {
        let mut inbox = self.msg.subscribe_artifact(self.id.id).await;

        // Stage 1: Generate Beaver Triples in RAM
        let (triple_pair, early_msgs) = match self.triple_gen.run(&mut inbox, self.epoch).await {
            Ok(res) => res,
            Err(err) => {
                tracing::warn!(id = ?self.id, ?err, "stage 1 triple generation failed");
                cleanup_artifact(&self.msg, self.id.id).await;
                return;
            }
        };

        // Stage 2: Cait-Sith Presignature Generation in RAM & insert into PresignatureStorage
        if let Err(err) = self
            .presign_gen
            .run(triple_pair, early_msgs, &mut inbox, self.epoch)
            .await
        {
            tracing::warn!(id = ?self.id, ?err, "stage 2 presignature generation failed");
        }

        cleanup_artifact(&self.msg, self.id.id).await;
    }
}

async fn cleanup_artifact(msg: &MessageChannel, id: u64) {
    msg.unsubscribe_artifact(id).await;
    msg.filter_artifact(id).await;
}

/// Handle to the background protocol spawner task running in the node.
pub struct ProtocolSpawnerTask {
    ongoing_triples_rx: watch::Receiver<usize>,
    ongoing_presignatures_rx: watch::Receiver<usize>,
    handle: JoinHandle<()>,
}

impl ProtocolSpawnerTask {
    pub fn run(
        me: Participant,
        threshold: usize,
        epoch: u64,
        ctx: &MpcSignProtocol,
        private_share: &SecretKeyShare,
        public_key: &PublicKey,
    ) -> Self {
        let (ongoing_triples_tx, ongoing_triples_rx) = watch::channel(0);
        let (ongoing_presignatures_tx, ongoing_presignatures_rx) = watch::channel(0);

        let spawner = ProtocolSpawner::new(
            me,
            threshold,
            epoch,
            private_share,
            public_key,
            &ctx.presignature_storage,
            ctx.msg_channel.clone(),
            ongoing_triples_tx,
            ongoing_presignatures_tx,
            ctx.my_account_id.to_string(),
        );

        let handle = tokio::spawn(spawner.run(ctx.mesh_state.clone(), ctx.config.clone()));

        Self {
            ongoing_triples_rx,
            ongoing_presignatures_rx,
            handle,
        }
    }

    pub fn ongoing_triples(&self) -> usize {
        *self.ongoing_triples_rx.borrow()
    }

    pub fn ongoing_presignatures(&self) -> usize {
        *self.ongoing_presignatures_rx.borrow()
    }

    pub fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for ProtocolSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}
