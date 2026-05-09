use super::artifact_task::{ArtifactProtocol, ProtocolSpawnerTask};
use super::message::{MessageChannel, PositProtocolId, TripleMessage};
use super::posit::PositAction;
use super::MpcSignProtocol;
use crate::storage::triple_storage::{TriplePair, TriplePairSlot, TripleStorage};
use crate::types::TripleProtocol;
use crate::util::AffinePointExt;

use mpc_contract::config::ProtocolConfig;

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::triples::{TriplePub, TripleShare};
use chrono::Utc;
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use std::time::{Duration, Instant};

/// Unique number used to identify a specific ongoing triple generation protocol.
pub type TripleId = u64;

/// A completed triple.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Triple {
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

// ── TripleGenerator ───────────────────────────────────────────────────────────

struct TripleGenerator {
    id: TripleId,
    me: Participant,
    owner: Participant,
    participants: Vec<Participant>,
    /// Temporarily moved to a blocking task during poke().
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
            Err(_) => {
                tracing::warn!(id = self.id, "triple generation timeout");
                None
            }
        }
    }

    pub async fn run(mut self, epoch: u64) {
        let start_time = Instant::now();
        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        crate::metrics::protocols::TRIPLE_BEFORE_POKE_DELAY
            .observe(self.created.elapsed().as_millis() as f64);

        loop {
            let poke_start_time = Instant::now();
            let mut protocol = self.protocol.take().expect("always Some");

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
                            "triple generation failed in blocking task",
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
                    let Some(msg) = self.recv().await else {
                        crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
                        if self.owner == self.me {
                            crate::metrics::protocols::TRIPLE_GENERATOR_OWNED_FAILURES.inc();
                        }
                        break;
                    };
                    self.protocol
                        .as_mut()
                        .expect("always Some")
                        .message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
                    for to in &self.participants {
                        if *to == self.me {
                            continue;
                        }
                        self.msg
                            .send(
                                self.me,
                                *to,
                                TripleMessage {
                                    id: self.id,
                                    epoch,
                                    from: self.me,
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
                            self.me,
                            to,
                            TripleMessage {
                                id: self.id,
                                epoch,
                                from: self.me,
                                data,
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                }
                Action::Return(outputs) => {
                    crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS.inc();
                    crate::metrics::protocols::TRIPLE_LATENCY
                        .observe(start_time.elapsed().as_secs_f64());
                    crate::metrics::protocols::TRIPLE_LATENCY_TOTAL
                        .observe(self.created.elapsed().as_secs_f64());
                    crate::metrics::protocols::TRIPLE_ACCRUED_WAIT_DELAY
                        .observe(total_wait.as_millis() as f64);
                    crate::metrics::protocols::TRIPLE_POKES_CNT.observe(total_pokes as f64);

                    let [first, second, ..] = &outputs[..] else {
                        tracing::warn!(
                            id = self.id,
                            triples = outputs.len(),
                            "unexpected: not enough triples to make pair"
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

// ── TripleArtifact ────────────────────────────────────────────────────────────

/// Shared context for all triple-generation tasks.
#[derive(Clone)]
pub struct TripleContext {
    pub storage: TripleStorage,
    pub msg: MessageChannel,
    pub node_account_id: String,
}

/// Marker struct implementing [`ArtifactProtocol`] for triple generation.
pub struct TripleArtifact;

impl ArtifactProtocol for TripleArtifact {
    type TaskId = TripleId;
    type ProposerState = ();
    type Context = TripleContext;

    fn posit_id(task_id: TripleId) -> PositProtocolId {
        PositProtocolId::Triple(task_id)
    }

    async fn propose(
        _ctx: &TripleContext,
        _me: Participant,
        active: &[Participant],
        _threshold: usize,
    ) -> Option<(TripleId, (), Vec<Participant>)> {
        let id: TripleId = rand::random();
        Some((id, (), active.to_vec()))
    }

    async fn can_participate(
        _ctx: &TripleContext,
        _task_id: TripleId,
        _from: Participant,
        _budget: Duration,
    ) -> bool {
        // Triples have no dependencies.
        true
    }

    async fn is_known(ctx: &TripleContext, task_id: TripleId) -> bool {
        ctx.storage.contains(task_id).await
    }

    async fn should_stockpile(
        ctx: &TripleContext,
        cfg: &ProtocolConfig,
        me: Participant,
        ongoing: usize,
        introduced: usize,
    ) -> bool {
        let len_potential = ctx.storage.len_generated().await + ongoing;
        if len_potential >= cfg.triple.max_triples as usize {
            return false;
        }
        let len_mine = ctx.storage.len_by_owner(me).await;
        len_mine < cfg.triple.min_triples as usize
            && introduced < cfg.max_concurrent_introduction as usize
            && ongoing < cfg.max_concurrent_generation as usize
    }

    fn generation_timeout(cfg: &ProtocolConfig) -> Duration {
        Duration::from_millis(cfg.triple.generation_timeout)
    }

    async fn run_generation(
        task_id: TripleId,
        me: Participant,
        owner: Participant,
        participants: Vec<Participant>,
        threshold: usize,
        epoch: u64,
        _proposer_state: Option<()>,
        ctx: TripleContext,
        timeout: Duration,
    ) {
        let Some(slot) = ctx.storage.create_slot(task_id, owner).await else {
            tracing::warn!(task_id, "triple slot already taken, skipping generation");
            return;
        };

        let generator = match TripleGenerator::new(
            task_id,
            me,
            owner,
            threshold,
            &participants,
            timeout,
            slot,
            &ctx.msg,
            &ctx.node_account_id,
        )
        .await
        {
            Ok(gen) => gen,
            Err(err) => {
                tracing::warn!(task_id, ?err, "failed to initialise triple generator");
                return;
            }
        };

        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS.inc();
        generator.run(epoch).await;
    }

    async fn subscribe_posit(
        ctx: &TripleContext,
    ) -> mpsc::Receiver<(TripleId, Participant, PositAction)> {
        ctx.msg.subscribe_triple_posit().await
    }

    async fn unsubscribe_posit(ctx: TripleContext) {
        ctx.msg.unsubscribe_triple_posit().await;
    }

    async fn update_metrics(
        ctx: &TripleContext,
        me: Participant,
        ongoing: usize,
        introduced: usize,
    ) {
        crate::metrics::storage::NUM_TRIPLES_MINE
            .set(ctx.storage.len_by_owner(me).await as i64);
        crate::metrics::storage::NUM_TRIPLES_TOTAL
            .set(ctx.storage.len_generated().await as i64);
        crate::metrics::protocols::NUM_TRIPLE_GENERATORS_INTRODUCED.set(introduced as i64);
        crate::metrics::protocols::NUM_TRIPLE_GENERATORS_TOTAL.set(ongoing as i64);
    }

}

// ── TripleSpawnerTask ─────────────────────────────────────────────────────────

/// Top-level handle for the triple-generation spawner.
pub struct TripleSpawnerTask {
    inner: ProtocolSpawnerTask,
}

impl TripleSpawnerTask {
    pub fn run(me: Participant, threshold: usize, epoch: u64, ctx: &MpcSignProtocol) -> Self {
        let context = TripleContext {
            storage: ctx.triple_storage.clone(),
            msg: ctx.msg_channel.clone(),
            node_account_id: ctx.my_account_id.to_string(),
        };
        Self {
            inner: ProtocolSpawnerTask::new::<TripleArtifact>(
                me,
                threshold,
                epoch,
                context,
                ctx.msg_channel.clone(),
                ctx.mesh_state.clone(),
                ctx.config.clone(),
            ),
        }
    }

    pub fn len_ongoing(&self) -> usize {
        self.inner.len_ongoing()
    }

    pub fn abort(&self) {
        self.inner.abort();
    }
}

impl Drop for TripleSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}
