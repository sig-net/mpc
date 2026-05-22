use super::artifact_task::{
    ArtifactProtocol, PokeMode, ProtocolBuildOutput, ProtocolSpawnerTask,
};
use super::message::{MessageChannel, PositProtocolId, TripleMessage};
use super::posit::PositAction;
use super::MpcSignProtocol;
use crate::storage::protocol_storage::ProtocolStorage;
use crate::storage::triple_storage::TriplePair;
use crate::types::TripleProtocol;
use crate::util::AffinePointExt;

use mpc_contract::config::ProtocolConfig;

use cait_sith::protocol::{MessageData, Participant, ProtocolError};
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

// ── TripleArtifact ────────────────────────────────────────────────────────────

/// Shared context for all triple-generation tasks.
#[derive(Clone)]
pub struct TripleContext {
    pub storage: ProtocolStorage<TriplePair>,
    pub msg: MessageChannel,
    pub node_account_id: String,
}

/// Marker struct implementing [`ArtifactProtocol`] for triple generation.
pub struct TripleArtifact;

impl ArtifactProtocol for TripleArtifact {
    type TaskId = TripleId;
    type ProposerState = ();
    type GenerationDeps = ();
    type Context = TripleContext;
    type Artifact = TriplePair;
    type GenerationState = ();
    type Protocol = TripleProtocol;
    type Output = Vec<(
        cait_sith::triples::TripleShare<Secp256k1>,
        cait_sith::triples::TriplePub<Secp256k1>,
    )>;
    type InMessage = TripleMessage;
    type WireMessage = TripleMessage;

    fn poke_mode(_state: &Self::GenerationState) -> PokeMode {
        PokeMode::Blocking
    }

    fn protocol_poke(protocol: &mut Self::Protocol) -> Result<cait_sith::protocol::Action<Self::Output>, ProtocolError> {
        protocol.poke()
    }

    fn protocol_message(protocol: &mut Self::Protocol, from: Participant, data: MessageData) {
        protocol.message(from, data);
    }

    fn split_incoming(msg: Self::InMessage) -> (Participant, MessageData) {
        (msg.from, msg.data)
    }

    fn build_message(
        _state: &Self::GenerationState,
        id: Self::TaskId,
        epoch: u64,
        from: Participant,
        _to: Participant,
        data: MessageData,
    ) -> Self::WireMessage {
        TripleMessage {
            id,
            epoch,
            from,
            data,
            timestamp: Utc::now().timestamp() as u64,
        }
    }

    fn observe_before_poke_delay(_state: &Self::GenerationState, created: Instant) {
        crate::metrics::protocols::TRIPLE_BEFORE_POKE_DELAY.observe(created.elapsed().as_millis() as f64);
    }

    fn observe_poke_cpu_time(_state: &Self::GenerationState, elapsed: Duration) {
        crate::metrics::protocols::TRIPLE_POKE_CPU_TIME.observe(elapsed.as_millis() as f64);
    }

    fn on_poke_protocol_error(
        _state: &mut Self::GenerationState,
        me: Participant,
        owner: Participant,
        err: ProtocolError,
    ) {
        crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
        if owner == me {
            crate::metrics::protocols::TRIPLE_GENERATOR_OWNED_FAILURES.inc();
        }
        tracing::warn!(?err, "triple generation failed");
    }

    fn on_poke_join_error(
        _state: &mut Self::GenerationState,
        me: Participant,
        owner: Participant,
        err: tokio::task::JoinError,
    ) {
        crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
        if owner == me {
            crate::metrics::protocols::TRIPLE_GENERATOR_OWNED_FAILURES.inc();
        }
        tracing::warn!(?err, "triple generation failed in blocking task");
    }

    fn on_recv_closed(
        _state: &mut Self::GenerationState,
        id: Self::TaskId,
        _owner: Participant,
    ) {
        crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
        tracing::warn!(id, "triple generation aborted");
    }

    fn on_recv_timeout(
        _state: &mut Self::GenerationState,
        id: Self::TaskId,
        _owner: Participant,
    ) {
        crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
        tracing::warn!(id, "triple generation timeout");
    }

    fn on_drop(_state: &Self::GenerationState, id: Self::TaskId, msg: MessageChannel) {
        tokio::spawn(async move {
            msg.unsubscribe_triple(id).await;
            msg.filter_triple(id).await;
        });
    }

    async fn finish(
        _state: &mut Self::GenerationState,
        id: Self::TaskId,
        me: Participant,
        owner: Participant,
        participants: &[Participant],
        created: Instant,
        outputs: Self::Output,
        run_elapsed: Duration,
        total_wait: Duration,
        total_pokes: usize,
    ) -> Option<Self::Artifact> {
        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS.inc();
        crate::metrics::protocols::TRIPLE_LATENCY.observe(run_elapsed.as_secs_f64());
        crate::metrics::protocols::TRIPLE_LATENCY_TOTAL.observe(created.elapsed().as_secs_f64());
        crate::metrics::protocols::TRIPLE_ACCRUED_WAIT_DELAY.observe(total_wait.as_millis() as f64);
        crate::metrics::protocols::TRIPLE_POKES_CNT.observe(total_pokes as f64);

        let [first, second, ..] = &outputs[..] else {
            tracing::warn!(id, triples = outputs.len(), "unexpected: not enough triples to make pair");
            return None;
        };
        let first = Triple {
            share: first.0.clone(),
            public: first.1.clone(),
        };
        let second = Triple {
            share: second.0.clone(),
            public: second.1.clone(),
        };

        let pair_is_mine = owner == me;
        tracing::debug!(
            id = ?id,
            ?me,
            ?owner,
            pair_is_mine,
            ?participants,
            big_a0 = ?first.public.big_a.to_base58(),
            big_a1 = ?second.public.big_a.to_base58(),
            elapsed = ?created.elapsed(),
            "completed triple pair generation"
        );

        if pair_is_mine {
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_OWNED_SUCCESS.inc();
        }

        Some(TriplePair {
            id,
            triple0: first,
            triple1: second,
            holders: Some(participants.to_vec()),
        })
    }

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

    async fn prepare_generation(
        _ctx: &TripleContext,
        _task_id: TripleId,
        _owner: Participant,
        _proposer_state: Option<()>,
        _timeout: Duration,
    ) -> Option<()> {
        Some(())
    }

    async fn build_protocol(
        task_id: TripleId,
        me: Participant,
        owner: Participant,
        participants: Vec<Participant>,
        threshold: usize,
        _epoch: u64,
        _dependencies: (),
        ctx: TripleContext,
        _timeout: Duration,
    ) -> Option<ProtocolBuildOutput<Self>> {
        let Some(slot) = ctx.storage.create_slot(task_id, owner).await else {
            tracing::warn!(task_id, "triple slot already taken, skipping generation");
            return None;
        };

        let mut sorted_participants = participants;
        sorted_participants.sort();

        let protocol: TripleProtocol = match cait_sith::triples::generate_triple_many::<Secp256k1, 2>(
            &sorted_participants,
            me,
            threshold,
        ) {
            Ok(protocol) => Box::new(protocol),
            Err(err) => {
                tracing::warn!(task_id, ?err, "failed to initialise triple generator");
                return None;
            }
        };

        let inbox = ctx.msg.subscribe_triple(task_id).await;
        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS.inc();
        Some(ProtocolBuildOutput {
            id: task_id,
            participants: sorted_participants,
            protocol,
            inbox,
            msg: ctx.msg,
            slot: Some(slot),
            state: (),
        })
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
