use super::artifact_task::{
    ArtifactProtocol, ProtocolGenerator, ProtocolGeneratorDriver, ProtocolSpawnerTask,
};
use super::message::{MessageChannel, PositProtocolId, PresignatureMessage};
use super::posit::PositAction;
use super::triple::TripleId;
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::MpcSignProtocol;
use crate::storage::presignature_storage::{PresignatureSlot, PresignatureStorage};
use crate::storage::triple_storage::{TriplesTaken, TriplesTakenDropper};
use crate::storage::protocol_storage::ProtocolArtifact;
use crate::storage::TripleStorage;
use crate::types::{PresignatureProtocol, SecretKeyShare};
use crate::util::AffinePointExt;

use async_trait::async_trait;
use cait_sith::protocol::{MessageData, Participant};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::PublicKey;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Unique number used to identify a specific ongoing presignature generation protocol.
pub type PresignatureId = u64;

/// The full presignature id — ties together the presignature and its source triple pair.
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
    pub holders: Option<Vec<Participant>>,
}

impl fmt::Debug for Presignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presignature")
            .field("id", &self.id)
            .field("participants", &self.participants)
            .field("holders", &self.holders)
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
            holders: None,
            participants: fields.participants,
        })
    }
}

// ── PresignatureGenerator ─────────────────────────────────────────────────────

pub struct PresignatureGenerator {
    id: PresignatureId,
    epoch: u64,
    me: Participant,
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
    async fn recv(&mut self) -> Option<PresignatureMessage> {
        match tokio::time::timeout(
            self.timeout.saturating_sub(self.created.elapsed()),
            self.inbox.recv(),
        )
        .await
        {
            Ok(Some(msg)) => Some(msg),
            Ok(None) => {
                tracing::warn!(id = self.id, owner = ?self.owner, "presignature generation aborted");
                None
            }
            Err(_) => {
                tracing::warn!(id = self.id, owner = ?self.owner, "presignature generation timeout");
                None
            }
        }
    }

}

#[async_trait]
impl ProtocolGeneratorDriver for PresignatureGenerator {
    type Output = PresignOutput<Secp256k1>;

    fn created_at(&self) -> Instant {
        self.created
    }

    fn observe_before_poke_delay(&self) {
        crate::metrics::protocols::PRESIGNATURE_BEFORE_POKE_DELAY
            .observe(self.created.elapsed().as_millis() as f64);
    }

    fn observe_poke_cpu_time(&self, elapsed: Duration) {
        crate::metrics::protocols::PRESIGNATURE_POKE_CPU_TIME
            .observe(elapsed.as_millis() as f64);
    }

    async fn poke(&mut self) -> Result<cait_sith::protocol::Action<Self::Output>, ()> {
        match self.protocol.poke() {
            Ok(action) => Ok(action),
            Err(err) => {
                crate::metrics::protocols::PRESIGNATURE_GENERATOR_FAILURES.inc();
                if self.owner == self.me {
                    crate::metrics::protocols::PRESIGNATURE_GENERATOR_MINE_FAILURES.inc();
                }
                tracing::warn!(id = ?self.id, owner = ?self.owner, ?err, "presignature generation failed");
                Err(())
            }
        }
    }

    async fn wait_for_messages(&mut self) -> bool {
        let Some(msg) = self.recv().await else {
            crate::metrics::protocols::PRESIGNATURE_GENERATOR_FAILURES.inc();
            return false;
        };
        self.protocol.message(msg.from, msg.data);
        true
    }

    async fn send_many(&mut self, data: MessageData) {
        for to in &self.participants {
            if *to == self.me {
                continue;
            }
            self.msg
                .send(
                    self.me,
                    *to,
                    PresignatureMessage {
                        id: self.id,
                        pair_id: self.dropper.id,
                        epoch: self.epoch,
                        from: self.me,
                        data: data.clone(),
                        timestamp: Utc::now().timestamp() as u64,
                    },
                )
                .await;
        }
    }

    async fn send_private(&mut self, to: Participant, data: MessageData) {
        self.msg
            .send(
                self.me,
                to,
                PresignatureMessage {
                    id: self.id,
                    pair_id: self.dropper.id,
                    epoch: self.epoch,
                    from: self.me,
                    data,
                    timestamp: Utc::now().timestamp() as u64,
                },
            )
            .await;
    }

    async fn finish(
        mut self,
        output: Self::Output,
        run_elapsed: Duration,
        total_wait: Duration,
        total_pokes: usize,
    ) {
        crate::metrics::protocols::PRESIGNATURE_LATENCY.observe(run_elapsed.as_secs_f64());
        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS.inc();
        crate::metrics::protocols::PRESIGNATURE_ACCRUED_WAIT_DELAY
            .observe(total_wait.as_millis() as f64);
        crate::metrics::protocols::PRESIGNATURE_POKES_CNT.observe(total_pokes as f64);

        tracing::info!(
            id = ?self.id,
            owner = ?self.owner,
            big_r = ?output.big_r.to_base58(),
            elapsed = ?self.created.elapsed(),
            "completed presignature generation"
        );

        if self.owner == self.me {
            tracing::info!(id = self.id, "assigning presignature to myself");
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS.inc();
        }

        let presignature = Presignature {
            id: self.id,
            output,
            participants: self.participants.clone(),
            holders: Some(self.participants.clone()),
        };
        self.slot.insert(presignature, self.owner).await;
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

// ── PendingTriples ────────────────────────────────────────────────────────────

/// Either an already-held triple pair (proposer) or one to be fetched from
/// storage (deliberator).
#[allow(clippy::large_enum_variant)]
enum PendingTriples {
    Available(TriplesTaken),
    InStorage(TripleId, TripleStorage),
}

pub struct PresignatureGenerationDeps(PendingTriples);

impl PendingTriples {
    /// Wait up to `timeout` for the triple pair to become available, then take it.
    async fn fetch(self, owner: Participant, timeout: Duration) -> Option<TriplesTaken> {
        let (pair_id, storage) = match self {
            Self::Available(triples) => return Some(triples),
            Self::InStorage(pair_id, storage) => (pair_id, storage),
        };

        match tokio::time::timeout(timeout, async {
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            loop {
                interval.tick().await;
                if let Some(triples) = storage.take(pair_id, owner).await {
                    break triples;
                }
            }
        })
        .await
        {
            Ok(triples) => Some(triples),
            Err(_) => {
                tracing::warn!(?pair_id, "timeout waiting for triple pair");
                None
            }
        }
    }
}

// ── PresignatureArtifact ──────────────────────────────────────────────────────

/// Shared context for all presignature-generation tasks.
#[derive(Clone)]
pub struct PresignatureContext {
    pub triples: TripleStorage,
    pub presignatures: PresignatureStorage,
    pub msg: MessageChannel,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub node_account_id: String,
}

/// Marker struct implementing [`ArtifactProtocol`] for presignature generation.
pub struct PresignatureArtifact;

impl ArtifactProtocol for PresignatureArtifact {
    type TaskId = FullPresignatureId;
    type ProposerState = TriplesTaken;
    type GenerationDeps = PresignatureGenerationDeps;
    type Context = PresignatureContext;

    fn posit_id(task_id: FullPresignatureId) -> PositProtocolId {
        PositProtocolId::Presignature(task_id)
    }

    fn validate_task_id(task_id: FullPresignatureId) -> bool {
        task_id.validate()
    }

    async fn propose(
        ctx: &PresignatureContext,
        _me: Participant,
        active: &[Participant],
        threshold: usize,
    ) -> Option<(FullPresignatureId, TriplesTaken, Vec<Participant>)> {
        let triples = ctx.triples.take_mine().await?;
        let pair_id = triples.artifact.id;

        let Some(holders) = triples.artifact.holders() else {
            tracing::error!(?pair_id, "holders not set on taken triple pair");
            return None;
        };

        let participants = intersect_vec(&[active, holders]);
        if participants.len() < threshold {
            tracing::warn!(
                ?pair_id,
                ?active,
                ?participants,
                "intersection < threshold, trashing triple pair"
            );
            return None;
        }

        let id = FullPresignatureId::from_pair(pair_id);
        tracing::info!(?id, "proposing presignature protocol");
        Some((id, triples, participants))
    }

    /// Deliberator waits up to `budget` for the required triple pair to appear
    /// in storage before deciding to accept or reject.
    async fn can_participate(
        ctx: &PresignatureContext,
        task_id: FullPresignatureId,
        _from: Participant,
        budget: Duration,
    ) -> bool {
        let pair_id = task_id.pair_id;

        let found = tokio::time::timeout(budget, async {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                if ctx.triples.contains_reserved(pair_id).await
                    || ctx.triples.contains(pair_id).await
                {
                    return true;
                }
            }
        })
        .await;

        match found {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    ?pair_id,
                    "deliberator timed out waiting for triple, rejecting presignature posit"
                );
                false
            }
        }
    }

    async fn is_known(ctx: &PresignatureContext, task_id: FullPresignatureId) -> bool {
        ctx.presignatures.contains(task_id.id).await
    }

    async fn should_stockpile(
        ctx: &PresignatureContext,
        cfg: &ProtocolConfig,
        me: Participant,
        ongoing: usize,
        introduced: usize,
    ) -> bool {
        let len_potential = ctx.presignatures.len_generated().await + ongoing;
        if len_potential >= cfg.presignature.max_presignatures as usize {
            return false;
        }
        let len_mine = ctx.presignatures.len_by_owner(me).await;
        len_mine < cfg.presignature.min_presignatures as usize
            && introduced < cfg.max_concurrent_introduction as usize
            && ongoing < cfg.max_concurrent_generation as usize
    }

    fn generation_timeout(cfg: &ProtocolConfig) -> Duration {
        Duration::from_millis(cfg.presignature.generation_timeout)
    }

    async fn prepare_generation(
        ctx: &PresignatureContext,
        task_id: FullPresignatureId,
        _owner: Participant,
        proposer_state: Option<TriplesTaken>,
        _timeout: Duration,
    ) -> Option<PresignatureGenerationDeps> {
        let pending = match proposer_state {
            Some(triples) => PendingTriples::Available(triples),
            None => PendingTriples::InStorage(task_id.pair_id, ctx.triples.clone()),
        };
        Some(PresignatureGenerationDeps(pending))
    }

    async fn run_generation(
        task_id: FullPresignatureId,
        me: Participant,
        owner: Participant,
        participants: Vec<Participant>,
        threshold: usize,
        epoch: u64,
        dependencies: PresignatureGenerationDeps,
        ctx: PresignatureContext,
        timeout: Duration,
    ) {
        let Some(slot) = ctx.presignatures.create_slot(task_id.id, owner).await else {
            tracing::warn!(?task_id, "presignature slot already taken, skipping");
            return;
        };

        let keygen_out = KeygenOutput {
            private_share: ctx.private_share,
            public_key: ctx.public_key,
        };

        let mut sorted_participants = participants.clone();
        sorted_participants.sort();

        let Some(triples) = dependencies.0.fetch(owner, timeout).await else {
            return;
        };

        let (pair, dropper) = triples.take();
        let protocol = match cait_sith::presign(
            &sorted_participants,
            me,
            &sorted_participants,
            me,
            PresignArguments {
                triple0: (pair.triple0.share, pair.triple0.public),
                triple1: (pair.triple1.share, pair.triple1.public),
                keygen_out,
                threshold,
            },
        ) {
            Ok(p) => Box::new(p),
            Err(err) => {
                tracing::warn!(?task_id, ?err, "failed to initialise presignature protocol");
                return;
            }
        };

        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS.inc();
        if owner == me {
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE.inc();
        }

        let inbox = ctx.msg.subscribe_presignature(task_id.id).await;

        #[cfg(feature = "debug-page")]
        let node_account_id = ctx.node_account_id.clone();

        let generator = PresignatureGenerator {
            id: task_id.id,
            epoch,
            me,
            owner,
            participants: sorted_participants,
            protocol,
            dropper,
            created: Instant::now(),
            timeout,
            slot,
            inbox,
            msg: ctx.msg,
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                node_account_id,
                format!("PresignatureGenerator {task_id:#?}"),
            ),
        };
        ProtocolGenerator::new(generator).run().await;
    }

    async fn subscribe_posit(
        ctx: &PresignatureContext,
    ) -> mpsc::Receiver<(FullPresignatureId, Participant, PositAction)> {
        ctx.msg.subscribe_presignature_posit().await
    }

    async fn unsubscribe_posit(ctx: PresignatureContext) {
        ctx.msg.unsubscribe_presignature_posit().await;
    }

    async fn update_metrics(
        ctx: &PresignatureContext,
        me: Participant,
        ongoing: usize,
        _introduced: usize,
    ) {
        crate::metrics::storage::NUM_PRESIGNATURES_MINE
            .set(ctx.presignatures.len_by_owner(me).await as i64);
        crate::metrics::storage::NUM_PRESIGNATURES_TOTAL
            .set(ctx.presignatures.len_generated().await as i64);
        crate::metrics::protocols::NUM_PRESIGNATURE_GENERATORS_TOTAL.set(ongoing as i64);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn hash_as_id(pair_id: TripleId) -> PresignatureId {
    let mut hasher = Sha3_256::new();
    hasher.update(pair_id.to_le_bytes());
    let id: [u8; 32] = hasher.finalize().into();
    u64::from_le_bytes(crate::util::first_8_bytes(id))
}

// ── PresignatureSpawnerTask ───────────────────────────────────────────────────

/// Top-level handle for the presignature-generation spawner.
pub struct PresignatureSpawnerTask {
    inner: ProtocolSpawnerTask,
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
        let context = PresignatureContext {
            triples: ctx.triple_storage.clone(),
            presignatures: ctx.presignature_storage.clone(),
            msg: ctx.msg_channel.clone(),
            private_share: *private_share,
            public_key: *public_key,
            node_account_id: ctx.my_account_id.to_string(),
        };
        Self {
            inner: ProtocolSpawnerTask::new::<PresignatureArtifact>(
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

impl Drop for PresignatureSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::{protocol::Participant, PresignOutput};
    use k256::{elliptic_curve::CurveArithmetic, Secp256k1};

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
            holders: None,
        };

        let serialized =
            serde_json::to_string(&presignature).expect("Failed to serialize Presignature");
        let deserialized: Presignature =
            serde_json::from_str(&serialized).expect("Failed to deserialize Presignature");

        assert_eq!(presignature.id, deserialized.id);
        assert_eq!(presignature.output.big_r, deserialized.output.big_r);
        assert_eq!(presignature.output.k, deserialized.output.k);
        assert_eq!(presignature.output.sigma, deserialized.output.sigma);
        assert_eq!(presignature.participants, deserialized.participants);
    }

    #[test]
    fn full_presignature_id_validates() {
        let pair_id: TripleId = 12345;
        let full_id = FullPresignatureId::from_pair(pair_id);
        assert!(full_id.validate());

        let tampered = FullPresignatureId {
            id: full_id.id ^ 1,
            pair_id,
        };
        assert!(!tampered.validate());
    }
}
