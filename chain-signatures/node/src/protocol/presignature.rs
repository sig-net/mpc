use super::message::{MessageChannel, PositMessage, PositProtocolId, PresignatureMessage};
use super::posit::{PositAction, Positor, Posits};
use super::state::RunningState;
use super::triple::TripleId;
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::error::GenerationError;
use crate::protocol::posit::PositInternalAction;
use crate::storage::presignature_storage::{
    PresignatureSlot, PresignatureStorage, PresignatureTaken,
};
use crate::storage::triple_storage::{TriplesTaken, TriplesTakenDropper};
use crate::storage::TripleStorage;
use crate::types::{PresignatureProtocol, SecretKeyShare};
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, Participant, ProtocolError};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::PublicKey;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

use near_account_id::AccountId;

/// Unique number used to identify a specific ongoing presignature generation protocol.
/// Without `PresignatureId` it would be unclear where to route incoming cait-sith presignature
/// generation messages.
pub type PresignatureId = u64;

/// The full presignature id. This encompasses the presignature id and the two triples
/// that were used to generate it.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

/// An ongoing presignature generator.
pub struct PresignatureGenerator {
    pub owner: Participant,
    pub participants: Vec<Participant>,
    pub protocol: PresignatureProtocol,
    pub dropper: TriplesTakenDropper,
    pub timestamp: Instant,
    pub timeout: Duration,
    /// latest poked time, total acrued wait time and total pokes per presignature protocol
    pub poked_latest: Option<(Instant, Duration, u64)>,
    pub slot: PresignatureSlot,
}

impl PresignatureGenerator {
    pub fn new(
        owner: Participant,
        protocol: PresignatureProtocol,
        participants: &[Participant],
        dropper: TriplesTakenDropper,
        timeout: u64,
        slot: PresignatureSlot,
    ) -> Self {
        Self {
            owner,
            participants: participants.to_vec(),
            protocol,
            dropper,
            timestamp: Instant::now(),
            timeout: Duration::from_millis(timeout),
            poked_latest: None,
            slot,
        }
    }

    pub fn poke(&mut self) -> Result<Action<PresignOutput<Secp256k1>>, ProtocolError> {
        if self.timestamp.elapsed() > self.timeout {
            let id = hash_as_id(self.dropper.id0, self.dropper.id1);
            tracing::warn!(
                owner = ?self.owner,
                presignature_id = id,
                triples = ?self.dropper,
                "presignature protocol timed out"
            );
            return Err(ProtocolError::Other(
                anyhow::anyhow!("presignature protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct PresignatureManager {
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    /// Ongoing presignature generation protocols.
    generators: HashMap<PresignatureId, PresignatureGenerator>,
    /// The set of presignatures that were introduced to the system by the current node.
    introduced: HashSet<PresignatureId>,
    /// The protocol posits that are currently being proposed by us.
    posits: Posits<PresignatureId, TriplesTaken>,

    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
    msg: MessageChannel,
}

impl PresignatureManager {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        my_account_id: &AccountId,
        triples: &TripleStorage,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
    ) -> Self {
        Self {
            triples: triples.clone(),
            presignatures: presignatures.clone(),
            generators: HashMap::new(),
            introduced: HashSet::new(),
            posits: Posits::new(me),
            me,
            threshold,
            epoch,
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

    pub async fn contains_used(&self, id: PresignatureId) -> bool {
        self.presignatures.contains_used(id).await
    }

    pub async fn process_posit(
        &mut self,
        id: FullPresignatureId,
        from: Participant,
        action: PositAction,
    ) -> Option<(Vec<Participant>, Positor<TriplesTaken>)> {
        // TODO: we should also validate on us having the triple t0 and t1 here as well.
        // For now, this validation is done in the `generate` function, so the protocol
        // does not advance until the triples are available.

        let internal_action = if !id.validate() {
            tracing::error!(?id, "presignature id does not match the expected hash");
            PositInternalAction::Reply(PositAction::Reject)
        } else if self.contains(id.id).await {
            tracing::warn!(?id, "presignature already generated");
            PositInternalAction::None
        } else {
            self.posits.act(id.id, from, self.threshold, &action)
        };

        let mut start = None;
        match internal_action {
            PositInternalAction::None => {}
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
                start = Some((participants, positor));
            }
        }

        start
    }

    pub async fn take_mine(&mut self) -> Option<PresignatureTaken> {
        let taken = self.presignatures.take_mine(self.me).await?;
        tracing::debug!(id = ?taken.presignature.id, "took presignature of mine");
        Some(taken)
    }

    /// Returns the number of unspent presignatures available in the manager.
    pub async fn len_generated(&self) -> usize {
        self.presignatures.len_generated().await
    }

    /// Returns the number of unspent presignatures assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.presignatures.len_by_owner(self.me).await
    }

    /// Returns if there are unspent presignatures available in the manager.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Returns the number of unspent presignatures we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        let complete_presignatures = self.len_generated().await;
        let ongoing_generators = self.generators.len();
        complete_presignatures + ongoing_generators
    }

    /// Starts a new presignature generation protocol.
    async fn propose(&mut self, active: &[Participant]) {
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

        self.introduced.insert(id.id);
        self.posits.propose(self.me, id.id, triples, &participants);
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
                    && self.introduced.len() < cfg.max_concurrent_introduction as usize
                    && self.generators.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_presignatures {
            tracing::debug!("not enough presignatures, generating");
            self.propose(active).await;
        }
    }

    pub fn generator(&mut self, id: PresignatureId) -> Option<&mut PresignatureProtocol> {
        self.generators.get_mut(&id).map(|gen| &mut gen.protocol)
    }

    pub async fn generate(
        &mut self,
        id: FullPresignatureId,
        positor: Positor<TriplesTaken>,
        participants: &[Participant],
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        cfg: &ProtocolConfig,
    ) -> Result<&mut PresignatureProtocol, GenerationError> {
        let (proposer, triples) = match positor {
            Positor::Proposer(proposer, triples) => (proposer, Some(triples)),
            Positor::Deliberator(proposer) => (proposer, None),
        };

        tracing::info!(
            ?id,
            ?proposer,
            "starting protocol to generate a new presignature"
        );

        let entry = match self.generators.entry(id.id) {
            Entry::Occupied(entry) => {
                tracing::warn!(?id, ?proposer, "presignature already generating");
                return Ok(&mut entry.into_mut().protocol);
            }
            Entry::Vacant(entry) => entry,
        };

        // TODO: decide whether to reserve first before starting the protocol for both the proposer and joiners
        let Some(slot) = self.presignatures.reserve(id.id).await else {
            return Err(GenerationError::PresignatureReserveError);
        };

        let triples = if let Some(triples) = triples {
            triples
        } else {
            self.triples
                .take_two(id.t0, id.t1, proposer, self.me)
                .await
                .ok_or(GenerationError::TripleMissing(id.t0, id.t1))?
        };

        let (triple0, triple1, dropper) = triples.take();
        let protocol = Box::new(cait_sith::presign(
            participants,
            self.me,
            // These paramaters appear to be to make it easier to use different indexing schemes for triples
            // Introduced in this PR https://github.com/LIT-Protocol/cait-sith/pull/7
            participants,
            self.me,
            PresignArguments {
                triple0: (triple0.share, triple0.public),
                triple1: (triple1.share, triple1.public),
                keygen_out: KeygenOutput {
                    private_share: *private_share,
                    public_key: *public_key,
                },
                threshold: self.threshold,
            },
        )?);
        let generator = PresignatureGenerator::new(
            proposer,
            protocol,
            participants,
            dropper,
            cfg.presignature.generation_timeout,
            slot,
        );
        let generator = entry.insert(generator);
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        if generator.owner != self.me {
            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE
                .with_label_values(&[self.my_account_id.as_str()])
                .inc();
        }

        Ok(&mut generator.protocol)
    }

    /// Poke all ongoing presignature generation protocols to completion.
    pub async fn poke(&mut self) {
        let mut errors = Vec::new();

        let presignature_generator_failures_metric =
            crate::metrics::PRESIGNATURE_GENERATOR_FAILURES
                .with_label_values(&[self.my_account_id.as_str()]);
        let presignature_before_poke_delay_metric = crate::metrics::PRESIGNATURE_BEFORE_POKE_DELAY
            .with_label_values(&[self.my_account_id.as_str()]);
        let presignature_accrued_wait_delay_metric =
            crate::metrics::PRESIGNATURE_ACCRUED_WAIT_DELAY
                .with_label_values(&[self.my_account_id.as_str()]);
        let presignature_pokes_cnt_metric = crate::metrics::PRESIGNATURE_POKES_CNT
            .with_label_values(&[self.my_account_id.as_str()]);
        let presignature_latency_metric =
            crate::metrics::PRESIGNATURE_LATENCY.with_label_values(&[self.my_account_id.as_str()]);
        let presignature_generator_success_mine_metric =
            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS
                .with_label_values(&[self.my_account_id.as_str()]);
        let presignature_generator_success_metric =
            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS
                .with_label_values(&[self.my_account_id.as_str()]);
        let presignature_poke_cpu_time_metric = crate::metrics::PRESIGNATURE_POKE_CPU_TIME
            .with_label_values(&[self.my_account_id.as_str()]);

        let mut remove = Vec::new();
        for (id, generator) in self.generators.iter_mut() {
            loop {
                let generator_poke_time = Instant::now();
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        presignature_generator_failures_metric.inc();
                        self.msg.filter_presignature(*id).await;
                        self.introduced.remove(id);
                        errors.push(e);
                        remove.push(*id);
                        break;
                    }
                };
                match action {
                    Action::Wait => {
                        // Retain protocol until we are finished
                        break;
                    }
                    Action::SendMany(data) => {
                        for to in generator.participants.iter() {
                            if *to == self.me {
                                continue;
                            }
                            self.msg
                                .send(
                                    self.me,
                                    *to,
                                    PresignatureMessage {
                                        id: *id,
                                        triple0: generator.dropper.id0,
                                        triple1: generator.dropper.id1,
                                        epoch: self.epoch,
                                        from: self.me,
                                        data: data.clone(),
                                        timestamp: Utc::now().timestamp() as u64,
                                    },
                                )
                                .await;
                        }
                        let (total_wait, total_pokes) =
                            if let Some((last_poked, total_wait, total_pokes)) =
                                &generator.poked_latest
                            {
                                (
                                    *total_wait + (generator_poke_time - *last_poked),
                                    total_pokes + 1,
                                )
                            } else {
                                let start_time = generator.timestamp;
                                presignature_before_poke_delay_metric
                                    .observe((generator_poke_time - start_time).as_millis() as f64);
                                (Duration::from_millis(0), 1)
                            };
                        generator.poked_latest = Some((Instant::now(), total_wait, total_pokes));
                        presignature_poke_cpu_time_metric
                            .observe(generator_poke_time.elapsed().as_millis() as f64);
                    }
                    Action::SendPrivate(to, data) => {
                        self.msg
                            .send(
                                self.me,
                                to,
                                PresignatureMessage {
                                    id: *id,
                                    triple0: generator.dropper.id0,
                                    triple1: generator.dropper.id1,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data,
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            )
                            .await;
                        let (total_wait, total_pokes) =
                            if let Some((last_poked, total_wait, total_pokes)) =
                                &generator.poked_latest
                            {
                                (
                                    *total_wait + (generator_poke_time - *last_poked),
                                    total_pokes + 1,
                                )
                            } else {
                                let start_time = generator.timestamp;
                                presignature_before_poke_delay_metric
                                    .observe((generator_poke_time - start_time).as_millis() as f64);
                                (Duration::from_millis(0), 1)
                            };
                        generator.poked_latest = Some((Instant::now(), total_wait, total_pokes));
                        presignature_poke_cpu_time_metric
                            .observe(generator_poke_time.elapsed().as_millis() as f64);
                    }
                    Action::Return(output) => {
                        tracing::info!(
                            id,
                            me = ?self.me,
                            big_r = ?output.big_r.to_base58(),
                            elapsed = ?generator.timestamp.elapsed(),
                            "completed presignature generation"
                        );
                        let presignature = Presignature {
                            id: *id,
                            output,
                            participants: generator.participants.clone(),
                        };
                        if generator.owner == self.me {
                            tracing::info!(id, "assigning presignature to myself");
                            presignature_generator_success_mine_metric.inc();
                        }
                        generator.slot.insert(presignature, generator.owner).await;
                        self.introduced.remove(id);
                        // Do not retain the protocol
                        remove.push(*id);

                        presignature_latency_metric
                            .observe(generator.timestamp.elapsed().as_secs_f64());
                        presignature_generator_success_metric.inc();
                        self.msg.filter_presignature(*id).await;
                        if let Some((last_poked, total_wait, total_pokes)) = generator.poked_latest
                        {
                            let elapsed = generator_poke_time - last_poked;
                            let total_wait = total_wait + elapsed;
                            let total_pokes = total_pokes + 1;
                            presignature_accrued_wait_delay_metric
                                .observe(total_wait.as_millis() as f64);
                            presignature_pokes_cnt_metric.observe(total_pokes as f64);
                        }
                        presignature_poke_cpu_time_metric
                            .observe(generator_poke_time.elapsed().as_millis() as f64);
                        break;
                    }
                }
            }
        }

        for id in remove {
            self.generators.remove(&id);
        }

        if !errors.is_empty() {
            tracing::warn!(?errors, "failed to generate some presignatures");
        }
    }

    pub async fn reserve(&self, id: PresignatureId) -> Option<PresignatureSlot> {
        self.presignatures.reserve(id).await
    }

    pub fn execute(
        state: &RunningState,
        protocol_cfg: &ProtocolConfig,
        active: Vec<Participant>,
    ) -> tokio::task::JoinHandle<()> {
        let presignature_manager = state.presignature_manager.clone();
        let protocol_cfg = protocol_cfg.clone();

        tokio::task::spawn(async move {
            let mut presignature_manager = presignature_manager.write().await;
            presignature_manager.stockpile(&active, &protocol_cfg).await;
            presignature_manager.poke().await;

            crate::metrics::NUM_PRESIGNATURES_MINE
                .with_label_values(&[presignature_manager.my_account_id.as_str()])
                .set(presignature_manager.len_mine().await as i64);
            crate::metrics::NUM_PRESIGNATURES_TOTAL
                .with_label_values(&[presignature_manager.my_account_id.as_str()])
                .set(presignature_manager.len_generated().await as i64);
            crate::metrics::NUM_PRESIGNATURE_GENERATORS_TOTAL
                .with_label_values(&[presignature_manager.my_account_id.as_str()])
                .set(
                    presignature_manager.len_potential().await as i64
                        - presignature_manager.len_generated().await as i64,
                );
        })
    }
}

pub fn hash_as_id(triple0: TripleId, triple1: TripleId) -> PresignatureId {
    let mut hasher = Sha3_256::new();
    hasher.update(triple0.to_le_bytes());
    hasher.update(triple1.to_le_bytes());
    let id: [u8; 32] = hasher.finalize().into();
    let id = u64::from_le_bytes(first_8_bytes(id));

    PresignatureId::from(id)
}

const fn first_8_bytes(input: [u8; 32]) -> [u8; 8] {
    let mut output = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        output[i] = input[i];
        i += 1;
    }
    output
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
