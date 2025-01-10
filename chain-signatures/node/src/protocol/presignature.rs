use super::message::{MessageChannel, PresignatureMessage};
use super::state::RunningState;
use super::triple::{Triple, TripleId, TripleManager};
use crate::protocol::contract::primitives::Participants;
use crate::storage::presignature_storage::PresignatureStorage;
use crate::types::{PresignatureProtocol, SecretKeyShare};
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use crypto_shared::PublicKey;
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::config::ProtocolConfig;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use near_account_id::AccountId;

/// Unique number used to identify a specific ongoing presignature generation protocol.
/// Without `PresignatureId` it would be unclear where to route incoming cait-sith presignature
/// generation messages.
pub type PresignatureId = u64;

/// A completed presignature.
pub struct Presignature {
    pub id: PresignatureId,
    pub output: PresignOutput<Secp256k1>,
    pub participants: Vec<Participant>,
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
    pub participants: Vec<Participant>,
    pub protocol: PresignatureProtocol,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub mine: bool,
    pub timestamp: Instant,
    pub timeout: Duration,
}

impl PresignatureGenerator {
    pub fn new(
        protocol: PresignatureProtocol,
        participants: Vec<Participant>,
        triple0: TripleId,
        triple1: TripleId,
        mine: bool,
        timeout: u64,
    ) -> Self {
        Self {
            protocol,
            participants,
            triple0,
            triple1,
            mine,
            timestamp: Instant::now(),
            timeout: Duration::from_millis(timeout),
        }
    }

    pub fn poke(&mut self) -> Result<Action<PresignOutput<Secp256k1>>, ProtocolError> {
        if self.timestamp.elapsed() > self.timeout {
            let id = hash_as_id(self.triple0, self.triple1);
            tracing::warn!(
                presignature_id = id,
                self.triple0,
                self.triple1,
                self.mine,
                "presignature protocol timed out"
            );
            return Err(ProtocolError::Other(
                anyhow::anyhow!("presignature protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("presignature already generated")]
    AlreadyGenerated,
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("triple storage error: {0}")]
    TripleStoreError(String),
    #[error("triple {0} is generating")]
    TripleIsGenerating(TripleId),
    #[error("triple {0} is in garbage collection")]
    TripleIsGarbageCollected(TripleId),
    #[error("triple access denied: id={0}, {1}")]
    TripleDenied(TripleId, &'static str),
    #[error("presignature {0} is generating")]
    PresignatureIsGenerating(PresignatureId),
    #[error("presignature {0} is missing")]
    PresignatureIsMissing(PresignatureId),
    #[error("presignature {0} is in garbage collection")]
    PresignatureIsGarbageCollected(TripleId),
    #[error("presignature access denied: id={0}, {1}")]
    PresignatureDenied(PresignatureId, &'static str),
    #[error("presignature bad parameters")]
    PresignatureBadParameters,
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct PresignatureManager {
    presignature_storage: PresignatureStorage,
    /// Ongoing presignature generation protocols.
    generators: HashMap<PresignatureId, PresignatureGenerator>,
    /// The set of presignatures that were introduced to the system by the current node.
    introduced: HashSet<PresignatureId>,
    /// Garbage collection for presignatures that have either been taken or failed. This
    /// will be maintained for at most presignature timeout period just so messages are
    /// cycled through the system.
    gc: HashMap<PresignatureId, Instant>,
    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
}

impl PresignatureManager {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        my_account_id: &AccountId,
        storage: &PresignatureStorage,
    ) -> Self {
        Self {
            presignature_storage: storage.clone(),
            generators: HashMap::new(),
            introduced: HashSet::new(),
            gc: HashMap::new(),
            me,
            threshold,
            epoch,
            my_account_id: my_account_id.clone(),
        }
    }

    pub async fn insert(&mut self, presignature: Presignature, mine: bool, back: bool) {
        let id = presignature.id;
        tracing::debug!(id, mine, "inserting presignature");
        if let Err(store_err) = self
            .presignature_storage
            .insert(presignature, mine, back)
            .await
        {
            tracing::error!(?store_err, mine, "failed to insert presignature");
        } else {
            // Remove from taken list if it was there
            self.gc.remove(&id);
        }
    }

    /// Returns true if the presignature with the given id is already generated
    pub async fn contains(&self, id: &PresignatureId) -> bool {
        self.presignature_storage
            .contains(id)
            .await
            .map_err(|e| {
                tracing::warn!(?e, "failed to check if presignature exist");
            })
            .unwrap_or(false)
    }

    /// Returns true if the mine presignature with the given id is already generated
    pub async fn contains_mine(&self, id: &PresignatureId) -> bool {
        self.presignature_storage
            .contains_mine(id)
            .await
            .map_err(|e| {
                tracing::warn!(?e, "failed to check if mine presignature exist");
            })
            .unwrap_or(false)
    }

    pub async fn contains_used(&self, id: &PresignatureId) -> bool {
        self.presignature_storage
            .contains_used(id)
            .await
            .map_err(|e| tracing::warn!(?e, "failed to check if presignature is used"))
            .unwrap_or(false)
    }

    pub async fn take(&mut self, id: PresignatureId) -> Result<Presignature, GenerationError> {
        let presignature = self
            .presignature_storage
            .take(&id)
            .await
            .map_err(|store_err| {
                if self.generators.contains_key(&id) {
                    tracing::warn!(id, ?store_err, "presignature is still generating");
                    GenerationError::PresignatureIsGenerating(id)
                } else if self.gc.contains_key(&id) {
                    tracing::warn!(id, ?store_err, "presignature was garbage collected");
                    GenerationError::PresignatureIsGarbageCollected(id)
                } else {
                    tracing::warn!(id, ?store_err, "presignature is missing");
                    GenerationError::PresignatureIsMissing(id)
                }
            })?;

        self.gc.insert(id, Instant::now());
        tracing::debug!(id, "took presignature");
        Ok(presignature)
    }

    pub async fn take_mine(&mut self) -> Option<Presignature> {
        let presignature = self
            .presignature_storage
            .take_mine()
            .await
            .map_err(|e| {
                tracing::error!(?e, "failed to look for mine presignature");
            })
            .ok()?;
        tracing::debug!(id = ?presignature.id, "took presignature of mine");
        Some(presignature)
    }

    /// Returns the number of unspent presignatures available in the manager.
    pub async fn len_generated(&self) -> usize {
        self.presignature_storage
            .len_generated()
            .await
            .map_err(|e| {
                tracing::error!(?e, "failed to count all presignatures");
            })
            .unwrap_or(0)
    }

    /// Returns the number of unspent presignatures assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.presignature_storage
            .len_mine()
            .await
            .map_err(|e| {
                tracing::error!(?e, "failed to count mine presignatures");
            })
            .unwrap_or(0)
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

    pub fn garbage_collect(&mut self, cfg: &ProtocolConfig) {
        let before = self.gc.len();
        self.gc
            .retain(|_, instant| instant.elapsed() < Duration::from_millis(cfg.garbage_timeout));
        let removed = before.saturating_sub(self.gc.len());
        if removed > 0 {
            tracing::debug!("garbage collected {} presignatures", removed);
        }
    }

    pub fn refresh_gc(&mut self, id: &PresignatureId) -> bool {
        let entry = self.gc.entry(*id).and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_internal(
        participants: &Participants,
        me: Participant,
        threshold: usize,
        triple0: Triple,
        triple1: Triple,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        mine: bool,
        timeout: u64,
    ) -> Result<PresignatureGenerator, InitializationError> {
        let participants: Vec<_> = participants.keys().cloned().collect();
        let protocol = Box::new(cait_sith::presign(
            &participants,
            me,
            // These paramaters appear to be to make it easier to use different indexing schemes for triples
            // Introduced in this PR https://github.com/LIT-Protocol/cait-sith/pull/7
            &participants,
            me,
            PresignArguments {
                triple0: (triple0.share, triple0.public),
                triple1: (triple1.share, triple1.public),
                keygen_out: KeygenOutput {
                    private_share: *private_share,
                    public_key: *public_key,
                },
                threshold,
            },
        )?);
        Ok(PresignatureGenerator::new(
            protocol,
            participants,
            triple0.id,
            triple1.id,
            mine,
            timeout,
        ))
    }

    /// Starts a new presignature generation protocol.
    pub async fn generate(
        &mut self,
        participants: &Participants,
        triple0: Triple,
        triple1: Triple,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        timeout: u64,
    ) -> Result<(), InitializationError> {
        let id = hash_as_id(triple0.id, triple1.id);

        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        if self.generators.contains_key(&id)
            || self.contains(&id).await
            || self.gc.contains_key(&id)
        {
            tracing::warn!(id, "presignature id collision");
            return Err(InitializationError::BadParameters(format!(
                "id collision: presignature_id={id}"
            )));
        }

        tracing::info!(id, "starting protocol to generate a new presignature");
        let generator = Self::generate_internal(
            participants,
            self.me,
            self.threshold,
            triple0,
            triple1,
            public_key,
            private_share,
            true,
            timeout,
        )?;
        self.generators.insert(id, generator);
        self.introduced.insert(id);
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        Ok(())
    }

    pub async fn stockpile(
        &mut self,
        active: &Participants,
        pk: &PublicKey,
        sk_share: &SecretKeyShare,
        triple_manager: &TripleManager,
        cfg: &ProtocolConfig,
    ) -> Result<(), InitializationError> {
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
            }
        };

        if not_enough_presignatures {
            tracing::debug!("not enough presignatures, generating");
            // To ensure there is no contention between different nodes we are only using triples
            // that we proposed. This way in a non-BFT environment we are guaranteed to never try
            // to use the same triple as any other node.
            if let Some((triple0, triple1)) = triple_manager.take_two_mine().await {
                let presig_participants = active
                    .intersection(&[&triple0.public.participants, &triple1.public.participants]);
                if presig_participants.len() < self.threshold {
                    tracing::warn!(
                        participants = ?presig_participants.keys_vec(),
                        "running: the intersection of participants is less than the threshold"
                    );
                    // TODO: do not insert back triples when we have a clear model for data consistency
                    // between nodes and utilizing only triples that meet threshold requirements.
                    triple_manager.insert(triple0, true, true).await;
                    triple_manager.insert(triple1, true, true).await;
                } else {
                    self.generate(
                        &presig_participants,
                        triple0,
                        triple1,
                        pk,
                        sk_share,
                        cfg.presignature.generation_timeout,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    /// Ensures that the presignature with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`, or
    /// 4) Depends on triples (`triple0`/`triple1`) that are unknown to the node
    // TODO: What if the presignature completed generation and is already spent?
    #[allow(clippy::too_many_arguments)]
    pub async fn get_or_start_generation(
        &mut self,
        participants: &Participants,
        id: PresignatureId,
        triple0: TripleId,
        triple1: TripleId,
        triple_manager: &TripleManager,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        cfg: &ProtocolConfig,
    ) -> Result<&mut PresignatureProtocol, GenerationError> {
        if id != hash_as_id(triple0, triple1) {
            tracing::error!(id, "presignature id does not match the expected hash");
            Err(GenerationError::PresignatureBadParameters)
        } else if self.contains(&id).await {
            tracing::debug!(id, "presignature already generated");
            Err(GenerationError::AlreadyGenerated)
        } else if self.gc.contains_key(&id) {
            tracing::warn!(id, "presignature was garbage collected");
            Err(GenerationError::PresignatureIsGarbageCollected(id))
        } else {
            match self.generators.entry(id) {
                Entry::Vacant(entry) => {
                    tracing::info!(id, "joining protocol to generate a new presignature");
                    let (triple0, triple1) = match triple_manager.take_two(triple0, triple1).await {
                        Ok(result) => result,
                        Err(error) => match error {
                            GenerationError::TripleIsGenerating(_) => {
                                tracing::warn!(
                                    ?error,
                                    id,
                                    triple0,
                                    triple1,
                                    "could not initiate non-introduced presignature: one triple is generating"
                                );
                                return Err(error);
                            }
                            GenerationError::TripleIsGarbageCollected(_) => {
                                tracing::warn!(
                                    ?error,
                                    id,
                                    triple0,
                                    triple1,
                                    "could not initiate non-introduced presignature: one triple is in garbage collection"
                                );
                                return Err(error);
                            }
                            GenerationError::TripleStoreError(_) => {
                                tracing::warn!(
                                    ?error,
                                    id,
                                    triple0,
                                    triple1,
                                    "could not initiate non-introduced presignature: triple store error"
                                );
                                return Err(error);
                            }
                            _ => {
                                tracing::error!(?error, "Unexpected Generation Error");
                                return Err(error);
                            }
                        },
                    };
                    let generator = Self::generate_internal(
                        participants,
                        self.me,
                        self.threshold,
                        triple0,
                        triple1,
                        public_key,
                        private_share,
                        false,
                        cfg.presignature.generation_timeout,
                    )?;
                    let generator = entry.insert(generator);
                    crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
                        .with_label_values(&[self.my_account_id.as_str()])
                        .inc();
                    Ok(&mut generator.protocol)
                }
                Entry::Occupied(entry) => Ok(&mut entry.into_mut().protocol),
            }
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub async fn poke(&mut self) -> Vec<(Participant, PresignatureMessage)> {
        let mut messages = Vec::new();
        let mut errors = Vec::new();
        let mut presignatures = Vec::new();
        self.generators.retain(|id, generator| {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        crate::metrics::PRESIGNATURE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                        self.gc.insert(*id, Instant::now());
                        self.introduced.remove(id);
                        errors.push(e);
                        break false;
                    }
                };
                match action {
                    Action::Wait => {
                        tracing::debug!("presignature: waiting");
                        // Retain protocol until we are finished
                        return true;
                    }
                    Action::SendMany(data) => {
                        for p in generator.participants.iter() {
                            messages.push((
                                *p,
                                PresignatureMessage {
                                    id: *id,
                                    triple0: generator.triple0,
                                    triple1: generator.triple1,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64
                                },
                            ))
                        }
                    }
                    Action::SendPrivate(p, data) => messages.push((
                        p,
                        PresignatureMessage {
                            id: *id,
                            triple0: generator.triple0,
                            triple1: generator.triple1,
                            epoch: self.epoch,
                            from: self.me,
                            data,
                            timestamp: Utc::now().timestamp() as u64
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            id,
                            me = ?self.me,
                            big_r = ?output.big_r.to_base58(),
                            "completed presignature generation"
                        );
                        let presignature = Presignature {
                            id: *id,
                            output,
                            participants: generator.participants.clone(),
                        };
                        if generator.mine {
                            tracing::info!(id, "assigning presignature to myself");
                            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS
                                .with_label_values(&[self.my_account_id.as_str()])
                                .inc();
                        }
                        presignatures.push((presignature, generator.mine));
                        self.introduced.remove(id);

                        crate::metrics::PRESIGNATURE_LATENCY
                            .with_label_values(&[self.my_account_id.as_str()])
                            .observe(generator.timestamp.elapsed().as_secs_f64());
                        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                        // Do not retain the protocol
                        return false;
                    }
                }
            }
        });

        for (presignature, mine) in presignatures {
            self.insert(presignature, mine, false).await;
        }

        if !errors.is_empty() {
            tracing::warn!(?errors, "failed to generate some presignatures");
        }

        messages
    }

    pub fn execute(
        state: &RunningState,
        active: &Participants,
        protocol_cfg: &ProtocolConfig,
        channel: &MessageChannel,
    ) -> tokio::task::JoinHandle<()> {
        let triple_manager = state.triple_manager.clone();
        let presignature_manager = state.presignature_manager.clone();
        let active = active.clone();
        let protocol_cfg = protocol_cfg.clone();
        let pk = state.public_key;
        let sk_share = state.private_share;
        let channel = channel.clone();

        tokio::task::spawn(async move {
            let mut presignature_manager = presignature_manager.write().await;
            if let Err(err) = presignature_manager
                .stockpile(&active, &pk, &sk_share, &triple_manager, &protocol_cfg)
                .await
            {
                tracing::warn!(?err, "running: failed to stockpile presignatures");
            }

            {
                let messages = presignature_manager
                    .poke()
                    .await
                    .into_iter()
                    .map(|(p, msg)| {
                        (
                            presignature_manager.me,
                            p,
                            super::MpcMessage::Presignature(msg),
                        )
                    });
                channel.send_many(messages).await;
            }

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
