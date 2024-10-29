use super::contract::primitives::Participants;
use super::cryptography::CryptographicError;
use super::message::TripleMessage;
use super::presignature::GenerationError;
use crate::storage::triple_storage::LockTripleRedisStorage;
use crate::types::TripleProtocol;
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::triples::{TripleGenerationOutput, TriplePub, TripleShare};
use chrono::Utc;
use highway::{HighwayHash, HighwayHasher};
use k256::elliptic_curve::group::GroupEncoding;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use near_account_id::AccountId;

/// Unique number used to identify a specific ongoing triple generation protocol.
/// Without `TripleId` it would be unclear where to route incoming cait-sith triple generation
/// messages.
pub type TripleId = u64;

// TODO: why do we have Clone here? Triples can not be reused.
/// A completed triple.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Triple {
    pub id: TripleId,
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

pub struct TripleGenerator {
    pub id: TripleId,
    pub participants: Vec<Participant>,
    pub protocol: TripleProtocol,
    pub timestamp: Option<Instant>,
    pub timeout: Duration,
}

impl TripleGenerator {
    pub fn new(
        id: TripleId,
        participants: Vec<Participant>,
        protocol: TripleProtocol,
        timeout: u64,
    ) -> Self {
        Self {
            id,
            participants,
            protocol,
            timestamp: None,
            timeout: Duration::from_millis(timeout),
        }
    }

    pub fn poke(&mut self) -> Result<Action<TripleGenerationOutput<Secp256k1>>, ProtocolError> {
        let timestamp = self.timestamp.get_or_insert_with(Instant::now);
        if timestamp.elapsed() > self.timeout {
            tracing::warn!(
                id = self.id,
                elapsed = ?timestamp.elapsed(),
                "triple protocol timed out"
            );
            return Err(ProtocolError::Other(
                anyhow::anyhow!("triple protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct TripleManager {
    /// Triple Storage
    pub triple_storage: LockTripleRedisStorage,

    /// The pool of triple protocols that have yet to be completed.
    pub generators: HashMap<TripleId, TripleGenerator>,

    /// Triples that are queued to be poked. If these generators sit for too long in
    /// the queue, they will be removed due to triple generation timeout.
    pub queued: VecDeque<TripleId>,

    /// Ongoing triple generation protocols. Once added here, they will not be removed until
    /// they are completed or timed out.
    pub ongoing: HashSet<TripleId>,

    /// The set of triples that were introduced to the system by the current node.
    pub introduced: HashSet<TripleId>,

    /// The set of triple ids that were already taken or failed. This will be maintained for at most
    /// triple timeout period just so messages are cycled through the system.
    pub gc: HashMap<TripleId, Instant>,

    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub my_account_id: AccountId,
}

impl fmt::Debug for TripleManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleManager")
            .field("generators", &self.generators.keys().collect::<Vec<_>>())
            .field("queued", &self.queued)
            .field("ongoing", &self.ongoing)
            .field("introduced", &self.introduced)
            .field("gc", &self.gc.keys().collect::<Vec<_>>())
            .field("me", &self.me)
            .field("threshold", &self.threshold)
            .field("epoch", &self.epoch)
            .field("my_account_id", &self.my_account_id)
            .finish()
    }
}

impl TripleManager {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        my_account_id: &AccountId,
        triple_storage: LockTripleRedisStorage,
    ) -> Self {
        Self {
            generators: HashMap::new(),
            queued: VecDeque::new(),
            ongoing: HashSet::new(),
            introduced: HashSet::new(),
            gc: HashMap::new(),
            me,
            threshold,
            epoch,
            triple_storage,
            my_account_id: my_account_id.clone(),
        }
    }

    pub async fn insert(&mut self, triple: Triple) {
        tracing::debug!(id = triple.id, "inserting triple");
        self.gc.remove(&triple.id);
        if let Err(e) = self.triple_storage.write().await.insert(triple).await {
            tracing::warn!(?e, "failed to insert triple");
        }
    }

    pub async fn insert_mine(&mut self, triple: Triple) {
        tracing::debug!(id = triple.id, "inserting mine triple");
        self.gc.remove(&triple.id);
        if let Err(e) = self.triple_storage.write().await.insert_mine(triple).await {
            tracing::warn!(?e, "failed to insert mine triple");
        }
    }

    pub async fn contains(&self, id: &TripleId) -> bool {
        self.triple_storage
            .write()
            .await
            .contains(id)
            .await
            .map_err(|e| tracing::warn!(?e, "failed to check if triple exists"))
            .unwrap_or(false)
    }

    pub async fn contains_mine(&self, id: &TripleId) -> bool {
        self.triple_storage
            .write()
            .await
            .contains_mine(id)
            .await
            .map_err(|e| tracing::warn!(?e, "failed to check if mine triple exists"))
            .unwrap_or(false)
    }

    /// Take two unspent triple by theirs id with no way to return it. Only takes
    /// if both of them are present.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two(
        &mut self,
        id0: TripleId,
        id1: TripleId,
    ) -> Result<(Triple, Triple), GenerationError> {
        let triple_0 = match self.triple_storage.write().await.take(&id0).await {
            Ok(Some(triple)) => triple,
            Ok(None) => {
                if self.generators.contains_key(&id0) {
                    tracing::warn!(id0, "triple is generating");
                    return Err(GenerationError::TripleIsGenerating(id0));
                } else if self.gc.contains_key(&id0) {
                    tracing::warn!(id0, "triple is garbage collected");
                    return Err(GenerationError::TripleIsGarbageCollected(id0));
                } else {
                    tracing::warn!(id0, "triple is missing");
                    return Err(GenerationError::TripleIsMissing(id0));
                }
            }
            Err(e) => {
                tracing::warn!(id0, ?e, "failed to take triple");
                return Err(GenerationError::TripleIsMissing(id0));
            }
        };

        let triple_1 = match self.triple_storage.write().await.take(&id1).await {
            Ok(Some(triple)) => triple,
            Ok(None) => {
                if let Err(e) = self.triple_storage.write().await.insert(triple_0).await {
                    tracing::warn!(id0, ?e, "failed to insert triple back");
                }
                if self.generators.contains_key(&id1) {
                    tracing::warn!(id1, "triple is generating");
                    return Err(GenerationError::TripleIsGenerating(id1));
                } else if self.gc.contains_key(&id1) {
                    tracing::warn!(id1, "triple is garbage collected");
                    return Err(GenerationError::TripleIsGarbageCollected(id1));
                } else {
                    tracing::warn!(id1, "triple is missing");
                    return Err(GenerationError::TripleIsMissing(id1));
                }
            }
            Err(e) => {
                tracing::warn!(id1, ?e, "failed to take triple");
                if let Err(e) = self.triple_storage.write().await.insert(triple_0).await {
                    tracing::warn!(id0, ?e, "failed to insert triple back");
                }
                return Err(GenerationError::TripleIsMissing(id1));
            }
        };

        self.gc.insert(id0, Instant::now());
        self.gc.insert(id1, Instant::now());

        tracing::debug!(id0, id1, "took two triples");

        Ok((triple_0, triple_1))
    }

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&mut self) -> Option<(Triple, Triple)> {
        if self.len_mine().await < 2 {
            tracing::warn!("not enough mine triples");
            return None;
        }
        let triple_0 = match self.triple_storage.write().await.take_mine().await {
            Ok(Some(triple)) => triple,
            Ok(None) => {
                tracing::warn!("no mine triple left");
                return None;
            }
            Err(e) => {
                tracing::warn!(?e, "failed to take mine triple");
                return None;
            }
        };

        let triple_1 = match self.triple_storage.write().await.take_mine().await {
            Ok(Some(triple)) => triple,
            Ok(None) => {
                if let Err(e) = self
                    .triple_storage
                    .write()
                    .await
                    .insert_mine(triple_0)
                    .await
                {
                    tracing::warn!(?e, "failed to insert mine triple back");
                }
                tracing::warn!("no mine triple left");
                return None;
            }
            Err(e) => {
                tracing::warn!(?e, "failed to take mine triple");
                if let Err(e) = self
                    .triple_storage
                    .write()
                    .await
                    .insert_mine(triple_0)
                    .await
                {
                    tracing::warn!(?e, "failed to insert mine triple back");
                }
                return None;
            }
        };

        self.gc.insert(triple_0.id, Instant::now());
        self.gc.insert(triple_1.id, Instant::now());

        tracing::debug!(triple_0.id, triple_1.id, "took two mine triples");

        Some((triple_0, triple_1))
    }

    /// Returns the number of unspent triples available in the manager.
    pub async fn len_generated(&self) -> usize {
        self.triple_storage
            .write()
            .await
            .len_generated()
            .await
            .unwrap_or(0)
    }

    /// Returns the number of unspent triples assigned to this node.
    pub async fn len_mine(&self) -> usize {
        self.triple_storage
            .write()
            .await
            .len_mine()
            .await
            .unwrap_or(0)
    }

    /// Returns if there's any unspent triple in the manager.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub async fn len_potential(&self) -> usize {
        self.len_generated().await + self.generators.len()
    }

    pub async fn has_min_triples(&self, cfg: &ProtocolConfig) -> bool {
        self.len_mine().await >= cfg.triple.min_triples as usize
    }

    /// Clears an entry from failed triples if that triple protocol was created more than 2 hrs ago
    pub fn garbage_collect(&mut self, cfg: &ProtocolConfig) {
        let before = self.gc.len();
        self.gc.retain(|_, timestamp| {
            timestamp.elapsed() < Duration::from_millis(cfg.garbage_timeout)
        });
        let garbage_collected = before.saturating_sub(self.gc.len());
        if garbage_collected > 0 {
            tracing::debug!("garbage collected {} triples", garbage_collected);
        }
    }

    /// Refresh item in the garbage collection. If it is present, return true and update internally
    /// the timestamp for gabage collection.
    pub fn refresh_gc(&mut self, id: &TripleId) -> bool {
        let entry = self.gc.entry(*id).and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }

    /// Starts a new Beaver triple generation protocol.
    pub async fn generate(
        &mut self,
        participants: &Participants,
        timeout: u64,
    ) -> Result<(), InitializationError> {
        let id = rand::random();

        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        if self.generators.contains_key(&id)
            || self.contains(&id).await
            || self.gc.contains_key(&id)
        {
            tracing::warn!(id, "triple id collision");
            return Err(InitializationError::BadParameters(format!(
                "id collision: triple_id={id}"
            )));
        }

        tracing::info!(id, "starting protocol to generate a new triple");
        let participants: Vec<_> = participants.keys().cloned().collect();
        let protocol: TripleProtocol = Box::new(cait_sith::triples::generate_triple::<Secp256k1>(
            &participants,
            self.me,
            self.threshold,
        )?);
        self.generators.insert(
            id,
            TripleGenerator::new(id, participants, protocol, timeout),
        );
        self.queued.push_back(id);
        self.introduced.insert(id);
        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        Ok(())
    }

    /// Stockpile triples if the amount of unspent triples is below the minimum
    /// and the maximum number of all ongoing generation protocols is below the maximum.
    pub async fn stockpile(
        &mut self,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Result<(), InitializationError> {
        let not_enough_triples = {
            // Stopgap to prevent too many triples in the system. This should be around min_triple*nodes*2
            // for good measure so that we have enough triples to do presig generation while also maintain
            // the minimum number of triples where a single node can't flood the system.
            if self.len_potential().await >= cfg.triple.max_triples as usize {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.len_mine().await < cfg.triple.min_triples as usize
                    && self.introduced.len() < cfg.max_concurrent_introduction as usize
                    && self.generators.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_triples {
            tracing::debug!("not enough triples, generating");
            self.generate(participants, cfg.triple.generation_timeout)
                .await?;
        }
        Ok(())
    }

    /// Ensures that the triple with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`
    // TODO: What if the triple completed generation and is already spent?
    pub async fn get_or_start_generation(
        &mut self,
        id: TripleId,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Result<Option<&mut TripleProtocol>, CryptographicError> {
        if self.contains(&id).await || self.gc.contains_key(&id) {
            Ok(None)
        } else {
            let potential_len = self.len_potential().await;
            match self.generators.entry(id) {
                Entry::Vacant(e) => {
                    if potential_len >= cfg.triple.max_triples as usize {
                        // We are at the maximum amount of triples, we cannot generate more. So just in case a node
                        // sends more triple generation requests, reject them and have them tiemout.
                        return Ok(None);
                    }

                    tracing::info!(id, "joining protocol to generate a new triple");
                    let participants = participants.keys_vec();
                    let protocol = Box::new(cait_sith::triples::generate_triple::<Secp256k1>(
                        &participants,
                        self.me,
                        self.threshold,
                    )?);
                    let generator = e.insert(TripleGenerator::new(
                        id,
                        participants,
                        protocol,
                        cfg.triple.generation_timeout,
                    ));
                    self.queued.push_back(id);
                    crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS
                        .with_label_values(&[self.my_account_id.as_str()])
                        .inc();
                    Ok(Some(&mut generator.protocol))
                }
                Entry::Occupied(e) => Ok(Some(&mut e.into_mut().protocol)),
            }
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub async fn poke(&mut self, cfg: &ProtocolConfig) -> Vec<(Participant, TripleMessage)> {
        // Add more protocols to the ongoing pool if there is space.
        let to_generate_len = cfg.max_concurrent_generation as usize - self.ongoing.len();
        if !self.queued.is_empty() && to_generate_len > 0 {
            for _ in 0..to_generate_len {
                self.queued.pop_front().map(|id| self.ongoing.insert(id));
            }
        }

        let mut messages = Vec::new();
        let mut errors = Vec::new();
        let mut new_triples = Vec::new();
        let mut new_mine_triples = Vec::new();
        self.generators.retain(|id, generator| {
            if !self.ongoing.contains(id) {
                // If the protocol is not ongoing, we should retain it for the next time
                // it is in the ongoing pool.
                return true;
            }

            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        errors.push(e);
                        crate::metrics::TRIPLE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                        self.gc.insert(*id, Instant::now());
                        self.ongoing.remove(id);
                        self.introduced.remove(id);
                        tracing::warn!(
                            elapsed = ?generator.timestamp.unwrap().elapsed(),
                            "added {id} to failed triples"
                        );
                        break false;
                    }
                };

                match action {
                    Action::Wait => {
                        tracing::debug!("triple: waiting");
                        // Retain protocol until we are finished
                        break true;
                    }
                    Action::SendMany(data) => {
                        for p in &generator.participants {
                            messages.push((
                                *p,
                                TripleMessage {
                                    id: *id,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            ))
                        }
                    }
                    Action::SendPrivate(p, data) => messages.push((
                        p,
                        TripleMessage {
                            id: *id,
                            epoch: self.epoch,
                            from: self.me,
                            data,
                            timestamp: Utc::now().timestamp() as u64,
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            id,
                            me = ?self.me,
                            elapsed = ?generator.timestamp.unwrap().elapsed(),
                            big_a = ?output.1.big_a.to_base58(),
                            big_b = ?output.1.big_b.to_base58(),
                            big_c = ?output.1.big_c.to_base58(),
                            "completed triple generation"
                        );

                        if let Some(start_time) = generator.timestamp {
                            crate::metrics::TRIPLE_LATENCY
                                .with_label_values(&[self.my_account_id.as_str()])
                                .observe(start_time.elapsed().as_secs_f64());
                        }

                        crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();

                        let triple = Triple {
                            id: *id,
                            share: output.0,
                            public: output.1,
                        };

                        // After creation the triple is assigned to a random node, which is NOT necessarily the one that initiated it's creation
                        let triple_is_mine = {
                            // This is an entirely unpredictable value to all participants because it's a combination of big_c_i
                            // It is the same value across all participants
                            let big_c = triple.public.big_c;

                            // We turn this into a u64 in a way not biased to the structure of the byte serialisation so we hash it
                            // We use Highway Hash because the DefaultHasher doesn't guarantee a consistent output across versions
                            let entropy =
                                HighwayHasher::default().hash64(&big_c.to_bytes()) as usize;

                            let num_participants = generator.participants.len();
                            // This has a *tiny* bias towards lower indexed participants, they're up to (1 + num_participants / u64::MAX)^2 times more likely to be selected
                            // This is acceptably small that it will likely never result in a biased selection happening
                            let triple_owner = generator.participants[entropy % num_participants];

                            triple_owner == self.me
                        };

                        if triple_is_mine {
                            new_mine_triples.push(triple.clone());
                            crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS
                                .with_label_values(&[self.my_account_id.as_str()])
                                .inc();
                        } else {
                            new_triples.push(triple.clone());
                        }

                        // Protocol done, remove it from the ongoing pool.
                        self.ongoing.remove(id);
                        self.introduced.remove(id);
                        // Do not retain the protocol
                        break false;
                    }
                }
            }
        });

        for triple in new_triples {
            self.insert(triple).await;
        }

        for triple in new_mine_triples {
            self.insert_mine(triple).await;
        }

        if !errors.is_empty() {
            tracing::warn!(?errors, "faled to generate some triples");
        }

        messages
    }
}
