use super::contract::primitives::Participants;
use super::cryptography::CryptographicError;
use super::message::TripleMessage;
use super::presignature::GenerationError;
use crate::gcp::error;
use crate::storage::triple_storage::{LockTripleNodeStorageBox, TripleData};
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
            tracing::info!(
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
    /// Completed unspent triples
    pub triples: HashMap<TripleId, Triple>,

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

    /// List of triple ids generation of which was initiated by the current node.
    pub mine: VecDeque<TripleId>,

    /// The set of triple ids that were already taken or failed. This will be maintained for at most
    /// triple timeout period just so messages are cycled through the system.
    pub gc: HashMap<TripleId, Instant>,

    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub triple_storage: LockTripleNodeStorageBox,
    pub my_account_id: AccountId,
}

impl fmt::Debug for TripleManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleManager")
            .field("triples", &self.triples.keys().collect::<Vec<_>>())
            .field("generators", &self.generators.keys().collect::<Vec<_>>())
            .field("queued", &self.queued)
            .field("ongoing", &self.ongoing)
            .field("introduced", &self.introduced)
            .field("gc", &self.gc.keys().collect::<Vec<_>>())
            .field("mine", &self.mine)
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
        triple_data: Vec<TripleData>,
        triple_storage: LockTripleNodeStorageBox,
        my_account_id: &AccountId,
    ) -> Self {
        let mut mine: VecDeque<TripleId> = VecDeque::new();
        let mut all_triples = HashMap::new();
        for entry in triple_data {
            tracing::debug!("the triple data loaded is {:?}", entry);
            if entry.mine {
                tracing::debug!("pushed tripleId = {} into mine.", entry.triple.id);
                mine.push_back(entry.triple.id);
            }
            all_triples.insert(entry.triple.id, entry.triple);
        }
        Self {
            triples: all_triples,
            generators: HashMap::new(),
            queued: VecDeque::new(),
            ongoing: HashSet::new(),
            introduced: HashSet::new(),
            gc: HashMap::new(),
            mine,
            me,
            threshold,
            epoch,
            triple_storage,
            my_account_id: my_account_id.clone(),
        }
    }

    /// Returns the number of unspent triples available in the manager.
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Returns if there's any unspent triple in the manager.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of unspent triples assigned to this node.
    pub fn my_len(&self) -> usize {
        self.mine.len()
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub fn potential_len(&self) -> usize {
        self.len() + self.generators.len()
    }

    pub fn has_min_triples(&self, cfg: &ProtocolConfig) -> bool {
        self.my_len() >= cfg.triple.min_triples as usize
    }

    /// Clears an entry from failed triples if that triple protocol was created more than 2 hrs ago
    pub fn garbage_collect(&mut self, cfg: &ProtocolConfig) {
        self.gc.retain(|_, timestamp| {
            timestamp.elapsed() < Duration::from_millis(cfg.garbage_timeout)
        });
    }

    /// Refresh item in the garbage collection. If it is present, return true and update internally
    /// the timestamp for gabage collection.
    pub fn refresh_gc(&mut self, id: &TripleId) -> bool {
        let entry = self.gc.entry(*id).and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }

    /// Starts a new Beaver triple generation protocol.
    pub fn generate(
        &mut self,
        participants: &Participants,
        timeout: u64,
    ) -> Result<(), InitializationError> {
        let id = rand::random();

        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        if self.generators.contains_key(&id)
            || self.triples.contains_key(&id)
            || self.gc.contains_key(&id)
        {
            return Err(InitializationError::BadParameters(format!(
                "id collision: triple_id={id}"
            )));
        }

        tracing::debug!(id, "starting protocol to generate a new triple");
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
    pub fn stockpile(
        &mut self,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Result<(), InitializationError> {
        let not_enough_triples = {
            // Stopgap to prevent too many triples in the system. This should be around min_triple*nodes*2
            // for good measure so that we have enough triples to do presig generation while also maintain
            // the minimum number of triples where a single node can't flood the system.
            if self.potential_len() >= cfg.triple.max_triples as usize {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.my_len() < cfg.triple.min_triples as usize
                    && self.introduced.len() < cfg.max_concurrent_introduction as usize
                    && self.generators.len() < cfg.max_concurrent_generation as usize
            }
        };

        if not_enough_triples {
            self.generate(participants, cfg.triple.generation_timeout)?;
        }
        Ok(())
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
        if !self.triples.contains_key(&id0) {
            if self.generators.contains_key(&id0) {
                Err(GenerationError::TripleIsGenerating(id0))
            } else if self.gc.contains_key(&id0) {
                Err(GenerationError::TripleIsGarbageCollected(id0))
            } else {
                Err(GenerationError::TripleIsMissing(id0))
            }
        } else if !self.triples.contains_key(&id1) {
            if self.generators.contains_key(&id1) {
                Err(GenerationError::TripleIsGenerating(id1))
            } else if self.gc.contains_key(&id1) {
                Err(GenerationError::TripleIsGarbageCollected(id1))
            } else {
                Err(GenerationError::TripleIsMissing(id1))
            }
        } else {
            // Ensure that the triples have been removed from the datastore if they're going to be used in a signing protocol.
            // We expect them to be there so warn if they're not.
            // They may already be in memory, so even if this fails still try to pull them out.
            if let Err(err) = self.delete_triple_from_storage(id0).await {
                tracing::warn!(triple_id = id0, ?err, "unable to delete triple: potentially missing from datastore; deleting from memory only");
            }
            if let Err(err) = self.delete_triple_from_storage(id1).await {
                tracing::warn!(triple_id = id1, ?err, "unable to delete triple: potentially missing from datastore; deleting from memory only");
            }

            self.gc.insert(id0, Instant::now());
            self.gc.insert(id1, Instant::now());

            let triple_0 = self
                .triples
                .remove(&id0)
                .ok_or(GenerationError::TripleIsMissing(id0))?;
            let triple_1 = self
                .triples
                .remove(&id1)
                .ok_or(GenerationError::TripleIsMissing(id1))?;
            Ok((triple_0, triple_1))
        }
    }

    async fn delete_triple_from_storage(
        &mut self,
        id: TripleId,
    ) -> Result<(), error::DatastoreStorageError> {
        let action = || async {
            let mut triple_storage = self.triple_storage.write().await;
            if let Err(err) = triple_storage.delete(id).await {
                tracing::warn!(?err, id, "triple deletion failed.");
                return Err(err);
            }
            Ok(())
        };

        // Retry the action 3x with 500ms delay between each retry
        let retry_strategy = std::iter::repeat_with(|| Duration::from_millis(500)).take(3);
        tokio_retry::Retry::spawn(retry_strategy, action).await
    }

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&mut self) -> Option<(Triple, Triple)> {
        if self.mine.len() < 2 {
            return None;
        }
        let id0 = self.mine.pop_front()?;
        let id1 = self.mine.pop_front()?;
        tracing::info!(id0, id1, me = ?self.me, "trying to take two triples");

        match self.take_two(id0, id1).await {
            Err(error)
                if matches!(
                    error,
                    GenerationError::TripleIsMissing(_) | GenerationError::TripleIsGenerating(_)
                ) =>
            {
                tracing::warn!(
                    triple_id0 = id0,
                    triple_id1 = id1,
                    ?error,
                    "unable to take two triples: one or both of the triples are missing/not-generated",
                );
                self.mine.push_front(id1);
                self.mine.push_front(id0);
                None
            }
            Err(error) => {
                tracing::warn!(
                    triple_id0 = id0,
                    triple_id1 = id1,
                    ?error,
                    "unexpected error encountered while taking two triples"
                );
                None
            }
            Ok(val) => Some(val),
        }
    }

    pub fn peek_two_mine(&self) -> Option<(&Triple, &Triple)> {
        if self.mine.len() < 2 {
            return None;
        }
        let id0 = self.mine.front()?;
        let id1 = self.mine.get(1)?;
        let triple0 = self.triples.get(id0)?;
        let triple1 = self.triples.get(id1)?;
        Some((triple0, triple1))
    }

    pub async fn insert_mine(&mut self, triple: Triple) {
        self.mine.push_back(triple.id);
        self.triples.insert(triple.id, triple.clone());
        self.gc.remove(&triple.id);
        self.insert_triples_to_storage(vec![triple]).await;
    }

    /// Ensures that the triple with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`
    // TODO: What if the triple completed generation and is already spent?
    pub fn get_or_generate(
        &mut self,
        id: TripleId,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Result<Option<&mut TripleProtocol>, CryptographicError> {
        if self.triples.contains_key(&id) || self.gc.contains_key(&id) {
            Ok(None)
        } else {
            let potential_len = self.potential_len();
            match self.generators.entry(id) {
                Entry::Vacant(e) => {
                    if potential_len >= cfg.triple.max_triples as usize {
                        // We are at the maximum amount of triples, we cannot generate more. So just in case a node
                        // sends more triple generation requests, reject them and have them tiemout.
                        return Ok(None);
                    }

                    tracing::debug!(id, "joining protocol to generate a new triple");
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
        let mut triples_to_insert = Vec::new();
        let mut errors = Vec::new();
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
                        self.gc.insert(*id, Instant::now());
                        self.ongoing.remove(id);
                        self.introduced.remove(id);
                        tracing::info!(
                            elapsed = ?generator.timestamp.unwrap().elapsed(),
                            "added {id} to failed triples"
                        );
                        break false;
                    }
                };

                match action {
                    Action::Wait => {
                        tracing::trace!("waiting");
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
                            self.mine.push_back(*id);
                            crate::metrics::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS
                                .with_label_values(&[self.my_account_id.as_str()])
                                .inc();
                        }

                        self.triples.insert(*id, triple.clone());
                        triples_to_insert.push(triple);

                        // Protocol done, remove it from the ongoing pool.
                        self.ongoing.remove(id);
                        self.introduced.remove(id);
                        // Do not retain the protocol
                        break false;
                    }
                }
            }
        });
        self.insert_triples_to_storage(triples_to_insert).await;

        if !errors.is_empty() {
            tracing::warn!(?errors, "faled to generate some triples");
        }

        messages
    }

    async fn insert_triples_to_storage(&mut self, triples_to_insert: Vec<Triple>) {
        for triple in triples_to_insert {
            let mine = self.mine.contains(&triple.id);
            let action = || async {
                let mut triple_storage = self.triple_storage.write().await;
                if let Err(e) = triple_storage.insert(triple.clone(), mine).await {
                    tracing::warn!(?e, id = triple.id, "triple insertion failed.");
                    return Err(e);
                }
                Ok(())
            };

            // Retry the action 3x with 500ms delay between each retry
            let retry_strategy = std::iter::repeat_with(|| Duration::from_millis(500)).take(3);
            let _ = tokio_retry::Retry::spawn(retry_strategy, action).await;
        }
    }

    pub fn preview(&self, triples: &HashSet<TripleId>) -> HashSet<TripleId> {
        triples
            .iter()
            .filter(|id| self.triples.contains_key(id))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod test {
    // TODO: This test currently takes 22 seconds on my machine, which is much slower than it should be
    // Improve this before we make more similar tests
    #[tokio::test]
    async fn test_happy_triple_generation_locally() {
        crate::test_utils::test_triple_generation(None).await
    }

    #[tokio::test]
    async fn test_triple_deletion_locally() {
        crate::test_utils::test_triple_deletion(None).await
    }
}
