use super::contract::primitives::Participants;
use super::state::RunningState;
use crate::kdf::derive_delta;
use crate::protocol::error::GenerationError;
use crate::protocol::message::{MessageChannel, SignatureMessage};
use crate::protocol::presignature::{Presignature, PresignatureId, PresignatureManager};
use crate::protocol::Chain;
use crate::rpc::RpcChannel;
use crate::types::SignatureProtocol;
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{FullSignature, PresignOutput};
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::{derive_key, PublicKey};
use mpc_primitives::{SignArgs, SignId};
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::SeedableRng;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, RwLock};

use near_account_id::AccountId;

/// This is the maximum amount of sign requests that we can accept in the network.
const MAX_SIGN_REQUESTS: usize = 1024;

/// All relevant info pertaining to an Indexed sign request from an indexer.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    pub timestamp: Instant,
}

/// The sign request for the node to process. This contains relevant info for the node
/// to generate a signature such as what has been indexed and what the node needs to maintain
/// metadata-wise to generate the signature.
#[derive(Debug, Clone, PartialEq)]
pub struct SignRequest {
    pub indexed: IndexedSignRequest,
    pub proposer: Participant,
    pub participants: Vec<Participant>,
}

pub struct SignQueue {
    me: Participant,
    sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
    my_requests: VecDeque<SignRequest>,
    other_requests: HashMap<SignId, SignRequest>,
}

impl SignQueue {
    pub fn channel() -> (
        mpsc::Sender<IndexedSignRequest>,
        mpsc::Receiver<IndexedSignRequest>,
    ) {
        mpsc::channel(MAX_SIGN_REQUESTS)
    }

    pub fn new(me: Participant, sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>) -> Self {
        Self {
            me,
            sign_rx,
            my_requests: VecDeque::new(),
            other_requests: HashMap::new(),
        }
    }

    pub fn len_mine(&self) -> usize {
        self.my_requests.len()
    }

    pub fn is_empty_mine(&self) -> bool {
        self.len_mine() == 0
    }

    pub fn len(&self) -> usize {
        self.my_requests.len() + self.other_requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub async fn organize(
        &mut self,
        threshold: usize,
        stable: &Participants,
        my_account_id: &AccountId,
    ) {
        let mut sign_rx = self.sign_rx.write().await;
        while let Ok(indexed) = {
            match sign_rx.try_recv() {
                err @ Err(TryRecvError::Disconnected) => {
                    tracing::error!("sign queue channel disconnected");
                    err
                }
                other => other,
            }
        } {
            let sign_id = indexed.id.clone();
            if self.my_requests.iter().any(|req| req.indexed.id == sign_id)
                || self.other_requests.contains_key(&sign_id)
            {
                tracing::info!(?sign_id, "skipping sign request: already in the sign queue");
                continue;
            }
            let mut rng = StdRng::from_seed(indexed.args.entropy);
            let subset = stable.keys().cloned().choose_multiple(&mut rng, threshold);
            let in_subset = subset.contains(&self.me);
            let proposer = *subset.choose(&mut rng).unwrap();
            let is_mine = proposer == self.me;

            tracing::info!(
                ?sign_id,
                ?subset,
                ?proposer,
                in_subset,
                is_mine,
                "sign queue: organizing request"
            );

            if in_subset {
                tracing::info!(
                    ?sign_id,
                    "saving sign request: node is in the signer subset"
                );

                let request = SignRequest {
                    indexed,
                    proposer,
                    participants: subset,
                };
                if is_mine {
                    crate::metrics::NUM_SIGN_REQUESTS_MINE
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();
                    self.my_requests.push_back(request);
                } else {
                    self.other_requests.insert(sign_id, request);
                }
            } else {
                tracing::info!(
                    ?sign_id,
                    "skipping sign request: node is NOT in the signer subset"
                );
            }
        }
    }

    pub fn push_failed(&mut self, request: SignRequest) {
        // NOTE: this prioritizes old requests first then tries to do new ones if there's enough presignatures.
        // TODO: we need to decide how to prioritize certain requests over others such as with gas or time of
        // when the request made it into the NEAR network.
        // issue: https://github.com/near/mpc-recovery/issues/596
        if request.proposer == self.me {
            self.my_requests.push_front(request);
        } else {
            self.other_requests
                .insert(request.indexed.id.clone(), request);
        }
    }

    pub fn take_mine(&mut self) -> Option<SignRequest> {
        self.my_requests.pop_front()
    }

    pub fn take(&mut self, id: &SignId) -> Option<SignRequest> {
        self.other_requests.remove(id)
    }

    pub fn expire(&mut self, cfg: &ProtocolConfig) {
        self.other_requests.retain(|_, request| {
            request.indexed.timestamp.elapsed()
                < Duration::from_millis(cfg.signature.generation_timeout_total)
        });
    }
}

/// An ongoing signature generator.
pub struct SignatureGenerator {
    pub protocol: SignatureProtocol,
    pub presignature_id: PresignatureId,
    pub request: SignRequest,
    pub timestamp: Instant,
    pub timeout: Duration,
    pub timeout_total: Duration,
}

impl SignatureGenerator {
    pub fn new(
        protocol: SignatureProtocol,
        presignature_id: PresignatureId,
        request: SignRequest,
        cfg: &ProtocolConfig,
    ) -> Self {
        Self {
            protocol,
            presignature_id,
            request,
            timestamp: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
        }
    }

    pub fn poke(&mut self) -> Result<Action<FullSignature<Secp256k1>>, ProtocolError> {
        if self.request.indexed.timestamp.elapsed() > self.timeout_total {
            let msg = "signature protocol timed out completely";
            tracing::warn!(msg);
            return Err(ProtocolError::Other(anyhow::anyhow!(msg).into()));
        }

        if self.timestamp.elapsed() > self.timeout {
            tracing::warn!(sign_id = ?self.request.indexed.id, "signature protocol timed out");
            return Err(ProtocolError::Other(
                anyhow::anyhow!("signature protocol timeout").into(),
            ));
        }

        self.protocol.poke()
    }
}

pub struct SignatureManager {
    /// Ongoing signature generation protocols.
    generators: HashMap<SignId, SignatureGenerator>,
    /// Set of completed signatures
    completed: HashMap<(SignId, PresignatureId), Instant>,
    /// Sign queue that maintains all requests coming in from indexer.
    sign_queue: SignQueue,

    me: Participant,
    my_account_id: AccountId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,
}

impl SignatureManager {
    pub fn new(
        me: Participant,
        my_account_id: &AccountId,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
        sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
    ) -> Self {
        Self {
            generators: HashMap::new(),
            completed: HashMap::new(),
            sign_queue: SignQueue::new(me, sign_rx),
            me,
            my_account_id: my_account_id.clone(),
            threshold,
            public_key,
            epoch,
        }
    }

    pub fn me(&self) -> Participant {
        self.me
    }

    fn generate_internal(
        me: Participant,
        public_key: PublicKey,
        presignature: Presignature,
        request: SignRequest,
        cfg: &ProtocolConfig,
    ) -> Result<SignatureGenerator, InitializationError> {
        let SignRequest {
            participants,
            indexed,
            ..
        } = &request;
        let IndexedSignRequest {
            id: SignId { request_id },
            args,
            ..
        } = indexed;

        let PresignOutput { big_r, k, sigma } = presignature.output;
        let delta = derive_delta(*request_id, args.entropy, big_r);
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + args.epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Box::new(cait_sith::sign(
            participants,
            me,
            derive_key(public_key, args.epsilon),
            output,
            args.payload,
        )?);
        Ok(SignatureGenerator::new(
            protocol,
            presignature.id,
            request,
            cfg,
        ))
    }

    /// Starts a new presignature generation protocol.
    pub fn generate(
        &mut self,
        presignature: Presignature,
        request: SignRequest,
        cfg: &ProtocolConfig,
    ) -> Result<(), InitializationError> {
        let sign_id = request.indexed.id.clone();
        tracing::info!(
            ?sign_id,
            me = ?self.me,
            presignature_id = presignature.id,
            participants = ?request.participants,
            "starting protocol to generate a new signature",
        );
        let generator =
            Self::generate_internal(self.me, self.public_key, presignature, request, cfg)?;
        crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        self.generators.insert(sign_id, generator);
        Ok(())
    }

    /// Ensures that the presignature with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`, or
    /// 4) Depends on triples (`triple0`/`triple1`) that are unknown to the node
    // TODO: What if the presignature completed generation and is already spent?
    pub async fn get_or_start_protocol(
        &mut self,
        sign_id: &SignId,
        proposer: Participant,
        presignature_id: PresignatureId,
        cfg: &ProtocolConfig,
        presignature_manager: &mut PresignatureManager,
    ) -> Result<&mut SignatureProtocol, GenerationError> {
        if self
            .completed
            .contains_key(&(sign_id.clone(), presignature_id))
        {
            tracing::warn!(
                ?sign_id,
                presignature_id,
                "presignature has already been used to generate a signature"
            );
            return Err(GenerationError::AlreadyGenerated);
        }

        let entry = match self.generators.entry(sign_id.clone()) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(entry) => return Ok(&mut entry.into_mut().protocol),
        };

        let Some(request) = self.sign_queue.take(sign_id) else {
            return Err(GenerationError::WaitingForIndexer(sign_id.clone()));
        };
        let our_proposer = request.proposer;
        if proposer != our_proposer {
            self.sign_queue.push_failed(request);
            return Err(GenerationError::InvalidProposer(proposer, our_proposer));
        }

        tracing::info!(?sign_id, me = ?self.me, presignature_id, "joining protocol to generate a new signature");
        let presignature = match presignature_manager.take(presignature_id).await {
            Ok(presignature) => presignature,
            Err(err @ GenerationError::PresignatureIsGenerating(_)) => {
                tracing::warn!(me = ?self.me, presignature_id, "presignature is generating, can't join signature generation protocol");
                self.sign_queue.push_failed(request);
                return Err(err);
            }
            Err(err @ GenerationError::PresignatureIsMissing(_)) => {
                tracing::warn!(me = ?self.me, presignature_id, "presignature is missing, can't join signature generation protocol");
                self.sign_queue.push_failed(request);
                return Err(err);
            }
            Err(err @ GenerationError::PresignatureIsGarbageCollected(_)) => {
                tracing::warn!(me = ?self.me, presignature_id, "presignature is garbage collected, can't join signature generation protocol");
                self.sign_queue.push_failed(request);
                return Err(err);
            }
            Err(err) => return Err(err),
        };
        tracing::info!(me = ?self.me, presignature_id, "found presignature: ready to start signature generation");
        let generator = match Self::generate_internal(
            self.me,
            self.public_key,
            presignature,
            request.clone(),
            cfg,
        ) {
            Ok(generator) => generator,
            Err(err @ InitializationError::BadParameters(_)) => {
                self.sign_queue.push_failed(request);
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    ?err,
                    "failed to start signature generation"
                );
                return Err(GenerationError::CaitSithInitializationError(err));
            }
        };
        let generator = entry.insert(generator);
        crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        Ok(&mut generator.protocol)
    }

    /// Pokes all of the ongoing generation protocols to completion
    pub async fn poke(&mut self, message: MessageChannel, rpc: RpcChannel) {
        let mut remove = Vec::new();
        let mut failed = Vec::new();
        for (sign_id, generator) in self.generators.iter_mut() {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(err) => {
                        remove.push(sign_id.clone());
                        self.completed
                            .insert((sign_id.clone(), generator.presignature_id), Instant::now());

                        if generator.request.indexed.timestamp.elapsed() < generator.timeout_total {
                            failed.push(sign_id.clone());
                            tracing::warn!(?err, "signature failed to be produced; pushing request back into failed queue");
                            if generator.request.proposer == self.me {
                                crate::metrics::SIGNATURE_GENERATOR_FAILURES
                                    .with_label_values(&[self.my_account_id.as_str()])
                                    .inc();
                            }
                        } else {
                            tracing::warn!(
                                ?err,
                                "signature failed to be produced; trashing request"
                            );
                            if generator.request.proposer == self.me {
                                crate::metrics::SIGNATURE_GENERATOR_FAILURES
                                    .with_label_values(&[self.my_account_id.as_str()])
                                    .inc();
                                crate::metrics::SIGNATURE_FAILURES
                                    .with_label_values(&[self.my_account_id.as_str()])
                                    .inc();
                            }
                        }
                        break;
                    }
                };
                match action {
                    Action::Wait => {
                        tracing::debug!("signature: waiting");
                        // Retain protocol until we are finished
                        break;
                    }
                    Action::SendMany(data) => {
                        for to in generator.request.participants.iter() {
                            if *to == self.me {
                                continue;
                            }
                            message
                                .send(
                                    self.me,
                                    *to,
                                    SignatureMessage {
                                        id: sign_id.clone(),
                                        proposer: generator.request.proposer,
                                        presignature_id: generator.presignature_id,
                                        epoch: self.epoch,
                                        from: self.me,
                                        data: data.clone(),
                                        timestamp: Utc::now().timestamp() as u64,
                                    },
                                )
                                .await;
                        }
                    }
                    Action::SendPrivate(to, data) => {
                        message
                            .send(
                                self.me,
                                to,
                                SignatureMessage {
                                    id: sign_id.clone(),
                                    proposer: generator.request.proposer,
                                    presignature_id: generator.presignature_id,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data,
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            )
                            .await
                    }
                    Action::Return(output) => {
                        tracing::info!(
                            ?sign_id,
                            me = ?self.me,
                            presignature_id = generator.presignature_id,
                            big_r = ?output.big_r.to_base58(),
                            s = ?output.s,
                            elapsed = ?generator.timestamp.elapsed(),
                            "completed signature generation"
                        );
                        crate::metrics::SIGN_GENERATION_LATENCY
                            .with_label_values(&[self.my_account_id.as_str()])
                            .observe(generator.timestamp.elapsed().as_secs_f64());

                        if generator.request.proposer == self.me {
                            rpc.publish(self.public_key, generator.request.clone(), output);
                        }
                        self.completed
                            .insert((sign_id.clone(), generator.presignature_id), Instant::now());
                        // Do not retain the protocol
                        remove.push(sign_id.clone());
                    }
                }
            }
        }

        for id in failed {
            if let Some(generator) = self.generators.remove(&id) {
                self.sign_queue.push_failed(generator.request);
            }
        }

        for id in remove {
            self.generators.remove(&id);
        }
    }

    pub async fn handle_requests(
        &mut self,
        stable: &Participants,
        presignature_manager: &mut PresignatureManager,
        cfg: &ProtocolConfig,
    ) {
        if stable.len() < self.threshold {
            tracing::warn!(
                "Require at least {} stable participants to handle_requests, got {}: {:?}",
                self.threshold,
                stable.len(),
                stable.keys_vec()
            );
            return;
        }

        self.sign_queue.expire(cfg);
        self.sign_queue
            .organize(self.threshold, stable, &self.my_account_id)
            .await;
        crate::metrics::SIGN_QUEUE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.sign_queue.len() as i64);
        crate::metrics::SIGN_QUEUE_MINE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.sign_queue.len_mine() as i64);

        while let Some(presignature) = {
            if self.sign_queue.is_empty_mine() {
                None
            } else {
                presignature_manager.take_mine().await
            }
        } {
            let Some(my_request) = self.sign_queue.take_mine() else {
                tracing::warn!("unexpected state, no more requests to handle");
                continue;
            };

            let participants =
                stable.intersection(&[&presignature.participants, &my_request.participants]);
            if participants.len() < self.threshold {
                tracing::warn!(
                    participants = ?participants.keys_vec(),
                    "intersection of stable participants and presignature participants is less than threshold, trashing presignature"
                );
                // TODO: do not insert back presignature when we have a clear model for data consistency
                // between nodes and utilizing only presignatures that meet threshold requirements.
                presignature_manager.insert(presignature, true, true).await;
                continue;
            }

            let sign_id = my_request.indexed.id.clone();
            let presignature_id = presignature.id;
            if let Err(InitializationError::BadParameters(err)) =
                self.generate(presignature, my_request, cfg)
            {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    ?err,
                    "failed to start signature generation: trashing presignature"
                );
                continue;
            }
        }
    }

    /// Garbage collect all the completed signatures.
    pub fn garbage_collect(&mut self, cfg: &ProtocolConfig) {
        let before = self.completed.len();
        self.completed.retain(|_, timestamp| {
            timestamp.elapsed() < Duration::from_millis(cfg.signature.garbage_timeout)
        });
        let garbage_collected = before.saturating_sub(self.completed.len());
        if garbage_collected > 0 {
            tracing::debug!(
                "garbage collected {} completed signatures",
                garbage_collected
            );
        }
    }

    pub fn refresh_gc(&mut self, sign_id: &SignId, presignature_id: PresignatureId) -> bool {
        let entry = self
            .completed
            .entry((sign_id.clone(), presignature_id))
            .and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }

    pub fn execute(
        state: &RunningState,
        stable: &Participants,
        protocol_cfg: &ProtocolConfig,
        ctx: &impl super::cryptography::CryptographicCtx,
    ) -> tokio::task::JoinHandle<()> {
        let presignature_manager = state.presignature_manager.clone();
        let signature_manager = state.signature_manager.clone();
        let stable = stable.clone();
        let protocol_cfg = protocol_cfg.clone();
        let rpc_channel = ctx.rpc_channel().clone();
        let channel = ctx.channel().clone();

        // NOTE: signatures should only use stable and not active participants. The difference here is that
        // stable participants utilizes more than the online status of a node, such as whether or not their
        // block height is up to date, such that they too can process signature requests. If they cannot
        // then they are considered unstable and should not be a part of signature generation this round.

        tokio::task::spawn(tokio::task::unconstrained(async move {
            let mut signature_manager = signature_manager.write().await;
            let mut presignature_manager = presignature_manager.write().await;
            signature_manager
                .handle_requests(&stable, &mut presignature_manager, &protocol_cfg)
                .await;
            drop(presignature_manager);
            signature_manager.poke(channel, rpc_channel).await;
        }))
    }
}
