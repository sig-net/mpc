use super::contract::primitives::Participants;
use super::presignature::{GenerationError, Presignature, PresignatureId, PresignatureManager};
use super::state::RunningState;
use crate::indexer::ContractSignRequest;
use crate::kdf::derive_delta;
use crate::protocol::message::{MessageChannel, SignatureMessage};
use crate::protocol::Chain;
use crate::rpc::RpcChannel;
use crate::types::SignatureProtocol;
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{FullSignature, PresignOutput};
use chrono::Utc;
use crypto_shared::SerializableScalar;
use crypto_shared::{derive_key, PublicKey};
use k256::{Scalar, Secp256k1};
use mpc_contract::config::ProtocolConfig;
use mpc_contract::primitives::SignatureRequest;
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
use near_primitives::hash::CryptoHash;

pub type ReceiptId = near_primitives::hash::CryptoHash;

/// This is the maximum amount of sign requests that we can accept in the network.
const MAX_SIGN_REQUESTS: usize = 1024;

pub struct SignRequest {
    pub request_id: [u8; 32],
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub entropy: [u8; 32],
    pub time_added: Instant,
}

pub struct SignQueue {
    me: Participant,
    sign_rx: Arc<RwLock<mpsc::Receiver<SignRequest>>>,
    my_requests: VecDeque<(SignRequest, Participant, Vec<Participant>)>,
    other_requests: HashMap<SignRequestIdentifier, (SignRequest, Participant, Vec<Participant>)>,
}

impl SignQueue {
    pub fn channel() -> (mpsc::Sender<SignRequest>, mpsc::Receiver<SignRequest>) {
        mpsc::channel(MAX_SIGN_REQUESTS)
    }

    pub fn new(me: Participant, sign_rx: Arc<RwLock<mpsc::Receiver<SignRequest>>>) -> Self {
        Self {
            me,
            sign_rx,
            my_requests: VecDeque::new(),
            other_requests: HashMap::new(),
        }
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
        while let Ok(request) = {
            match sign_rx.try_recv() {
                err @ Err(TryRecvError::Disconnected) => {
                    tracing::error!("sign queue channel disconnected");
                    err
                }
                other => other,
            }
        } {
            let mut rng = StdRng::from_seed(request.entropy);
            let subset = stable.keys().cloned().choose_multiple(&mut rng, threshold);
            let in_subset = subset.contains(&self.me);
            let proposer = *subset.choose(&mut rng).unwrap();
            let is_mine = proposer == self.me;
            let request_id = CryptoHash(request.request_id);

            tracing::info!(
                ?request_id,
                ?subset,
                ?proposer,
                in_subset,
                is_mine,
                "sign queue: organizing request"
            );

            let sign_id = SignRequestIdentifier::new(
                request.request_id,
                request.epsilon,
                request.request.payload,
            );

            if in_subset {
                tracing::info!(
                    ?request_id,
                    "saving sign request: node is in the signer subset"
                );

                if is_mine {
                    crate::metrics::NUM_SIGN_REQUESTS_MINE
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();
                    self.my_requests.push_back((request, proposer, subset));
                } else {
                    self.other_requests
                        .insert(sign_id, (request, proposer, subset));
                }
            } else {
                tracing::info!(
                    ?request_id,
                    "skipping sign request: node is NOT in the signer subset"
                );
            }
        }
    }

    pub fn take_my_requests(&mut self) -> VecDeque<(SignRequest, Participant, Vec<Participant>)> {
        std::mem::take(&mut self.my_requests)
    }

    pub fn insert_mine(
        &mut self,
        requests: VecDeque<(SignRequest, Participant, Vec<Participant>)>,
    ) {
        self.my_requests = requests;
    }

    pub fn take(
        &mut self,
        id: &SignRequestIdentifier,
    ) -> Option<(SignRequest, Participant, Vec<Participant>)> {
        self.other_requests.remove(id)
    }
}

/// An ongoing signature generator.
pub struct SignatureGenerator {
    pub protocol: SignatureProtocol,
    pub participants: Vec<Participant>,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub request_id: [u8; 32],
    pub entropy: [u8; 32],
    pub sign_request_timestamp: Instant,
    pub generator_timestamp: Instant,
    pub timeout: Duration,
    pub timeout_total: Duration,
}

impl SignatureGenerator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: SignatureProtocol,
        participants: Vec<Participant>,
        proposer: Participant,
        presignature_id: PresignatureId,
        request: ContractSignRequest,
        epsilon: Scalar,
        request_id: [u8; 32],
        entropy: [u8; 32],
        sign_request_timestamp: Instant,
        cfg: &ProtocolConfig,
    ) -> Self {
        Self {
            protocol,
            participants,
            proposer,
            presignature_id,
            request,
            epsilon,
            request_id,
            entropy,
            sign_request_timestamp,
            generator_timestamp: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
        }
    }

    pub fn poke(&mut self) -> Result<Action<FullSignature<Secp256k1>>, ProtocolError> {
        if self.sign_request_timestamp.elapsed() > self.timeout_total {
            let msg = "signature protocol timed out completely";
            tracing::warn!(msg);
            return Err(ProtocolError::Other(anyhow::anyhow!(msg).into()));
        }

        if self.generator_timestamp.elapsed() > self.timeout {
            tracing::warn!(self.presignature_id, "signature protocol timed out");
            return Err(ProtocolError::Other(
                anyhow::anyhow!("signature protocol timeout").into(),
            ));
        }

        self.protocol.poke()
    }
}

/// Generator for signature thas has failed. Only retains essential information
/// for starting up this failed signature once again.
pub struct GenerationRequest {
    pub proposer: Participant,
    pub participants: Vec<Participant>,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub request_id: [u8; 32],
    pub entropy: [u8; 32],
    pub sign_request_timestamp: Instant,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignRequestIdentifier {
    pub request_id: [u8; 32],
    pub epsilon: Scalar,
    pub payload: Scalar,
}

impl std::hash::Hash for SignRequestIdentifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.request_id.hash(state);
        self.epsilon.to_bytes().hash(state);
        self.payload.to_bytes().hash(state);
    }
}

impl SignRequestIdentifier {
    pub fn new(request_id: [u8; 32], epsilon: Scalar, payload: Scalar) -> Self {
        Self {
            request_id,
            epsilon,
            payload,
        }
    }
}

pub struct SignatureManager {
    /// Ongoing signature generation protocols.
    generators: HashMap<SignRequestIdentifier, SignatureGenerator>,
    /// Failed signatures awaiting to be retried.
    failed: VecDeque<(SignRequestIdentifier, GenerationRequest)>,
    /// Set of completed signatures
    completed: HashMap<SignRequestIdentifier, Instant>,
    /// Sign queue that maintains all requests coming in from indexer.
    sign_queue: SignQueue,

    me: Participant,
    my_account_id: AccountId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,
}

pub struct ToPublish {
    pub request_id: [u8; 32],
    pub request: SignatureRequest,
    pub time_added: Instant,
    pub signature: FullSignature<Secp256k1>,
    pub retry_count: u8,
    pub chain: Chain,
}

impl ToPublish {
    pub fn new(
        request_id: [u8; 32],
        request: SignatureRequest,
        time_added: Instant,
        signature: FullSignature<Secp256k1>,
        chain: Chain,
    ) -> ToPublish {
        ToPublish {
            request_id,
            request,
            time_added,
            signature,
            retry_count: 0,
            chain,
        }
    }
}

impl SignatureManager {
    pub fn new(
        me: Participant,
        my_account_id: &AccountId,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
        sign_rx: Arc<RwLock<mpsc::Receiver<SignRequest>>>,
    ) -> Self {
        Self {
            generators: HashMap::new(),
            failed: VecDeque::new(),
            completed: HashMap::new(),
            sign_queue: SignQueue::new(me, sign_rx),
            me,
            my_account_id: my_account_id.clone(),
            threshold,
            public_key,
            epoch,
        }
    }

    pub fn failed_len(&self) -> usize {
        self.failed.len()
    }

    pub fn me(&self) -> Participant {
        self.me
    }

    #[allow(clippy::result_large_err)]
    fn generate_internal(
        me: Participant,
        public_key: PublicKey,
        presignature: Presignature,
        req: GenerationRequest,
        cfg: &ProtocolConfig,
    ) -> Result<SignatureGenerator, (Presignature, InitializationError)> {
        let GenerationRequest {
            proposer,
            participants,
            request,
            epsilon,
            request_id,
            entropy,
            sign_request_timestamp,
        } = req;
        let PresignOutput { big_r, k, sigma } = presignature.output;
        let delta = derive_delta(request_id, entropy, big_r);
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + epsilon * k) * delta.invert().unwrap(),
        };
        let presignature_id = presignature.id;
        let protocol = Box::new(
            cait_sith::sign(
                &participants,
                me,
                derive_key(public_key, epsilon),
                output,
                request.payload,
            )
            .map_err(|err| (presignature, err))?,
        );
        Ok(SignatureGenerator::new(
            protocol,
            participants.to_vec(),
            proposer,
            presignature_id,
            request,
            epsilon,
            request_id,
            entropy,
            sign_request_timestamp,
            cfg,
        ))
    }

    #[allow(clippy::result_large_err)]
    fn retry_failed_generation(
        &mut self,
        sign_id: SignRequestIdentifier,
        req: GenerationRequest,
        presignature: Presignature,
        cfg: &ProtocolConfig,
    ) -> Result<(), (Presignature, InitializationError)> {
        tracing::info!(
            ?sign_id,
            participants = ?req.participants,
            "restarting failed protocol to generate signature"
        );
        let generator = Self::generate_internal(self.me, self.public_key, presignature, req, cfg)?;
        crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        self.generators.insert(sign_id, generator);
        Ok(())
    }

    /// Starts a new presignature generation protocol.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    pub fn generate(
        &mut self,
        participants: &Participants,
        request_id: [u8; 32],
        presignature: Presignature,
        request: ContractSignRequest,
        epsilon: Scalar,
        entropy: [u8; 32],
        sign_request_timestamp: Instant,
        cfg: &ProtocolConfig,
    ) -> Result<(), (Presignature, InitializationError)> {
        let sign_request_identifier =
            SignRequestIdentifier::new(request_id, epsilon, request.payload);
        let participants = participants.keys_vec();
        tracing::info!(
            ?sign_request_identifier,
            me = ?self.me,
            presignature_id = presignature.id,
            ?participants,
            "starting protocol to generate a new signature",
        );
        let generator = Self::generate_internal(
            self.me,
            self.public_key,
            presignature,
            GenerationRequest {
                proposer: self.me,
                participants,
                request,
                epsilon,
                request_id,
                entropy,
                sign_request_timestamp,
            },
            cfg,
        )?;
        crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        self.generators.insert(sign_request_identifier, generator);
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
        sign_id: &SignRequestIdentifier,
        proposer: Participant,
        presignature_id: PresignatureId,
        cfg: &ProtocolConfig,
        presignature_manager: &mut PresignatureManager,
    ) -> Result<&mut SignatureProtocol, GenerationError> {
        if self.completed.contains_key(sign_id) {
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

        let Some((request, our_proposer, subset)) = self.sign_queue.take(sign_id) else {
            return Err(GenerationError::WaitingForIndexer(sign_id.clone()));
        };
        if proposer != our_proposer {
            return Err(GenerationError::InvalidProposer(proposer, our_proposer));
        }

        tracing::info!(?sign_id, me = ?self.me, presignature_id, "joining protocol to generate a new signature");
        let presignature = match presignature_manager.take(presignature_id).await {
            Ok(presignature) => presignature,
            Err(err @ GenerationError::PresignatureIsGenerating(_)) => {
                tracing::warn!(me = ?self.me, presignature_id, "presignature is generating, can't join signature generation protocol");
                return Err(err);
            }
            Err(err @ GenerationError::PresignatureIsMissing(_)) => {
                tracing::warn!(me = ?self.me, presignature_id, "presignature is missing, can't join signature generation protocol");
                return Err(err);
            }
            Err(err @ GenerationError::PresignatureIsGarbageCollected(_)) => {
                tracing::warn!(me = ?self.me, presignature_id, "presignature is garbage collected, can't join signature generation protocol");
                return Err(err);
            }
            Err(err) => return Err(err),
        };
        tracing::info!(me = ?self.me, presignature_id, "found presignature: ready to start signature generation");
        let generator = match Self::generate_internal(
            self.me,
            self.public_key,
            presignature,
            GenerationRequest {
                proposer,
                participants: subset,
                request: request.request,
                epsilon: request.epsilon,
                entropy: request.entropy,
                request_id: sign_id.request_id,
                sign_request_timestamp: Instant::now(),
            },
            cfg,
        ) {
            Ok(generator) => generator,
            Err((presignature, err @ InitializationError::BadParameters(_))) => {
                tracing::warn!(
                    ?sign_id,
                    presignature.id,
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
        for (sign_request_id, generator) in self.generators.iter_mut() {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(err) => {
                        if generator.proposer == self.me {
                            if generator.sign_request_timestamp.elapsed() < generator.timeout_total
                            {
                                tracing::warn!(?err, "signature failed to be produced; pushing request back into failed queue");
                                crate::metrics::SIGNATURE_GENERATOR_FAILURES
                                    .with_label_values(&[self.my_account_id.as_str()])
                                    .inc();
                                // only retry the signature generation if it was initially proposed by us. We do not
                                // want any nodes to be proposing the same signature multiple times.
                                self.failed.push_back((
                                    sign_request_id.clone(),
                                    GenerationRequest {
                                        proposer: generator.proposer,
                                        participants: generator.participants.clone(),
                                        request: generator.request.clone(),
                                        epsilon: generator.epsilon,
                                        request_id: generator.request_id,
                                        entropy: generator.entropy,
                                        sign_request_timestamp: generator.sign_request_timestamp,
                                    },
                                ));
                            } else {
                                self.completed
                                    .insert(sign_request_id.clone(), Instant::now());
                                crate::metrics::SIGNATURE_GENERATOR_FAILURES
                                    .with_label_values(&[self.my_account_id.as_str()])
                                    .inc();
                                crate::metrics::SIGNATURE_FAILURES
                                    .with_label_values(&[self.my_account_id.as_str()])
                                    .inc();
                                tracing::warn!(
                                    ?err,
                                    "signature failed to be produced; trashing request"
                                );
                            }
                        }
                        remove.push(sign_request_id.clone());
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
                        for to in generator.participants.iter() {
                            if *to == self.me {
                                continue;
                            }
                            message
                                .send(
                                    self.me,
                                    *to,
                                    SignatureMessage {
                                        request_id: sign_request_id.request_id,
                                        proposer: generator.proposer,
                                        presignature_id: generator.presignature_id,
                                        request: generator.request.clone(),
                                        epsilon: generator.epsilon,
                                        entropy: generator.entropy,
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
                                    request_id: sign_request_id.request_id,
                                    proposer: generator.proposer,
                                    presignature_id: generator.presignature_id,
                                    request: generator.request.clone(),
                                    epsilon: generator.epsilon,
                                    entropy: generator.entropy,
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
                            ?sign_request_id,
                            me = ?self.me,
                            presignature_id = generator.presignature_id,
                            big_r = ?output.big_r.to_base58(),
                            s = ?output.s,
                            elapsed = ?generator.generator_timestamp.elapsed(),
                            "completed signature generation"
                        );
                        crate::metrics::SIGN_GENERATION_LATENCY
                            .with_label_values(&[self.my_account_id.as_str()])
                            .observe(generator.generator_timestamp.elapsed().as_secs_f64());

                        self.completed
                            .insert(sign_request_id.clone(), Instant::now());
                        let request = SignatureRequest {
                            epsilon: SerializableScalar {
                                scalar: generator.epsilon,
                            },
                            payload_hash: generator.request.payload.into(),
                        };
                        if generator.proposer == self.me {
                            let to_publish = ToPublish::new(
                                sign_request_id.request_id,
                                request,
                                generator.sign_request_timestamp,
                                output,
                                generator.request.chain,
                            );
                            tokio::spawn(rpc.clone().publish(self.public_key, to_publish));
                        }
                        // Do not retain the protocol
                        remove.push(sign_request_id.clone());
                    }
                }
            }
        }

        for sign_request_id in remove {
            self.generators.remove(&sign_request_id);
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

        self.sign_queue
            .organize(self.threshold, stable, &self.my_account_id)
            .await;
        crate::metrics::SIGN_QUEUE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.sign_queue.len() as i64);
        let mut my_requests = self.sign_queue.take_my_requests();
        crate::metrics::SIGN_QUEUE_MINE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(my_requests.len() as i64);

        while let Some(mut presignature) = {
            if self.failed.is_empty() && my_requests.is_empty() {
                None
            } else {
                presignature_manager.take_mine().await
            }
        } {
            // NOTE: this prioritizes old requests first then tries to do new ones if there's enough presignatures.
            // TODO: we need to decide how to prioritize certain requests over others such as with gas or time of
            // when the request made it into the NEAR network.
            // issue: https://github.com/near/mpc-recovery/issues/596
            if let Some((sign_id, failed_req)) = self.failed.pop_front() {
                let participants =
                    stable.intersection(&[&presignature.participants, &failed_req.participants]);
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

                if let Err((presignature, InitializationError::BadParameters(err))) =
                    self.retry_failed_generation(sign_id.clone(), failed_req, presignature, cfg)
                {
                    tracing::warn!(
                        ?sign_id,
                        presignature.id,
                        ?err,
                        "failed to retry signature generation: trashing presignature"
                    );
                    continue;
                }

                if my_requests.is_empty() {
                    continue;
                }

                if let Some(another_presignature) = presignature_manager.take_mine().await {
                    presignature = another_presignature;
                } else {
                    break;
                }
            }

            let Some((my_request, _proposer, subset)) = my_requests.pop_front() else {
                tracing::warn!("unexpected state, no more requests to handle");
                continue;
            };

            let participants = stable.intersection(&[&presignature.participants, &subset]);
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

            if let Err((presignature, InitializationError::BadParameters(err))) = self.generate(
                &participants,
                my_request.request_id,
                presignature,
                my_request.request,
                my_request.epsilon,
                my_request.entropy,
                my_request.time_added,
                cfg,
            ) {
                tracing::warn!(request_id = ?CryptoHash(my_request.request_id), presignature.id, ?err, "failed to start signature generation: trashing presignature");
                continue;
            }
        }

        // We do not have enough presignature stockpile and the taken requests need to be fulfilled,
        // so insert it back into the sign queue to be fulfilled in the next iteration.
        if !my_requests.is_empty() {
            self.sign_queue.insert_mine(my_requests);
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

    pub fn refresh_gc(&mut self, id: &SignRequestIdentifier) -> bool {
        let entry = self
            .completed
            .entry(id.clone())
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
