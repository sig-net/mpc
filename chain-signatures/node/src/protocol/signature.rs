use super::contract::primitives::intersect_vec;
use super::MpcSignProtocol;
use crate::config::Config;
use crate::kdf::derive_delta;
use crate::mesh::MeshState;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::message::{MessageChannel, PositMessage, PositProtocolId, SignatureMessage};
use crate::protocol::posit::{PositAction, PositInternalAction, PositManager, Positor};
use crate::protocol::presignature::PresignatureId;
use crate::protocol::Chain;
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::sign_respond_tx::SignRespondSignatureChannel;
use crate::storage::presignature_storage::{PresignatureTaken, PresignatureTakenDropper};
use crate::storage::PresignatureStorage;
use crate::types::SignatureProtocol;
use crate::util::{AffinePointExt, JoinMap};

use crate::protocol::SignRequestType;
use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::PresignOutput;
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::{derive_key, PublicKey};
use mpc_primitives::{SignArgs, SignId};
use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tokio::task::{JoinHandle, JoinSet};

use near_account_id::AccountId;

/// This is the maximum amount of sign requests that we can accept in the network.
const MAX_SIGN_REQUESTS: usize = 1024;

/// All relevant info pertaining to an Indexed sign request from an indexer.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    pub unix_timestamp_indexed: u64,
    pub timestamp_sign_queue: Option<Instant>,
    pub total_timeout: Duration,
    pub sign_request_type: SignRequestType,
    pub participants: Option<Vec<Participant>>,
}

#[allow(clippy::large_enum_variant)]
pub enum PendingRequest {
    Available(SignRequest),
    Pending(SignId, oneshot::Receiver<SignRequest>),
}

impl PendingRequest {
    fn id(&self) -> SignId {
        match self {
            Self::Available(request) => request.indexed.id,
            Self::Pending(id, _) => *id,
        }
    }

    async fn fetch(self, timeout: Duration) -> Option<SignRequest> {
        match self {
            PendingRequest::Available(request) => Some(request),
            PendingRequest::Pending(sign_id, channel) => {
                match tokio::time::timeout(timeout, channel).await {
                    Ok(Ok(request)) => Some(request),
                    Ok(Err(_)) => {
                        tracing::warn!(
                            ?sign_id,
                            "pending sign request channel closed before receiving request"
                        );
                        None
                    }
                    Err(_) => {
                        tracing::warn!(
                            ?sign_id,
                            ?timeout,
                            "timeout waiting for pending sign request"
                        );
                        None
                    }
                }
            }
        }
    }
}

/// The sign request for the node to process. This contains relevant info for the node
/// to generate a signature such as what has been indexed and what the node needs to maintain
/// metadata-wise to generate the signature.
#[derive(Debug, Clone, PartialEq)]
pub struct SignRequest {
    pub indexed: IndexedSignRequest,
    pub proposer: Participant,
    pub stable: BTreeSet<Participant>,
    pub round: usize,
}

pub struct SignQueue {
    me: Participant,
    sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
    /// The requests that belong to us where we will the propose the signature to the chain.
    my_requests: VecDeque<SignId>,
    /// Set of requests that failed to be processed during signature generation and need to
    /// be reorganized with a potentially newer set of stable participants.
    failed_requests: VecDeque<SignId>,
    /// The pool of requests that we are about to process or are currently processing. Only
    /// to be removed when fully timing out or when the request is completed.
    requests: HashMap<SignId, SignRequest>,
    /// The set of pending request listeners that are waiting for a sign request to be indexed.
    /// They will be notified when a sign request is available.
    pending: HashMap<SignId, oneshot::Sender<SignRequest>>,
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
            requests: HashMap::new(),
            failed_requests: VecDeque::new(),
            pending: HashMap::new(),
        }
    }

    pub fn len_mine(&self) -> usize {
        self.my_requests.len()
    }

    pub fn is_empty_mine(&self) -> bool {
        self.len_mine() == 0
    }

    /// Length of requests that are currently in the sign queue. This includes all requests that
    /// our node has observed, which means this does not include pending requests.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns true if the sign queue is empty. Excludes pending requests.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn contains(&self, sign_id: &SignId) -> bool {
        self.requests.contains_key(sign_id)
    }

    fn organize_request(
        &self,
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        indexed: IndexedSignRequest,
        initial_round: usize,
    ) -> SignRequest {
        let sign_id = indexed.id;
        let reorganize = initial_round > 0;
        let mut participants = if indexed.participants.is_some() {
            indexed.participants.clone().unwrap()
        } else {
            participants.keys().cloned().collect()
        };
        participants.sort();

        // Simple round-robin selection of the proposer, using only inputs that
        // are guaranteed to be the same on all nodes.
        fn proposer_per_round(
            round: usize,
            participants: &[Participant],
            entropy: &[u8; 32],
        ) -> Participant {
            // if entropy is random, using one byte is as good as using all
            let index = entropy[0] as usize + round;
            participants[index % participants.len()]
        }

        let max_rounds = initial_round + 512;
        // Use the smallest round that selects a stable proposer.
        let (round, proposer) = (initial_round..max_rounds)
            .map(|round| {
                (
                    round,
                    proposer_per_round(round, &participants, &indexed.args.entropy),
                )
            })
            .find(|(_, potential_proposer)| stable.contains(potential_proposer))
            // on exhausting all rounds, just pick one at random and have posits error out.
            .unwrap_or_else(|| {
                (
                    max_rounds,
                    *stable
                        .iter()
                        .choose(&mut StdRng::from_seed(indexed.args.entropy))
                        .unwrap(),
                )
            });

        let is_mine = proposer == self.me;
        tracing::info!(
            ?stable,
            ?sign_id,
            ?proposer,
            me = ?self.me,
            is_mine,
            "sign queue: {}organizing request",
            if reorganize { "re" } else { "" },
        );

        SignRequest {
            indexed,
            proposer,
            stable: stable.clone(),
            round,
        }
    }

    pub async fn organize(
        &mut self,
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        my_account_id: &AccountId,
    ) {
        // Reorganize the failed requests with a potentially newer list of stable participants.
        self.organize_failed(stable, participants, my_account_id);

        // try and organize the new incoming requests.
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
            let sign_id = indexed.id;
            if self.contains(&sign_id) {
                tracing::info!(?sign_id, "skipping sign request: already in the sign queue");
                continue;
            }
            crate::metrics::NUM_UNIQUE_SIGN_REQUESTS
                .with_label_values(&[indexed.chain.as_str(), my_account_id.as_str()])
                .inc();

            let request = self.organize_request(stable, participants, indexed, 0);
            let is_mine = request.proposer == self.me;
            if is_mine {
                self.my_requests.push_back(sign_id);
                crate::metrics::NUM_SIGN_REQUESTS_MINE
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
            }
            if let Some(pending) = self.pending.remove(&sign_id) {
                if pending.send(request.clone()).is_err() {
                    tracing::warn!(
                        ?sign_id,
                        "pending sign request channel closed before able to send request"
                    );
                }
            }

            self.requests.insert(sign_id, request);
        }
    }

    fn organize_failed(
        &mut self,
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        my_account_id: &AccountId,
    ) {
        while let Some(id) = self.failed_requests.pop_front() {
            let Some(request) = self.requests.remove(&id) else {
                continue;
            };

            let (reorganized, request) = if &request.stable == stable {
                // just use the same request if the participants are the same
                (false, request)
            } else {
                let request =
                    self.organize_request(stable, participants, request.indexed, request.round);
                (true, request)
            };

            // NOTE: this prioritizes old requests first then tries to do new ones if there's enough presignatures.
            // TODO: we need to decide how to prioritize certain requests over others such as with gas or time of
            // when the request made it into the NEAR network.
            // issue: https://github.com/near/mpc-recovery/issues/596
            if request.proposer == self.me {
                self.my_requests.push_front(request.indexed.id);
                if reorganized {
                    crate::metrics::NUM_SIGN_REQUESTS_MINE
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();
                }
            }

            self.requests.insert(request.indexed.id, request);
        }
    }

    pub fn push_failed(&mut self, sign_id: SignId) {
        self.failed_requests.push_back(sign_id);
    }

    pub fn take_mine(&mut self) -> Option<SignRequest> {
        let id = self.my_requests.pop_front()?;
        self.requests.get(&id).cloned()
    }

    pub fn get_or_pending(&mut self, id: &SignId) -> PendingRequest {
        if let Some(request) = self.requests.get(id) {
            PendingRequest::Available(request.clone())
        } else {
            let (tx, rx) = oneshot::channel();
            self.pending.insert(*id, tx);
            PendingRequest::Pending(*id, rx)
        }
    }

    pub fn expire(&mut self, cfg: &ProtocolConfig) {
        self.requests.retain(|_, request| {
            request.indexed.timestamp_sign_queue.is_none_or(|t| {
                t.elapsed() < Duration::from_millis(cfg.signature.generation_timeout_total)
            })
        });
        self.my_requests.retain(|id| {
            let Some(request) = self.requests.get(id) else {
                // if we are unable to find the corresponding request, we can remove it.
                return false;
            };
            crate::util::duration_between_unix(
                request.indexed.unix_timestamp_indexed,
                crate::util::current_unix_timestamp(),
            ) < request.indexed.total_timeout
        });
        self.failed_requests.retain(|id| {
            let Some(request) = self.requests.get(id) else {
                // if we are unable to find the corresponding request, we can remove it.
                return false;
            };
            crate::util::duration_between_unix(
                request.indexed.unix_timestamp_indexed,
                crate::util::current_unix_timestamp(),
            ) < request.indexed.total_timeout
        });
    }

    pub fn remove(&mut self, sign_id: SignId) -> Option<SignRequest> {
        self.requests.remove(&sign_id)
    }
}

enum SignError {
    Retry,
    TotalTimeout,
    Aborted,
}

/// Messages that can be sent to a SignatureGenerator.
#[derive(Debug)]
enum GeneratorMessage {
    Posit(Participant, PositAction),
    Signature(SignatureMessage),
}

/// Tracks whether presignature is available or needs to be fetched.
enum PendingPresignature {
    Available(PresignatureTaken),
    InStorage(PresignatureId, Participant, PresignatureStorage),
}

impl PendingPresignature {
    fn id(&self) -> PresignatureId {
        match self {
            PendingPresignature::Available(taken) => taken.presignature.id,
            PendingPresignature::InStorage(id, _, _) => *id,
        }
    }

    async fn fetch(self, me: Participant, timeout: Duration) -> Option<PresignatureTaken> {
        let (id, storage, owner) = match self {
            PendingPresignature::Available(taken) => return Some(taken),
            PendingPresignature::InStorage(id, owner, storage) => (id, storage, owner),
        };

        let presignature = tokio::time::timeout(timeout, async {
            // TODO: we can make storage wait for presignature to be available instead of here
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            loop {
                interval.tick().await;
                if let Some(presignature) = storage.take(id, owner, me).await {
                    break presignature;
                };
            }
        })
        .await;

        match presignature {
            Ok(presignature) => Some(presignature),
            Err(_) => {
                tracing::warn!(
                    id,
                    ?timeout,
                    "timeout waiting for presignature to be available"
                );
                None
            }
        }
    }
}

/// An ongoing signature generator.
struct SignatureGenerator {
    sign_id: SignId,
    presignature_id: PresignatureId,
    posit_manager: PositManager<PresignatureTaken>,
    pending_presignature: Option<PendingPresignature>,
    presignature_output: Option<PresignOutput<Secp256k1>>,
    protocol: Option<SignatureProtocol>,
    dropper: Option<PresignatureTakenDropper>,
    participants: Vec<Participant>,
    request: SignRequest,
    public_key: PublicKey,
    created: Instant,
    timeout: Duration,
    timeout_total: Duration,
    posit_inbox: mpsc::Receiver<GeneratorMessage>,
    signature_inbox: mpsc::Receiver<SignatureMessage>,
    msg: MessageChannel,
    rpc: RpcChannel,
    sign_respond_signature_channel: SignRespondSignatureChannel,
}

impl SignatureGenerator {
    #[allow(clippy::too_many_arguments)]
    async fn new_proposer(
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        presignature_taken: PresignatureTaken,
        participants: Vec<Participant>,
        public_key: PublicKey,
        cfg: ProtocolConfig,
        posit_inbox: mpsc::Receiver<GeneratorMessage>,
        msg: MessageChannel,
        rpc: RpcChannel,
        sign_respond_signature_channel: SignRespondSignatureChannel,
    ) -> Self {
        tracing::info!(
            ?me,
            ?sign_id,
            presignature_id,
            "starting signature generator as proposer"
        );

        let signature_inbox = msg.subscribe_signature(sign_id, presignature_id).await;
        let posit_manager = PositManager::new_proposer(me, presignature_taken, &participants);

        Self {
            sign_id,
            presignature_id,
            posit_manager,
            pending_presignature: None,
            presignature_output: None,
            protocol: None,
            dropper: None,
            participants,
            request,
            public_key,
            created: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
            posit_inbox,
            signature_inbox,
            msg,
            rpc,
            sign_respond_signature_channel,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_deliberator(
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        proposer: Participant,
        presignature_storage: PresignatureStorage,
        participants: Vec<Participant>,
        public_key: PublicKey,
        cfg: ProtocolConfig,
        posit_inbox: mpsc::Receiver<GeneratorMessage>,
        msg: MessageChannel,
        rpc: RpcChannel,
        sign_respond_signature_channel: SignRespondSignatureChannel,
    ) -> Self {
        tracing::info!(
            ?me,
            ?sign_id,
            presignature_id,
            "starting signature generator as deliberator"
        );

        let signature_inbox = msg.subscribe_signature(sign_id, presignature_id).await;
        let posit_manager = PositManager::new_deliberator(me, participants.len() * 2 / 3 + 1);
        let pending_presignature = Some(PendingPresignature::InStorage(
            presignature_id,
            proposer,
            presignature_storage,
        ));

        Self {
            sign_id,
            presignature_id,
            posit_manager,
            pending_presignature,
            presignature_output: None,
            protocol: None,
            dropper: None,
            participants,
            request,
            public_key,
            created: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
            posit_inbox,
            signature_inbox,
            msg,
            rpc,
            sign_respond_signature_channel,
        }
    }

    fn timeout_total(&self) -> bool {
        let timestamp = self
            .request
            .indexed
            .timestamp_sign_queue
            .as_ref()
            .unwrap_or(&self.created);
        timestamp.elapsed() >= self.timeout_total
    }

    /// Receive the next message from either the posit or signature channel.
    async fn recv(&mut self) -> Result<GeneratorMessage, SignError> {
        let sign_id = self.sign_id;
        let presignature_id = self.presignature_id;

        let timeout_duration = self.timeout.saturating_sub(self.created.elapsed());

        tokio::select! {
            biased;

            msg = self.posit_inbox.recv() => {
                msg.ok_or_else(|| {
                    tracing::warn!(?sign_id, presignature_id, "posit channel closed");
                    SignError::Aborted
                })
            }
            msg = self.signature_inbox.recv() => {
                msg.map(GeneratorMessage::Signature)
                    .ok_or_else(|| {
                        tracing::warn!(?sign_id, presignature_id, "signature channel closed");
                        SignError::Aborted
                    })
            }
            _ = tokio::time::sleep(timeout_duration) => {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    "signature generation timeout"
                );
                Err(SignError::Retry)
            }
        }
    }

    /// Handle a posit message and update the posit manager state.
    /// Returns true if posit consensus is reached.
    async fn handle_posit(
        &mut self,
        from: Participant,
        action: &PositAction,
        me: Participant,
        _epoch: u64,
    ) -> bool {
        let sign_id = self.sign_id;
        let presignature_id = self.presignature_id;

        let internal_action = self.posit_manager.act(from, action);

        match internal_action {
            PositInternalAction::None => false,
            PositInternalAction::Abort => {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    ?from,
                    "posit action rejected, aborting"
                );
                false
            }
            PositInternalAction::Reply(reply_action) => {
                self.msg
                    .send(
                        me,
                        from,
                        PositMessage {
                            id: PositProtocolId::Signature(sign_id, presignature_id),
                            from: me,
                            action: reply_action,
                        },
                    )
                    .await;
                false
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                // For proposer, extract the presignature from positor
                if let crate::protocol::posit::Positor::Proposer(_proposer_id, taken) = positor {
                    let (presignature, dropper) = taken.take();
                    self.presignature_output = Some(presignature.output);
                    self.dropper = Some(dropper);
                }

                // Send START message to all participants
                for &p in &participants {
                    if p == me {
                        continue;
                    }
                    self.msg
                        .send(
                            me,
                            p,
                            PositMessage {
                                id: PositProtocolId::Signature(sign_id, presignature_id),
                                from: me,
                                action: PositAction::Start(participants.clone()),
                            },
                        )
                        .await;
                }

                self.participants = participants;
                self.participants.sort();
                true
            }
        }
    }

    /// Wait for presignature to become available (for deliberators).
    async fn wait_for_presignature(&mut self, me: Participant) -> Result<(), SignError> {
        if let Some(pending) = self.pending_presignature.take() {
            let presignature_id = self.presignature_id;
            let sign_id = self.sign_id;

            tracing::debug!(
                ?sign_id,
                presignature_id,
                "waiting for presignature to be available"
            );

            let taken = pending.fetch(me, self.timeout).await.ok_or_else(|| {
                tracing::warn!(?sign_id, presignature_id, "presignature not available");
                SignError::Retry
            })?;

            let (presignature, dropper) = taken.take();
            self.presignature_output = Some(presignature.output);
            self.dropper = Some(dropper);

            tracing::debug!(?sign_id, presignature_id, "presignature is now available");
        }
        Ok(())
    }

    /// Initialize the signature protocol with the presignature.
    async fn initialize_protocol(&mut self, me: Participant) -> Result<(), SignError> {
        let sign_id = self.sign_id;
        let indexed = &self.request.indexed;

        // For proposer, posit_manager stores the presignature. For deliberator, we already have it from wait_for_presignature.
        if self.presignature_output.is_none() {
            // Proposer path: get presignature from posit_manager's store
            let taken_manager = std::mem::replace(
                &mut self.posit_manager,
                PositManager::new_deliberator(
                    self.participants[0],
                    self.participants.len() * 2 / 3 + 1,
                ),
            );
            if let Some(taken) = taken_manager.take_store() {
                let (presignature, dropper) = taken.take();
                self.presignature_output = Some(presignature.output);
                self.dropper = Some(dropper);
            } else {
                tracing::error!(?sign_id, ?me, "no presignature in posit manager");
                return Err(SignError::Retry);
            }
        }

        // At this point, both presignature_output and dropper must be set
        let presignature_id = self.dropper.as_ref().unwrap().id;
        let presignature_output = self.presignature_output.as_ref().unwrap();

        let PresignOutput { big_r, k, sigma } = presignature_output;
        let delta = derive_delta(indexed.id.request_id, indexed.args.entropy, *big_r);
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (*big_r * delta).to_affine(),
            k: *k * delta.invert().unwrap(),
            sigma: (*sigma + indexed.args.epsilon * k) * delta.invert().unwrap(),
        };

        let protocol = Box::new(
            cait_sith::sign(
                &self.participants,
                me,
                derive_key(self.public_key, indexed.args.epsilon),
                output,
                indexed.args.payload,
            )
            .map_err(|e| {
                tracing::error!(
                    ?sign_id,
                    presignature_id,
                    ?e,
                    "failed to initialize signature protocol"
                );
                SignError::Retry
            })?,
        );

        self.protocol = Some(protocol);
        tracing::info!(
            ?sign_id,
            presignature_id,
            ?me,
            "signature protocol initialized"
        );
        Ok(())
    }

    async fn run(
        mut self,
        me: Participant,
        epoch: u64,
        my_account_id: AccountId,
    ) -> Result<(), SignError> {
        let sign_id = self.sign_id;
        let presignature_id = self.presignature_id;

        // Phase 1: Posit consensus
        loop {
            match self.recv().await? {
                GeneratorMessage::Posit(from, action) => {
                    if self.handle_posit(from, &action, me, epoch).await {
                        // Posit consensus reached
                        break;
                    }
                }
                GeneratorMessage::Signature(_) => {
                    tracing::warn!(
                        ?sign_id,
                        "received signature message before posit consensus"
                    );
                }
            }
        }

        // Phase 2: Wait for presignature (deliberators only)
        if self.pending_presignature.is_some() {
            self.wait_for_presignature(me).await?;
        }

        // Phase 3: Initialize protocol
        self.initialize_protocol(me).await?;

        // Phase 4: Run signature protocol

        // Phase 4: Run signature protocol
        let presignature_id = self.presignature_id;

        let accrued_wait_delay = crate::metrics::SIGNATURE_ACCRUED_WAIT_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let poke_counts =
            crate::metrics::SIGNATURE_POKES_CNT.with_label_values(&[my_account_id.as_str()]);
        let poke_latency =
            crate::metrics::SIGNATURE_POKE_CPU_TIME.with_label_values(&[my_account_id.as_str()]);

        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        crate::metrics::SIGNATURE_BEFORE_POKE_DELAY
            .with_label_values(&[my_account_id.as_str()])
            .observe(self.created.elapsed().as_millis() as f64);

        loop {
            let timestamp = self
                .request
                .indexed
                .timestamp_sign_queue
                .as_ref()
                .unwrap_or(&self.created);
            if timestamp.elapsed() >= self.timeout_total {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    "signature generation timeout, exhausted all attempts"
                );
                if self.request.proposer == me {
                    crate::metrics::SIGNATURE_GENERATOR_FAILURES
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();
                    crate::metrics::SIGNATURE_FAILURES
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();
                }
                break Err(SignError::TotalTimeout);
            }

            let poke_start_time = Instant::now();
            let action = match self.protocol.as_mut().unwrap().poke() {
                Ok(action) => action,
                Err(err) => {
                    tracing::error!(
                        ?sign_id,
                        ?err,
                        "signature generation failed on protocol advancement",
                    );
                    break Err(SignError::Retry);
                }
            };

            total_wait += poke_start_time - poke_last_time;
            total_pokes += 1;
            poke_last_time = Instant::now();
            poke_latency.observe(poke_start_time.elapsed().as_millis() as f64);

            match action {
                Action::Wait => {
                    // Wait for the next signature message
                    let msg = match self.recv().await? {
                        GeneratorMessage::Signature(msg) => msg,
                        GeneratorMessage::Posit(from, action) => {
                            tracing::warn!(
                                ?sign_id,
                                ?from,
                                ?action,
                                "received posit message during protocol execution"
                            );
                            continue;
                        }
                    };
                    self.protocol.as_mut().unwrap().message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
                    for &to in self.participants.iter() {
                        if to == me {
                            continue;
                        }
                        self.msg
                            .send(
                                me,
                                to,
                                SignatureMessage {
                                    id: sign_id,
                                    proposer: self.request.proposer,
                                    presignature_id,
                                    epoch,
                                    from: me,
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
                            me,
                            to,
                            SignatureMessage {
                                id: sign_id,
                                proposer: self.request.proposer,
                                presignature_id,
                                epoch,
                                from: me,
                                data,
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                }
                Action::Return(output) => {
                    tracing::info!(
                        ?sign_id,
                        ?me,
                        presignature_id,
                        big_r = ?output.big_r.to_base58(),
                        s = ?output.s,
                        elapsed = ?self.created.elapsed(),
                        "completed signature generation"
                    );

                    accrued_wait_delay.observe(total_wait.as_millis() as f64);
                    poke_counts.observe(total_pokes as f64);
                    crate::metrics::SIGN_GENERATION_LATENCY
                        .with_label_values(&[my_account_id.as_str()])
                        .observe(self.created.elapsed().as_secs_f64());

                    if self.request.proposer == me {
                        self.rpc.publish(
                            self.public_key,
                            self.request.clone(),
                            output,
                            self.participants.clone(),
                        );
                    } else if let SignRequestType::SignRespond(_) =
                        self.request.indexed.sign_request_type
                    {
                        self.sign_respond_signature_channel.send(
                            self.public_key,
                            self.request.clone(),
                            output,
                            self.participants.clone(),
                        );
                    }

                    break Ok(());
                }
            }
        }
    }
}

impl Drop for SignatureGenerator {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        let sign_id = self.sign_id;
        let presignature_id = self.presignature_id;
        tokio::spawn(async move {
            msg.unsubscribe_signature(sign_id, presignature_id).await;
            msg.filter_sign(sign_id, presignature_id).await;
        });
    }
}

pub struct SignatureSpawner {
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Ongoing signature generation protocols.
    ongoing: JoinMap<(SignId, PresignatureId), Result<(), SignError>>,
    /// Sign queue that maintains all requests coming in from indexer.
    sign_queue: SignQueue,
    /// Channels to send messages to individual generators.
    generator_channels: HashMap<(SignId, PresignatureId), mpsc::Sender<GeneratorMessage>>,
    /// Messages waiting for generators to be created.
    pending_messages: HashMap<(SignId, PresignatureId), Vec<(Participant, PositAction)>>,

    me: Participant,
    my_account_id: AccountId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,
    msg: MessageChannel,
    rpc: RpcChannel,
    sign_respond_signature_channel: SignRespondSignatureChannel,
}

impl SignatureSpawner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        me: Participant,
        my_account_id: &AccountId,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
        sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
        rpc: RpcChannel,
        sign_respond_signature_channel: SignRespondSignatureChannel,
    ) -> Self {
        Self {
            presignatures: presignatures.clone(),
            ongoing: JoinMap::new(),
            sign_queue: SignQueue::new(me, sign_rx),
            generator_channels: HashMap::new(),
            pending_messages: HashMap::new(),
            me,
            my_account_id: my_account_id.clone(),
            threshold,
            public_key,
            epoch,
            msg,
            rpc,
            sign_respond_signature_channel,
        }
    }

    /// Routes a posit message to the appropriate generator, or returns true if we should spawn a pending task.
    fn route_posit_message(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        from: Participant,
        action: PositAction,
    ) -> bool {
        let id = (sign_id, presignature_id);

        if let Some(channel) = self.generator_channels.get(&id) {
            // Route to existing generator
            let channel = channel.clone();
            tokio::spawn(async move {
                let _ = channel.send(GeneratorMessage::Posit(from, action)).await;
            });
            false
        } else {
            // Generator doesn't exist yet
            match action {
                PositAction::Propose => {
                    // Need to fetch request asynchronously and create generator
                    true
                }
                PositAction::Start(_) | PositAction::Accept | PositAction::Reject => {
                    // These messages arrive after Propose, but generator might not be created yet.
                    // Queue them for processing after generator is created.
                    self.pending_messages
                        .entry(id)
                        .or_insert_with(Vec::new)
                        .push((from, action));
                    false
                }
            }
        }
    }

    /// Spawns a new signature generator as either proposer or deliberator.
    async fn spawn_generator(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        proposer: Participant,
        participants: Vec<Participant>,
        presignature_taken: Option<PresignatureTaken>,
    ) {
        let id = (sign_id, presignature_id);

        if self.ongoing.contains_key(&id) {
            tracing::warn!(?sign_id, presignature_id, "generator already exists");
            return;
        }

        if participants.len() < self.threshold {
            tracing::warn!(
                ?sign_id,
                presignature_id,
                "insufficient participants for signature generation"
            );
            self.sign_queue.push_failed(sign_id);
            return;
        }

        let (tx, rx) = mpsc::channel(1024);
        self.generator_channels.insert(id, tx.clone());

        // Send any pending messages that arrived before the generator was created
        if let Some(pending) = self.pending_messages.remove(&id) {
            for (from, action) in pending {
                tokio::spawn({
                    let tx = tx.clone();
                    async move {
                        let _ = tx.send(GeneratorMessage::Posit(from, action)).await;
                    }
                });
            }
        }

        let me = self.me;
        let epoch = self.epoch;
        let public_key = self.public_key;
        let my_account_id = self.my_account_id.clone();
        let msg = self.msg.clone();
        let rpc = self.rpc.clone();
        let sign_respond_signature_channel = self.sign_respond_signature_channel.clone();
        let cfg = mpc_contract::config::ProtocolConfig::default(); // TODO: pass actual config

        let generator = if let Some(taken) = presignature_taken {
            // Proposer
            SignatureGenerator::new_proposer(
                me,
                sign_id,
                presignature_id,
                request,
                taken,
                participants,
                public_key,
                cfg,
                rx,
                msg,
                rpc,
                sign_respond_signature_channel,
            )
            .await
        } else {
            // Deliberator
            SignatureGenerator::new_deliberator(
                me,
                sign_id,
                presignature_id,
                request,
                proposer,
                self.presignatures.clone(),
                participants,
                public_key,
                cfg,
                rx,
                msg,
                rpc,
                sign_respond_signature_channel,
            )
            .await
        };

        crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[my_account_id.as_str()])
            .inc();

        let task = async move { generator.run(me, epoch, my_account_id).await };

        self.ongoing.spawn(id, task);
    }

    /// Starts a new signature generation protocol as proposer.
    async fn propose_signature(
        &mut self,
        request: &SignRequest,
        taken: PresignatureTaken,
        participants: &[Participant],
    ) {
        let sign_id = request.indexed.id;
        let presignature_id = taken.presignature.id;
        tracing::info!(
            ?sign_id,
            presignature_id,
            "proposing protocol to generate a new signature"
        );

        // Spawn the generator as proposer
        self.spawn_generator(
            sign_id,
            presignature_id,
            request.clone(),
            self.me,
            participants.to_vec(),
            Some(taken),
        )
        .await;

        // Send propose messages to all participants
        for &p in participants.iter() {
            if p == self.me {
                continue;
            }

            self.msg
                .send(
                    self.me,
                    p,
                    PositMessage {
                        id: PositProtocolId::Signature(sign_id, presignature_id),
                        from: self.me,
                        action: PositAction::Propose,
                    },
                )
                .await;
        }
    }

    async fn handle_requests(
        &mut self,
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) {
        if stable.len() < self.threshold {
            tracing::warn!(
                ?stable,
                threshold = self.threshold,
                "not enough stable participants to handle requests"
            );
            return;
        }

        self.sign_queue.expire(cfg);
        self.sign_queue
            .organize(stable, participants, &self.my_account_id)
            .await;
        crate::metrics::SIGN_QUEUE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.sign_queue.len() as i64);
        crate::metrics::SIGN_QUEUE_MINE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.sign_queue.len_mine() as i64);

        let mut retry = Vec::new();
        while let Some(taken) = {
            if self.sign_queue.is_empty_mine() {
                None
            } else {
                self.presignatures.take_mine(self.me).await
            }
        } {
            let Some(my_request) = self.sign_queue.take_mine() else {
                tracing::warn!(
                    presignature = ?taken.presignature,
                    "unexpected, no more requests to handle. presignature will be removed",
                );
                continue;
            };

            let stable = stable.iter().copied().collect::<Vec<_>>();
            let participants = intersect_vec(&[&stable, &taken.presignature.participants]);
            if participants.len() < self.threshold {
                tracing::warn!(
                    sign_id = ?my_request.indexed.id,
                    presignature_id = ?taken.presignature.id,
                    ?participants,
                    "intersection < threshold, trashing presignature"
                );
                retry.push(my_request.indexed.id);
                continue;
            }

            self.propose_signature(&my_request, taken, &participants)
                .await;
        }

        for sign_id in retry {
            self.sign_queue.push_failed(sign_id);
        }
    }

    async fn run(
        mut self,
        contract: ContractStateWatcher,
        mesh_state: watch::Receiver<MeshState>,
        cfg: watch::Receiver<Config>,
    ) {
        // NOTE: signatures should only use stable and not active participants. The difference here is that
        // stable participants utilizes more than the online status of a node, such as whether or not their
        // block height is up to date, such that they too can process signature requests. If they cannot
        // then they are considered unstable and should not be a part of signature generation this round.

        let mut check_requests_interval = tokio::time::interval(Duration::from_millis(100));
        let mut posits = self.msg.subscribe_signature_posit().await;
        let mut pending_posits = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                Some((sign_id, presignature_id, from, action)) = posits.recv() => {
                    if self.route_posit_message(sign_id, presignature_id, from, action.clone()) {
                        // Need to spawn a task to wait for the request

                        // If this is a Propose, immediately send Accept so we don't miss consensus
                        if matches!(action, PositAction::Propose) && from != self.me {
                            self.msg.send(
                                self.me,
                                from,
                                PositMessage {
                                    id: PositProtocolId::Signature(sign_id, presignature_id),
                                    from: self.me,
                                    action: PositAction::Accept,
                                },
                            ).await;
                        }

                        let request = self.sign_queue.get_or_pending(&sign_id);
                        let timeout = Duration::from_millis(cfg.borrow().protocol.signature.generation_timeout);
                        pending_posits.spawn(async move {
                            let request = request.fetch(timeout).await;
                            (sign_id, presignature_id, request, from, action)
                        });
                    }
                }
                Some(pending_posit) = pending_posits.join_next() => {
                    let (sign_id, presignature_id, request, from, action) = match pending_posit {
                        Ok(posit) => posit,
                        Err(_) => {
                            tracing::warn!("signature posit fetching request interrupted");
                            continue;
                        },
                    };

                    let Some(request) = request else {
                        tracing::warn!(?sign_id, presignature_id, "received propose but sign request not available");
                        continue;
                    };

                    // Calculate participants - for deliberator we use stable participants
                    let participants = request.stable.iter().copied().collect::<Vec<_>>();

                    // Now spawn the generator and route the message
                    self.spawn_generator(sign_id, presignature_id, request.clone(), from, participants, None).await;

                    // Send the Propose message to the generator
                    if let Some(channel) = self.generator_channels.get(&(sign_id, presignature_id)) {
                        let _ = channel.send(GeneratorMessage::Posit(from, action)).await;
                    }
                }
                // `join_next` returns None on the set being empty, so don't handle that case
                Some(result) = self.ongoing.join_next(), if !self.ongoing.is_empty() => {
                    let ((sign_id, presignature_id), result) = match result {
                        Ok(outcome) => outcome,
                        Err((sign_id, presignature_id)) => {
                            tracing::warn!(?sign_id, presignature_id, "signature generation task interrupted");
                            self.generator_channels.remove(&(sign_id, presignature_id));
                            continue;
                        }
                    };

                    // Clean up the generator channel
                    self.generator_channels.remove(&(sign_id, presignature_id));

                    match result {
                        Err(SignError::Retry) => {
                            self.sign_queue.push_failed(sign_id);
                        }
                        Ok(()) | Err(SignError::TotalTimeout) | Err(SignError::Aborted) => {
                            self.sign_queue.remove(sign_id);
                        }
                    }
                }
                _ = check_requests_interval.tick() => {
                    let Some(participants) = contract.participants() else {
                        continue;
                    };
                    let stable = mesh_state.borrow().stable.clone();
                    let protocol = cfg.borrow().protocol.clone();
                    self.handle_requests(&stable, &participants, &protocol).await;
                }
            }
        }
    }
}

impl Drop for SignatureSpawner {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        tokio::spawn(msg.unsubscribe_signature_posit());
    }
}

pub struct SignatureSpawnerTask {
    handle: JoinHandle<()>,
}

impl SignatureSpawnerTask {
    pub fn run(
        me: Participant,
        threshold: usize,
        epoch: u64,
        ctx: &MpcSignProtocol,
        public_key: PublicKey,
    ) -> Self {
        let spawner = SignatureSpawner::new(
            me,
            &ctx.my_account_id,
            threshold,
            public_key,
            epoch,
            ctx.sign_rx.clone(),
            &ctx.presignature_storage,
            ctx.msg_channel.clone(),
            ctx.rpc_channel.clone(),
            ctx.sign_respond_signature_channel.clone(),
        );

        Self {
            handle: tokio::spawn(spawner.run(
                ctx.contract.clone(),
                ctx.mesh_state.clone(),
                ctx.config.clone(),
            )),
        }
    }

    pub fn abort(&self) {
        // NOTE: since dropping the handle here, PresignatureSpawner will drop their JoinSet/JoinMap
        // which will also abort all ongoing presignature generation tasks. This is important to note
        // since we do not want to leak any presignature generation tasks when we are resharing, and
        // potentially wasting compute.
        self.handle.abort();
    }
}

impl Drop for SignatureSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}
