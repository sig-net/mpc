use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::state::{
    GeneratingState, NodeState, ReshareAwaiting, ReshareRunning, ResharingPhase, ResharingState,
    RESHARING_READY_BROADCAST_INTERVAL,
};
use super::MpcSignProtocol;
use crate::protocol::contract::ResharingContractState;
use crate::protocol::message::{GeneratingMessage, ReadyMessage, ResharingMessage};
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MeshState;
use crate::types::{ReshareProtocol, SecretKeyShare};

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use k256::sha2::{Digest, Sha256};
use mpc_crypto::PublicKey;
use tokio::sync::mpsc;

pub static RESHARING_RUNNING_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(300);

pub fn resharing_running_timeout() -> Duration {
    Duration::from_secs(RESHARING_RUNNING_TIMEOUT_SECS.load(Ordering::SeqCst))
}

pub fn set_resharing_running_timeout(duration: Duration) {
    RESHARING_RUNNING_TIMEOUT_SECS.swap(duration.as_secs(), Ordering::SeqCst);
}

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
}

pub(crate) trait CryptographicProtocol {
    async fn progress(self, ctx: &mut MpcSignProtocol, mesh_state: MeshState) -> NodeState;
}

impl CryptographicProtocol for GeneratingState {
    async fn progress(mut self, ctx: &mut MpcSignProtocol, mesh_state: MeshState) -> NodeState {
        // Previous save to secret storage failed, try again until successful.
        if let Some((pk, sk_share)) = self.failed_store.take() {
            return self.finalize(pk, sk_share, ctx).await;
        }

        let participants = self.participants.keys_vec();
        tracing::info!(
            ?participants,
            active = ?mesh_state.active,
            "generating: progressing key generation",
        );
        loop {
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    tracing::error!(?err, "generating failed: refreshing...");
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh keygen protocol");
                    }
                    return NodeState::Generating(self);
                }
            };
            match action {
                Action::Wait => {
                    tracing::debug!("generating: waiting");
                    let mut counts = HashMap::<Participant, usize>::new();
                    loop {
                        let msg = match ctx.generating.try_recv() {
                            Ok(msg) => msg,
                            Err(mpsc::error::TryRecvError::Empty) => {
                                break;
                            }
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                tracing::warn!("generating: unexpected channel closure, stopping");
                                break;
                            }
                        };

                        counts.entry(msg.from).and_modify(|c| *c += 1).or_insert(1);
                        self.protocol.message(msg.from, msg.data);
                    }
                    if !counts.is_empty() {
                        tracing::info!(?counts, "generating: handling new messages");
                    }
                    return NodeState::Generating(self);
                }
                Action::SendMany(data) => {
                    tracing::debug!("generating: sending a message to many participants");
                    for p in &participants {
                        if p == &self.me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        ctx.msg_channel
                            .send(
                                self.me,
                                *p,
                                GeneratingMessage {
                                    from: self.me,
                                    data: data.clone(),
                                },
                            )
                            .await;
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("generating: sending a private message to {to:?}");
                    ctx.msg_channel
                        .send(
                            self.me,
                            to,
                            GeneratingMessage {
                                from: self.me,
                                data,
                            },
                        )
                        .await;
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "generating: successfully completed key generation"
                    );
                    return self.finalize(r.public_key, r.private_share, ctx).await;
                }
            }
        }
    }
}

impl GeneratingState {
    async fn finalize(
        mut self,
        public_key: PublicKey,
        private_share: SecretKeyShare,
        ctx: &mut MpcSignProtocol,
    ) -> NodeState {
        if let Err(err) = ctx
            .secret_storage
            .store(&PersistentNodeData {
                epoch: 0,
                private_share,
                public_key,
            })
            .await
        {
            tracing::error!(?err, "generating: failed to store secret");
            self.failed_store.replace((public_key, private_share));
            return NodeState::Generating(self);
        }

        NodeState::WaitingForConsensus(WaitingForConsensusState {
            epoch: 0,
            participants: self.participants,
            threshold: self.threshold,
            private_share,
            public_key,
        })
    }
}

impl CryptographicProtocol for WaitingForConsensusState {
    async fn progress(self, _ctx: &mut MpcSignProtocol, _mesh_state: MeshState) -> NodeState {
        // Wait for ConsensusProtocol step to advance state
        NodeState::WaitingForConsensus(self)
    }
}

impl CryptographicProtocol for ResharingState {
    async fn progress(mut self, ctx: &mut MpcSignProtocol, mesh_state: MeshState) -> NodeState {
        tracing::info!(active = ?mesh_state.active.keys_vec(), "progressing key reshare");

        let mut resharing = match self.phase {
            ResharingPhase::Resharing(resharing) => resharing,
            ResharingPhase::Awaiting(mut state) => {
                state.ready.insert(self.me);
                state.ready_tokens.insert(self.me, state.local_attempt);
                if state.update(ctx, &self.contract) {
                    tracing::debug!(?state.ready, "resharing: readiness updated");
                }

                let ready_tokens_snapshot = state.ready_tokens.clone();


                self.ready_nonce = state
                    .broadcast_ready(self.me, ctx, &self.contract, self.ready_nonce)
                    .await;

                if !state.startable(&self.contract) {
                    if tracing::enabled!(tracing::Level::DEBUG) {
                        let missing_ready: Vec<_> = self
                            .contract
                            .new_participants
                            .keys()
                            .filter(|participant| !state.ready.contains(participant))
                            .copied()
                            .collect();
                        let missing_tokens: Vec<_> = self
                            .contract
                            .new_participants
                            .keys()
                            .filter(|participant| !state.ready_tokens.contains_key(participant))
                            .copied()
                            .collect();
                        tracing::debug!(
                            ?missing_ready,
                            ?missing_tokens,
                            ready = ?state.ready,
                            ready_tokens = ?state.ready_tokens,
                            "resharing: not all participants ready yet"
                        );
                    }
                    self.active_ready_tokens = ready_tokens_snapshot;
                    self.phase = ResharingPhase::Awaiting(state);
                    return NodeState::Resharing(self);
                }

                let attempt_id = match state.combined_attempt_id(&self.contract) {
                    Some(attempt_id) => attempt_id,
                    None => {
                        tracing::debug!(
                            "resharing: waiting for attempt identifiers from all participants"
                        );
                        self.active_ready_tokens = ready_tokens_snapshot;
                        self.phase = ResharingPhase::Awaiting(state);
                        return NodeState::Resharing(self);
                    }
                };

                self.last_attempt_id = self.attempt_id;
                self.attempt_id = Some(attempt_id);
                self.active_ready_tokens = ready_tokens_snapshot;

                let mut protocol =
                    match ReshareProtocol::new(self.local_private_share, self.me, &self.contract) {
                        Ok(protocol) => protocol,
                        Err(err) => {
                            tracing::error!(?err, "resharing: failed to initialize/start protocol");
                            self.last_attempt_id = self.attempt_id;
                            self.attempt_id = None;
                            self.active_ready_tokens.clear();
                            self.phase = ResharingPhase::awaiting(self.me);
                            self.pending.clear();
                            return NodeState::Resharing(self);
                        }
                    };

                let mut replayed = HashMap::<Participant, usize>::new();
                while let Some(msg) = self.pending.pop_front() {
                    replayed
                        .entry(msg.from)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                    protocol.message(msg.from, msg.data);
                }
                if !replayed.is_empty() {
                    tracing::info!(
                        ?replayed,
                        "resharing: replayed buffered protocol messages after starting"
                    );
                }

                tracing::info!("resharing: all participants ready, starting protocol");
                let now = Instant::now();
                let mut running = ReshareRunning {
                    protocol,
                    failed_store: None,
                    started_at: now,
                    last_activity: now,
                };
                if !replayed.is_empty() {
                    running.last_activity = Instant::now();
                }
                self.phase = ResharingPhase::Resharing(running);
                return NodeState::Resharing(self);
            }
        };

        let mut restart_ready = HashMap::<Participant, u64>::new();
        loop {
            match ctx.ready.try_recv() {
                Ok(ReadyMessage {
                    epoch,
                    from,
                    attempt,
                    ..
                }) => {
                    if epoch != self.contract.old_epoch {
                        tracing::debug!(
                            message_epoch = epoch,
                            contract_epoch = self.contract.old_epoch,
                            "resharing: ignoring readiness message for other epoch while running",
                        );
                        continue;
                    }
                    if from == self.me {
                        continue;
                    }
                    match self.active_ready_tokens.get(&from) {
                        Some(current) if *current == attempt => {}
                        _ => {
                            restart_ready.insert(from, attempt);
                        }
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    tracing::warn!(
                        "resharing: readiness channel closed unexpectedly while running"
                    );
                    break;
                }
            }
        }

        if !restart_ready.is_empty() {
            let participants: Vec<_> = restart_ready.keys().copied().collect();
            tracing::info!(
                ?participants,
                "resharing: received readiness for new attempt while running, restarting"
            );
            self.last_attempt_id = self.attempt_id;
            self.attempt_id = None;
            self.active_ready_tokens.clear();
            self.phase = ResharingPhase::awaiting(self.me);
            self.pending.clear();
            if let ResharingPhase::Awaiting(state) = &mut self.phase {
                for (participant, attempt) in restart_ready {
                    if self.contract.new_participants.contains_key(&participant) {
                        state.ready.insert(participant);
                        state.ready_tokens.insert(participant, attempt);
                    }
                }
            }
            return NodeState::Resharing(self);
        }

        if let Some(sk_share) = resharing.failed_store.take() {
            match Self::try_finalize(ctx, &mut resharing, sk_share, &self.contract).await {
                Ok(next_state) => return next_state,
                Err(()) => {
                    self.phase = ResharingPhase::Resharing(resharing);
                    return NodeState::Resharing(self);
                }
            }
        }

        if resharing.last_activity.elapsed() > resharing_running_timeout() {
            tracing::warn!(
                elapsed = ?resharing.last_activity.elapsed(),
                "resharing: protocol timed out, restarting readiness phase",
            );
            self.last_attempt_id = self.attempt_id;
            self.attempt_id = None;
            self.active_ready_tokens.clear();
            self.phase = ResharingPhase::awaiting(self.me);
            self.pending.clear();
            return NodeState::Resharing(self);
        }

        loop {
            let action = match resharing.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    tracing::warn!(?err, "resharing failed, going back to awaiting phase");
                    self.last_attempt_id = self.attempt_id;
                    self.attempt_id = None;
                    self.active_ready_tokens.clear();
                    self.phase = ResharingPhase::awaiting(self.me);
                    self.pending.clear();
                    return NodeState::Resharing(self);
                }
            };

            match action {
                Action::Wait => {
                    tracing::debug!("resharing: waiting");
                    let mut counts = HashMap::<Participant, usize>::new();
                    loop {
                        let msg = match ctx.resharing.try_recv() {
                            Ok(msg) => msg,
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                tracing::warn!("resharing: unexpected channel closure, stopping");
                                break;
                            }
                        };

                        if msg.epoch != self.contract.old_epoch {
                            tracing::debug!(
                                expected = self.contract.old_epoch,
                                actual = msg.epoch,
                                "resharing: ignoring message for other epoch",
                            );
                            continue;
                        }

                        let Some(current_attempt) = self.attempt_id else {
                            tracing::warn!(
                                participant = ?msg.from,
                                "resharing: received protocol message without active attempt id"
                            );
                            continue;
                        };
                        if msg.attempt != current_attempt {
                            tracing::debug!(
                                expected = ?current_attempt,
                                actual = ?msg.attempt,
                                participant = ?msg.from,
                                "resharing: ignoring message for different resharing attempt",
                            );
                            continue;
                        }

                        counts.entry(msg.from).and_modify(|c| *c += 1).or_insert(1);
                        resharing.protocol.message(msg.from, msg.data);
                    }
                    if !counts.is_empty() {
                        resharing.last_activity = Instant::now();
                        tracing::info!(?counts, "resharing: handling new messages");
                    }
                    self.phase = ResharingPhase::Resharing(resharing);
                    return NodeState::Resharing(self);
                }
                Action::SendMany(data) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    resharing.last_activity = Instant::now();
                    let Some(attempt_id) = self.attempt_id else {
                        tracing::error!(
                            "resharing: unable to send broadcast without active attempt identifier"
                        );
                        continue;
                    };
                    for p in self.contract.new_participants.keys() {
                        if p == &self.me {
                            continue;
                        }
                        ctx.msg_channel
                            .send(
                                self.me,
                                *p,
                                ResharingMessage {
                                    epoch: self.contract.old_epoch,
                                    from: self.me,
                                    attempt: attempt_id,
                                    data: data.clone(),
                                },
                            )
                            .await;
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("resharing: sending a private message to {to:?}");
                    if self.contract.new_participants.get(&to).is_none() {
                        tracing::error!("resharing: send_private unknown participant {to:?}");
                    } else {
                        resharing.last_activity = Instant::now();
                        let Some(attempt_id) = self.attempt_id else {
                            tracing::error!(
                                "resharing: unable to send private message without active attempt identifier"
                            );
                            continue;
                        };
                        ctx.msg_channel
                            .send(
                                self.me,
                                to,
                                ResharingMessage {
                                    epoch: self.contract.old_epoch,
                                    from: self.me,
                                    attempt: attempt_id,
                                    data,
                                },
                            )
                            .await;
                    }
                }
                Action::Return(private_share) => {
                    tracing::info!("resharing: successfully completed key reshare");
                    resharing.last_activity = Instant::now();
                    match Self::try_finalize(ctx, &mut resharing, private_share, &self.contract)
                        .await
                    {
                        Ok(next_state) => return next_state,
                        Err(()) => {
                            self.phase = ResharingPhase::Resharing(resharing);
                            return NodeState::Resharing(self);
                        }
                    }
                }
            }
        }
    }
}

impl ResharingState {
    async fn try_finalize(
        ctx: &mut MpcSignProtocol,
        running_state: &mut ReshareRunning,
        private_share: SecretKeyShare,
        contract: &ResharingContractState,
    ) -> Result<NodeState, ()> {
        if let Err(err) = ctx
            .secret_storage
            .store(&PersistentNodeData {
                epoch: contract.old_epoch + 1,
                private_share,
                public_key: contract.public_key,
            })
            .await
        {
            tracing::error!(?err, "resharing: failed to store secret");
            running_state.failed_store.replace(private_share);
            return Err(());
        }

        if !ctx.triple_storage.clear().await {
            tracing::error!("failed to clear triples from storage on new epoch start");
        }

        if !ctx.presignature_storage.clear().await {
            tracing::error!("failed to clear presignatures from storage on new epoch start");
        }

        Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
            epoch: contract.old_epoch + 1,
            participants: contract.new_participants.clone(),
            threshold: contract.threshold,
            private_share,
            public_key: contract.public_key,
        }))
    }
}

impl ReshareAwaiting {
    fn startable(&self, contract: &ResharingContractState) -> bool {
        let ready = self.ready_count(contract);
        let total = contract.new_participants.len();
        let threshold = contract.threshold;

        total >= threshold
            && ready == total
            && contract
                .new_participants
                .keys()
                .all(|participant| self.ready_tokens.contains_key(participant))
    }

    fn update(&mut self, ctx: &mut MpcSignProtocol, contract: &ResharingContractState) -> bool {
        let mut updated = false;
        loop {
            match ctx.ready.try_recv() {
                Ok(ReadyMessage {
                    epoch,
                    from,
                    attempt,
                    ..
                }) => {
                    if epoch != contract.old_epoch {
                        tracing::warn!(
                            message_epoch = epoch,
                            contract_epoch = contract.old_epoch,
                            "resharing: ignoring readiness message for other epoch",
                        );
                        continue;
                    }
                    if contract.new_participants.contains_key(&from) {
                        if self.ready.insert(from) {
                            updated = true;
                        }
                        self.ready_tokens.insert(from, attempt);
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    tracing::warn!("resharing: readiness channel closed unexpectedly");
                    break;
                }
            }
        }
        updated
    }

    async fn broadcast_ready(
        &mut self,
        me: Participant,
        ctx: &mut MpcSignProtocol,
        contract: &ResharingContractState,
        nonce: u64,
    ) -> u64 {
        // We will constantly broadcast our readiness until the running phase begins.
        // This is to ensure that all participants are aware of our readiness state.
        // Everyone maintains a set of ready participants, so repeatedly broadcasting
        // will not affect correctness and ensures liveness in case of message loss.
        if self.broadcast_interval.elapsed() < RESHARING_READY_BROADCAST_INTERVAL {
            return nonce;
        }
        self.broadcast_interval = Instant::now();

        for &participant in contract.new_participants.keys() {
            if participant == me {
                continue;
            }
            ctx.msg_channel
                .send(
                    me,
                    participant,
                    ReadyMessage {
                        epoch: contract.old_epoch,
                        from: me,
                        nonce,
                        attempt: self.local_attempt,
                    },
                )
                .await;
        }

        nonce.wrapping_add(1)
    }

    fn ready_count(&self, contract: &ResharingContractState) -> usize {
        self.ready
            .iter()
            .filter(|participant| contract.new_participants.contains_key(participant))
            .count()
    }

    fn combined_attempt_id(&self, contract: &ResharingContractState) -> Option<u64> {
        let mut tokens = Vec::with_capacity(contract.new_participants.len());
        for participant in contract.new_participants.keys() {
            tokens.push(*self.ready_tokens.get(participant)?);
        }
        tokens.sort_unstable();

        let mut hasher = Sha256::new();
        for token in tokens {
            hasher.update(token.to_le_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        Some(u64::from_le_bytes(bytes))
    }
}

impl CryptographicProtocol for NodeState {
    async fn progress(self, ctx: &mut MpcSignProtocol, mesh_state: MeshState) -> NodeState {
        match self {
            NodeState::Generating(state) => state.progress(ctx, mesh_state).await,
            NodeState::Resharing(state) => state.progress(ctx, mesh_state).await,
            NodeState::WaitingForConsensus(state) => state.progress(ctx, mesh_state).await,
            _ => self,
        }
    }
}
