use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::state::{
    GeneratingState, NodeState, ResharingPhase, ResharingReadyState, ResharingRunningState,
    ResharingState, RESHARING_READY_BROADCAST_INTERVAL,
};
use super::MpcSignProtocol;
use crate::protocol::message::{GeneratingMessage, ResharingMessage, ResharingReadyMessage};
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MeshState;
use crate::types::{ReshareProtocol, SecretKeyShare};

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use mpc_crypto::PublicKey;
use tokio::sync::mpsc;

const RESHARING_RUNNING_TIMEOUT: Duration = Duration::from_secs(60);

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

        loop {
            let mut phase = ResharingPhase::AwaitingReady(self.initial_ready_state());
            std::mem::swap(&mut self.phase, &mut phase);

            match phase {
                ResharingPhase::AwaitingReady(mut ready_state) => {
                    ready_state.ready.insert(self.me);
                    let updated = self.drain_ready_messages(ctx, &mut ready_state);
                    if updated {
                        tracing::debug!(?ready_state.ready, "resharing: readiness updated");
                    }

                    if ready_state.last_broadcast.elapsed() >= RESHARING_READY_BROADCAST_INTERVAL {
                        self.broadcast_ready(ctx).await;
                        ready_state.last_broadcast = Instant::now();
                    }

                    let ready_count = self.ready_count(&ready_state, &mesh_state);
                    let total = self.contract.new_participants.len();
                    let threshold = self.contract.threshold;

                    if total >= threshold && ready_count == total {
                        match self.begin_running_phase() {
                            Ok(running_state) => {
                                tracing::info!(
                                    "resharing: all participants ready, starting protocol"
                                );
                                self.phase = ResharingPhase::Running(running_state);
                                continue;
                            }
                            Err(err) => {
                                tracing::error!(
                                    ?err,
                                    "resharing: failed to initialize protocol from readiness"
                                );
                                ready_state = self.initial_ready_state();
                            }
                        }
                    } else {
                        tracing::debug!(
                            ready = ready_count,
                            total,
                            "resharing: waiting for participants to announce readiness"
                        );
                    }

                    self.phase = ResharingPhase::AwaitingReady(ready_state);
                    return NodeState::Resharing(self);
                }
                ResharingPhase::Running(mut running_state) => {
                    if let Some(sk_share) = running_state.failed_store.take() {
                        match self.try_finalize(ctx, &mut running_state, sk_share).await {
                            Ok(next_state) => return next_state,
                            Err(()) => {
                                self.phase = ResharingPhase::Running(running_state);
                                return NodeState::Resharing(self);
                            }
                        }
                    }

                    if running_state.last_activity.elapsed() > RESHARING_RUNNING_TIMEOUT {
                        tracing::warn!(
                            elapsed = ?running_state.last_activity.elapsed(),
                            "resharing: protocol timed out, restarting readiness phase",
                        );
                        self.phase = ResharingPhase::AwaitingReady(self.initial_ready_state());
                        return NodeState::Resharing(self);
                    }

                    loop {
                        let action = match running_state.protocol.poke() {
                            Ok(action) => action,
                            Err(err) => {
                                tracing::warn!(?err, "resharing failed: refreshing...");
                                if let Err(refresh_err) = running_state.protocol.refresh().await {
                                    tracing::warn!(
                                        ?refresh_err,
                                        "unable to refresh reshare protocol"
                                    );
                                }
                                self.phase = ResharingPhase::Running(running_state);
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
                                            tracing::warn!(
                                                "resharing: unexpected channel closure, stopping"
                                            );
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

                                    counts.entry(msg.from).and_modify(|c| *c += 1).or_insert(1);
                                    running_state.protocol.message(msg.from, msg.data);
                                }
                                if !counts.is_empty() {
                                    running_state.last_activity = Instant::now();
                                    tracing::info!(?counts, "resharing: handling new messages");
                                }
                                self.phase = ResharingPhase::Running(running_state);
                                return NodeState::Resharing(self);
                            }
                            Action::SendMany(data) => {
                                tracing::debug!("resharing: sending a message to all participants");
                                running_state.last_activity = Instant::now();
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
                                                data: data.clone(),
                                            },
                                        )
                                        .await;
                                }
                            }
                            Action::SendPrivate(to, data) => {
                                tracing::debug!("resharing: sending a private message to {to:?}");
                                if self.contract.new_participants.get(&to).is_none() {
                                    tracing::error!(
                                        "resharing: send_private unknown participant {to:?}"
                                    );
                                } else {
                                    running_state.last_activity = Instant::now();
                                    ctx.msg_channel
                                        .send(
                                            self.me,
                                            to,
                                            ResharingMessage {
                                                epoch: self.contract.old_epoch,
                                                from: self.me,
                                                data,
                                            },
                                        )
                                        .await;
                                }
                            }
                            Action::Return(private_share) => {
                                tracing::info!("resharing: successfully completed key reshare");
                                running_state.last_activity = Instant::now();
                                match self
                                    .try_finalize(ctx, &mut running_state, private_share)
                                    .await
                                {
                                    Ok(next_state) => return next_state,
                                    Err(()) => {
                                        self.phase = ResharingPhase::Running(running_state);
                                        return NodeState::Resharing(self);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl ResharingState {
    fn initial_ready_state(&self) -> ResharingReadyState {
        ResharingReadyState {
            ready: std::iter::once(self.me).collect(),
            last_broadcast: Instant::now() - RESHARING_READY_BROADCAST_INTERVAL,
        }
    }

    fn ready_count(&self, ready_state: &ResharingReadyState, _mesh_state: &MeshState) -> usize {
        ready_state
            .ready
            .iter()
            .filter(|participant| self.contract.new_participants.contains_key(participant))
            .count()
    }

    fn drain_ready_messages(
        &self,
        ctx: &mut MpcSignProtocol,
        ready_state: &mut ResharingReadyState,
    ) -> bool {
        let mut updated = false;
        loop {
            match ctx.resharing_ready.try_recv() {
                Ok(ResharingReadyMessage { epoch, from }) => {
                    if epoch != self.contract.old_epoch {
                        continue;
                    }
                    if self.contract.new_participants.contains_key(&from)
                        && ready_state.ready.insert(from)
                    {
                        updated = true;
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

    async fn broadcast_ready(&self, ctx: &mut MpcSignProtocol) {
        for participant in self.contract.new_participants.keys() {
            if participant == &self.me {
                continue;
            }
            ctx.msg_channel
                .send(
                    self.me,
                    *participant,
                    ResharingReadyMessage {
                        epoch: self.contract.old_epoch,
                        from: self.me,
                    },
                )
                .await;
        }
    }

    fn begin_running_phase(&mut self) -> Result<ResharingRunningState, InitializationError> {
        let protocol = ReshareProtocol::new(self.local_private_share, self.me, &self.contract)?;
        let now = Instant::now();
        Ok(ResharingRunningState {
            protocol,
            failed_store: None,
            started_at: now,
            last_activity: now,
        })
    }

    async fn try_finalize(
        &mut self,
        ctx: &mut MpcSignProtocol,
        running_state: &mut ResharingRunningState,
        private_share: SecretKeyShare,
    ) -> Result<NodeState, ()> {
        if let Err(err) = ctx
            .secret_storage
            .store(&PersistentNodeData {
                epoch: self.contract.old_epoch + 1,
                private_share,
                public_key: self.contract.public_key,
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
            epoch: self.contract.old_epoch + 1,
            participants: self.contract.new_participants.clone(),
            threshold: self.contract.threshold,
            private_share,
            public_key: self.contract.public_key,
        }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::contract::ResharingContractState;
    use crate::protocol::MeshState;
    use crate::util::NearPublicKeyExt;
    use cait_sith::protocol::Participant;
    use near_crypto::SecretKey;
    use std::collections::{BTreeSet, HashSet};
    use std::time::Instant;

    fn sample_contract() -> (ResharingState, Participant, Participant) {
        let me = Participant::from(0);
        let other = Participant::from(1);

        let mut old_participants = Participants::default();
        old_participants.insert(&me, ParticipantInfo::new(0));
        old_participants.insert(&other, ParticipantInfo::new(1));
        let new_participants = old_participants.clone();

        let public_key = SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "reshare-test")
            .public_key()
            .into_affine_point();

        let contract = ResharingContractState {
            old_epoch: 3,
            old_participants,
            new_participants,
            threshold: 2,
            public_key,
            finished_votes: HashSet::new(),
        };

        let state = ResharingState {
            me,
            contract,
            local_private_share: None,
            phase: ResharingPhase::AwaitingReady(ResharingReadyState {
                ready: BTreeSet::new(),
                last_broadcast: Instant::now(),
            }),
        };

        (state, me, other)
    }

    #[test]
    fn initial_ready_state_marks_self() {
        let (state, me, _) = sample_contract();
        let ready = state.initial_ready_state();
        assert!(ready.ready.contains(&me));
        let elapsed = Instant::now().duration_since(ready.last_broadcast);
        assert!(elapsed >= RESHARING_READY_BROADCAST_INTERVAL);
    }

    #[test]
    fn ready_count_respects_mesh_state() {
        let (state, me, other) = sample_contract();
        let mut ready = state.initial_ready_state();
        ready.ready.insert(other);

        let mut mesh_state = MeshState::default();
        mesh_state.stable.insert(me);
        assert_eq!(state.ready_count(&ready, &mesh_state), 1);

        mesh_state.stable.insert(other);
        assert_eq!(state.ready_count(&ready, &mesh_state), 2);
    }
}
