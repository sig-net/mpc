use super::signature::SignatureManager;
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::MpcSignProtocol;
use crate::config::Config;
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
use crate::protocol::presignature::PresignatureManager;
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MeshState;
use crate::types::SecretKeyShare;

use cait_sith::protocol::{Action, InitializationError, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use mpc_crypto::PublicKey;

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
}

pub(crate) trait CryptographicProtocol {
    async fn progress(
        self,
        ctx: &mut MpcSignProtocol,
        cfg: Config,
        mesh_state: MeshState,
    ) -> NodeState;
}

impl CryptographicProtocol for GeneratingState {
    async fn progress(
        mut self,
        ctx: &mut MpcSignProtocol,
        _cfg: Config,
        mesh_state: MeshState,
    ) -> NodeState {
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
    async fn progress(
        self,
        _ctx: &mut MpcSignProtocol,
        _cfg: Config,
        _mesh_state: MeshState,
    ) -> NodeState {
        // Wait for ConsensusProtocol step to advance state
        NodeState::WaitingForConsensus(self)
    }
}

impl CryptographicProtocol for ResharingState {
    async fn progress(
        mut self,
        ctx: &mut MpcSignProtocol,
        _cfg: Config,
        mesh_state: MeshState,
    ) -> NodeState {
        // Previous save to secret storage failed, try again until successful.
        if let Some(sk_share) = self.failed_store.take() {
            return self.finalize(sk_share, ctx).await;
        }

        tracing::info!(active = ?mesh_state.active.keys_vec(), "progressing key reshare");
        loop {
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    tracing::warn!(?err, "resharing failed: refreshing...");
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh reshare protocol");
                    }
                    return NodeState::Resharing(self);
                }
            };
            match action {
                Action::Wait => {
                    tracing::debug!("resharing: waiting");
                    return NodeState::Resharing(self);
                }
                Action::SendMany(data) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    for p in self.new_participants.keys() {
                        if p == &self.me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        ctx.msg_channel
                            .send(
                                self.me,
                                *p,
                                ResharingMessage {
                                    epoch: self.old_epoch,
                                    from: self.me,
                                    data: data.clone(),
                                },
                            )
                            .await;
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("resharing: sending a private message to {to:?}");
                    if self.new_participants.get(&to).is_none() {
                        tracing::error!("resharing: send_private unknown participant {to:?}");
                    } else {
                        ctx.msg_channel
                            .send(
                                self.me,
                                to,
                                ResharingMessage {
                                    epoch: self.old_epoch,
                                    from: self.me,
                                    data,
                                },
                            )
                            .await;
                    }
                }
                Action::Return(private_share) => {
                    tracing::info!("resharing: successfully completed key reshare");
                    return self.finalize(private_share, ctx).await;
                }
            }
        }
    }
}

impl ResharingState {
    async fn finalize(
        mut self,
        private_share: SecretKeyShare,
        ctx: &mut MpcSignProtocol,
    ) -> NodeState {
        if let Err(err) = ctx
            .secret_storage
            .store(&PersistentNodeData {
                epoch: self.old_epoch + 1,
                private_share,
                public_key: self.public_key,
            })
            .await
        {
            tracing::error!(?err, "resharing: failed to store secret");
            self.failed_store.replace(private_share);
            return NodeState::Resharing(self);
        }

        // Clear triples from storage before starting the new epoch. This is necessary if the node has accumulated
        // triples from previous epochs. If it was not able to clear the previous triples, we'll leave them as-is
        if !ctx.triple_storage.clear().await {
            tracing::error!("failed to clear triples from storage on new epoch start");
        }

        if !ctx.presignature_storage.clear().await {
            tracing::error!("failed to clear presignatures from storage on new epoch start");
        }

        NodeState::WaitingForConsensus(WaitingForConsensusState {
            epoch: self.old_epoch + 1,
            participants: self.new_participants,
            threshold: self.threshold,
            private_share,
            public_key: self.public_key,
        })
    }
}

impl CryptographicProtocol for RunningState {
    async fn progress(
        self,
        ctx: &mut MpcSignProtocol,
        cfg: Config,
        mesh_state: MeshState,
    ) -> NodeState {
        let active = mesh_state.active.keys_vec();
        if active.len() < self.threshold {
            tracing::warn!(?active, "running: not enough participants to progress");
            return NodeState::Running(self);
        }

        let presig_task = PresignatureManager::execute(&self, &cfg.protocol, active);

        let stable = mesh_state.stable;
        tracing::debug!(?stable, "stable participants");
        let sig_task = SignatureManager::execute(&self, &stable, &cfg.protocol, ctx);

        match tokio::try_join!(presig_task, sig_task) {
            Ok(_result) => (),
            Err(err) => {
                tracing::warn!(?err, "running: failed to progress cryptographic protocol");
            }
        }

        NodeState::Running(self)
    }
}

impl CryptographicProtocol for NodeState {
    async fn progress(
        self,
        ctx: &mut MpcSignProtocol,
        cfg: Config,
        mesh_state: MeshState,
    ) -> NodeState {
        match self {
            NodeState::Generating(state) => state.progress(ctx, cfg, mesh_state).await,
            NodeState::Resharing(state) => state.progress(ctx, cfg, mesh_state).await,
            NodeState::Running(state) => state.progress(ctx, cfg, mesh_state).await,
            NodeState::WaitingForConsensus(state) => state.progress(ctx, cfg, mesh_state).await,
            _ => self,
        }
    }
}
