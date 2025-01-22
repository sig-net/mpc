use super::message::MessageChannel;
use super::signature::SignatureManager;
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use crate::config::Config;
use crate::gcp::error::SecretStorageError;
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
use crate::protocol::presignature::PresignatureManager;
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MeshState;
use crate::storage::secret_storage::SecretNodeStorageBox;

use async_trait::async_trait;
use cait_sith::protocol::{Action, InitializationError, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use web3::Web3;

pub trait CryptographicCtx {
    fn rpc_client(&self) -> &near_fetch::Client;
    fn eth_client(&self) -> &Web3<web3::transports::Http>;
    fn eth_contract_address(&self) -> String;
    fn eth_account_sk(&self) -> String;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox;
    fn my_account_id(&self) -> &AccountId;
    fn channel(&self) -> &MessageChannel;
}

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

#[async_trait]
pub trait CryptographicProtocol {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        self,
        ctx: C,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError>;
}

#[async_trait]
impl CryptographicProtocol for GeneratingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        mut ctx: C,
        _cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        tracing::info!(active = ?mesh_state.active.keys_vec(), "generating: progressing key generation");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh keygen protocol");
                    }
                    return Err(err)?;
                }
            };
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("generating: waiting");
                    return Ok(NodeState::Generating(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("generating: sending a message to many participants");
                    for p in mesh_state.active.keys() {
                        if p == &self.me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        ctx.channel()
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
                    ctx.channel()
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
                    // TODO: handle secret storage error
                    ctx.secret_storage()
                        .store(&PersistentNodeData {
                            epoch: 0,
                            private_share: r.private_share,
                            public_key: r.public_key,
                        })
                        .await?;

                    tracing::info!(
                        epoch = 0,
                        "generating(return): creating new WaitingForConsensusState"
                    );
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: 0,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: r.private_share,
                        public_key: r.public_key,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl CryptographicProtocol for WaitingForConsensusState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        _ctx: C,
        _cfg: Config,
        _mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        // Wait for ConsensusProtocol step to advance state
        Ok(NodeState::WaitingForConsensus(self))
    }
}

#[async_trait]
impl CryptographicProtocol for ResharingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        mut ctx: C,
        _cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        // TODO: we are not using active potential participants here, but we should in the future.
        // Currently resharing protocol does not timeout and restart with new set of participants.
        // So if it picks up a participant that is not active, it will never be able to send a message to it.
        let active = mesh_state.active.and(&mesh_state.active_potential);
        tracing::info!(active = ?active.keys_vec(), "progressing key reshare");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    tracing::error!(?err, "reshare failed");
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh reshare protocol");
                    }
                    return Ok(NodeState::Resharing(self));
                }
            };
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("resharing: waiting");
                    return Ok(NodeState::Resharing(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    for p in self.new_participants.keys() {
                        if p == &self.me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        ctx.channel()
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
                        ctx.channel()
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
                    tracing::debug!("resharing: successfully completed key reshare");

                    // TODO: make sure to handle secret storage error and try again later.
                    ctx.secret_storage()
                        .store(&PersistentNodeData {
                            epoch: self.old_epoch + 1,
                            private_share,
                            public_key: self.public_key,
                        })
                        .await?;

                    tracing::info!(
                        epoch = self.old_epoch + 1,
                        "resharing(return): creating new WaitingForConsensusState"
                    );
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: self.old_epoch + 1,
                        participants: self.new_participants,
                        threshold: self.threshold,
                        private_share,
                        public_key: self.public_key,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl CryptographicProtocol for RunningState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        ctx: C,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        let active = mesh_state.active;
        if active.len() < self.threshold {
            tracing::warn!(
                active = ?active.keys_vec(),
                "running: not enough participants to progress"
            );
            return Ok(NodeState::Running(self));
        }

        let triple_task =
            self.triple_manager
                .clone()
                .execute(&active, &cfg.protocol, ctx.channel());

        let presig_task =
            PresignatureManager::execute(&self, &active, &cfg.protocol, ctx.channel());

        let stable = mesh_state.stable;
        tracing::debug!(?stable, "stable participants");
        let sig_task = SignatureManager::execute(&self, &stable, &cfg.protocol, &ctx);

        match tokio::try_join!(triple_task, presig_task, sig_task) {
            Ok(_result) => (),
            Err(err) => {
                tracing::warn!(?err, "running: failed to progress cryptographic protocol");
            }
        }

        Ok(NodeState::Running(self))
    }
}

#[async_trait]
impl CryptographicProtocol for NodeState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        self,
        ctx: C,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        match self {
            NodeState::Generating(state) => state.progress(ctx, cfg, mesh_state).await,
            NodeState::Resharing(state) => state.progress(ctx, cfg, mesh_state).await,
            NodeState::Running(state) => state.progress(ctx, cfg, mesh_state).await,
            NodeState::WaitingForConsensus(state) => state.progress(ctx, cfg, mesh_state).await,
            _ => Ok(self),
        }
    }
}
