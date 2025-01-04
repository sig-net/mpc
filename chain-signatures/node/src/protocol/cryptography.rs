use std::sync::PoisonError;

use super::signature::SignatureManager;
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use crate::config::Config;
use crate::gcp::error::SecretStorageError;
use crate::http_client::SendError;
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
use crate::protocol::presignature::PresignatureManager;
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MeshState;
use crate::protocol::MpcMessage;
use crate::storage::secret_storage::SecretNodeStorageBox;
use async_trait::async_trait;
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;

#[async_trait::async_trait]
pub trait CryptographicCtx {
    async fn me(&self) -> Participant;
    fn http_client(&self) -> &reqwest::Client;
    fn rpc_client(&self) -> &near_fetch::Client;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox;
    fn my_account_id(&self) -> &AccountId;
}

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("failed to send a message: {0}")]
    SendError(#[from] SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error("rpc error: {0}")]
    RpcError(#[from] near_fetch::Error),
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("more than one writing to state: {0}")]
    InvalidStateHandle(String),
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

impl<T> From<PoisonError<T>> for CryptographicError {
    fn from(_: PoisonError<T>) -> Self {
        let typename = std::any::type_name::<T>();
        Self::SyncError(format!("PoisonError: {typename}"))
    }
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
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        tracing::info!(active = ?mesh_state.active_participants.keys_vec(), "generating: progressing key generation");
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
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &cfg.local.network.sign_sk,
                            ctx.http_client(),
                            &mesh_state.active_participants,
                            &cfg.protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?mesh_state.active_participants.keys_vec(),
                            "generating(wait): failed to send encrypted message; {failures:?}"
                        );
                    }

                    return Ok(NodeState::Generating(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("generating: sending a message to many participants");
                    let mut messages = self.messages.write().await;
                    for (p, info) in mesh_state.active_participants.iter() {
                        if p == &ctx.me().await {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        messages.push(
                            Participant::from(info.id),
                            MpcMessage::Generating(GeneratingMessage {
                                from: ctx.me().await,
                                data: data.clone(),
                            }),
                        );
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("generating: sending a private message to {to:?}");
                    self.messages.write().await.push(
                        to,
                        MpcMessage::Generating(GeneratingMessage {
                            from: ctx.me().await,
                            data,
                        }),
                    );
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "generating: successfully completed key generation"
                    );
                    ctx.secret_storage()
                        .store(&PersistentNodeData {
                            epoch: 0,
                            private_share: r.private_share,
                            public_key: r.public_key,
                        })
                        .await?;
                    // Send any leftover messages
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &cfg.local.network.sign_sk,
                            ctx.http_client(),
                            &mesh_state.active_participants,
                            &cfg.protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?mesh_state.active_participants.keys_vec(),
                            "generating(return): failed to send encrypted message; {failures:?}"
                        );
                    }
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: 0,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: r.private_share,
                        public_key: r.public_key,
                        messages: self.messages,
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
        ctx: C,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        let failures = self
            .messages
            .write()
            .await
            .send_encrypted(
                ctx.me().await,
                &cfg.local.network.sign_sk,
                ctx.http_client(),
                &mesh_state.active_participants,
                &cfg.protocol,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?mesh_state.active_participants.keys_vec(),
                "waitingForConsensus: failed to send encrypted message; {failures:?}"
            );
        }

        // Wait for ConsensusProtocol step to advance state
        Ok(NodeState::WaitingForConsensus(self))
    }
}

#[async_trait]
impl CryptographicProtocol for ResharingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        mut ctx: C,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<NodeState, CryptographicError> {
        // TODO: we are not using active potential participants here, but we should in the future.
        // Currently resharing protocol does not timeout and restart with new set of participants.
        // So if it picks up a participant that is not active, it will never be able to send a message to it.
        let active = mesh_state
            .active_participants
            .and(&mesh_state.potential_participants);
        tracing::info!(active = ?active.keys().collect::<Vec<_>>(), "progressing key reshare");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    tracing::debug!("got action fail, {}", err);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh reshare protocol");
                    }
                    return Err(err)?;
                }
            };
            tracing::debug!("got action ok");
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("resharing: waiting");
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &cfg.local.network.sign_sk,
                            ctx.http_client(),
                            &active,
                            &cfg.protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(wait): failed to send encrypted message; {failures:?}",
                        );
                    }

                    return Ok(NodeState::Resharing(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    let me = ctx.me().await;
                    let mut messages = self.messages.write().await;
                    for (p, _info) in self.new_participants.iter() {
                        if p == &me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        messages.push(
                            *p,
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: me,
                                data: data.clone(),
                            }),
                        )
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("resharing: sending a private message to {to:?}");
                    match self.new_participants.get(&to) {
                        Some(_) => self.messages.write().await.push(
                            to,
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: ctx.me().await,
                                data,
                            }),
                        ),
                        None => return Err(CryptographicError::UnknownParticipant(to)),
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("resharing: successfully completed key reshare");
                    ctx.secret_storage()
                        .store(&PersistentNodeData {
                            epoch: self.old_epoch + 1,
                            private_share,
                            public_key: self.public_key,
                        })
                        .await?;

                    // Send any leftover messages.
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &cfg.local.network.sign_sk,
                            ctx.http_client(),
                            &active,
                            &cfg.protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(return): failed to send encrypted message; {failures:?}",
                        );
                    }

                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: self.old_epoch + 1,
                        participants: self.new_participants,
                        threshold: self.threshold,
                        private_share,
                        public_key: self.public_key,
                        messages: self.messages,
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
        let active = mesh_state.active_participants;
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
                .execute(&active, &cfg.protocol, self.messages.clone());

        let presig_task = PresignatureManager::execute(&self, &active, &cfg.protocol);

        let me = ctx.me().await;
        let stable = mesh_state.stable_participants;
        tracing::debug!(?stable, "stable participants");
        let sig_task = SignatureManager::execute(&self, &stable, me, &cfg.protocol, &ctx);

        match tokio::try_join!(triple_task, presig_task, sig_task) {
            Ok(_result) => (),
            Err(err) => {
                tracing::warn!(?err, "running: failed to progress cryptographic protocol");
            }
        }

        let mut messages = self.messages.write().await;
        crate::metrics::MESSAGE_QUEUE_SIZE
            .with_label_values(&[ctx.my_account_id().as_str()])
            .set(messages.len() as i64);

        let failures = messages
            .send_encrypted(
                me,
                &cfg.local.network.sign_sk,
                ctx.http_client(),
                &active,
                &cfg.protocol,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?active.keys_vec(),
                "running: failed to send encrypted message; {failures:?}"
            );
        }
        drop(messages);

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
