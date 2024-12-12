use std::sync::PoisonError;

use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use crate::config::Config;
use crate::gcp::error::SecretStorageError;
use crate::http_client::SendError;
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
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
                            info.clone(),
                            MpcMessage::Generating(GeneratingMessage {
                                from: ctx.me().await,
                                data: data.clone(),
                            }),
                        );
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("generating: sending a private message to {to:?}");
                    let info = self.fetch_participant(&to)?;
                    self.messages.write().await.push(
                        info.clone(),
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
                    for (p, info) in self.new_participants.iter() {
                        if p == &me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        messages.push(
                            info.clone(),
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
                        Some(info) => self.messages.write().await.push(
                            info.clone(),
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
        let active = mesh_state.active_participants.clone();
        if active.len() < self.threshold {
            tracing::warn!(
                active = ?active.keys_vec(),
                "running: not enough participants to progress"
            );
            return Ok(NodeState::Running(self));
        }

        let participant_map = active
            .iter()
            .map(|(p, info)| (p.clone(), info.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        let my_account_id = self.triple_manager.my_account_id.clone();
        let protocol_cfg = cfg.protocol.clone();
        let messages = self.messages.clone();
        let triple_par = participant_map.clone();
        let triple_manager = self.triple_manager.clone();
        let triple_task = tokio::task::spawn(async move {
            let participant_map = triple_par;
            let my_account_id = triple_manager.my_account_id.clone();
            // crate::metrics::MESSAGE_QUEUE_SIZE
            //     .with_label_values(&[my_account_id.as_str()])
            //     .set(messages.len() as i64);
            if let Err(err) = triple_manager.stockpile(&active, &protocol_cfg).await {
                tracing::warn!(?err, "running: failed to stockpile triples");
            }
            let mut messages = messages.write().await;
            for (p, msg) in triple_manager.poke(&protocol_cfg).await {
                messages.push(
                    participant_map.get(&p).unwrap().clone(),
                    MpcMessage::Triple(msg),
                );
            }
            drop(messages);

            crate::metrics::NUM_TRIPLES_MINE
                .with_label_values(&[my_account_id.as_str()])
                .set(triple_manager.len_mine().await as i64);
            crate::metrics::NUM_TRIPLES_TOTAL
                .with_label_values(&[my_account_id.as_str()])
                .set(triple_manager.len_generated().await as i64);
            // crate::metrics::NUM_TRIPLE_GENERATORS_INTRODUCED
            //     .with_label_values(&[my_account_id.as_str()])
            //     .set(triple_manager.introduced.len() as i64);
            // crate::metrics::NUM_TRIPLE_GENERATORS_TOTAL
            //     .with_label_values(&[my_account_id.as_str()])
            //     .set(triple_manager.ongoing.len() as i64);
        });

        let messages = self.messages.clone();
        let triple_manager = self.triple_manager.clone();
        let presignature_manager = self.presignature_manager.clone();
        let presig_par = participant_map.clone();
        let active = mesh_state.active_participants.clone();
        let protocol_cfg = cfg.protocol.clone();
        let presig_task = tokio::task::spawn(async move {
            let participant_map = presig_par;
            let mut presignature_manager = presignature_manager.write().await;
            if let Err(err) = presignature_manager
                .stockpile(
                    &active,
                    &self.public_key,
                    &self.private_share,
                    &triple_manager,
                    &protocol_cfg,
                )
                .await
            {
                tracing::warn!(?err, "running: failed to stockpile presignatures");
            }
            let my_account_id = triple_manager.my_account_id.clone();
            drop(triple_manager);

            let mut messages = messages.write().await;
            for (p, msg) in presignature_manager.poke().await {
                messages.push(
                    participant_map.get(&p).unwrap().clone(),
                    MpcMessage::Presignature(msg),
                );
            }
            drop(messages);

            crate::metrics::NUM_PRESIGNATURES_MINE
                .with_label_values(&[my_account_id.as_str()])
                .set(presignature_manager.len_mine().await as i64);
            crate::metrics::NUM_PRESIGNATURES_TOTAL
                .with_label_values(&[my_account_id.as_str()])
                .set(presignature_manager.len_generated().await as i64);
            crate::metrics::NUM_PRESIGNATURE_GENERATORS_TOTAL
                .with_label_values(&[my_account_id.as_str()])
                .set(
                    presignature_manager.len_potential().await as i64
                        - presignature_manager.len_generated().await as i64,
                );
        });

        // NOTE: signatures should only use stable and not active participants. The difference here is that
        // stable participants utilizes more than the online status of a node, such as whether or not their
        // block height is up to date, such that they too can process signature requests. If they cannot
        // then they are considered unstable and should not be a part of signature generation this round.
        let stable = mesh_state.stable_participants.clone();
        tracing::debug!(?stable, "stable participants");

        // let mut sign_queue = self.sign_queue.write().await;
        // crate::metrics::SIGN_QUEUE_SIZE
        //     .with_label_values(&[my_account_id.as_str()])
        //     .set(sign_queue.len() as i64);
        let me = ctx.me().await;
        let sig_task = tokio::task::spawn({
            let presignature_manager = self.presignature_manager.clone();
            let signature_manager = self.signature_manager.clone();
            let messages = self.messages.clone();
            let protocol_cfg = cfg.protocol.clone();
            let sign_queue = self.sign_queue.clone();
            let rpc_client = ctx.rpc_client().clone();
            let signer = ctx.signer().clone();
            let mpc_contract_id = ctx.mpc_contract_id().clone();
            let participant_map = participant_map.clone();

            tokio::task::unconstrained(async move {
                tracing::debug!(?stable, "stable participants");

                let mut sign_queue = sign_queue.write().await;
                // crate::metrics::SIGN_QUEUE_SIZE
                //     .with_label_values(&[my_account_id.as_str()])
                //     .set(sign_queue.len() as i64);
                sign_queue.organize(self.threshold, &stable, me, &my_account_id);

                let my_requests = sign_queue.my_requests(me);
                // crate::metrics::SIGN_QUEUE_MINE_SIZE
                //     .with_label_values(&[my_account_id.as_str()])
                //     .set(my_requests.len() as i64);

                let mut presignature_manager = presignature_manager.write().await;
                let mut signature_manager = signature_manager.write().await;
                signature_manager
                    .handle_requests(
                        self.threshold,
                        &stable,
                        my_requests,
                        &mut presignature_manager,
                        &protocol_cfg,
                    )
                    .await;
                drop(presignature_manager);

                let mut messages = messages.write().await;
                for (p, msg) in signature_manager.poke() {
                    messages.push(
                        participant_map.get(&p).unwrap().clone(),
                        MpcMessage::Signature(msg),
                    );
                }
                drop(messages);
                signature_manager
                    .publish(&rpc_client, &signer, &mpc_contract_id)
                    .await;
            })
        });

        match tokio::try_join!(triple_task, presig_task, sig_task) {
            Ok(_result) => (),
            Err(err) => {
                tracing::warn!(?err, "running: failed to progress cryptographic protocol");
            }
        }

        let mut messages = self.messages.write().await;
        let failures = messages
            .send_encrypted(
                me,
                &cfg.local.network.sign_sk,
                ctx.http_client(),
                &mesh_state.active_participants,
                &cfg.protocol,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?mesh_state.active_participants.keys_vec(),
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
