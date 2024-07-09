pub mod contract;
mod cryptography;
pub mod presignature;
mod signature;
pub mod triple;

pub mod consensus;
pub mod message;
pub mod state;

pub use consensus::ConsensusError;
pub use contract::primitives::ParticipantInfo;
pub use contract::ProtocolState;
pub use cryptography::CryptographicError;
pub use message::MpcMessage;
pub use signature::SignQueue;
pub use signature::SignRequest;
pub use state::NodeState;

use self::consensus::ConsensusCtx;
use self::cryptography::CryptographicCtx;
use self::message::MessageCtx;
use self::presignature::PresignatureConfig;
use self::triple::TripleConfig;
use crate::mesh::{Mesh, NetworkConfig};
use crate::protocol::consensus::ConsensusProtocol;
use crate::protocol::cryptography::CryptographicProtocol;
use crate::protocol::message::{MessageHandler, MpcMessageQueue};
use crate::rpc_client;
use crate::storage::secret_storage::SecretNodeStorageBox;
use crate::storage::triple_storage::LockTripleNodeStorageBox;

use cait_sith::protocol::Participant;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use reqwest::IntoUrl;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio::sync::RwLock;
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    pub triple_cfg: TripleConfig,
    pub presig_cfg: PresignatureConfig,
    pub network_cfg: NetworkConfig,
}

struct Ctx {
    my_address: Url,
    account_id: AccountId,
    mpc_contract_id: AccountId,
    signer: InMemorySigner,
    rpc_client: near_fetch::Client,
    http_client: reqwest::Client,
    sign_queue: Arc<RwLock<SignQueue>>,
    secret_storage: SecretNodeStorageBox,
    triple_storage: LockTripleNodeStorageBox,
    cfg: Config,
    mesh: Mesh,
}

impl ConsensusCtx for &mut MpcSignProtocol {
    fn my_account_id(&self) -> &AccountId {
        &self.ctx.account_id
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.ctx.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.ctx.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.ctx.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn my_address(&self) -> &Url {
        &self.ctx.my_address
    }

    fn sign_queue(&self) -> Arc<RwLock<SignQueue>> {
        self.ctx.sign_queue.clone()
    }

    fn secret_storage(&self) -> &SecretNodeStorageBox {
        &self.ctx.secret_storage
    }

    fn cfg(&self) -> &Config {
        &self.ctx.cfg
    }

    fn triple_storage(&self) -> LockTripleNodeStorageBox {
        self.ctx.triple_storage.clone()
    }
}

#[async_trait::async_trait]
impl CryptographicCtx for &mut MpcSignProtocol {
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.ctx.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.ctx.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.ctx.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox {
        &mut self.ctx.secret_storage
    }

    fn cfg(&self) -> &Config {
        &self.ctx.cfg
    }

    fn mesh(&self) -> &Mesh {
        &self.ctx.mesh
    }
}

#[async_trait::async_trait]
impl MessageCtx for &MpcSignProtocol {
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn mesh(&self) -> &Mesh {
        &self.ctx.mesh
    }
}

pub struct MpcSignProtocol {
    ctx: Ctx,
    receiver: mpsc::Receiver<MpcMessage>,
    state: Arc<RwLock<NodeState>>,
}

impl MpcSignProtocol {
    #![allow(clippy::too_many_arguments)]
    pub fn init<U: IntoUrl>(
        my_address: U,
        mpc_contract_id: AccountId,
        account_id: AccountId,
        rpc_client: near_fetch::Client,
        signer: InMemorySigner,
        receiver: mpsc::Receiver<MpcMessage>,
        sign_queue: Arc<RwLock<SignQueue>>,
        secret_storage: SecretNodeStorageBox,
        triple_storage: LockTripleNodeStorageBox,
        cfg: Config,
    ) -> (Self, Arc<RwLock<NodeState>>) {
        let state = Arc::new(RwLock::new(NodeState::Starting));
        let ctx = Ctx {
            my_address: my_address.into_url().unwrap(),
            account_id,
            mpc_contract_id,
            rpc_client,
            http_client: reqwest::Client::new(),
            sign_queue,
            signer,
            secret_storage,
            triple_storage,
            cfg,
            mesh: Mesh::default(),
        };
        let protocol = MpcSignProtocol {
            ctx,
            receiver,
            state: state.clone(),
        };
        (protocol, state)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let my_account_id = self.ctx.account_id.to_string();
        let _span = tracing::info_span!("running", my_account_id);
        crate::metrics::NODE_RUNNING
            .with_label_values(&[my_account_id.as_str()])
            .set(1);
        crate::metrics::NODE_VERSION
            .with_label_values(&[my_account_id.as_str()])
            .set(node_version());
        let mut queue = MpcMessageQueue::default();
        let mut last_state_update = Instant::now();
        let mut last_pinged = Instant::now();
        loop {
            let protocol_time = Instant::now();
            tracing::debug!("trying to advance mpc recovery protocol");
            loop {
                let msg_result = self.receiver.try_recv();
                match msg_result {
                    Ok(msg) => {
                        tracing::debug!("received a new message");
                        queue.push(msg);
                    }
                    Err(TryRecvError::Empty) => {
                        tracing::debug!("no new messages received");
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        tracing::debug!("communication was disconnected, no more messages will be received, spinning down");
                        return Ok(());
                    }
                }
            }

            let contract_state = if last_state_update.elapsed() > Duration::from_secs(1) {
                let contract_state = match rpc_client::fetch_mpc_contract_state(
                    &self.ctx.rpc_client,
                    &self.ctx.mpc_contract_id,
                )
                .await
                {
                    Ok(contract_state) => contract_state,
                    Err(e) => {
                        tracing::error!("could not fetch contract's state: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                tracing::debug!(?contract_state);

                // Establish the participants for this current iteration of the protocol loop. This will
                // set which participants are currently active in the protocol and determines who will be
                // receiving messages.
                self.ctx.mesh.establish_participants(&contract_state).await;

                last_state_update = Instant::now();
                Some(contract_state)
            } else {
                None
            };

            if last_pinged.elapsed() > Duration::from_millis(300) {
                self.ctx.mesh.ping().await;
                last_pinged = Instant::now();
            }

            let state = {
                let guard = self.state.read().await;
                guard.clone()
            };

            let crypto_time = Instant::now();
            let mut state = match state.progress(&mut self).await {
                Ok(state) => state,
                Err(err) => {
                    tracing::info!("protocol unable to progress: {err:?}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            crate::metrics::PROTOCOL_LATENCY_ITER_CRYPTO
                .with_label_values(&[my_account_id.as_str()])
                .observe(crypto_time.elapsed().as_secs_f64());

            let consensus_time = Instant::now();
            if let Some(contract_state) = contract_state {
                state = match state.advance(&mut self, contract_state).await {
                    Ok(state) => state,
                    Err(err) => {
                        tracing::info!("protocol unable to advance: {err:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
            }
            crate::metrics::PROTOCOL_LATENCY_ITER_CONSENSUS
                .with_label_values(&[my_account_id.as_str()])
                .observe(consensus_time.elapsed().as_secs_f64());

            let message_time = Instant::now();
            if let Err(err) = state.handle(&self, &mut queue).await {
                tracing::info!("protocol unable to handle messages: {err:?}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            crate::metrics::PROTOCOL_LATENCY_ITER_MESSAGE
                .with_label_values(&[my_account_id.as_str()])
                .observe(message_time.elapsed().as_secs_f64());

            let sleep_ms = match state {
                NodeState::Generating(_) => 500,
                NodeState::Resharing(_) => 500,
                NodeState::Running(_) => 100,

                NodeState::Starting => 1000,
                NodeState::Started(_) => 1000,
                NodeState::WaitingForConsensus(_) => 1000,
                NodeState::Joining(_) => 1000,
            };

            let mut guard = self.state.write().await;
            *guard = state;
            drop(guard);

            crate::metrics::PROTOCOL_LATENCY_ITER_TOTAL
                .with_label_values(&[my_account_id.as_str()])
                .observe(protocol_time.elapsed().as_secs_f64());
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    }
}

async fn get_my_participant(protocol: &MpcSignProtocol) -> Participant {
    let my_near_acc_id = &protocol.ctx.account_id;
    let state = protocol.state.read().await;
    let participant_info = state
        .find_participant_info(my_near_acc_id)
        .unwrap_or_else(|| {
            tracing::error!("could not find participant info for {my_near_acc_id}");
            panic!("could not find participant info for {my_near_acc_id}");
        });
    participant_info.id.into()
}

fn node_version() -> i64 {
    env!("CARGO_PKG_VERSION")
        .split('.')
        .map(|s| s.parse::<i64>().unwrap())
        .fold(0, |acc, x| acc * 1000 + x)
}
