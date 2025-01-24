mod cryptography;

pub mod consensus;
pub mod contract;
pub mod message;
pub mod presignature;
pub mod signature;
pub mod state;
pub mod triple;

pub use consensus::ConsensusError;
pub use contract::primitives::ParticipantInfo;
pub use contract::ProtocolState;
pub use cryptography::CryptographicError;
pub use message::{Message, MessageChannel};
pub use signature::{SignQueue, SignRequest};
pub use state::NodeState;
pub use sysinfo::{Components, CpuRefreshKind, Disks, RefreshKind, System};

use self::consensus::ConsensusCtx;
use self::cryptography::CryptographicCtx;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::consensus::ConsensusProtocol;
use crate::protocol::cryptography::CryptographicProtocol;
use crate::protocol::message::MessageReceiver as _;
use crate::rpc::{NearClient, RpcChannel};
use crate::storage::presignature_storage::PresignatureStorage;
use crate::storage::secret_storage::SecretNodeStorageBox;
use crate::storage::triple_storage::TripleStorage;

use near_account_id::AccountId;
use reqwest::IntoUrl;
use std::path::Path;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use url::Url;

struct Ctx {
    my_address: Url,
    account_id: AccountId,
    mpc_contract_id: AccountId,
    near: NearClient,
    rpc_channel: RpcChannel,
    sign_rx: Arc<RwLock<mpsc::Receiver<SignRequest>>>,
    secret_storage: SecretNodeStorageBox,
    triple_storage: TripleStorage,
    presignature_storage: PresignatureStorage,
}

impl ConsensusCtx for &mut MpcSignProtocol {
    fn my_account_id(&self) -> &AccountId {
        &self.ctx.account_id
    }

    fn near_client(&self) -> &NearClient {
        &self.ctx.near
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn my_address(&self) -> &Url {
        &self.ctx.my_address
    }

    fn sign_rx(&self) -> Arc<RwLock<mpsc::Receiver<SignRequest>>> {
        self.ctx.sign_rx.clone()
    }

    fn secret_storage(&self) -> &SecretNodeStorageBox {
        &self.ctx.secret_storage
    }

    fn triple_storage(&self) -> &TripleStorage {
        &self.ctx.triple_storage
    }

    fn presignature_storage(&self) -> &PresignatureStorage {
        &self.ctx.presignature_storage
    }
}

impl CryptographicCtx for &mut MpcSignProtocol {
    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn my_account_id(&self) -> &AccountId {
        &self.ctx.account_id
    }

    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox {
        &mut self.ctx.secret_storage
    }

    fn channel(&self) -> &MessageChannel {
        &self.channel
    }

    fn rpc_channel(&self) -> &crate::rpc::RpcChannel {
        &self.ctx.rpc_channel
    }
}

pub struct MpcSignProtocol {
    ctx: Ctx,
    channel: MessageChannel,
    state: Arc<RwLock<NodeState>>,
}

impl MpcSignProtocol {
    #![allow(clippy::too_many_arguments)]
    pub fn init<U: IntoUrl>(
        my_address: U,
        mpc_contract_id: AccountId,
        account_id: AccountId,
        state: Arc<RwLock<NodeState>>,
        near: NearClient,
        rpc_channel: RpcChannel,
        channel: MessageChannel,
        sign_rx: mpsc::Receiver<SignRequest>,
        secret_storage: SecretNodeStorageBox,
        triple_storage: TripleStorage,
        presignature_storage: PresignatureStorage,
    ) -> Self {
        let my_address = my_address.into_url().unwrap();
        let ctx = Ctx {
            my_address,
            account_id,
            mpc_contract_id,
            near,
            rpc_channel,
            sign_rx: Arc::new(RwLock::new(sign_rx)),
            secret_storage,
            triple_storage,
            presignature_storage,
        };
        MpcSignProtocol {
            ctx,
            channel,
            state,
        }
    }

    pub async fn run(
        mut self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        config: Arc<RwLock<Config>>,
        mesh_state: Arc<RwLock<MeshState>>,
    ) -> anyhow::Result<()> {
        let my_account_id = self.ctx.account_id.as_str();
        let _span = tracing::info_span!("running", my_account_id);
        let my_account_id = self.ctx.account_id.clone();

        crate::metrics::NODE_RUNNING
            .with_label_values(&[my_account_id.as_str()])
            .set(1);
        crate::metrics::NODE_VERSION
            .with_label_values(&[my_account_id.as_str()])
            .set(node_version());
        let mut last_hardware_pull = Instant::now();

        loop {
            let protocol_time = Instant::now();
            tracing::debug!("trying to advance chain signatures protocol");
            // Hardware metric refresh
            if last_hardware_pull.elapsed() > Duration::from_secs(5) {
                update_system_metrics(my_account_id.as_str());
                last_hardware_pull = Instant::now();
            }

            crate::metrics::PROTOCOL_ITER_CNT
                .with_label_values(&[my_account_id.as_str()])
                .inc();

            let contract_state = {
                let state = contract_state.read().await;
                state.clone()
            };
            let cfg = {
                let config = config.read().await;
                config.clone()
            };
            let mesh_state = {
                let state = mesh_state.read().await;
                state.clone()
            };

            let state = {
                let guard = self.state.read().await;
                guard.clone()
            };

            let crypto_time = Instant::now();
            let mut state = match state
                .progress(&mut self, cfg.clone(), mesh_state.clone())
                .await
            {
                Ok(state) => {
                    tracing::debug!("progress ok: {state}");
                    state
                }
                Err(err) => {
                    tracing::warn!("protocol unable to progress: {err:?}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            crate::metrics::PROTOCOL_LATENCY_ITER_CRYPTO
                .with_label_values(&[my_account_id.as_str()])
                .observe(crypto_time.elapsed().as_secs_f64());

            if let Some(contract_state) = contract_state {
                let consensus_time = Instant::now();
                let from_state = format!("{state}");
                state = match state.advance(&mut self, contract_state, cfg.clone()).await {
                    Ok(state) => {
                        tracing::debug!("advance ok: {from_state} => {state}");
                        state
                    }
                    Err(err) => {
                        tracing::warn!("protocol unable to advance: {err:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                crate::metrics::PROTOCOL_LATENCY_ITER_CONSENSUS
                    .with_label_values(&[my_account_id.as_str()])
                    .observe(consensus_time.elapsed().as_secs_f64());
            }

            let message_time = Instant::now();
            if let Err(err) = state.recv(&self.channel, cfg, mesh_state).await {
                tracing::warn!("protocol unable to receive messages: {err:?}");
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

/// our release versions take the form of "1.0.0-rc.2"
fn node_version() -> i64 {
    let version = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    let rc_num = if let Some(rc_str) = version.pre.split('.').nth(1) {
        rc_str.parse::<u64>().unwrap_or(0)
    } else {
        0
    };
    (rc_num + version.patch * 1000 + version.minor * 1000000 + version.major * 1000000000) as i64
}

fn update_system_metrics(node_account_id: &str) {
    let mut system = System::new_all();

    // Refresh only the necessary components
    system.refresh_all();

    let mut s =
        System::new_with_specifics(RefreshKind::new().with_cpu(CpuRefreshKind::everything()));
    // Wait a bit because CPU usage is based on diff.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    // Refresh CPUs again to get actual value.
    s.refresh_cpu_specifics(CpuRefreshKind::everything());

    // Update CPU usage metric
    let cpu_usage = s.global_cpu_usage() as i64;
    crate::metrics::CPU_USAGE_PERCENTAGE
        .with_label_values(&["global", node_account_id])
        .set(cpu_usage);

    // Update available memory metric
    let available_memory = system.available_memory() as i64;
    crate::metrics::AVAILABLE_MEMORY_BYTES
        .with_label_values(&["available_mem", node_account_id])
        .set(available_memory);

    // Update used memory metric
    let used_memory = system.used_memory() as i64;
    crate::metrics::USED_MEMORY_BYTES
        .with_label_values(&["used", node_account_id])
        .set(used_memory);

    let root_mount_point = Path::new("/");
    // Update available disk space metric
    let available_disk_space = Disks::new_with_refreshed_list()
        .iter()
        .find(|d| d.mount_point() == root_mount_point)
        .expect("No disk found mounted at '/'")
        .available_space() as i64;
    crate::metrics::AVAILABLE_DISK_SPACE_BYTES
        .with_label_values(&["available_disk", node_account_id])
        .set(available_disk_space);

    // Update total disk space metric
    let total_disk_space = Disks::new_with_refreshed_list()
        .iter()
        .find(|d| d.mount_point() == root_mount_point)
        .expect("No disk found mounted at '/'")
        .total_space() as i64;
    crate::metrics::TOTAL_DISK_SPACE_BYTES
        .with_label_values(&["total_disk", node_account_id])
        .set(total_disk_space);
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Copy)]
pub enum Chain {
    NEAR,
    Ethereum,
}
