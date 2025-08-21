mod cryptography;

pub mod consensus;
pub mod contract;
pub mod error;
pub mod message;
pub mod posit;
pub mod presignature;
pub mod signature;
pub mod state;
pub mod sync;
pub mod triple;

pub use contract::primitives::ParticipantInfo;
pub use contract::ProtocolState;
pub use cryptography::CryptographicError;
pub use message::{Message, MessageChannel};
pub use signature::{IndexedSignRequest, SignQueue};
pub use state::{Node, NodeState};

use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::consensus::ConsensusProtocol;
use crate::protocol::cryptography::CryptographicProtocol;
use crate::protocol::message::MessageReceiver as _;
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::storage::presignature_storage::PresignatureStorage;
use crate::storage::secret_storage::SecretNodeStorageBox;
use crate::storage::triple_storage::TripleStorage;

use near_account_id::AccountId;
use semver::Version;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{CpuRefreshKind, Disks, RefreshKind, System};
use tokio::sync::RwLock;
use tokio::sync::{mpsc, watch};

pub struct MpcSignProtocol {
    pub(crate) my_account_id: AccountId,
    pub(crate) secret_storage: SecretNodeStorageBox,
    pub(crate) triple_storage: TripleStorage,
    pub(crate) presignature_storage: PresignatureStorage,
    pub(crate) sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
    pub(crate) msg_channel: MessageChannel,
    pub(crate) rpc_channel: RpcChannel,
    pub(crate) config: watch::Receiver<Config>,
    pub(crate) mesh_state: watch::Receiver<MeshState>,
}

/// Interface required by the [`MpcSignProtocol`] to participate in the
/// self-governing methods of the MPC network.
pub trait Governance {
    fn propose_join(&self) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;

    fn vote_reshared(
        &self,
        epoch: u64,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;

    fn vote_public_key(
        &self,
        public_key: &near_crypto::PublicKey,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
}

impl MpcSignProtocol {
    pub async fn run<G: Governance>(
        mut self,
        mut node: Node,
        mut gov_client: G,
        contract_state: ContractStateWatcher,
        config: watch::Receiver<Config>,
        mesh_state: watch::Receiver<MeshState>,
    ) {
        let my_account_id = self.my_account_id.as_str();
        let _span = tracing::info_span!("running", my_account_id);
        let my_account_id = self.my_account_id.clone();

        crate::metrics::NODE_RUNNING
            .with_label_values(&[my_account_id.as_str()])
            .set(1);
        crate::metrics::NODE_VERSION
            .with_label_values(&[my_account_id.as_str()])
            .set(node_version());

        loop {
            let protocol_time = Instant::now();
            tracing::debug!("trying to advance chain signatures protocol");

            crate::metrics::PROTOCOL_ITER_CNT
                .with_label_values(&[my_account_id.as_str()])
                .inc();

            let cfg = config.borrow().clone();
            let mesh_state = mesh_state.borrow().clone();

            let crypto_time = Instant::now();
            node.state = node
                .state
                .progress(&mut self, cfg.clone(), mesh_state.clone())
                .await;
            node.update_watchers().await;
            crate::metrics::PROTOCOL_LATENCY_ITER_CRYPTO
                .with_label_values(&[my_account_id.as_str()])
                .observe(crypto_time.elapsed().as_secs_f64());

            if let Some(contract_state) = contract_state.state() {
                let consensus_time = Instant::now();
                node.state = node
                    .state
                    .advance(&mut self, &mut gov_client, contract_state)
                    .await;
                crate::metrics::PROTOCOL_LATENCY_ITER_CONSENSUS
                    .with_label_values(&[my_account_id.as_str()])
                    .observe(consensus_time.elapsed().as_secs_f64());
                node.update_watchers().await;
            }

            let message_time = Instant::now();
            if let Err(err) = node.state.recv(&self.msg_channel, cfg, mesh_state).await {
                tracing::warn!("protocol unable to receive messages: {err:?}");
            }
            crate::metrics::PROTOCOL_LATENCY_ITER_MESSAGE
                .with_label_values(&[my_account_id.as_str()])
                .observe(message_time.elapsed().as_secs_f64());

            let sleep_ms = match node.state {
                NodeState::Generating(_) => 500,
                NodeState::Resharing(_) => 500,
                NodeState::Running(_) => 100,

                NodeState::Starting => 1000,
                NodeState::Started(_) => 1000,
                NodeState::WaitingForConsensus(_) => 1000,
                NodeState::Joining(_) => 1000,
            };

            crate::metrics::PROTOCOL_LATENCY_ITER_TOTAL
                .with_label_values(&[my_account_id.as_str()])
                .observe(protocol_time.elapsed().as_secs_f64());
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    }

    #[cfg(feature = "test-feature")]
    pub fn new_test(
        my_account_id: AccountId,
        secret_storage: SecretNodeStorageBox,
        triple_storage: TripleStorage,
        presignature_storage: PresignatureStorage,
        sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
        msg_channel: MessageChannel,
        rpc_channel: RpcChannel,
        config: watch::Receiver<Config>,
        mesh_state: watch::Receiver<MeshState>,
    ) -> Self {
        Self {
            my_account_id,
            secret_storage,
            triple_storage,
            presignature_storage,
            sign_rx,
            msg_channel,
            rpc_channel,
            config,
            mesh_state,
        }
    }

    pub fn my_account_id(&self) -> &AccountId {
        &self.my_account_id
    }
}

/// our release versions take the form of "1.0.0-rc.2"
fn node_version() -> i64 {
    parse_node_version(env!("CARGO_PKG_VERSION"))
}

fn parse_node_version(version: &str) -> i64 {
    let version = match Version::parse(version) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("Failed to parse version: {}", version);
            Version::new(999, 999, 999)
        }
    };
    let rc_num = if let Some(rc_str) = version.pre.split('.').nth(1) {
        rc_str.parse::<u64>().unwrap_or(0)
    } else {
        0
    };
    (rc_num + version.patch * 1000 + version.minor * 1000000 + version.major * 1000000000) as i64
}

pub async fn spawn_system_metrics(node_account_id: &str) -> tokio::task::JoinHandle<()> {
    let node_account_id = node_account_id.to_string();
    tokio::task::spawn_blocking(move || {
        loop {
            let mut system = System::new_all();

            // Refresh only the necessary components
            system.refresh_all();

            let mut s = System::new_with_specifics(
                RefreshKind::new().with_cpu(CpuRefreshKind::everything()),
            );
            // Wait a bit because CPU usage is based on diff.
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
            // Refresh CPUs again to get actual value.
            s.refresh_cpu_specifics(CpuRefreshKind::everything());

            // Update CPU usage metric
            let cpu_usage = s.global_cpu_usage() as i64;
            crate::metrics::CPU_USAGE_PERCENTAGE
                .with_label_values(&["global", &node_account_id])
                .set(cpu_usage);

            // Update available memory metric
            let available_memory = system.available_memory() as i64;
            crate::metrics::AVAILABLE_MEMORY_BYTES
                .with_label_values(&["available_mem", &node_account_id])
                .set(available_memory);

            // Update used memory metric
            let used_memory = system.used_memory() as i64;
            crate::metrics::USED_MEMORY_BYTES
                .with_label_values(&["used", &node_account_id])
                .set(used_memory);

            let root_mount_point = Path::new("/");
            // Update available disk space metric
            let available_disk_space = Disks::new_with_refreshed_list()
                .iter()
                .find(|d| d.mount_point() == root_mount_point)
                .expect("No disk found mounted at '/'")
                .available_space() as i64;
            crate::metrics::AVAILABLE_DISK_SPACE_BYTES
                .with_label_values(&["available_disk", &node_account_id])
                .set(available_disk_space);

            // Update total disk space metric
            let total_disk_space = Disks::new_with_refreshed_list()
                .iter()
                .find(|d| d.mount_point() == root_mount_point)
                .expect("No disk found mounted at '/'")
                .total_space() as i64;
            crate::metrics::TOTAL_DISK_SPACE_BYTES
                .with_label_values(&["total_disk", &node_account_id])
                .set(total_disk_space);

            std::thread::sleep(Duration::from_secs(5));
        }
    })
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Copy, Hash)]
pub enum Chain {
    NEAR,
    Ethereum,
    Solana,
}

impl Chain {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Chain::NEAR => "NEAR",
            Chain::Ethereum => "Ethereum",
            Chain::Solana => "Solana",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_version() {
        assert_eq!(parse_node_version("1.0.0-beta"), 1000000000);
        assert_eq!(parse_node_version("1.0.0-rc.1"), 1000000001);
        assert_eq!(parse_node_version("1.0.0-rc.2"), 1000000002);
        assert_eq!(parse_node_version("1.2.3-rc.4"), 1002003004);
        assert_eq!(parse_node_version("1.0.0"), 1000000000);
        assert_eq!(parse_node_version("1.1.0"), 1001000000);
        assert_eq!(parse_node_version("1.2.3"), 1002003000);
        assert_eq!(parse_node_version("2.0.0"), 2000000000);
        assert_eq!(parse_node_version("2.1.0"), 2001000000);
        assert_eq!(parse_node_version("2.1.1-rc.5"), 2001001005);
        assert_eq!(parse_node_version("2.1.1"), 2001001000);
        assert_eq!(parse_node_version("10.20.30-rc.40"), 10020030040);
    }

    #[test]
    fn test_parse_node_version_invalid() {
        assert_eq!(parse_node_version("bad_version"), 999999999000);
        assert_eq!(parse_node_version(""), 999999999000);
    }
}
