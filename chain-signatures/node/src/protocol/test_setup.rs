use crate::backlog::Backlog;
use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::signature::SignatureSpawnerTask;
use crate::protocol::{MessageChannel, MpcSignProtocol, Sign};
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::storage::secret_storage::SecretNodeStorageVariant;
use crate::storage::{PresignatureStorage, TripleStorage};
use near_sdk::AccountId;
use tokio::sync::{mpsc, watch};

pub struct TestProtocolStorage {
    pub secret_storage: SecretNodeStorageVariant,
    pub triple_storage: TripleStorage,
    pub presignature_storage: PresignatureStorage,
}

pub struct TestProtocolChannels {
    pub sign_rx: mpsc::Receiver<Sign>,
    pub msg_channel: MessageChannel,
    pub rpc_channel: RpcChannel,
    pub config: watch::Receiver<Config>,
    pub mesh_state: watch::Receiver<MeshState>,
}

impl MpcSignProtocol {
    pub async fn new_test(
        my_account_id: AccountId,
        storage: TestProtocolStorage,
        channels: TestProtocolChannels,
        contract: ContractStateWatcher,
    ) -> Self {
        let generating = channels.msg_channel.subscribe_generation().await;
        let resharing = channels.msg_channel.subscribe_resharing().await;
        let ready = channels.msg_channel.subscribe_ready().await;
        let sign_task = SignatureSpawnerTask::run(
            my_account_id.clone(),
            channels.sign_rx,
            contract.clone(),
            channels.config.clone(),
            storage.presignature_storage.clone(),
            channels.mesh_state.clone(),
            channels.msg_channel.clone(),
            channels.rpc_channel.clone(),
            Backlog::new(),
        );
        Self {
            my_account_id,
            secret_storage: storage.secret_storage,
            triple_storage: storage.triple_storage,
            presignature_storage: storage.presignature_storage,
            sign_task,
            msg_channel: channels.msg_channel,
            generating,
            resharing,
            ready,
            config: channels.config,
            mesh_state: channels.mesh_state,
        }
    }
}
