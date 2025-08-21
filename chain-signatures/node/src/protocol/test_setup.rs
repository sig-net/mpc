use std::sync::Arc;

use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::{IndexedSignRequest, MessageChannel, MpcSignProtocol};
use crate::rpc::RpcChannel;
use crate::storage::secret_storage::SecretNodeStorageBox;
use crate::storage::{PresignatureStorage, TripleStorage};
use near_sdk::AccountId;
use tokio::sync::{mpsc, watch, RwLock};

pub struct TestProtocolStorage {
    pub secret_storage: SecretNodeStorageBox,
    pub triple_storage: TripleStorage,
    pub presignature_storage: PresignatureStorage,
}

pub struct TestProtocolChannels {
    pub sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
    pub msg_channel: MessageChannel,
    pub rpc_channel: RpcChannel,
    pub config: watch::Receiver<Config>,
    pub mesh_state: watch::Receiver<MeshState>,
}

impl MpcSignProtocol {
    pub fn new_test(
        my_account_id: AccountId,
        storage: TestProtocolStorage,
        channels: TestProtocolChannels,
    ) -> Self {
        Self {
            my_account_id,
            secret_storage: storage.secret_storage,
            triple_storage: storage.triple_storage,
            presignature_storage: storage.presignature_storage,
            sign_rx: channels.sign_rx,
            msg_channel: channels.msg_channel,
            rpc_channel: channels.rpc_channel,
            config: channels.config,
            mesh_state: channels.mesh_state,
        }
    }
}
