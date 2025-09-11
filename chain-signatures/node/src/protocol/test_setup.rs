use std::sync::Arc;

use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::{IndexedSignRequest, MessageChannel, MpcSignProtocol};
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::sign_respond_tx::SignRespondSignatureChannel;
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
    pub sign_respond_signature_channel: SignRespondSignatureChannel,
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
        Self {
            my_account_id,
            secret_storage: storage.secret_storage,
            triple_storage: storage.triple_storage,
            presignature_storage: storage.presignature_storage,
            sign_rx: channels.sign_rx,
            msg_channel: channels.msg_channel,
            generating,
            resharing,
            rpc_channel: channels.rpc_channel,
            contract,
            config: channels.config,
            mesh_state: channels.mesh_state,
            sign_respond_signature_channel: channels.sign_respond_signature_channel,
        }
    }
}
