//! Create an isolated MPC network for testing without hitting a real network.

use crate::containers::Redis;
use cait_sith::protocol::Participant;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use k256::Secp256k1;
use mpc_contract::primitives::{
    CandidateInfo, Candidates as CandidatesById, ParticipantInfo, Participants as ParticipantsById,
};
use mpc_crypto::ScalarExt;
use mpc_keys::hpke::{self, Ciphered};
use mpc_node::config::{Config, LocalConfig, NetworkConfig};
use mpc_node::mesh::MeshState;
use mpc_node::protocol::contract::primitives::{Candidates, Participants, PkVotes, Votes};
use mpc_node::protocol::contract::{InitializingContractState, RunningContractState};
use mpc_node::protocol::message::{MessageInbox, SignedMessage};
use mpc_node::protocol::{
    self, Governance, IndexedSignRequest, MessageChannel, MpcSignProtocol, ProtocolState, SignQueue,
};
use mpc_node::rpc::RpcChannel;
use mpc_node::rpc::{ContractStateWatcher, RpcAction};
use mpc_node::storage::{
    presignature_storage, secret_storage, triple_storage, Options, PresignatureStorage,
    TripleStorage,
};
use mpc_node::util::NearPublicKeyExt;
use near_sdk::AccountId;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

pub struct TestMpcNetworkBuilder {
    prepared_nodes: Vec<TestMpcNodeBuilder>,
    threshold: usize,
    shared_public_key: Option<mpc_crypto::PublicKey>,
    protocol_state: ProtocolState,
    participants: Participants,
    participants_by_id: ParticipantsById,
    candidates: Candidates,
    triple_stockpile_factor: u32,
    presignature_stockpile: bool,
}

pub struct TestMpcNetwork {
    pub nodes: Vec<TestMpcNode>,
    pub redis_container: Redis,
    pub rpc_actions: Arc<Mutex<HashSet<String>>>,
    pub msg_log: Arc<Mutex<Vec<String>>>,
}

struct TestMpcNodeBuilder {
    me: Participant,
    candidate_info: CandidateInfo,
    participant_info: ParticipantInfo,
    config: Config,
    msg_tx: Sender<Ciphered>,
    msg_rx: mpsc::Receiver<(
        mpc_node::protocol::Message,
        (Participant, Participant, std::time::Instant),
    )>,
    msg_channel: MessageChannel,
}

pub struct TestMpcNode {
    pub me: Participant,
    pub mesh: watch::Sender<MeshState>,
    pub config: watch::Sender<Config>,

    pub protocol_state: watch::Sender<Option<ProtocolState>>,
    pub sign_tx: Sender<IndexedSignRequest>,
    pub msg_tx: Sender<Ciphered>,

    pub triple_storage: TripleStorage,
    pub presignature_storage: PresignatureStorage,
}

impl Default for TestMpcNetworkBuilder {
    fn default() -> Self {
        Self::new(3, 2)
    }
}

impl TestMpcNetworkBuilder {
    pub fn new(num_nodes: u32, threshold: usize) -> Self {
        // This is a bit of a weird place to install the subscriber but every
        // test needs to call it somewhere. Since tests will usually call this
        // before doing anything interesting, might as well do it here.
        crate::utils::init_tracing_log();

        let prepared_nodes: Vec<_> = (0..num_nodes).map(TestMpcNodeBuilder::new).collect();

        // construct full list of participants and candidates (same set)
        let mut candidates_by_id = CandidatesById::new();
        for node in &prepared_nodes {
            candidates_by_id.insert(
                node.candidate_info.account_id.clone(),
                node.candidate_info.clone(),
            );
        }
        let participants_by_id = ParticipantsById::from(candidates_by_id.clone());
        let participants = Participants::from(participants_by_id.clone());
        let candidates = Candidates::from(candidates_by_id);

        let protocol_state = ProtocolState::Initializing(InitializingContractState {
            candidates: candidates.clone(),
            threshold,
            pk_votes: PkVotes {
                pk_votes: Default::default(),
            },
        });

        TestMpcNetworkBuilder {
            threshold,
            triple_stockpile_factor: 0,
            prepared_nodes,
            shared_public_key: None,
            protocol_state,
            participants,
            participants_by_id,
            candidates,
            presignature_stockpile: false,
        }
    }

    pub async fn build(mut self) -> TestMpcNetwork {
        let redis_container = self.build_redis().await;

        // Build a routing table: Participant -> msg_tx
        let mut routing_table: HashMap<Participant, Sender<Ciphered>> = HashMap::new();
        for node in &self.prepared_nodes {
            let participant = self
                .participants_by_id
                .account_to_participant_id
                .get(&node.participant_info.account_id)
                .unwrap();
            routing_table.insert(Participant::from(*participant), node.msg_tx.clone());
        }

        // mark all participant as already active and stable when the network starts
        let initial_mesh_state = MeshState {
            active: self.participants.clone(),
            need_sync: Default::default(),
            stable: self.participants.keys_vec(),
        };

        let rpc_actions = Default::default();
        let msg_log = Default::default();
        let mut nodes = vec![];

        // Start each node's tokio tasks
        for node in self.prepared_nodes.drain(..) {
            let started = node
                .start(
                    routing_table.clone(),
                    &redis_container.pool(),
                    &initial_mesh_state,
                    &self.protocol_state,
                    &self.shared_public_key,
                    self.presignature_stockpile,
                    Arc::clone(&msg_log),
                    Arc::clone(&rpc_actions),
                )
                .await;

            nodes.push(started);
        }

        TestMpcNetwork {
            redis_container,
            nodes,
            rpc_actions,
            msg_log,
        }
    }

    async fn build_redis(&self) -> Redis {
        let redis_container = redis().await;

        // TODO(jakmeier): make this configurable
        let mut protocol = mpc_contract::config::ProtocolConfig::default();
        protocol.triple.min_triples = 10;
        protocol.triple.max_triples = 100;
        protocol.presignature.min_presignatures = 10;
        protocol.presignature.max_presignatures = 100;
        let cfg = crate::NodeConfig {
            nodes: self.prepared_nodes.len(),
            threshold: self.threshold,
            protocol,
            eth: None,
            sol: None,
        };

        if self.triple_stockpile_factor > 0 {
            redis_container
                .stockpile_triples(&cfg, &self.participants_by_id, self.triple_stockpile_factor)
                .await;
        }

        redis_container
    }

    pub fn with_preshared_key(mut self) -> Self {
        let encoded = EncodedPoint::<Secp256k1>::from_str(
            "0303D6C6F119014A09A6B2A58B0BB075A7938EDF3D0E9F58AC2ED58A19CB5C20C0",
        )
        .unwrap();
        self.shared_public_key = Some(mpc_crypto::PublicKey::from_encoded_point(&encoded).unwrap());

        self.protocol_state = ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: self.shared_public_key.unwrap(),
            participants: self.participants.clone(),
            candidates: self.candidates.clone(),
            join_votes: Votes::default(),
            leave_votes: Default::default(),
            threshold: self.threshold,
        });

        self
    }

    pub fn with_stockpiled_triples(mut self, triple_stockpile_factor: u32) -> Self {
        assert!(
            self.shared_public_key.is_some(),
            "can't stockpile without preshared key"
        );
        self.triple_stockpile_factor = triple_stockpile_factor;
        self
    }

    pub fn with_presignature_stockpile(mut self) -> Self {
        self.presignature_stockpile = true;
        self
    }
}

impl TestMpcNetwork {
    pub async fn wait_for_triples(&self, threshold_per_node: usize) {
        for node in &self.nodes {
            node.wait_for_triples(threshold_per_node).await;
        }
    }

    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        for node in &self.nodes {
            node.wait_for_presignatures(threshold_per_node).await;
        }
    }
}

struct MockGovernance {
    pub me: AccountId,
    pub protocol_state_tx: watch::Sender<Option<ProtocolState>>,
}

impl Governance for MockGovernance {
    async fn propose_join(&self) -> anyhow::Result<()> {
        tracing::debug!(me = ?self.me, "propose_join");
        Ok(())
    }

    async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        tracing::debug!(me = ?self.me, ?epoch, "vote_reshared");
        Ok(true)
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> anyhow::Result<bool> {
        tracing::debug!(me = ?self.me, ?public_key, "vote_public_key");
        let mut result = false;
        self.protocol_state_tx.send_if_modified(|protocol_state| {
            let modified;
            match protocol_state {
                Some(ProtocolState::Initializing(ref mut state)) => {
                    modified = state
                        .pk_votes
                        .pk_votes
                        .entry(public_key.clone())
                        .or_default()
                        .insert(self.me.clone());

                    if state.pk_votes.pk_votes.len() >= state.threshold {
                        *protocol_state = Some(ProtocolState::Running(RunningContractState {
                            epoch: 0,
                            participants: state.candidates.clone().into(),
                            threshold: state.threshold,
                            public_key: public_key.clone().into_affine_point(),
                            candidates: Default::default(),
                            join_votes: Default::default(),
                            leave_votes: Default::default(),
                        }));
                        result = true;
                    }
                }

                Some(_) => todo!(),
                None => todo!(),
            }
            modified
        });
        Ok(result)
    }
}

impl TestMpcNodeBuilder {
    fn new(index: u32) -> Self {
        let account_id: AccountId = format!("p-{index}").parse().unwrap();
        let url = format!("fake{index}.url");

        let cipher_sk = hpke::SecretKey::from_bytes(&[index as u8; 32]);
        let cipher_pk = cipher_sk.public_key().to_bytes();

        let sign_sk = near_crypto::SecretKey::from_seed(
            near_crypto::KeyType::ED25519,
            &account_id.to_string(),
        );
        let sign_pk = near_sdk::PublicKey::from_parts(
            near_sdk::CurveType::ED25519,
            sign_sk.public_key().key_data().to_vec(),
        )
        .unwrap();

        let candidate_info = CandidateInfo {
            account_id,
            url,
            cipher_pk,
            sign_pk,
        };
        let participant_info = ParticipantInfo::from(candidate_info.clone());

        let config = Config::new(LocalConfig {
            network: NetworkConfig { sign_sk, cipher_sk },
            ..Default::default()
        });

        // Needs to be built ahead of time to create routing table
        let (msg_tx, msg_rx, msg_channel) = MessageChannel::new();

        TestMpcNodeBuilder {
            me: Participant::from(index),
            candidate_info,
            participant_info,
            config,
            msg_tx,
            msg_rx,
            msg_channel,
        }
    }

    async fn start(
        self,
        routing_table: HashMap<Participant, Sender<Ciphered>>,
        redis_pool: &deadpool_redis::Pool,
        init_mesh: &MeshState,
        protocol_state: &ProtocolState,
        public_key: &Option<mpc_crypto::PublicKey>,
        presignature_stockpile: bool,
        msg_log: Arc<Mutex<Vec<String>>>,
        rpc_actions: Arc<Mutex<HashSet<String>>>,
    ) -> TestMpcNode {
        let index = u32::from(self.me);
        let key_storage = if let Some(public_key) = public_key {
            // TODO(jakmeier): make this work with other configs than num_nodes = 3
            let secrets = [
                "D098A0E6DE766B341F618B5651264ABAFD215E661080978489B99E6B9692201A",
                "246E77A94C03FEEEC444C6EFC50232AB1A70ABF2E5A07368330AEA021A6223EB",
                "4059292990D4E26D3291E41F20EFBE31D2B227A0CFF97DB0612F5D62CD2055EC",
            ];
            let bytes = hex::decode(secrets[index as usize]).unwrap();
            let secret_share = k256::Scalar::from_bytes(bytes.try_into().unwrap()).unwrap();

            secret_storage::test_store(0, secret_share, *public_key)
        } else {
            secret_storage::init(
                None,
                &Options {
                    env: "test_env".to_owned(),
                    gcp_project_id: "-".to_owned(),
                    sk_share_secret_id: None,
                    sk_share_local_path: None,
                    redis_url: ".".to_owned(),
                },
                &self.participant_info.account_id,
            )
        };

        let triple_storage = triple_storage::init(redis_pool, &self.participant_info.account_id);
        let presignature_storage =
            presignature_storage::init(redis_pool, &self.participant_info.account_id);

        if presignature_stockpile {
            for presig in PRESIGNATURES[index as usize].iter() {
                let mut slot = presignature_storage
                    .reserve(presig.id)
                    .await
                    .expect("must be able to reserve slot");
                let deserialized = serde_json::de::from_str(presig.presignature).unwrap();
                // TODO(jakmeier): make this work with other configs than num_nodes = 3
                let owner = (index % 3) as u32;
                slot.insert(deserialized, owner.into()).await;
            }
        }

        let (sign_tx, sign_rx) = SignQueue::channel();
        const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
        let (rpc_tx, rpc_rx) = tokio::sync::mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        let rpc_channel = RpcChannel { tx: rpc_tx };

        let (mesh_tx, mesh_rx) = watch::channel(init_mesh.clone());
        let (config_tx, config_rx) = watch::channel(self.config);

        let inbox = Arc::clone(self.msg_channel.inbox());
        let protocol = MpcSignProtocol::new_test(
            self.participant_info.account_id.clone(),
            key_storage,
            triple_storage.clone(),
            presignature_storage.clone(),
            Arc::new(RwLock::new(sign_rx)),
            self.msg_channel,
            rpc_channel,
            config_rx.clone(),
            mesh_rx.clone(),
        );

        let account_id = protocol.my_account_id().clone();

        // task running the protocol
        let (protocol_state_rx, protocol_state_tx) =
            ContractStateWatcher::with(&account_id, protocol_state.clone());
        let _protocol_handle = tokio::spawn(protocol.run(
            protocol::Node::new(),
            MockGovernance {
                me: account_id.clone(),
                protocol_state_tx: protocol_state_tx.clone(),
            },
            protocol_state_rx.clone(),
            config_rx.clone(),
            mesh_rx.clone(),
        ));

        let _mock_network_handle = Self::test_mock_network(
            routing_table,
            rpc_actions,
            msg_log,
            self.msg_rx,
            rpc_rx,
            mesh_tx.clone(),
            config_tx.clone(),
        );

        let _message_executor_handle = tokio::spawn(Self::test_message_executor(
            config_rx,
            protocol_state_rx,
            inbox,
        ));

        TestMpcNode {
            me: self.me,
            mesh: mesh_tx,
            config: config_tx,
            protocol_state: protocol_state_tx,
            sign_tx,
            msg_tx: self.msg_tx,
            triple_storage,
            presignature_storage,
        }
    }

    /// This replaces what is usually done by MessageExecutor::spawn.
    ///
    /// Right now, this only polls the inbox to update.
    /// The outbox is skipped because the mock network directly inserts non-encrypted messages.
    async fn test_message_executor(
        config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
        inbox: Arc<RwLock<MessageInbox>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            let config = config.borrow().clone();

            let participants = contract.participants().await;
            {
                let mut inbox = inbox.write().await;
                let expiration = Duration::from_millis(config.protocol.message_timeout);
                inbox
                    .update(expiration, &config.local.network.cipher_sk, &participants)
                    .await;
            }
        }
    }

    fn test_mock_network(
        routing_table: HashMap<Participant, Sender<Ciphered>>,
        rpc_actions: Arc<Mutex<HashSet<String>>>,
        msg_log: Arc<Mutex<Vec<String>>>,
        mut msg_rx: Receiver<(
            mpc_node::protocol::Message,
            (Participant, Participant, std::time::Instant),
        )>,
        mut rpc_rx: Receiver<RpcAction>,
        mesh: watch::Sender<MeshState>,
        config: watch::Sender<Config>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            tracing::debug!(target: "mock_network", "Test message executor started");
            loop {
                tokio::select! {
                    Some((msg, (from, to, ts))) = msg_rx.recv() => {
                        tracing::debug!(target: "mock_network", ?to, ?ts, "Received MPC message");

                        let log_msg = match msg {
                            protocol::Message::Posit(_) => "Posit",
                            protocol::Message::Generating(_) => "Generating",
                            protocol::Message::Resharing(_) => "Resharing",
                            protocol::Message::Triple(_) => "Triple",
                            protocol::Message::Presignature(_) => "Presignature",
                            protocol::Message::Signature(_) => "Signature",
                            protocol::Message::Unknown(_) => "Unknown",
                        };
                        msg_log.lock().await.push(format!("{log_msg} from {from:?} to {to:?}"));

                        // directly send out single message, no batching
                        // (might want to add MessageOutbox, too, but for now this is easier)
                        let config = config.borrow().clone();
                        let participants = mesh.borrow().active.clone();
                        let receiver_info = participants.get(&to).expect("TODO: support sending to non-active participants in tests");
                        match SignedMessage::encrypt(
                            &[msg],
                            from,
                            &config.local.network.sign_sk,
                            &receiver_info.cipher_pk,
                        ) {
                            Ok(ciphered) => {
                                if let Some(tx) = routing_table.get(&to) {
                                    if let Err(e) = tx.send(ciphered).await {
                                        tracing::warn!(target: "mock_network", ?e, "Failed to forward encrypted message to {to:?}");
                                    }
                                } else {
                                    tracing::error!(target: "mock_network", "Test setup bug: No route to participant {:?}", to);
                                }
                            }
                            Err(e) => {
                                tracing::error!(target: "mock_network", ?e, "Encryption failed");
                            }
                        }
                    }

                    Some(rpc) = rpc_rx.recv() => {
                        let action_str = match rpc {
                            RpcAction::Publish(publish_action) => {
                                format!(
                                    "RpcAction::Publish({:?}",
                                    publish_action.request,
                                )
                            },
                        };
                        tracing::error!(target: "mock_network", ?action_str, "Received RPC action");
                        let mut actions_log = rpc_actions.lock().await;
                        actions_log.insert(action_str);
                    }

                    else => {
                        tracing::info!(target: "mock_network", "All channels closed, exiting handler loop for one node");
                        break;
                    }
                }
            }
            tracing::info!(target: "mock_network", "Test mock network task exited");
        })
    }
}

impl TestMpcNode {
    pub async fn wait_for_triples(&self, threshold_per_node: usize) {
        loop {
            let count = self.triple_storage.len_by_owner(self.me).await;
            if count >= threshold_per_node {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        loop {
            let count = self.presignature_storage.len_by_owner(self.me).await;
            if count >= threshold_per_node {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }
}

// impl Drop for TestMpcNetwork {
//     fn drop(&mut self) {
//         tracing::info!("printing all messages between nodes");
//         let out = &mut std::fs::File::create("network_msg.txt").unwrap();

//         for line in self.msg_log.lock().await.iter() {
//             tracing::info!("{line}");
//             writeln!(out, "{line}").unwrap();
//         }
//     }
// }

async fn redis() -> Redis {
    let spawner = crate::cluster::spawner::ClusterSpawner::default()
        .network("mpc-test")
        .init_network()
        .await
        .expect("failed setting up redis container");

    crate::containers::Redis::run(&spawner).await
}

impl std::ops::Index<usize> for TestMpcNetwork {
    type Output = TestMpcNode;

    fn index(&self, index: usize) -> &TestMpcNode {
        &self.nodes[index]
    }
}
impl std::ops::IndexMut<usize> for TestMpcNetwork {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.nodes[index]
    }
}

struct SerializedPresignature {
    id: u64,
    presignature: &'static str,
}

const PRESIGNATURES: [[SerializedPresignature; 15]; 3] = [
    [
        SerializedPresignature { id:10578615463967501927 , presignature:"{\"id\":10578615463967501927,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:13267685776613424333 , presignature:"{\"id\":13267685776613424333,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:13749498474387665027 , presignature:"{\"id\":13749498474387665027,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:14481654503363904241 , presignature:"{\"id\":14481654503363904241,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:15860611008650236091 , presignature:"{\"id\":15860611008650236091,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:2735443904802631835 , presignature:"{\"id\":2735443904802631835,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:3000585238922530005 , presignature:"{\"id\":3000585238922530005,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:3053026411059970257 , presignature:"{\"id\":3053026411059970257,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:3632459615945342142 , presignature:"{\"id\":3632459615945342142,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:3869672684191711158 , presignature:"{\"id\":3869672684191711158,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:4327689991975093939 , presignature:"{\"id\":4327689991975093939,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:5751834371102806199 , presignature:"{\"id\":5751834371102806199,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:7078077870043747112 , presignature:"{\"id\":7078077870043747112,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:8565255253298638177 , presignature:"{\"id\":8565255253298638177,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
        SerializedPresignature { id:928724233213890770 , presignature:"{\"id\":928724233213890770,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"7E1BA6970B802E7B6AB1D7AD3B83B6BB6CA24DEE615137B2A025BE5DEDCB0CEE\",\"output_sigma\":\"8EE0E2CB16B8A9DAC6DDF008835A7CB3B79A5591EA46291FFF1FB9CB90765ED3\",\"participants\":[0,1,2]}" },
    ],
    [
    SerializedPresignature { id:10578615463967501927, presignature:"{\"id\":10578615463967501927,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:13267685776613424333, presignature:"{\"id\":13267685776613424333,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:13749498474387665027, presignature:"{\"id\":13749498474387665027,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:14481654503363904241, presignature:"{\"id\":14481654503363904241,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:15860611008650236091, presignature:"{\"id\":15860611008650236091,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:2735443904802631835, presignature:"{\"id\":2735443904802631835,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:3000585238922530005, presignature:"{\"id\":3000585238922530005,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:3053026411059970257, presignature:"{\"id\":3053026411059970257,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:3632459615945342142, presignature:"{\"id\":3632459615945342142,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:3869672684191711158, presignature:"{\"id\":3869672684191711158,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:4327689991975093939, presignature:"{\"id\":4327689991975093939,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:5751834371102806199, presignature:"{\"id\":5751834371102806199,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:7078077870043747112, presignature:"{\"id\":7078077870043747112,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:8565255253298638177, presignature:"{\"id\":8565255253298638177,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    SerializedPresignature { id:928724233213890770, presignature:"{\"id\":928724233213890770,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"AC01734F9AF01194F4D47C33EE71AAB3A0010121E04CBAC3BE685F06F43AB1F4\",\"output_sigma\":\"5A447495B032C71EED5D48CAB355D7D43F1C804249E36F877E74C59138F9D607\",\"participants\":[0,1,2]}"},
    ],
    [
    SerializedPresignature {id:10578615463967501927, presignature:"{\"id\":10578615463967501927,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:13267685776613424333, presignature:"{\"id\":13267685776613424333,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:13749498474387665027, presignature:"{\"id\":13749498474387665027,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:14481654503363904241, presignature:"{\"id\":14481654503363904241,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:15860611008650236091, presignature:"{\"id\":15860611008650236091,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:2735443904802631835, presignature:"{\"id\":2735443904802631835,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:3000585238922530005, presignature:"{\"id\":3000585238922530005,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:3053026411059970257, presignature:"{\"id\":3053026411059970257,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:3632459615945342142, presignature:"{\"id\":3632459615945342142,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:3869672684191711158, presignature:"{\"id\":3869672684191711158,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:4327689991975093939, presignature:"{\"id\":4327689991975093939,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:5751834371102806199, presignature:"{\"id\":5751834371102806199,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:7078077870043747112, presignature:"{\"id\":7078077870043747112,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:8565255253298638177, presignature:"{\"id\":8565255253298638177,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    SerializedPresignature {id:928724233213890770, presignature:"{\"id\":928724233213890770,\"output_big_r\":\"030D71EEF1DD9992CA5D615C46C87B3EEE508EC6F28F2087970E195B2F7B222D63\",\"output_k\":\"D9E740082A5FF4AE7EF720BAA15F9EABD35FB4555F483DD4DCAAFFAFFAAA56FA\",\"output_sigma\":\"F7572E67C047F51C19C18A7BCC96BE7EF6A497ADA3183DEE063B956A1ADC4803\",\"participants\":[0,1,2]}"},
    ]
];
