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
use mpc_node::protocol::contract::primitives::{Candidates, Participants, Votes};
use mpc_node::protocol::contract::RunningContractState;
use mpc_node::protocol::message::{MessageInbox, SignedMessage};
use mpc_node::protocol::{
    self, Governance, IndexedSignRequest, MessageChannel, MpcSignProtocol, ProtocolState, SignQueue,
};
use mpc_node::rpc::RpcChannel;
use mpc_node::rpc::{ContractStateWatcher, RpcAction};
use mpc_node::storage::{
    presignature_storage, secret_storage, triple_storage, PresignatureStorage,
};
use mpc_node::types::SecretKeyShare;
use near_sdk::AccountId;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

pub struct TestMpcNetwork {
    prepared_nodes: Vec<TestMpcNodeBuilder>,
    pub running: Vec<TestMpcNode>,
    pub redis_container: Redis,
    pub shared_public_key: mpc_crypto::PublicKey,
    pub rpc_actions: Arc<Mutex<HashSet<String>>>,
}

struct TestMpcNodeBuilder {
    me: Participant,
    candidate_info: CandidateInfo,
    participant_info: ParticipantInfo,
    config: Config,
    secret_share: SecretKeyShare,
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

    pub presignature_storage: PresignatureStorage,
}

impl TestMpcNetwork {
    pub async fn new() -> Self {
        // This is a bit of a weird place to install the subscriber but every
        // test needs to call it somewhere. Since tests will usually call this
        // before doing anything interesting, might as well do it here.
        crate::utils::init_tracing_log();

        // TODO(jakmeier): make this configurable
        let num_nodes = 3;
        let redis_container = redis().await;

        // TODO(jakmeier): make this configurable
        let encoded = EncodedPoint::<Secp256k1>::from_str(
            "0303D6C6F119014A09A6B2A58B0BB075A7938EDF3D0E9F58AC2ED58A19CB5C20C0",
        )
        .unwrap();
        let shared_public_key: mpc_crypto::PublicKey =
            mpc_crypto::PublicKey::from_encoded_point(&encoded).unwrap();

        TestMpcNetwork {
            prepared_nodes: (0..num_nodes).map(TestMpcNodeBuilder::new).collect(),
            running: vec![],
            redis_container,
            shared_public_key,
            rpc_actions: Default::default(),
        }
    }

    pub async fn start(&mut self) {
        // construct full list of participants and candidates (same set)
        let mut candidates_by_id = CandidatesById::new();
        for node in &self.prepared_nodes {
            candidates_by_id.insert(
                node.candidate_info.account_id.clone(),
                node.candidate_info.clone(),
            );
        }
        let participants_by_id = ParticipantsById::from(candidates_by_id.clone());
        let participants = Participants::from(participants_by_id.clone());
        let candidates = Candidates::from(candidates_by_id);

        // mark all participant as already active and stable when the network starts
        let init_mesh = MeshState {
            active: participants.clone(),
            // active: Default::default(),
            need_sync: Default::default(),
            stable: participants.keys_vec(),
            // stable: Default::default(),
        };

        // create a starting protocol state matching the participants
        // include everyone already having voted for everybody else
        let threshold = 2;
        let mut join_votes = Votes::default();
        let vote_for_all = HashSet::from_iter(participants.account_ids().into_iter().cloned());
        for (_p, info) in participants.iter() {
            join_votes
                .votes
                .insert(info.account_id.clone(), vote_for_all.clone());
        }
        let protocol_state = ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: self.shared_public_key,
            participants: participants.clone(),
            candidates: candidates.clone(),
            join_votes,
            leave_votes: Default::default(),
            threshold,
        });

        // Build a routing table: Participant -> msg_tx
        let mut routing_table: HashMap<Participant, Sender<Ciphered>> = HashMap::new();
        for node in &self.prepared_nodes {
            let participant = participants_by_id
                .account_to_participant_id
                .get(&node.participant_info.account_id)
                .unwrap();
            routing_table.insert(Participant::from(*participant), node.msg_tx.clone());
        }

        let mut protocol = mpc_contract::config::ProtocolConfig::default();
        protocol.triple.min_triples = 10;
        protocol.triple.max_triples = 100;
        protocol.presignature.min_presignatures = 10;
        protocol.presignature.max_presignatures = 100;
        let cfg = crate::NodeConfig {
            nodes: self.prepared_nodes.len(),
            threshold,
            protocol,
            eth: None,
            sol: None,
        };

        // TODO(jakmeier): make this configurable
        self.redis_container
            .stockpile_triples(&cfg, &participants_by_id, 1)
            .await;

        // Start each node's tokio tasks
        for node in self.prepared_nodes.drain(..) {
            let started = node.start(
                routing_table.clone(),
                &self.redis_container.pool(),
                &init_mesh,
                &protocol_state,
                &self.shared_public_key,
            );
            self.running.push(started);
        }
    }

    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        for node in &self.running {
            node.wait_for_presignatures(threshold_per_node).await;
        }
    }
}

struct MockGovernance {
    pub me: String,
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
        Ok(true)
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

        // TODO(jakmeier): make this configurable
        let secrets = [
            "D098A0E6DE766B341F618B5651264ABAFD215E661080978489B99E6B9692201A",
            "246E77A94C03FEEEC444C6EFC50232AB1A70ABF2E5A07368330AEA021A6223EB",
            "4059292990D4E26D3291E41F20EFBE31D2B227A0CFF97DB0612F5D62CD2055EC",
        ];
        let bytes = hex::decode(secrets[index as usize]).unwrap();
        let secret_share = k256::Scalar::from_bytes(bytes.try_into().unwrap()).unwrap();

        TestMpcNodeBuilder {
            me: Participant::from(index),
            candidate_info,
            participant_info,
            config,
            secret_share,
            msg_tx,
            msg_rx,
            msg_channel,
        }
    }

    fn start(
        self,
        routing_table: HashMap<Participant, Sender<Ciphered>>,
        redis_pool: &deadpool_redis::Pool,
        init_mesh: &MeshState,
        protocol_state: &ProtocolState,
        public_key: &mpc_crypto::PublicKey,
    ) -> TestMpcNode {
        let key_storage = secret_storage::test_store(0, self.secret_share, *public_key);

        let triple_storage = triple_storage::init(redis_pool, &self.participant_info.account_id);
        let presignature_storage =
            presignature_storage::init(redis_pool, &self.participant_info.account_id);

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
            triple_storage,
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
                me: account_id.to_string(),
            },
            protocol_state_rx.clone(),
            config_rx.clone(),
            mesh_rx.clone(),
        ));

        let rpc_actions = Default::default();
        let _mock_network_handle = Self::test_mock_network(
            routing_table,
            Arc::clone(&rpc_actions),
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
                                        tracing::debug!(target: "mock_network", ?e, "Failed to forward encrypted message to {to:?}");
                                    }
                                } else {
                                    tracing::debug!(target: "mock_network", "No route to participant {:?}", to);
                                }
                            }
                            Err(e) => {
                                tracing::debug!(target: "mock_network", ?e, "Encryption failed");
                            }
                        }
                    }

                    Some(rpc) = rpc_rx.recv() => {
                        let action_str = match rpc {
                            RpcAction::Publish(publish_action) => {
                                format!("RpcAction::Publish({:?})", publish_action.request)
                            },
                        };
                        tracing::debug!(target: "mock_network", ?action_str, "Received RPC action");
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
        &self.running[index]
    }
}
impl std::ops::IndexMut<usize> for TestMpcNetwork {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.running[index]
    }
}
