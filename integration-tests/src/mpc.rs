//! Create an isolated MPC network for testing without hitting a real network.

use crate::containers::Redis;
use crate::mpc::fixture_input::FixtureInput;
use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_contract::primitives::{
    CandidateInfo, Candidates as CandidatesById, ParticipantInfo, Participants as ParticipantsById,
};
use mpc_keys::hpke::{self, Ciphered};
use mpc_node::config::{Config, LocalConfig, NetworkConfig};
use mpc_node::mesh::MeshState;
use mpc_node::protocol::contract::primitives::{Candidates, Participants, PkVotes, Votes};
use mpc_node::protocol::contract::{InitializingContractState, RunningContractState};
use mpc_node::protocol::message::{MessageInbox, SignedMessage};
use mpc_node::protocol::state::{NodeKeyInfo, NodeStateWatcher};
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
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

mod fixture_input;

pub struct TestMpcNetworkBuilder {
    prepared_nodes: Vec<TestMpcNodeBuilder>,
    threshold: usize,
    shared_public_key: Option<mpc_crypto::PublicKey>,
    protocol_state: ProtocolState,
    participants: Participants,
    participants_by_id: ParticipantsById,
    candidates: Candidates,
    fixture_input: FixtureInput,

    presignature_stockpile: bool,
    use_preshared_triples: bool,

    triple_stockpile_factor: u32,
    min_triples: u32,
    max_triples: u32,
    min_presignatures: u32,
    max_presignatures: u32,
}

pub struct TestMpcNetwork {
    pub nodes: Vec<TestMpcNode>,
    pub redis_container: Redis,
    pub rpc_actions: Arc<Mutex<HashSet<String>>>,
    pub msg_log: Arc<Mutex<Vec<String>>>,
    pub shared_contract_state: watch::Sender<Option<ProtocolState>>,
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
    key_info: Option<NodeKeyInfo>,
}

pub struct TestMpcNode {
    pub me: Participant,
    pub state: NodeStateWatcher,
    pub mesh: watch::Sender<MeshState>,
    pub config: watch::Sender<Config>,

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

        let fixture_input = FixtureInput::load(num_nodes);
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
            prepared_nodes,
            shared_public_key: None,
            protocol_state,
            participants,
            participants_by_id,
            candidates,
            fixture_input,

            use_preshared_triples: false,
            presignature_stockpile: false,

            triple_stockpile_factor: 0,
            min_triples: 10,
            max_triples: 100,
            min_presignatures: 10,
            max_presignatures: 100,
        }
    }

    pub async fn build(mut self) -> TestMpcNetwork {
        let finalized_protocol_config = self.build_protocol_config();
        let redis_container = self.build_redis(finalized_protocol_config.clone()).await;

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

        let account_ids: Vec<_> = self
            .prepared_nodes
            .iter()
            .map(|node| node.participant_info.account_id.clone())
            .collect();

        let (contract_state_watchers, shared_contract_state_tx) =
            ContractStateWatcher::test_batch(&account_ids, self.protocol_state);

        // Start each node's tokio tasks
        for (mut node, contract_state) in self.prepared_nodes.drain(..).zip(contract_state_watchers)
        {
            node.config.protocol = finalized_protocol_config.clone();
            let started = node
                .start(
                    routing_table.clone(),
                    &redis_container.pool(),
                    &initial_mesh_state,
                    contract_state,
                    shared_contract_state_tx.clone(),
                    self.use_preshared_triples,
                    self.presignature_stockpile,
                    Arc::clone(&msg_log),
                    Arc::clone(&rpc_actions),
                    &mut self.fixture_input,
                )
                .await;

            nodes.push(started);
        }

        TestMpcNetwork {
            redis_container,
            nodes,
            rpc_actions,
            msg_log,
            shared_contract_state: shared_contract_state_tx,
        }
    }

    fn build_protocol_config(&self) -> ProtocolConfig {
        let mut config = ProtocolConfig::default();
        config.presignature.max_presignatures = self.max_presignatures;
        config.presignature.min_presignatures = self.min_presignatures;
        config.triple.max_triples = self.max_triples;
        config.triple.min_triples = self.min_triples;
        config
    }

    async fn build_redis(&self, protocol_config: ProtocolConfig) -> Redis {
        let redis_container = redis().await;

        let cfg = crate::NodeConfig {
            nodes: self.prepared_nodes.len(),
            threshold: self.threshold,
            protocol: protocol_config,
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
        let keys = &self.fixture_input.keys;
        let public_key = keys.first_key_value().unwrap().1.public_key;
        self.shared_public_key = Some(public_key);

        self.protocol_state = ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: self.shared_public_key.unwrap(),
            participants: self.participants.clone(),
            candidates: self.candidates.clone(),
            join_votes: Votes::default(),
            leave_votes: Default::default(),
            threshold: self.threshold,
        });

        for node in &mut self.prepared_nodes {
            node.key_info = keys.get(&node.me).cloned();
        }

        self
    }

    /// Use triples from fixture input
    pub fn with_preshared_triples(mut self) -> Self {
        self.use_preshared_triples = true;
        self
    }

    /// Deal triples from cait-sith's central triple generation
    pub fn with_dealt_triples(mut self, triple_stockpile_factor: u32) -> Self {
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

    pub fn with_min_triples_stockpile(mut self, value: u32) -> Self {
        self.min_triples = value;
        self
    }

    pub fn with_max_triples_stockpile(mut self, value: u32) -> Self {
        self.max_triples = value;
        self
    }

    pub fn with_min_presignatures_stockpile(mut self, value: u32) -> Self {
        self.min_presignatures = value;
        self
    }

    pub fn with_max_presignatures_stockpile(mut self, value: u32) -> Self {
        self.max_presignatures = value;
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
            let mut modified;
            match protocol_state {
                Some(ProtocolState::Initializing(ref mut state)) => {
                    let entry = state
                        .pk_votes
                        .pk_votes
                        .entry(public_key.clone())
                        .or_default();

                    modified = entry.insert(self.me.clone());

                    if entry.len() >= state.threshold {
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
                        modified = true;
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
            key_info: None,
        }
    }

    async fn start(
        self,
        routing_table: HashMap<Participant, Sender<Ciphered>>,
        redis_pool: &deadpool_redis::Pool,
        init_mesh: &MeshState,
        contract_state: ContractStateWatcher,
        protocol_state_tx: watch::Sender<Option<ProtocolState>>,
        use_preshared_triples: bool,
        presignature_stockpile: bool,
        msg_log: Arc<Mutex<Vec<String>>>,
        rpc_actions: Arc<Mutex<HashSet<String>>>,
        fixture_input: &mut FixtureInput,
    ) -> TestMpcNode {
        let key_storage = if let Some(key) = self.key_info {
            secret_storage::test_store(0, key.private_share, key.public_key)
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

        if use_preshared_triples {
            // removing here because we can't clone a triple
            let my_shares = fixture_input.triples.remove(&self.me).unwrap();
            for (owner, triple_shares) in my_shares {
                for triple_share in triple_shares {
                    let mut slot = triple_storage.reserve(triple_share.id).await.unwrap();
                    slot.insert(triple_share, owner).await;
                }
            }
        }

        let presignature_storage =
            presignature_storage::init(redis_pool, &self.participant_info.account_id);

        if presignature_stockpile {
            // removing here because we can't clone a presignature
            let my_shares = fixture_input.presignatures.remove(&self.me).unwrap();
            for (owner, presignature_shares) in my_shares {
                for presignature_share in presignature_shares {
                    let mut slot = presignature_storage
                        .reserve(presignature_share.id)
                        .await
                        .unwrap();
                    slot.insert(presignature_share, owner).await;
                }
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
        let node = protocol::Node::new();
        let node_state = node.watch();

        // task running the protocol
        let _protocol_handle = tokio::spawn(protocol.run(
            node,
            MockGovernance {
                me: account_id.clone(),
                protocol_state_tx,
            },
            contract_state.clone(),
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
            contract_state,
            inbox,
        ));

        TestMpcNode {
            me: self.me,
            state: node_state,
            mesh: mesh_tx,
            config: config_tx,
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
