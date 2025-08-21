//! Types used by tests directly to create an MPC network fixture and configure
//! it before it starts running.

use crate::containers::Redis;
use crate::mpc_fixture::fixture_interface::SharedOutput;
use crate::mpc_fixture::input::FixtureInput;
use crate::mpc_fixture::mock_governance::MockGovernance;
use crate::mpc_fixture::{fixture_tasks, MpcFixture, MpcFixtureNode};
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
use mpc_node::protocol::state::NodeKeyInfo;
use mpc_node::protocol::{self, MessageChannel, MpcSignProtocol, ProtocolState, SignQueue};
use mpc_node::rpc::ContractStateWatcher;
use mpc_node::rpc::RpcChannel;
use mpc_node::storage::{presignature_storage, secret_storage, triple_storage, Options};
use near_sdk::AccountId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::watch;
use tokio::sync::RwLock;

pub struct MpcFixtureBuilder {
    prepared_nodes: Vec<MpcFixtureNodeBuilder>,
    threshold: usize,
    shared_public_key: Option<mpc_crypto::PublicKey>,
    protocol_state: ProtocolState,
    participants: Participants,
    participants_by_id: ParticipantsById,
    candidates: Candidates,
    fixture_config: FixtureConfig,
}

struct MpcFixtureNodeBuilder {
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

/// Config options for the test setup.
///
/// This struct is used to change settings before building the final network.
struct FixtureConfig {
    input: FixtureInput,

    use_preshared_triples: bool,
    presignature_stockpile: bool,

    min_triples: u32,
    max_triples: u32,
    min_presignatures: u32,
    max_presignatures: u32,
}

/// Context required to start a fixture node.
///
/// This is constructed right before a node starts, as it depends on builder
/// configs.
struct MockedNodeContext {
    routing_table: HashMap<Participant, Sender<Ciphered>>,
    redis_pool: deadpool_redis::Pool,
    init_mesh: MeshState,
    contract_state: ContractStateWatcher,
}

impl Default for MpcFixtureBuilder {
    fn default() -> Self {
        Self::new(3, 2)
    }
}

impl FixtureConfig {
    fn new(num_nodes: u32) -> Self {
        Self {
            input: FixtureInput::load(num_nodes),
            use_preshared_triples: false,
            presignature_stockpile: false,
            min_triples: 10,
            max_triples: 100,
            min_presignatures: 10,
            max_presignatures: 100,
        }
    }
}

impl MpcFixtureBuilder {
    pub fn new(num_nodes: u32, threshold: usize) -> Self {
        // This is a bit of a weird place to install the subscriber but every
        // test needs to call it somewhere. Since tests will usually call this
        // before doing anything interesting, might as well do it here.
        crate::utils::init_tracing_log();

        let prepared_nodes: Vec<_> = (0..num_nodes).map(MpcFixtureNodeBuilder::new).collect();

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

        MpcFixtureBuilder {
            threshold,
            prepared_nodes,
            shared_public_key: None,
            protocol_state,
            participants,
            participants_by_id,
            candidates,
            fixture_config: FixtureConfig::new(num_nodes),
        }
    }

    pub async fn build(mut self) -> MpcFixture {
        let finalized_protocol_config = self.build_protocol_config();
        let redis_container = redis().await;

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

        let output = SharedOutput::default();
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

            let node_context = MockedNodeContext {
                routing_table: routing_table.clone(),
                redis_pool: redis_container.pool(),
                init_mesh: initial_mesh_state.clone(),
                contract_state,
            };

            let started = node
                .start(
                    node_context,
                    shared_contract_state_tx.clone(),
                    &mut self.fixture_config,
                    &output,
                )
                .await;

            nodes.push(started);
        }

        MpcFixture {
            redis_container,
            nodes,
            output,
            shared_contract_state: shared_contract_state_tx,
        }
    }

    fn build_protocol_config(&self) -> ProtocolConfig {
        let mut config = ProtocolConfig::default();
        config.presignature.max_presignatures = self.fixture_config.max_presignatures;
        config.presignature.min_presignatures = self.fixture_config.min_presignatures;
        config.triple.max_triples = self.fixture_config.max_triples;
        config.triple.min_triples = self.fixture_config.min_triples;
        config
    }

    pub fn with_preshared_key(mut self) -> Self {
        let keys = &self.fixture_config.input.keys;
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
        self.fixture_config.use_preshared_triples = true;
        self
    }

    /// Use presignatures from fixture input
    pub fn with_presignature_stockpile(mut self) -> Self {
        self.fixture_config.presignature_stockpile = true;
        self
    }

    /// Set protocol config
    pub fn with_min_triples_stockpile(mut self, value: u32) -> Self {
        self.fixture_config.min_triples = value;
        self
    }

    /// Set protocol config
    pub fn with_max_triples_stockpile(mut self, value: u32) -> Self {
        self.fixture_config.max_triples = value;
        self
    }

    /// Set protocol config
    pub fn with_min_presignatures_stockpile(mut self, value: u32) -> Self {
        self.fixture_config.min_presignatures = value;
        self
    }

    /// Set protocol config
    pub fn with_max_presignatures_stockpile(mut self, value: u32) -> Self {
        self.fixture_config.max_presignatures = value;
        self
    }
}

impl MpcFixtureNodeBuilder {
    fn new(index: u32) -> Self {
        let account_id: AccountId = format!("p-{index}").parse().unwrap();
        let url = format!("fake{index}.url");

        let cipher_sk = hpke::SecretKey::from_bytes(&[index as u8; 32]);
        let cipher_pk = cipher_sk.public_key().to_bytes();

        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, account_id.as_ref());
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

        MpcFixtureNodeBuilder {
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
        context: MockedNodeContext,
        protocol_state_tx: watch::Sender<Option<ProtocolState>>,
        fixture_config: &mut FixtureConfig,
        shared_output: &SharedOutput,
    ) -> MpcFixtureNode {
        let storage = self.build_storage(&context, fixture_config).await;
        let triple_storage = storage.triple_storage.clone();
        let presignature_storage = storage.presignature_storage.clone();

        let (sign_tx, sign_rx) = SignQueue::channel();
        const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
        let (rpc_tx, rpc_rx) = tokio::sync::mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        let rpc_channel = RpcChannel { tx: rpc_tx };
        let (mesh_tx, mesh_rx) = watch::channel(context.init_mesh.clone());
        let (config_tx, config_rx) = watch::channel(self.config);
        let inbox = Arc::clone(self.msg_channel.inbox());

        let channels = protocol::test_setup::TestProtocolChannels {
            sign_rx: Arc::new(RwLock::new(sign_rx)),
            msg_channel: self.msg_channel,
            rpc_channel,
            config: config_rx.clone(),
            mesh_state: mesh_rx.clone(),
        };

        let protocol =
            MpcSignProtocol::new_test(self.participant_info.account_id.clone(), storage, channels);

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
            context.contract_state.clone(),
            config_rx.clone(),
            mesh_rx.clone(),
        ));

        let _mock_network_handle = fixture_tasks::test_mock_network(
            context.routing_table,
            shared_output,
            self.msg_rx,
            rpc_rx,
            mesh_tx.clone(),
            config_tx.clone(),
        );

        let _message_executor_handle = tokio::spawn(fixture_tasks::test_message_executor(
            config_rx,
            context.contract_state,
            inbox,
        ));

        MpcFixtureNode {
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

    /// Build a node's triple, presignature, and secret storage.
    async fn build_storage(
        &self,
        context: &MockedNodeContext,
        fixture_config: &mut FixtureConfig,
    ) -> protocol::test_setup::TestProtocolStorage {
        let secret_storage = if let Some(key) = &self.key_info {
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

        let triple_storage =
            triple_storage::init(&context.redis_pool, &self.participant_info.account_id);

        if fixture_config.use_preshared_triples {
            // removing here because we can't clone a triple
            let my_shares = fixture_config.input.triples.remove(&self.me).unwrap();
            for (owner, triple_shares) in my_shares {
                for triple_share in triple_shares {
                    let mut slot = triple_storage.reserve(triple_share.id).await.unwrap();
                    slot.insert(triple_share, owner).await;
                }
            }
        }

        let presignature_storage =
            presignature_storage::init(&context.redis_pool, &self.participant_info.account_id);

        if fixture_config.presignature_stockpile {
            // removing here because we can't clone a presignature
            let my_shares = fixture_config.input.presignatures.remove(&self.me).unwrap();
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

        protocol::test_setup::TestProtocolStorage {
            secret_storage,
            triple_storage,
            presignature_storage,
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
