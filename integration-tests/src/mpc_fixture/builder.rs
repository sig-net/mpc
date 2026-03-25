//! Types used by tests directly to create an MPC network fixture and configure
//! it before it starts running.

use crate::containers::Redis;
use crate::mpc_fixture::fixture_interface::SharedOutput;
use crate::mpc_fixture::fixture_tasks::MessageFilter;
use crate::mpc_fixture::input::FixtureInput;
use crate::mpc_fixture::message_collector::CollectMessages;
use crate::mpc_fixture::mock_governance::MockGovernance;
use crate::mpc_fixture::{fixture_tasks, MpcFixture, MpcFixtureNode};
use cait_sith::protocol::Participant;
use mpc_contract::config::{min_to_ms, ProtocolConfig};
use mpc_contract::primitives::{
    CandidateInfo, Candidates as CandidatesById, ParticipantInfo, Participants as ParticipantsById,
};
use mpc_keys::hpke::{self, Ciphered};
use mpc_node::backlog::Backlog;
use mpc_node::config::{Config, LocalConfig, NetworkConfig};
use mpc_node::mesh::connection::NodeStatus;
use mpc_node::mesh::MeshState;
use mpc_node::protocol::contract::primitives::{Candidates, Participants, PkVotes, Votes};
use mpc_node::protocol::contract::{InitializingContractState, RunningContractState};
use mpc_node::protocol::message::{MessageInbox, MessageOutbox};
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::state::NodeKeyInfo;
use mpc_node::protocol::{self, MessageChannel, MpcSignProtocol, ProtocolState};
use mpc_node::rpc::ContractStateWatcher;
use mpc_node::rpc::RpcChannel;
use mpc_node::storage::{secret_storage, triple_storage::TriplePair, Options};
use near_sdk::AccountId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::{watch, Mutex, RwLock};

pub struct MpcFixtureBuilder {
    prepared_nodes: Vec<MpcFixtureNodeBuilder>,
    threshold: usize,
    shared_public_key: Option<mpc_crypto::PublicKey>,
    protocol_state: ProtocolState,
    participants: Participants,
    participants_by_id: ParticipantsById,
    candidates: Candidates,
    fixture_config: FixtureConfig,
    output: SharedOutput,
}

struct MpcFixtureNodeBuilder {
    me: Participant,
    candidate_info: CandidateInfo,
    participant_info: ParticipantInfo,
    config: Config,
    messaging: NodeMessagingBuilder,
    key_info: Option<NodeKeyInfo>,
}

/// Config options for the test setup.
///
/// This struct is used to change settings before building the final network.
struct FixtureConfig {
    input: FixtureInput,
    num_nodes: u32,

    use_preshared_triples: bool,
    presignature_stockpile: bool,

    node_min_triples: u32,
    network_max_triples: u32,
    node_min_presignatures: u32,
    network_max_presignatures: u32,

    signature_timeout_ms: u64,
    presignature_timeout_ms: u64,
    triple_timeout_ms: u64,
}

/// Context required to start a fixture node.
///
/// This is constructed right before a node starts, as it depends on builder
/// configs.
struct MockedNodeContext {
    protocol_config: ProtocolConfig,
    routing_table: HashMap<Participant, Sender<Ciphered>>,
    redis_pool: deadpool_redis::Pool,
    init_mesh: MeshState,
    contract_state: ContractStateWatcher,

    #[allow(dead_code)]
    node_account_id: AccountId,
}

/// Has the interface for a message channel but nothing is running, yet.
struct NodeMessagingBuilder {
    channel: MessageChannel,
    inbox: MessageInbox,
    outbox: MessageOutbox,

    /// allows dropping specific messages sent by this node
    filter: MessageFilter,
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
            num_nodes,
            use_preshared_triples: false,
            presignature_stockpile: false,
            node_min_triples: 10,
            network_max_triples: 10 * num_nodes * 4,
            node_min_presignatures: 10,
            network_max_presignatures: 10 * num_nodes * 4,
            signature_timeout_ms: 10_000,
            presignature_timeout_ms: 10_000,
            triple_timeout_ms: min_to_ms(10),
        }
    }
}

impl MpcFixtureBuilder {
    pub fn new(num_nodes: u32, threshold: usize) -> Self {
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
            output: SharedOutput::default(),
        }
    }

    pub async fn build(mut self) -> MpcFixture {
        let finalized_protocol_config = self.build_protocol_config();
        let redis_container = redis().await;
        let routing_table = self.build_routing_table();
        let initial_mesh_state = self.build_mesh_state();

        let output = self.output;
        let mut nodes = vec![];

        let account_ids: Vec<_> = self
            .prepared_nodes
            .iter()
            .map(|node| node.participant_info.account_id.clone())
            .collect();
        let (contract_state_watchers, shared_contract_state_tx) =
            ContractStateWatcher::test_batch(&account_ids, self.protocol_state);

        // Start each node's tokio tasks
        for (node, contract_state) in self.prepared_nodes.drain(..).zip(contract_state_watchers) {
            let node_context = MockedNodeContext {
                protocol_config: finalized_protocol_config.clone(),
                routing_table: routing_table.clone(),
                redis_pool: redis_container.pool(),
                init_mesh: initial_mesh_state.clone(),
                contract_state,
                node_account_id: node.participant_info.account_id.clone(),
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
        config.signature.generation_timeout = self.fixture_config.signature_timeout_ms;
        config.presignature.max_presignatures = self.fixture_config.network_max_presignatures;
        config.presignature.min_presignatures = self.fixture_config.node_min_presignatures;
        config.presignature.generation_timeout = self.fixture_config.presignature_timeout_ms;
        config.triple.max_triples = self.fixture_config.network_max_triples;
        config.triple.min_triples = self.fixture_config.node_min_triples;
        config.triple.generation_timeout = self.fixture_config.triple_timeout_ms;
        config
    }

    /// Build a routing table: Participant -> msg_tx
    fn build_routing_table(&self) -> HashMap<Participant, Sender<Ciphered>> {
        let mut routing_table: HashMap<Participant, Sender<Ciphered>> = HashMap::new();
        for node in &self.prepared_nodes {
            let participant = self
                .participants_by_id
                .account_to_participant_id
                .get(&node.participant_info.account_id)
                .unwrap();
            routing_table.insert(
                Participant::from(*participant),
                node.messaging.channel.inbox.clone(),
            );
        }
        routing_table
    }

    fn build_mesh_state(&self) -> MeshState {
        // mark all participants as already active when the network starts
        let mut mesh_state = MeshState::default();
        for (participant, info) in self.participants.iter() {
            mesh_state.update(*participant, NodeStatus::Active, info.clone());
        }
        mesh_state
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

    /// Set the per-node minimum number of triples to maintain.
    /// Each node will keep generating triples until it owns at least this many.
    /// Also updates the network-wide max to `value * num_nodes * 4`.
    pub fn with_node_min_triples(mut self, value: u32) -> Self {
        self.fixture_config.node_min_triples = value;
        self.fixture_config.network_max_triples = value * self.fixture_config.num_nodes * 4;
        self
    }

    /// Set the per-node minimum number of presignatures to maintain.
    /// Each node will keep generating presignatures until it owns at least this many.
    /// Also updates the network-wide max to `value * num_nodes * 4`.
    pub fn with_node_min_presignatures(mut self, value: u32) -> Self {
        self.fixture_config.node_min_presignatures = value;
        self.fixture_config.network_max_presignatures = value * self.fixture_config.num_nodes * 4;
        self
    }

    /// Set protocol config
    pub fn with_signature_timeout_ms(mut self, ms: u64) -> Self {
        self.fixture_config.signature_timeout_ms = ms;
        self
    }

    /// Set protocol config
    pub fn with_triple_timeout_ms(mut self, ms: u64) -> Self {
        self.fixture_config.triple_timeout_ms = ms;
        self
    }

    /// Set protocol config
    pub fn with_presignature_timeout_ms(mut self, ms: u64) -> Self {
        self.fixture_config.presignature_timeout_ms = ms;
        self
    }

    /// Specify a method that acts as message filter for all sent messages the given node.
    pub fn with_outgoing_message_filter(mut self, node_idx: usize, filter: MessageFilter) -> Self {
        self.prepared_nodes[node_idx].messaging.filter = filter;
        self
    }

    /// Specify a method that acts as message filter for all sent messages the given node.
    pub fn with_message_collector(
        mut self,
        collector: Arc<Mutex<dyn CollectMessages + Send>>,
    ) -> Self {
        self.output.msg_log = collector;
        self
    }

    /// Short-hand for creating an MPC setup that's prepared to produce triples.
    ///
    /// This setup will not attempt to stockpile presignatures.
    pub fn only_generate_triples(self) -> Self {
        self.with_preshared_key().with_node_min_presignatures(0)
    }

    /// Short-hand for creating an MPC setup that's prepared to produce presignatures.
    ///
    /// This setup will not attempt to stockpile triples.
    pub fn only_generate_presignatures(self) -> Self {
        self.with_preshared_key()
            .with_preshared_triples()
            .with_node_min_triples(0)
    }

    /// Short-hand for creating an MPC setup that's prepared to produce signatures.
    ///
    /// This setup will not attempt to stockpile triples or presignatures.
    pub fn only_generate_signatures(self) -> Self {
        self.with_preshared_key()
            .with_presignature_stockpile()
            .with_node_min_triples(0)
            .with_node_min_presignatures(0)
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
        let (inbox, outbox, channel) = MessageChannel::new();
        let messaging = NodeMessagingBuilder {
            inbox,
            outbox,
            channel,
            filter: Box::new(|_| true),
        };

        MpcFixtureNodeBuilder {
            me: Participant::from(index),
            candidate_info,
            participant_info,
            config,
            messaging,
            key_info: None,
        }
    }

    async fn start(
        mut self,
        context: MockedNodeContext,
        protocol_state_tx: watch::Sender<Option<ProtocolState>>,
        fixture_config: &mut FixtureConfig,
        shared_output: &SharedOutput,
    ) -> MpcFixtureNode {
        // overwrite the default protocol config with the built config
        self.config.protocol = context.protocol_config.clone();

        // build storage
        let storage = self.build_storage(&context, fixture_config).await;
        let triple_storage = storage.triple_storage.clone();
        let presignature_storage = storage.presignature_storage.clone();

        // prepare all channels for the node
        let (sign_tx, sign_rx) = mpsc::channel(1024);
        const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
        let (rpc_tx, rpc_rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        let rpc_channel = RpcChannel { tx: rpc_tx };
        let (mesh_tx, mesh_rx) = watch::channel(context.init_mesh.clone());
        let (config_tx, config_rx) = watch::channel(self.config);

        let channels = protocol::test_setup::TestProtocolChannels {
            sign_rx: Arc::new(RwLock::new(sign_rx)),
            msg_channel: self.messaging.channel.clone(),
            rpc_channel,
            config: config_rx.clone(),
            mesh_state: mesh_rx.clone(),
        };

        // We have to start the inbox job before calling
        // `MpcSignProtocol::new_test` or else subscribing to messages will
        // await the subscription response forever.
        let _inbox_handle = tokio::spawn(
            self.messaging
                .inbox
                .run(config_rx.clone(), context.contract_state.clone()),
        );

        let protocol = MpcSignProtocol::new_test(
            self.participant_info.account_id.clone(),
            storage,
            channels,
            context.contract_state.clone(),
        )
        .await;

        // start task running the protocol
        let account_id = protocol.my_account_id().clone();
        let node = protocol::Node::new();
        let node_state = node.watch();
        let _protocol_handle = tokio::spawn(protocol.run(
            node,
            MockGovernance {
                me: account_id.clone(),
                protocol_state_tx,
            },
            context.contract_state,
            mesh_rx.clone(),
        ));

        // handle outbox messages manually, we want them before they are
        // encrypted and we want to send them directly to other node's inboxes
        let _mock_network_handle = fixture_tasks::test_mock_network(
            context.routing_table,
            shared_output,
            self.messaging.outbox,
            rpc_rx,
            mesh_tx.clone(),
            config_tx.clone(),
            self.messaging.filter,
        );

        let mut node = MpcFixtureNode {
            me: self.me,
            state: node_state,
            mesh: mesh_tx,
            config: config_tx,
            sign_tx,
            msg_channel: self.messaging.channel,
            triple_storage,
            presignature_storage,
            backlog: Backlog::new(),
            web_handle: None,
        };

        node.start_web_interface(self.participant_info.account_id);

        node
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
            TriplePair::storage(&context.redis_pool, &self.participant_info.account_id);

        if fixture_config.use_preshared_triples {
            // removing here because we can't clone a triple
            let my_shares = fixture_config.input.triples.remove(&self.me).unwrap();
            for (owner, triple_shares) in my_shares {
                for mut pair in triple_shares {
                    let pair_id = pair.id;
                    if pair.holders.is_none() {
                        pair.holders = Some(pair.triple0.public.participants.clone());
                    }
                    let mut slot = triple_storage.reserve(pair_id).await.unwrap();
                    slot.insert(pair, owner).await;
                }
            }
        }

        let presignature_storage =
            Presignature::storage(&context.redis_pool, &self.participant_info.account_id);

        if fixture_config.presignature_stockpile {
            // removing here because we can't clone a presignature
            let my_shares = fixture_config.input.presignatures.remove(&self.me).unwrap();
            for (owner, presignature_shares) in my_shares {
                for mut presignature_share in presignature_shares {
                    if presignature_share.holders.is_none() {
                        presignature_share.holders = Some(presignature_share.participants.clone());
                    }
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
