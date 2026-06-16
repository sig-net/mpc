use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_node::protocol::state::NodeKeyInfo;
use near_account_id::AccountId;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Worker};

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::{Future, IntoFuture};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::containers::{self, DockerClient};
use crate::utils::dev_gen_indexed;
use crate::{execute, NodeBinarySource, NodeConfig, Nodes};

use crate::cluster::Cluster;

thread_local! {
    static THREAD_NETWORK_NAME: RefCell<Option<String>> = const { RefCell::new(None) };
    static THREAD_NETWORK_CLEANUP: RefCell<Option<ThreadNetworkCleanup>> = const { RefCell::new(None) };
}

static NEXT_NETWORK_SLOT: AtomicUsize = AtomicUsize::new(0);

struct ThreadNetworkCleanup {
    docker: DockerClient,
    network: String,
}

impl Drop for ThreadNetworkCleanup {
    fn drop(&mut self) {
        self.docker.best_effort_remove_network(self.network.clone());
    }
}

fn thread_network_name(docker: &DockerClient) -> String {
    THREAD_NETWORK_NAME.with(|name_cell| {
        let mut name = name_cell.borrow_mut();
        if let Some(name) = name.as_ref() {
            return name.clone();
        }

        let slot = NEXT_NETWORK_SLOT.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let network = format!("mpc_it_{}_{}", pid, slot);
        THREAD_NETWORK_CLEANUP.with(|cleanup_cell| {
            *cleanup_cell.borrow_mut() = Some(ThreadNetworkCleanup {
                docker: docker.clone(),
                network: network.clone(),
            });
        });
        *name = Some(network.clone());
        network
    })
}

const GCP_PROJECT_ID: &str = "multichain-integration";
const ENV: &str = "integration-tests";

/// Configuration for pregenerated keys to skip the 20+ second key generation phase.
///
/// When enabled, uses hardcoded key shares from fixture data to start nodes in
/// Running state immediately, avoiding the expensive MPC key generation protocol.
#[derive(Clone)]
pub enum PregeneratedKeys {
    /// Generate keys fresh during cluster setup (slow but tests full protocol)
    Disabled,
    /// Use pregenerated keys from fixture data (fast, skips keygen)
    Enabled {
        /// Key shares for each participant, indexed by participant ID
        keys: BTreeMap<Participant, NodeKeyInfo>,
        /// The shared public key for all participants
        public_key: mpc_crypto::PublicKey,
    },
}

impl PregeneratedKeys {
    /// Load pregenerated keys for the given number of nodes and threshold from fixture data.
    pub fn load(num_nodes: usize, threshold: usize) -> Option<Self> {
        let data = match (num_nodes, threshold) {
            (3, 2) => include_str!("../mpc_fixture/3_nodes_2_threshold.json"),
            (5, 4) => include_str!("../mpc_fixture/5_nodes_4_threshold.json"),
            _ => {
                tracing::warn!("No pregenerated keys for {num_nodes} nodes, threshold {threshold}");
                return None;
            }
        };

        #[derive(serde::Deserialize)]
        struct FixtureData {
            keys: BTreeMap<Participant, NodeKeyInfo>,
        }

        let fixture: FixtureData = serde_json::from_str(data)
            .expect("Failed to parse pregenerated keys from fixture data");

        let public_key = fixture
            .keys
            .values()
            .next()
            .expect("No keys in fixture data")
            .public_key;

        Some(Self::Enabled {
            keys: fixture.keys,
            public_key,
        })
    }

    /// Check if keys are enabled
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }

    /// Get the key info for a specific participant
    pub fn get(&self, participant: &Participant) -> Option<&NodeKeyInfo> {
        match self {
            Self::Disabled => None,
            Self::Enabled { keys, .. } => keys.get(participant),
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> Option<mpc_crypto::PublicKey> {
        match self {
            Self::Disabled => None,
            Self::Enabled { public_key, .. } => Some(*public_key),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Disabled => 0,
            Self::Enabled { keys, .. } => keys.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct Prestockpile {
    /// Multiplier to increase the stockpile such that stockpiling presignatures does not trigger
    /// the number of triples to be lower than the stockpile limit.
    pub multiplier: u32,
}
pub struct ClusterSpawner {
    pub docker: DockerClient,
    pub release: bool,
    pub env: String,
    pub gcp_project_id: String,
    pub network: String,
    pub accounts: Vec<Account>,
    pub participants: Vec<Participant>,
    pub tmp_dir: PathBuf,

    pub cfg: NodeConfig,
    pub wait_for_running: bool,
    pub redis: Option<containers::Redis>,
    pub worker: Option<Worker<Sandbox>>,
    pub solana: Option<containers::Solana>,
    pub canton: Option<crate::canton::CantonSandbox>,
    pub program_address: Option<String>,
    prestockpile: Option<Prestockpile>,
    pub pregenerated_keys: PregeneratedKeys,
    pub use_ethereum: bool,
    /// Tracks which binary source to use for each node index
    pub node_binary_sources: Vec<NodeBinarySource>,
}

impl Default for ClusterSpawner {
    fn default() -> Self {
        let docker = DockerClient::default();
        let network = thread_network_name(&docker);

        let mut tmp_dir = execute::target_dir().expect("unable to locate target dir");
        // Create a unique temporary directory for this test run to avoid conflicts
        tmp_dir.push(format!("tmp_{}", network));

        let nodes = 3;
        let threshold = 2;
        let cfg = NodeConfig {
            nodes,
            threshold,
            ..Default::default()
        };

        Self {
            docker,
            release: true,
            env: ENV.to_string(),
            gcp_project_id: GCP_PROJECT_ID.to_string(),
            network,
            accounts: Vec::with_capacity(cfg.nodes),
            participants: Vec::with_capacity(cfg.nodes),
            tmp_dir,

            cfg,
            wait_for_running: true,
            redis: None,
            worker: None,
            solana: None,
            canton: None,
            program_address: None,
            prestockpile: Some(Prestockpile { multiplier: 4 }),
            pregenerated_keys: PregeneratedKeys::load(nodes, threshold).unwrap(),
            use_ethereum: false,
            node_binary_sources: vec![NodeBinarySource::CurrentCode; nodes],
        }
    }
}

impl ClusterSpawner {
    pub async fn init_network(self) -> anyhow::Result<Self> {
        self.docker.create_network(&self.network).await?;
        Ok(self)
    }

    pub fn nodes(mut self, nodes: usize) -> Self {
        self.cfg.nodes = nodes;
        // Resize the binary sources vector to match
        self.node_binary_sources
            .resize(nodes, NodeBinarySource::CurrentCode);
        self
    }

    /// Add mainnet nodes to the cluster using the tagged binary under target/compat/mainnet.
    pub fn mainnet_nodes(mut self, count: usize) -> Self {
        let current_len = self.node_binary_sources.len();
        self.node_binary_sources
            .extend((0..count).map(|_| NodeBinarySource::Mainnet));
        self.cfg.nodes = current_len + count;
        self
    }

    /// Add testnet nodes to the cluster using the tagged binary under target/compat/testnet.
    pub fn testnet_nodes(mut self, count: usize) -> Self {
        let current_len = self.node_binary_sources.len();
        self.node_binary_sources
            .extend((0..count).map(|_| NodeBinarySource::Testnet));
        self.cfg.nodes = current_len + count;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.cfg.threshold = threshold;
        self
    }

    pub fn protocol(mut self, protocol: ProtocolConfig) -> Self {
        self.cfg.protocol = protocol;
        self
    }

    pub fn config(mut self, cfg: NodeConfig) -> Self {
        self.cfg = cfg;
        self
    }

    pub fn with_config(mut self, call: impl FnOnce(&mut NodeConfig)) -> Self {
        call(&mut self.cfg);
        self
    }

    /// Do not wait for the nodes to be running.
    pub fn disable_wait_running(mut self) -> Self {
        self.wait_for_running = false;
        self
    }

    pub fn disable_prestockpile(mut self) -> Self {
        self.prestockpile = None;
        self
    }

    pub fn prestockpile(mut self, multiplier: u32) -> Self {
        self.prestockpile = Some(Prestockpile { multiplier });
        self
    }

    /// Disable pregenerated keys and generate keys fresh.
    /// This is slower but tests the full key generation protocol.
    pub fn without_pregenerated_keys(mut self) -> Self {
        self.pregenerated_keys = PregeneratedKeys::Disabled;
        self
    }

    fn load_pregenerated_keys(mut self) -> Self {
        if self.pregenerated_keys.is_enabled() && self.pregenerated_keys.len() != self.cfg.nodes {
            self.pregenerated_keys = PregeneratedKeys::load(self.cfg.nodes, self.cfg.threshold)
                .unwrap_or(PregeneratedKeys::Disabled);
        }
        self
    }

    /// Configures the cluster to spawn with Solana sandbox.
    /// This method sets up a Solana test validator and configures the SolConfig.
    pub fn solana(mut self) -> Self {
        // Enable Solana by setting a placeholder if not already configured
        if self.cfg.sol.is_none() {
            self.cfg.sol = Some(mpc_node::indexer_sol::SolConfig {
                account_sk: String::new(),      // Will be filled in later
                rpc_http_url: String::new(),    // Will be filled in later
                rpc_ws_url: String::new(),      // Will be filled in later
                program_address: String::new(), // Will be filled in later
            });
        }
        self
    }

    /// Set the Solana program address to watch for events.
    pub fn program_address(mut self, address: String) -> Self {
        self.program_address = Some(address);
        self
    }

    pub fn env(mut self, env: &str) -> Self {
        self.env = env.to_string();
        self
    }

    pub fn gcp_project_id(mut self, gcp_project_id: &str) -> Self {
        self.gcp_project_id = gcp_project_id.to_string();
        self
    }

    pub fn network(mut self, network: &str) -> Self {
        self.network = network.to_string();
        self
    }

    pub fn ethereum(mut self) -> Self {
        self.use_ethereum = true;
        self
    }

    pub fn canton(mut self) -> Self {
        if self.cfg.canton.is_none() {
            self.cfg.canton = Some(mpc_node::indexer_canton::CantonConfig {
                json_api_url: String::new(),
                json_api_ws_url: String::new(),
                auth: mpc_node::indexer_canton::CantonAuthConfig {
                    token_url: String::new(),
                    client_id: String::new(),
                    client_secret: String::new(),
                    audience: String::new(),
                    scope: None,
                },
                ledger_api_user: String::new(),
                party_id: String::new(),
                signer_contract_id: String::new(),
                signer_template_id: String::new(),
            });
        }
        self
    }

    pub fn debug_node(&mut self) -> &mut Self {
        self.release = false;
        self
    }

    pub fn account_id(&self, idx: usize) -> AccountId {
        if idx >= self.accounts.len() {
            panic!("Account index out of bounds: {idx}");
        }
        self.accounts[idx].id().clone()
    }

    /// Create accounts for the nodes
    pub async fn create_accounts(&mut self, worker: &Worker<Sandbox>) {
        if self.accounts.len() >= self.cfg.nodes {
            // accounts already created, don't create anymore.
            return;
        }

        for i in 0..self.cfg.nodes {
            self.accounts
                .push(dev_gen_indexed(worker, i).await.unwrap());
        }
        self.participants
            .extend((0..self.accounts.len() as u32).map(Participant::from));
    }

    pub async fn spawn_redis(&self) -> containers::Redis {
        containers::Redis::run(self).await
    }

    pub async fn spawn_solana(&self) -> containers::Solana {
        containers::Solana::run().await
    }

    /// Prespawns a redis instance where we're able to make use of it before the nodes are spun
    /// up and are in running phase. This redis instance will be reused when the whole environment
    /// is setup.
    pub async fn prespawn_redis(&mut self) -> &containers::Redis {
        self.redis = Some(self.spawn_redis().await);
        self.redis.as_ref().unwrap()
    }

    /// Prespawns a Solana test validator instance for integration testing.
    pub async fn prespawn_solana(&mut self) -> &containers::Solana {
        self.solana = Some(self.spawn_solana().await);
        self.solana.as_ref().unwrap()
    }

    /// Grabs the underlying redis instance that was prespawned, or if not prespawned, create a
    /// new one from start up.
    pub async fn take_redis(&mut self) -> containers::Redis {
        match self.redis.take() {
            Some(redis) => redis,
            None => self.spawn_redis().await,
        }
    }

    /// Grabs the underlying Solana instance that was prespawned, or if not prespawned, create a
    /// new one from start up.
    pub async fn take_solana(&mut self) -> Option<containers::Solana> {
        self.solana.take()
    }

    pub async fn prespawn_sandbox(&mut self) -> anyhow::Result<&Worker<Sandbox>> {
        if self.worker.is_none() {
            self.worker = Some(spawn_sandbox_with_retry().await?);
        }
        Ok(self.worker.as_ref().unwrap())
    }

    pub async fn take_worker(&mut self) -> Worker<Sandbox> {
        match self.worker.take() {
            Some(worker) => worker,
            None => spawn_sandbox_with_retry()
                .await
                .expect("failed to spawn sandbox"),
        }
    }

    pub async fn presetup(&mut self) -> anyhow::Result<&containers::Redis> {
        let worker = self.prespawn_sandbox().await?.clone();
        self.create_accounts(&worker).await;
        Ok(self.prespawn_redis().await)
    }

    pub async fn run(&mut self) -> anyhow::Result<Nodes> {
        crate::run(self).await
    }

    pub async fn dry_run(&mut self) -> anyhow::Result<crate::Context> {
        crate::dry_run(self).await
    }
}

impl IntoFuture for ClusterSpawner {
    type Output = anyhow::Result<Cluster>;
    type IntoFuture = std::pin::Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            self = self.load_pregenerated_keys().init_network().await?;

            // Check if Solana is enabled and spawn if needed
            if self.cfg.sol.is_some() {
                // Start Solana test validator
                let solana = self.spawn_solana().await;

                // Deploy the core contracts and get the program address
                let program_address = if let Some(addr) = self.program_address.clone() {
                    // Use provided program address
                    addr
                } else {
                    // Deploy the contract and use the deployed program address
                    solana.deploy_contract().await?
                };

                let sol_config = solana.get_config(program_address);
                self.cfg.sol = Some(sol_config);

                // Store the Solana container for potential later use
                self.solana = Some(solana);
            }

            if self.cfg.canton.is_some() && self.canton.is_none() {
                let sandbox = crate::canton::CantonSandbox::run().await?;
                self.cfg.canton = Some(sandbox.get_config());
                self.canton = Some(sandbox);
            }

            let nodes = self.run().await?;
            let connector = near_jsonrpc_client::JsonRpcClient::new_client();
            let jsonrpc_client = connector.connect(nodes.ctx().worker.rpc_addr());
            let rpc_client = near_fetch::Client::from_client(jsonrpc_client);

            let cluster = Cluster {
                cfg: self.cfg,
                rpc_client,
                http_client: reqwest::Client::default(),
                docker_client: self.docker,
                account_idx: nodes.len(),
                solana: self.solana.take(),
                canton: self.canton.take(),
                nodes,
            };

            if self.wait_for_running {
                cluster.wait().running().nodes_running().await?;

                if let Some(prestockpile) = self.prestockpile {
                    cluster.prestockpile(prestockpile).await;
                }
            }

            Ok(cluster)
        })
    }
}

/// Spawn a near sandbox with retry logic to handle potential transient failures (i.e., due to CPU contention)
async fn spawn_sandbox_with_retry() -> anyhow::Result<Worker<Sandbox>> {
    let mut last_err = None;
    for attempt in 1..=5 {
        match near_workspaces::sandbox().await {
            Ok(worker) => return Ok(worker),
            Err(e) => {
                tracing::warn!(
                    attempt,
                    "failed to spawn near sandbox within timeout, retrying: {e}"
                );
                last_err = Some(e);
                // Give the OS a moment to breathe before trying again
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
    anyhow::bail!(
        "failed to spawn near sandbox after 5 attempts: {:?}",
        last_err
    )
}
