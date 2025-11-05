use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_node::protocol::state::NodeKeyInfo;
use near_account_id::AccountId;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Worker};

use std::collections::BTreeMap;
use std::future::{Future, IntoFuture};
use std::path::PathBuf;

use crate::containers::{self, DockerClient};
use crate::utils::dev_gen_indexed;
use crate::{execute, NodeConfig, Nodes};

use crate::cluster::Cluster;

const DOCKER_NETWORK: &str = "mpc_it_network";
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
    /// Load pregenerated keys for the given number of nodes from fixture data
    pub fn load(num_nodes: u32) -> Self {
        let data = match num_nodes {
            3 => include_str!("../mpc_fixture/3_nodes.json"),
            5 => include_str!("../mpc_fixture/5_nodes.json"),
            other => panic!("No pregenerated keys for {other} nodes available"),
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

        Self::Enabled {
            keys: fixture.keys,
            public_key,
        }
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
    pub program_address: Option<String>,
    prestockpile: Option<Prestockpile>,
    pub pregenerated_keys: PregeneratedKeys,
    pub use_ethereum: bool,
}

impl Default for ClusterSpawner {
    fn default() -> Self {
        let mut tmp_dir = execute::target_dir().expect("unable to locate target dir");
        tmp_dir.push("tmp");

        let cfg = NodeConfig {
            nodes: 3,
            threshold: 2,
            ..Default::default()
        };
        Self {
            docker: DockerClient::default(),
            release: true,
            env: ENV.to_string(),
            gcp_project_id: GCP_PROJECT_ID.to_string(),
            network: DOCKER_NETWORK.to_string(),
            accounts: Vec::with_capacity(cfg.nodes),
            participants: Vec::with_capacity(cfg.nodes),
            tmp_dir,

            cfg,
            wait_for_running: true,
            redis: None,
            worker: None,
            solana: None,
            program_address: None,
            prestockpile: Some(Prestockpile { multiplier: 4 }),
            pregenerated_keys: PregeneratedKeys::load(3), // Default: use pregenerated keys
            use_ethereum: false,
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
        // Update pregenerated keys if enabled
        if self.pregenerated_keys.is_enabled() {
            self.pregenerated_keys = PregeneratedKeys::load(nodes as u32);
        }
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
        // Update pregenerated keys if enabled and node count changed
        if self.pregenerated_keys.is_enabled() && self.cfg.nodes != cfg.nodes {
            self.pregenerated_keys = PregeneratedKeys::load(cfg.nodes as u32);
        }
        self.cfg = cfg;
        self
    }

    pub fn with_config(mut self, call: impl FnOnce(&mut NodeConfig)) -> Self {
        let old_nodes = self.cfg.nodes;
        call(&mut self.cfg);
        // Update pregenerated keys if enabled and node count changed
        if self.pregenerated_keys.is_enabled() && old_nodes != self.cfg.nodes {
            self.pregenerated_keys = PregeneratedKeys::load(self.cfg.nodes as u32);
        }
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

    /// Enable pregenerated keys (default behavior).
    /// This skips the 20+ second key generation phase by using hardcoded key shares.
    pub fn with_pregenerated_keys(mut self) -> Self {
        self.pregenerated_keys = PregeneratedKeys::load(self.cfg.nodes as u32);
        self
    }

    /// Disable pregenerated keys and generate keys fresh.
    /// This is slower but tests the full key generation protocol.
    pub fn without_pregenerated_keys(mut self) -> Self {
        self.pregenerated_keys = PregeneratedKeys::Disabled;
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
                total_timeout: 60,
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
            self.worker = Some(near_workspaces::sandbox().await?);
        }
        Ok(self.worker.as_ref().unwrap())
    }

    pub async fn take_worker(&mut self) -> Worker<Sandbox> {
        match self.worker.take() {
            Some(worker) => worker,
            None => near_workspaces::sandbox().await.unwrap(),
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
            let init_start = std::time::Instant::now();
            self = self.init_network().await?;
            tracing::info!("⏱️  init_network took: {:?}", init_start.elapsed());

            // Check if Solana is enabled and spawn if needed
            if self.cfg.sol.is_some() {
                // Start Solana test validator
                let solana_start = std::time::Instant::now();
                let solana = self.spawn_solana().await;
                tracing::info!("⏱️  spawn_solana took: {:?}", solana_start.elapsed());

                // Deploy the core contracts and get the program address
                let deploy_start = std::time::Instant::now();
                let program_address = if let Some(addr) = self.program_address.clone() {
                    // Use provided program address
                    addr
                } else {
                    // Deploy the contract and use the deployed program address
                    solana.deploy_contract().await?
                };
                tracing::info!("⏱️  deploy_contract took: {:?}", deploy_start.elapsed());

                let sol_config = solana.get_config(program_address);
                self.cfg.sol = Some(sol_config);

                // Store the Solana container for potential later use
                self.solana = Some(solana);
            }

            let run_start = std::time::Instant::now();
            let nodes = self.run().await?;
            tracing::info!("⏱️  run (spawn nodes) took: {:?}", run_start.elapsed());
            
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
                nodes,
            };

            if self.wait_for_running {
                let start = std::time::Instant::now();
                tracing::info!("⏱️  Starting wait for running state...");
                cluster.wait().running().nodes_running().await?;
                tracing::info!("⏱️  Wait for running took: {:?}", start.elapsed());

                if let Some(prestockpile) = self.prestockpile {
                    let start = std::time::Instant::now();
                    tracing::info!("⏱️  Starting prestockpile...");
                    cluster.prestockpile(prestockpile).await;
                    tracing::info!("⏱️  Prestockpile took: {:?}", start.elapsed());
                }
            }

            Ok(cluster)
        })
    }
}
