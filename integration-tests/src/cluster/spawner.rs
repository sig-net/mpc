use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_node::protocol::state::NodeKeyInfo;
use near_account_id::AccountId;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Worker};
use std::sync::Arc;
use once_cell::sync::Lazy;
use tokio::sync::Mutex as AsyncMutex;

use std::collections::BTreeMap;
use std::future::{Future, IntoFuture};
use std::path::PathBuf;

use crate::containers::{self, DockerClient};
use crate::utils::dev_gen_indexed;
use crate::{execute, NodeConfig, Nodes};

use crate::cluster::Cluster;
use libc;

// Global singletons used by the `parallel` feature to share test infrastructure.
static GLOBAL_REDIS: Lazy<AsyncMutex<Option<Arc<containers::Redis>>>> = Lazy::new(|| AsyncMutex::new(None));
static GLOBAL_WORKER: Lazy<AsyncMutex<Option<Arc<Worker<Sandbox>>>>> = Lazy::new(|| AsyncMutex::new(None));
static GLOBAL_SOLANA: Lazy<AsyncMutex<Option<Arc<containers::Solana>>>> = Lazy::new(|| AsyncMutex::new(None));
static GLOBAL_ETH: Lazy<AsyncMutex<Option<Arc<containers::EthereumSandbox>>>> = Lazy::new(|| AsyncMutex::new(None));

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
    pub fn load(num_nodes: usize) -> Option<Self> {
        let data = match num_nodes {
            3 => include_str!("../mpc_fixture/3_nodes.json"),
            5 => include_str!("../mpc_fixture/5_nodes.json"),
            other => {
                tracing::warn!("No pregenerated keys for {other} nodes available");
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
    pub redis: Option<Arc<containers::Redis>>,
    pub worker: Option<Arc<Worker<Sandbox>>>,
    pub solana: Option<Arc<containers::Solana>>,
    pub ethereum: Option<Arc<containers::EthereumSandbox>>,
    pub program_address: Option<String>,
    prestockpile: Option<Prestockpile>,
    pub pregenerated_keys: PregeneratedKeys,
    pub use_ethereum: bool,
}

/// Shutdown and clear any global instances created for the `parallel` feature.
///
/// This attempts a graceful shutdown of containers and processes and then clears
/// the module-level references so new instances can be created by later tests.
pub async fn shutdown_global_instances() {
    // Stop Ethereum sandbox if present
    {
        let mut guard = GLOBAL_ETH.lock().await;
        if let Some(sandbox) = guard.take() {
            tracing::info!("stopping global ethereum sandbox: {}", sandbox.external_http_endpoint);
            if let Err(e) = sandbox.container.stop().await {
                tracing::warn!("failed to stop ethereum sandbox container: {:?}", e);
            }
        }
    }

    // Stop Solana process if present
    {
        let mut guard = GLOBAL_SOLANA.lock().await;
        if let Some(solana) = guard.take() {
            tracing::info!("stopping global solana test-validator: {}", solana.rpc_address);
            // best-effort: if we can get an OS pid, send SIGTERM
            let pid = solana.process.id();
            if pid != 0 {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        }
    }

    // Stop Redis container if present
    {
        let mut guard = GLOBAL_REDIS.lock().await;
        if let Some(redis) = guard.take() {
            tracing::info!("stopping global redis instance: {}", redis.internal_address);
            if let Err(e) = redis.container.stop().await {
                tracing::warn!("failed to stop redis container: {:?}", e);
            }
        }
    }

    // Clear worker (sandbox) reference; there's no explicit stop for near-workspaces
    {
        let mut guard = GLOBAL_WORKER.lock().await;
        if let Some(worker) = guard.take() {
            tracing::info!("cleared global near sandbox: {}", worker.rpc_addr());
            // Drop worker by taking it out of global state
        }
    }
}

impl Default for ClusterSpawner {
    fn default() -> Self {
        let mut tmp_dir = execute::target_dir().expect("unable to locate target dir");
        tmp_dir.push("tmp");

        let nodes = 3;
        let cfg = NodeConfig {
            nodes,
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
            ethereum: None,
            program_address: None,
            prestockpile: Some(Prestockpile { multiplier: 4 }),
            pregenerated_keys: PregeneratedKeys::load(nodes).unwrap(),
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
            self.pregenerated_keys =
                PregeneratedKeys::load(self.cfg.nodes).unwrap_or(PregeneratedKeys::Disabled);
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

    // module-level global guards for parallel mode

    pub async fn spawn_redis(&self) -> Arc<containers::Redis> {
        // When parallel feature is enabled, we attempt to reuse a global redis instance
        #[cfg(feature = "parallel")]
        {
            let mut guard = crate::cluster::spawner::GLOBAL_REDIS.lock().await;
            if let Some(existing) = &*guard {
                tracing::info!("reusing global redis instance: {}", existing.internal_address);
                return Arc::clone(existing);
            }
            let redis = Arc::new(containers::Redis::run(self).await);
            tracing::info!("initialized global redis instance: {}", redis.internal_address);
            *guard = Some(Arc::clone(&redis));
            return redis;
        }

        #[cfg(not(feature = "parallel"))]
        {
            Arc::new(containers::Redis::run(self).await)
        }
    }

    pub async fn spawn_solana(&self) -> Arc<containers::Solana> {
        #[cfg(feature = "parallel")]
        {
            let mut guard = crate::cluster::spawner::GLOBAL_SOLANA.lock().await;
            if let Some(existing) = &*guard {
                tracing::info!("reusing global solana instance: {}", existing.rpc_address);
                return Arc::clone(existing);
            }
            let solana = Arc::new(containers::Solana::run().await);
            tracing::info!("initialized global solana instance: {}", solana.rpc_address);
            *guard = Some(Arc::clone(&solana));
            solana
        }

        #[cfg(not(feature = "parallel"))]
        {
            Arc::new(containers::Solana::run().await)
        }
    }

    /// Prespawns a redis instance where we're able to make use of it before the nodes are spun
    /// up and are in running phase. This redis instance will be reused when the whole environment
    /// is setup.
    pub async fn prespawn_redis(&mut self) -> &Arc<containers::Redis> {
        self.redis = Some(self.spawn_redis().await);
        self.redis.as_ref().unwrap()
    }

    /// Prespawns a Solana test validator instance for integration testing.
    pub async fn prespawn_solana(&mut self) -> &Arc<containers::Solana> {
        self.solana = Some(self.spawn_solana().await);
        self.solana.as_ref().unwrap()
    }

    /// Grabs the underlying redis instance that was prespawned, or if not prespawned, create a
    /// new one from start up.
    pub async fn take_redis(&mut self) -> Arc<containers::Redis> {
        match self.redis.take() {
            Some(redis) => redis,
            None => self.spawn_redis().await,
        }
    }

    /// Grabs the underlying Solana instance that was prespawned, or if not prespawned, create a
    /// new one from start up.
    pub async fn take_solana(&mut self) -> Option<Arc<containers::Solana>> {
        self.solana.take()
    }

    pub async fn spawn_ethereum(&self) -> anyhow::Result<Arc<containers::EthereumSandbox>> {
        #[cfg(feature = "parallel")]
        {
            let mut guard = crate::cluster::spawner::GLOBAL_ETH.lock().await;
            if let Some(existing) = &*guard {
                tracing::info!("reusing global ethereum instance: {}", existing.external_http_endpoint);
                return Ok(Arc::clone(existing));
            }
            let sandbox = Arc::new(containers::EthereumSandbox::run(self).await?);
            tracing::info!("initialized global ethereum instance: {}", sandbox.external_http_endpoint);
            *guard = Some(Arc::clone(&sandbox));
            Ok(sandbox)
        }

        #[cfg(not(feature = "parallel"))]
        {
            Ok(Arc::new(containers::EthereumSandbox::run(self).await?))
        }
    }

    pub async fn prespawn_ethereum(&mut self) -> anyhow::Result<&Arc<containers::EthereumSandbox>> {
        self.ethereum = Some(self.spawn_ethereum().await?);
        Ok(self.ethereum.as_ref().unwrap())
    }

    pub async fn take_ethereum(&mut self) -> anyhow::Result<Arc<containers::EthereumSandbox>> {
        match self.ethereum.take() {
            Some(s) => Ok(s),
            None => self.spawn_ethereum().await,
        }
    }

    pub async fn prespawn_sandbox(&mut self) -> anyhow::Result<&Arc<Worker<Sandbox>>> {
        if self.worker.is_none() {
            #[cfg(feature = "parallel")]
            {
                let mut guard = crate::cluster::spawner::GLOBAL_WORKER.lock().await;
                if let Some(w) = &*guard {
                    tracing::info!("reusing global near sandbox instance: {}", w.rpc_addr());
                    self.worker = Some(Arc::clone(w));
                } else {
                    let worker = Arc::new(near_workspaces::sandbox().await?);
                    tracing::info!("initialized global near sandbox instance: {}", worker.rpc_addr());
                    *guard = Some(Arc::clone(&worker));
                    self.worker = Some(worker);
                }
            }

            #[cfg(not(feature = "parallel"))]
            {
                self.worker = Some(Arc::new(near_workspaces::sandbox().await?));
            }
        }
        Ok(self.worker.as_ref().unwrap())
    }

    pub async fn take_worker(&mut self) -> Arc<Worker<Sandbox>> {
        match self.worker.take() {
            Some(worker) => worker,
            None => {
                #[cfg(feature = "parallel")]
                {
                    let mut guard = crate::cluster::spawner::GLOBAL_WORKER.lock().await;
                    if let Some(w) = &*guard {
                        tracing::info!("reusing global near sandbox instance: {}", w.rpc_addr());
                        Arc::clone(w)
                    } else {
                        let worker = Arc::new(near_workspaces::sandbox().await.unwrap());
                        tracing::info!("initialized global near sandbox instance: {}", worker.rpc_addr());
                        *guard = Some(Arc::clone(&worker));
                        worker
                    }
                }

                #[cfg(not(feature = "parallel"))]
                {
                    Arc::new(near_workspaces::sandbox().await.unwrap())
                }
            }
        }
    }

    pub async fn presetup(&mut self) -> anyhow::Result<&Arc<containers::Redis>> {
        let worker = self.prespawn_sandbox().await?.clone();
        self.create_accounts(&*worker).await;
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
                ethereum: self.ethereum.take(),
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
