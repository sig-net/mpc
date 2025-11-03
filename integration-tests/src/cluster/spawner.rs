use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use near_account_id::AccountId;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Worker};

use crate::cluster::env::ClusterEnv;
use crate::containers::DockerClient;
use crate::utils::dev_gen_indexed;
use crate::{execute, NodeConfig, Nodes};
use std::future::{Future, IntoFuture};
use std::path::PathBuf;

use crate::cluster::Cluster;

const GCP_PROJECT_ID: &str = "multichain-integration";
const ENV: &str = "integration-tests";

pub struct Prestockpile {
    /// Multiplier to increase the stockpile such that stockpiling presignatures does not trigger
    /// the number of triples to be lower than the stockpile limit.
    pub multiplier: u32,
}

pub struct ClusterSpawner {
    pub env: ClusterEnv,
    pub release: bool,
    pub gcp_env: String,
    pub gcp_project_id: String,
    pub accounts: Vec<Account>,
    pub participants: Vec<Participant>,
    pub tmp_dir: PathBuf,

    pub cfg: NodeConfig,
    pub wait_for_running: bool,
    prestockpile: Option<Prestockpile>,
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
            env: ClusterEnv::new(),
            release: true,
            gcp_env: ENV.to_string(),
            gcp_project_id: GCP_PROJECT_ID.to_string(),
            accounts: Vec::with_capacity(cfg.nodes),
            participants: Vec::with_capacity(cfg.nodes),
            tmp_dir,

            cfg,
            wait_for_running: true,
            prestockpile: Some(Prestockpile { multiplier: 4 }),
            use_ethereum: false,
        }
    }
}

impl ClusterSpawner {
    pub async fn init_network(self) -> anyhow::Result<Self> {
        self.env.docker().create_network(self.env.network()).await?;
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

    pub fn env(mut self, env: &str) -> Self {
        self.gcp_env = env.to_string();
        self
    }

    pub fn gcp_project_id(mut self, gcp_project_id: &str) -> Self {
        self.gcp_project_id = gcp_project_id.to_string();
        self
    }

    pub fn network(mut self, network: &str) -> Self {
        self.env.set_network(network);
        self
    }

    pub fn ethereum(mut self) -> Self {
        self.use_ethereum = true;
        self.env.enable_ethereum();
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

    pub fn docker_client(&self) -> DockerClient {
        self.env.docker().clone()
    }

    pub fn docker_network(&self) -> &str {
        self.env.network()
    }

    pub fn cluster_env(&mut self) -> &mut ClusterEnv {
        &mut self.env
    }

    pub async fn spawn_redis(&mut self) -> anyhow::Result<&crate::containers::Redis> {
        self.env.spawn_redis();
        self.env.redis().await
    }

    pub async fn redis(&mut self) -> anyhow::Result<&crate::containers::Redis> {
        self.env.redis().await
    }

    pub fn spawn_redis_task(&mut self) {
        self.env.spawn_redis();
    }

    pub async fn prespawn_redis(&mut self) -> anyhow::Result<&crate::containers::Redis> {
        self.spawn_redis().await
    }

    pub async fn prespawn_sandbox(&mut self) -> anyhow::Result<&Worker<Sandbox>> {
        self.env.spawn_near_sandbox();
        self.env.near_sandbox().await
    }

    pub async fn take_worker(&mut self) -> anyhow::Result<Worker<Sandbox>> {
        self.env.take_near_sandbox().await
    }

    pub async fn presetup(&mut self) -> anyhow::Result<&crate::containers::Redis> {
        let worker = self.prespawn_sandbox().await?.clone();
        self.create_accounts(&worker).await;
        self.redis().await
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
            self = self.init_network().await?;

            let nodes = self.run().await?;
            let connector = near_jsonrpc_client::JsonRpcClient::new_client();
            let jsonrpc_client = connector.connect(nodes.ctx().worker.rpc_addr());
            let rpc_client = near_fetch::Client::from_client(jsonrpc_client);

            let docker_client = self.docker_client();
            let cfg = self.cfg;
            let wait_for_running = self.wait_for_running;
            let prestockpile = self.prestockpile;

            let cluster = Cluster {
                cfg,
                rpc_client,
                http_client: reqwest::Client::default(),
                docker_client,
                account_idx: nodes.len(),
                nodes,
            };

            if wait_for_running {
                cluster.wait().running().nodes_running().await?;

                if let Some(prestockpile) = prestockpile {
                    cluster.prestockpile(prestockpile).await;
                }
            }

            Ok(cluster)
        })
    }
}
