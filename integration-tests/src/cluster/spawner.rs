use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Worker};

use std::future::{Future, IntoFuture};
use std::path::PathBuf;

use crate::containers::DockerClient;
use crate::{NodeConfig, Nodes, execute};

use crate::cluster::Cluster;

const DOCKER_NETWORK: &str = "mpc_it_network";
const GCP_PROJECT_ID: &str = "multichain-integration";
const ENV: &str = "integration-tests";

struct Prestockpile {
    /// Multiplier to increase the stockpile such that stockpiling presignatures does not trigger
    /// the number of triples to be lower than the stockpile limit.
    multiplier: u32,
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
    prestockpile: Option<Prestockpile>,
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
            prestockpile: Some(Prestockpile { multiplier: 4 }),
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

    pub fn debug_node(&mut self) -> &mut Self {
        self.release = false;
        self
    }

    /// Create accounts for the nodes
    pub async fn create_accounts(&mut self, worker: &Worker<Sandbox>) {
        let mut accounts = Vec::with_capacity(self.cfg.nodes);
        for _ in 0..self.cfg.nodes {
            accounts.push(worker.dev_create_account().await.unwrap());
        }
        self.participants
            .extend((0..accounts.len() as u32).map(Participant::from));
        self.accounts.extend(accounts);
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
            let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
            let rpc_client = near_fetch::Client::from_client(jsonrpc_client);

            let cfg = self.cfg.clone();
            let cluster = Cluster {
                cfg: self.cfg,
                rpc_client,
                http_client: reqwest::Client::default(),
                docker_client: self.docker,
                nodes,
            };

            if self.wait_for_running {
                cluster.wait().running().nodes_running().await?;
            }

            if let Some(prestockpile) = self.prestockpile {
                let participants = cluster.participants().await.unwrap();
                cluster
                    .nodes
                    .ctx()
                    .redis
                    .stockpile_triples(&cfg, &participants, prestockpile.multiplier)
                    .await;

                cluster
                    .wait()
                    .min_mine_presignatures(cfg.protocol.presignature.min_presignatures as usize)
                    .await
                    .unwrap();
            }

            Ok(cluster)
        })
    }
}
