use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use near_account_id::AccountId;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Worker};

use std::future::{Future, IntoFuture};
use std::path::PathBuf;

use crate::containers::{self, DockerClient};
use crate::utils::dev_gen_indexed;
use crate::{execute, initialize_lake_indexer, LakeIndexerCtx, NodeConfig, Nodes};

use crate::cluster::Cluster;

const DOCKER_NETWORK: &str = "mpc_it_network";
const GCP_PROJECT_ID: &str = "multichain-integration";
const ENV: &str = "integration-tests";

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
    pub toxiproxy: bool,
    pub redis: Option<containers::Redis>,
    pub lake: Option<LakeIndexerCtx>,
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
            toxiproxy: false,
            redis: None,
            lake: None,
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

    pub fn enable_toxiproxy(mut self) -> Self {
        self.toxiproxy = true;
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

    pub async fn prespawn_lake(&mut self) -> anyhow::Result<&LakeIndexerCtx> {
        let lake = initialize_lake_indexer(self).await?;
        self.lake = Some(lake);
        Ok(self.lake.as_ref().unwrap())
    }

    /// Grabs the underlying lake instance that was prespawned, or if not prespawned, create a
    /// new one from start up.
    pub async fn take_lake(&mut self) -> LakeIndexerCtx {
        match self.lake.take() {
            Some(lake) => lake,
            None => initialize_lake_indexer(self).await.unwrap(),
        }
    }

    pub async fn spawn_redis(&self) -> containers::Redis {
        containers::Redis::run(self).await
    }

    /// Prespawns a redis instance where we're able to make use of it before the nodes are spun
    /// up and are in running phase. This redis instance will be reused when the whole environment
    /// is setup.
    pub async fn prespawn_redis(&mut self) -> &containers::Redis {
        self.redis = Some(self.spawn_redis().await);
        self.redis.as_ref().unwrap()
    }

    /// Grabs the underlying redis instance that was prespawned, or if not prespawned, create a
    /// new one from start up.
    pub async fn take_redis(&mut self) -> containers::Redis {
        match self.redis.take() {
            Some(redis) => redis,
            None => self.spawn_redis().await,
        }
    }

    pub async fn presetup(&mut self) -> anyhow::Result<&containers::Redis> {
        let lake = self.prespawn_lake().await?;
        let worker = lake.worker.clone();
        self.create_accounts(&worker).await;
        Ok(self.prespawn_redis().await)
    }

    pub async fn run(&mut self) -> anyhow::Result<Nodes> {
        crate::run(self).await
    }

    pub async fn dry_run(&mut self) -> anyhow::Result<crate::Context> {
        crate::dry_run(self).await
    }

    /// Integration tests rely on a fake AWS configuration for LocalStack
    pub fn fake_aws_credentials(&self) {
        std::env::set_var("AWS_ACCESS_KEY_ID", "123");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "456");
        std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");
    }
}

impl IntoFuture for ClusterSpawner {
    type Output = anyhow::Result<Cluster>;
    type IntoFuture = std::pin::Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            self = self.init_network().await?;
            self.fake_aws_credentials();

            let nodes = self.run().await?;
            let connector = near_jsonrpc_client::JsonRpcClient::new_client();
            let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
            let rpc_client = near_fetch::Client::from_client(jsonrpc_client);

            let cluster = Cluster {
                cfg: self.cfg,
                rpc_client,
                http_client: reqwest::Client::default(),
                docker_client: self.docker,
                account_idx: nodes.len(),
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
