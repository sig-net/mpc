mod spawner;

use std::collections::HashSet;

use integration_tests_chain_signatures::local::NodeEnvConfig;
use mpc_contract::primitives::Participants;
use near_workspaces::network::Sandbox;
use spawner::ClusterSpawner;

use mpc_contract::{ProtocolContractState, RunningContractState};
use mpc_node::web::StateView;

use anyhow::Context;
use integration_tests_chain_signatures::containers::DockerClient;
use integration_tests_chain_signatures::{utils, NodeConfig, Nodes};
use near_workspaces::{Account, AccountId, Contract, Worker};
use url::Url;

use crate::actions::sign::SignAction;
use crate::actions::wait::WaitAction;

pub fn spawn() -> ClusterSpawner {
    ClusterSpawner {
        wait_for_running: false,
        cfg: NodeConfig {
            nodes: 3,
            threshold: 2,
            protocol: Default::default(),
        },
    }
}

pub struct Cluster {
    pub cfg: NodeConfig,
    pub docker_client: DockerClient,
    pub rpc_client: near_fetch::Client,
    http_client: reqwest::Client,
    pub(crate) nodes: Nodes,
}

impl Cluster {
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn url(&self, id: usize) -> Url {
        Url::parse(self.nodes.url(id)).unwrap()
    }

    pub async fn fetch_state(&self, id: usize) -> anyhow::Result<StateView> {
        let url = self.url(id).join("/state").unwrap();
        let state_view: StateView = self.http_client.get(url).send().await?.json().await?;
        Ok(state_view)
    }

    pub async fn fetch_states(&self) -> anyhow::Result<Vec<StateView>> {
        let tasks = (0..self.len()).map(|id| self.fetch_state(id));
        futures::future::try_join_all(tasks).await
    }

    pub fn wait(&self) -> WaitAction<'_, ()> {
        WaitAction::new(self)
    }

    pub fn sign(&self) -> SignAction<'_> {
        SignAction::new(self)
    }

    pub fn worker(&self) -> &Worker<Sandbox> {
        &self.nodes.ctx().worker
    }

    pub fn contract(&self) -> &Contract {
        self.nodes.contract()
    }

    pub async fn contract_state(&self) -> anyhow::Result<ProtocolContractState> {
        let state: ProtocolContractState = self
            .contract()
            .view("state")
            .await
            .with_context(|| "could not view state")?
            .json()?;
        Ok(state)
    }

    pub async fn expect_running(&self) -> anyhow::Result<RunningContractState> {
        let state = self.contract_state().await?;
        if let ProtocolContractState::Running(state) = state {
            Ok(state)
        } else {
            anyhow::bail!("expected running state, got {:?}", state)
        }
    }

    pub async fn participants(&self) -> anyhow::Result<Participants> {
        let state = self.expect_running().await?;
        Ok(state.participants)
    }

    pub async fn participant_ids(&self) -> anyhow::Result<HashSet<AccountId>> {
        let participants = self.participants().await?;
        Ok(participants.keys().cloned().collect())
    }

    pub async fn participant_accounts(&self) -> anyhow::Result<Vec<&Account>> {
        let participant_ids = self.participant_ids().await?;
        let mut node_accounts = self.nodes.near_accounts();
        node_accounts.retain(|a| participant_ids.contains(a.id()));
        Ok(node_accounts)
    }

    pub async fn root_public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        let state: RunningContractState = self.expect_running().await?;
        Ok(state.public_key)
    }

    pub async fn kill_node(&mut self, account_id: &AccountId) -> NodeEnvConfig {
        self.nodes.kill_node(account_id).await
    }

    pub async fn restart_node(&mut self, config: NodeEnvConfig) -> anyhow::Result<()> {
        self.nodes.restart_node(config).await
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let sk_local_path = self.nodes.ctx().storage_options.sk_share_local_path.clone();
        let _task = tokio::task::spawn(utils::clear_local_sk_shares(sk_local_path));
    }
}
