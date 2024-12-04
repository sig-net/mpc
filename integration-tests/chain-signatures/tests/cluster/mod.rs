mod spawner;

use near_workspaces::network::Sandbox;
use spawner::ClusterSpawner;

use mpc_contract::{errors, ProtocolContractState, RunningContractState};
use mpc_node::web::StateView;

use anyhow::Context;
use integration_tests_chain_signatures::containers::DockerClient;
use integration_tests_chain_signatures::{utils, MultichainConfig, Nodes};
use near_workspaces::{Contract, Worker};
use url::Url;

use crate::actions::wait::WaitAction;
use crate::actions::{self, wait_for};

pub fn spawn() -> ClusterSpawner {
    ClusterSpawner {
        wait_for_running: false,
        cfg: MultichainConfig {
            nodes: 3,
            threshold: 2,
            protocol: Default::default(),
        },
    }
}

pub struct Cluster {
    pub cfg: MultichainConfig,
    pub docker_client: DockerClient,
    pub rpc_client: near_fetch::Client,
    http_client: reqwest::Client,
    nodes: Nodes,
}

impl Cluster {
    pub fn len(&self) -> usize {
        self.nodes.len()
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

    pub fn wait(&self) -> WaitAction<'_> {
        WaitAction::new(self)
    }

    pub async fn sign(&self) -> anyhow::Result<()> {
        let state = self.expect_running().await?;
        let (_, payload_hash, account, status) = actions::request_sign_(self).await?;
        // We have to use seperate transactions because one could fail.
        // This leads to a potential race condition where this transaction could get sent after the signature completes, but I think that's unlikely
        let rogue_status =
            actions::rogue_respond_(self, payload_hash, account.id(), "test").await?;
        let err = wait_for::rogue_message_responded(rogue_status).await?;

        assert!(err.contains(&errors::RespondError::InvalidSignature.to_string()));
        let signature = wait_for::signature_responded(status).await?;

        let mut mpc_pk_bytes = vec![0x04];
        mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);

        // Useful for populating the "signatures_havent_changed" test's hardcoded values
        // dbg!(
        //     hex::encode(signature.big_r.to_encoded_point(true).to_bytes()),
        //     hex::encode(signature.s.to_bytes()),
        //     hex::encode(&mpc_pk_bytes),
        //     hex::encode(&payload_hash),
        //     account.id(),
        // );
        actions::assert_signature(account.id(), &mpc_pk_bytes, payload_hash, &signature).await;

        Ok(())
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
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let sk_local_path = self.nodes.ctx().storage_options.sk_share_local_path.clone();
        let _ = tokio::task::spawn(utils::clear_local_sk_shares(sk_local_path));
    }
}
