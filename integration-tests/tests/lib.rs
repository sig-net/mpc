mod actions;
mod cases;
pub mod cluster;

use cluster::Cluster;
use mpc_contract::update::{ProposeUpdateArgs, UpdateId};

use integration_tests::local::NodeEnvConfig;
use integration_tests::utils::{vote_join, vote_leave};

use near_workspaces::types::NearToken;
use near_workspaces::{Account, AccountId};

const CURRENT_CONTRACT_DEPLOY_DEPOSIT: NearToken = NearToken::from_millinear(9000);
const CURRENT_CONTRACT_FILE_PATH: &str =
    "../target/wasm32-unknown-unknown/release/mpc_contract.wasm";

impl Cluster {
    /// Starts a node and waits for the cluster to be in running. This does not have the node join the network,
    /// but it does appear as a candidate in the contract.
    pub async fn start(&mut self, node: Option<NodeEnvConfig>) -> anyhow::Result<Account> {
        let node_account = match node {
            Some(node) => {
                tracing::info!(
                    node_account_id = %node.account.id(),
                    "adding pre-existing participant"
                );
                node.account
            }
            None => {
                let account = self.worker().dev_create_account().await?;
                tracing::info!(node_account_id = %account.id(), "adding new participant");
                account
            }
        };

        // Wait for new node to add itself as a candidate
        let id = self.nodes.start_node(&self.cfg, &node_account).await?;
        self.wait()
            .node_joining(id)
            .candidate_present(node_account.id())
            .await?;
        Ok(node_account)
    }

    /// Adds a new node to the network. If `existing_node` is provided, it will be used as a participant
    /// information. Otherwise, a new account will be created alongside the equivalent details for the node.
    pub async fn join(&mut self, existing_node: Option<NodeEnvConfig>) -> anyhow::Result<()> {
        let state = self.expect_running().await?;
        let node_account = self.start(existing_node).await?;

        // T number of participants should vote
        let participants = self.participant_accounts().await?;
        let voting_participants = participants
            .iter()
            .take(state.threshold)
            .cloned()
            .collect::<Vec<_>>();
        vote_join(
            &voting_participants,
            self.contract().id(),
            node_account.id(),
        )
        .await?;

        let new_state = self
            .wait()
            .running_on_epoch(state.epoch + 1)
            .candidate_missing(node_account.id())
            .participant_present(node_account.id())
            .nodes_running()
            .await?;
        assert_eq!(new_state.participants.len(), state.participants.len() + 1);
        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        Ok(())
    }

    /// Stops a node and waits for the cluster to be in running. This does not kick it from the network but
    /// merely stops the node itself from operating.
    pub async fn stop(&mut self, node: &AccountId) -> anyhow::Result<NodeEnvConfig> {
        let config = self.nodes.kill_node(node).await;
        self.wait().running().await?;
        Ok(config)
    }

    /// Kicks the node out of the network. The node will be stopped and the cluster will reach the Running state.
    /// once resharing completes.
    pub async fn leave(&mut self, kick: Option<&AccountId>) -> anyhow::Result<NodeEnvConfig> {
        let state = self.expect_running().await?;
        let participant_accounts = self.participant_accounts().await?;
        let kick = kick
            .unwrap_or_else(|| participant_accounts.last().unwrap().id())
            .clone();
        let voting_accounts = participant_accounts
            .iter()
            .filter(|account| account.id() != &kick)
            .take(state.threshold)
            .cloned()
            .collect::<Vec<_>>();

        tracing::info!(?voting_accounts, %kick, at_epoch = state.epoch, "kicking participant");
        vote_leave(&voting_accounts, self.contract().id(), &kick).await?;

        let new_state = self
            .wait()
            .running_on_epoch(state.epoch + 1)
            .participant_missing(&kick)
            .await?;

        tracing::info!(
            "Getting new state, old {} {:?}, new {} {:?}",
            state.participants.len(),
            state.public_key,
            new_state.participants.len(),
            new_state.public_key
        );

        assert_eq!(state.participants.len(), new_state.participants.len() + 1);

        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        let config = self.stop(&kick).await?;
        // Wait for the node to be offline then check all running nodes for running:
        self.wait().nodes_running().await?;
        Ok(config)
    }

    pub async fn propose_update(&self, args: ProposeUpdateArgs) -> mpc_contract::update::UpdateId {
        let accounts = self.nodes.near_accounts();
        accounts[0]
            .call(self.contract().id(), "propose_update")
            .args_borsh((args,))
            .max_gas()
            .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
            .transact()
            .await
            .unwrap()
            .json()
            .unwrap()
    }

    pub async fn propose_update_contract_default(&self) -> UpdateId {
        let same_contract_bytes = std::fs::read(CURRENT_CONTRACT_FILE_PATH).unwrap();
        self.propose_update(ProposeUpdateArgs {
            code: Some(same_contract_bytes),
            config: None,
        })
        .await
    }

    pub async fn vote_update(&self, id: UpdateId) {
        let participants = self.participant_accounts().await.unwrap();

        let mut success = 0;
        for account in participants.iter() {
            let execution = account
                .call(self.contract().id(), "vote_update")
                .args_json((id,))
                .max_gas()
                .transact()
                .await
                .unwrap()
                .into_result();

            match execution {
                Ok(_) => success += 1,
                Err(e) => tracing::warn!(?id, ?e, "Failed to vote for update"),
            }
        }

        assert!(
            success >= self.cfg.threshold,
            "did not successfully vote for update"
        );

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}
