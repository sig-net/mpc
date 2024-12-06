use crate::config::Config;
use crate::protocol::ProtocolState;
use crate::rpc_client;
use near_account_id::AccountId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct ContractUpdater {
    rpc_client: near_fetch::Client,
    mpc_contract_id: AccountId,
}

impl ContractUpdater {
    pub fn init(rpc_client: near_fetch::Client, mpc_contract_id: AccountId) -> Self {
        Self {
            rpc_client,
            mpc_contract_id: mpc_contract_id.clone(),
        }
    }

    pub async fn run(
        &self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        config: Arc<RwLock<Config>>,
    ) -> anyhow::Result<()> {
        let mut last_state_update = Instant::now();
        let mut last_config_update = Instant::now();
        loop {
            if last_state_update.elapsed() > Duration::from_millis(1000) {
                let mut contract_state = contract_state.write().await;
                *contract_state =
                    rpc_client::fetch_mpc_contract_state(&self.rpc_client, &self.mpc_contract_id)
                        .await
                        .ok();
                last_state_update = Instant::now();
            }
            if last_config_update.elapsed() > Duration::from_millis(300) {
                let mut config = config.write().await;
                if let Err(error) = config
                    .fetch_inplace(&self.rpc_client, &self.mpc_contract_id)
                    .await
                {
                    tracing::error!("could not fetch contract's config: {error:?}");
                }
                last_config_update = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
