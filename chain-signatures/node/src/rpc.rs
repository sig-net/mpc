use crate::config::Config;
use crate::protocol::ProtocolState;
use crate::rpc_client;
use near_account_id::AccountId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub struct RpcExecutor {
    rpc_client: near_fetch::Client,
    mpc_contract_id: AccountId,
}

impl RpcExecutor {
    pub fn init(rpc_client: &near_fetch::Client, mpc_contract_id: &AccountId) -> Self {
        Self {
            rpc_client: rpc_client.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
        }
    }

    pub async fn run(
        self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        config: Arc<RwLock<Config>>,
    ) -> anyhow::Result<()> {
        loop {
            {
                match rpc_client::fetch_mpc_contract_state(&self.rpc_client, &self.mpc_contract_id)
                    .await
                {
                    Err(error) => {
                        tracing::error!("could not fetch contract's state: {error:?}");
                    }
                    Ok(state) => {
                        let mut contract_state_guard = contract_state.write().await;
                        *contract_state_guard = Some(state);
                    }
                }

                let mut config = config.write().await;
                if let Err(error) = config
                    .fetch_inplace(&self.rpc_client, &self.mpc_contract_id)
                    .await
                {
                    tracing::error!("could not fetch contract's config: {error:?}");
                }
            }
            tokio::time::sleep(Duration::from_millis(3000)).await;
        }
    }
}
