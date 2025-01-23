use crate::config::{Config, ContractConfig};
use crate::protocol::ProtocolState;
use near_account_id::AccountId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub struct RpcExecutor {
    rpc_client: RpcClient,
}

impl RpcExecutor {
    pub fn init(rpc_client: &near_fetch::Client, mpc_contract_id: &AccountId) -> Self {
        Self {
            rpc_client: RpcClient::new(rpc_client, mpc_contract_id),
        }
    }

    pub async fn run(
        self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        config: Arc<RwLock<Config>>,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(3000));
        loop {
            interval.tick().await;
            match self.rpc_client.fetch_state().await {
                Err(error) => {
                    tracing::error!("could not fetch contract's state: {error:?}");
                }
                Ok(state) => {
                    let mut contract_state_guard = contract_state.write().await;
                    *contract_state_guard = Some(state);
                }
            }

            let mut config = config.write().await;
            if let Err(error) = config.fetch_inplace(&self.rpc_client).await {
                tracing::error!("could not fetch contract's config: {error:?}");
            }
        }
    }
}

#[derive(Clone)]
pub struct RpcClient {
    client: near_fetch::Client,
    contract_id: AccountId,
}

impl RpcClient {
    pub fn new(client: &near_fetch::Client, contract_id: &AccountId) -> Self {
        Self {
            client: client.clone(),
            contract_id: contract_id.clone(),
        }
    }

    pub async fn fetch_state(&self) -> anyhow::Result<ProtocolState> {
        let contract_state: mpc_contract::ProtocolContractState = self
            .client
            .view(&self.contract_id, "state")
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to fetch protocol state");
            })?
            .json()?;

        let protocol_state: ProtocolState = contract_state.try_into().map_err(|_| {
            let msg = "failed to parse protocol state, has it been initialized?".to_string();
            tracing::error!(msg);
            anyhow::anyhow!(msg)
        })?;

        tracing::debug!(?protocol_state, "protocol state");
        Ok(protocol_state)
    }

    pub async fn fetch_config(&self, original: &Config) -> anyhow::Result<Config> {
        let contract_config: ContractConfig = self
            .client
            .view(&self.contract_id, "config")
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to fetch contract config");
            })?
            .json()?;
        tracing::debug!(?contract_config, "contract config");
        Config::try_from_contract(contract_config, original).ok_or_else(|| {
            let msg = "failed to parse contract config";
            tracing::error!(msg);
            anyhow::anyhow!(msg)
        })
    }
}
