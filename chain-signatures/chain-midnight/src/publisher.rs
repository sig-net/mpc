//! Midnight publisher.

use async_trait::async_trait;
use mpc_chain_integration_core::{ChainPublisher, PublishAction};

/// Posts MPC responses back to the Midnight central contract.
#[derive(Clone, Debug, Default)]
pub struct MidnightPublisher;

#[async_trait]
impl ChainPublisher for MidnightPublisher {
    async fn publish_signature(&self, _action: &PublishAction) -> anyhow::Result<()> {
        anyhow::bail!("midnight publisher not implemented")
    }
}
