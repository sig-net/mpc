//! Midnight publisher.

use async_trait::async_trait;
use mpc_chain_integration_core::{ChainPublisher, PublishAction};

/// Posts MPC responses back to the Midnight central contract.
///
/// The publish path is not built yet, so every attempt fails loudly. Reporting
/// success without posting would let a request settle as published.
#[derive(Clone, Debug, Default)]
pub struct MidnightPublisher;

#[async_trait]
impl ChainPublisher for MidnightPublisher {
    async fn publish_signature(&self, _action: &PublishAction) -> anyhow::Result<()> {
        anyhow::bail!("midnight publisher not implemented (PR-4)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_primitives::{Chain, SignKind};

    #[tokio::test]
    async fn publish_signature_reports_failure() {
        let action = make_publish_action(Chain::Midnight, SignKind::Sign);
        assert!(MidnightPublisher.publish_signature(&action).await.is_err());
    }
}
