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

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_primitives::{Chain, SignBidirectionalEvent, SignId, SignKind};

    #[tokio::test]
    async fn publish_signature_reports_failure() {
        let event = SignBidirectionalEvent {
            sender: [0; 32],
            serialized_transaction: vec![],
            caip2_id: "midnight:testnet".to_string(),
            key_version: 1,
            deposit: 0,
            path: String::new(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            chain: Chain::Midnight,
            chain_ctx: None,
        };

        let action = make_publish_action(
            Chain::Midnight,
            SignKind::SignBidirectional(event),
            SignId::new([0u8; 32]),
        );
        assert!(MidnightPublisher.publish_signature(&action).await.is_err());
    }
}
