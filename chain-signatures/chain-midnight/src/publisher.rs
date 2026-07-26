//! Midnight publisher.

use async_trait::async_trait;
use mpc_chain_integration_core::{ChainPublisher, PublishAction};

/// Posts MPC responses back to the Midnight central contract.
///
/// The publish path is not built yet, so every attempt returns an error.
/// That is not a bounded failure: `execute_publish` wraps publishers in an
/// unbounded retry (`max_times: usize::MAX`, no overall timeout, delays
/// capped at 60s), so an enabled Midnight publish becomes an immortal task
/// retrying roughly once a minute forever, one warning per attempt, and the
/// request never settles as published. Still the right trade: reporting
/// success without posting would let the request settle as published.
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
    use mpc_primitives::{Chain, SignBidirectionalEvent, SignKind};

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

        let action = make_publish_action(Chain::Midnight, SignKind::SignBidirectional(event));
        assert!(MidnightPublisher.publish_signature(&action).await.is_err());
    }
}
