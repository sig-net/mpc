use crate::actions::wait_for;
use crate::with_multichain_nodes;

use integration_tests_chain_signatures::MultichainConfig;
use test_log::test;

#[test(tokio::test)]
async fn test_signature_basic() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;

            Ok(())
        })
    })
    .await
}
